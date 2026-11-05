"""
Unit tests for yomi_mcp.mcp_server.YomiMCPServer.

READ_VAULTS/WRITE_VAULTS use hardcoded ABSOLUTE paths (/tmp, /home, etc.),
not paths relative to mcp_server.py's own __file__ -- so unlike most other
modules tested so far, there's nothing to monkeypatch for isolation.
Instead, tests that need an "authorized" path use pytest's tmp_path
fixture directly, since it lands under the real /tmp (already on the
vault allowlist) on this system.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def server(isolated_stamp, monkeypatch):
    from yomi_mcp.mcp_server import YomiMCPServer

    monkeypatch.setattr("shutil.which", lambda name: None)
    return YomiMCPServer()


# --------------------------------------------------------------------------
# list_tools
# --------------------------------------------------------------------------

def test_list_tools_returns_valid_jsonrpc_with_all_registered_tools(server):
    response = json.loads(server.list_tools(request_id=1))
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    tool_names = {t["name"] for t in response["result"]["tools"]}
    assert "run_cryogenic_freeze" in tool_names
    assert "run_volatility_pslist" in tool_names
    assert len(tool_names) == len(server.tool_registry)


# --------------------------------------------------------------------------
# _validate_dynamic_arguments
# --------------------------------------------------------------------------

def test_validate_missing_required_argument_vetoed(server):
    is_valid, msg, _ = server._validate_dynamic_arguments("run_cryogenic_freeze", {})
    assert is_valid is False
    assert "required but missing" in msg


def test_validate_non_digit_pid_vetoed(server):
    is_valid, msg, _ = server._validate_dynamic_arguments(
        "run_cryogenic_freeze", {"target_pid": "not_a_number"}
    )
    assert is_valid is False
    assert "strictly numeric" in msg


def test_validate_digit_pid_sanitized(server):
    is_valid, msg, args = server._validate_dynamic_arguments(
        "run_cryogenic_freeze", {"target_pid": " 1234 "}
    )
    assert is_valid is True
    assert args["target_pid"] == "1234"


def test_validate_path_traversal_dots_vetoed(server):
    is_valid, msg, _ = server._validate_dynamic_arguments(
        "run_volatility_pslist", {"memory_dump_path": "/tmp/../etc/passwd"}
    )
    assert is_valid is False
    assert "traversal" in msg.lower()


def test_validate_path_outside_vault_vetoed(server):
    is_valid, msg, _ = server._validate_dynamic_arguments(
        "run_volatility_pslist", {"memory_dump_path": "/root/secret_dump.raw"}
    )
    assert is_valid is False
    assert "vault boundaries" in msg


def test_validate_path_inside_read_vault_authorized(server, tmp_path):
    dump = tmp_path / "memory.raw"
    dump.write_bytes(b"x")
    is_valid, msg, args = server._validate_dynamic_arguments(
        "run_volatility_pslist", {"memory_dump_path": str(dump)}
    )
    assert is_valid is True
    assert args["memory_dump_path"] == str(dump.resolve())


def test_validate_output_dir_checked_against_write_vault(server, tmp_path):
    # "output_dir" contains "dir" -> checked against WRITE_VAULTS, not
    # READ_VAULTS. /tmp is on both lists, so this specific case still
    # passes -- confirms the write-intent branch is reachable, not that
    # the vaults differ in coverage for /tmp specifically.
    is_valid, msg, args = server._validate_dynamic_arguments(
        "run_bulk_extractor", {"target_path": str(tmp_path), "output_dir": str(tmp_path)}
    )
    assert is_valid is True


def test_validate_shell_chaining_operators_vetoed(server):
    dangerous_inputs = ["evil$(rm -rf /)", "a`whoami`", "a|b", "a;b", "a&&b", "a||b", "a>b"]
    for payload in dangerous_inputs:
        is_valid, msg, _ = server._validate_dynamic_arguments(
            "run_strings_grep", {"target_path": "/tmp/x", "pattern": payload}
        )
        assert is_valid is False, f"payload not vetoed: {payload!r}"
        assert "chaining" in msg.lower() or "execution operator" in msg.lower()


def test_validate_clean_generic_argument_passes(server):
    is_valid, msg, args = server._validate_dynamic_arguments(
        "run_strings_grep", {"target_path": "/tmp/x", "pattern": "mimikatz"}
    )
    assert is_valid is True
    assert args["pattern"] == "mimikatz"


def test_validate_optional_argument_absent_defaults_empty(server, tmp_path):
    is_valid, msg, args = server._validate_dynamic_arguments(
        "run_bulk_extractor", {"target_path": str(tmp_path)}
    )
    assert is_valid is True
    assert args.get("output_dir", "") == ""


# --------------------------------------------------------------------------
# call_tool: VVIP freeze/thaw bypass (no thread pool, direct harness route)
# --------------------------------------------------------------------------

def test_call_tool_unknown_tool_returns_error(server):
    response = json.loads(server.call_tool("nonexistent_tool", {}, request_id=1))
    assert "error" in response
    assert "not found" in response["error"]


def test_call_tool_freeze_bypasses_thread_pool_directly_to_harness(server, monkeypatch):
    monkeypatch.setattr(
        server.harness, "process_intent",
        lambda intent: {"status": "SUCCESS", "action": "FROZEN"},
    )
    response = json.loads(server.call_tool("run_cryogenic_freeze", {"target_pid": "5000"}))
    assert response["result"]["status"] == "SUCCESS"
    assert server.active_tasks == 0  # never touched the worker-pool accounting


def test_call_tool_freeze_vetoed_pid_returns_harness_veto(server, monkeypatch):
    monkeypatch.setattr(
        server.harness, "process_intent",
        lambda intent: {"status": "VETOED", "message": "PID 1 is protected."},
    )
    response = json.loads(server.call_tool("run_cryogenic_freeze", {"target_pid": "1"}))
    assert response["result"]["status"] == "VETOED"


def test_call_tool_freeze_seals_command_to_ledger(server, isolated_stamp, monkeypatch):
    monkeypatch.setattr(
        server.harness, "process_intent",
        lambda intent: {"status": "SUCCESS", "action": "FROZEN"},
    )
    server.call_tool("run_cryogenic_freeze", {"target_pid": "5000"})

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "FREEZE_COMMAND"


def test_call_tool_invalid_arguments_never_reach_harness(server, monkeypatch):
    called = []
    monkeypatch.setattr(server.harness, "process_intent", lambda intent: called.append(intent))

    response = json.loads(server.call_tool("run_cryogenic_freeze", {"target_pid": "not_numeric"}))
    assert "error" in response
    assert called == []


# --------------------------------------------------------------------------
# call_tool: worker-pool tools, load shedding, accounting
# --------------------------------------------------------------------------

def test_call_tool_load_shedding_rejects_when_at_capacity(server):
    server.active_tasks = server.MAX_WORKERS  # simulate full queue
    response = json.loads(
        server.call_tool("run_ssdeep", {"target_path": "/tmp/x"})
    )
    assert "error" in response
    assert "OVERLOAD" in response["error"]


def test_call_tool_successful_execution_decrements_active_tasks(server, tmp_path, monkeypatch):
    monkeypatch.setattr(server.arsenal, "run_ssdeep", lambda path: {"status": "SUCCESS", "output": "hash123"})

    target = tmp_path / "sample.bin"
    target.write_bytes(b"x")
    response = json.loads(server.call_tool("run_ssdeep", {"target_path": str(target)}))

    assert "hash123" in response["result"]
    assert server.active_tasks == 0  # wrapper decremented after completion


def test_call_tool_exception_in_tool_is_caught_and_active_tasks_still_decremented(server, tmp_path, monkeypatch):
    def raise_error(path):
        raise RuntimeError("simulated tool crash")

    monkeypatch.setattr(server.arsenal, "run_ssdeep", raise_error)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"x")

    response = json.loads(server.call_tool("run_ssdeep", {"target_path": str(target)}))
    assert "error" in response
    assert "Internal tool execution error" in response["error"]
    assert server.active_tasks == 0  # _worker_execution_wrapper's finally still ran


def test_call_tool_truncates_huge_output_and_logs(server, isolated_stamp, tmp_path, monkeypatch):
    huge_output = "A" * 200000
    monkeypatch.setattr(server.arsenal, "run_ssdeep", lambda path: huge_output)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"x")

    response = json.loads(server.call_tool("run_ssdeep", {"target_path": str(target)}))
    assert len(response["result"]) <= 100100  # 100000 + truncation marker
    assert "TRUNCATED BY YOMI VAULT" in response["result"]

    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "OUTPUT_TRUNCATED"


def test_call_tool_normal_output_logs_tool_executed(server, isolated_stamp, tmp_path, monkeypatch):
    monkeypatch.setattr(server.arsenal, "run_ssdeep", lambda path: {"status": "SUCCESS"})
    target = tmp_path / "sample.bin"
    target.write_bytes(b"x")

    server.call_tool("run_ssdeep", {"target_path": str(target)})
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert lines[-1]["action_type"] == "TOOL_EXECUTED"


def test_call_tool_timeout_reports_orphaned(server, tmp_path, monkeypatch):
    import concurrent.futures as cf

    target = tmp_path / "sample.bin"
    target.write_bytes(b"x")

    class FakeFuture:
        def result(self, timeout=None):
            raise cf.TimeoutError()

    monkeypatch.setattr(server.worker_pool, "submit", lambda fn, *a, **k: FakeFuture())

    response = json.loads(server.call_tool("run_ssdeep", {"target_path": str(target)}))
    assert "Execution Timeout" in response["error"]


# --------------------------------------------------------------------------
# Known issue #10: operator-configurable vaults
# --------------------------------------------------------------------------
# /srv is not on the built-in vault lists, and the vault check works on
# resolved path strings (no file needs to exist), so these tests need no
# filesystem setup outside pytest's tmp_path.

def _make_server(monkeypatch, **env):
    from yomi_mcp.mcp_server import YomiMCPServer

    monkeypatch.setattr("shutil.which", lambda name: None)
    for key in ("YOMI_MCP_READ_VAULTS", "YOMI_MCP_WRITE_VAULTS"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return YomiMCPServer()


def test_default_vaults_unchanged_when_env_unset(isolated_stamp, monkeypatch):
    import os
    from yomi_mcp.mcp_server import DEFAULT_READ_VAULTS, DEFAULT_WRITE_VAULTS

    server = _make_server(monkeypatch)
    assert server.READ_VAULTS == [os.path.realpath(p) for p in DEFAULT_READ_VAULTS]
    assert server.WRITE_VAULTS == [os.path.realpath(p) for p in DEFAULT_WRITE_VAULTS]


def test_path_outside_builtin_vaults_is_vetoed_by_default(isolated_stamp, monkeypatch):
    server = _make_server(monkeypatch)
    is_valid, msg, _ = server._validate_dynamic_arguments(
        "run_volatility_pslist", {"memory_dump_path": "/srv/cases/memory.raw"}
    )
    assert is_valid is False
    assert "READ vault boundaries" in msg


def test_extra_read_vault_authorizes_deployment_outside_builtin_list(isolated_stamp, monkeypatch):
    server = _make_server(monkeypatch, YOMI_MCP_READ_VAULTS="/srv/cases")
    is_valid, msg, args = server._validate_dynamic_arguments(
        "run_volatility_pslist", {"memory_dump_path": "/srv/cases/memory.raw"}
    )
    assert is_valid is True, msg
    assert args["memory_dump_path"].endswith("/srv/cases/memory.raw")


def test_extra_read_vault_does_not_authorize_writes(isolated_stamp, monkeypatch):
    server = _make_server(monkeypatch, YOMI_MCP_READ_VAULTS="/srv/cases")
    is_valid, msg, _ = server._validate_dynamic_arguments(
        "run_bulk_extractor",
        {"target_path": "/srv/cases/disk.dd", "output_dir": "/srv/cases/out"},
    )
    assert is_valid is False
    assert "WRITE vault boundaries" in msg


def test_extra_write_vault_authorizes_output_dir(isolated_stamp, monkeypatch):
    server = _make_server(
        monkeypatch,
        YOMI_MCP_READ_VAULTS="/srv/cases",
        YOMI_MCP_WRITE_VAULTS="/srv/cases/out",
    )
    is_valid, msg, _ = server._validate_dynamic_arguments(
        "run_bulk_extractor",
        {"target_path": "/srv/cases/disk.dd", "output_dir": "/srv/cases/out"},
    )
    assert is_valid is True, msg


def test_extra_vaults_add_to_defaults_never_replace_them(isolated_stamp, monkeypatch, tmp_path):
    server = _make_server(monkeypatch, YOMI_MCP_READ_VAULTS="/srv/cases")
    dump = tmp_path / "memory.raw"
    dump.write_bytes(b"x")
    is_valid, msg, _ = server._validate_dynamic_arguments(
        "run_volatility_pslist", {"memory_dump_path": str(dump)}
    )
    assert is_valid is True, msg  # /tmp (built-in) still authorized


def test_extra_vault_does_not_match_string_prefix_sibling(isolated_stamp, monkeypatch):
    server = _make_server(monkeypatch, YOMI_MCP_READ_VAULTS="/srv/cases")
    is_valid, msg, _ = server._validate_dynamic_arguments(
        "run_volatility_pslist", {"memory_dump_path": "/srv/cases_evil/memory.raw"}
    )
    assert is_valid is False
    assert "vault boundaries" in msg


def test_multiple_entries_use_os_pathsep_and_blanks_are_ignored(isolated_stamp, monkeypatch):
    import os

    value = os.pathsep.join(["/srv/a", "", "  ", "/srv/b"])
    server = _make_server(monkeypatch, YOMI_MCP_READ_VAULTS=value)
    assert os.path.realpath("/srv/a") in server.READ_VAULTS
    assert os.path.realpath("/srv/b") in server.READ_VAULTS


@pytest.mark.parametrize("bad", ["relative/dir", "./here"])
def test_relative_vault_entry_fails_loudly(isolated_stamp, monkeypatch, bad):
    with pytest.raises(ValueError, match="absolute"):
        _make_server(monkeypatch, YOMI_MCP_READ_VAULTS=bad)


@pytest.mark.parametrize("var", ["YOMI_MCP_READ_VAULTS", "YOMI_MCP_WRITE_VAULTS"])
def test_filesystem_root_vault_is_refused(isolated_stamp, monkeypatch, var):
    with pytest.raises(ValueError, match="root"):
        _make_server(monkeypatch, **{var: "/"})
