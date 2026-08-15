"""
Unit tests for yomi_core.router: OpenClawGateway (LLM cascade) and
YomiRouter (Triad Council / ReAct self-correction loop).

All requests.post calls are mocked -- no real network calls to Gemini or
a local Ollama instance happen in this test file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _gemini_response(content_text: str, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "candidates": [{"content": content_text}],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15},
    }
    resp.text = content_text
    return resp


def _local_llm_response(content_text: str):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {
        "choices": [{"message": {"content": content_text}}],
        "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
    }
    resp.text = content_text
    return resp


VALID_INTENT_JSON = json.dumps({
    "red_agent": "Malicious activity found.",
    "blue_agent": "Recommend containment.",
    "judge_verdict": "APPROVE",
    "epistemic_doubt": 10,
    "action": "freeze",
    "target_pid": 5000,
})


@pytest.fixture
def gateway(isolated_stamp, monkeypatch):
    from yomi_core import router as router_module

    # Isolate from whatever real env vars happen to be set on the test host.
    monkeypatch.delenv("YOMI_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("YOMI_AIR_GAPPED_MODE", raising=False)
    monkeypatch.delenv("YOMI_FORCE_LOCAL_LLM", raising=False)
    monkeypatch.setattr(router_module, "GEMINI_API_KEY", "fake-key-for-tests")
    monkeypatch.setattr(router_module, "AIR_GAPPED_MODE", False)
    monkeypatch.setattr(router_module, "FORCE_LOCAL_LLM", False)

    return router_module.OpenClawGateway()


@pytest.fixture
def local_only_gateway(isolated_stamp, monkeypatch):
    from yomi_core import router as router_module

    monkeypatch.setattr(router_module, "GEMINI_API_KEY", None)
    monkeypatch.setattr(router_module, "AIR_GAPPED_MODE", True)
    monkeypatch.setattr(router_module, "FORCE_LOCAL_LLM", False)

    return router_module.OpenClawGateway()


# --------------------------------------------------------------------------
# OpenClawGateway: cascade selection logic
# --------------------------------------------------------------------------

def test_local_only_gateway_skips_gemini_entirely(local_only_gateway, monkeypatch):
    call_log = []

    def fake_post(url, **kwargs):
        call_log.append(url)
        return _local_llm_response(VALID_INTENT_JSON)

    monkeypatch.setattr("requests.post", fake_post)
    result = local_only_gateway.generate_intent("some incident context")

    assert json.loads(result)["action"] == "freeze"
    assert all("gemini" not in url for url in call_log)


def test_gateway_tries_gemini_first_when_key_present(gateway, monkeypatch):
    call_order = []

    def fake_post(url, **kwargs):
        call_order.append(url)
        return _gemini_response(VALID_INTENT_JSON)

    monkeypatch.setattr("requests.post", fake_post)
    result = gateway.generate_intent("context")

    assert json.loads(result)["action"] == "freeze"
    assert "gemini" in call_order[0]


def test_gateway_falls_through_gemini_cascade_to_next_model(gateway, monkeypatch):
    call_urls = []

    def fake_post(url, **kwargs):
        call_urls.append(url)
        if "gemini-2.5-pro" in url:
            resp = MagicMock()
            resp.raise_for_status.side_effect = Exception("503 Service Unavailable")
            return resp
        return _gemini_response(VALID_INTENT_JSON)

    monkeypatch.setattr("requests.post", fake_post)
    result = gateway.generate_intent("context")

    assert json.loads(result)["action"] == "freeze"
    assert len(call_urls) >= 2  # first model failed, second succeeded


def test_gateway_falls_back_to_local_after_full_gemini_cascade_fails(gateway, monkeypatch):
    def fake_post(url, **kwargs):
        if "gemini" in url:
            resp = MagicMock()
            resp.raise_for_status.side_effect = Exception("all gemini models down")
            return resp
        return _local_llm_response(VALID_INTENT_JSON)

    monkeypatch.setattr("requests.post", fake_post)
    result = gateway.generate_intent("context")
    assert json.loads(result)["action"] == "freeze"


def test_gateway_all_models_fail_returns_synthetic_error_intent(gateway, monkeypatch):
    def fake_post(url, **kwargs):
        resp = MagicMock()
        resp.raise_for_status.side_effect = Exception("everything is down")
        return resp

    monkeypatch.setattr("requests.post", fake_post)
    result = gateway.generate_intent("context")
    parsed = json.loads(result)

    assert parsed["judge_verdict"] == "LLM_GATEWAY_FAILURE"
    assert parsed["epistemic_doubt"] == 100
    assert parsed["action"] == "unknown"


# --------------------------------------------------------------------------
# _extract_gemini_text / _extract_local_text
# --------------------------------------------------------------------------

def test_extract_gemini_text_from_string_content(gateway):
    assert gateway._extract_gemini_text({"candidates": [{"content": "hello"}]}) == "hello"


def test_extract_gemini_text_from_fragment_list(gateway):
    payload = {"candidates": [{"content": [{"text": "part1 "}, {"text": "part2"}]}]}
    assert gateway._extract_gemini_text(payload) == "part1 part2"


def test_extract_gemini_text_no_candidates_returns_none(gateway):
    assert gateway._extract_gemini_text({"candidates": []}) is None
    assert gateway._extract_gemini_text({}) is None


def test_extract_local_text_from_message_content(gateway):
    payload = {"choices": [{"message": {"content": "local response"}}]}
    assert gateway._extract_local_text(payload) == "local response"


def test_extract_local_text_from_plain_text_field(gateway):
    payload = {"choices": [{"text": "plain completion"}]}
    assert gateway._extract_local_text(payload) == "plain completion"


def test_extract_local_text_empty_choices_returns_none(gateway):
    assert gateway._extract_local_text({"choices": []}) is None


# --------------------------------------------------------------------------
# _extract_json_payload: brace-depth matching (not regex)
# --------------------------------------------------------------------------

def test_extract_json_payload_handles_nested_braces(gateway):
    text = 'Some preamble {"a": {"b": {"c": 1}}, "d": 2} trailing text'
    result = gateway._extract_json_payload(text)
    assert json.loads(result) == {"a": {"b": {"c": 1}}, "d": 2}


def test_extract_json_payload_no_braces_returns_none(gateway):
    assert gateway._extract_json_payload("no json here at all") is None


def test_extract_json_payload_unbalanced_braces_returns_none(gateway):
    assert gateway._extract_json_payload('{"a": 1, "b": 2') is None


def test_extract_json_payload_ignores_markdown_fencing(gateway):
    text = '```json\n{"action": "freeze", "target_pid": 100}\n```'
    result = gateway._extract_json_payload(text)
    assert json.loads(result)["action"] == "freeze"


# --------------------------------------------------------------------------
# _build_token_metrics
# --------------------------------------------------------------------------

def test_token_metrics_uses_real_usage_when_provided(gateway):
    metrics = gateway._build_token_metrics(
        backend="gemini", model="gemini-2.5-pro",
        system_prompt="sys", user_prompt="usr", response_text="resp",
        usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
    )
    assert metrics["token_usage"]["total_tokens"] == 150


def test_token_metrics_estimates_when_usage_missing(gateway):
    metrics = gateway._build_token_metrics(
        backend="local", model="llama3",
        system_prompt="x" * 400, user_prompt="y" * 400, response_text="z" * 400,
        usage={},
    )
    # Estimate is len // 4 -- just confirm it's a positive, non-real-usage number.
    assert metrics["token_usage"]["prompt_tokens"] == (400 + 400) // 4


# --------------------------------------------------------------------------
# YomiRouter._evaluate_intent
# --------------------------------------------------------------------------

@pytest.fixture
def router(isolated_stamp, monkeypatch):
    from yomi_core import router as router_module

    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr(router_module, "GEMINI_API_KEY", None)
    monkeypatch.setattr(router_module, "AIR_GAPPED_MODE", True)
    return router_module.YomiRouter()


def test_router_init_logs_boot(router, isolated_stamp):
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "INITIALIZATION" for l in lines)


def test_evaluate_invalid_json_rejected(router):
    result = router._evaluate_intent("not valid json {{{")
    assert result["status"] == "REJECTED"


def test_evaluate_disallowed_action_rejected(router):
    payload = json.dumps({"action": "delete_all", "epistemic_doubt": 0, "target_pid": 100})
    result = router._evaluate_intent(payload)
    assert result["status"] == "REJECTED"


def test_evaluate_non_numeric_doubt_rejected_type_confusion_defense(router):
    payload = json.dumps({"action": "freeze", "epistemic_doubt": "not_a_number", "target_pid": 100})
    result = router._evaluate_intent(payload)
    assert result["status"] == "REJECTED"
    assert "epistemic_doubt" in result["message"]


def test_evaluate_non_integer_pid_rejected_type_confusion_defense(router):
    payload = json.dumps({"action": "freeze", "epistemic_doubt": 0, "target_pid": "not_a_pid"})
    result = router._evaluate_intent(payload)
    assert result["status"] == "REJECTED"
    assert "target_pid" in result["message"]


def test_evaluate_high_doubt_requires_self_correction(router):
    payload = json.dumps({"action": "freeze", "epistemic_doubt": 75, "target_pid": 100})
    result = router._evaluate_intent(payload)
    assert result["status"] == "SELF_CORRECTION_REQUIRED"
    assert result["doubt"] == 75


def test_evaluate_valid_low_doubt_routes_to_harness(router, monkeypatch):
    monkeypatch.setattr(
        router.harness, "process_intent",
        lambda payload: {"status": "SUCCESS", "action": "FROZEN"},
    )
    payload = json.dumps({"action": "freeze", "epistemic_doubt": 5, "target_pid": 100})
    result = router._evaluate_intent(payload)
    assert result["status"] == "SUCCESS"


def test_evaluate_unknown_action_with_low_doubt_gets_vetoed_by_harness(router):
    """
    NOTE: originally assumed action="unknown" would reach harness's
    trailing "no OS routing defined" ERROR branch. It doesn't --
    harness.py's own allowed_actions list is ["freeze", "thaw"] only (a
    stricter, separate check from router.py's allowed_actions, which
    explicitly permits "unknown" to pass ITS validation). So "unknown"
    gets VETOED by harness before ever reaching the dispatch logic. See
    test_harness.py's dead-code finding this uncovered: harness.py's
    trailing ERROR branch ("Action valid but no OS routing defined") is
    unreachable, since only "freeze"/"thaw" can ever pass _veto_check, and
    both of those are explicitly dispatched.
    """
    payload = json.dumps({"action": "unknown", "epistemic_doubt": 5, "target_pid": None})
    result = router._evaluate_intent(payload)
    assert result["status"] == "VETOED"


# --------------------------------------------------------------------------
# YomiRouter.execute_autonomous_triage: full ReAct loop
# --------------------------------------------------------------------------

def test_triage_succeeds_on_first_iteration(router, monkeypatch):
    monkeypatch.setattr(router.llm_gateway, "generate_intent", lambda ctx: VALID_INTENT_JSON)
    monkeypatch.setattr(
        router.harness, "process_intent",
        lambda payload: {"status": "SUCCESS", "action": "FROZEN"},
    )
    result = router.execute_autonomous_triage("initial forensic context")
    assert result["status"] == "SUCCESS"


def test_triage_self_corrects_on_high_doubt_then_succeeds(router, monkeypatch):
    responses = [
        json.dumps({"action": "unknown", "epistemic_doubt": 90, "target_pid": None}),
        VALID_INTENT_JSON,
    ]
    call_count = {"n": 0}

    def fake_generate(ctx):
        result = responses[call_count["n"]]
        call_count["n"] += 1
        return result

    monkeypatch.setattr(router.llm_gateway, "generate_intent", fake_generate)
    monkeypatch.setattr(
        router.harness, "process_intent",
        lambda payload: {"status": "SUCCESS", "action": "FROZEN"},
    )
    result = router.execute_autonomous_triage("context")
    assert result["status"] == "SUCCESS"
    assert call_count["n"] == 2


def test_triage_KNOWN_GAP_os_level_failure_gets_no_feedback_and_silently_retries(router, monkeypatch):
    """
    KNOWN GAP: execute_autonomous_triage's if-chain explicitly handles
    "REJECTED", "SELF_CORRECTION_REQUIRED", "SUCCESS"-and-not-vetoed, and
    "VETOED" -- but harness.process_intent() can also return whatever
    os_bridge.cryogenic_freeze()/thaw_process() returns for a LEGITIMATELY
    APPROVED action that fails at the OS level (e.g. status="GHOST_PROCESS"
    for a PID that no longer exists, or status="ERROR" for some other OS
    failure). Neither of those matches any branch in the if-chain, so the
    loop silently falls through to the next iteration WITHOUT appending
    any [SYSTEM FEEDBACK] to current_context -- unlike every other
    rejection path (REJECTED, SELF_CORRECTION_REQUIRED, VETOED all give
    the LLM a reason). The LLM has no way to know its freeze attempt
    failed and may repeat the identical response next iteration, burning
    through max_iterations with no useful signal.
    """
    monkeypatch.setattr(router.llm_gateway, "generate_intent", lambda ctx: VALID_INTENT_JSON)
    monkeypatch.setattr(
        router.harness, "process_intent",
        lambda payload: {"status": "GHOST_PROCESS", "reason": "PID no longer exists."},
    )

    result = router.execute_autonomous_triage("context")
    # Falls through all 3 iterations with identical unhelpful context,
    # eventually escalates -- documents current (gap-y) behavior.
    assert result["status"] == "ESCALATED_TO_SHADOW_NET"
    call_contexts = []

    def fake_generate(ctx):
        call_contexts.append(ctx)
        return VALID_INTENT_JSON

    monkeypatch.setattr(router.llm_gateway, "generate_intent", fake_generate)

    harness_calls = {"n": 0}

    def fake_process_intent(payload):
        harness_calls["n"] += 1
        if harness_calls["n"] == 1:
            return {"status": "VETOED", "message": "PID 5000 is protected."}
        return {"status": "SUCCESS", "action": "FROZEN"}

    monkeypatch.setattr(router.harness, "process_intent", fake_process_intent)

    result = router.execute_autonomous_triage("context")
    assert result["status"] == "SUCCESS"
    # Second call's context must include feedback about the veto.
    assert "vetoed" in call_contexts[1].lower()


def test_triage_exhausts_iterations_and_escalates_to_shadow_net(router, monkeypatch):
    always_high_doubt = json.dumps({"action": "unknown", "epistemic_doubt": 99, "target_pid": None})
    monkeypatch.setattr(router.llm_gateway, "generate_intent", lambda ctx: always_high_doubt)

    result = router.execute_autonomous_triage("context")
    assert result["status"] == "ESCALATED_TO_SHADOW_NET"


def test_triage_max_iterations_reached_is_logged(router, isolated_stamp, monkeypatch):
    always_invalid = "not valid json"
    monkeypatch.setattr(router.llm_gateway, "generate_intent", lambda ctx: always_invalid)

    router.execute_autonomous_triage("context")
    with open(isolated_stamp.ledger_file, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert any(l["action_type"] == "MAX_ITERATIONS_REACHED" for l in lines)
