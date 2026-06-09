import sys
import os
import json
import re
import shlex
import concurrent.futures
import threading
from typing import Union

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_mcp.sift_toolkit import SiftArsenal
from yomi_mcp.harness import YomiHarness

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - Native Server Protocol (v11.0)
# Purpose: Exposes SIFT Arsenal and Harness as a compliant Model Context Protocol.
#          - Perfect Thread Accounting: Eradicates Queue-Freezing DoS via Worker Wrappers.
#          - VVIP OS Routing: Freeze/Thaw commands completely bypass threading locks.
#          - Context Shield: Truncates massive tool outputs to protect LLM memory.
# ==============================================================================


class YomiMCPServer:
    def __init__(self):
        self.arsenal = SiftArsenal()
        self.harness = YomiHarness()

        self.MAX_WORKERS = 5
        self.worker_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.MAX_WORKERS
        )

        # Load Shedding State
        self.active_tasks = 0
        self.task_lock = threading.Lock()

        self.READ_VAULTS = [
            os.path.realpath(p)
            for p in [
                "/tmp",
                "/var/tmp",
                "/mnt",
                "/home",
                "/workspace",
                "/data",
                "/media",
                "/opt/yomi",
            ]
        ]

        self.WRITE_VAULTS = [
            os.path.realpath(p)
            for p in [
                "/tmp",
                "/var/tmp",
                "/workspace/output",
                "/data/output",
                "/opt/yomi/output",
            ]
        ]

        self.tool_registry = {
            "run_cryogenic_freeze": {
                "parameters": {
                    "properties": {"target_pid": {"type": "string"}},
                    "required": ["target_pid"],
                }
            },
            "run_thaw_process": {
                "parameters": {
                    "properties": {"target_pid": {"type": "string"}},
                    "required": ["target_pid"],
                }
            },
            "run_volatility_pslist": {
                "parameters": {
                    "properties": {"memory_dump_path": {"type": "string"}},
                    "required": ["memory_dump_path"],
                }
            },
            "run_volatility_netscan": {
                "parameters": {
                    "properties": {"memory_dump_path": {"type": "string"}},
                    "required": ["memory_dump_path"],
                }
            },
            "run_volatility_cmdline": {
                "parameters": {
                    "properties": {"memory_dump_path": {"type": "string"}},
                    "required": ["memory_dump_path"],
                }
            },
            "run_volatility_yarascan": {
                "parameters": {
                    "properties": {
                        "memory_dump_path": {"type": "string"},
                        "yara_rules_path": {"type": "string"},
                    },
                    "required": ["memory_dump_path", "yara_rules_path"],
                }
            },
            "run_plaso_timeline": {
                "parameters": {
                    "properties": {
                        "target_drive_path": {"type": "string"},
                        "output_path": {"type": "string"},
                    },
                    "required": ["target_drive_path"],
                }
            },
            "run_tsk_fls": {
                "parameters": {
                    "properties": {"image_path": {"type": "string"}},
                    "required": ["image_path"],
                }
            },
            "run_tsk_img_stat": {
                "parameters": {
                    "properties": {"image_path": {"type": "string"}},
                    "required": ["image_path"],
                }
            },
            "run_tsk_icat": {
                "parameters": {
                    "properties": {
                        "image_path": {"type": "string"},
                        "inode_id": {"type": "string"},
                        "output_path": {"type": "string"},
                    },
                    "required": ["image_path", "inode_id"],
                }
            },
            "run_tshark_pcap": {
                "parameters": {
                    "properties": {"pcap_path": {"type": "string"}},
                    "required": ["pcap_path"],
                }
            },
            "run_radare2_analysis": {
                "parameters": {
                    "properties": {"binary_path": {"type": "string"}},
                    "required": ["binary_path"],
                }
            },
            "run_bulk_extractor": {
                "parameters": {
                    "properties": {
                        "target_path": {"type": "string"},
                        "output_dir": {"type": "string"},
                    },
                    "required": ["target_path"],
                }
            },
            "run_strings_grep": {
                "parameters": {
                    "properties": {
                        "target_path": {"type": "string"},
                        "pattern": {"type": "string"},
                    },
                    "required": ["target_path", "pattern"],
                }
            },
            "run_yara_scan": {
                "parameters": {
                    "properties": {
                        "target_path": {"type": "string"},
                        "rule_path": {"type": "string"},
                    },
                    "required": ["target_path", "rule_path"],
                }
            },
            "run_reglookup": {
                "parameters": {
                    "properties": {"registry_path": {"type": "string"}},
                    "required": ["registry_path"],
                }
            },
            "run_mftparser": {
                "parameters": {
                    "properties": {"mft_path": {"type": "string"}},
                    "required": ["mft_path"],
                }
            },
            "run_ssdeep": {
                "parameters": {
                    "properties": {"target_path": {"type": "string"}},
                    "required": ["target_path"],
                }
            },
            "run_scalpel": {
                "parameters": {
                    "properties": {
                        "image_path": {"type": "string"},
                        "config_path": {"type": "string"},
                        "output_dir": {"type": "string"},
                    },
                    "required": ["image_path"],
                }
            },
            "run_volatility_windows_malfind": {
                "parameters": {
                    "properties": {"memory_dump_path": {"type": "string"}},
                    "required": ["memory_dump_path"],
                }
            },
            "run_volatility_linux_malfind": {
                "parameters": {
                    "properties": {"memory_dump_path": {"type": "string"}},
                    "required": ["memory_dump_path"],
                }
            },
        }

    def list_tools(self, request_id: Union[int, str, None] = None) -> str:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "result": {
                    "tools": [
                        {"name": name, **schema}
                        for name, schema in self.tool_registry.items()
                    ]
                },
                "id": request_id,
            },
            indent=4,
        )

    def _validate_dynamic_arguments(
        self, tool_name: str, arguments: dict
    ) -> tuple[bool, str, dict]:
        parameters = self.tool_registry[tool_name]["parameters"]
        properties = parameters.get("properties", {})
        required_keys = set(parameters.get("required", []))
        sanitized_args = {}

        for key, prop_schema in properties.items():
            value = arguments.get(key)

            if key in required_keys and (value is None or str(value).strip() == ""):
                return False, f"VETO: Argument '{key}' is required but missing.", {}

            if value is not None:
                clean_value = str(value).strip()

                if "pid" in key:
                    if not clean_value.isdigit():
                        return False, f"VETO: '{key}' must be strictly numeric.", {}
                    sanitized_args[key] = clean_value

                elif any(
                    x in key
                    for x in ["path", "dir", "file", "image", "pcap", "binary", "mft"]
                ):
                    if ".." in clean_value:
                        return (
                            False,
                            f"VETO: Path traversal payload ('..') detected.",
                            {},
                        )

                    true_physical_path = os.path.realpath(clean_value)
                    is_write_intent = "output" in key or "dir" in key
                    allowed_vaults = (
                        self.WRITE_VAULTS if is_write_intent else self.READ_VAULTS
                    )

                    is_authorized = False
                    for vault in allowed_vaults:
                        try:
                            if os.path.commonpath([vault, true_physical_path]) == vault:
                                is_authorized = True
                                break
                        except ValueError:
                            continue

                    if not is_authorized:
                        return (
                            False,
                            f"VETO: Target '{true_physical_path}' violates {'WRITE' if is_write_intent else 'READ'} vault boundaries.",
                            {},
                        )

                    sanitized_args[key] = true_physical_path

                else:
                    if re.search(r"(\$\(|`|\||;|&&|\|\||>)", clean_value):
                        return (
                            False,
                            f"VETO: Shell chaining/execution operator detected in '{key}'.",
                            {},
                        )
                    sanitized_args[key] = clean_value
            else:
                sanitized_args[key] = ""

        return True, "", sanitized_args

    def _worker_execution_wrapper(self, tool_func, args) -> str:
        """
        Ensures the active_tasks counter is ONLY decremented when the physical
        worker thread actually finishes the task or dies, completely eliminating
        the state-mismatch race condition caused by Main Thread Timeouts.
        """
        try:
            return tool_func(args)
        finally:
            with self.task_lock:
                if self.active_tasks > 0:
                    self.active_tasks -= 1

    def call_tool(
        self, tool_name: str, arguments: dict, request_id: Union[int, str, None] = None
    ) -> str:
        if tool_name not in self.tool_registry:
            return json.dumps(
                {"error": f"Tool '{tool_name}' not found.", "id": request_id}
            )

        print(f"\n[MCP SERVER] Intercepted LLM request to execute: {tool_name}")

        is_valid, err_msg, safe_args = self._validate_dynamic_arguments(
            tool_name, arguments
        )
        if not is_valid:
            print(f"[MCP SERVER] [BLOCKED] {err_msg}")
            return json.dumps({"error": err_msg, "id": request_id})

        if tool_name == "run_cryogenic_freeze":
            result = self.harness.validate_and_execute(
                "freeze", safe_args["target_pid"]
            )
            return json.dumps({"jsonrpc": "2.0", "result": result, "id": request_id})
        elif tool_name == "run_thaw_process":
            result = self.harness.validate_and_execute("thaw", safe_args["target_pid"])
            return json.dumps({"jsonrpc": "2.0", "result": result, "id": request_id})

        # Pre-emptive Load Shedding Check
        with self.task_lock:
            if self.active_tasks >= self.MAX_WORKERS:
                print(
                    f"[MCP SERVER] [VETO] Server overloaded. Dropping request for {tool_name}."
                )
                return json.dumps(
                    {
                        "error": f"SYSTEM OVERLOAD: All {self.MAX_WORKERS} forensic agents are currently occupied by hanging or heavy tasks. To prevent Server Queue Freeze, this request is instantly rejected.",
                        "id": request_id,
                    }
                )
            self.active_tasks += 1

        tool_map = {
            "run_volatility_pslist": lambda args: self.arsenal.run_volatility_pslist(
                args["memory_dump_path"]
            ),
            "run_volatility_netscan": lambda args: self.arsenal.run_volatility_netscan(
                args["memory_dump_path"]
            ),
            "run_volatility_cmdline": lambda args: self.arsenal.run_volatility_cmdline(
                args["memory_dump_path"]
            ),
            "run_volatility_yarascan": lambda args: self.arsenal.run_volatility_yarascan(
                args["memory_dump_path"], args["yara_rules_path"]
            ),
            "run_plaso_timeline": lambda args: self.arsenal.run_plaso_timeline(
                args["target_drive_path"],
                args.get("output_path") or "/tmp/timeline.plaso",
            ),
            "run_tsk_fls": lambda args: self.arsenal.run_tsk_fls(args["image_path"]),
            "run_tsk_img_stat": lambda args: self.arsenal.run_tsk_img_stat(
                args["image_path"]
            ),
            "run_tsk_icat": lambda args: self.arsenal.run_tsk_icat(
                args["image_path"], args["inode_id"], args.get("output_path")
            ),
            "run_tshark_pcap": lambda args: self.arsenal.run_tshark_pcap(
                args["pcap_path"]
            ),
            "run_radare2_analysis": lambda args: self.arsenal.run_radare2_analysis(
                args["binary_path"]
            ),
            "run_bulk_extractor": lambda args: self.arsenal.run_bulk_extractor(
                args["target_path"], args.get("output_dir")
            ),
            "run_strings_grep": lambda args: self.arsenal.run_strings_grep(
                args["target_path"], args["pattern"]
            ),
            "run_yara_scan": lambda args: self.arsenal.run_yara_scan(
                args["target_path"], args["rule_path"]
            ),
            "run_reglookup": lambda args: self.arsenal.run_reglookup(
                args["registry_path"]
            ),
            "run_mftparser": lambda args: self.arsenal.run_mftparser(args["mft_path"]),
            "run_ssdeep": lambda args: self.arsenal.run_ssdeep(args["target_path"]),
            "run_scalpel": lambda args: self.arsenal.run_scalpel(
                args["image_path"], args.get("config_path"), args.get("output_dir")
            ),
            "run_volatility_windows_malfind": lambda args: self.arsenal.run_volatility_windows_malfind(
                args["memory_dump_path"]
            ),
            "run_volatility_linux_malfind": lambda args: self.arsenal.run_volatility_linux_malfind(
                args["memory_dump_path"]
            ),
        }

        try:
            # Execute through the wrapper to enforce perfect accounting
            future = self.worker_pool.submit(
                self._worker_execution_wrapper, tool_map[tool_name], safe_args
            )
            raw_result = future.result(timeout=300)
        except concurrent.futures.TimeoutError:
            print(
                f"[YOMI-MCP] [WARNING] Execution Timeout. Tool '{tool_name}' orphaned."
            )
            return json.dumps(
                {
                    "error": f"Execution Timeout: Tool '{tool_name}' exceeded 5-minute limit. Operation orphaned in background.",
                    "id": request_id,
                }
            )
        except Exception as exc:
            print(f"[YOMI-MCP] [INTERNAL ERROR] Tool execution failed: {exc}")
            return json.dumps(
                {"error": "Internal tool execution error occurred.", "id": request_id}
            )

        # LLM Context Window Protection
        result_str = str(raw_result)
        MAX_CHARS = 100000
        if len(result_str) > MAX_CHARS:
            result_str = (
                result_str[:MAX_CHARS]
                + "\n\n...[TRUNCATED BY YOMI VAULT: Output exceeds 100KB safety limit]..."
            )

        return json.dumps({"jsonrpc": "2.0", "result": result_str, "id": request_id})
