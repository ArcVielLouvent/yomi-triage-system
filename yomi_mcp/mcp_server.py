import sys
import os
import json

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_mcp.sift_toolkit import SiftArsenal

# ==============================================================================
# YOMI TRIAGE SYSTEM: MCP Vault - Native Server Protocol
# Purpose: Exposes the SIFT Arsenal as a compliant Model Context Protocol (MCP)
#          Server. Allows OpenClaw/Gemini to dynamically discover and call tools.
# ==============================================================================


class YomiMCPServer:
    def __init__(self):
        self.arsenal = SiftArsenal()
        self.tool_registry = {
            "run_volatility_pslist": {
                "description": "Enumerate active processes from a memory image.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_dump_path": {
                            "type": "string",
                            "description": "Absolute path to the memory dump file.",
                        }
                    },
                    "required": ["memory_dump_path"],
                },
            },
            "run_volatility_netscan": {
                "description": "Scan memory for live network connections and suspicious sockets.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_dump_path": {
                            "type": "string",
                            "description": "Absolute path to the memory dump file.",
                        }
                    },
                    "required": ["memory_dump_path"],
                },
            },
            "run_volatility_cmdline": {
                "description": "Extract process command lines from a volatile memory image.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_dump_path": {
                            "type": "string",
                            "description": "Absolute path to the memory dump file.",
                        }
                    },
                    "required": ["memory_dump_path"],
                },
            },
            "run_volatility_yarascan": {
                "description": "Scan memory using YARA rules to identify known malware patterns.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_dump_path": {"type": "string"},
                        "yara_rules_path": {"type": "string"},
                    },
                    "required": ["memory_dump_path", "yara_rules_path"],
                },
            },
            "run_plaso_timeline": {
                "description": "Build a forensic event timeline from a disk or raw image.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_drive_path": {
                            "type": "string",
                            "description": "Absolute path to the disk or image source.",
                        },
                        "output_path": {
                            "type": "string",
                            "description": "Optional timeline output path.",
                        },
                    },
                    "required": ["target_drive_path"],
                },
            },
            "run_tsk_fls": {
                "description": "Enumerate deleted files and metadata from a disk image using TSK.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "image_path": {"type": "string"},
                    },
                    "required": ["image_path"],
                },
            },
            "run_tsk_img_stat": {
                "description": "Inspect filesystem metadata for a disk image using TSK.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "image_path": {"type": "string"},
                    },
                    "required": ["image_path"],
                },
            },
            "run_tsk_icat": {
                "description": "Extract a file by inode from a disk image.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "image_path": {"type": "string"},
                        "inode_id": {"type": "string"},
                        "output_path": {"type": "string"},
                    },
                    "required": ["image_path", "inode_id"],
                },
            },
            "run_tshark_pcap": {
                "description": "Inspect network captures for suspicious traffic patterns.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string"},
                    },
                    "required": ["pcap_path"],
                },
            },
            "run_radare2_analysis": {
                "description": "Analyze a binary with Radare2 for embedded IOCs and suspicious strings.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string"},
                    },
                    "required": ["binary_path"],
                },
            },
            "run_bulk_extractor": {
                "description": "Extract forensic artifacts from image or PCAP sources using bulk_extractor.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string"},
                        "output_dir": {"type": "string"},
                    },
                    "required": ["target_path"],
                },
            },
            "run_strings_grep": {
                "description": "Search a binary or image for suspicious strings using strings+grep.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string"},
                        "pattern": {"type": "string"},
                    },
                    "required": ["target_path", "pattern"],
                },
            },
            "run_yara_scan": {
                "description": "Run YARA signature scanning against a target file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string"},
                        "rule_path": {"type": "string"},
                    },
                    "required": ["target_path", "rule_path"],
                },
            },
            "run_reglookup": {
                "description": "Parse Windows registry hive files for forensic indicators.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "registry_path": {"type": "string"},
                    },
                    "required": ["registry_path"],
                },
            },
            "run_mftparser": {
                "description": "Parse an NTFS MFT for deleted or hidden file records.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "mft_path": {"type": "string"},
                    },
                    "required": ["mft_path"],
                },
            },
            "run_ssdeep": {
                "description": "Compute ssdeep similarity hashes for a file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string"},
                    },
                    "required": ["target_path"],
                },
            },
            "run_scalpel": {
                "description": "Carve file fragments from an image using Scalpel.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "image_path": {"type": "string"},
                        "config_path": {"type": "string"},
                        "output_dir": {"type": "string"},
                    },
                    "required": ["image_path"],
                },
            },
            "run_volatility_windows_malfind": {
                "description": "Scan Windows memory for injected code or hidden PEs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_dump_path": {
                            "type": "string",
                            "description": "Absolute path to the memory dump file.",
                        }
                    },
                    "required": ["memory_dump_path"],
                },
            },
            "run_volatility_linux_malfind": {
                "description": "Scan Linux memory for injected code or hidden PEs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_dump_path": {
                            "type": "string",
                            "description": "Absolute path to the memory dump file.",
                        }
                    },
                    "required": ["memory_dump_path"],
                },
            },
        }

    def list_tools(self) -> str:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "result": {
                    "tools": [
                        {"name": name, **schema}
                        for name, schema in self.tool_registry.items()
                    ]
                },
                "id": 1,
            },
            indent=4,
        )

    def _validate_string_argument(
        self, arguments: dict, key: str, required: bool = True
    ) -> tuple[bool, str]:
        value = arguments.get(key)
        if required and (not isinstance(value, str) or not value):
            return (
                False,
                f"Argument '{key}' is required and must be a non-empty string.",
            )
        return True, value

    def call_tool(self, tool_name: str, arguments: dict) -> str:
        if tool_name not in self.tool_registry:
            return json.dumps({"error": f"Tool '{tool_name}' not found in MCP Vault."})

        print(f"\n[MCP SERVER] Intercepted LLM request to execute: {tool_name}")

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
                args.get("output_path", "/tmp/timeline.plaso"),
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
            validation_map = {
                "memory_dump_path": lambda a: self._validate_string_argument(
                    a, "memory_dump_path"
                ),
                "target_drive_path": lambda a: self._validate_string_argument(
                    a, "target_drive_path"
                ),
                "image_path": lambda a: self._validate_string_argument(a, "image_path"),
                "pcap_path": lambda a: self._validate_string_argument(a, "pcap_path"),
                "binary_path": lambda a: self._validate_string_argument(
                    a, "binary_path"
                ),
                "target_path": lambda a: self._validate_string_argument(
                    a, "target_path"
                ),
                "pattern": lambda a: self._validate_string_argument(a, "pattern"),
                "rule_path": lambda a: self._validate_string_argument(a, "rule_path"),
                "registry_path": lambda a: self._validate_string_argument(
                    a, "registry_path"
                ),
                "mft_path": lambda a: self._validate_string_argument(a, "mft_path"),
                "inode_id": lambda a: self._validate_string_argument(a, "inode_id"),
            }

            parameters = self.tool_registry[tool_name]["parameters"]
            properties = parameters.get("properties", {})
            required = set(parameters.get("required", []))

            for key, validator in validation_map.items():
                if key not in properties:
                    continue
                if key not in arguments and key not in required:
                    continue
                valid, message = validator(arguments)
                if not valid:
                    return json.dumps({"error": message})

            result = tool_map[tool_name](arguments)
        except KeyError as exc:
            return json.dumps(
                {"error": f"Missing required argument for {tool_name}: {exc}"}
            )
        except Exception as exc:
            return json.dumps({"error": f"Unhandled tool execution exception: {exc}"})

        return json.dumps({"jsonrpc": "2.0", "result": result, "id": 2})
