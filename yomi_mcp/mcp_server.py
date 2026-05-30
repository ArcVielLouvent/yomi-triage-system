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
        # Define the exact schemas expected by MCP-compliant LLMs
        self.tool_registry = {
            "run_volatility_netscan": {
                "description": "Scans memory dump for active/hidden network connections.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_dump_path": {
                            "type": "string",
                            "description": "Absolute path to the RAM dump.",
                        }
                    },
                    "required": ["memory_dump_path"],
                },
            },
            "run_plaso_timeline": {
                "description": "Extracts super-timeline from an entire disk image.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_drive_path": {
                            "type": "string",
                            "description": "Path to the disk image (/dev/sda1).",
                        }
                    },
                    "required": ["target_drive_path"],
                },
            },
        }

    def list_tools(self) -> str:
        """MCP Standard: Returns available tools and their schemas to the LLM."""
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

    def call_tool(self, tool_name: str, arguments: dict) -> str:
        """MCP Standard: Executes a tool based on structured LLM requests."""
        if tool_name not in self.tool_registry:
            return json.dumps({"error": f"Tool '{tool_name}' not found in MCP Vault."})

        print(f"\n[MCP SERVER] Intercepted LLM request to execute: {tool_name}")

        # Route to the SiftArsenal type-safe wrappers
        if tool_name == "run_volatility_netscan":
            memory_dump_path = arguments.get("memory_dump_path")
            if not isinstance(memory_dump_path, str) or not memory_dump_path:
                return json.dumps(
                    {"error": "Argument 'memory_dump_path' is required and must be a non-empty string."}
                )
            result = self.arsenal.run_volatility_netscan(memory_dump_path)
        elif tool_name == "run_plaso_timeline":
            target_drive_path = arguments.get("target_drive_path")
            if not isinstance(target_drive_path, str) or not target_drive_path:
                return json.dumps(
                    {"error": "Argument 'target_drive_path' is required and must be a non-empty string."}
                )
            result = self.arsenal.run_plaso_timeline(target_drive_path)
        else:
            result = {"status": "ERROR", "reason": "Implementation pending."}

        return json.dumps({"jsonrpc": "2.0", "result": result, "id": 2})


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    mcp = YomiMCPServer()

    print("[+] Testing MCP list_tools() protocol:")
    print(mcp.list_tools())

    print("\n[+] Testing MCP call_tool() protocol (Mocking LLM intent):")
    mock_request = {"memory_dump_path": "/tmp/ram.raw"}
    print(mcp.call_tool("run_volatility_netscan", mock_request))
