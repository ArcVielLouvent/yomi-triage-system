import sys
import json
import argparse
import os
import traceback

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from yomi_audit.stamp import ImmutableStamp
from yomi_engine.library import OmniLibrary
from yomi_engine.remediator import ReverserEngine
from yomi_engine.swarm import SwarmOrchestrator
from yomi_engine.hunter import OmniVectorHunter
from yomi_engine.sandbox import SandboxEnvironment 

# ==============================================================================
# YOMI TRIAGE SYSTEM: Core Module - The Ouroboros Router v1.5 (FINAL BACKEND)
# ==============================================================================

class YomiRouter:
    def __init__(self, stance="shogun"):
        self.stance = stance
        self.audit = ImmutableStamp()
        self.library = OmniLibrary()
        self.reverser = ReverserEngine()
        self.swarm = SwarmOrchestrator()
        self.hunter = OmniVectorHunter()
        self.sandbox = SandboxEnvironment()
        
        self.audit.record_action(
            agent_name="SYSTEM_BOOT",
            action_type="INITIALIZATION",
            description=f"Yomi Core Router started with Full 6-Pillar Backend.",
            raw_command="yomi_core/router.py"
        )

    def send_response(self, request_id, result_dict, is_error=False):
        response = {"jsonrpc": "2.0", "id": request_id}
        if is_error:
            response["error"] = {"code": -32000, "message": str(result_dict)}
        else:
            response["result"] = result_dict
        print(json.dumps(response))
        sys.stdout.flush()

    def handle_initialize(self, req_id):
        response = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "yomi-enterprise-gateway", "version": "1.5.0"}
        }
        self.send_response(req_id, response)
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        sys.stdout.flush()

    def handle_tools_list(self, req_id):
        response = {
            "tools": [
                {
                    "name": "yomi_threat_intel",
                    "description": "Query the Yomi Omni-Library for CVEs.",
                    "inputSchema": {"type": "object", "properties": {"artifact_name": {"type": "string"}}, "required": ["artifact_name"]}
                },
                {
                    "name": "yomi_remediator",
                    "description": "Draft a bash remediation script (playbook).",
                    "inputSchema": {"type": "object", "properties": {"playbook_name": {"type": "string"}, "bash_commands": {"type": "array", "items": {"type": "string"}}, "reasoning": {"type": "string"}}, "required": ["playbook_name", "bash_commands", "reasoning"]}
                },
                {
                    "name": "yomi_swarm_scan",
                    "description": "Deploy micro-agents to scan system simultaneously.",
                    "inputSchema": {"type": "object", "properties": {"target_scope": {"type": "string"}}, "required": ["target_scope"]}
                },
                {
                    "name": "yomi_root_cause_hunt",
                    "description": "Reverse-track an artifact through system logs.",
                    "inputSchema": {"type": "object", "properties": {"artifact_name": {"type": "string"}}, "required": ["artifact_name"]}
                },
                {
                    "name": "yomi_deploy_honeypot",
                    "description": "Deploy phantom decoys (files/ports) to trap attackers.",
                    "inputSchema": {"type": "object", "properties": {}}
                },
                {
                    "name": "yomi_lazarus_detonate",
                    "description": "Move a suspicious sleeping file to an isolated sandbox to observe its behavior.",
                    "inputSchema": {
                        "type": "object", 
                        "properties": {"artifact_path": {"type": "string", "description": "Path to the file to detonate."}},
                        "required": ["artifact_path"]
                    }
                }
            ]
        }
        self.send_response(req_id, response)

    def listen(self):
        for line in sys.stdin:
            line = line.strip()
            if not line: continue
            try:
                request = json.loads(line)
                method = request.get("method")
                req_id = request.get("id")

                if req_id is None: continue

                if method == "initialize":
                    self.handle_initialize(req_id)
                    continue
                if method == "tools/list":
                    self.handle_tools_list(req_id)
                    continue
                    
                if method == "tools/call":
                    tool_params = request.get("params", {}).get("arguments", {})
                    tool_name = request.get("params", {}).get("name", "")
                    
                    if tool_name == "yomi_threat_intel":
                        artifact = tool_params.get("artifact_name", "")
                        self.audit.record_action("OpenClaw", "THREAT_INTEL", f"Library query: {artifact}")
                        self.send_response(req_id, {"content": [{"type": "text", "text": json.dumps(self.library.analyze_artifact(artifact, []))}]})
                    
                    elif tool_name == "yomi_remediator":
                        name = tool_params.get("playbook_name", "fix")
                        cmds = tool_params.get("bash_commands", [])
                        self.audit.record_action("OpenClaw", "DRAFT_PLAYBOOK", f"Drafting: {name}")
                        self.send_response(req_id, {"content": [{"type": "text", "text": json.dumps(self.reverser.draft_playbook(name, cmds, "Threat mitigation"))}]})
                        
                    elif tool_name == "yomi_swarm_scan":
                        self.audit.record_action("OpenClaw", "DEPLOY_SWARM", "Scanning system")
                        self.send_response(req_id, {"content": [{"type": "text", "text": json.dumps(self.swarm.deploy_swarm())}]})
                        
                    elif tool_name == "yomi_root_cause_hunt":
                        artifact = tool_params.get("artifact_name", "unknown")
                        self.audit.record_action("OpenClaw", "ROOT_CAUSE_HUNT", f"Tracking {artifact}")
                        self.send_response(req_id, {"content": [{"type": "text", "text": json.dumps(self.hunter.hunt_root_cause(artifact))}]})
                    
                    elif tool_name == "yomi_deploy_honeypot":
                        self.audit.record_action("OpenClaw-Main", "DEPLOY_HONEYPOT", "Deploying system decoys")
                        self.send_response(req_id, {"content": [{"type": "text", "text": json.dumps(self.sandbox.deploy_honeypot())}]})
                        
                    elif tool_name == "yomi_lazarus_detonate":
                        artifact = tool_params.get("artifact_path", "unknown_file.exe")
                        self.audit.record_action("OpenClaw-Main", "DETONATE_SANDBOX", f"Detonating {artifact} in Lazarus Chamber")
                        self.send_response(req_id, {"content": [{"type": "text", "text": json.dumps(self.sandbox.detonate_artifact(artifact))}]})
                    
                    else:
                        self.send_response(req_id, f"Tool {tool_name} not found.", True)
                    continue

                self.send_response(req_id, f"Method {method} not supported.", True)

            except json.JSONDecodeError: pass
            except Exception as e:
                self.audit.record_action("ROUTER", "ERROR", f"Crash: {str(e)}", traceback.format_exc())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stance', type=str, default='shogun')
    args = parser.parse_args()
    YomiRouter(stance=args.stance).listen()

if __name__ == "__main__":
    main()