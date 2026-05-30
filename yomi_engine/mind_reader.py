import os
import sys
import time
import json

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.sift_toolkit import SiftArsenal
from yomi_core.router import OpenClawGateway
from yomi_engine.library import OmniLibrary

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Mind-Reader Decompiler (v2.0)
# Purpose: Deep Reverse Engineering & Threat Actor Profiling.
#          Translates compiled binaries (ELF/EXE) into assembly using Radare2,
#          then leverages the OpenClaw LLM to build a psychological profile of the hacker.
# ==============================================================================


class MindReaderDecompiler:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.arsenal = SiftArsenal()
        self.openclaw = OpenClawGateway()
        self.library = OmniLibrary()

    def decompile_and_profile(self, binary_path: str, target_pid: int) -> dict:
        """
        Executes Radare2 on the isolated malware, extracts assembly logic,
        and sends the hex/assembly strings to the LLM for psychological profiling.
        """
        print(
            f"\n[YOMI-MINDREADER] [VOID BLACK] Initiating deep decompilation on {binary_path}..."
        )

        # 1. Execute Type-Safe Radare2 Wrapper
        r2_result = self.arsenal.run_radare2_analysis(binary_path)

        if r2_result.get("status") not in ["SUCCESS", "MOCK_SUCCESS"]:
            error_msg = f"Radare2 decompilation failed: {r2_result.get('reason')}"
            self.audit.record_action("MINDREADER", "DECOMPILATION_ERROR", error_msg)
            return {"status": "ERROR", "message": error_msg}

        assembly_output = r2_result.get("output", "")
        print(
            f"[YOMI-MINDREADER] [CYBER-PURPLE] Assembly logic extracted successfully. Routing to OpenClaw AI..."
        )

        # 2. Assemble the profiling prompt for the LLM
        profiling_context = f"""
        [AUTONOMOUS REVERSE ENGINEERING TASK]
        Objective: Profile the Threat Actor's psychology, skill level, and methodology.
        Target PID: {target_pid}
        Radare2 Extracted Assembly & Strings:
        {assembly_output}
        
        Analyze the code structure. Is it a script-kiddie using off-the-shelf tools, 
        or an advanced persistent threat (APT) using custom obfuscation?
        """

        # 3. Request LLM Analysis
        # In a live environment, this uses a specific prompt template via OpenClaw.
        # Here we simulate the LLM's psychological assessment based on assembly heuristics.
        ai_profile_response = self._simulate_llm_profiling(assembly_output)

        self.audit.record_action(
            "MINDREADER",
            "PROFILE_GENERATED",
            f"Psychological profile created for PID {target_pid}",
        )
        print(f"[YOMI-MINDREADER] [PLASMA BLUE] Hacker psychology profile generated.")

        # Feed the generated profile BACK into the Omni-Library database
        new_threat_intel = {
            "target": f"Auto-Learned_Threat_PID_{target_pid}",
            "description": f"Autonomously profiled by Mind-Reader: {ai_profile_response['methodology']}",
            "indicators": ai_profile_response["mitre_tactics"],
        }

        with self.library.database_lock:
            self.library.database.append(new_threat_intel)
            # Call atomic save to persist knowledge to disk
            temp_file = self.library.db_file + ".tmp"
            with open(temp_file, "w") as f:
                json.dump(self.library.database, f, indent=4)
            os.replace(temp_file, self.library.db_file)

        print(
            f"[YOMI-MINDREADER] [VOID BLACK] Threat intel permanently injected into Omni-Library RAG Database."
        )
        self.audit.record_action(
            "MINDREADER",
            "KNOWLEDGE_UPDATED",
            "New APT signature saved to local intelligence library.",
        )

        return {
            "status": "SUCCESS",
            "target_pid": target_pid,
            "hacker_profile": ai_profile_response,
        }

    def _simulate_llm_profiling(self, assembly_code: str) -> dict:
        """Mocks the LLM's response to the psychological profiling prompt."""
        time.sleep(2)  # Simulating LLM thinking time

        if "socket" in assembly_code.lower() or "103.45.0.0" in assembly_code:
            return {
                "skill_level": "Intermediate to Advanced (APT Behavior)",
                "methodology": "Custom C2 beaconing. The attacker favors stealth and lateral movement over immediate destruction.",
                "psychology": "Calculated and patient. The code uses stripped symbols, indicating a deliberate attempt to frustrate forensic analysts.",
                "mitre_tactics": [
                    "T1055 (Process Injection)",
                    "T1071 (Application Layer Protocol)",
                ],
            }
        else:
            return {
                "skill_level": "Novice (Script Kiddie)",
                "methodology": "Unobfuscated standard reverse shell payload.",
                "psychology": "Opportunistic. Looking for quick wins rather than long-term persistence.",
                "mitre_tactics": ["T1059 (Command and Scripting Interpreter)"],
            }


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    print("\n[+] Powering up the Mind-Reader Decompiler...")
    decompiler = MindReaderDecompiler()

    # Path to the malware previously secured by the Lazarus Chamber
    mock_binary_path = "/workspaces/yomi-triage-system/yomi_data/lazarus_chamber/isolated_target_4092_mock.bin"

    result = decompiler.decompile_and_profile(mock_binary_path, 4092)

    if result["status"] == "SUCCESS":
        profile = result["hacker_profile"]
        print("\n" + "=" * 60)
        print("[THREAT ACTOR PSYCHOLOGICAL PROFILE]")
        print("=" * 60)
        print(f"Skill Level  : {profile['skill_level']}")
        print(f"Methodology  : {profile['methodology']}")
        print(f"Psychology   : {profile['psychology']}")
        print(f"MITRE Tactics: {', '.join(profile['mitre_tactics'])}")
        print("=" * 60 + "\n")
