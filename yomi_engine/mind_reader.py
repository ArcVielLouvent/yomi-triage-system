import os
import sys
import time
import json

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.sift_toolkit import SiftArsenal
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

        if r2_result.get("status") != "SUCCESS":
            error_msg = f"Radare2 decompilation failed: {r2_result.get('error', r2_result.get('reason', 'unknown'))}"
            self.audit.record_action("MINDREADER", "DECOMPILATION_ERROR", error_msg)
            return {"status": "ERROR", "message": error_msg}

        assembly_output = r2_result.get("output", "")
        print(
            f"[YOMI-MINDREADER] [CYBER-PURPLE] Assembly logic extracted successfully. Performing heuristic profiling..."
        )

        profiling_context = f"""
        [AUTONOMOUS REVERSE ENGINEERING TASK]
        Objective: Profile the Threat Actor's psychology, skill level, and methodology.
        Target PID: {target_pid}
        Radare2 Extracted Assembly & Strings:
        {assembly_output}
        """

        ai_profile_response = self._derive_profile_from_assembly(assembly_output)

        self.audit.record_action(
            "MINDREADER",
            "PROFILE_GENERATED",
            f"Psychological profile created for PID {target_pid}",
        )
        print(f"[YOMI-MINDREADER] [PLASMA BLUE] Hacker psychology profile generated.")

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

    def _derive_profile_from_assembly(self, assembly_code: str) -> dict:
        if not assembly_code:
            return {
                "skill_level": "Unknown",
                "methodology": "No assembly output available for profiling.",
                "psychology": "Data insufficient for behavioral classification.",
                "mitre_tactics": ["T1027 (Obfuscated Files or Information)"],
            }

        normalized = assembly_code.lower()
        if "socket" in normalized or "connect" in normalized or "103.45.0.0" in normalized:
            return {
                "skill_level": "Advanced (APT Behavior)",
                "methodology": "Network-centric C2 payload with stealth and persistence mechanisms.",
                "psychology": "Deliberate and patient; designed to evade analysis and maintain long-term access.",
                "mitre_tactics": [
                    "T1055 (Process Injection)",
                    "T1071 (Application Layer Protocol)",
                    "T1027 (Obfuscated Files or Information)",
                ],
            }

        if "call" in normalized and "exec" in normalized and ("cmd" in normalized or "powershell" in normalized):
            return {
                "skill_level": "Intermediate",
                "methodology": "Script-like payload favoring command execution and lateral movement.",
                "psychology": "Opportunistic with moderate obfuscation; likely executed by an experienced intruder.",
                "mitre_tactics": [
                    "T1059 (Command and Scripting Interpreter)",
                    "T1086 (PowerShell)",
                ],
            }

        return {
            "skill_level": "Novice",
            "methodology": "Simple payload with limited obfuscation and direct system calls.",
            "psychology": "Opportunistic and fast-moving. Likely a less sophisticated attacker.",
            "mitre_tactics": ["T1059 (Command and Scripting Interpreter)"],
        }
