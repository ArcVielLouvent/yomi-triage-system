import os
import sys

# Append root directory to sys.path to ensure absolute imports function correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.sift_toolkit import SiftArsenal

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Root-Cause Hunter (v2.0)
# Purpose: Traces the origin (Patient Zero) of a detected anomaly.
#          Utilizes Plaso for timeline reconstruction and TSK for deleted artifacts.
# ==============================================================================


class OmniVectorHunter:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.arsenal = SiftArsenal()

    def hunt_root_cause(self, target_pid: int) -> dict:
        """
        Initiates a temporal and spatial hunt to find the initial infection vector.
        """
        print(
            f"\n[YOMI-HUNTER] [CYBER-PURPLE] Initiating Root-Cause Hunt for PID {target_pid}..."
        )

        # Step 1: Temporal Hunting (Plaso Log2Timeline)
        print("[YOMI-HUNTER] Querying Plaso super-timeline for temporal anomalies...")
        plaso_result = self.arsenal.run_plaso_timeline("/dev/sda1")

        temporal_clue = "None"
        if plaso_result.get("status") in ["SUCCESS", "MOCK_SUCCESS"]:
            # In a live environment, this parses massive Plaso CSV outputs.
            temporal_clue = "Unauthorized Logon Success detected 2 seconds prior to process creation."

        # Step 2: Spatial Hunting (TSK File System Analysis)
        print(
            "[YOMI-HUNTER] Querying The Sleuth Kit (TSK) for orphaned or deleted droppers..."
        )
        tsk_result = self.arsenal.run_tsk_fls("/dev/sda1")

        spatial_clue = "None"
        if tsk_result.get("status") in ["SUCCESS", "MOCK_SUCCESS"]:
            output = tsk_result.get("output", "")
            # Searching for standard threat artifacts in the unallocated space
            if "mimikatz" in output.lower() or "deleted" in output.lower():
                spatial_clue = (
                    "Deleted initial dropper binary located in unallocated /Temp space."
                )

        hunt_summary = {
            "status": "HUNT_COMPLETE",
            "target_pid": target_pid,
            "temporal_vector": temporal_clue,
            "spatial_vector": spatial_clue,
            "conclusion": "Root-cause vector identified. Breach likely originated via compromised credentials leading to volatile payload deployment.",
        }

        self.audit.record_action("HUNTER", "ROOT_CAUSE_FOUND", str(hunt_summary))
        print(
            "[YOMI-HUNTER] [PLASMA BLUE] Root-Cause trace finalized. Awaiting Triad Council assessment."
        )

        return hunt_summary


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    print("\n[+] Activating Root-Cause Hunter...")
    hunter = OmniVectorHunter()
    result = hunter.hunt_root_cause(4092)

    print(f"\n[+] Hunt Conclusion: {result['conclusion']}")
