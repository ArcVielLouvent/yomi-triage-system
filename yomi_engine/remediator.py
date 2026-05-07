import os
from datetime import datetime

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - The Reverser
# Purpose: Autonomous Remediation Playbook Generator.
# ==============================================================================

class ReverserEngine:
    def __init__(self):
        # Ensure the playbook directory exists
        self.playbook_dir = "/workspaces/yomi-triage-system/yomi_data/playbooks"
        os.makedirs(self.playbook_dir, exist_ok=True)

    def draft_playbook(self, playbook_name, commands, reasoning):
        """
        Translates AI intent into a localized, executable Bash script.
        """
        # Append timestamp to avoid overwriting existing playbooks
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = playbook_name.replace(" ", "_").lower()
        filename = f"{safe_name}_{timestamp}.sh"
        filepath = os.path.join(self.playbook_dir, filename)

        # Assemble the Bash script
        with open(filepath, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# ==========================================\n")
            f.write("# YOMI AUTONOMOUS REMEDIATION PLAYBOOK\n")
            f.write(f"# Target : {playbook_name}\n")
            f.write(f"# Reason : {reasoning}\n")
            f.write("# ==========================================\n\n")
            
            f.write("echo '[YOMI] Initiating remediation sequence...'\n\n")
            
            if isinstance(commands, list):
                for cmd in commands:
                    f.write(f"{cmd}\n")
            else:
                f.write(f"{commands}\n")
                
            f.write("\necho '[YOMI] Remediation complete. Please perform validation scan.'\n")

        # Grant execution permissions (chmod +x)
        os.chmod(filepath, 0o755)
        
        return {
            "status": "PLAYBOOK_DRAFTED",
            "playbook_path": filepath,
            "message": f"Remediation script successfully written to {filepath}. Awaiting human approval."
        }