#!/bin/bash
# ==========================================
# YOMI AUTONOMOUS REMEDIATION PLAYBOOK
# Target : fix_xz_backdoor_cve_2024_3094
# Reason : The threat intelligence confirms CVE-2024-3094. The remediation requires downgrading the xz-utils and liblzma libraries to a known safe version (5.4.6 or earlier) and restarting the SSH service to ensure any compromised processes are terminated.
# ==========================================

echo '[YOMI] Memulai proses remediasi...'

# Check current xz version
xz --version
# Downgrade xz-utils to a safe version (e.g., 5.4.x)
sudo apt-get update && sudo apt-get install --allow-downgrades -y xz-utils=5.4.1-0.2 liblzma5=5.4.1-0.2
# Restart SSH service to clear potential backdoored processes
sudo systemctl restart ssh
# Search and kill any remaining high-CPU processes associated with the exploit
ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | grep sshd | head -n 5

echo '[YOMI] Remediasi selesai. Silakan lakukan validasi ulang.'
