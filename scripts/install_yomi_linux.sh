#!/usr/bin/env bash
#
# install_yomi_linux.sh — one-command Linux installer for the Yomi
# Triage System, run as a persistent background daemon via systemd.
#
# Usage (from the repo root, after `git clone`):
#   sudo ./scripts/install_yomi_linux.sh
#
# What it does, in order:
#   1. Verifies root + Linux + Python 3.10+.
#   2. `pip install .` (uses setup.py's install_requires, which is the
#      deployment-targeted dependency list -- not requirements.txt,
#      which is dev/CI-targeted and deliberately narrower, e.g. it
#      doesn't include boto3 for the optional AWS KMS HMAC key mode).
#      This also registers the global `yomi-triage` console command
#      (setup.py has defined this entry point since the start; it just
#      was never wired into the systemd service generation until now
#      -- see the ExecStart fix in yomi_core/cli.py's install_persistence()).
#   3. Checks for the optional Ring-0 eBPF toolchain (bcc) -- purely
#      informational, does not fail the install if missing, since the
#      eBPF Sensor module is OFF by default anyway.
#   4. Runs `yomi-triage --install` to generate the systemd unit file,
#      installs it to /etc/systemd/system/, reloads systemd, and
#      enables + starts the service.
#   5. Prints how to check status, view logs, stop, and enable optional
#      invasive modules.
#
# Idempotent: safe to re-run (e.g. after a `git pull`) -- it will just
# reinstall dependencies and restart the service with the latest code.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This installer must be run as root: sudo ./scripts/install_yomi_linux.sh" >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This installer only supports Linux (systemd). See docs/installation.md" >&2
    echo "for manual setup on other platforms." >&2
    exit 1
fi

if ! command -v systemctl &>/dev/null; then
    echo "systemctl not found -- this installer requires a systemd-based Linux" >&2
    echo "distribution (Ubuntu, Debian, RHEL/CentOS/Fedora, SIFT Workstation, etc.)." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# SECURITY WARNING: `pip install .` packages yomi_data/ as a Python
# package (it has an __init__.py, so setuptools includes it like any
# other module -- this isn't a bug in this installer, it's how
# setup.py's find_packages() + include_package_data are configured).
# If this checkout already has a generated audit_hmac.key (e.g. from
# running tests or a prior manual run), THAT SAME KEY gets baked into
# this "production" install -- a dev/test HMAC key would then be
# signing the real evidence ledger. This is flagged loudly rather than
# silently proceeding or silently deleting it (an operator might have a
# legitimate reason to reuse a specific key). See docs/known_issues.md
# #28.
if [[ -f "$REPO_ROOT/yomi_data/audit_hmac.key" ]]; then
    echo "" >&2
    echo "WARNING: $REPO_ROOT/yomi_data/audit_hmac.key already exists in this" >&2
    echo "checkout and will be COPIED into the new install below. If this key" >&2
    echo "came from local testing/development, the production ledger will end up" >&2
    echo "signed with a non-production key. If that's not what you want, stop now" >&2
    echo "(Ctrl+C) and remove yomi_data/audit_hmac.key first, or set" >&2
    echo "YOMI_AUDIT_HMAC_MODE=ephemeral / configure a KMS provider instead --" >&2
    echo "see docs/security.md." >&2
    echo "" >&2
    read -rp "Continue anyway and reuse this key? [y/N] " _confirm
    if [[ ! "$_confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted." >&2
        exit 1
    fi
fi

echo "==> [1/5] Checking Python"
PYTHON_BIN="$(command -v python3 || true)"
if [[ -z "$PYTHON_BIN" ]]; then
    echo "python3 not found. Install Python 3.10+ first." >&2
    exit 1
fi
PYVER_OK=$("$PYTHON_BIN" -c 'import sys; print(1 if sys.version_info >= (3, 10) else 0)')
if [[ "$PYVER_OK" != "1" ]]; then
    echo "Python 3.10+ required. Found: $("$PYTHON_BIN" --version)" >&2
    exit 1
fi
echo "    $("$PYTHON_BIN" --version) OK"

echo "==> [2/5] Creating an isolated virtual environment and installing Yomi into it"
# Modern Debian/Ubuntu (PEP 668, "externally-managed-environment") refuses a
# bare `pip install .` into the system Python. A dedicated venv sidesteps
# that entirely (no --break-system-packages, which would be a bad idea for
# a persistent daemon anyway) and keeps Yomi's pinned dependency versions
# isolated from whatever else is on the host.
VENV_DIR="$REPO_ROOT/.venv"
# --system-site-packages: bcc (the Ring-0 eBPF toolchain) must be
# installed via apt into the SYSTEM Python -- docs/installation.md is
# explicit that it should never be pip-installed. A fully-isolated venv
# would make the eBPF Sensor permanently unreachable even if the
# operator installed bcc correctly. This flag lets the venv see it
# while keeping Yomi's own pinned dependencies local to the venv.
"$PYTHON_BIN" -m venv --system-site-packages "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet --upgrade . 2>&1 | tail -20
# Put the venv first on PATH for the rest of this script, so
# `shutil.which("yomi-triage")` inside install_persistence() (see
# yomi_core/cli.py) resolves to the venv's copy and bakes its absolute
# path into the generated systemd ExecStart line -- systemd doesn't
# inherit an interactive shell's PATH, so the unit file needs an
# absolute path either way.
export PATH="$VENV_DIR/bin:$PATH"
YOMI_CMD="$VENV_DIR/bin/yomi-triage"
if [[ ! -x "$YOMI_CMD" ]]; then
    echo "Expected $YOMI_CMD after install but it wasn't created." >&2
    exit 1
fi
echo "    Installed into $VENV_DIR ($($YOMI_CMD --help >/dev/null 2>&1 && echo OK || echo 'unexpected error'))"

echo "==> [3/5] Checking for the optional Ring-0 eBPF toolchain"
if "$VENV_DIR/bin/python3" -c "import bcc" >/dev/null 2>&1; then
    echo "    bcc found -- Ring-0 eBPF Sensor is available if enabled (YOMI_MODULE_EBPF_SENSOR=true)."
else
    echo "    bcc not found. This is fine -- EBPF_SENSOR is disabled by default anyway."
    echo "    To enable it later: sudo apt-get install bpfcc-tools linux-headers-\$(uname -r) python3-bpfcc"
fi

echo "==> [4/5] Generating and installing the systemd service"
rm -f "$REPO_ROOT/yomi-triage.service"
"$YOMI_CMD" --install

SERVICE_FILE="$REPO_ROOT/yomi-triage.service"
if [[ ! -f "$SERVICE_FILE" ]]; then
    echo "Expected $SERVICE_FILE to be generated but it wasn't found." >&2
    exit 1
fi

install -m 0644 "$SERVICE_FILE" /etc/systemd/system/yomi-triage.service
rm -f "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable --now yomi-triage.service

echo "==> [5/5] Verifying the daemon started"
sleep 1
if systemctl is-active --quiet yomi-triage.service; then
    echo "    yomi-triage.service is active and running."
else
    echo "    yomi-triage.service did not report 'active'. Check the logs below." >&2
fi

# Resolve the actual yomi_data path now (glob doesn't expand inside the
# heredoc below), so the printed path is real, not a literal "python3.*".
DATA_DIR_ACTUAL="$(find "$VENV_DIR/lib" -maxdepth 3 -type d -name yomi_data 2>/dev/null | head -1)"
DATA_DIR_ACTUAL="${DATA_DIR_ACTUAL:-$VENV_DIR/lib/pythonX.Y/site-packages/yomi_data (exact version varies)}"

cat <<EOF

Yomi Triage System is installed and running as a background daemon.

  Status:    systemctl status yomi-triage
  Logs:      journalctl -u yomi-triage -f
  Stop:      sudo systemctl stop yomi-triage
  Restart:   sudo systemctl restart yomi-triage
  Disable:   sudo systemctl disable --now yomi-triage
  Uninstall: sudo systemctl disable --now yomi-triage && sudo rm /etc/systemd/system/yomi-triage.service && sudo systemctl daemon-reload

IMPORTANT for chain-of-custody: the evidence ledger, notary checkpoint,
CVE store, and HMAC key for THIS install live inside the venv, not in
this git checkout -- see docs/known_issues.md #27 for why (pip install
packages yomi_data/ like any other module). Exact path:

  $DATA_DIR_ACTUAL/

Back this path up as you would any other forensic evidence store.

Invasive-tier modules (Shadow Net, Sandbox, Mirage, Ghost Protocol,
raw eBPF Sensor) are OFF by default. To enable one, add an
Environment= line to the service and restart, e.g.:

  sudo systemctl edit yomi-triage
  # add under [Service]:
  #   Environment=YOMI_MODULE_GHOST=true
  sudo systemctl daemon-reload && sudo systemctl restart yomi-triage

See docs/demo_mode.md for the full list of module keys, and
docs/usage.md for what each one does.
EOF
