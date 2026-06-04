import os
import sys
import time
import subprocess
import hashlib
import hmac
import json
import base64
from fpdf import FPDF

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_engine.weaver import TemporalNarrativeWeaver
from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Court-Ready Dossier Generator
# Purpose: Converts the Temporal Narrative into a Dual-Artifact (PDF + TXT)
#          and cryptographically seals them via GPG or internal HMAC-SHA256.
# ==============================================================================


class CourtReadyDossier:
    def __init__(self):
        self.weaver = TemporalNarrativeWeaver()
        self.audit = ImmutableStamp()
        self.report_dir = os.path.join(
            os.path.dirname(__file__), "..", "yomi_data", "reports"
        )
        os.makedirs(self.report_dir, exist_ok=True)
        # Verify if GPG exists on the system securely
        gpg_check = subprocess.run(["which", "gpg"], capture_output=True, text=True)
        self.gpg_binary = gpg_check.stdout.strip() if gpg_check.returncode == 0 else ""

    def _sign_artifact(self, filepath: str) -> dict:
        """
        Attempts strict GPG signing (--batch --no-tty).
        Falls back to internal Yomi HMAC-SHA256 if GPG fails or requires manual TTY.
        """
        signature_path = f"{filepath}.sig"

        # 1. Attempt OS-Level GPG Sign (If properly configured for batch mode)
        if self.gpg_binary:
            try:
                result = subprocess.run(
                    [
                        self.gpg_binary,
                        "--batch",
                        "--no-tty",
                        "--yes",
                        "--armor",
                        "--detach-sign",
                        "--output",
                        signature_path,
                        filepath,
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    return {
                        "status": "SUCCESS",
                        "mode": "GPG",
                        "sig_file": signature_path,
                    }
            except Exception:
                pass

        # 2. Fallback to Internal HMAC-SHA256 (Zero-Disk Air-Gapped Key)
        print(
            "[YOMI-DOSSIER] [WARNING] GPG unavailable/locked. Falling back to internal HMAC-SHA256 sealing."
        )

        try:
            with open(filepath, "rb") as f:
                file_bytes = f.read()

            if hasattr(self.audit, "hmac_key") and self.audit.hmac_key:
                signature = base64.b64encode(
                    hmac.new(self.audit.hmac_key, file_bytes, hashlib.sha256).digest()
                ).decode("ascii")
                sig_type = "HMAC-SHA256"
            else:
                signature = hashlib.sha256(file_bytes).hexdigest()
                sig_type = "SHA256 (UNSEALED)"

            sig_payload = {
                "signature_type": sig_type,
                "signed_by": "Yomi Autonomous Engine",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "target_file": os.path.basename(filepath),
                "signature": signature,
            }

            with open(signature_path, "w", encoding="utf-8") as f:
                json.dump(sig_payload, f, indent=4)

            os.chmod(signature_path, 0o640)
            return {"status": "SUCCESS", "mode": sig_type, "sig_file": signature_path}

        except Exception as e:
            return {"status": "ERROR", "mode": "FAILED", "reason": str(e)}

    def generate_pdf_dossier(self):
        print(
            "\n[YOMI-DOSSIER] [VOID BLACK] Assembling Court-Ready Cryptographic Dossier..."
        )

        # Ingest the narrative from the Weaver
        narrative = self.weaver.generate_narrative()
        timestamp = int(time.time())

        base_filename = os.path.join(self.report_dir, f"YOMI_DOSSIER_{timestamp}")
        pdf_filename = f"{base_filename}.pdf"
        txt_filename = f"{base_filename}.txt"

        # ======================================================================
        # 1. CREATE RAW UTF-8 TEXT ANNEX (Prevents Evidence Spoliation)
        # ======================================================================
        with open(txt_filename, "w", encoding="utf-8") as f:
            f.write(narrative)

        # Calculate raw hash to embed in the PDF
        raw_hash = hashlib.sha256(narrative.encode("utf-8")).hexdigest()

        # ======================================================================
        # 2. CREATE PDF REPORT (For Human/Judge Consumption)
        # ======================================================================
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, txt="KUROTECH: YOMI TRIAGE SYSTEM", ln=True, align="C")
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, txt="OFFICIAL FORENSIC DOSSIER", ln=True, align="C")
        pdf.line(10, 30, 200, 30)
        pdf.ln(5)

        # Embed the raw hash to prove PDF matches the TXT annex
        pdf.set_font("Courier", "I", 8)
        pdf.cell(
            0, 5, txt=f"RAW EVIDENCE HASH (SHA256): {raw_hash}", ln=True, align="C"
        )
        pdf.ln(5)

        pdf.set_font("Courier", size=9)
        # Safe transliteration for FPDF constraints (The TXT file holds the true Unicode evidence)
        safe_narrative = narrative.encode("latin-1", "replace").decode("latin-1")
        pdf.multi_cell(0, 5, safe_narrative)

        pdf.output(pdf_filename)
        print(
            f"[YOMI-DOSSIER] [PLASMA BLUE] Dual-Artifact Compiled:\n -> {pdf_filename}\n -> {txt_filename}"
        )

        # ======================================================================
        # 3. APPLY CRYPTOGRAPHIC SIGNATURES
        # ======================================================================
        print("[YOMI-DOSSIER] [CYBER-PURPLE] Applying Cryptographic Signatures...")

        # Sign both the PDF and the RAW Text Annex
        pdf_sig = self._sign_artifact(pdf_filename)
        txt_sig = self._sign_artifact(txt_filename)

        print(
            f"[YOMI-DOSSIER] [VOID BLACK] PDF Signature : {pdf_sig.get('mode', 'FAILED')}"
        )
        print(
            f"[YOMI-DOSSIER] [VOID BLACK] TXT Signature : {txt_sig.get('mode', 'FAILED')}"
        )

        self.audit.record_action(
            "DOSSIER",
            "REPORT_SIGNED",
            f"Generated Dual-Artifact Dossier. PDF Mode: {pdf_sig.get('mode')} | TXT Mode: {txt_sig.get('mode')}",
            metadata={"pdf_file": pdf_filename, "txt_file": txt_filename},
        )


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    dossier = CourtReadyDossier()
    dossier.generate_pdf_dossier()
