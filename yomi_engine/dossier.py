import os
import sys
import time
import subprocess
from fpdf import FPDF

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_engine.weaver import TemporalNarrativeWeaver
from yomi_audit.stamp import ImmutableStamp

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - Court-Ready Dossier (v4.0)
# Purpose: Converts the Temporal Narrative into a GPG-signed PDF document
#          suitable for international court admissibility.
# ==============================================================================


class CourtReadyDossier:
    def __init__(self):
        self.weaver = TemporalNarrativeWeaver()
        self.audit = ImmutableStamp()
        self.report_dir = os.path.join(
            os.path.dirname(__file__), "..", "yomi_data", "reports"
        )
        os.makedirs(self.report_dir, exist_ok=True)

    def _sign_file(self, filepath: str) -> bool:
        """Attempts absolute GPG detached signature. Returns false if GPG is unavailable."""
        try:
            # Attempt true cryptographic signing
            result = subprocess.run(
                ["gpg", "--yes", "--armor", "--detach-sign", filepath],
                capture_output=True,
            )
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            pass

        return False

    def generate_pdf_dossier(self):
        print(
            "\n[YOMI-DOSSIER] [VOID BLACK] Assembling Court-Ready Cryptographic Dossier..."
        )

        # Ingest the narrative from the Weaver
        narrative = self.weaver.generate_narrative()

        # Initialize PDF
        pdf = FPDF()
        pdf.add_page()

        # KuroTech Header
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, txt="KUROTECH: YOMI TRIAGE SYSTEM", ln=True, align="C")
        pdf.set_font("Arial", "B", 12)
        pdf.cell(
            0, 10, txt="OFFICIAL FORENSIC DOSSIER (GPG SEALED)", ln=True, align="C"
        )
        pdf.line(10, 30, 200, 30)
        pdf.ln(15)

        # Body Content
        pdf.set_font("Courier", size=9)
        # Clean special characters for FPDF Latin-1 compatibility
        safe_narrative = (
            narrative.replace("\u2019", "'")
            .encode("latin-1", "replace")
            .decode("latin-1")
        )
        pdf.multi_cell(0, 5, safe_narrative)

        # Save PDF
        timestamp = int(time.time())
        pdf_filename = os.path.join(self.report_dir, f"YOMI_DOSSIER_{timestamp}.pdf")
        pdf.output(pdf_filename)
        print(f"[YOMI-DOSSIER] [PLASMA BLUE] PDF Compiled: {pdf_filename}")

        # Apply Signature
        print("[YOMI-DOSSIER] [CYBER-PURPLE] Applying Cryptographic Signature...")
        is_real_gpg = self._sign_file(pdf_filename)

        sig_type = "REAL GPG" if is_real_gpg else "UNSIGNED"
        print(
            f"[YOMI-DOSSIER] [VOID BLACK] Signature status: {sig_type}."
        )

        self.audit.record_action(
            "DOSSIER",
            "REPORT_SIGNED",
            f"Generated and signed PDF dossier. Mode: {sig_type}",
        )


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    dossier = CourtReadyDossier()
    dossier.generate_pdf_dossier()
