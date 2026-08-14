"""PDF renderer for attestation v2 bundles.

Uses fpdf2 for lightweight PDF generation without browser dependencies.
"""

from __future__ import annotations

from datetime import datetime
from io import BytesIO
from pathlib import Path

try:
    from fpdf import FPDF

    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


class AttestationPDF:
    """Render an attestation bundle as a PDF document."""

    def __init__(self, attestation: dict):
        self.att = attestation

    def render(self) -> bytes:
        """Render the attestation to PDF bytes."""
        if not HAS_FPDF:
            raise ImportError(
                "fpdf2 is required for PDF rendering. Install with: pip install fpdf2"
            )

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=25)
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 12, "Kahu Security Attestation", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(4)

        # Version badge
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(
            0,
            6,
            f"Attestation v{self.att.get('version', '2.0')} | "
            f"Engine {self.att.get('engine_version', 'unknown')}",
            new_x="LMARGIN",
            new_y="NEXT",
            align="C",
        )
        pdf.set_text_color(0, 0, 0)
        pdf.ln(8)

        # Separator
        self._draw_separator(pdf)

        # Appliance info
        appliance = self.att.get("appliance", {})
        self._section_header(pdf, "Appliance")
        self._kv_row(pdf, "Organization", appliance.get("org_name", "N/A"))
        self._kv_row(pdf, "Appliance ID", appliance.get("appliance_id", "N/A"))
        self._kv_row(pdf, "Attestation ID", self.att.get("attestation_id", "N/A"))
        self._kv_row(pdf, "Created", self._fmt_date(self.att.get("created", "")))
        self._kv_row(pdf, "Expires", self._fmt_date(self.att.get("expires", "")))
        pdf.ln(4)

        # Pono Score
        snapshot = self.att.get("pono_snapshot", {})
        self._section_header(pdf, "Pono Score")
        score = snapshot.get("pono_score", 0)
        pdf.set_font("Helvetica", "B", 28)
        color = self._score_color(score)
        pdf.set_text_color(*color)
        pdf.cell(0, 16, f"{score:.1f} / 100", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        # Component breakdown
        components = snapshot.get("components", [])
        if components:
            self._section_header(pdf, "Component Breakdown")
            # Table header
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(240, 240, 240)
            col_widths = [55, 25, 25, 25, 20, 40]
            headers = ["Component", "Score", "Max", "Raw", "Status", "Evidence Age"]
            for w, h in zip(col_widths, headers, strict=False):
                pdf.cell(w, 7, h, border=1, fill=True)
            pdf.ln()

            pdf.set_font("Helvetica", "", 9)
            for c in components:
                pdf.cell(col_widths[0], 7, c.get("name", ""), border=1)
                pdf.cell(col_widths[1], 7, f"{c.get('weighted_score', 0):.1f}", border=1, align="R")
                pdf.cell(col_widths[2], 7, str(c.get("max_points", 0)), border=1, align="R")
                pdf.cell(col_widths[3], 7, f"{c.get('raw_score', 0):.3f}", border=1, align="R")
                pdf.cell(col_widths[4], 7, c.get("label", ""), border=1, align="C")
                age = c.get("evidence_age_days", 0)
                pdf.cell(col_widths[5], 7, f"{age:.1f} days", border=1, align="R")
                pdf.ln()
            pdf.ln(4)

        # Biggest gain recommendation
        gain = snapshot.get("biggest_gain")
        if gain:
            self._section_header(pdf, "Recommendation")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(
                0,
                6,
                f"Biggest available gain: {gain['component']} "
                f"(+{gain['available_gain']:.1f} points possible, "
                f"currently {gain['current_score']:.1f}/{gain['max_points']})",
            )
            pdf.ln(4)

        # Evidence chain
        chain = self.att.get("evidence_chain", {})
        chain_links = chain.get("chain", [])
        if chain_links:
            self._section_header(pdf, "Evidence Chain")
            pdf.set_font("Courier", "", 7)
            pdf.cell(0, 5, f"Root: {chain.get('root', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 5, f"Links: {len(chain_links)}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)

        # Signature
        self._draw_separator(pdf)
        self._section_header(pdf, "Digital Signature")
        sig = self.att.get("signature", "N/A")
        pdf.set_font("Courier", "", 7)
        # Wrap long signature
        for i in range(0, len(sig), 80):
            pdf.cell(0, 4, sig[i : i + 80], new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(
            0,
            5,
            "Ed25519 signature over canonical JSON."
            " Verify with: kahu-verify <bundle.json> <pubkey.pem>",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_text_color(0, 0, 0)

        buf = BytesIO()
        pdf.output(buf)
        return buf.getvalue()

    def save(self, path: str | Path) -> None:
        """Render and save PDF to file."""
        Path(path).write_bytes(self.render())

    @staticmethod
    def _section_header(pdf: FPDF, text: str) -> None:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)

    @staticmethod
    def _kv_row(pdf: FPDF, key: str, value: str) -> None:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(45, 6, f"{key}:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, value, new_x="LMARGIN", new_y="NEXT")

    @staticmethod
    def _draw_separator(pdf: FPDF) -> None:
        pdf.set_draw_color(200, 200, 200)
        y = pdf.get_y()
        pdf.line(10, y, 200, y)
        pdf.ln(4)

    @staticmethod
    def _score_color(score: float) -> tuple[int, int, int]:
        if score >= 80:
            return (0, 150, 0)  # Green
        elif score >= 60:
            return (200, 150, 0)  # Yellow/amber
        else:
            return (200, 0, 0)  # Red

    @staticmethod
    def _fmt_date(iso_str: str) -> str:
        if not iso_str:
            return "N/A"
        try:
            dt = datetime.fromisoformat(iso_str)
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except (ValueError, TypeError):
            return iso_str
