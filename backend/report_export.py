"""
backend/report_export.py

Render the plain-text diagnostic report to a clean, paginated PDF.
Uses fpdf2 (pure-Python, PyInstaller-friendly). The core PDF fonts are
Latin-1, so non-Latin glyphs are transliterated to safe ASCII first.
"""

_REPLACEMENTS = {
    "—": "-", "–": "-", "•": "*", "·": "-", "▸": ">", "✔": "[OK]", "✘": "[X]",
    "“": '"', "”": '"', "’": "'", "‘": "'", "…": "...", "©": "(c)", "→": "->",
    "≈": "~", "🎉": "", "⚠": "!",
}


def _safe(text: str) -> str:
    text = text or ""
    for bad, good in _REPLACEMENTS.items():
        text = text.replace(bad, good)
    return text.encode("latin-1", "replace").decode("latin-1")


def text_report_to_pdf(text: str, path: str, title: str, meta_lines=None):
    """
    Write `text` to `path` as a PDF. Raises ImportError if fpdf2 is missing
    (the caller surfaces a friendly message).
    """
    from fpdf import FPDF  # fpdf2

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.set_margins(12, 12, 12)
    pdf.add_page()

    # Header
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 9, _safe(title), ln=1)
    pdf.set_draw_color(120, 144, 156)
    y = pdf.get_y()
    pdf.line(12, y, pdf.w - 12, y)
    pdf.ln(3)

    if meta_lines:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(90, 100, 110)
        for m in meta_lines:
            pdf.cell(0, 5, _safe(m), ln=1)
        pdf.ln(2)

    # Body (monospace, so command output lines up)
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Courier", "", 8)
    epw = pdf.w - pdf.l_margin - pdf.r_margin
    for raw in text.splitlines():
        line = _safe(raw)
        if not line.strip():
            pdf.ln(3)
            continue
        pdf.multi_cell(epw, 4, line)

    pdf.output(path)
    return path
