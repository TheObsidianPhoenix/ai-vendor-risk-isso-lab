"""PDF checks: active content, encryption, hidden text, metadata, page limits.

Hidden text is found by walking each page's drawing instructions and tracking
the fill colour, font size and text render mode in effect when text is drawn.
Text drawn in white, at under 4 points, or in invisible render mode is
flagged and removed from the text passed on, so the model never sees it.

Known limitation: text inside form XObjects (reusable drawing blocks) and text
drawn in a colour that merely matches a coloured background are not checked.
Both are recorded in docs/system-security/intake-controls.md.
"""

from __future__ import annotations

import io
import math

from pypdf import PdfReader
from pypdf.generic import ContentStream

from .limits import Limits
from .patterns import instruction_like
from .result import Flag, Rejected, Segment

TINY_POINTS = 4.0
TEXT_OPERATORS = {b"Tj", b"TJ", b"'", b'"'}
METADATA_FIELDS = ("/Title", "/Subject", "/Author", "/Keywords", "/Creator", "/Producer")


def scan_pdf(data: bytes, limits: Limits) -> tuple[list[Flag], list[Segment]]:
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        raise Rejected("Encrypted PDF: contents can't be checked")
    _reject_active_content(reader)

    if len(reader.pages) > limits.max_pdf_pages:
        raise Rejected(f"PDF has {len(reader.pages)} pages; the limit is {limits.max_pdf_pages}")

    flags: list[Flag] = []
    segments: list[Segment] = []
    for number, page in enumerate(reader.pages, start=1):
        location = f"page {number}"
        hidden = _hidden_text(page, reader)
        for reason, text in hidden:
            flags.append(Flag("hidden_text", location, reason, text[: limits.max_excerpt_chars]))
        visible = page.extract_text() or ""
        for _, text in hidden:
            visible = visible.replace(text, "")  # The model never receives hidden text
        visible = visible.strip()
        phrase = instruction_like(visible)
        if phrase:
            flags.append(Flag("instruction_like_text", location, "Visible text reads like an instruction to an AI", phrase))
        if visible:
            segments.append(Segment(location, visible))

    meta = reader.metadata or {}
    for key in METADATA_FIELDS:
        value = meta.get(key)
        if value and instruction_like(str(value)):
            flags.append(Flag("metadata_instruction", f"metadata {key[1:]}",
                              "Document metadata reads like an instruction to an AI",
                              str(value)[: limits.max_excerpt_chars]))

    if sum(len(s.text) for s in segments) < limits.min_extracted_chars:
        raise Rejected("No extractable text. Scanned, image-only PDFs aren't supported (decision D-04)")
    return flags, segments


def _reject_active_content(reader: PdfReader) -> None:
    """JavaScript, launch actions and embedded files have no place in a vendor policy PDF."""
    root = reader.trailer["/Root"]
    names = root.get("/Names")
    names = names.get_object() if names is not None else {}
    if "/JavaScript" in names or ("/OpenAction" in root and _is_script(root["/OpenAction"])):
        raise Rejected("PDF contains JavaScript")
    if "/EmbeddedFiles" in names:
        raise Rejected("PDF contains embedded files")
    if "/AA" in root:
        raise Rejected("PDF contains automatic actions")
    for page in reader.pages:
        if "/AA" in page:
            raise Rejected("PDF page contains automatic actions")
        for annot in page.get("/Annots") or []:
            action = annot.get_object().get("/A")
            if action is not None and action.get_object().get("/S") in ("/Launch", "/JavaScript"):
                raise Rejected("PDF contains a launch or JavaScript action")


def _is_script(action) -> bool:
    action = action.get_object()
    return hasattr(action, "get") and action.get("/S") in ("/JavaScript", "/Launch")


def _hidden_text(page, reader) -> list[tuple[str, str]]:
    contents = page.get_contents()
    if contents is None:
        return []
    operations = contents.operations if hasattr(contents, "operations") else ContentStream(contents, reader).operations

    found: list[tuple[str, str]] = []
    fill_white = False
    font_size = 12.0
    text_scale = 1.0
    render_mode = 0
    stack: list[tuple[bool, float, float, int]] = []

    for operands, operator in operations:
        if operator == b"q":
            stack.append((fill_white, font_size, text_scale, render_mode))
        elif operator == b"Q" and stack:
            fill_white, font_size, text_scale, render_mode = stack.pop()
        elif operator == b"rg" and len(operands) == 3:
            fill_white = all(float(v) >= 0.95 for v in operands)
        elif operator == b"g" and len(operands) == 1:
            fill_white = float(operands[0]) >= 0.95
        elif operator == b"k" and len(operands) == 4:
            fill_white = all(float(v) <= 0.05 for v in operands)
        elif operator == b"Tf" and len(operands) == 2:
            font_size = abs(float(operands[1]))
        elif operator == b"Tm" and len(operands) == 6:
            b, d = float(operands[1]), float(operands[3])
            text_scale = math.hypot(b, d) or 1.0
        elif operator == b"Tr" and operands:
            render_mode = int(operands[0])
        elif operator in TEXT_OPERATORS:
            text = _operand_text(operands)
            if not text.strip():
                continue
            effective = font_size * text_scale
            if render_mode == 3:
                found.append(("Text drawn in invisible render mode", text))
            elif fill_white:
                found.append(("White text, invisible on a white page", text))
            elif effective < TINY_POINTS:
                found.append((f"Text at {effective:.1f} pt, too small to read", text))
    return found


def _operand_text(operands) -> str:
    parts = []
    for operand in operands:
        if isinstance(operand, (str, bytes)):
            parts.append(operand.decode("latin-1") if isinstance(operand, bytes) else operand)
        elif isinstance(operand, list):  # TJ arrays mix strings and spacing numbers
            parts.extend(item if isinstance(item, str) else "" for item in operand)
    return "".join(parts)
