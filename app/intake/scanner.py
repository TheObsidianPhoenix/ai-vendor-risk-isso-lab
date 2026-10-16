"""Intake scanner: every uploaded file passes through here before anything else reads it.

Trust boundary TB3 (Phase 2 architecture): untrusted vendor document in,
either a rejection or plain visible text with page and row locations out.

Order of checks:
1. Size limit, before reading anything else.
2. File type from the file's own bytes, not its name. The name must agree.
3. Format-specific checks (active content, macros, zip bombs, hidden text,
   metadata), run in a separate process with a time limit, so a file that
   makes a parser loop forever is stopped and rejected.

Nothing here decides anything about the vendor. Flags go to the reviewer and
are recorded by the rules engine without changing the score.
"""

from __future__ import annotations

import hashlib
import io
import multiprocessing
import queue
import zipfile
from pathlib import PurePath

from .limits import DEFAULT_LIMITS, Limits
from .office import scan_docx, scan_xlsx
from .pdf import scan_pdf
from .result import IntakeResult, Rejected

EXTENSIONS = {"pdf": {".pdf"}, "xlsx": {".xlsx"}, "docx": {".docx"}}


def scan_file(data: bytes, filename: str, limits: Limits = DEFAULT_LIMITS) -> IntakeResult:
    """Scan one uploaded file. Never raises for a bad file: it returns a rejected result."""
    digest = hashlib.sha256(data).hexdigest()  # Recorded for integrity evidence, accepted or not
    base = dict(filename=PurePath(filename).name, sha256=digest, size_bytes=len(data))

    if not data:
        return IntakeResult(**base, status="rejected", rejection_reason="File is empty")
    if len(data) > limits.max_file_bytes:
        return IntakeResult(**base, status="rejected",
                            rejection_reason=f"File is {len(data):,} bytes; the limit is {limits.max_file_bytes:,}")

    file_type = detect_type(data)
    if file_type is None:
        return IntakeResult(**base, status="rejected", rejection_reason="Not a PDF, XLSX or DOCX file")
    if PurePath(filename).suffix.lower() not in EXTENSIONS[file_type]:
        return IntakeResult(**base, status="rejected", file_type=file_type,
                            rejection_reason=f"File name says {PurePath(filename).suffix or 'nothing'} but the content is {file_type.upper()}")

    outcome = run_with_time_limit(_scan_content, (data, file_type, limits), limits.max_seconds)
    if isinstance(outcome, str):
        return IntakeResult(**base, status="rejected", file_type=file_type, rejection_reason=outcome)
    flags, segments = outcome
    return IntakeResult(**base, status="accepted", file_type=file_type, flags=tuple(flags), segments=tuple(segments))


def detect_type(data: bytes) -> str | None:
    """Identify the file from its first bytes (its 'magic number'), never from its name."""
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        # Read only the archive's table of contents; nothing is decompressed here
        try:
            names = {name.lower() for name in zipfile.ZipFile(io.BytesIO(data)).namelist()}
        except zipfile.BadZipFile:
            return None
        if "xl/workbook.xml" in names:
            return "xlsx"
        if "word/document.xml" in names:
            return "docx"
    return None


def _scan_content(data: bytes, file_type: str, limits: Limits):
    scanners = {"pdf": scan_pdf, "xlsx": scan_xlsx, "docx": scan_docx}
    try:
        return scanners[file_type](data, limits)
    except Rejected as reason:
        return str(reason)
    except Exception as error:  # A parser crash on hostile input is a rejection, never a pass
        return f"File could not be processed safely ({type(error).__name__})"


def run_with_time_limit(function, args: tuple, seconds: float):
    """Run function(*args) in a separate process and stop it after `seconds`.

    A thread can't be stopped from outside; a process can. If the child crashes
    or runs out of time, the caller gets a rejection message instead of a result.
    """
    context = multiprocessing.get_context("spawn")  # Same behaviour on macOS, Linux and in Lambda
    results = context.Queue()
    worker = context.Process(target=_child, args=(results, function, args), daemon=True)
    worker.start()
    try:
        outcome = results.get(timeout=seconds)
    except queue.Empty:
        outcome = f"Processing stopped after the {seconds:g}-second limit"
    finally:
        if worker.is_alive():
            worker.kill()
        worker.join(timeout=5)
    return outcome


def _child(results, function, args) -> None:
    try:
        results.put(function(*args))
    except Exception as error:
        results.put(f"File could not be processed safely ({type(error).__name__})")
