"""Shared helpers for tests: scan the sample vendors once and reuse the results."""

from __future__ import annotations

import functools
import json
from pathlib import Path

from app.intake import scan_file
from app.intake.result import INJECTION_FLAG_KINDS

SAMPLES = Path(__file__).resolve().parent.parent / "sample-data"
VENDORS = ("nimbus-notes-ai", "copperline-backup", "kestrel-payroll-cloud")


def doc_type_for(filename: str) -> str:
    """The label a person gives each sample document at upload."""
    if filename.startswith("soc2-"):
        return "audit_report"
    if "questionnaire" in filename:
        return "questionnaire"
    if "policy" in filename:
        return "policy"
    return "other"


@functools.lru_cache(maxsize=None)
def sample_documents(vendor: str) -> tuple:
    """Intake results for one sample vendor, in the shape the app stores them."""
    docs = []
    for path in sorted((SAMPLES / vendor).glob("*.*")):
        if path.suffix == ".json":
            continue
        result = scan_file(path.read_bytes(), path.name)
        docs.append({
            "filename": result.filename, "sha256": result.sha256, "doc_type": doc_type_for(result.filename),
            "segments": [[s.location, s.text] for s in result.segments],
            "flags": [{"kind": f.kind, "location": f.location, "injection": f.kind in INJECTION_FLAG_KINDS}
                      for f in result.flags],
        })
    return tuple(docs)


def expected(vendor: str) -> dict:
    return json.loads((SAMPLES / vendor / "expected-findings.json").read_text())
