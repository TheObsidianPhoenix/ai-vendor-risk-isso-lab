"""One assessment, end to end: prompt, model, validation, rules engine.

Returns a plain record of everything that happened, ready to store. The
record has no decision field. A vendor's final status exists only as a
separate decision record, written by a person through app.decision (HR-01).
"""

from __future__ import annotations

from dataclasses import asdict

from app.rules_engine import score

from . import schema
from .prompt import build_prompt


def run_assessment(*, vendor_id: str, vendor_name: str, uses_ai_on_customer_data: bool,
                   documents: list[dict], model) -> dict:
    """documents: accepted intake results for this vendor, as stored:
    {"filename", "sha256", "segments": [[location, text], ...], "flags": [...]}"""
    injection_flags = [dict(flag, document=doc["filename"]) for doc in documents
                       for flag in doc["flags"] if flag.get("injection")]
    segments = {doc["filename"]: [tuple(s) for s in doc["segments"]] for doc in documents}

    prompt = build_prompt(vendor_id, vendor_name, [(name, segs) for name, segs in segments.items()])
    raw = model.invoke(prompt)

    record = {
        "vendor_id": vendor_id,
        "model_id": model.model_id,
        "model_mode": getattr(model, "mode", "normal"),
        "documents": [{"filename": d["filename"], "sha256": d["sha256"]} for d in documents],
        "injection_flags": injection_flags,
        "prompt_fence": "random per request",
        "requires_human_review": True,
    }
    try:
        checked = schema.validate(raw, segments)
    except schema.OutputRejected as reason:
        # Fail safe: nothing from this answer is used, and no score is produced (SR-11)
        return dict(record, status="ai_output_rejected", rejection_reason=str(reason),
                    findings=[], follow_up_questions=[], summary="", citation_problems=[], score=None)

    result = score([f.for_rules_engine() for f in checked.findings],
                   uses_ai_on_customer_data=uses_ai_on_customer_data,
                   prompt_injection_flagged=bool(injection_flags))
    return dict(
        record,
        status="ready_for_review",
        rejection_reason=None,
        findings=[asdict(f) for f in checked.findings],
        follow_up_questions=list(checked.follow_up_questions),
        summary=checked.summary,
        citation_problems=list(checked.problems),
        score=asdict(result),
    )
