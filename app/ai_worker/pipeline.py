"""One assessment, end to end: prompt, model, validation, rules engine.

Returns a plain record of everything that happened, ready to store. The
record has no decision field. A vendor's final status exists only as a
separate decision record, written by a person through app.decision (HR-01).
"""

from __future__ import annotations

from dataclasses import asdict

from app.rules_engine import Finding, score

from . import schema
from .bedrock_model import ModelError
from .prompt import build_prompt


def run_assessment(*, vendor_id: str, vendor_name: str, uses_ai_on_customer_data: bool,
                   documents: list[dict], model) -> dict:
    """documents: accepted intake results for this vendor, as stored:
    {"filename", "sha256", "segments": [[location, text], ...], "flags": [...]}"""
    injection_flags = [dict(flag, document=doc["filename"]) for doc in documents
                       for flag in doc["flags"] if flag.get("injection")]
    segments = {doc["filename"]: [tuple(s) for s in doc["segments"]] for doc in documents}

    prompt = build_prompt(vendor_id, vendor_name, [(name, segs) for name, segs in segments.items()])
    record = {
        "vendor_id": vendor_id,
        "model_id": model.model_id,
        "model_mode": getattr(model, "mode", "normal"),
        "documents": [{"filename": d["filename"], "sha256": d["sha256"]} for d in documents],
        "injection_flags": injection_flags,
        "prompt_fence": "random per request",
        "requires_human_review": True,
    }
    empty = dict(findings=[], follow_up_questions=[], summary="", citation_problems=[], score=None)
    try:
        raw = model.invoke(prompt)
    except ModelError as reason:
        # The model couldn't be reached or gave nothing usable: no score, nothing decided
        return dict(record, status="ai_call_failed", rejection_reason=str(reason), usage=_usage(model), **empty)
    record["usage"] = _usage(model)
    try:
        checked = schema.validate(raw, segments)
    except schema.OutputRejected as reason:
        # Fail safe: nothing from this answer is used, and no score is produced (SR-11)
        return dict(record, status="ai_output_rejected", rejection_reason=str(reason), **empty)

    doc_types = {doc["filename"]: doc.get("doc_type", "other") for doc in documents}
    findings, evidence_problems = require_independent_evidence(checked.findings, doc_types)
    result = score(findings,
                   uses_ai_on_customer_data=uses_ai_on_customer_data,
                   prompt_injection_flagged=bool(injection_flags))
    return dict(
        record,
        status="ready_for_review",
        rejection_reason=None,
        findings=[asdict(f) for f in checked.findings],
        follow_up_questions=list(checked.follow_up_questions),
        summary=checked.summary,
        citation_problems=list(checked.problems) + evidence_problems,
        score=asdict(result),
    )


def _usage(model) -> dict | None:
    """Tokens and time for the call, when the model reports them (cost and abuse monitoring, SR-14)."""
    usage = getattr(model, "last_usage", None)
    return None if usage is None else dict(vars(usage))


# Document types a person picks at upload. Only an independent audit report can
# make a control "verified"; anything the vendor writes about itself can't.
DOCUMENT_TYPES = {
    "audit_report": "Independent audit report (SOC 2, ISO 27001 certificate, pen test letter)",
    "questionnaire": "Vendor-completed questionnaire",
    "policy": "Vendor policy or security documentation",
    "other": "Other vendor document",
}
INDEPENDENT = {"audit_report"}


def require_independent_evidence(checked_findings, doc_types: dict) -> tuple[list[Finding], list[str]]:
    """A 'verified' claim needs at least one found quote from an independent audit report.

    The quote check proves a quote exists; it can't judge whether the source is
    independent. This rule does, deterministically, from the label a PERSON gave
    the document at upload, never from anything the document or the model says.
    A claim that fails is scored as 'unverified' (a vendor claim), not dropped.
    """
    findings, problems = [], []
    for f in checked_findings:
        finding = f.for_rules_engine()
        if f.evidence_state == "verified":
            independent = [c for c in f.citations if c.verified and doc_types.get(c.document) in INDEPENDENT]
            if not independent:
                problems.append(f"{f.category}: marked verified without an independent audit report; scored as unverified")
                finding = Finding(f.category, "unverified", finding.citations)
        findings.append(finding)
    return findings, problems
