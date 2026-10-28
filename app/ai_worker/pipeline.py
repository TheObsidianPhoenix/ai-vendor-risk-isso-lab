"""One assessment, end to end: prompt, model, validation, rules engine.

Returns a plain record of everything that happened, ready to store. The
record has no decision field. A vendor's final status exists only as a
separate decision record, written by a person through app.decision (HR-01).
"""

from __future__ import annotations

from dataclasses import asdict

from app.rules_engine import Finding, ruleset, score

from . import retrieval, schema
from .bedrock_model import MAX_PROMPT_CHARS, ModelError
from .prompt import build_prompt

SINGLE_CALL_CHARS = MAX_PROMPT_CHARS   # Above this, "auto" switches to focused passes


STRATEGIES = ("auto", "single", "focused")


def run_assessment(*, vendor_id: str, vendor_name: str, uses_ai_on_customer_data: bool,
                   documents: list[dict], model, strategy: str = "auto") -> dict:
    """documents: accepted intake results for this vendor, as stored:
    {"filename", "sha256", "segments": [[location, text], ...], "flags": [...]}

    strategy: "single" sends everything in one call; "focused" runs one pass per
    control category with only the matching sections (retrieval.py); "auto"
    uses single when everything fits in one call, focused when it doesn't."""
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {', '.join(STRATEGIES)}")
    injection_flags = [dict(flag, document=doc["filename"]) for doc in documents
                       for flag in doc["flags"] if flag.get("injection")]
    segments = {doc["filename"]: [tuple(s) for s in doc["segments"]] for doc in documents}

    full_prompt = build_prompt(vendor_id, vendor_name, [(name, segs) for name, segs in segments.items()])
    if strategy == "auto":
        strategy = "single" if len(full_prompt.user) <= SINGLE_CALL_CHARS else "focused"
    record = {
        "vendor_id": vendor_id,
        "model_id": model.model_id,
        "model_mode": getattr(model, "mode", "normal"),
        "documents": [{"filename": d["filename"], "sha256": d["sha256"]} for d in documents],
        "injection_flags": injection_flags,
        "prompt_fence": "random per request",
        "requires_human_review": True,
        "strategy": strategy,
    }
    empty = dict(findings=[], follow_up_questions=[], summary="", citation_problems=[], score=None)

    if strategy == "single":
        passes = [(full_prompt, segments)]
    else:
        categories = [c for c in ruleset.CATEGORIES
                      if uses_ai_on_customer_data or c not in ruleset.AI_ONLY_CATEGORIES]
        passes = []
        record["passes"] = []
        for category in categories:
            chosen = retrieval.select(category, segments)
            passes.append((build_prompt(vendor_id, vendor_name, list(chosen.documents.items()), (category,)),
                           chosen.documents))
            record["passes"].append({"category": category, "sections_sent": chosen.segments,
                                     "chars_sent": chosen.chars, "truncated": chosen.truncated})

    checked_findings, problems, questions, summaries, usages = [], [], [], [], []
    for prompt, sent in passes:
        try:
            raw = model.invoke(prompt)
        except ModelError as reason:
            # The model couldn't be reached or gave nothing usable: no score, nothing decided.
            # A focused assessment with a failed pass stops too: a missing pass would look like missing evidence.
            return dict(record, status="ai_call_failed", rejection_reason=str(reason),
                        usage=_total_usage(usages), **empty)
        usages.append(_usage(model))
        try:
            # Quotes are checked only against the sections this pass was actually sent
            checked = schema.validate(raw, sent)
        except schema.OutputRejected as reason:
            # Fail safe: one bad answer rejects the whole assessment, nothing is used (SR-11)
            return dict(record, status="ai_output_rejected", rejection_reason=str(reason),
                        usage=_total_usage(usages), **empty)
        for finding in checked.findings:
            if finding.category in prompt.categories:
                checked_findings.append(finding)
            else:
                problems.append(f"{finding.category}: reported in the {prompt.categories[0]} pass; ignored")
        problems.extend(checked.problems)
        questions.extend(q for q in checked.follow_up_questions if q not in questions)
        if checked.summary:
            summaries.append(checked.summary)
    record["usage"] = _total_usage(usages)

    doc_types = {doc["filename"]: doc.get("doc_type", "other") for doc in documents}
    findings, evidence_problems = require_independent_evidence(checked_findings, doc_types)
    result = score(findings,
                   uses_ai_on_customer_data=uses_ai_on_customer_data,
                   prompt_injection_flagged=bool(injection_flags))
    summary = summaries[0] if len(summaries) == 1 else (
        f"Assessed in {len(passes)} focused passes, one per control area. " + " ".join(summaries))
    return dict(
        record,
        status="ready_for_review",
        rejection_reason=None,
        findings=[asdict(f) for f in checked_findings],
        follow_up_questions=questions[:schema.MAX_QUESTIONS],
        summary=summary[:schema.MAX_TEXT * 2],
        citation_problems=problems + evidence_problems,
        score=asdict(result),
    )


def _total_usage(usages: list) -> dict | None:
    """Tokens and time summed over every call of the assessment (cost monitoring, SR-14)."""
    usages = [u for u in usages if u]
    if not usages:
        return None
    total = {"input_tokens": 0, "output_tokens": 0, "latency_ms": 0, "calls": len(usages)}
    for u in usages:
        for k in ("input_tokens", "output_tokens", "latency_ms"):
            total[k] += int(u.get(k, 0))
    total["stop_reason"] = usages[-1].get("stop_reason", "")
    return total


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
