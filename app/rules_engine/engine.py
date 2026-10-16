"""Deterministic risk scoring.

The model reads, the code scores, and a person decides. This module is the
"code scores" part: it turns proposed evidence states into a score and a
classification using the published rule set. It has no randomness, no AI
and no network access, so the same evidence always produces the same result
and anyone can recompute it by hand.

What this module deliberately cannot do: set a vendor's final status.
ScoreResult has no decision, approval or status field (HR-01, SR-12).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import ruleset


class InvalidFindings(ValueError):
    """Raised when the input can't be scored safely. Scoring stops; nothing is guessed."""


@dataclass(frozen=True)
class Finding:
    """One control category's evidence, as proposed by the extraction step."""

    category: str
    proposed_state: str
    citations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScoredLine:
    category: str
    proposed_state: str
    scored_state: str
    points: int
    reason: str


@dataclass(frozen=True)
class ScoreResult:
    rule_set_version: str
    score: int
    classification: str
    lines: tuple[ScoredLine, ...]
    floor_rule_applied: str | None
    prompt_injection_flagged: bool
    requires_human_review: bool = True  # Always. The engine advises; it never decides.
    notes: tuple[str, ...] = field(default=())


def score(findings: list[Finding], *, uses_ai_on_customer_data: bool,
          prompt_injection_flagged: bool = False) -> ScoreResult:
    """Score one vendor.

    uses_ai_on_customer_data comes from the vendor record entered by a person.
    prompt_injection_flagged comes from the intake scanner. It adds no points:
    the documents are still assessed on their evidence, and the flag is shown
    to the reviewer.
    """
    by_category = _validate(findings)
    notes: list[str] = []
    lines: list[ScoredLine] = []

    for category in ruleset.CATEGORIES:
        if category in ruleset.AI_ONLY_CATEGORIES and not uses_ai_on_customer_data:
            if category in by_category:
                notes.append(f"{category}: not applicable (vendor record says no AI on our data); finding ignored")
            continue
        lines.append(_score_line(category, by_category.get(category)))

    total = min(ruleset.MAX_SCORE, sum(line.points for line in lines))
    classification = next(name for floor, name in ruleset.BANDS if total >= floor)

    floor_rule = None
    gaps = sum(1 for line in lines if line.scored_state == "critical_gap")
    if gaps >= 2 and classification != "Critical":
        classification, floor_rule = "Critical", "Two or more critical gaps: at least Critical"
    elif gaps == 1 and classification in ("Low", "Moderate"):
        classification, floor_rule = "High", "One critical gap: at least High"

    if prompt_injection_flagged:
        notes.append("Prompt-injection indicator found at intake: score unaffected; reviewer must see the flag")

    return ScoreResult(
        rule_set_version=ruleset.VERSION,
        score=total,
        classification=classification,
        lines=tuple(lines),
        floor_rule_applied=floor_rule,
        prompt_injection_flagged=prompt_injection_flagged,
        notes=tuple(notes),
    )


def _validate(findings: list[Finding]) -> dict[str, Finding]:
    """Fail closed on anything unexpected (SR-11). Never silently drop or guess."""
    by_category: dict[str, Finding] = {}
    for finding in findings:
        if finding.category not in ruleset.CATEGORIES:
            raise InvalidFindings(f"Unknown category: {finding.category!r}")
        if finding.proposed_state not in ruleset.PROPOSED_STATES:
            raise InvalidFindings(f"Unknown evidence state for {finding.category}: {finding.proposed_state!r}")
        if finding.category in by_category:
            raise InvalidFindings(f"Duplicate finding for category: {finding.category}")
        by_category[finding.category] = finding
    return by_category


def _score_line(category: str, finding: Finding | None) -> ScoredLine:
    critical = category in ruleset.CRITICAL_CATEGORIES

    if finding is None:
        proposed, state, reason = "missing", "absent", "No finding reported for this category; treated as absent"
    elif finding.proposed_state != "absent" and not finding.citations:
        # SR-13: a claim the model can't point to in the documents doesn't count.
        proposed, state, reason = finding.proposed_state, "absent", "No citation to a source document; treated as absent"
    elif finding.proposed_state == "contradicted":
        proposed, state, reason = "contradicted", "absent", "The documents contradict the control"
    else:
        proposed, state, reason = finding.proposed_state, finding.proposed_state, _REASONS[finding.proposed_state]

    if state == "absent" and critical:
        state, reason = "critical_gap", f"Critical control. {reason}"

    return ScoredLine(category, proposed, state, ruleset.POINTS[state], reason)


_REASONS = {
    "verified": "Backed by independent evidence",
    "unverified": "Claimed by the vendor without supporting evidence",
    "conflict": "Vendor sources disagree; reviewer must resolve",
    "absent": "Not addressed in the documents",
}
