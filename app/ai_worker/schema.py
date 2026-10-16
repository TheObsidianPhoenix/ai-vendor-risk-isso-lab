"""Model output validation (SR-11, SR-13; OWASP LLM05, LLM09).

The model's answer is treated like any other untrusted input:

1. Structure: it must be JSON with exactly the expected fields. An unknown
   field, including any attempt to add a "decision" or "score", rejects the
   whole answer. Nothing is guessed or repaired.
2. Evidence: every quote must actually appear at the cited location in a
   document that was uploaded for this vendor. A quote that can't be found
   is dropped, and a finding left with no real citation counts as missing
   evidence in the rules engine.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app.rules_engine import Finding, ruleset

TOP_LEVEL = {"findings", "follow_up_questions", "summary"}
FINDING_FIELDS = {"category", "evidence_state", "citations", "interpretation", "confidence"}
CITATION_FIELDS = {"document", "location", "quote"}
CONFIDENCE = {"high", "medium", "low"}
MAX_OUTPUT_CHARS = 60_000
MAX_TEXT = 600
MAX_QUESTIONS = 12


class OutputRejected(Exception):
    """The model's answer can't be used at all. The assessment stops safely."""


@dataclass(frozen=True)
class CheckedCitation:
    document: str
    location: str
    quote: str
    verified: bool
    problem: str = ""


@dataclass(frozen=True)
class CheckedFinding:
    category: str
    evidence_state: str
    interpretation: str
    confidence: str
    citations: tuple[CheckedCitation, ...]

    def for_rules_engine(self) -> Finding:
        # Only citations whose quote was found count. The engine treats an uncited claim as absent.
        real = tuple(f"{c.document} {c.location}" for c in self.citations if c.verified)
        return Finding(self.category, self.evidence_state, real)


@dataclass(frozen=True)
class CheckedOutput:
    findings: tuple[CheckedFinding, ...]
    follow_up_questions: tuple[str, ...]
    summary: str
    problems: tuple[str, ...] = field(default=())


def validate(raw: str, documents: dict[str, list[tuple[str, str]]]) -> CheckedOutput:
    """documents: {file name: [(location, visible text), ...]} for this vendor only."""
    if len(raw) > MAX_OUTPUT_CHARS:
        raise OutputRejected("Model output is too long")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise OutputRejected("Model output is not valid JSON") from None
    if not isinstance(data, dict):
        raise OutputRejected("Model output must be a JSON object")
    _exact_fields(data, TOP_LEVEL, "the answer")

    findings_in = data["findings"]
    if not isinstance(findings_in, list):
        raise OutputRejected("'findings' must be a list")
    seen: set[str] = set()
    problems: list[str] = []
    findings: list[CheckedFinding] = []
    for index, item in enumerate(findings_in, start=1):
        if not isinstance(item, dict):
            raise OutputRejected(f"Finding {index} is not an object")
        _exact_fields(item, FINDING_FIELDS, f"finding {index}")
        category, state = item["category"], item["evidence_state"]
        if category not in ruleset.CATEGORIES:
            raise OutputRejected(f"Finding {index} has an unknown category")
        if state not in ruleset.PROPOSED_STATES:
            raise OutputRejected(f"Finding {index} has an unknown evidence state")
        if category in seen:
            raise OutputRejected(f"Category {category} appears twice")
        seen.add(category)
        if item["confidence"] not in CONFIDENCE:
            raise OutputRejected(f"Finding {index} has an unknown confidence level")
        interpretation = _text(item["interpretation"], f"finding {index} interpretation")
        if not isinstance(item["citations"], list):
            raise OutputRejected(f"Finding {index} citations must be a list")

        citations = []
        for c_index, citation in enumerate(item["citations"], start=1):
            if not isinstance(citation, dict):
                raise OutputRejected(f"Finding {index} citation {c_index} is not an object")
            _exact_fields(citation, CITATION_FIELDS, f"finding {index} citation {c_index}")
            checked = _check_citation(
                _text(citation["document"], "document"), _text(citation["location"], "location"),
                _text(citation["quote"], "quote"), documents)
            if not checked.verified:
                problems.append(f"{category}: {checked.problem}")
            citations.append(checked)
        findings.append(CheckedFinding(category, state, interpretation, item["confidence"], tuple(citations)))

    questions = data["follow_up_questions"]
    if not isinstance(questions, list) or len(questions) > MAX_QUESTIONS:
        raise OutputRejected("'follow_up_questions' must be a list of at most 12 questions")
    return CheckedOutput(
        findings=tuple(findings),
        follow_up_questions=tuple(_text(q, "follow-up question") for q in questions),
        summary=_text(data["summary"], "summary"),
        problems=tuple(problems),
    )


def _exact_fields(obj: dict, expected: set[str], where: str) -> None:
    extra = set(obj) - expected
    if extra:
        # The name of an unexpected field is model-chosen text, so it's reported but trimmed
        names = ", ".join(sorted(str(name)[:40] for name in extra))
        raise OutputRejected(f"Unexpected field in {where}: {names}")
    missing = expected - set(obj)
    if missing:
        raise OutputRejected(f"Missing field in {where}: {', '.join(sorted(missing))}")


def _text(value, where: str) -> str:
    if not isinstance(value, str):
        raise OutputRejected(f"{where} must be text")
    return value.strip()[:MAX_TEXT]


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _check_citation(document: str, location: str, quote: str, documents) -> CheckedCitation:
    def fail(problem: str) -> CheckedCitation:
        return CheckedCitation(document, location, quote, False, problem)

    if document not in documents:
        return fail(f"cites '{document[:60]}', which wasn't uploaded for this vendor")
    if len(_normalise(quote)) < 3:
        return fail("citation has no quote")
    segments = documents[document]
    page = re.fullmatch(r"(?:page|p\.?)\s*(\d+)", location.strip(), re.IGNORECASE)
    if page:
        candidates = [text for loc, text in segments if loc == f"page {page.group(1)}"]
    else:
        # Questionnaire citations use the question ID, which starts its row: "IR-03 | ..."
        candidates = [text for _, text in segments if text.split(" | ", 1)[0].strip().upper() == location.strip().upper()]
    if not candidates:
        return fail(f"location '{location[:40]}' doesn't exist in {document}")
    if not any(_normalise(quote) in _normalise(text) for text in candidates):
        return fail(f"quote not found at {document} {location[:40]}")
    return CheckedCitation(document, location, quote, True)
