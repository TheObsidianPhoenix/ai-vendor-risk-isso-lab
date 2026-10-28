"""Retrieval by control area: send the model only what each category needs.

Why: a full CAIQ v4 can run to several hundred thousand characters, well past
the 120,000-character limit for one model call (SR-14, cost cap). Instead of
cutting the document off, the assessment runs one focused pass per control
category, and each pass gets only the document sections that are about that
category.

How sections are picked (deterministic, no extra service, no extra cost):

1. Question IDs. A questionnaire row whose ID starts with a category's prefix
   is always included: "IAM-" for identity and access, "CEK-" (CAIQ v4) or
   "ENC-" for encryption, and so on.
2. Keywords. Other sections are ranked by how many of the category's keywords
   they contain, and added best first until the category's character budget
   is used up.
3. Context. The first rows or page of every document (its title and reference)
   are always included, so the model knows what it's reading.

Plain keyword matching was chosen over embeddings on purpose: it's
repeatable, explainable line by line, needs no vector database, and sends no
text to another service. Its weakness is that a section using none of the
expected words is missed. The retrieval-recall check in the evals measures
exactly that, against the sources in each answer key.

Nothing here weakens a control: every pass goes through the same fenced
prompt, strict validation, quote check and evidence rule, and a quote is
only accepted if it's found in a section that pass was actually sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.rules_engine import ruleset

CATEGORY_BUDGET_CHARS = 24_000   # About 6,000 tokens of document text per pass
CONTEXT_SEGMENTS = 3             # Title and reference rows/page of each document
MAX_PASS_CHARS = 100_000         # Hard ceiling even for ID-matched rows, under the 120,000 model limit

# Question-ID prefixes: CAIQ v4 domain codes, plus this project's sample questionnaire codes.
ID_PREFIXES: dict[str, tuple[str, ...]] = {
    "identity_access": ("IAM",),
    "encryption": ("CEK", "ENC"),
    "incident_response": ("SEF", "IR"),
    "vulnerability_management": ("TVM", "VM"),
    "data_retention": ("DSP", "DR"),
    "logging_monitoring": ("LOG", "LM"),
    "business_continuity": ("BCR", "BC"),
    "security_awareness": ("HRS", "SA"),
    "secure_development": ("AIS", "CCC", "SD"),
    "third_party": ("STA", "TP"),
    "privacy": ("DSP", "PR"),
    "ai_governance": ("AI",),
}

KEYWORDS: dict[str, tuple[str, ...]] = {
    "identity_access": ("access", "mfa", "multi-factor", "multifactor", "single sign-on", "sso", "password",
                        "authenticat", "privileged", "least privilege", "account", "logical access"),
    "encryption": ("encrypt", "tls", "aes", "key management", "cryptograph", "kms", "at rest", "in transit"),
    "incident_response": ("incident", "breach", "notif", "forensic", "security event"),
    "vulnerability_management": ("vulnerab", "patch", "penetration", "pen test", "scan", "cve", "remediat"),
    "data_retention": ("retain", "retention", "delet", "dispos", "purge", "destroy", "contract end"),
    "logging_monitoring": ("logging", "log ", "logs", "monitor", "siem", "alert", "audit trail"),
    "business_continuity": ("continuity", "disaster", "recovery", "backup", "rto", "rpo", "resilien", "restore"),
    "security_awareness": ("awareness", "training", "phishing", "background check", "onboarding"),
    "secure_development": ("development", "sdlc", "code review", "secure coding", "change management",
                           "software", "release", "testing"),
    "third_party": ("subprocessor", "sub-processor", "third part", "third-part", "supplier", "vendor",
                    "partner", "fourth"),
    "privacy": ("privacy", "personal data", "personal information", "gdpr", "ccpa", "data subject", "consent"),
    "ai_governance": ("artificial intelligence", "machine learning", "model", "train", "llm", " ai ", "ai-",
                      "transcription", "opt out", "opt-out"),
}

_ID = re.compile(r"^\s*([A-Z&]{1,4})-\d")


@dataclass(frozen=True)
class Selection:
    category: str
    documents: dict[str, list[tuple[str, str]]]   # {file name: [(location, text), ...]}, original order
    chars: int
    segments: int
    truncated: bool = False   # True if ID-matched rows alone passed MAX_PASS_CHARS and some were left out


def question_prefix(text: str) -> str | None:
    """'IAM-01.2 | Is MFA...' -> 'IAM'. Questionnaire rows start with their question ID."""
    match = _ID.match(text.split(" | ", 1)[0])
    return match.group(1) if match else None


def relevance(category: str, location: str, text: str) -> int:
    if question_prefix(text) in ID_PREFIXES[category]:
        return 1_000
    lowered = f" {text.lower()} "
    return sum(lowered.count(word) for word in KEYWORDS[category])


def select(category: str, documents: dict[str, list[tuple[str, str]]],
           budget: int = CATEGORY_BUDGET_CHARS) -> Selection:
    """Pick the sections of this vendor's documents to send for one category."""
    if category not in ruleset.CATEGORIES:
        raise ValueError(f"Unknown category: {category}")
    chosen: set[tuple[str, int]] = set()
    used = 0
    for name, segments in documents.items():
        for index in range(min(CONTEXT_SEGMENTS, len(segments))):
            chosen.add((name, index))
            used += len(segments[index][1])

    ranked = sorted(
        ((relevance(category, loc, text), name, index, len(text))
         for name, segments in documents.items()
         for index, (loc, text) in enumerate(segments)
         if (name, index) not in chosen),
        key=lambda item: (-item[0], item[1], item[2]))
    truncated = False
    for points, name, index, size in ranked:
        if points <= 0:
            break
        if used + size > budget and points < 1_000:
            continue   # Keyword matches are optional; a section that won't fit is skipped
        if used + size > MAX_PASS_CHARS:
            truncated = True   # Even matching question rows stop here; the record says so
            continue
        chosen.add((name, index))
        used += size

    picked = {name: [seg for i, seg in enumerate(segments) if (name, i) in chosen]
              for name, segments in documents.items()}
    return Selection(category, picked, used, len(chosen), truncated)
