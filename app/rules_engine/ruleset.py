"""Rule set 1.0: the scoring policy, kept apart from the code that applies it.

Changing anything in this file changes how vendors are rated, so it goes
through a reviewed pull request and the version number must go up
(change control: CM-3, SR-15). The methodology is explained in
docs/risk-management/scoring-methodology.md.
"""

from __future__ import annotations

VERSION = "1.0"

# Evidence states the AI extraction step may propose for a control category.
# The AI only proposes; the engine decides what each state is worth.
PROPOSED_STATES = frozenset({"verified", "unverified", "conflict", "absent", "contradicted"})

# Points added to the score for each scored state.
POINTS = {
    "verified": 0,      # Control described and backed by independent evidence
    "unverified": 6,    # Claimed by the vendor, with no supporting evidence
    "conflict": 8,      # Two vendor sources disagree
    "absent": 12,       # Not mentioned, left blank, or contradicted (standard control)
    "critical_gap": 25, # A critical control is absent or contradicted
}

# Classification bands, checked from highest floor down. Scores are capped at 100.
BANDS = ((75, "Critical"), (50, "High"), (25, "Moderate"), (0, "Low"))
MAX_SCORE = 100

# Every category the engine scores. A category missing from the AI's output
# is scored as absent, so a model can't lower a score by leaving things out.
CATEGORIES = (
    "identity_access",
    "encryption",
    "incident_response",
    "vulnerability_management",
    "data_retention",
    "logging_monitoring",
    "business_continuity",
    "security_awareness",
    "secure_development",
    "third_party",
    "privacy",
    "ai_governance",
)

# Categories where "absent" or "contradicted" becomes a critical gap.
CRITICAL_CATEGORIES = frozenset({"identity_access", "encryption", "incident_response", "ai_governance"})

# Scored only when the vendor uses AI on our data. That fact comes from the
# vendor record a person entered, never from the vendor's own documents or the
# model, so a document can't talk its way out of being assessed.
AI_ONLY_CATEGORIES = frozenset({"ai_governance"})
