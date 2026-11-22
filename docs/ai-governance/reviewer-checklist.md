# Reviewer checklist: AI-drafted findings

AG-01 (the Counterpart assessment worker) fills in one findings form per control area, with quotes from the vendor's own documents. A named reviewer makes every decision — this checklist is what that review should actually look at, not just confirm that a form exists. Written against OWASP LLM09 (Overreliance): the two-person rule and the fixed single-tool output already prevent the AI from acting on its own, but neither of those stops a reviewer from rubber-stamping a wrong finding.

## Before approving a finding, check:

1. **Does every quote actually appear in the source document, verbatim?** The independent-evidence rule and quote-check guardrail are meant to catch this automatically — treat a flagged mismatch as a hard stop, not something to wave through.
2. **Does the quote actually support the finding it's attached to?** A real quote can still be used to support the wrong conclusion (taken out of context, answering a different question than the control asks). The automated quote check proves the text exists in the document; it doesn't prove it means what the finding says it means.
3. **Is anything missing that should have been found?** The AI only reports on what it was asked to look for in the control areas it was given. A vendor document that's silent on a control isn't the same as a vendor document that satisfies it — confirm the finding distinguishes "not addressed" from "addressed and compliant."
4. **Does the confidence/rating match the actual evidence strength**, not just the presence of a plausible-sounding quote? A single sentence in a 40-page SOC 2 report is weaker evidence than a dedicated section — the finding should reflect that, not just that a match was found.
5. **For a Critical-rated vendor requiring two reviewers** — is the second reviewer actually looking independently, or just confirming the first reviewer's read? The control calls for two people, not one person twice.
6. **If the finding touches a regulated-data or FedRAMP question** — has the separate FedRAMP check (`app/decision/fedramp.py`, D-13) actually run and been recorded, rather than assumed from the AI's summary?
7. **Would this finding survive the vendor pushing back on it?** If a vendor disputed the finding, could you point to the exact quote and page/section it came from? If not, that's a sign the finding needs firmer evidence before it's approved, not just better phrasing.

## What this checklist is not

It doesn't replace the automated guardrails (intake scanner, quote verification, independent-evidence rule, deterministic scoring) — those run regardless of whether a reviewer is careful. It's specifically for the judgment calls those guardrails can't make: whether the evidence actually means what the finding claims.

## Related

- [Agent register, AG-01](agent-register.md#ag-01-in-detail-counterpart-assessment-worker) — what the AI worker can and can't do, and its known gaps
- [Risk register, R-05](../risk-management/risk-register.md) — the current evaluation set is small (3 fictional vendors, 5 attacks); a reviewer should treat findings on an unfamiliar vendor type with extra scrutiny until the evaluation set grows
