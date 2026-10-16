# Vendor Risk Scoring Methodology

| | |
|---|---|
| **Rule set** | 1.0 |
| **Code** | [`app/rules_engine/`](../../app/rules_engine/) (policy values in [`ruleset.py`](../../app/rules_engine/ruleset.py)) |
| **Tests** | [`tests/test_rules_engine.py`](../../tests/test_rules_engine.py) |
| **Document owner** | Jasmine Alexander, ISSO |
| **Status** | Draft. One open policy question (section 9). |

> **Decision authority statement:** AI recommendations are advisory. Final vendor risk acceptance and approval authority remains with an authorized human reviewer.

## 1. Principle

**The model reads, the code scores, and a person decides.**

The AI extraction step reads vendor documents and proposes an *evidence state* for each control category, with a citation. It never assigns points. This rules engine converts evidence states into a score using fixed, published rules, so the same evidence always gives the same result and anyone can recompute it by hand. A reviewer then makes the decision.

## 2. Evidence states

The AI may propose one of five states. The engine decides what each is worth.

| Proposed state | Meaning | Scored as (standard control) | Scored as (critical control) |
|---|---|---|---|
| `verified` | Described and backed by independent evidence, such as an audit report | verified: **0** | verified: **0** |
| `unverified` | Claimed by the vendor, with no supporting evidence | unverified: **6** | unverified: **6** |
| `conflict` | Two vendor sources disagree | conflict: **8** | conflict: **8** |
| `absent` | Not mentioned or left blank | absent: **12** | critical gap: **25** |
| `contradicted` | The documents show the control is not in place | absent: **12** | critical gap: **25** |

## 3. Categories

Identity & access, encryption, incident response, vulnerability management, data retention, logging & monitoring, business continuity, security awareness, secure development, third-party risk, privacy, and AI governance.

**Critical categories:** identity & access, encryption, incident response, and AI governance.

**AI governance** is scored only when the vendor uses AI on our data. That fact comes from the vendor record entered by a person, not from the vendor's documents or the model, so a document can't talk its way out of an AI assessment.

## 4. Score and classification

The score is the sum of the points for every category, capped at 100.

| Score | Classification |
|---|---|
| 0–24 | Low |
| 25–49 | Moderate |
| 50–74 | High |
| 75–100 | Critical |

**Floor rules** apply after the bands:

- One critical gap sets the classification to at least **High**.
- Two or more critical gaps set it to **Critical**.

## 5. Safeguards built into the scoring

| Safeguard | Why | Requirement |
|---|---|---|
| A finding without a citation counts as **absent** | A claim the model can't point to in the documents doesn't count, whether it came from a model error or injected text | SR-13 |
| A category missing from the AI's output counts as **absent** | A model can't lower a score by leaving things out | SR-11 |
| Unknown categories, unknown states and duplicate categories stop scoring with an error | Fail closed: nothing is guessed. Duplicates are rejected so a manipulated response can't add a second, better finding | SR-11 |
| A prompt-injection flag adds **no points** and doesn't lower any | The vendor is still assessed on its evidence; the flag is shown to the reviewer | SR-08 |
| The result has no decision, approval or status field, and always says human review is required | The engine advises; it has no way to decide | HR-01, SR-12 |
| Every result records the rule set version | A past score can always be explained by the rules in force at the time | CM-3 |

## 6. Worked example: Nimbus Notes AI

| Category | Proposed | Scored | Points |
|---|---|---|---|
| Identity & access | verified | verified | 0 |
| Encryption | verified | verified | 0 |
| Incident response | conflict (30 days vs 72 hours) | conflict | 8 |
| Vulnerability management | absent (questions blank) | absent | 12 |
| Data retention | absent (no limit) | absent | 12 |
| Logging & monitoring | unverified | unverified | 6 |
| Business continuity | unverified | unverified | 6 |
| Security awareness, secure development, third-party, privacy | verified | verified | 0 |
| AI governance | contradicted (trains on customer data by default) | **critical gap** | 25 |
| **Total** | | | **69, High** |

One critical gap means the classification must be at least High; at 69 it already is. The prompt-injection flag from intake is recorded and changes nothing in the score.

## 7. Expected results for the test vendors

| Vendor | Score | Classification |
|---|---|---|
| Nimbus Notes AI | 69 | High |
| Copperline Backup | 80 | Critical |
| Kestrel Payroll Cloud | 0 | Low |

These are written in each vendor's `expected-findings.json` independently of the engine, and the tests check the engine reproduces them.

## 8. Changing the rules

Point values, bands, critical categories and floor rules live in `ruleset.py`. A change:

1. goes through a pull request (required by the repository ruleset),
2. increases `VERSION`,
3. updates this document and the expected results, and
4. must pass the test suite before it can merge.

## 9. Open policy question: self-attested vendors

Copperline Backup scores **80, Critical**, though nothing it says is contradicted. It simply sent answers without evidence: eight "unverified" categories add 48 points on their own. A Critical rating also triggers the two-person review rule.

Options for the document owner to decide:

| Option | Effect on Copperline | Tradeoff |
|---|---|---|
| **A. Keep rule set 1.0** | 80, Critical | Strongly rewards evidence. Treats a vendor that sends nothing as seriously as one with real gaps. |
| **B. Lower "unverified" from 6 to 4 points** | 64, High | Missing evidence still matters, but less than real gaps. Changes Nimbus to 65 (still High). |
| **C. Add a band cap: unverified alone can't exceed High** | 80, capped at High | Keeps the score, adjusts the label. Adds a rule reviewers must understand. |
| **D. Add a "request evidence" outcome before rating** | Not rated until evidence is requested | Closest to real TPRM practice, but it's a workflow change, not a scoring change. |

**Decision:** pending. Recorded here once made, with the rule set version it applies to.

## 10. Test evidence

`python3 -m unittest discover -s tests -v` runs 22 tests on every pull request (the **Tests** check). To confirm the tests can actually fail, the engine was deliberately broken three ways before this was committed. Each break was caught:

| Deliberate break | Tests that failed |
|---|---|
| "Unverified" worth 5 points instead of 6 | 2 |
| Accept findings without citations | 5 |
| Let the prompt-injection flag lower the score | 3 |
