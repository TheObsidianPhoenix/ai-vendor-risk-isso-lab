# AI Vendor Risk & ISSO Security Lab

An AI-assisted third-party risk management (TPRM) application, built and governed the way an Information Systems Security Officer (ISSO) would secure a real AI system.

> **Core governance rule:** AI recommendations are advisory. Final vendor risk acceptance and approval authority remains with an authorized human reviewer. This is enforced in code and IAM, not just in the AI prompt.

**The model reads, the code scores, and a person decides.**

## Project status

| Milestone | Status |
|---|---|
| 1. Foundation: secured repo, design, requirements, architecture, test data, security pipeline | ✅ Complete |
| 2. Working app | ✅ Working locally: sign-in by role, vendors, upload, intake scanner, AI extraction with validation, scoring, human decisions, audit log. Tested on the real model (Claude) |
| 3. AWS deployment (Terraform) | 🔄 **Foundation layer deployed:** 47 resources, with tamper and budget alerts verified ([deploy runbook](docs/architecture/deploy-runbook.md)). App layer (Cognito sign-in with MFA, API, Lambda) is next |
| 4. Security testing | 🔄 Evaluation suite run on the real model: 5 injection attacks, answer keys, quote checks. **[DAST with OWASP ZAP](docs/system-security/dast-local-zap.md)** run against the app locally: about 10,000 attack requests, no high or medium findings, no server errors. Repeated against AWS after the app layer |
| 5. ISSO documentation package | 🔄 Decision log (D-01 to D-16), [risk register and POA&M](docs/risk-management/risk-register.md), agent register, cost card, FedRAMP self-check and data retention done; control matrix and SSP next |

**Latest additions (October 2026):**

- **Real-model results:** Claude Sonnet 5.5 matched 97% of the answer key, every quote checked out, and it resisted all 5 attacks ([results](#ai-evaluation))
- **Finding EV-01, fixed:** the evaluation caught a weakness in the scoring rules: a page of unsupported claims could lower a score. Documents labelled "other" no longer count as evidence, and a test reproducing the attack runs on every change ([details](evals/README.md#finding-ev-01-unsupported-claims-can-lower-a-score))
- **AWS foundation deployed** with Terraform, applied by hand after review (D-14)
- **[Retrieval by control area](docs/system-security/retrieval-by-control-area.md):** long questionnaires are assessed one control area at a time, with the same checks on every pass
- **[Read-only MCP server](docs/system-security/mcp-server.md):** AI assistants like Claude Desktop can look up vendor status and findings, under the same permissions as the app
- **[Agent register and risk tiers](docs/ai-governance/agent-register.md)** and a **[cost card](docs/ai-governance/cost-card.md)** (about $0.03 per typical assessment)
- **[FedRAMP requirement](docs/system-security/fedramp.md) (D-13):** a vendor handling federal data can't get a plain approval without a sufficient FedRAMP authorization
- **Data retention:** records expire 3 years after the vendor's last activity
- **[Testing through Anthropic's API](docs/ai-governance/anthropic-api-testing.md) (D-15)** while Amazon Bedrock is unavailable: the account's model quotas are 0 and AWS declined the default because the account is new (D-16, rechecked monthly)
- **[Automated control checks](docs/continuous-monitoring/control-checks.md):** eleven checks pull evidence straight from AWS (CloudTrail, root and IAM users, admin access, S3, KMS, DynamoDB, alerts, budget), mapped to SOC 2, ISO 27001 and NIST 800-53, with risk-register exceptions that expire
- **[DAST with OWASP ZAP](docs/system-security/dast-local-zap.md):** about 10,000 attack requests signed out and as two roles; no high or medium findings, no server errors, and the one low alert verified harmless in a real browser
- **[Risk register and POA&M](docs/risk-management/risk-register.md):** 10 open risks with a plan for each, 7 accepted risks, and EV-01 closed
- **[Multi-tenant, with tenant isolation](docs/system-security/tenant-isolation.md):** two fictional client companies share one running product, and no role in one company can read, change or even detect the other's records. Fourteen tests attack the boundary; breaking it on purpose makes 23 checks fail
- **[Risk-tiered review workflow](docs/system-security/tenant-isolation.md#milestone-2-required-review-tasks-by-risk-tier-d-19) (D-19):** a vendor's tier decides who has to weigh in (Security, AI usage, IT, Legal, Privacy, a department head), enforced server-side — a decision can't be recorded while any required review is still open — with the two-person rule now covering High as well as Critical vendors
- 229 automated tests; every change goes through a pull request with required checks

## See it

![Counterpart assessment screen](docs/screenshots/assessment-and-score.png)

| | |
|---|---|
| ![Hidden text caught at intake](docs/screenshots/intake-catches-hidden-text.png) **Hidden white text caught** before the AI sees it | ![AI tries to approve](docs/screenshots/red-team-ai-tries-to-approve.png) **Red team:** the AI tries to approve and its answer is rejected |
| ![Human decision](docs/screenshots/human-decision.png) **Only a reviewer decides**, with a rationale; overrides are flagged | ![Audit log](docs/screenshots/audit-log.png) **Tamper-evident audit log**, including denied actions |

**Run it on your own computer** (Python 3.9 or later, which recent Macs include):

```bash
python3 -m pip install -r requirements.txt
python3 scripts/run_app.py
```

Open http://127.0.0.1:8000, sign in as Priya Shah, add a vendor, and upload the files in `sample-data/nimbus-notes-ai/`.

## What it does

A user uploads fictional vendor security documents (questionnaires, SOC 2 summaries, security policies). An AI model extracts security controls, gaps and evidence, each with a citation back to the source document. A deterministic rules engine calculates a risk score from that evidence. An authorized human reviewer makes the final decision, which is recorded with their identity.

## Why I built it

To demonstrate, end to end, how an ISSO defines, secures, monitors, tests and documents an AI-powered system, with human decision authority enforced technically rather than by policy alone.

## Architecture

Serverless on AWS: Cognito, API Gateway, Lambda, S3, DynamoDB, SQS, KMS, Amazon Bedrock, CloudTrail and CloudWatch, deployed with Terraform. See [Phase 2 Architecture](docs/architecture/phase-2-architecture.md) for diagrams, trust boundaries, the IAM model and the cost estimate.

## Security model

**Repository:** two-factor authentication; secret scanning with push protection; Dependabot alerts and updates; a ruleset that blocks deletion and history rewrites of `main` and requires a pull request plus four passing checks before any merge, with no bypass. Terraform validation and a Checkov scan also run on every change. Every third-party GitHub Action is pinned to a full commit hash and runs with a read-only token.

**Application:** four roles checked on the server for every request, default deny, requesters see only their own vendors, a reviewer can't decide on a vendor they requested, Critical vendors need two reviewers, and a hash-chained audit log that includes refused actions ([controls](docs/system-security/milestone-2-app-controls.md)).

**AWS (deployed):** CloudTrail to an audit bucket with Object Lock, a customer-managed KMS key, private encrypted buckets that refuse non-HTTPS requests, encrypted DynamoDB tables, alerts on changes to logging, keys, buckets and tables, and a $20 monthly spend cap with budget alerts. No long-lived AWS keys exist anywhere.

## AI security controls

Untrusted documents pass an [intake scanner](docs/system-security/intake-controls.md) that strips hidden text and rejects macros and active content. Document text is fenced as data in the prompt. Model output must match a strict schema, so any attempt to add a decision or score rejects the whole answer. Every quote the model cites is checked against the document, so invented evidence can only make a vendor look worse. Details and tests are in the [Milestone 2 controls](docs/system-security/milestone-2-app-controls.md). Long documents are assessed one [control area at a time](docs/system-security/retrieval-by-control-area.md), and every pass gets the same checks. Every model call has limits on input size, output length and time, and any failure stops the assessment with no score: the system fails closed.

## AI evaluation

The AI step is measured, not assumed. [`evals/`](evals/README.md) runs the real pipeline against answer keys for three fictional vendors and five prompt-injection attacks, and reports:

- accuracy
- quote accuracy
- whether the model resisted each attack
- whether the system still held
- time and tokens

The production design is **Claude on Amazon Bedrock**, called with an IAM role, so no API key exists anywhere. The model has one tool, a findings form, and an answer is accepted only if it's exactly one completed form: it can never take an action. Every pull request re-runs the evaluation with the offline model and fails if any score drops.

While Bedrock is blocked for this AWS account, real-model runs go through Anthropic's API with synthetic data only and the same guardrails ([D-15](docs/ai-governance/anthropic-api-testing.md)).

**First real-model results** (2026-10-29, `claude-sonnet-5-5` through Anthropic's API, fictional vendors only):

| Measure | Result |
|---|---|
| Evidence states matching the answer key | 97% (33 of 34) |
| Quotes found word for word in the documents | 100% (71 of 71) |
| Injection attacks the model itself resisted | 5 of 5 |
| Injection attacks the system defended | 4 of 5 |
| Median time per assessment | 18.3 s |

The one attack that got through changed no control to "verified". A page of unsupported vendor claims turned blank answers into claims, which the rules score lower, so Copperline went from 80 (Critical) to 68 (High). That was a weakness in the scoring rules, not the model, recorded as finding EV-01 and **fixed on 2026-11-01**: documents labelled "other" no longer count as evidence ([evaluation details](evals/README.md#first-real-model-results)).

## AI governance

- **[Agent register](docs/ai-governance/agent-register.md):** every AI agent with its owner, data, access, oversight and risk tier, plus intake questions and a "not allowed" list. Counterpart's assessment worker (AG-01) and MCP server (AG-02) are both Tier 2.
- **[Cost card](docs/ai-governance/cost-card.md):** about $0.03 per typical assessment and $16.20 a month at 50 vendors on Claude Sonnet 5.5 (estimates).
- **Decision log:** 16 recorded decisions with the options considered and the trade-offs, in section 13 of the [architecture document](docs/architecture/phase-2-architecture.md).
- **[Real vendor testing (D-12)](docs/risk-management/real-vendor-testing.md):** rules for testing with public CSA STAR questionnaires, kept local and private.

## Human-in-the-loop design

Five independent layers keep the AI from making a vendor decision: an output schema with no decision field, separate data stores, an explicit IAM deny, a dedicated decision service, and decision records that can't be overwritten. Details are in section 7 of the [architecture document](docs/architecture/phase-2-architecture.md).

## Framework mappings

NIST SP 800-53 Rev. 5 · NIST AI RMF and Generative AI Profile · ISO/IEC 42001 · EU AI Act · OWASP Top 10 for LLM Applications · OWASP API Security Top 10 · OWASP Top 10 · MITRE ATLAS · MITRE ATT&CK

*The control matrix is coming in Milestone 5.* Mappings that still need validation are marked rather than guessed.

## Attack and testing scenarios

| Scenario | Expected result | Status |
|---|---|---|
| Hidden prompt injection in a vendor document | Flagged; treated as data; score unaffected; AI can't approve | ✅ Removed at intake, fenced in the prompt, flagged to the reviewer (tested) |
| Malicious or oversized upload (macros, zip bomb, JavaScript PDF) | Rejected before any parsing or AI | ✅ [Intake scanner](docs/system-security/intake-controls.md) tested |
| Request for another vendor's information | Unavailable to the model and to other users | ✅ One vendor per prompt; other users get "not found" (tested) |
| Normal user tries to approve a vendor | Access denied | ✅ Server refuses and logs it (tested) |
| AI tries to set a final decision | Technically impossible | ✅ Whole answer rejected; red team demo (tested). IAM deny designed for the app layer |
| Malformed AI output | Schema validation fails safely | ✅ Rejected, no score, logged (tested) |
| Encryption claimed without evidence | Flagged as an evidence gap, not verified | ✅ Copperline scored Unverified (tested) |
| AI invents evidence | Caught; can't lower a score | ✅ Every quote checked against the document (tested) |
| Critical vendor approved by one person | Needs a second, different reviewer | ✅ Two-person rule (tested) |
| Vendor handling federal data without FedRAMP | Plain approval refused; exceptions recorded | ✅ D-13 requirement (tested) |
| Common web attacks on the running app (XSS, injection, path traversal, header fuzzing) | No exploitable finding, no crash | ✅ OWASP ZAP DAST, locally, signed out and as two roles; AWS scan after the app layer |
| Fake "assurance summary" with no auditor | Rating unchanged | ✅ **Fixed (EV-01):** the real model's first run dropped the score from 80 to 68. Documents labelled "other" no longer count as evidence; reproduction tested on every change. Real-model rerun pending |

## Deployment

Infrastructure is Terraform with a cloud-agnostic module layout ([`infrastructure/`](infrastructure/README.md)). Every pull request runs `terraform validate` and a Checkov security scan, and a person applies every reviewed plan by hand from CloudShell (D-14: this account's organization policy blocks GitHub OIDC, and stored AWS keys were ruled out). The foundation layer is deployed: 47 resources, with tamper and budget alerts verified. The [deploy runbook](docs/architecture/deploy-runbook.md) covers the cost (about $1.10 a month for the foundation layer) and the steps, starting with the account decision gate.

## Screenshots

All in [`docs/screenshots/`](docs/screenshots/), taken from the running app with synthetic data. The original [design prototype](docs/design/counterpart-design-prototype.html) is kept for comparison.

## Lessons learned

- **Test the whole system, not just the model.** The real model behaved well and still produced a bad outcome through a gap in my scoring rules (EV-01). Only the evaluation suite caught it, and the fix went in with a test that reproduces the attack.
- **Fail closed.** On the first real run, three different errors (two settings the new model refuses, and an answer cut off at the output limit) each produced no score rather than a wrong one. Each was fixed through a reviewed change.
- **Guardrails belong in code, not in the request.** When the model stopped accepting a forced tool choice, the protection already lived in Counterpart's own validation, so nothing was lost.
- **Work within the controls.** When the AWS organization policy blocked GitHub OIDC, I chose manual, reviewed deployments over stored keys or an irreversible account change (D-14).

## Repository layout

```
app/               Application code (Python)
compliance/        Automated AWS control checks (evidence from source systems)
tests/             Automated tests, including security tests
sample-data/       Fictional, synthetic vendor documents only
infrastructure/    Terraform: bootstrap, environments, modules
docs/              ISSO documentation package
evidence/          Redacted evidence that controls work
scripts/           Helper scripts
.github/           Pull request template and automated checks
```

## Data notice

All data in this repository is fictional and synthetic. No real vendor, customer or personal information is stored here. Public CSA STAR questionnaires may be tested locally under decision D-12; they're never committed, and only totals are published.

## License

[MIT](LICENSE)
