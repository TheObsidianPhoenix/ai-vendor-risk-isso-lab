# AI Vendor Risk & ISSO Security Lab

An AI-assisted third-party risk management (TPRM) application, built and governed the way an Information Systems Security Officer (ISSO) would secure a real AI system.

> **Core governance rule:** AI recommendations are advisory. Final vendor risk acceptance and approval authority remains with an authorized human reviewer. This is enforced in code and IAM, not just in the AI prompt.

**The model reads, the code scores, and a person decides.**

## Project status

| Milestone | Status |
|---|---|
| 1. Foundation: secured repo, design, requirements, architecture, test data, security pipeline | ✅ Complete |
| 2. Working app (local, with a pretend AI) | ✅ Working: sign-in by role, vendors, upload, intake scanner, AI extraction with validation, scoring, human decisions, audit log |
| 3. AWS deployment (Terraform) | 🔄 Foundation layer written and security-scanned ([infrastructure](infrastructure/README.md)); not yet deployed |
| 4. Security testing | ⏳ Planned |
| 5. ISSO documentation package | ⏳ Planned |

**Completed so far:** GitHub repository secured, with every change to `main` requiring a pull request and passing security checks · design prototype · [Phase 1 Requirements & Security Brief](docs/system-security/phase-1-requirements-security-brief.md) · [Phase 2 Architecture](docs/architecture/phase-2-architecture.md) · AWS account baseline (Phase 0) · [fictional vendor documents with planted attacks](sample-data/README.md) · automated security checks (CodeQL, dependency review, test-data integrity, Dependabot) · [intake scanner](docs/system-security/intake-controls.md) · [working app with AI guardrails and human review](docs/system-security/milestone-2-app-controls.md) (95 automated tests)

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

**In place now (repository):** two-factor authentication; secret scanning with push protection; Dependabot alerts and updates; a ruleset that blocks deletion and history rewrites of `main` and requires a pull request plus four passing checks before any merge, with no bypass. Every third-party GitHub Action is pinned to a full commit hash and runs with a read-only token.

*Coming in Milestones 2 and 3:* application identity, data protection, logging and monitoring controls, with links to the control matrix.

## AI security controls

Untrusted documents pass an [intake scanner](docs/system-security/intake-controls.md) that strips hidden text and rejects macros and active content. Document text is fenced as data in the prompt. Model output must match a strict schema, so any attempt to add a decision or score rejects the whole answer. Every quote the model cites is checked against the document, so invented evidence can only make a vendor look worse. Details and tests are in the [Milestone 2 controls](docs/system-security/milestone-2-app-controls.md). Consumption limits per user arrive with Amazon Bedrock in Phase 5.

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
| AI tries to set a final decision | Technically impossible | ✅ Whole answer rejected; red team demo (tested). IAM deny added in Milestone 3 |
| Malformed AI output | Schema validation fails safely | ✅ Rejected, no score, logged (tested) |
| Encryption claimed without evidence | Flagged as an evidence gap, not verified | ✅ Copperline scored Unverified (tested) |
| AI invents evidence | Caught; can't lower a score | ✅ Every quote checked against the document (tested) |
| Critical vendor approved by one person | Needs a second, different reviewer | ✅ Two-person rule (tested) |

## Deployment

Infrastructure is Terraform with a cloud-agnostic module layout ([`infrastructure/`](infrastructure/README.md)). Every pull request runs `terraform validate` and a Checkov security scan, and GitHub will deploy with short-lived OIDC credentials, never stored keys. The [deploy runbook](docs/architecture/deploy-runbook.md) covers the cost (about $1.10 a month for the foundation layer) and the steps, starting with the account decision gate.

## Screenshots

All in [`docs/screenshots/`](docs/screenshots/), taken from the running app with synthetic data. The original [design prototype](docs/design/counterpart-design-prototype.html) is kept for comparison.

## Lessons learned

*Added as the project progresses.*

## Repository layout

```
app/               Application code (Python)
tests/             Automated tests, including security tests
sample-data/       Fictional, synthetic vendor documents only
infrastructure/    Terraform: bootstrap, environments, modules
docs/              ISSO documentation package
evidence/          Redacted evidence that controls work
scripts/           Helper scripts
.github/           Pull request template and automated checks
```

## Data notice

All data in this project is fictional and synthetic. No real vendor, customer or personal information is used.

## License

[MIT](LICENSE)
