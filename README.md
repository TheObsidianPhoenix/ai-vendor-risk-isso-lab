# AI Vendor Risk & ISSO Security Lab

An AI-assisted third-party risk management (TPRM) application, built and governed the way an Information Systems Security Officer (ISSO) would secure a real AI system.

> **Core governance rule:** AI recommendations are advisory. Final vendor risk acceptance and approval authority remains with an authorized human reviewer. This is enforced in code and IAM, not just in the AI prompt.

**The model reads, the code scores, and a person decides.**

## Project status

| Milestone | Status |
|---|---|
| 1. Foundation: secured repo, design, requirements, architecture, test data, security pipeline | ✅ Complete |
| 2. Working app (local, with a pretend AI) | 🔄 Next |
| 3. AWS deployment (Terraform) | ⏳ Planned |
| 4. Security testing | ⏳ Planned |
| 5. ISSO documentation package | ⏳ Planned |

**Completed so far:** GitHub repository secured, with every change to `main` requiring a pull request and passing security checks · design prototype · [Phase 1 Requirements & Security Brief](docs/system-security/phase-1-requirements-security-brief.md) · [Phase 2 Architecture](docs/architecture/phase-2-architecture.md) · AWS account baseline (Phase 0) · [fictional vendor documents with planted attacks](sample-data/README.md) · automated security checks (CodeQL, dependency review, test-data integrity, Dependabot)

## What it does

A user uploads fictional vendor security documents (questionnaires, SOC 2 summaries, security policies). An AI model extracts security controls, gaps and evidence, each with a citation back to the source document. A deterministic rules engine calculates a risk score from that evidence. An authorized human reviewer makes the final decision, which is recorded with their identity.

## Why I built it

To demonstrate, end to end, how an ISSO defines, secures, monitors, tests and documents an AI-powered system, with human decision authority enforced technically rather than by policy alone.

## Architecture

Serverless on AWS: Cognito, API Gateway, Lambda, S3, DynamoDB, SQS, KMS, Amazon Bedrock, CloudTrail and CloudWatch, deployed with Terraform. See [Phase 2 Architecture](docs/architecture/phase-2-architecture.md) for diagrams, trust boundaries, the IAM model and the cost estimate.

## Security model

**In place now (repository):** two-factor authentication; secret scanning with push protection; Dependabot alerts and updates; a ruleset that blocks deletion and history rewrites of `main` and requires a pull request plus three passing checks before any merge, with no bypass. Every third-party GitHub Action is pinned to a full commit hash and runs with a read-only token.

*Coming in Milestones 2 and 3:* application identity, data protection, logging and monitoring controls, with links to the control matrix.

## AI security controls

*Coming in Milestone 2.* Untrusted-document handling, prompt-injection defenses, structured output with schema validation, and consumption limits.

## Human-in-the-loop design

Five independent layers keep the AI from making a vendor decision: an output schema with no decision field, separate data stores, an explicit IAM deny, a dedicated decision service, and decision records that can't be overwritten. Details are in section 7 of the [architecture document](docs/architecture/phase-2-architecture.md).

## Framework mappings

NIST SP 800-53 Rev. 5 · NIST AI RMF and Generative AI Profile · ISO/IEC 42001 · EU AI Act · OWASP Top 10 for LLM Applications · OWASP API Security Top 10 · OWASP Top 10 · MITRE ATLAS · MITRE ATT&CK

*The control matrix is coming in Milestone 5.* Mappings that still need validation are marked rather than guessed.

## Attack and testing scenarios

| Scenario | Expected result | Status |
|---|---|---|
| Hidden prompt injection in a vendor document | Flagged; treated as data; score unaffected; AI can't approve | ⏳ Planned |
| Request for another vendor's information | Unavailable to the model | ⏳ Planned |
| Normal user tries to approve a vendor | Access denied | ⏳ Planned |
| AI tries to set a final decision | Technically impossible | ⏳ Planned |
| Malformed AI output | Schema validation fails safely | ⏳ Planned |
| Encryption claimed without evidence | Flagged as an evidence gap, not verified | ⏳ Planned |

## Deployment

*Coming in Milestone 3.*

## Screenshots

*Coming in Milestone 2.* The interactive [design prototype](docs/design/counterpart-design-prototype.html) shows the planned screens.

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
