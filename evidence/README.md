# Evidence

Proof that each control is in place and working. An assessor should be able to pick any row and find the file.

## Rules

- **Redact before committing.** Cover AWS account numbers, email addresses, access portal URLs and anything that identifies a real person other than the system owner's name. On a Mac, open the screenshot in Preview, choose Markup, draw a filled rectangle over the detail, and save a copy.
- **Keep unredacted originals out of Git.** Store them in `evidence/raw/`, which is ignored, or outside the repository.
- **Never commit secrets** as evidence, even expired ones.
- **Name files** `YYYY-MM-DD_source_short-description.png`, for example `2026-10-07_github_2fa-enabled.png`.

## Evidence index

| ID | Control | What it shows | File | Collected |
|---|---|---|---|---|
| EV-001 | IA-2 (prelim.) | GitHub two-factor authentication enabled | `github/2026-10-07_github_2fa-enabled.png` | 2026-10-07 |
| EV-002 | RA-5, SI-2, IA-5 (prelim.) | Repository security features enabled (Dependabot, secret scanning, push protection) | `github/2026-10-07_github_security-features.png` | 2026-10-07 |
| EV-003 | CM-3, CM-5 (prelim.) | Branch ruleset protecting `main` | `github/2026-10-07_github_branch-ruleset.png` | 2026-10-07 |
| EV-004 | IA-2 (prelim.) | MFA on the AWS Settings sign-in | `aws/2026-10-11_aws_settings-mfa.png` | 2026-10-11 |
| EV-005 | AC-2, AC-6 (prelim.) | Console access through `AccountFullAccessRole` (temporary credentials, no access keys) | `aws/2026-10-11_aws_iam-roles.png` | 2026-10-11 |
| EV-006 | Cost guardrail (mapping to validate) | Zero-spend budget alert | `aws/2026-10-11_aws_zero-spend-budget.png` | 2026-10-11 |
| EV-007 | AU-2, AU-12 (prelim.) | CloudTrail trail delivering to S3 | `aws/2026-10-11_aws_cloudtrail-trail.png` | 2026-10-11 |
| EV-008 | CM-3 (prelim.) | First change merged through a pull request | `github/YYYY-MM-DD_github_first-pull-request.png` | Pending |

Control IDs marked "prelim." are preliminary and are validated in the Phase 10 control matrix.
