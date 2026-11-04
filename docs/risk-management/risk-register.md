# Risk register and POA&M

**Draft for review, 2026-11-03.** Owner: Jasmine Alexander (system owner and ISSO). Reviewed monthly, and whenever a decision, finding or deployment changes a risk.

Counterpart processes **synthetic data only** under its current authorization, so every rating below is for the system as designed for production, with today's exposure noted where it differs. Ratings use a simple scale: **likelihood** and **impact** are Low, Moderate or High, and the **risk** is the higher of the two unless a compensating control is noted. Control references are NIST SP 800-53 Rev. 5.

## Open risks

| ID | Risk | Control | Likelihood | Impact | Risk | Treatment | Status |
|---|---|---|---|---|---|---|---|
| R-01 | **Amazon Bedrock unavailable.** The account's model quotas are 0 and a request for the default was declined because the account is new (D-16). No real model can run inside AWS | SA-9, CP-2 | High (current) | Moderate | **Moderate** | Mitigate: Anthropic's API for synthetic-data tests with the same guardrails (D-15); production design unchanged; monthly recheck | POA&M P-01 |
| R-02 | **Daily work uses a full administrator role.** The AWS Projects sign-in role has `AdministratorAccess`, so a mistake or a stolen session could change anything in the account | AC-6, AC-2 | Moderate | High | **High** | Mitigate: a narrower role for routine work; keep the admin role for reviewed changes; the planned deploy role gets a permission boundary | POA&M P-02 |
| R-03 | **Temporary API key exists** for Anthropic's API, a secret outside AWS. It was briefly exposed on screen once and replaced | IA-5, SC-12 | Low | Low | **Low** | Mitigate: key only in the shell during a run, $5 spend limit, never in the repo; delete when testing ends | POA&M P-03 |
| R-04 | **Manual deployments.** Every Terraform change is applied by hand from CloudShell (D-14), so a person could apply the wrong plan | CM-3, CM-5 | Low | Moderate | **Moderate** | Mitigate: plans are reviewed before apply, Checkov and `terraform validate` run on every pull request, deployment record kept in the runbook | Accepted with compensating controls |
| R-05 | **Small evaluation set.** Real-model results come from 3 fictional vendors and 5 attacks. A larger or different document set could expose weaknesses the current set doesn't | SA-11, RA-3 | Moderate | Moderate | **Moderate** | Mitigate: add vendors and attacks over time; test the nine public CAIQs once a permitted model is available (D-12) | POA&M P-04 |
| R-06 | **App layer not built:** no Cognito sign-in with MFA, no API, no per-function IAM roles yet. Today the app runs only on a laptop, so there's no exposure | IA-2(1), AC-3 | Low (current) | High | **Moderate** | Avoid: the app is not put online until sign-in with MFA and the per-function roles, including the AI worker's explicit deny on decisions, are deployed | POA&M P-05 |
| R-07 | **No dynamic application security testing (DAST)** of a running deployment yet | RA-5, SA-11 | Moderate | Moderate | **Moderate** | Mitigate: OWASP ZAP scan once the app layer is deployed; the test suite already attacks the local API | POA&M P-06 |
| R-08 | **No incident response plan.** Alerts exist (CloudTrail tampering, key, bucket, table changes) but there is no written procedure, including for AI incidents | IR-8, IR-4 | Low | Moderate | **Moderate** | Mitigate: write the incident response procedure | POA&M P-07 |
| R-09 | **Terraform deprecation:** DynamoDB tables use `hash_key`, which is deprecated. A careless fix could replace (and empty) the tables | CM-2, CP-9 | Low | Moderate | **Low** | Mitigate: change to `key_schema` only with a plan that shows 0 to destroy | POA&M P-08 |
| R-10 | **Provider versions not locked:** `.terraform.lock.hcl` isn't committed, so a future `init` could pick up a different provider version | CM-2, SR-11 | Low | Low | **Low** | Mitigate: commit the lock file | POA&M P-09 |

## Accepted risks (recorded decisions)

| ID | Risk | Decision | Compensating controls |
|---|---|---|---|
| R-11 | No web application firewall | D-08 | Authentication on every route, API throttling, strict input validation |
| R-12 | GuardDuty, Security Hub and AWS Config not always on | D-09 | CloudTrail with tamper alerts; may be enabled briefly to capture findings |
| R-13 | Single region, no high availability | D-10 | Point-in-time recovery and versioning |
| R-14 | Audit bucket Object Lock in governance mode for 30 days, which an administrator with special permission can override | D-05 | Hash-chained audit log detects edits; production would use compliance mode |
| R-15 | One KMS key for all lab data | D-06 | Key policy limits each service; production would split keys |
| R-16 | No malware scanning of uploads | D-07 | Intake scanner rejects macros, active content and oversized files; synthetic data only |
| R-17 | Functions run outside a VPC (when deployed) | D-02 | IAM-only access to services; no inbound network path |

## Closed

| ID | Risk | Closed | How |
|---|---|---|---|
| EV-01 | A page of unsupported vendor claims could lower a vendor's score (found by the real-model evaluation: Copperline went from 80 Critical to 68 High) | 2026-11-01 | Documents labelled "other" no longer count as evidence; a reproduction test runs on every pull request ([details](../../evals/README.md#finding-ev-01-unsupported-claims-can-lower-a-score)). Real-model rerun to confirm is part of P-04 |
| R-18 | Budget alerts couldn't be delivered (the account couldn't verify email contacts) | 2026-10-29 | Routed through the confirmed security alert topic |

## POA&M (plan of action and milestones)

Target dates are proposals for the system owner to confirm.

| ID | Weakness | Risk | Milestones | Target | Status |
|---|---|---|---|---|---|
| P-01 | Bedrock unavailable | R-01 | Recheck the Bedrock quotas page monthly; when access opens, rerun the evaluation on Bedrock and update the README; then delete the Anthropic key | First recheck 2026-12-01 | Open |
| P-02 | Administrator role used for daily work | R-02 | Write a read-only or narrower role for routine checks; use the admin role only to apply reviewed plans; add a permission boundary to the deploy role | 2026-11-30 | Open |
| P-03 | Temporary API key | R-03 | Rerun the real-model evaluation to confirm EV-01; then delete the key in the Anthropic console | 2026-11-30 | Open |
| P-04 | Small evaluation set | R-05 | Confirm EV-01 on the real model; add at least one vendor and one attack; test the public CAIQs under D-12 when permitted | 2026-12-31 | Open |
| P-05 | App layer not built | R-06 | Decide the model for the online app (offline stand-in, Anthropic's API with Secrets Manager, or wait for Bedrock); build Cognito with MFA, API Gateway, Lambda and per-function roles; review cost before deploying | 2026-12-15 | Open |
| P-06 | No DAST | R-07 | OWASP ZAP baseline scan against the deployed app; record findings and fixes | After P-05 | Open |
| P-07 | No incident response plan | R-08 | Write the procedure: detection (existing alerts), triage, containment, AI-specific incidents (prompt injection, model misbehavior), lessons learned | 2026-11-30 | Open |
| P-08 | Terraform `hash_key` deprecation | R-09 | Change to `key_schema`; confirm the plan shows 0 to destroy before applying | 2026-11-20 | Open |
| P-09 | Provider lock file not committed | R-10 | Commit `.terraform.lock.hcl` for each environment | 2026-11-10 | Open |
