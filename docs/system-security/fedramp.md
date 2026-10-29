# FedRAMP in Counterpart

Two separate things, kept separate on purpose:

1. **A feature:** Counterpart checks whether a vendor that will handle federal data has the FedRAMP authorization it needs (decision D-13).
2. **A self-check:** how Counterpart itself lines up with FedRAMP. Counterpart is **not** FedRAMP authorized and can't be: authorization is for real cloud services sold to agencies, with an independent assessment. This is a readiness exercise, not a claim.

## 1. The FedRAMP requirement (D-13)

**Decided 2026-10-28, Jasmine Alexander (system owner).** A vendor that will handle federal data must hold a FedRAMP authorization at least as high as that data's impact level.

| Step | Who | What |
|---|---|---|
| Say whether federal data is involved | The **requester**, when creating the vendor | None, low, moderate or high impact. A document can't talk its way out of the requirement, the same idea as "uses AI on our data" |
| Record the vendor's FedRAMP status | A **reviewer**, after checking the public [FedRAMP Marketplace](https://www.fedramp.gov/marketplace/guide/) | Certified, in process or not listed; the class or level shown; the date checked; optionally the listing ID. The requester can't, so nobody vouches for their own vendor |
| Check the requirement | Code (`app/decision/fedramp.py`) | Met only if certified, at a level that covers the data, and checked within the last 90 days |
| Decide | A **reviewer** | A plain **Approved** is refused while the requirement is unmet. **Approved with Conditions** is allowed, but it's recorded as a FedRAMP exception and an override. Rejecting is always allowed |

**Levels accepted,** lowest to highest: Class B / LI-SaaS / Low, then Class C / Moderate, then Class D / High. FedRAMP is moving from Low/Moderate/High labels to certification classes under its 2026 consolidated rules, so both are accepted. **Class A (pilot)** doesn't meet a requirement by itself; a reviewer has to judge it.

**What it doesn't change:**

- **The score.** Rule set 1.0 is unchanged; the requirement is shown next to the score, not inside it.
- **The evidence rule.** A Marketplace listing proves an independent assessment happened, but it doesn't quote individual controls, so it never makes a control "verified."
- **The AI.** It has no part in this. People enter both facts, and code compares them.

**Proof:** `tests/test_fedramp.py`, 14 tests (levels, stale checks, input validation, decisions, web permissions, audit). **Sabotage checks:** removing the approval block, letting the requester record the status, and accepting any level each made tests fail. A browser run confirmed both screens: the requester sees "Requirement not met", and the reviewer records the check and sees "Requirement met". The MCP server's `get_vendor_status` also returns the requirement.

**Options considered:** a score penalty (rejected: it would mix a contract requirement into the evidence score); blocking every approval, including conditional ones (rejected: real programs grant time-limited exceptions, but they must be written down). The owner can tighten this later.

## 2. FedRAMP readiness self-check

FedRAMP's newer **20x** approach measures outcomes with machine-checkable **Key Security Indicators (KSIs)** instead of long written control narratives. NIST SP 800-53 Rev. 5 controls still apply, and Counterpart is already built on 800-53. Sources: [FedRAMP 20x Phase 2 recap](https://fedramp.gov/20x/phases/2/) and [a 2026 summary of program changes](https://knoxsystems.com/resources/fedramp-news-2026). KSI identifiers aren't listed here except where a source named them.

| Area FedRAMP emphasizes | Counterpart today | Gap |
|---|---|---|
| Infrastructure as code, configuration scanning | All AWS resources in Terraform; Checkov runs on every change and blocks failures | None for the foundation layer |
| Vulnerability and dependency scanning | CodeQL, Dependabot and dependency review on every change | No container or runtime scanning yet |
| Least privilege | Four roles, checked on the server; one IAM role per job; the AI's role is denied the decisions table | None in design; to verify after deployment |
| Phishing-resistant MFA | Cognito with MFA designed | Not deployed; would need passkeys or security keys specifically |
| Continuous monitoring | CloudTrail to a locked bucket; alerts on changes to logging, keys, buckets and tables; budget alerts | GuardDuty and Security Hub not always on (D-09) |
| Incident response | Audit log with hash chain; alerts | **No incident response plan or runbook yet** |
| Third-party dependency management (KSI-TPR) | Pinned dependencies with Dependabot; and Counterpart itself is a third-party risk tool | No software bill of materials (SBOM) published |
| Machine-readable authorization package (OSCAL) | Not started | Would be required for a real package |
| Federal hosting | AWS us-east-2 (commercial) | A federal deployment would use AWS GovCloud (US). Claude on Bedrock in GovCloud received FedRAMP High in June 2025 for named older models ([Anthropic](https://anthropic.com/news/claude-in-amazon-bedrock-fedramp-high)); check which current models are covered |

**The honest summary:** the engineering habits FedRAMP 20x rewards (everything as code, automated scanning, least privilege, measurable evidence) are already in place. The paperwork and operations a real authorization needs (incident response plan, OSCAL package, GovCloud hosting, independent assessment) are not, and a portfolio project shouldn't pretend otherwise.
