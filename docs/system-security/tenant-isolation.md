# Tenant isolation (multi-tenant Milestone 1)

Counterpart now serves more than one client company from one running product. Each company is a **tenant**. This page explains how one tenant is kept from ever reaching another's data, and how that is proven.

Both demo companies are fictional: **Harborline Federal** (sells to US government agencies; vendors that touch federal data need a FedRAMP authorization) and **Larkspur Robotics** (commercial customers only).

## The rules

1. **Every record and file belongs to exactly one tenant.** Vendors, documents, assessments, decisions, settings and the audit trail live in that tenant's own space.
2. **The tenant comes from the signed-in identity and nowhere else.** It is never read from a URL, header, cookie value or request body, so a caller can't ask for another company.
3. **The code serving a request holds only that tenant's space.** There is one `TenantApp` per tenant, and it has no reference to any other tenant's store. A cross-tenant read isn't blocked by a check that could be forgotten; the data simply isn't there to read.
4. **A second, independent check.** `TenantApp.handle` refuses any session from another company before a handler runs, in case routing ever goes wrong.
5. **No ID probing.** Asking for another company's record gives exactly the same answer as asking for a record that never existed.
6. **Tenant IDs can't point elsewhere.** Only known IDs matching a strict pattern are accepted, so `../` and similar tricks are refused.
7. **Each tenant has its own tamper-evident audit trail.** A refused attempt is recorded in the trail of the company whose user made it.

## How this maps to AWS (decision D-17)

| Here, on a laptop | In AWS |
|---|---|
| One folder per tenant under `tenants/` | DynamoDB items and S3 objects whose key starts with the tenant's ID |
| `TenantApp` holds only its own store | Each request runs with temporary credentials limited to that key prefix (`dynamodb:LeadingKeys`, S3 prefix conditions) |
| Tenant taken from the session | Tenant taken from a claim in the Cognito token |
| Per-tenant audit file | Per-tenant audit prefix in the Object Lock bucket |
| (not applicable locally) | One KMS key per tenant, so one tenant's role can't decrypt another's files |

Nothing in this milestone is deployed. It runs locally with synthetic data.

## How it's proven

`tests/test_tenant_isolation.py` runs both companies on one server. Harborline creates a vendor, uploads its documents and runs an assessment. Then every Larkspur role, including its reviewer, administrator and compliance officer, tries to:

- read the vendor, and find it in lists or the overview
- upload a document, run an assessment, record a FedRAMP status and record a decision
- choose Harborline as their tenant through headers, the query string and a forged body field
- read Harborline's audit trail, people and settings
- reach the data through the read-only AI connector (MCP server)

Every attempt is refused, nothing in Harborline's space changes, and the refused answer is identical to "not found". The tests also check that data sits only in its own tenant's folder and that crafted tenant IDs are rejected.

To confirm the tests have teeth, the routing was deliberately broken (every request sent to Harborline, with the second check removed): 23 checks failed. With the code restored, all pass.

## Not covered yet

- The operator (Obsidian Phoenix Labs) has no access path to tenant data at all in this milestone. Time-limited, approved and logged support access is a later design.
- Per-tenant encryption keys and IAM-scoped credentials exist only in the design until the AWS deployment milestone.
- Each tenant's own standards and a richer cross-department workflow (due dates, escalation) are a later milestone.

## Milestone 2: required review tasks by risk tier (D-19)

A vendor's classification (`app.rules_engine`) decides which reviews are required before a decision can be recorded, from `app.review.tasks.REQUIRED_TASKS`:

| Tier | Required reviews |
|---|---|
| Low | Security, AI usage, department head (one approver) |
| Moderate | Security, AI usage, IT, department head (one approver) |
| High | Security, AI usage, IT, Legal, Privacy, department head (**two-person rule**) |
| Critical | Security, AI usage, IT, Legal, Privacy, department head (**two-person rule**) |

Every tier always includes an explicit AI-usage review, on top of whatever the automated scoring already covers for a vendor flagged as using AI on our data (`uses_ai_on_customer_data`) — because a vendor's own self-report shouldn't be the only check on that, and few vendors today have no AI involvement at all. The two-person rule, previously Critical only, now also applies to High.

The checklist is generated once, the moment an assessment becomes `ready_for_review` (`app.web.server.assess`), and `app.decision.service.record_decision` refuses to record a decision while any required task is still open — enforced on the server, not a UI convenience. There's no separate "Legal" or "Department head" role: a reviewer checks off every kind of task, and the note records who actually gave that answer (e.g. "Department head Maria Chen approved by email"). Administrators still have no vendor visibility at all (unchanged from Milestone 1), so they can't complete tasks or comment either.

Each vendor also carries an append-only comment thread (`app.review.comments`), visible only inside its own tenant.

Proven the same way as tenant isolation: the task-completion gate was deliberately removed from `record_decision`, the full suite was run (2 tests failed, exactly naming the missing gate), and the code was restored.
