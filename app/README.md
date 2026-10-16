# app/

Application code, written in Python. Built in Milestone 2.

| Folder (planned) | Purpose |
|---|---|
| `api/` | Vendor records, upload links, starting assessments |
| `intake/` | File checks (type, size, macros, hidden text) and text extraction |
| `ai_worker/` | Prompt building, model call, schema validation |
| `rules_engine/` | Deterministic scoring from evidence states. **Built** (rule set 1.0); see `docs/risk-management/scoring-methodology.md` |
| `decision/` | The only code that records a human decision |
| `common/` | Shared pieces such as audit logging and permission checks |

Each folder becomes its own Lambda function with its own IAM role (see `docs/architecture/phase-2-architecture.md`, sections 5.4 and 6).
