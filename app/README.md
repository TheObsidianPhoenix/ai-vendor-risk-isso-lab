# app/

Application code, written in Python with only two outside libraries (pypdf, openpyxl). Run it with `python3 scripts/run_app.py`.

| Folder | Purpose |
|---|---|
| `api/` | Vendor records, upload links, starting assessments. Locally these are the handlers in `web/server.py` |
| `intake/` | File checks (type, size, macros, hidden text) and text extraction. **Built**; see `docs/system-security/intake-controls.md` |
| `ai_worker/` | Prompt building, model call, schema validation. **Built** with a pretend model; Bedrock in Phase 5 |
| `rules_engine/` | Deterministic scoring from evidence states. **Built** (rule set 1.0); see `docs/risk-management/scoring-methodology.md` |
| `decision/` | The only code that records a human decision. **Built** |
| `common/` | Audit log, storage, sign-in and permission checks. **Built** (local stand-ins for AWS) |
| `web/` | Local server and browser app. Becomes API Gateway + Lambda and CloudFront in Milestone 3 |

Each folder becomes its own Lambda function with its own IAM role (see `docs/architecture/phase-2-architecture.md`, sections 5.4 and 6).
