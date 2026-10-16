# tests/

Automated tests, run on every pull request. Built in Milestone 2.

Security tests prove the controls work. Each one maps to a scenario in the README and to a security requirement in the Phase 1 brief:

| Test (planned) | Proves | Requirement |
|---|---|---|
| Hidden prompt injection | Injection is flagged and the score is unaffected | SR-07, SR-08 |
| Cross-vendor request | Another vendor's data is unavailable | SR-09 |
| Normal user approves a vendor | Access denied | SR-01, HR-02 |
| AI sets a final decision | Impossible by design | SR-12, HR-01 |
| Malformed AI output | Validation fails safely | SR-11 |
| Encryption claimed without evidence | Treated as an evidence gap | SR-13 |

Test results are saved as evidence in Milestone 4.
