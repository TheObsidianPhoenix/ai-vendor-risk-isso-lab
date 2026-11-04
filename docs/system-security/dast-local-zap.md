# DAST: OWASP ZAP scan of the running app (local)

**Run 2026-11-03 by Jasmine Alexander (ISSO).** First dynamic application security test (DAST) of Counterpart: OWASP ZAP attacked the running app the way an outsider and two signed-in users would. This is milestone 1 of POA&M item P-06. The same scan is repeated against the AWS deployment once the app layer exists.

## Result in one line

About **10,000 attack requests** across three identities produced **no high or medium findings and no server errors**. ZAP raised one low-risk alert worth checking (script text stored in vendor fields). A browser test confirmed it can't run: the app shows it as plain text.

## Scope and method

| | |
|---|---|
| **Tool** | OWASP ZAP 2.17.0, official Linux release from the zaproxy GitHub project, run headless with the automation framework. SHA-256 of the download: `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a` |
| **Target** | Counterpart at `main` plus the pending documentation changes (no code differences), running locally at `http://127.0.0.1:8000` with synthetic data only |
| **Identities** | Signed out; **Priya Shah**, requester (`app_user`); **Dana Whitfield**, reviewer. Each authenticated scan reused a real session cookie |
| **Coverage** | Every API route was seeded with valid requests: reads, vendor creation, upload, FedRAMP record, assessment, decision and settings. Then ZAP's spider, passive scan and full default active scan policy ran (injection, XSS, path traversal, command injection, header and parameter fuzzing, and more) |
| **Volume** | 10,241 requests. Responses: 1,551 success (200), 2,662 not signed in (401), 2,845 forbidden (403), 979 not found (404), 858 bad request (400), 638 conflict (409), 65 unsupported type (415). **Zero 500 errors**: no attack crashed the server |
| **Reports** | [`evidence/dast/`](../../evidence/dast/): HTML and JSON for each identity (EV-012 to EV-014). They contain no session cookies |

## Findings

| Alert (ZAP risk) | Where | Verdict | Why |
|---|---|---|---|
| **Cross Site Scripting Weakness, persistent in JSON response** (Low) | `/api/overview`, `/api/vendors`: vendor `name`, `service`, `data_shared` | **Not exploitable; accepted** | The API stores what's typed and returns it as JSON, which is correct. What matters is how the page displays it. The page builds every element with `createTextNode`, never `innerHTML`, so text can't become code. The strict Content Security Policy (`script-src 'self'`) would block an inline script anyway, and `X-Content-Type-Options: nosniff` stops a browser treating JSON as a page. **Verified in a real browser** (`scripts/dast/check_rendering.js`): the payload `<script>alert(1);</script>` displayed as literal text on the vendor list and vendor page, with 0 dialogs and 0 scripts injected |
| Timestamp disclosure, Unix (Low) | `/api/me`, `/api/overview`, `/api/vendors` | **Accepted** | These are the app's own record times (sign-in, created, updated), which the screens need. They reveal nothing about the server |
| Information disclosure, suspicious comments (Info) | `app.js`, `/api/vendors` | **False positive** | The words "from" and "select" appear in normal code and text, not in developer comments |
| Modern web application (Info) | `/` | Informational | ZAP noting that the page is built with JavaScript |
| Session management response identified (Info) | `POST /api/session` | Informational | ZAP recognized the `cp_session` cookie, which is `HttpOnly` and `SameSite=Strict` |
| User agent fuzzer (Info) | `POST .../assessments` | Informational | Responses don't change by browser type |

**What ZAP didn't find:** missing security headers, cookie weaknesses, SQL or command injection, path traversal, open redirects, or error pages that leak details. The headers on every response include a strict CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.

## Observation (not a ZAP alert)

**O-01: No request rate limit in the app itself.** The scan created more than 600 test vendors in minutes without being slowed down. That's expected locally. In AWS the design puts API Gateway throttling in front of the app (decision D-08). The AWS scan should confirm the throttling works, and it's added to P-06.

**O-02: The session cookie has no `Secure` flag.** That's correct for a local app served over plain HTTP, and ZAP only checks it on HTTPS. Once deployed behind HTTPS, the cookie must carry `Secure` so it's never sent unencrypted. It's added to P-05, and the AWS scan checks it.

## Limits of this test

- **Local, not deployed.** It tests Counterpart's own code and headers, not AWS: no Cognito sign-in, API Gateway or CloudFront yet. The AWS scan is still open in P-06.
- **The anti-forgery header was always sent**, so ZAP could reach the API. That control (`X-Counterpart-Request` plus a `SameSite=Strict` cookie) is tested separately in `tests/test_web.py`.
- **Two of the four roles.** Admin and ISSO weren't scanned, and their routes overlap with the reviewer's. Access control between roles is covered by the automated tests, not by ZAP.
- **An automated scan is not a penetration test.** It finds common, known weakness patterns. Logic flaws, such as approving a vendor you shouldn't, are covered by the decision and permission tests.

## How to repeat it

```bash
python3 scripts/run_app.py --reset                      # terminal 1
python3 scripts/dast/seed_local.py .dast                 # terminal 2
for r in none priya dana; do python3 scripts/dast/zap_plan.py .dast $r > .dast/plan-$r.yaml; done
zap.sh -cmd -autorun .dast/plan-priya.yaml               # once per plan; reports land in .dast/reports
```

`.dast/` is git-ignored because the plans contain live session cookies. Copy only the reports into `evidence/dast/`.
