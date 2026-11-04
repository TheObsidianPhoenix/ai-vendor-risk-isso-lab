"""Write an OWASP ZAP automation plan for one role (see docs/system-security/dast-local-zap.md).

    python3 scripts/dast/zap_plan.py .dast none   > .dast/plan-none.yaml
    python3 scripts/dast/zap_plan.py .dast priya  > .dast/plan-priya.yaml
    python3 scripts/dast/zap_plan.py .dast dana   > .dast/plan-dana.yaml
    zap.sh -cmd -autorun .dast/plan-priya.yaml

"none" scans as a signed-out visitor. Other roles reuse the session cookie in
.dast/seed.json (from seed_local.py), so plans contain a secret: keep them in
.dast/, which is git-ignored. Sign-in and sign-out are excluded from
authenticated scans so the scanner can't end its own session.
"""
import json
import sys

import yaml  # PyYAML

S = sys.argv[1]
role = sys.argv[2]
seed = json.load(open(f"{S}/seed.json"))
v, a = seed["vendor"], seed["assessment"]
B = "http://127.0.0.1:8000"
J = {"Content-Type": "application/json", "X-Counterpart-Request": "1"}
reqs = [{"url": B + p, "method": "GET"} for p in
        ["/", "/app.css", "/app.js", "/api/demo-users", "/api/me", "/api/overview", "/api/vendors",
         f"/api/vendors/{v}", "/api/audit", "/api/users", "/api/settings", "/api/rules", "/api/does-not-exist"]]
def post(path, body, headers=J):
    return {"url": B + path, "method": "POST", "data": body if isinstance(body, str) else json.dumps(body),
            "headers": [f"{k}:{val}" for k, val in headers.items()]}
reqs += [
    post("/api/vendors", {"name": "Zap Test Vendor", "service": "Testing", "data_shared": "None",
                          "uses_ai_on_customer_data": False, "federal_data_impact": "none"}),
    post(f"/api/vendors/{v}/fedramp", {"status": "certified", "level": "Low", "checked_on": "2026-11-01", "listing": "x"}),
    post(f"/api/vendors/{v}/assessments", {}),
    post(f"/api/assessments/{a}/decisions", {"decision": "Further Review Required", "conditions": "",
                                            "rationale": "Reviewed the evidence for this scan test.", "evidence_confirmed": True}),
    post(f"/api/vendors/{v}/documents", "%PDF-1.4 zap test", {"X-Counterpart-Request": "1", "X-Filename": "zap-test.pdf",
                                                              "X-Document-Type": "other", "Content-Type": "application/octet-stream"}),
]
if role == "none":
    reqs.append(post("/api/session", {"user_id": "usr_priya"}))
else:
    reqs.append(post("/api/settings", {"model_mode": "normal"}))
rules = [{"description": "CSRF header", "matchType": "req_header", "matchString": "X-Counterpart-Request", "replacementString": "1"}]
if role != "none":
    rules.append({"description": "Session", "matchType": "req_header", "matchString": "Cookie", "replacementString": seed["cookies"][role]})
plan = {
  "env": {"contexts": [{"name": "counterpart", "urls": [B], "includePaths": [B + ".*"],
                        "excludePaths": [B + "/api/session.*"] if role != "none" else []}],
          "parameters": {"failOnError": False, "progressToStdout": True}},
  "jobs": [
    {"type": "replacer", "parameters": {"deleteAllRules": True}, "rules": rules},
    {"type": "requestor", "requests": reqs},
    {"type": "spider", "parameters": {"context": "counterpart", "maxDuration": 2}},
    {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
    {"type": "activeScan", "parameters": {"context": "counterpart", "maxScanDurationInMins": 15, "maxRuleDurationInMins": 3}},
    {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
    {"type": "report", "parameters": {"template": "traditional-json", "reportDir": f"{S}/reports", "reportFile": f"zap-{role}.json"}},
    {"type": "report", "parameters": {"template": "traditional-html", "reportDir": f"{S}/reports", "reportFile": f"zap-{role}.html",
                                       "reportTitle": f"Counterpart DAST: OWASP ZAP 2.17.0 ({role})"}},
  ]}
print(yaml.safe_dump(plan, sort_keys=False))
