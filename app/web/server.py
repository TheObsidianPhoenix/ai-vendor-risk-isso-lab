"""Counterpart local server (Milestone 2). Python standard library only.

Run it with:  python scripts/run_app.py   then open http://127.0.0.1:8000

Each API handler here becomes a Lambda function behind API Gateway in
Milestone 3. The security behaviour is the same in both places:

- Every request is checked on the server: signed in, role allowed, and
  allowed to see that particular vendor (SR-01). A vendor you can't see
  returns "not found", so its existence isn't revealed.
- Changes need a custom request header, which another website can't send,
  plus a SameSite=Strict cookie (protection against cross-site request forgery).
- Every response carries security headers, including a Content Security
  Policy that only allows this app's own scripts (protection against XSS).
- Errors return a short message, never a stack trace.
- The server listens only on this computer (127.0.0.1).
"""

from __future__ import annotations

import json
import re
import traceback
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from app.ai_worker import DOCUMENT_TYPES, MODES, make_model, provider, run_assessment
from app.common import auth
from app.common.audit import AuditLog
from app.common.store import Store
from app.decision import DECISIONS, DecisionRefused, record_decision, vendor_status
from app.intake import DEFAULT_LIMITS, scan_file
from app.intake.result import INJECTION_FLAG_KINDS
from app.rules_engine import RULE_SET_VERSION, ruleset

STATIC = Path(__file__).resolve().parent / "static"
STATIC_FILES = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                "/app.css": ("app.css", "text/css")}
COOKIE = "cp_session"
CSRF_HEADER = "X-Counterpart-Request"
ID = r"[a-z]{3}_[0-9a-f]{12}"
MAX_JSON_BYTES = 64 * 1024

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class CounterpartApp:
    """Everything the handlers share. One instance per running server."""

    def __init__(self, data_dir: Path, clock=None):
        self.store = Store(Path(data_dir))
        self.audit = AuditLog(Path(data_dir) / "audit.jsonl")
        self.sessions = auth.Sessions(clock) if clock else auth.Sessions()
        self.settings = {"model_mode": "normal"}
        self.quiet = False
        self.purge_expired()

    def purge_expired(self) -> dict:
        """Apply the retention rule (also the local stand-in for DynamoDB TTL and S3 lifecycle)."""
        removed = self.store.purge_expired()
        if any(removed.values()):
            self.audit.record(actor="system", role="system", action="retention.purge", details=removed)
        return removed

    # ----- routing ---------------------------------------------------------------
    def routes(self):
        return [
            ("GET", r"/api/demo-users", self.demo_users, False),
            ("POST", r"/api/session", self.sign_in, False),
            ("DELETE", r"/api/session", self.sign_out, True),
            ("GET", r"/api/me", self.me, True),
            ("GET", r"/api/overview", self.overview, True),
            ("GET", r"/api/vendors", self.list_vendors, True),
            ("POST", r"/api/vendors", self.create_vendor, True),
            ("GET", rf"/api/vendors/(?P<vendor_id>{ID})", self.get_vendor, True),
            ("POST", rf"/api/vendors/(?P<vendor_id>{ID})/documents", self.upload, True),
            ("POST", rf"/api/vendors/(?P<vendor_id>{ID})/assessments", self.assess, True),
            ("POST", rf"/api/assessments/(?P<assessment_id>{ID})/decisions", self.decide, True),
            ("GET", r"/api/audit", self.audit_log, True),
            ("GET", r"/api/users", self.users, True),
            ("GET", r"/api/settings", self.get_settings, True),
            ("POST", r"/api/settings", self.change_settings, True),
            ("GET", r"/api/rules", self.rules, True),
        ]

    # ----- helpers ---------------------------------------------------------------
    def _visible_vendor(self, session, vendor_id: str) -> dict:
        vendor = self.store.get_vendor(vendor_id)
        if vendor is None or not auth.can_view_vendor(session.user, vendor):
            # Same answer whether it doesn't exist or you can't see it (no ID probing)
            if vendor is not None:
                self._log(session, "vendor.view", vendor_id, "denied")
            raise ApiError(404, "Vendor not found")
        return vendor

    def _log(self, session, action, target="", outcome="success", **details):
        self.audit.record(actor=session.user.id, role=session.user.role, action=action, target=target,
                          outcome=outcome, details=details)

    def _require(self, session, permission: str, action: str):
        if not session.user.has(permission):
            self._log(session, action, outcome="denied", reason=f"missing permission {permission}")
            raise ApiError(403, "Your role isn't allowed to do this")

    def _vendor_summary(self, vendor: dict) -> dict:
        latest = self.store.latest_assessment(vendor["id"])
        score = latest["score"] if latest and latest.get("score") else None
        return dict(vendor, status=vendor_status(self.store, vendor["id"])["status"],
                    score=score["score"] if score else None,
                    classification=score["classification"] if score else None,
                    injection_flagged=bool(latest and latest["injection_flags"]),
                    document_count=len(self.store.list_documents(vendor["id"])))

    # ----- handlers --------------------------------------------------------------
    def demo_users(self, session, body, **_):
        return {"users": [{"id": uid, **info, "role_name": auth.ROLES[info["role"]]} for uid, info in auth.DEMO_USERS.items()],
                "note": "Local sandbox sign-in. Replaced by Amazon Cognito with MFA in Milestone 3."}

    def sign_in(self, session, body, **_):
        user_id = str(body.get("user_id", ""))
        try:
            token, new = self.sessions.sign_in(user_id)
        except auth.PermissionDenied:
            self.audit.record(actor="unknown", role="none", action="auth.sign_in", outcome="denied",
                              details={"reason": "unknown user"})
            raise ApiError(401, "Sign-in failed") from None
        self._log(new, "auth.sign_in")
        return {"user": new.user.public(), "_set_cookie": token}

    def sign_out(self, session, body, token=None, **_):
        self.sessions.sign_out(token)
        self._log(session, "auth.sign_out")
        return {"_clear_cookie": True}

    def me(self, session, body, **_):
        return {"user": session.user.public(), "signed_in_at": session.signed_in_at,
                "fresh_for_seconds": max(0, int(auth.FRESH_SIGN_IN_SECONDS - (self.sessions.clock() - session.signed_in_at))),
                "model_mode": self.settings["model_mode"], "model_mode_label": MODES[self.settings["model_mode"]],
                "model_provider": provider()}

    def overview(self, session, body, **_):
        user = session.user
        vendors = [self._vendor_summary(v) for v in self.store.list_vendors() if auth.can_view_vendor(user, v)]
        counts = {}
        for v in vendors:
            if v["classification"]:
                counts[v["classification"]] = counts.get(v["classification"], 0) + 1
        awaiting = [v for v in vendors if v["status"] in ("Awaiting human decision", "Awaiting second approval")]
        events = self.audit.read() if user.has("audit.view") else []
        return {"vendor_count": len(vendors), "by_classification": counts, "awaiting_decision": len(awaiting),
                "injection_flagged": sum(1 for v in vendors if v["injection_flagged"]),
                "denied_events": sum(1 for e in events if e["outcome"] == "denied") if events else None,
                "recent": vendors[-5:][::-1]}

    def list_vendors(self, session, body, **_):
        return {"vendors": [self._vendor_summary(v) for v in self.store.list_vendors()
                            if auth.can_view_vendor(session.user, v)][::-1]}

    def create_vendor(self, session, body, **_):
        self._require(session, "vendor.create", "vendor.create")
        name = _field(body, "name", 80)
        service = _field(body, "service", 200)
        data_shared = _field(body, "data_shared", 200)
        uses_ai = body.get("uses_ai_on_customer_data")
        if not isinstance(uses_ai, bool):
            raise ApiError(400, "Say whether the vendor uses AI on our data")
        vendor = self.store.create_vendor(name=name, service=service, data_shared=data_shared,
                                          uses_ai_on_customer_data=uses_ai, owner_id=session.user.id,
                                          owner_name=session.user.name)
        self._log(session, "vendor.create", vendor["id"], uses_ai_on_customer_data=uses_ai)
        return {"vendor": vendor}

    def get_vendor(self, session, body, vendor_id, **_):
        vendor = self._visible_vendor(session, vendor_id)
        documents = [{k: v for k, v in d.items() if k != "segments"} for d in self.store.list_documents(vendor_id)]
        latest = self.store.latest_assessment(vendor_id)
        user = session.user
        uploaders = {d["uploaded_by"] for d in documents}
        return {
            "vendor": self._vendor_summary(vendor),
            "documents": documents,
            "assessment": latest,
            "assessment_count": len(self.store.list_assessments(vendor_id)),
            "decisions": self.store.list_decisions(vendor_id),
            "status": vendor_status(self.store, vendor_id),
            "can": {
                "upload": auth.can_upload(user, vendor),
                "assess": auth.can_run_assessment(user, vendor),
                "decide": user.has("decision.record"),
                "decide_blocked_reason": ("Separation of duties: you requested this vendor or uploaded its documents"
                                          if user.id == vendor["owner_id"] or user.id in uploaders else None),
            },
            "decision_options": DECISIONS,
            "document_types": DOCUMENT_TYPES,
        }

    def upload(self, session, body, vendor_id, raw=b"", filename="", doc_type="", **_):
        vendor = self._visible_vendor(session, vendor_id)
        if not auth.can_upload(session.user, vendor):
            self._log(session, "document.upload", vendor_id, "denied", reason="not the vendor's requester")
            raise ApiError(403, "Only the person who requested this vendor can upload its documents")
        doc_type = doc_type if doc_type in DOCUMENT_TYPES else None
        if doc_type is None:
            raise ApiError(400, "Choose what kind of document this is")
        result = scan_file(raw, filename or "unnamed")
        flags = [{"kind": f.kind, "location": f.location, "detail": f.detail, "excerpt": f.excerpt,
                  "injection": f.kind in INJECTION_FLAG_KINDS} for f in result.flags]
        document = self.store.add_document(
            vendor_id, raw if result.status == "accepted" else None,
            filename=result.filename, sha256=result.sha256, size_bytes=result.size_bytes,
            file_type=result.file_type, status=result.status, rejection_reason=result.rejection_reason,
            doc_type=doc_type, flags=flags, segments=[[s.location, s.text] for s in result.segments],
            uploaded_by=session.user.id, uploaded_by_name=session.user.name)
        # Audit: what was found and where, never the excerpt itself
        self._log(session, "document.upload", vendor_id, "success" if result.status == "accepted" else "rejected",
                  document_id=document["id"], sha256=result.sha256, file_type=result.file_type, doc_type=doc_type,
                  rejection_reason=result.rejection_reason,
                  flags=[f"{f['kind']} @ {f['location']}" for f in flags])
        return {"document": {k: v for k, v in document.items() if k != "segments"}}

    def assess(self, session, body, vendor_id, **_):
        vendor = self._visible_vendor(session, vendor_id)
        if not auth.can_run_assessment(session.user, vendor):
            self._log(session, "assessment.run", vendor_id, "denied")
            raise ApiError(403, "Your role can't start an assessment for this vendor")
        documents = [d for d in self.store.list_documents(vendor_id) if d["status"] == "accepted"]
        if not documents:
            raise ApiError(400, "Upload at least one document that passes the intake checks")
        record = run_assessment(vendor_id=vendor_id, vendor_name=vendor["name"],
                                uses_ai_on_customer_data=vendor["uses_ai_on_customer_data"],
                                documents=documents, model=make_model(self.settings["model_mode"]))
        assessment = self.store.add_assessment(record, started_by=session.user.id, started_by_name=session.user.name)
        score = assessment["score"]
        self._log(session, "assessment.run", vendor_id,
                  "success" if assessment["status"] == "ready_for_review" else assessment["status"],
                  assessment_id=assessment["id"], model_mode=record["model_mode"],
                  rejection_reason=assessment["rejection_reason"],
                  score=score["score"] if score else None,
                  classification=score["classification"] if score else None,
                  citation_problems=len(assessment["citation_problems"]),
                  input_tokens=(assessment.get("usage") or {}).get("input_tokens"),
                  output_tokens=(assessment.get("usage") or {}).get("output_tokens"),
                  injection_flags=len(assessment["injection_flags"]))
        return {"assessment": assessment}

    def decide(self, session, body, assessment_id, **_):
        if not session.user.has("decision.record"):
            # Checked before anything is looked up, so non-reviewers learn nothing about assessments
            self._log(session, "decision.record", assessment_id, "denied", reason="not a reviewer")
            raise ApiError(403, "Only a Vendor Risk Reviewer can record a decision")
        assessment = self.store.get_assessment(assessment_id)
        if assessment is None:
            raise ApiError(404, "Assessment not found")
        self._visible_vendor(session, assessment["vendor_id"])
        try:
            record = record_decision(
                store=self.store, audit=self.audit, session=session, assessment_id=assessment_id,
                decision=str(body.get("decision", "")), rationale=str(body.get("rationale", "")),
                conditions=str(body.get("conditions", "")), evidence_confirmed=body.get("evidence_confirmed") is True)
        except DecisionRefused as reason:
            raise ApiError(409, str(reason)) from None
        except auth.PermissionDenied as reason:
            raise ApiError(403, str(reason)) from None
        return {"decision": record}

    def audit_log(self, session, body, **_):
        self._require(session, "audit.view", "audit.view")
        events = self.audit.read()
        return {"events": events[::-1][:500], "chain": self.audit.verify()}

    def users(self, session, body, **_):
        self._require(session, "users.view", "users.view")
        return {"users": [auth.get_user(uid).public() for uid in auth.DEMO_USERS], "roles": auth.ROLES}

    def get_settings(self, session, body, **_):
        return {"model_mode": self.settings["model_mode"], "modes": MODES, "model_provider": provider(),
                "can_change": session.user.has("settings.change")}

    def change_settings(self, session, body, **_):
        self._require(session, "settings.change", "settings.change")
        mode = body.get("model_mode")
        if mode not in MODES:
            raise ApiError(400, "Unknown model mode")
        old = self.settings["model_mode"]
        self.settings["model_mode"] = mode
        self._log(session, "settings.change", "model_mode", previous=old, new=mode)
        return {"model_mode": mode}

    def rules(self, session, body, **_):
        return {"version": RULE_SET_VERSION, "points": ruleset.POINTS, "bands": ruleset.BANDS,
                "categories": ruleset.CATEGORIES, "critical": sorted(ruleset.CRITICAL_CATEGORIES)}


def _field(body: dict, name: str, max_len: int) -> str:
    value = body.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ApiError(400, f"'{name}' is required")
    value = value.strip()
    if len(value) > max_len:
        raise ApiError(400, f"'{name}' must be at most {max_len} characters")
    return value


class Handler(BaseHTTPRequestHandler):
    app: CounterpartApp  # Set by make_server
    server_version = "Counterpart"
    sys_version = ""

    def log_message(self, fmt, *args):  # Request lines only; no bodies, cookies or tokens
        if not self.app.quiet:
            print(f"{self.command} {urlparse(self.path).path} -> {args[1] if len(args) > 1 else ''}")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method: str):
        path = urlparse(self.path).path
        try:
            if method == "GET" and path in STATIC_FILES:
                name, kind = STATIC_FILES[path]
                return self._send(200, (STATIC / name).read_bytes(), f"{kind}; charset=utf-8")
            for route_method, pattern, handler, needs_session in self.app.routes():
                match = re.fullmatch(pattern, path)
                if not match:
                    continue
                if route_method != method:
                    continue
                return self._call(method, handler, needs_session, match.groupdict())
            if path.startswith("/api/"):
                raise ApiError(404, "Not found")
            raise ApiError(404, "Not found")
        except ApiError as error:
            self._json(error.status, {"error": error.message})
        except Exception:  # Never send internals to the browser
            traceback.print_exc()
            self._json(500, {"error": "Something went wrong. The error was logged."})

    def _call(self, method, handler, needs_session, params):
        if method != "GET" and self.headers.get(CSRF_HEADER) != "1":
            raise ApiError(403, "Missing request header")
        token = self._cookie()
        session = self.app.sessions.get(token)
        if needs_session and session is None:
            raise ApiError(401, "Please sign in")

        length = int(self.headers.get("Content-Length") or 0)
        raw, body = b"", {}
        if handler == self.app.upload:
            if length > DEFAULT_LIMITS.max_file_bytes + 1:
                raise ApiError(413, f"Files must be at most {DEFAULT_LIMITS.max_file_bytes // (1024 * 1024)} MB")
            raw = self.rfile.read(length)
            params["filename"] = (self.headers.get("X-Filename") or "")[:200]
            params["doc_type"] = (self.headers.get("X-Document-Type") or "")[:40]
        elif length:
            if length > MAX_JSON_BYTES:
                raise ApiError(413, "Request too large")
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                raise ApiError(415, "Send JSON")
            try:
                body = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                raise ApiError(400, "Invalid JSON") from None
            if not isinstance(body, dict):
                raise ApiError(400, "Invalid JSON")
        result = handler(session, body, raw=raw, token=token, **params)
        cookie = None
        if "_set_cookie" in result:
            cookie = f"{COOKIE}={result.pop('_set_cookie')}; HttpOnly; SameSite=Strict; Path=/"
        elif result.pop("_clear_cookie", False):
            cookie = f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        self._json(200, result, cookie)

    def _cookie(self) -> str | None:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie") or "")
        except Exception:
            return None
        return jar[COOKIE].value if COOKIE in jar else None

    def _json(self, status: int, data: dict, cookie: str | None = None):
        self._send(status, json.dumps(data).encode(), "application/json", cookie)

    def _send(self, status: int, payload: bytes, content_type: str, cookie: str | None = None):
        self.send_response(status, HTTPStatus(status).phrase)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)


def make_server(data_dir: Path, host: str = "127.0.0.1", port: int = 8000, clock=None,
                quiet: bool = False) -> ThreadingHTTPServer:
    app = CounterpartApp(data_dir, clock)
    app.quiet = quiet
    handler = type("BoundHandler", (Handler,), {"app": app})
    server = ThreadingHTTPServer((host, port), handler)
    server.app = app
    return server
