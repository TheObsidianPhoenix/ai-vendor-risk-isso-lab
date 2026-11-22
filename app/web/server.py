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
from app.common import auth, tenants
from app.common.audit import AuditLog
from app.common.store import Store, now
from app.decision import DECISIONS, DecisionRefused, fedramp, record_decision, vendor_status
from app.intake import DEFAULT_LIMITS, scan_file
from app.intake.result import INJECTION_FLAG_KINDS
from app.review import LABELS, can_comment, can_complete, generate as generate_tasks, open_kinds
from app.review.comments import MAX_LENGTH as MAX_COMMENT_LENGTH
from app.review.tasks import MIN_NOTE
from app.rules_engine import RULE_SET_VERSION, ruleset

STATIC = Path(__file__).resolve().parent / "static"
STATIC_FILES = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                "/app.css": ("app.css", "text/css"),
                "/phoenix-light.webp": ("phoenix-light.webp", "image/webp"),
                "/phoenix-dark.webp": ("phoenix-dark.webp", "image/webp")}
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


# The handlers a tenant app answers. Anything else is refused, whatever a caller asks for.
TENANT_ROUTES = frozenset({"sign_out", "me", "overview", "list_vendors", "create_vendor", "get_vendor", "upload",
                           "record_fedramp", "assess", "decide", "audit_log", "users", "get_settings",
                           "change_settings", "rules", "complete_task", "add_comment", "list_comments",
                           "tracking"})


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class TenantApp:
    """One client company's Counterpart. It holds only that tenant's store, audit trail and
    settings, so nothing in here can reach another tenant's data: there is no reference to it.
    In AWS this is the Lambda running with credentials scoped to one tenant's key prefix."""

    def __init__(self, tenant: tenants.Tenant, space: Path, sessions: auth.Sessions):
        self.tenant = tenant
        self.store = Store(space)
        self.audit = AuditLog(space / "audit.jsonl")
        self.sessions = sessions
        self.settings = {"model_mode": "normal"}
        self.purge_expired()

    def purge_expired(self) -> dict:
        """Apply the retention rule (also the local stand-in for DynamoDB TTL and S3 lifecycle)."""
        removed = self.store.purge_expired()
        if any(removed.values()):
            self.audit.record(actor="system", role="system", action="retention.purge", details=removed)
        return removed

    def handle(self, name: str, session, body: dict, **params) -> dict:
        """The only way in. A second, independent check: even if routing above ever went wrong,
        a session from another company is refused here before any handler runs."""
        if session is None or session.user.tenant_id != self.tenant.id:
            self.audit.record(actor="unknown", role="none", action="tenant.boundary", outcome="denied",
                              details={"reason": "session belongs to a different company"})
            raise ApiError(403, "Your account isn't linked to this company")
        if name.startswith("_") or name not in TENANT_ROUTES:
            raise ApiError(404, "Not found")
        return getattr(self, name)(session, body, **params)

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
        open_tasks = open_kinds(self.store.list_tasks(assessment_id=latest["id"])) if latest else []
        return dict(vendor, status=vendor_status(self.store, vendor["id"])["status"],
                    score=score["score"] if score else None,
                    classification=score["classification"] if score else None,
                    injection_flagged=bool(latest and latest["injection_flags"]),
                    fedramp_requirement=fedramp.requirement(vendor),
                    document_count=len(self.store.list_documents(vendor["id"])),
                    open_review_tasks=[LABELS.get(k, k) for k in open_tasks])

    # ----- handlers --------------------------------------------------------------
    def sign_out(self, session, body, token=None, **_):
        self.sessions.sign_out(token)
        self._log(session, "auth.sign_out")
        return {"_clear_cookie": True}

    def me(self, session, body, **_):
        return {"user": session.user.public(), "tenant": self.tenant.public(), "signed_in_at": session.signed_in_at,
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
        federal = body.get("federal_data_impact", "none")
        if federal not in fedramp.IMPACT_LEVELS:
            raise ApiError(400, "Say whether the vendor will handle federal data, and at what impact level")
        vendor = self.store.create_vendor(name=name, service=service, data_shared=data_shared,
                                          uses_ai_on_customer_data=uses_ai, federal_data_impact=federal,
                                          owner_id=session.user.id, owner_name=session.user.name)
        self._log(session, "vendor.create", vendor["id"], uses_ai_on_customer_data=uses_ai,
                  federal_data_impact=federal)
        return {"vendor": vendor}

    def get_vendor(self, session, body, vendor_id, **_):
        vendor = self._visible_vendor(session, vendor_id)
        documents = [{k: v for k, v in d.items() if k != "segments"} for d in self.store.list_documents(vendor_id)]
        latest = self.store.latest_assessment(vendor_id)
        user = session.user
        uploaders = {d["uploaded_by"] for d in documents}
        tasks = self.store.list_tasks(assessment_id=latest["id"]) if latest else []
        for t in tasks:
            t["can_complete"] = t["status"] == "open" and can_complete(user, t["kind"])
        return {
            "vendor": self._vendor_summary(vendor),
            "documents": documents,
            "assessment": latest,
            "assessment_count": len(self.store.list_assessments(vendor_id)),
            "decisions": self.store.list_decisions(vendor_id),
            "tasks": tasks,
            "comments": self.store.list_comments(vendor_id),
            "status": vendor_status(self.store, vendor_id),
            "can": {
                "upload": auth.can_upload(user, vendor),
                "assess": auth.can_run_assessment(user, vendor),
                "decide": user.has("decision.record"),
                "verify_fedramp": user.has("vendor.verify_fedramp"),
                "comment": can_comment(user, vendor),
                "decide_blocked_reason": ("Separation of duties: you requested this vendor or uploaded its documents"
                                          if user.id == vendor["owner_id"] or user.id in uploaders else None),
            },
            "decision_options": DECISIONS,
            "document_types": DOCUMENT_TYPES,
            "fedramp_levels": list(fedramp.LEVELS),
        }

    def record_fedramp(self, session, body, vendor_id, **_):
        """A reviewer records what the FedRAMP Marketplace shows for this vendor (D-13)."""
        self._require(session, "vendor.verify_fedramp", "vendor.fedramp")
        vendor = self._visible_vendor(session, vendor_id)
        try:
            record = fedramp.validate_status(body if isinstance(body, dict) else {})
        except ValueError as problem:
            raise ApiError(400, str(problem)) from None
        record.update(recorded_by=session.user.id, recorded_by_name=session.user.name, recorded_at=now())
        vendor = self.store.set_vendor_fedramp(vendor_id, record)
        self._log(session, "vendor.fedramp", vendor_id, status=record["status"], level=record["level"],
                  checked_on=record["checked_on"])
        return {"vendor": self._vendor_summary(vendor)}

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
        tasks = []
        if assessment["status"] == "ready_for_review" and score:
            # The tier decides who has to review it (Milestone 2). Generated once, right
            # here, so a decision can never be recorded against a checklist that doesn't exist.
            tasks = self.store.create_tasks(vendor_id, assessment["id"],
                                            generate_tasks(vendor_id, assessment["id"], score["classification"]))
        self._log(session, "assessment.run", vendor_id,
                  "success" if assessment["status"] == "ready_for_review" else assessment["status"],
                  assessment_id=assessment["id"], model_mode=record["model_mode"],
                  rejection_reason=assessment["rejection_reason"],
                  score=score["score"] if score else None,
                  classification=score["classification"] if score else None,
                  citation_problems=len(assessment["citation_problems"]),
                  input_tokens=(assessment.get("usage") or {}).get("input_tokens"),
                  output_tokens=(assessment.get("usage") or {}).get("output_tokens"),
                  injection_flags=len(assessment["injection_flags"]),
                  review_tasks=[t["kind"] for t in tasks])
        return {"assessment": assessment, "tasks": tasks}

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

    def complete_task(self, session, body, task_id, **_):
        """Check off one required review (Milestone 2). The note says who from that
        function weighed in and what they found; it's part of the record, not a formality."""
        task = self.store.get_task(task_id)
        if task is None:
            raise ApiError(404, "Review task not found")
        self._visible_vendor(session, task["vendor_id"])  # Same 404 if it's another company's task
        if not can_complete(session.user, task["kind"]):
            self._log(session, "task.complete", task_id, "denied", kind=task["kind"])
            raise ApiError(403, f"Your role can't complete the {LABELS.get(task['kind'], task['kind'])} task")
        if task["status"] == "done":
            raise ApiError(409, "This review is already checked off")
        note = str(body.get("note", "")).strip()
        if len(note) < MIN_NOTE:
            raise ApiError(400, f"Say what you reviewed, in at least {MIN_NOTE} characters")
        updated = self.store.complete_task(task_id, session.user.id, session.user.name, note[:1000])
        self._log(session, "task.complete", task_id, kind=task["kind"], vendor_id=task["vendor_id"],
                  assessment_id=task["assessment_id"])
        return {"task": updated}

    def add_comment(self, session, body, vendor_id, **_):
        vendor = self._visible_vendor(session, vendor_id)
        if not can_comment(session.user, vendor):
            self._log(session, "comment.add", vendor_id, "denied")
            raise ApiError(403, "You can't comment on this vendor")
        text = str(body.get("body", "")).strip()
        if not text:
            raise ApiError(400, "Write something before posting")
        comment = self.store.add_comment(vendor_id, session.user.id, session.user.name, text[:MAX_COMMENT_LENGTH])
        self._log(session, "comment.add", vendor_id, comment_id=comment["id"])
        return {"comment": comment}

    def list_comments(self, session, body, vendor_id, **_):
        self._visible_vendor(session, vendor_id)
        return {"comments": self.store.list_comments(vendor_id)}

    def tracking(self, session, body, **_):
        """Cross-vendor tracking view: everything the signed-in person can see,
        grouped by whether a required review is still open. The same visibility
        rule as list_vendors (SR-01); nothing new is exposed here."""
        user = session.user
        vendors = [self._vendor_summary(v) for v in self.store.list_vendors() if auth.can_view_vendor(user, v)]
        needs_review = [v for v in vendors if v["open_review_tasks"]]
        ready_for_decision = [v for v in vendors if v["classification"] and not v["open_review_tasks"]
                              and v["status"] in ("Awaiting human decision", "Awaiting second approval")]
        return {"needs_review": needs_review[::-1], "ready_for_decision": ready_for_decision[::-1],
                "total": len(vendors)}

    def audit_log(self, session, body, **_):
        self._require(session, "audit.view", "audit.view")
        events = self.audit.read()
        return {"events": events[::-1][:500], "chain": self.audit.verify()}

    def users(self, session, body, **_):
        self._require(session, "users.view", "users.view")
        return {"users": [u.public() for u in auth.users_in(self.tenant.id)], "roles": auth.ROLES}

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



class CounterpartApp:
    """The platform: sign-in, and routing each request to the signed-in user's tenant.

    The tenant is taken from the session (the signed-in identity) and from nowhere else.
    Tenant spaces are separate folders under <data>/tenants/, one per client company."""

    PLATFORM_HANDLERS = {"demo_users", "sign_in"}

    def __init__(self, data_dir: Path, clock=None):
        self.data_dir = Path(data_dir)
        self.sessions = auth.Sessions(clock) if clock else auth.Sessions()
        self.audit = AuditLog(self.data_dir / "platform-audit.jsonl")   # Sign-in failures only; no tenant data
        self.quiet = False
        self._tenants = {tid: TenantApp(tenant, tenants.space_path(self.data_dir, tid), self.sessions)
                         for tid, tenant in tenants.TENANTS.items()}

    def tenant(self, tenant_id: str) -> TenantApp:
        app = self._tenants.get(tenant_id)
        if app is None:
            raise ApiError(403, "Your account isn't linked to a company")
        return app

    def routes(self):
        return [
            ("GET", r"/api/demo-users", "demo_users", False),
            ("POST", r"/api/session", "sign_in", False),
            ("DELETE", r"/api/session", "sign_out", True),
            ("GET", r"/api/me", "me", True),
            ("GET", r"/api/overview", "overview", True),
            ("GET", r"/api/vendors", "list_vendors", True),
            ("POST", r"/api/vendors", "create_vendor", True),
            ("GET", rf"/api/vendors/(?P<vendor_id>{ID})", "get_vendor", True),
            ("POST", rf"/api/vendors/(?P<vendor_id>{ID})/documents", "upload", True),
            ("POST", rf"/api/vendors/(?P<vendor_id>{ID})/fedramp", "record_fedramp", True),
            ("POST", rf"/api/vendors/(?P<vendor_id>{ID})/assessments", "assess", True),
            ("POST", rf"/api/assessments/(?P<assessment_id>{ID})/decisions", "decide", True),
            ("POST", rf"/api/tasks/(?P<task_id>{ID})/complete", "complete_task", True),
            ("GET", rf"/api/vendors/(?P<vendor_id>{ID})/comments", "list_comments", True),
            ("POST", rf"/api/vendors/(?P<vendor_id>{ID})/comments", "add_comment", True),
            ("GET", r"/api/tracking", "tracking", True),
            ("GET", r"/api/audit", "audit_log", True),
            ("GET", r"/api/users", "users", True),
            ("GET", r"/api/settings", "get_settings", True),
            ("POST", r"/api/settings", "change_settings", True),
            ("GET", r"/api/rules", "rules", True),
        ]

    def call(self, name: str, session, body: dict, **params) -> dict:
        if name in self.PLATFORM_HANDLERS:
            return getattr(self, name)(session, body, **params)
        # Every other route needs a session, and the tenant comes from that session only
        return self.tenant(session.user.tenant_id).handle(name, session, body, **params)

    def demo_users(self, session, body, **_):
        return {"companies": [
                    {**tenant.public(),
                     "users": [{"id": u.id, "name": u.name, "role_name": u.role_name, "title": u.title}
                               for u in auth.users_in(tenant.id)]}
                    for tenant in tenants.TENANTS.values()],
                "note": "No passwords here. In AWS, Amazon Cognito handles sign-in and MFA."}

    def sign_in(self, session, body, **_):
        user_id = str(body.get("user_id", ""))
        try:
            token, new = self.sessions.sign_in(user_id)
        except auth.PermissionDenied:
            self.audit.record(actor="unknown", role="none", action="auth.sign_in", outcome="denied",
                              details={"reason": "unknown user"})
            raise ApiError(401, "Sign-in failed") from None
        home = self.tenant(new.user.tenant_id)
        home.audit.record(actor=new.user.id, role=new.user.role, action="auth.sign_in", outcome="success", details={})
        return {"user": new.user.public(), "tenant": home.tenant.public(), "_set_cookie": token}

    def purge_expired(self) -> dict:
        return {tid: app.purge_expired() for tid, app in self._tenants.items()}


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
            for route_method, pattern, name, needs_session in self.app.routes():
                match = re.fullmatch(pattern, path)
                if not match:
                    continue
                if route_method != method:
                    continue
                return self._call(method, name, needs_session, match.groupdict())
            if path.startswith("/api/"):
                raise ApiError(404, "Not found")
            raise ApiError(404, "Not found")
        except ApiError as error:
            self._json(error.status, {"error": error.message})
        except Exception:  # Never send internals to the browser
            traceback.print_exc()
            self._json(500, {"error": "Something went wrong. The error was logged."})

    def _call(self, method, name, needs_session, params):
        if method != "GET" and self.headers.get(CSRF_HEADER) != "1":
            raise ApiError(403, "Missing request header")
        token = self._cookie()
        session = self.app.sessions.get(token)
        if needs_session and session is None:
            raise ApiError(401, "Please sign in")

        length = int(self.headers.get("Content-Length") or 0)
        raw, body = b"", {}
        if name == "upload":
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
        result = self.app.call(name, session, body, raw=raw, token=token, **params)
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
