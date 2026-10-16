"""Tests for the local web server: access control, request forgery, headers, audit.

These start the real server on a random port and talk to it over HTTP, the
same way the browser does. Threats covered: broken access control (OWASP
A01, API1 BOLA), privilege escalation, CSRF, XSS defences, log integrity.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from app.web.server import make_server
from tests.helpers import SAMPLES


class Client:
    def __init__(self, base):
        self.base, self.cookie = base, None

    def call(self, method, path, body=None, raw=None, filename=None, csrf=True):
        headers = {}
        if csrf:
            headers["X-Counterpart-Request"] = "1"
        data = None
        if raw is not None:
            data, headers["X-Filename"] = raw, filename
        elif body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        if self.cookie:
            headers["Cookie"] = self.cookie
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request) as response:
                status, payload, head = response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            status, payload, head = error.code, error.read(), error.headers
        if head.get("Set-Cookie"):
            self.cookie = head["Set-Cookie"].split(";")[0]
        return status, json.loads(payload) if payload.startswith(b"{") else payload, head

    def sign_in(self, user_id):
        status, _, _ = self.call("POST", "/api/session", {"user_id": user_id})
        assert status == 200
        return self


class WebApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server = make_server(Path(cls.tmp.name), port=0, quiet=True)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

        # Priya requests Nimbus and uploads its documents; Dana reviews
        cls.priya = Client(cls.base).sign_in("usr_priya")
        _, body, _ = cls.priya.call("POST", "/api/vendors", {"name": "Nimbus Notes AI", "service": "Transcription",
                                                             "data_shared": "Meeting audio", "uses_ai_on_customer_data": True})
        cls.vendor_id = body["vendor"]["id"]
        for path in sorted((SAMPLES / "nimbus-notes-ai").glob("*.*")):
            if path.suffix != ".json":
                cls.priya.call("POST", f"/api/vendors/{cls.vendor_id}/documents", raw=path.read_bytes(), filename=path.name)
        _, body, _ = cls.priya.call("POST", f"/api/vendors/{cls.vendor_id}/assessments")
        cls.assessment = body["assessment"]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def test_full_flow_scores_and_flags_nimbus(self):
        self.assertEqual(self.assessment["status"], "ready_for_review")
        self.assertEqual((self.assessment["score"]["score"], self.assessment["score"]["classification"]), (69, "High"))
        self.assertEqual(len(self.assessment["injection_flags"]), 2)

    def test_security_headers_on_every_response(self):
        for path in ("/", "/app.js", "/api/demo-users", "/api/nope"):
            with self.subTest(path=path):
                _, _, head = Client(self.base).call("GET", path)
                self.assertIn("script-src 'self'", head["Content-Security-Policy"])
                self.assertEqual(head["X-Content-Type-Options"], "nosniff")
                self.assertEqual(head["X-Frame-Options"], "DENY")

    def test_session_cookie_is_httponly_and_samesite_strict(self):
        _, _, head = Client(self.base).call("POST", "/api/session", {"user_id": "usr_omar"})
        self.assertIn("HttpOnly", head["Set-Cookie"])
        self.assertIn("SameSite=Strict", head["Set-Cookie"])

    def test_signed_out_requests_are_refused(self):
        for method, path in (("GET", "/api/vendors"), ("GET", f"/api/vendors/{self.vendor_id}"), ("GET", "/api/audit")):
            with self.subTest(path=path):
                self.assertEqual(Client(self.base).call(method, path)[0], 401)

    def test_changes_without_the_request_header_are_refused(self):
        status, _, _ = self.priya.call("POST", "/api/vendors", {"name": "x", "service": "x", "data_shared": "x",
                                                                "uses_ai_on_customer_data": False}, csrf=False)
        self.assertEqual(status, 403)

    def test_users_cannot_see_each_others_vendors(self):
        omar = Client(self.base).sign_in("usr_omar")
        self.assertEqual(omar.call("GET", f"/api/vendors/{self.vendor_id}")[0], 404)
        self.assertEqual(omar.call("GET", "/api/vendors")[1]["vendors"], [])
        status, _, _ = omar.call("POST", f"/api/vendors/{self.vendor_id}/documents", raw=b"%PDF-1.7", filename="x.pdf")
        self.assertEqual(status, 404)

    def test_roles_are_enforced_on_the_server(self):
        dana = Client(self.base).sign_in("usr_dana")
        sam = Client(self.base).sign_in("usr_sam")
        jasmine = Client(self.base).sign_in("usr_jasmine")
        decision = {"decision": "Approved", "rationale": "x" * 30, "evidence_confirmed": True}
        url = f"/api/assessments/{self.assessment['id']}/decisions"
        self.assertEqual(self.priya.call("POST", url, decision)[0], 403)    # Requester
        self.assertEqual(sam.call("POST", url, decision)[0], 403)           # Administrator
        self.assertEqual(jasmine.call("POST", url, decision)[0], 403)       # ISSO is read-only
        self.assertEqual(sam.call("GET", f"/api/vendors/{self.vendor_id}")[0], 404)  # Admins don't see vendor data
        self.assertEqual(self.priya.call("GET", "/api/audit")[0], 403)
        self.assertEqual(dana.call("POST", "/api/settings", {"model_mode": "approves"})[0], 403)
        status, _, _ = dana.call("POST", f"/api/vendors/{self.vendor_id}/documents", raw=b"x", filename="x.pdf")
        self.assertEqual(status, 403)                                        # Reviewers don't upload

    def test_rejected_upload_is_recorded_but_not_stored(self):
        status, body, _ = self.priya.call("POST", f"/api/vendors/{self.vendor_id}/documents", raw=b"MZ program", filename="policy.pdf")
        self.assertEqual(status, 200)
        self.assertEqual(body["document"]["status"], "rejected")
        stored = Path(self.tmp.name, "files", self.vendor_id)
        self.assertNotIn(body["document"]["sha256"], [p.name for p in stored.iterdir()])

    def test_audit_log_is_intact_and_holds_no_document_text(self):
        jasmine = Client(self.base).sign_in("usr_jasmine")
        _, body, _ = jasmine.call("GET", "/api/audit")
        self.assertTrue(body["chain"]["intact"])
        log = Path(self.tmp.name, "audit.jsonl").read_text()
        for secret in ("Ignore all previous instructions", "CANARY-NIMBUS", "SYSTEM NOTE", jasmine.cookie.split("=")[1]):
            self.assertNotIn(secret, log)

    def test_unknown_routes_and_bad_ids_are_not_found(self):
        for path in ("/api/vendors/../../etc/passwd", "/api/vendors/ven_ZZZ", "/static/../server.py"):
            with self.subTest(path=path):
                self.assertEqual(self.priya.call("GET", path)[0], 404)


class AuditTamperDetection(unittest.TestCase):
    def test_editing_an_old_event_breaks_the_chain(self):
        from app.common.audit import AuditLog
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            for action in ("a", "b", "c"):
                log.record(actor="usr_dana", role="reviewer", action=action)
            self.assertTrue(log.verify()["intact"])
            lines = log.path.read_text().splitlines()
            lines[1] = lines[1].replace('"outcome": "success"', '"outcome": "denied"')
            log.path.write_text("\n".join(lines) + "\n")
            self.assertEqual(log.verify(), {"intact": False, "events": 3, "first_bad_seq": 2})

    def test_audit_refuses_document_contents(self):
        from app.common.audit import AuditLog
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                AuditLog(Path(tmp) / "a.jsonl").record(actor="x", role="y", action="z", details={"excerpt": "text"})


if __name__ == "__main__":
    unittest.main()
