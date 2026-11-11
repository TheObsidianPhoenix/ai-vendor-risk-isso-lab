"""Tenant isolation: one client company can never reach another's data.

Two fictional companies use the same running server: Harborline Federal and Larkspur
Robotics. Harborline creates a vendor, uploads its documents and runs an assessment.
Then Larkspur's people, including its most privileged roles, try to read, list,
change and decide on Harborline's records, and try to pick their own tenant.

Threats covered: cross-tenant data access (OWASP API1 BOLA across tenants), tenant
ID forgery, path traversal in a tenant ID, shared settings leaking between tenants,
and a routing bug handing a request to the wrong tenant.
"""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.common import auth, tenants
from app.common.auth import Session, get_user
from app.mcp_server.server import CounterpartMCP
from app.web.server import ApiError, make_server
from tests.helpers import SAMPLES, doc_type_for
from tests.test_web import Client

HARBORLINE, LARKSPUR = "ten_harborline", "ten_larkspur"
SECRET_NAME = "Copperline Backup"           # Harborline's vendor: must never appear at Larkspur


class TenantIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.server = make_server(cls.root, port=0, quiet=True)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

        # Harborline: Priya requests a vendor, uploads its documents and runs an assessment
        cls.priya = Client(cls.base).sign_in("usr_priya")
        _, body, _ = cls.priya.call("POST", "/api/vendors", {"name": SECRET_NAME, "service": "Backups",
                                                             "data_shared": "Database backups",
                                                             "uses_ai_on_customer_data": False})
        cls.vendor_id = body["vendor"]["id"]
        for path in sorted((SAMPLES / "copperline-backup").glob("*.*")):
            if path.suffix != ".json":
                cls.priya.call("POST", f"/api/vendors/{cls.vendor_id}/documents", raw=path.read_bytes(),
                               filename=path.name, doc_type=doc_type_for(path.name))
        _, body, _ = cls.priya.call("POST", f"/api/vendors/{cls.vendor_id}/assessments")
        cls.assessment_id = body["assessment"]["id"]

        # Larkspur: one of each role
        cls.lena = Client(cls.base).sign_in("usr_lena")      # requester
        cls.theo = Client(cls.base).sign_in("usr_theo")      # reviewer: sees every vendor in HIS company
        cls.ravi = Client(cls.base).sign_in("usr_ravi")      # admin
        cls.noor = Client(cls.base).sign_in("usr_noor")      # compliance officer: reads everything in HER company
        cls.larkspur = {"requester": cls.lena, "reviewer": cls.theo, "admin": cls.ravi, "compliance": cls.noor}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    # ----- reading ----------------------------------------------------------------
    def test_the_owner_company_can_see_its_own_vendor(self):
        dana = Client(self.base).sign_in("usr_dana")
        status, body, _ = dana.call("GET", f"/api/vendors/{self.vendor_id}")
        self.assertEqual((status, body["vendor"]["name"]), (200, SECRET_NAME))

    def test_no_role_in_another_company_can_read_the_vendor(self):
        for role, client in self.larkspur.items():
            with self.subTest(role=role):
                status, body, _ = client.call("GET", f"/api/vendors/{self.vendor_id}")
                self.assertEqual(status, 404)
                self.assertNotIn(SECRET_NAME, str(body))

    def test_a_cross_company_request_looks_exactly_like_a_missing_record(self):
        # Same status and same words as an ID that never existed: no way to tell a real ID from a fake one
        real = self.theo.call("GET", f"/api/vendors/{self.vendor_id}")
        fake = self.theo.call("GET", "/api/vendors/ven_000000000000")
        self.assertEqual((real[0], real[1]), (fake[0], fake[1]))

    def test_lists_and_overview_hold_nothing_from_another_company(self):
        for role, client in self.larkspur.items():
            for path in ("/api/vendors", "/api/overview"):
                with self.subTest(role=role, path=path):
                    _, body, _ = client.call("GET", path)
                    self.assertNotIn(SECRET_NAME, str(body))
                    self.assertNotIn(self.vendor_id, str(body))
        self.assertEqual(self.theo.call("GET", "/api/vendors")[1]["vendors"], [])

    # ----- changing ---------------------------------------------------------------
    def test_another_company_cannot_change_or_decide_anything(self):
        attempts = {
            "upload a document": lambda c: c.call("POST", f"/api/vendors/{self.vendor_id}/documents",
                                                  raw=b"%PDF-1.7", filename="x.pdf"),
            "run an assessment": lambda c: c.call("POST", f"/api/vendors/{self.vendor_id}/assessments"),
            "record FedRAMP status": lambda c: c.call("POST", f"/api/vendors/{self.vendor_id}/fedramp",
                                                      {"status": "authorized", "impact_level": "moderate",
                                                       "marketplace_id": "FR0000000000", "note": "x"}),
            "record a decision": lambda c: c.call("POST", f"/api/assessments/{self.assessment_id}/decisions",
                                                  {"decision": "approve", "justification": "Looks fine to me, approving now.",
                                                   "evidence_confirmed": True}),
        }
        before = self._fingerprint(HARBORLINE)
        for what, attempt in attempts.items():
            for role, client in self.larkspur.items():
                with self.subTest(what=what, role=role):
                    status, body, _ = attempt(client)
                    self.assertIn(status, (403, 404))
                    self.assertNotIn(SECRET_NAME, str(body))
        self.assertEqual(self._fingerprint(HARBORLINE), before, "nothing in Harborline's space changed")

    # ----- choosing a tenant ------------------------------------------------------
    def test_the_tenant_cannot_be_chosen_by_the_caller(self):
        # Headers, query strings and body fields naming another tenant are all ignored:
        # the tenant comes only from who is signed in.
        import json
        import urllib.request
        for label, path, headers, body in (
            ("header", "/api/vendors", {"X-Tenant-Id": HARBORLINE, "X-Tenant": HARBORLINE}, None),
            ("query string", f"/api/vendors?tenant_id={HARBORLINE}&tenant={HARBORLINE}", {}, None),
            ("header on a record", f"/api/vendors/{self.vendor_id}", {"X-Tenant-Id": HARBORLINE}, None),
        ):
            with self.subTest(label=label):
                request = urllib.request.Request(self.base + path, headers={"Cookie": self.theo.cookie, **headers})
                try:
                    with urllib.request.urlopen(request) as response:
                        payload = response.read().decode()
                except urllib.error.HTTPError as error:
                    payload = error.read().decode()
                self.assertNotIn(SECRET_NAME, payload)
        # A vendor created with a forged tenant field still lands in the caller's own company
        _, body, _ = self.lena.call("POST", "/api/vendors", {"name": "Forged Tenant Test", "service": "s", "data_shared": "d",
                                                             "uses_ai_on_customer_data": False, "tenant_id": HARBORLINE})
        forged_id = body["vendor"]["id"]
        self.assertTrue((tenants.space_path(self.root, LARKSPUR) / "vendors.json").read_text().count(forged_id))
        self.assertNotIn(forged_id, (tenants.space_path(self.root, HARBORLINE) / "vendors.json").read_text())
        self.assertEqual(self.priya.call("GET", f"/api/vendors/{forged_id}")[0], 404)
        self.assertNotIn("tenant_id", json.dumps(body["vendor"]).replace('"owner', ""))

    def test_tenant_ids_cannot_point_outside_the_tenant_area(self):
        for bad in ("../ten_harborline", "ten_harborline/../ten_larkspur", "..", "", "ten_unknown", "TEN_HARBORLINE",
                    "ten_harborline\x00", "/etc", None, 7):
            with self.subTest(tenant_id=bad):
                with self.assertRaises(tenants.UnknownTenant):
                    tenants.space_path(self.root, bad)

    def test_a_session_from_another_company_is_refused_inside_the_tenant_app(self):
        # Defence in depth: even if routing ever sent a request to the wrong company's app,
        # that app checks the session's company itself before running any handler.
        harborline = self.server.app.tenant(HARBORLINE)
        outsider = Session(get_user("usr_theo"), time.time())
        for name in ("list_vendors", "get_vendor", "audit_log", "users", "decide"):
            with self.subTest(handler=name):
                with self.assertRaises(ApiError) as refused:
                    harborline.handle(name, outsider, {}, vendor_id=self.vendor_id, assessment_id=self.assessment_id)
                self.assertEqual(refused.exception.status, 403)
        with self.assertRaises(ApiError):
            harborline.handle("store", Session(get_user("usr_dana"), time.time()), {})   # Not a route: refused

    # ----- audit trail, people, settings -------------------------------------------
    def test_each_company_has_its_own_audit_trail(self):
        _, mine, _ = self.noor.call("GET", "/api/audit")
        self.assertTrue(mine["chain"]["intact"])
        text = str(mine["events"])
        for leak in ("usr_priya", "usr_dana", SECRET_NAME):
            self.assertNotIn(leak, text)
        # An ID a Larkspur user typed themselves may appear, but only as the target of their own
        # refused attempt. That is evidence of the attempt, kept in the attacker's own company trail.
        for event in mine["events"]:
            if self.vendor_id in str(event) or self.assessment_id in str(event):
                self.assertEqual(event["outcome"], "denied", event)
        actors = {e["actor"] for e in mine["events"]}
        self.assertTrue(actors <= {u.id for u in auth.users_in(LARKSPUR)} | {"system", "unknown"}, actors)
        # And Harborline's own trail is intact and does hold its events
        _, theirs, _ = Client(self.base).sign_in("usr_jasmine").call("GET", "/api/audit")
        self.assertTrue(theirs["chain"]["intact"])
        self.assertIn(self.vendor_id, str(theirs["events"]))
        self.assertNotIn("usr_theo", str(theirs["events"]))

    def test_an_admin_sees_only_their_own_companys_people(self):
        _, body, _ = self.ravi.call("GET", "/api/users")
        self.assertEqual({u["id"] for u in body["users"]}, {u.id for u in auth.users_in(LARKSPUR)})
        self.assertTrue(all(u["tenant_id"] == LARKSPUR for u in body["users"]))

    def test_settings_changed_in_one_company_do_not_change_another(self):
        self.assertEqual(self.ravi.call("POST", "/api/settings", {"model_mode": "fabricates"})[0], 200)
        try:
            self.assertEqual(self.ravi.call("GET", "/api/settings")[1]["model_mode"], "fabricates")
            self.assertEqual(self.priya.call("GET", "/api/settings")[1]["model_mode"], "normal")
        finally:
            self.ravi.call("POST", "/api/settings", {"model_mode": "normal"})

    def test_me_reports_the_signed_in_users_own_company(self):
        self.assertEqual(self.theo.call("GET", "/api/me")[1]["tenant"]["name"], "Larkspur Robotics")
        self.assertEqual(self.priya.call("GET", "/api/me")[1]["tenant"]["name"], "Harborline Federal")

    # ----- on disk, and the read-only AI connector ----------------------------------
    def test_data_lives_only_in_its_own_companys_space(self):
        harborline = tenants.space_path(self.root, HARBORLINE)
        larkspur = tenants.space_path(self.root, LARKSPUR)
        self.assertIn(self.vendor_id, (harborline / "vendors.json").read_text())
        for path in larkspur.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.vendor_id.encode(), path.read_bytes(), path)
        self.assertEqual(sorted(p.name for p in (self.root / "tenants").iterdir()), [HARBORLINE, LARKSPUR])
        # Nothing with tenant data sits outside the tenant folders
        outside = [p for p in self.root.iterdir() if p.name != "tenants"]
        for path in outside:
            self.assertNotIn(self.vendor_id.encode(), path.read_bytes(), path)

    def test_the_ai_connector_is_limited_to_the_users_company(self):
        def call(user, tool, **args):
            server = CounterpartMCP(self.root, user)
            reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": tool, "arguments": args}})
            return reply["result"]
        self.assertEqual(call("usr_theo", "list_vendors")["structuredContent"]["vendors"], [])
        other = call("usr_theo", "get_findings", vendor_id=self.vendor_id)
        missing = call("usr_theo", "get_findings", vendor_id="ven_000000000000")
        self.assertTrue(other["isError"])
        self.assertEqual(other["structuredContent"], missing["structuredContent"])
        mine = call("usr_dana", "list_vendors")["structuredContent"]["vendors"]
        self.assertEqual([v["name"] for v in mine], [SECRET_NAME])

    # ----- helper -----------------------------------------------------------------
    def _fingerprint(self, tenant_id: str) -> dict:
        import hashlib
        space = tenants.space_path(self.root, tenant_id)
        return {str(p.relative_to(space)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(space.rglob("*")) if p.is_file() and p.name != "audit.jsonl"}


if __name__ == "__main__":
    unittest.main()
