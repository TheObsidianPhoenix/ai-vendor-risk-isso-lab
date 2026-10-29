"""Tests for the FedRAMP requirement (decision D-13).

A vendor that will handle federal data needs a FedRAMP authorization at least
as high as the data's impact level. People enter both facts; the check is
deterministic; an unmet requirement blocks a plain approval.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from datetime import date, timedelta
from pathlib import Path

from app.ai_worker import PretendModel, run_assessment
from app.common.audit import AuditLog
from app.common.auth import Session, get_user
from app.common.store import Store
from app.decision import DecisionRefused, fedramp, record_decision
from app.web.server import make_server
from tests.helpers import SAMPLES, doc_type_for, expected, sample_documents
from tests.test_web import Client

TODAY = date(2026, 10, 28)


def checked(level="Class C (Moderate)", status="certified", days_ago=5):
    return {"status": status, "level": level, "checked_on": (TODAY - timedelta(days=days_ago)).isoformat()}


class Requirement(unittest.TestCase):
    def test_no_federal_data_means_no_requirement(self):
        result = fedramp.requirement({"federal_data_impact": "none"}, TODAY)
        self.assertEqual((result["applies"], result["met"]), (False, True))

    def test_vendors_created_before_this_rule_count_as_no_federal_data(self):
        self.assertTrue(fedramp.requirement({}, TODAY)["met"])

    def test_level_must_cover_the_data(self):
        cases = [("low", "Class B (Low)", True), ("moderate", "Class B (Low)", False),
                 ("moderate", "Class C (Moderate)", True), ("moderate", "High", True),
                 ("high", "Moderate", False), ("high", "Class D (High)", True),
                 ("low", "LI-SaaS", True), ("low", "Class A (Pilot)", False)]
        for impact, level, met in cases:
            with self.subTest(impact=impact, level=level):
                vendor = {"federal_data_impact": impact, "fedramp": checked(level)}
                self.assertEqual(fedramp.requirement(vendor, TODAY)["met"], met)

    def test_not_recorded_in_process_or_not_listed_is_not_met(self):
        for status in (None, checked(status="in_process", level=""), checked(status="not_listed", level="")):
            with self.subTest(status=status):
                vendor = {"federal_data_impact": "low", "fedramp": status}
                self.assertFalse(fedramp.requirement(vendor, TODAY)["met"])

    def test_an_old_check_must_be_repeated(self):
        vendor = {"federal_data_impact": "low", "fedramp": checked("Low", days_ago=fedramp.RECHECK_DAYS + 1)}
        result = fedramp.requirement(vendor, TODAY)
        self.assertFalse(result["met"])
        self.assertIn("check again", result["reason"])

    def test_reviewer_input_is_validated(self):
        bad = [{"status": "approved"}, {"status": "certified", "level": "Platinum", "checked_on": "2026-10-01"},
               {"status": "certified", "level": "Low", "checked_on": "yesterday"},
               {"status": "certified", "level": "Low", "checked_on": "2026-12-01"}]
        for body in bad:
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    fedramp.validate_status(body, TODAY)
        clean = fedramp.validate_status({"status": "not_listed", "level": "High", "checked_on": "2026-10-20",
                                         "listing": "x" * 500}, TODAY)
        self.assertEqual((clean["level"], len(clean["listing"]), clean["source"]), ("", 200, "FedRAMP Marketplace"))


class DecisionsHonourTheRequirement(unittest.TestCase):
    """Kestrel scores Low, so a plain approval is normally fine. Only FedRAMP can block it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store, self.audit = Store(root), AuditLog(root / "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def assessed(self, impact):
        info = expected("kestrel-payroll-cloud")
        vendor = self.store.create_vendor(name=info["vendor"], service="s", data_shared="d",
                                          uses_ai_on_customer_data=False, federal_data_impact=impact,
                                          owner_id="usr_priya", owner_name="Priya")
        for doc in sample_documents("kestrel-payroll-cloud"):
            self.store.add_document(vendor["id"], None, filename=doc["filename"], sha256=doc["sha256"],
                                    doc_type=doc["doc_type"], status="accepted", flags=doc["flags"],
                                    segments=doc["segments"], uploaded_by="usr_priya", uploaded_by_name="Priya",
                                    size_bytes=1, file_type="pdf")
        record = run_assessment(vendor_id=vendor["id"], vendor_name=vendor["name"], uses_ai_on_customer_data=False,
                                documents=self.store.list_documents(vendor["id"]), model=PretendModel())
        return vendor, self.store.add_assessment(record, started_by="usr_priya", started_by_name="Priya")

    def decide(self, assessment, decision, conditions=""):
        return record_decision(store=self.store, audit=self.audit, session=Session(get_user("usr_dana"), time.time()),
                               assessment_id=assessment["id"], decision=decision, conditions=conditions,
                               rationale="Reviewed the SOC 2 report and the FedRAMP listing.", evidence_confirmed=True)

    def test_plain_approval_is_refused_while_the_requirement_is_unmet(self):
        _, assessment = self.assessed("moderate")
        with self.assertRaisesRegex(DecisionRefused, "FedRAMP requirement not met"):
            self.decide(assessment, "Approved")
        self.assertEqual(self.store.list_decisions(), [])
        refused = [e for e in self.audit.read() if e["outcome"] == "denied"]
        self.assertIn("FedRAMP", refused[-1]["details"]["reason"])

    def test_conditional_approval_is_an_exception_and_an_override(self):
        _, assessment = self.assessed("moderate")
        record = self.decide(assessment, "Approved with Conditions", "No federal data until FedRAMP Moderate is granted.")
        self.assertTrue(record["fedramp_exception"])
        self.assertTrue(record["override"])
        self.assertFalse(record["fedramp_requirement"]["met"])

    def test_rejecting_is_always_allowed(self):
        _, assessment = self.assessed("high")
        self.assertFalse(self.decide(assessment, "Rejected")["fedramp_exception"])

    def test_approval_works_once_a_reviewer_records_a_sufficient_listing(self):
        vendor, assessment = self.assessed("moderate")
        self.store.set_vendor_fedramp(vendor["id"], dict(fedramp.validate_status(
            {"status": "certified", "level": "Class C (Moderate)", "checked_on": date.today().isoformat()}),
            recorded_by="usr_dana", recorded_by_name="Dana Whitfield"))
        record = self.decide(assessment, "Approved")
        self.assertEqual((record["fedramp_exception"], record["override"]), (False, False))
        self.assertTrue(record["fedramp_requirement"]["met"])

    def test_vendors_without_federal_data_are_unaffected(self):
        _, assessment = self.assessed("none")
        self.assertFalse(self.decide(assessment, "Approved")["fedramp_exception"])


class WebApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server = make_server(Path(cls.tmp.name), port=0, quiet=True)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.priya = Client(cls.base).sign_in("usr_priya")
        _, body, _ = cls.priya.call("POST", "/api/vendors", {"name": "Kestrel Payroll Cloud", "service": "Payroll",
                                                             "data_shared": "Employee records", "uses_ai_on_customer_data": False,
                                                             "federal_data_impact": "moderate"})
        cls.vendor_id = body["vendor"]["id"]
        cls.url = f"/api/vendors/{cls.vendor_id}/fedramp"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def check(self, **overrides):
        return dict({"status": "certified", "level": "Class C (Moderate)", "checked_on": date.today().isoformat()}, **overrides)

    def test_requester_says_federal_data_but_cannot_vouch_for_the_listing(self):
        _, body, _ = self.priya.call("GET", f"/api/vendors/{self.vendor_id}")
        self.assertFalse(body["vendor"]["fedramp_requirement"]["met"])
        self.assertFalse(body["can"]["verify_fedramp"])
        self.assertEqual(self.priya.call("POST", self.url, self.check())[0], 403)

    def test_bad_impact_level_is_refused(self):
        status, _, _ = self.priya.call("POST", "/api/vendors", {"name": "x", "service": "x", "data_shared": "x",
                                                                "uses_ai_on_customer_data": False,
                                                                "federal_data_impact": "secret"})
        self.assertEqual(status, 400)

    def test_reviewer_records_the_listing_and_it_is_audited(self):
        dana = Client(self.base).sign_in("usr_dana")
        self.assertEqual(dana.call("POST", self.url, self.check(level="Gold"))[0], 400)
        status, body, _ = dana.call("POST", self.url, self.check())
        self.assertEqual(status, 200)
        self.assertTrue(body["vendor"]["fedramp_requirement"]["met"])
        self.assertEqual(body["vendor"]["fedramp_requirement"]["recorded_by"], "Dana Whitfield")
        jasmine = Client(self.base).sign_in("usr_jasmine")
        events = [e for e in jasmine.call("GET", "/api/audit")[1]["events"] if e["action"] == "vendor.fedramp"]
        self.assertEqual(events[0]["details"]["level"], "Class C (Moderate)")


if __name__ == "__main__":
    unittest.main()
