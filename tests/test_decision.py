"""Tests for the decision service: human review requirements HR-01 to HR-07."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from app.ai_worker import PretendModel, run_assessment
from app.common.audit import AuditLog
from app.common.auth import FRESH_SIGN_IN_SECONDS, PermissionDenied, Session, get_user
from app.common.store import Store
from app.decision import DecisionRefused, record_decision, vendor_status
from tests.helpers import expected, sample_documents

RATIONALE = "Reviewed the SOC 2 evidence and the open conflicts in detail."


class DecisionRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store, self.audit = Store(root), AuditLog(root / "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def vendor(self, sample="nimbus-notes-ai", mode="normal", owner="usr_priya"):
        info = expected(sample)
        vendor = self.store.create_vendor(name=info["vendor"], service="s", data_shared="d",
                                          uses_ai_on_customer_data=info["uses_ai_on_customer_data"],
                                          owner_id=owner, owner_name="Owner")
        for doc in sample_documents(sample):
            self.store.add_document(vendor["id"], None, filename=doc["filename"], sha256=doc["sha256"],
                                    status="accepted", flags=doc["flags"], segments=doc["segments"],
                                    uploaded_by=owner, uploaded_by_name="Owner", size_bytes=1, file_type="pdf")
        return vendor, self.assess(vendor, mode)

    def assess(self, vendor, mode="normal"):
        record = run_assessment(vendor_id=vendor["id"], vendor_name=vendor["name"],
                                uses_ai_on_customer_data=vendor["uses_ai_on_customer_data"],
                                documents=self.store.list_documents(vendor["id"]), model=PretendModel(mode))
        return self.store.add_assessment(record, started_by="usr_priya", started_by_name="Priya")

    def decide(self, assessment, user="usr_dana", decision="Further Review Required", fresh=True, **extra):
        session = Session(get_user(user), time.time() if fresh else time.time() - FRESH_SIGN_IN_SECONDS - 60)
        args = dict(rationale=RATIONALE, evidence_confirmed=True, conditions="")
        args.update(extra)
        return record_decision(store=self.store, audit=self.audit, session=session,
                               assessment_id=assessment["id"], decision=decision, **args)

    # ----- who may decide ---------------------------------------------------------
    def test_only_reviewers_can_decide_and_refusals_are_logged(self):
        _, assessment = self.vendor()
        for user in ("usr_priya", "usr_omar", "usr_sam", "usr_jasmine"):
            with self.subTest(user=user):
                with self.assertRaises(PermissionDenied):
                    self.decide(assessment, user)
        denied = [e for e in self.audit.read() if e["outcome"] == "denied"]
        self.assertEqual(len(denied), 4)
        self.assertEqual(self.store.list_decisions(), [])

    def test_decision_needs_a_recent_sign_in(self):
        _, assessment = self.vendor()
        with self.assertRaisesRegex(DecisionRefused, "sign in again"):
            self.decide(assessment, fresh=False)

    def test_separation_of_duties(self):
        _, assessment = self.vendor(owner="usr_dana")  # The reviewer requested this vendor
        with self.assertRaisesRegex(DecisionRefused, "Separation of duties"):
            self.decide(assessment, "usr_dana")
        self.decide(assessment, "usr_marcus")  # A different reviewer can

    # ----- what a decision must contain -----------------------------------------
    def test_required_contents(self):
        _, assessment = self.vendor()
        cases = {"Choose one": dict(decision="Yes please"),
                 "rationale": dict(rationale="ok"),
                 "conditions": dict(decision="Approved with Conditions", conditions=""),
                 "Confirm": dict(evidence_confirmed=False)}
        for message, change in cases.items():
            with self.subTest(case=message):
                with self.assertRaisesRegex(DecisionRefused, message):
                    self.decide(assessment, **change)

    def test_record_holds_who_what_why_and_versions(self):
        _, assessment = self.vendor()
        record = self.decide(assessment, decision="Rejected")
        for key in ("reviewer_id", "reviewer_name", "decision", "rationale", "recorded_at",
                    "assessment_version", "rule_set_version", "score", "classification"):
            self.assertIn(key, record)

    # ----- no overwrites, current evidence only ---------------------------------
    def test_a_final_decision_is_never_replaced(self):
        _, assessment = self.vendor()
        self.decide(assessment, decision="Rejected")
        with self.assertRaisesRegex(DecisionRefused, "already has a final decision"):
            self.decide(assessment, "usr_marcus", decision="Approved")
        self.assertEqual(len(self.store.list_decisions()), 1)
        self.assertFalse(hasattr(self.store, "update_decision") or hasattr(self.store, "delete_decision"))

    def test_only_the_latest_assessment_can_be_decided(self):
        vendor, first = self.vendor()
        self.assess(vendor)
        with self.assertRaisesRegex(DecisionRefused, "newer assessment"):
            self.decide(first)

    def test_rejected_ai_output_cannot_be_decided(self):
        _, assessment = self.vendor(mode="approves")
        with self.assertRaisesRegex(DecisionRefused, "no valid result"):
            self.decide(assessment)

    # ----- two-person rule and overrides ----------------------------------------
    def test_critical_approval_needs_a_second_different_reviewer(self):
        vendor, assessment = self.vendor("copperline-backup")
        self.assertEqual(assessment["score"]["classification"], "Critical")
        first = self.decide(assessment, "usr_dana", "Approved")
        self.assertEqual(first["stage"], "first_approval")
        self.assertEqual(vendor_status(self.store, vendor["id"])["status"], "Awaiting second approval")
        with self.assertRaisesRegex(DecisionRefused, "different reviewer"):
            self.decide(assessment, "usr_dana", "Approved")
        second = self.decide(assessment, "usr_marcus", "Approved")
        self.assertEqual((second["stage"], second["second_approval_of"]), ("final", first["id"]))
        self.assertEqual(vendor_status(self.store, vendor["id"])["status"], "Approved")

    def test_rejecting_a_critical_vendor_needs_one_reviewer(self):
        _, assessment = self.vendor("copperline-backup")
        self.assertEqual(self.decide(assessment, decision="Rejected")["stage"], "final")

    def test_overrides_are_flagged(self):
        _, high = self.vendor("nimbus-notes-ai")
        self.assertTrue(self.decide(high, decision="Approved")["override"])
        _, low = self.vendor("kestrel-payroll-cloud", owner="usr_omar")
        self.assertTrue(self.decide(low, decision="Rejected")["override"])
        _, low2 = self.vendor("kestrel-payroll-cloud", owner="usr_omar")
        self.assertFalse(self.decide(low2, decision="Approved")["override"])

    def test_no_status_until_a_person_decides(self):
        vendor, _ = self.vendor()
        self.assertEqual(vendor_status(self.store, vendor["id"]), {"status": "Awaiting human decision", "final": False})


if __name__ == "__main__":
    unittest.main()
