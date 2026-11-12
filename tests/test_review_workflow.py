"""Web-level tests for Milestone 2: the checklist a new assessment gets,
completing those tasks over the API, comments, and the tracking view.

Each test builds its own vendor and assessment (helper: new_high_tier_vendor),
so one test completing a task never changes what another test sees -- the
same reason tests/test_decision.py gives each test its own self.vendor().
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from app.review.tasks import LABELS
from app.web.server import make_server
from tests.helpers import SAMPLES, doc_type_for
from tests.test_web import Client


class ReviewWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server = make_server(Path(cls.tmp.name), port=0, quiet=True)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.priya = Client(self.base).sign_in("usr_priya")
        self.dana = Client(self.base).sign_in("usr_dana")        # reviewer
        self.marcus = Client(self.base).sign_in("usr_marcus")    # reviewer
        self.sam = Client(self.base).sign_in("usr_sam")          # admin
        self.jasmine = Client(self.base).sign_in("usr_jasmine")  # isso, read-only
        self.omar = Client(self.base).sign_in("usr_omar")        # app_user, uninvolved
        self.vendor_id, self.assessment, self.tasks = self.new_high_tier_vendor()

    def new_high_tier_vendor(self, name="Nimbus Notes AI"):
        """A fresh vendor scored High (6 required tasks, two-person rule)."""
        _, body, _ = self.priya.call("POST", "/api/vendors", {"name": name, "service": "Transcription",
                                                               "data_shared": "Meeting audio",
                                                               "uses_ai_on_customer_data": True})
        vendor_id = body["vendor"]["id"]
        for path in sorted((SAMPLES / "nimbus-notes-ai").glob("*.*")):
            if path.suffix != ".json":
                self.priya.call("POST", f"/api/vendors/{vendor_id}/documents", raw=path.read_bytes(),
                                filename=path.name, doc_type=doc_type_for(path.name))
        status, body, _ = self.priya.call("POST", f"/api/vendors/{vendor_id}/assessments")
        assert status == 200, body
        assert body["assessment"]["score"]["classification"] == "High", body["assessment"]["score"]
        return vendor_id, body["assessment"], body["tasks"]

    def task_id(self, kind: str) -> str:
        return next(t["id"] for t in self.tasks if t["kind"] == kind)

    def complete_all(self):
        for task in self.tasks:
            status, _, _ = self.dana.call("POST", f"/api/tasks/{task['id']}/complete",
                                          {"note": f"{task['kind']}: cleared for this test."})
            assert status == 200

    # ----- checklist generation ---------------------------------------------------
    def test_a_high_tier_assessment_gets_all_six_required_tasks(self):
        self.assertEqual({t["kind"] for t in self.tasks}, set(LABELS))
        self.assertTrue(all(t["status"] == "open" for t in self.tasks))

    def test_the_vendor_lists_its_open_review_tasks_by_label(self):
        _, body, _ = self.dana.call("GET", f"/api/vendors/{self.vendor_id}")
        self.assertEqual(sorted(body["vendor"]["open_review_tasks"]), sorted(LABELS.values()))

    # ----- completing tasks: permissions -------------------------------------------
    def test_isso_can_see_the_task_but_not_complete_it(self):
        status, body, _ = self.jasmine.call("POST", f"/api/tasks/{self.task_id('security')}/complete",
                                            {"note": "Trying anyway."})
        self.assertEqual(status, 403, body)

    def test_an_app_user_who_cannot_even_see_the_vendor_gets_not_found(self):
        status, body, _ = self.omar.call("POST", f"/api/tasks/{self.task_id('security')}/complete",
                                         {"note": "Trying anyway."})
        self.assertEqual(status, 404, body)  # Omar isn't this vendor's owner, so he can't see it at all

    def test_admin_cannot_complete_a_task_either_because_they_cannot_see_the_vendor(self):
        # Unchanged from Milestone 1: administrators have no vendor visibility at all.
        status, body, _ = self.sam.call("POST", f"/api/tasks/{self.task_id('department_head')}/complete",
                                        {"note": "Approved for the department."})
        self.assertEqual(status, 404, body)

    def test_a_reviewer_completes_the_department_head_task_by_recording_who_approved(self):
        status, body, _ = self.dana.call("POST", f"/api/tasks/{self.task_id('department_head')}/complete",
                                         {"note": "Department head Maria Chen approved by email 11/11."})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["task"]["completed_by_name"], "Dana Whitfield")  # who recorded it
        self.assertIn("Maria Chen", body["task"]["note"])                     # who actually approved
        status, body, _ = self.dana.call("POST", f"/api/tasks/{self.task_id('department_head')}/complete",
                                         {"note": "Trying again."})
        self.assertEqual(status, 409, body)

    def test_a_note_is_required_and_has_a_minimum_length(self):
        for note in ("", "ok"):
            with self.subTest(note=repr(note)):
                status, body, _ = self.dana.call("POST", f"/api/tasks/{self.task_id('security')}/complete",
                                                  {"note": note})
                self.assertEqual(status, 400, body)

    def test_reviewer_completes_the_non_head_tasks(self):
        for kind in ("security", "ai_usage", "it", "legal", "privacy"):
            status, body, _ = self.dana.call("POST", f"/api/tasks/{self.task_id(kind)}/complete",
                                             {"note": f"{kind}: reviewed, no concerns."})
            self.assertEqual(status, 200, (kind, body))

    def test_another_companys_user_gets_the_same_not_found_as_a_missing_task(self):
        lena = Client(self.base).sign_in("usr_lena")  # Larkspur Robotics
        status, _, _ = lena.call("POST", f"/api/tasks/{self.task_id('security')}/complete", {"note": "x" * 10})
        self.assertEqual(status, 404)
        status, _, _ = lena.call("POST", "/api/tasks/tsk_000000000000/complete", {"note": "x" * 10})
        self.assertEqual(status, 404)

    # ----- the decision is gated on the checklist, and the two-person rule --------
    def test_decision_refused_until_every_task_is_checked_off(self):
        status, body, _ = self.dana.call("POST", f"/api/assessments/{self.assessment['id']}/decisions",
                                         {"decision": "Approved", "rationale": "x" * 30, "evidence_confirmed": True})
        self.assertEqual(status, 409, body)
        self.assertIn("Required reviews", body["error"])

    def test_once_checked_off_a_high_tier_approval_needs_two_reviewers(self):
        self.complete_all()
        decision = {"decision": "Approved", "rationale": "x" * 30, "evidence_confirmed": True}
        status, body, _ = self.dana.call("POST", f"/api/assessments/{self.assessment['id']}/decisions", decision)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["decision"]["stage"], "first_approval")
        status, body, _ = self.marcus.call("POST", f"/api/assessments/{self.assessment['id']}/decisions", decision)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["decision"]["stage"], "final")

    # ----- comments -----------------------------------------------------------------
    def test_the_requester_and_a_reviewer_can_comment_an_isso_cannot(self):
        status, body, _ = self.priya.call("POST", f"/api/vendors/{self.vendor_id}/comments",
                                          {"body": "Flagging that the vendor is on a tight renewal timeline."})
        self.assertEqual(status, 200, body)
        status, body, _ = self.dana.call("POST", f"/api/vendors/{self.vendor_id}/comments",
                                         {"body": "Noted; prioritizing the review."})
        self.assertEqual(status, 200, body)
        status, body, _ = self.jasmine.call("POST", f"/api/vendors/{self.vendor_id}/comments", {"body": "x"})
        self.assertEqual(status, 403, body)

    def test_an_uninvolved_app_user_cannot_comment_on_someone_elses_vendor(self):
        status, _, _ = self.omar.call("POST", f"/api/vendors/{self.vendor_id}/comments", {"body": "x"})
        self.assertEqual(status, 404)  # Omar can't even see this vendor

    def test_comments_appear_in_order_on_the_vendor_and_in_the_dedicated_list(self):
        self.priya.call("POST", f"/api/vendors/{self.vendor_id}/comments", {"body": "First."})
        self.dana.call("POST", f"/api/vendors/{self.vendor_id}/comments", {"body": "Second."})
        _, body, _ = self.dana.call("GET", f"/api/vendors/{self.vendor_id}")
        _, body2, _ = self.dana.call("GET", f"/api/vendors/{self.vendor_id}/comments")
        self.assertEqual([c["body"] for c in body["comments"]], ["First.", "Second."])
        self.assertEqual([c["body"] for c in body["comments"]], [c["body"] for c in body2["comments"]])

    def test_empty_comments_are_refused(self):
        status, body, _ = self.dana.call("POST", f"/api/vendors/{self.vendor_id}/comments", {"body": "   "})
        self.assertEqual(status, 400, body)

    # ----- tracking view -------------------------------------------------------------
    def test_tracking_view_lists_this_vendor_under_needs_review(self):
        _, body, _ = self.dana.call("GET", "/api/tracking")
        self.assertTrue(any(v["id"] == self.vendor_id for v in body["needs_review"]))
        self.assertFalse(any(v["id"] == self.vendor_id for v in body["ready_for_decision"]))

    def test_tracking_view_moves_a_vendor_once_every_task_is_done(self):
        self.complete_all()
        _, body, _ = self.dana.call("GET", "/api/tracking")
        self.assertFalse(any(v["id"] == self.vendor_id for v in body["needs_review"]))
        self.assertTrue(any(v["id"] == self.vendor_id for v in body["ready_for_decision"]))

    def test_tracking_view_is_scoped_like_list_vendors(self):
        status, body, _ = self.omar.call("GET", "/api/tracking")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 0)  # Omar owns no vendor here and isn't a reviewer


if __name__ == "__main__":
    unittest.main()
