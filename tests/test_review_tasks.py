"""Tests for app.review.tasks: the required-review checklist per risk tier.

The table itself (D-19, approved 2026-11-11): every tier always gets a
Security review and an explicit AI usage review; Moderate adds IT; High and
Critical add Legal and Privacy too; every tier ends with a department head's
sign-off, and High/Critical need two different people for that (checked
separately, in test_decision.py).
"""

from __future__ import annotations

import unittest

from app.common.auth import PERMISSIONS, get_user
from app.review.tasks import LABELS, REQUIRED_TASKS, can_complete, generate, open_kinds, required_kinds


class RequiredTasks(unittest.TestCase):
    def test_every_tier_always_requires_security_and_ai_usage(self):
        for tier in ("Low", "Moderate", "High", "Critical"):
            with self.subTest(tier=tier):
                kinds = required_kinds(tier)
                self.assertIn("security", kinds)
                self.assertIn("ai_usage", kinds)
                self.assertIn("department_head", kinds)

    def test_it_only_from_moderate_up(self):
        self.assertNotIn("it", required_kinds("Low"))
        for tier in ("Moderate", "High", "Critical"):
            self.assertIn("it", required_kinds(tier))

    def test_legal_and_privacy_only_at_high_and_critical(self):
        for tier in ("Low", "Moderate"):
            self.assertNotIn("legal", required_kinds(tier))
            self.assertNotIn("privacy", required_kinds(tier))
        for tier in ("High", "Critical"):
            self.assertIn("legal", required_kinds(tier))
            self.assertIn("privacy", required_kinds(tier))

    def test_unknown_or_missing_tier_requires_nothing(self):
        self.assertEqual(required_kinds(None), ())
        self.assertEqual(required_kinds(""), ())
        self.assertEqual(required_kinds("Imaginary"), ())

    def test_every_label_has_a_kind_and_vice_versa(self):
        all_kinds = {k for kinds in REQUIRED_TASKS.values() for k in kinds}
        self.assertEqual(all_kinds, set(LABELS))

    def test_generate_builds_one_open_task_per_required_kind(self):
        tasks = generate("ven_x", "asm_x", "High")
        self.assertEqual({t["kind"] for t in tasks}, set(required_kinds("High")))
        for t in tasks:
            self.assertEqual(t["vendor_id"], "ven_x")
            self.assertEqual(t["assessment_id"], "asm_x")
            self.assertEqual(t["status"], "open")
            self.assertEqual(t["label"], LABELS[t["kind"]])


class OpenKinds(unittest.TestCase):
    def test_only_open_tasks_are_reported(self):
        tasks = [{"kind": "security", "status": "done"}, {"kind": "it", "status": "open"}]
        self.assertEqual(open_kinds(tasks), ["it"])

    def test_empty_checklist_has_nothing_open(self):
        self.assertEqual(open_kinds([]), [])


class CanComplete(unittest.TestCase):
    def test_only_reviewers_complete_tasks_of_any_kind(self):
        for kind in list(LABELS):
            with self.subTest(kind=kind):
                self.assertTrue(can_complete(get_user("usr_dana"), kind))     # reviewer
                self.assertFalse(can_complete(get_user("usr_sam"), kind))     # admin: no vendor visibility
                self.assertFalse(can_complete(get_user("usr_priya"), kind))   # app_user
                self.assertFalse(can_complete(get_user("usr_jasmine"), kind))  # isso, read-only

    def test_a_reviewer_can_complete_the_department_head_task_too(self):
        # Reviewers record what each function said, including the department head's
        # sign-off; the note names who actually gave it. There's no separate role for it.
        self.assertTrue(can_complete(get_user("usr_dana"), "department_head"))

    def test_permissions_table_grants_exactly_what_can_complete_expects(self):
        # A change to PERMISSIONS that quietly removed task.complete would break every
        # reviewer check above; this pins the grant itself, not just its effect.
        self.assertIn("task.complete", PERMISSIONS["reviewer"])
        self.assertNotIn("task.complete", PERMISSIONS["admin"])
        self.assertNotIn("task.complete", PERMISSIONS["app_user"])
        self.assertNotIn("task.complete", PERMISSIONS["isso"])


if __name__ == "__main__":
    unittest.main()
