"""Tests for data retention (Phase 2, section 8): records expire, active vendors don't.

A fake clock jumps forward in time, so three years pass in milliseconds.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.common.store import Store

DAY = 86400


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now

    def advance(self, days: float):
        self.now += days * DAY


class Retention(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.store = Store(Path(self.tmp.name), retention_days=30, clock=self.clock)
        self.vendor = self.store.create_vendor(name="Test", owner_id="usr_priya")
        self.document = self.store.add_document(self.vendor["id"], b"%PDF-1.7 synthetic", sha256="abc123", status="accepted")
        self.file = Path(self.tmp.name, "files", self.vendor["id"], "abc123")
        self.store.add_assessment({"vendor_id": self.vendor["id"], "status": "ready_for_review"})
        self.store.append_decision({"vendor_id": self.vendor["id"], "assessment_id": "asm_x", "stage": "final"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_record_carries_an_expiry_date(self):
        for record in (self.store.get_vendor(self.vendor["id"]), self.document,
                       self.store.latest_assessment(self.vendor["id"]), self.store.list_decisions()[0]):
            self.assertEqual(record["expires_at"], int(self.clock.now) + 30 * DAY)

    def test_nothing_is_removed_before_the_retention_date(self):
        self.clock.advance(29)
        self.assertEqual(sum(self.store.purge_expired().values()), 0)
        self.assertTrue(self.file.exists())

    def test_everything_for_an_expired_vendor_is_removed_including_files(self):
        self.clock.advance(31)
        removed = self.store.purge_expired()
        self.assertEqual(removed, {"vendors": 1, "documents": 1, "assessments": 1, "decisions": 1, "files": 1})
        self.assertIsNone(self.store.get_vendor(self.vendor["id"]))
        self.assertEqual(self.store.list_decisions(), [])
        self.assertFalse(self.file.exists())

    def test_activity_keeps_a_vendor_alive(self):
        self.clock.advance(25)
        self.store.add_assessment({"vendor_id": self.vendor["id"], "status": "ready_for_review"})
        self.clock.advance(10)  # 35 days after creation, 10 after the latest activity
        removed = self.store.purge_expired()
        self.assertIsNotNone(self.store.get_vendor(self.vendor["id"]))
        self.assertEqual(removed["vendors"], 0)
        # The old records still expire on their own dates; the new assessment stays
        self.assertEqual(removed["assessments"], 1)
        self.assertEqual(len(self.store.list_assessments(self.vendor["id"])), 1)


if __name__ == "__main__":
    unittest.main()
