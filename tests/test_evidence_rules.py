"""The two evidence rules, decided by the label a person gave each document.

Rule 1: only an independent audit report can make a control 'verified'.
Rule 2 (finding EV-01): a document labelled "other" can't count as evidence,
so it can't turn a blank answer into a claim and lower a vendor's score.
"""

from __future__ import annotations

import unittest

from app.ai_worker.pipeline import require_independent_evidence
from app.ai_worker.schema import CheckedCitation, CheckedFinding

TYPES = {"soc2.pdf": "audit_report", "q.xlsx": "questionnaire", "policy.pdf": "policy", "addendum.pdf": "other"}


def finding(state, *documents, category="encryption"):
    citations = tuple(CheckedCitation(document=d, location="page 1", quote="x", verified=True) for d in documents)
    return CheckedFinding(category=category, evidence_state=state, citations=citations,
                          interpretation="", confidence="high")


def scored(state, *documents):
    findings, problems = require_independent_evidence([finding(state, *documents)], TYPES)
    return findings[0].proposed_state, problems


class EvidenceRules(unittest.TestCase):
    def test_verified_needs_an_audit_report(self):
        self.assertEqual(scored("verified", "soc2.pdf")[0], "verified")
        self.assertEqual(scored("verified", "q.xlsx")[0], "unverified")

    def test_vendor_claims_count_from_questionnaires_and_policies(self):
        for document in ("q.xlsx", "policy.pdf", "soc2.pdf"):
            with self.subTest(document=document):
                self.assertEqual(scored("unverified", document)[0], "unverified")

    def test_other_documents_cannot_turn_a_blank_into_a_claim(self):
        for state in ("verified", "unverified", "conflict"):
            with self.subTest(state=state):
                result, problems = scored(state, "addendum.pdf")
                self.assertEqual(result, "absent")
                self.assertIn("labelled 'other'", problems[-1])

    def test_an_unlabelled_document_is_treated_as_other(self):
        self.assertEqual(scored("unverified", "unknown.pdf")[0], "absent")

    def test_other_documents_alongside_real_evidence_are_fine(self):
        self.assertEqual(scored("unverified", "addendum.pdf", "q.xlsx")[0], "unverified")

    def test_bad_news_from_other_documents_still_counts(self):
        # Rule 2 only blocks states that LOWER a score; a contradiction makes it worse
        self.assertEqual(scored("contradicted", "addendum.pdf")[0], "contradicted")


if __name__ == "__main__":
    unittest.main()
