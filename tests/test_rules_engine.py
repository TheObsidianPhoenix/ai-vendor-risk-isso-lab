"""Tests for the deterministic rules engine.

Each test names the requirement it proves (from the Phase 1 brief), so a
passing run is evidence that the control works.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import dataclasses
import json
import random
import unittest
from pathlib import Path

from app.rules_engine import Finding, InvalidFindings, RULE_SET_VERSION, score
from app.rules_engine import ruleset

ROOT = Path(__file__).resolve().parent.parent
ANSWER_KEYS = sorted((ROOT / "sample-data").glob("*/expected-findings.json"))


def findings_from_answer_key(key: dict) -> list[Finding]:
    return [Finding(category, item["state"], tuple(item["sources"])) for category, item in key["expected_findings"].items()]


def all_verified(**overrides: str) -> list[Finding]:
    """A clean vendor: every category verified with a citation, except any overrides."""
    states = {category: "verified" for category in ruleset.CATEGORIES}
    states.update(overrides)
    return [Finding(category, state, ("test-doc.pdf p1",)) for category, state in states.items()]


class AnswerKeyTests(unittest.TestCase):
    """The engine must reproduce the expected result for every fictional vendor."""

    def test_answer_keys_exist(self):
        self.assertEqual(len(ANSWER_KEYS), 3)

    def test_each_vendor_scores_as_expected(self):
        for path in ANSWER_KEYS:
            key = json.loads(path.read_text())
            expected = key["expected_score"]
            with self.subTest(vendor=key["vendor"]):
                result = score(findings_from_answer_key(key),
                               uses_ai_on_customer_data=key["uses_ai_on_customer_data"],
                               prompt_injection_flagged=expected["prompt_injection_flagged"])
                self.assertEqual(result.rule_set_version, expected["rule_set"])
                self.assertEqual(result.score, expected["score"])
                self.assertEqual(result.classification, expected["classification"])


class DeterminismTests(unittest.TestCase):
    """Same evidence in, same result out, every time (Phase 1: transparent scoring)."""

    def test_same_input_same_result(self):
        findings = all_verified(encryption="unverified", incident_response="conflict")
        first = score(findings, uses_ai_on_customer_data=True)
        for _ in range(20):
            self.assertEqual(score(findings, uses_ai_on_customer_data=True), first)

    def test_order_of_findings_does_not_matter(self):
        findings = all_verified(encryption="unverified", data_retention="absent")
        expected = score(findings, uses_ai_on_customer_data=True)
        shuffled = findings[:]
        random.Random(7).shuffle(shuffled)
        self.assertEqual(score(shuffled, uses_ai_on_customer_data=True), expected)


class EvidenceTests(unittest.TestCase):

    def test_claimed_encryption_without_evidence_is_not_verified(self):
        """Phase 1 test scenario 'Missing Evidence' (SR-13): a claim is not a verified control."""
        result = score(all_verified(encryption="unverified"), uses_ai_on_customer_data=False)
        line = next(l for l in result.lines if l.category == "encryption")
        self.assertEqual(line.scored_state, "unverified")
        self.assertEqual(line.points, ruleset.POINTS["unverified"])

    def test_finding_without_citation_counts_as_absent(self):
        """SR-13: the model must point to the source, or the finding doesn't count."""
        findings = [f if f.category != "secure_development" else Finding("secure_development", "verified", ())
                    for f in all_verified()]
        line = next(l for l in score(findings, uses_ai_on_customer_data=False).lines if l.category == "secure_development")
        self.assertEqual(line.scored_state, "absent")

    def test_uncited_verified_critical_control_becomes_critical_gap(self):
        findings = [f if f.category != "identity_access" else Finding("identity_access", "verified", ())
                    for f in all_verified()]
        result = score(findings, uses_ai_on_customer_data=False)
        line = next(l for l in result.lines if l.category == "identity_access")
        self.assertEqual(line.scored_state, "critical_gap")
        self.assertEqual(result.classification, "High")

    def test_missing_category_counts_as_absent(self):
        """A model can't lower a score by leaving a category out."""
        findings = [f for f in all_verified() if f.category != "vulnerability_management"]
        result = score(findings, uses_ai_on_customer_data=False)
        line = next(l for l in result.lines if l.category == "vulnerability_management")
        self.assertEqual((line.proposed_state, line.scored_state), ("missing", "absent"))
        self.assertEqual(result.score, ruleset.POINTS["absent"])


class CriticalControlTests(unittest.TestCase):

    def test_one_critical_gap_sets_at_least_high(self):
        result = score(all_verified(incident_response="absent"), uses_ai_on_customer_data=False)
        self.assertEqual(result.score, 25)
        self.assertEqual(result.classification, "High")
        self.assertIsNotNone(result.floor_rule_applied)

    def test_two_critical_gaps_set_critical(self):
        result = score(all_verified(identity_access="absent", encryption="contradicted"), uses_ai_on_customer_data=False)
        self.assertEqual(result.score, 50)
        self.assertEqual(result.classification, "Critical")

    def test_contradicted_standard_control_scores_as_absent(self):
        result = score(all_verified(data_retention="contradicted"), uses_ai_on_customer_data=False)
        line = next(l for l in result.lines if l.category == "data_retention")
        self.assertEqual(line.scored_state, "absent")

    def test_score_is_capped(self):
        findings = [Finding(c, "absent") for c in ruleset.CATEGORIES]
        result = score(findings, uses_ai_on_customer_data=True)
        self.assertEqual(result.score, ruleset.MAX_SCORE)
        self.assertEqual(result.classification, "Critical")


class AiGovernanceApplicabilityTests(unittest.TestCase):

    def test_ai_governance_scored_when_vendor_uses_ai(self):
        result = score(all_verified(ai_governance="contradicted"), uses_ai_on_customer_data=True)
        self.assertEqual(result.score, 25)

    def test_ai_governance_ignored_when_vendor_record_says_no_ai(self):
        """Applicability comes from the vendor record a person entered, not from the documents."""
        result = score(all_verified(ai_governance="contradicted"), uses_ai_on_customer_data=False)
        self.assertEqual(result.score, 0)
        self.assertNotIn("ai_governance", [l.category for l in result.lines])
        self.assertTrue(any("not applicable" in n for n in result.notes))


class FailClosedTests(unittest.TestCase):
    """SR-11: unexpected input stops scoring instead of being guessed at."""

    def test_unknown_category_rejected(self):
        with self.assertRaises(InvalidFindings):
            score([Finding("vendor_is_trustworthy", "verified", ("x",))], uses_ai_on_customer_data=False)

    def test_unknown_state_rejected(self):
        with self.assertRaises(InvalidFindings):
            score([Finding("encryption", "approved", ("x",))], uses_ai_on_customer_data=False)

    def test_duplicate_category_rejected(self):
        """Stops a manipulated response from adding a second, better finding for the same control."""
        with self.assertRaises(InvalidFindings):
            score([Finding("encryption", "absent"), Finding("encryption", "verified", ("x",))],
                  uses_ai_on_customer_data=False)


class HumanDecisionTests(unittest.TestCase):
    """HR-01 and SR-12: the engine advises; it has no way to decide."""

    def test_result_has_no_decision_field(self):
        names = {f.name for f in dataclasses.fields(score(all_verified(), uses_ai_on_customer_data=False))}
        for forbidden in ("decision", "approved", "status", "final_status", "approval"):
            self.assertNotIn(forbidden, names)

    def test_every_result_requires_human_review(self):
        for findings in (all_verified(), all_verified(encryption="absent")):
            self.assertTrue(score(findings, uses_ai_on_customer_data=False).requires_human_review)


class PromptInjectionTests(unittest.TestCase):

    def test_injection_flag_does_not_change_the_score(self):
        """Phase 1 test scenario 'Prompt Injection': the score is never lowered or raised by the flag."""
        findings = all_verified(encryption="unverified")
        clean = score(findings, uses_ai_on_customer_data=False)
        flagged = score(findings, uses_ai_on_customer_data=False, prompt_injection_flagged=True)
        self.assertEqual(flagged.score, clean.score)
        self.assertEqual(flagged.classification, clean.classification)
        self.assertTrue(flagged.prompt_injection_flagged)

    def test_injected_perfect_score_claim_cannot_produce_a_perfect_score(self):
        """Even if injected text made the model report everything verified with no evidence, uncited claims count as absent."""
        findings = [Finding(c, "verified") for c in ruleset.CATEGORIES]  # no citations
        result = score(findings, uses_ai_on_customer_data=True, prompt_injection_flagged=True)
        self.assertEqual(result.classification, "Critical")
        self.assertNotEqual(result.score, 0)


class VersionTests(unittest.TestCase):

    def test_result_records_rule_set_version(self):
        self.assertEqual(score(all_verified(), uses_ai_on_customer_data=False).rule_set_version, RULE_SET_VERSION)


if __name__ == "__main__":
    unittest.main()
