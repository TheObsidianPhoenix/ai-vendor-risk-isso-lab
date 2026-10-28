"""Tests for retrieval by control area (focused passes).

Long documents are assessed one control category at a time, with only the
matching sections. These tests prove the change keeps every guardrail: the
same results as one big call, no approval sneaking through a pass, and quotes
accepted only from sections that pass was actually sent.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from app.ai_worker import PretendModel, run_assessment
from app.ai_worker.bedrock_model import MAX_PROMPT_CHARS
from app.ai_worker.retrieval import MAX_PASS_CHARS, select
from app.rules_engine import ruleset
from tests.helpers import VENDORS, expected, sample_documents

SAMPLES = Path(__file__).resolve().parent.parent / "sample-data"


def assess(vendor, model=None, strategy="focused", documents=None):
    info = expected(vendor)
    return run_assessment(vendor_id=vendor, vendor_name=info["vendor"],
                          uses_ai_on_customer_data=info["uses_ai_on_customer_data"],
                          documents=documents if documents is not None else list(sample_documents(vendor)),
                          model=model or PretendModel(), strategy=strategy)


class Recorder:
    """Wraps a model and keeps every prompt it was sent."""

    def __init__(self, inner):
        self.inner, self.prompts = inner, []
        self.model_id, self.mode = inner.model_id, getattr(inner, "mode", "normal")

    def invoke(self, prompt):
        self.prompts.append(prompt)
        return self.inner.invoke(prompt)


class PerPassModel:
    """Returns a hand-written answer for each pass, keyed by its category."""
    model_id = "per-pass"

    def __init__(self, answers):
        self.answers = answers

    def invoke(self, prompt):
        return json.dumps(self.answers.get(prompt.categories[0], {"findings": [], "follow_up_questions": [], "summary": ""}))


def finding(category, state, document, location, quote):
    return {"category": category, "evidence_state": state, "interpretation": "test", "confidence": "high",
            "citations": [{"document": document, "location": location, "quote": quote}]}


class SameAnswersAsOneCall(unittest.TestCase):
    def test_focused_passes_score_every_sample_vendor_the_same(self):
        for vendor in VENDORS:
            with self.subTest(vendor=vendor):
                single, focused = assess(vendor, strategy="single"), assess(vendor, strategy="focused")
                self.assertEqual(focused["status"], "ready_for_review")
                self.assertEqual(focused["score"]["score"], single["score"]["score"])
                self.assertEqual(focused["score"]["classification"], single["score"]["classification"])
                self.assertEqual(focused["citation_problems"], [], "every quote must be in the sections sent")

    def test_red_team_modes_behave_the_same(self):
        for vendor in VENDORS:
            with self.subTest(vendor=vendor):
                self.assertEqual(assess(vendor, PretendModel("approves"))["status"], "ai_output_rejected")
                lying = assess(vendor, PretendModel("fabricates"))
                self.assertGreaterEqual(lying["score"]["score"], assess(vendor)["score"]["score"])


class RetrievalRecall(unittest.TestCase):
    """Every source in the answer keys must be among the sections picked for its category."""

    def test_every_answer_key_source_is_retrieved(self):
        for vendor in VENDORS:
            docs = {d["filename"]: [tuple(s) for s in d["segments"]] for d in sample_documents(vendor)}
            key = json.loads((SAMPLES / vendor / "expected-findings.json").read_text())
            for category, item in key["expected_findings"].items():
                picked = select(category, docs).documents
                for source in item["sources"]:
                    document, where = source.split(" ", 1)
                    sent = picked.get(document, [])
                    page = re.match(r"p(\d+)", where)
                    with self.subTest(vendor=vendor, category=category, source=source):
                        if page:
                            self.assertIn(f"page {page.group(1)}", [loc for loc, _ in sent])
                        else:
                            ids = [text.split(" | ", 1)[0].strip() for _, text in sent]
                            for question in re.findall(r"[A-Z]+-\d+", where):
                                self.assertIn(question, ids)

    def test_question_rows_are_picked_by_id_prefix(self):
        docs = {"caiq.xlsx": [("row 1", "Title"), ("row 2", "Ref"), ("row 3", "Intro"),
                              ("row 4", "IAM-01.1 | Is MFA required? | Yes"),
                              ("row 5", "CEK-03.1 | Is data encrypted at rest? | Yes"),
                              ("row 6", "BCR-01.1 | Is there a continuity plan? | Yes")]}
        picked = [text for _, text in select("encryption", docs).documents["caiq.xlsx"]]
        self.assertIn("CEK-03.1 | Is data encrypted at rest? | Yes", picked)
        self.assertNotIn("BCR-01.1 | Is there a continuity plan? | Yes", picked)


class LongDocuments(unittest.TestCase):
    def long_copperline(self):
        documents = list(sample_documents("copperline-backup"))
        filler = [[f"sheet 'Extra' row {n}", f"ZZZ-{n:03d} | Unrelated guidance text. " + "lorem ipsum " * 50]
                  for n in range(300)]
        documents[0] = dict(documents[0], segments=documents[0]["segments"] + filler)
        return documents

    def test_auto_switches_to_focused_passes_and_stays_under_the_limit(self):
        documents = self.long_copperline()
        model = Recorder(PretendModel())
        result = assess("copperline-backup", model, strategy="auto", documents=documents)
        self.assertEqual(result["strategy"], "focused")
        self.assertEqual(result["status"], "ready_for_review")
        self.assertEqual(result["score"]["score"], expected("copperline-backup")["expected_score"]["score"])
        for prompt in model.prompts:
            self.assertLess(len(prompt.user), MAX_PROMPT_CHARS)
            self.assertEqual(len(prompt.categories), 1)
            self.assertNotIn("ZZZ-", prompt.user, "unrelated sections must not be sent")

    def test_short_documents_still_use_one_call(self):
        model = Recorder(PretendModel())
        result = assess("nimbus-notes-ai", model, strategy="auto")
        self.assertEqual(result["strategy"], "single")
        self.assertEqual(len(model.prompts), 1)

    def test_matching_rows_are_capped_and_the_cap_is_recorded(self):
        rows = [("r1", "Title"), ("r2", "Ref"), ("r3", "Intro")] + [
            (f"r{n}", f"IAM-{n:02d}.1 | " + "x" * 2_000) for n in range(80)]
        chosen = select("identity_access", {"caiq.xlsx": rows})
        self.assertLessEqual(chosen.chars, MAX_PASS_CHARS)
        self.assertTrue(chosen.truncated)


class GuardrailsPerPass(unittest.TestCase):
    def test_vendor_without_ai_gets_no_ai_governance_pass(self):
        model = Recorder(PretendModel())
        assess("copperline-backup", model)
        self.assertNotIn("ai_governance", [p.categories[0] for p in model.prompts])
        self.assertEqual(len(model.prompts), len(ruleset.CATEGORIES) - 1)

    def test_quote_from_a_section_not_sent_in_that_pass_is_not_accepted(self):
        # In the identity pass, cite the retention row DR-01: it's in the document, but wasn't sent
        answers = {"identity_access": {"findings": [finding(
            "identity_access", "unverified", "vendor-questionnaire.xlsx", "DR-01",
            "Customer data is deleted within 30 days of contract end.")], "follow_up_questions": [], "summary": ""}}
        result = assess("copperline-backup", PerPassModel(answers))
        self.assertTrue(any("identity_access" in p and "doesn't exist" in p for p in result["citation_problems"]))
        line = {l["category"]: l for l in result["score"]["lines"]}["identity_access"]
        self.assertEqual(line["scored_state"], "critical_gap", "an unsupported claim counts as missing")

    def test_finding_for_another_category_is_ignored(self):
        answers = {"encryption": {"findings": [finding(
            "privacy", "unverified", "vendor-questionnaire.xlsx", "ENC-01",
            "All backups are encrypted using industry-standard encryption.")], "follow_up_questions": [], "summary": ""}}
        result = assess("copperline-backup", PerPassModel(answers))
        self.assertTrue(any("privacy: reported in the encryption pass" in p for p in result["citation_problems"]))
        self.assertEqual(result["findings"], [])

    def test_one_bad_pass_rejects_the_whole_assessment(self):
        answers = {"privacy": {"findings": [], "follow_up_questions": [], "summary": "", "decision": "Approved"}}
        result = assess("copperline-backup", PerPassModel(answers))
        self.assertEqual(result["status"], "ai_output_rejected")
        self.assertIsNone(result["score"])

    def test_usage_is_summed_across_passes(self):
        class Counting(PretendModel):
            def invoke(self, prompt):
                from app.ai_worker.bedrock_model import Usage
                self.last_usage = Usage(input_tokens=100, output_tokens=10, latency_ms=5)
                return super().invoke(prompt)
        result = assess("copperline-backup", Counting())
        calls = len(ruleset.CATEGORIES) - 1
        self.assertEqual(result["usage"], {"input_tokens": 100 * calls, "output_tokens": 10 * calls,
                                           "latency_ms": 5 * calls, "calls": calls, "stop_reason": ""})


if __name__ == "__main__":
    unittest.main()
