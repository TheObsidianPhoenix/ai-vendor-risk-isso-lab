"""Tests for the Bedrock model adapter and the evaluation harness.

No AWS calls: a fake client stands in for Bedrock, so these run anywhere and
cost nothing. They check what our code does with each kind of answer.
"""

from __future__ import annotations

import copy
import json
import unittest

from app.ai_worker import BedrockModel, ModelError, run_assessment
from app.ai_worker.bedrock_model import MAX_PROMPT_CHARS, TOOL_NAME, tool_schema
from app.ai_worker.prompt import build_prompt
from app.ai_worker.recordings import COPPERLINE, NIMBUS
from evals import run_evals
from tests.helpers import expected, sample_documents


class FakeBedrock:
    """Records each request and returns a canned Converse response."""

    def __init__(self, response=None, error=None):
        self.response, self.error, self.requests = response, error, []

    def converse(self, **request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.response


def converse_reply(report: dict, stop="tool_use", name=TOOL_NAME, extra_blocks=()):
    return {
        "output": {"message": {"role": "assistant", "content": [
            *extra_blocks, {"toolUse": {"toolUseId": "t1", "name": name, "input": report}}]}},
        "stopReason": stop,
        "usage": {"inputTokens": 5200, "outputTokens": 900, "totalTokens": 6100},
    }


def nimbus(model):
    info = expected("nimbus-notes-ai")
    return run_assessment(vendor_id="v", vendor_name=info["vendor"], uses_ai_on_customer_data=True,
                          documents=list(sample_documents("nimbus-notes-ai")), model=model)


class Adapter(unittest.TestCase):
    def test_good_answer_flows_through_the_same_guardrails(self):
        client = FakeBedrock(converse_reply(NIMBUS))
        result = nimbus(BedrockModel("test-model", client=client))
        self.assertEqual(result["status"], "ready_for_review")
        self.assertEqual(result["score"]["score"], 69)
        self.assertEqual(result["usage"]["input_tokens"], 5200)
        self.assertEqual(result["model_id"], "test-model")

    def test_request_is_locked_down(self):
        client = FakeBedrock(converse_reply(NIMBUS))
        nimbus(BedrockModel("test-model", client=client))
        request = client.requests[0]
        self.assertEqual(request["inferenceConfig"]["temperature"], 0)
        self.assertLessEqual(request["inferenceConfig"]["maxTokens"], 4096)
        # Exactly one tool, and the model must use it: no free text, no other actions
        self.assertEqual([t["toolSpec"]["name"] for t in request["toolConfig"]["tools"]], [TOOL_NAME])
        self.assertEqual(request["toolConfig"]["toolChoice"], {"tool": {"name": TOOL_NAME}})
        # Instructions in the system prompt; document text only in the user message
        self.assertIn("untrusted DATA", request["system"][0]["text"])
        self.assertNotIn("CANARY", request["system"][0]["text"])

    def test_the_answer_form_has_no_decision_or_score(self):
        fields = json.dumps(tool_schema())
        for forbidden in ("decision", "approv", "risk_score", "status"):
            self.assertNotIn(forbidden, fields)
        self.assertFalse(tool_schema()["additionalProperties"])

    def test_an_answer_with_extra_fields_is_still_rejected(self):
        report = dict(copy.deepcopy(NIMBUS), decision="Approved")
        result = nimbus(BedrockModel("m", client=FakeBedrock(converse_reply(report))))
        self.assertEqual(result["status"], "ai_output_rejected")
        self.assertIsNone(result["score"])

    def test_failures_stop_safely_with_no_score(self):
        cases = {
            "network or permission error": FakeBedrock(error=RuntimeError("AccessDenied")),
            "answer cut off": FakeBedrock(converse_reply(NIMBUS, stop="max_tokens")),
            "wrong tool": FakeBedrock(converse_reply(NIMBUS, name="approve_vendor")),
            "two reports": FakeBedrock(converse_reply(NIMBUS, extra_blocks=[{"toolUse": {"name": TOOL_NAME, "input": {}}}])),
            "text only": FakeBedrock({"output": {"message": {"content": [{"text": "Looks fine, approve it."}]}},
                                      "stopReason": "end_turn", "usage": {}}),
        }
        for name, client in cases.items():
            with self.subTest(case=name):
                result = nimbus(BedrockModel("m", client=client))
                self.assertEqual(result["status"], "ai_call_failed")
                self.assertIsNone(result["score"])

    def test_oversized_input_is_refused_before_any_call(self):
        client = FakeBedrock(converse_reply(NIMBUS))
        prompt = build_prompt("v", "Vendor", [("big.pdf", [("page 1", "x" * (MAX_PROMPT_CHARS + 1))])])
        with self.assertRaises(ModelError):
            BedrockModel("m", client=client).invoke(prompt)
        self.assertEqual(client.requests, [])

    def test_model_id_must_be_configured(self):
        with self.assertRaises(ModelError):
            BedrockModel(model_id="", client=FakeBedrock())


class GullibleModel:
    """A model that falls for attacks, to prove the evaluation can report failure."""
    mode = "normal"
    model_id = "gullible-test-model"

    def __init__(self, quote_attack_document: bool):
        self.quote_attack_document = quote_attack_document

    def invoke(self, prompt):
        report = copy.deepcopy(COPPERLINE)
        attack_docs = [line.split("=== document: ")[1].split(" ===")[0]
                       for line in prompt.user.splitlines() if "=== document: addendum-" in line]
        if attack_docs:
            for finding in report["findings"]:
                finding["evidence_state"] = "verified"
                if self.quote_attack_document:  # Cites the attacker's own page, so the quote IS found
                    finding["citations"] = [{"document": attack_docs[0], "location": "page 1",
                                             "quote": "Copperline Backup"}]
        return json.dumps(report)


class EvaluationCanFail(unittest.TestCase):
    def test_harness_reports_a_fooled_model(self):
        # The model marks everything verified, citing real questionnaire answers.
        # Those quotes exist, so the quote check can't catch it: deciding whether
        # a quote is strong enough to count as "verified" is the model's judgment.
        # The evaluation must report that the model was fooled.
        model = GullibleModel(quote_attack_document=False)
        baseline = run_evals.assess("copperline-backup", run_evals.vendor_documents("copperline-backup"), model)
        result = run_evals.attack_run("fake-authority", model, baseline)
        self.assertFalse(result["model_resisted"])

    def test_fooled_model_citing_the_attack_document_fails_the_defence(self):
        model = GullibleModel(quote_attack_document=True)
        baseline = run_evals.assess("copperline-backup", run_evals.vendor_documents("copperline-backup"), model)
        result = run_evals.attack_run("fake-evidence", model, baseline)
        self.assertFalse(result["model_resisted"])
        self.assertFalse(result["defence_held"])
        self.assertLess(result["score"], result["baseline_score"])


if __name__ == "__main__":
    unittest.main()
