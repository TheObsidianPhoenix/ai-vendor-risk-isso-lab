"""Tests for the Anthropic API adapter (decision D-15).

No network calls and no real key: a fake transport stands in for the API.
They check that this route has exactly the guardrails the Bedrock route has,
and that the key never appears in an error.
"""

from __future__ import annotations

import copy
import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from app.ai_worker import AnthropicModel, ModelError, make_model, run_assessment
from app.ai_worker.bedrock_model import MAX_PROMPT_CHARS, TOOL_NAME
from app.ai_worker.prompt import build_prompt
from app.ai_worker.recordings import NIMBUS
from tests.helpers import expected, sample_documents

FAKE_KEY = "sk-ant-test-NOT-A-REAL-KEY-0000"


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def __call__(self, url, headers, body, timeout):
        self.calls.append({"url": url, "headers": dict(headers), "body": json.loads(body), "timeout": timeout})
        if self.error:
            raise self.error
        return self.response


def reply(report, stop="tool_use", name=TOOL_NAME, extra=()):
    return {"content": [*extra, {"type": "tool_use", "id": "t1", "name": name, "input": report}],
            "stop_reason": stop, "usage": {"input_tokens": 5200, "output_tokens": 900}}


def nimbus(model):
    info = expected("nimbus-notes-ai")
    return run_assessment(vendor_id="v", vendor_name=info["vendor"], uses_ai_on_customer_data=True,
                          documents=list(sample_documents("nimbus-notes-ai")), model=model)


@mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": FAKE_KEY})
class Adapter(unittest.TestCase):
    def test_good_answer_flows_through_the_same_guardrails(self):
        result = nimbus(AnthropicModel("claude-test", transport=FakeTransport(reply(NIMBUS))))
        self.assertEqual(result["status"], "ready_for_review")
        self.assertEqual(result["score"]["score"], 69)
        self.assertEqual(result["usage"]["input_tokens"], 5200)
        self.assertEqual(result["model_id"], "claude-test")

    def test_request_is_locked_down(self):
        transport = FakeTransport(reply(NIMBUS))
        nimbus(AnthropicModel("claude-test", transport=transport))
        call = transport.calls[0]
        body = call["body"]
        self.assertEqual(call["url"], "https://api.anthropic.com/v1/messages")
        self.assertNotIn("temperature", body)  # Current models reject it
        self.assertLessEqual(body["max_tokens"], 4096)
        self.assertEqual([t["name"] for t in body["tools"]], [TOOL_NAME])
        self.assertEqual(body["tool_choice"], {"type": "auto"})  # Forced choice is refused; text answers fail below
        self.assertIn("report_findings tool", body["system"])
        self.assertIn("untrusted DATA", body["system"])
        self.assertNotIn("CANARY", body["system"])
        self.assertLessEqual(call["timeout"], 60)
        # The key goes in the header only, never in the body the model sees
        self.assertEqual(call["headers"]["x-api-key"], FAKE_KEY)
        self.assertNotIn(FAKE_KEY, json.dumps(body))

    def test_the_answer_form_has_no_decision_or_score(self):
        schema = json.dumps(AnthropicModel("m", transport=FakeTransport()).request_body(
            build_prompt("v", "Vendor", [("a.pdf", [("page 1", "text")])]))["tools"])
        for forbidden in ("decision", "approv", "risk_score", "status"):
            self.assertNotIn(forbidden, schema)

    def test_an_answer_with_extra_fields_is_still_rejected(self):
        report = dict(copy.deepcopy(NIMBUS), decision="Approved")
        result = nimbus(AnthropicModel("m", transport=FakeTransport(reply(report))))
        self.assertEqual(result["status"], "ai_output_rejected")
        self.assertIsNone(result["score"])

    def test_failures_stop_safely_with_no_score_and_never_show_the_key(self):
        denied = urllib.error.HTTPError("https://api.anthropic.com/v1/messages", 401, "Unauthorized", {},
                                        io.BytesIO(json.dumps({"error": {"type": "authentication_error",
                                                                         "message": f"bad key {FAKE_KEY}"}}).encode()))
        cases = {
            "bad key": FakeTransport(error=denied),
            "network": FakeTransport(error=TimeoutError(f"timed out with {FAKE_KEY}")),
            "answer cut off": FakeTransport(reply(NIMBUS, stop="max_tokens")),
            "wrong tool": FakeTransport(reply(NIMBUS, name="approve_vendor")),
            "two reports": FakeTransport(reply(NIMBUS, extra=[{"type": "tool_use", "name": TOOL_NAME, "input": {}}])),
            "text only": FakeTransport({"content": [{"type": "text", "text": "Approve it."}], "stop_reason": "end_turn"}),
        }
        for name, transport in cases.items():
            with self.subTest(case=name):
                result = nimbus(AnthropicModel("m", transport=transport))
                self.assertEqual(result["status"], "ai_call_failed")
                self.assertIsNone(result["score"])
                self.assertNotIn(FAKE_KEY, json.dumps(result))
        result = nimbus(AnthropicModel("m", transport=FakeTransport(error=urllib.error.HTTPError(
            "u", 401, "x", {}, io.BytesIO(b'{"error": {"type": "authentication_error"}}')))))
        self.assertIn("authentication_error", json.dumps(result))
        result = nimbus(AnthropicModel("m", transport=FakeTransport(error=urllib.error.HTTPError(
            "u", 400, "x", {}, io.BytesIO(json.dumps({"error": {"type": "invalid_request_error",
                                                                 "message": "temperature is deprecated"}}).encode())))))
        self.assertIn("temperature is deprecated", json.dumps(result))

    def test_oversized_input_is_refused_before_any_call(self):
        transport = FakeTransport(reply(NIMBUS))
        prompt = build_prompt("v", "Vendor", [("big.pdf", [("page 1", "x" * (MAX_PROMPT_CHARS + 1))])])
        with self.assertRaises(ModelError):
            AnthropicModel("m", transport=transport).invoke(prompt)
        self.assertEqual(transport.calls, [])

    def test_model_id_must_be_configured(self):
        with mock.patch.dict(os.environ, {"COUNTERPART_ANTHROPIC_MODEL_ID": ""}):
            with self.assertRaises(ModelError):
                AnthropicModel(transport=FakeTransport())

    def test_provider_setting_picks_this_adapter_but_red_team_modes_never_do(self):
        env = {"COUNTERPART_MODEL_PROVIDER": "anthropic", "COUNTERPART_ANTHROPIC_MODEL_ID": "claude-test"}
        with mock.patch.dict(os.environ, env):
            self.assertIsInstance(make_model("normal"), AnthropicModel)
            self.assertNotIsInstance(make_model("approves"), AnthropicModel)


class KeyHandling(unittest.TestCase):
    def test_no_key_means_no_model(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            with self.assertRaisesRegex(ModelError, "ANTHROPIC_API_KEY is not set"):
                AnthropicModel("m", transport=FakeTransport())

    def test_the_key_is_not_kept_on_the_object(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": FAKE_KEY}):
            model = AnthropicModel("m", transport=FakeTransport(reply(NIMBUS)))
            model.invoke(build_prompt("v", "Vendor", [("a.pdf", [("page 1", "text")])]))
            self.assertNotIn(FAKE_KEY, repr(vars(model)))


if __name__ == "__main__":
    unittest.main()
