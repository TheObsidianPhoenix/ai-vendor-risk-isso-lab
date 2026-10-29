"""The real model: Claude on Amazon Bedrock (Phase 5).

Same shape as the pretend model (prompt in, text out), so everything around
it stays the same: the intake scanner, the fenced prompt, strict validation,
quote checking and the rules engine.

Security choices (SR-08, SR-10, SR-12, SR-14, SR-15; OWASP LLM01, LLM06, LLM10):

- No API key. The function's AWS role is allowed to call one model and nothing
  else (Terraform, ai module). There is no secret in code, config or logs.
- The model is given exactly one tool, "report_findings", and is required to
  use it. It can't browse, run code, call other tools or take any action. The
  tool's form has no decision, approval or score field. The tool is a form to
  fill in, not a capability: our code reads the form and then validates it
  with the same strict rules as before (schema.validate is still the authority).
- Hard limits on every call: input size, output tokens, and a timeout.
  No temperature setting: current Claude models reject it ("temperature is
  deprecated for this model"). Repeatability comes from the forced form, strict
  validation and the deterministic rules engine, and the evals measure it.
- The model ID is pinned in configuration, never "latest", so behaviour can't
  change without a reviewed change (SR-15). It's read from the environment.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from app.rules_engine import ruleset

from .prompt import Prompt
from .schema import CITATION_FIELDS, CONFIDENCE, FINDING_FIELDS, MAX_QUESTIONS, MAX_TEXT

TOOL_NAME = "report_findings"
MAX_PROMPT_CHARS = 120_000       # About 30,000 input tokens: caps cost per assessment (SR-14)
MAX_OUTPUT_TOKENS = 4_096
TIMEOUT_SECONDS = 60


class ModelError(Exception):
    """The model call failed or returned nothing usable. The assessment stops safely."""


def tool_schema() -> dict:
    """The only thing the model may produce: a findings report. No decision field exists."""
    text = {"type": "string", "maxLength": MAX_TEXT}
    citation = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(CITATION_FIELDS),
        "properties": {
            "document": {**text, "description": "File name exactly as given"},
            "location": {**text, "description": "'page N' for PDFs, or the question ID such as 'IR-03'"},
            "quote": {**text, "description": "Exact words copied from that location"},
        },
    }
    finding = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(FINDING_FIELDS),
        "properties": {
            "category": {"type": "string", "enum": list(ruleset.CATEGORIES)},
            "evidence_state": {"type": "string", "enum": sorted(ruleset.PROPOSED_STATES)},
            "citations": {"type": "array", "items": citation, "maxItems": 4},
            "interpretation": text,
            "confidence": {"type": "string", "enum": sorted(CONFIDENCE)},
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["findings", "follow_up_questions", "summary"],
        "properties": {
            "findings": {"type": "array", "items": finding, "maxItems": len(ruleset.CATEGORIES)},
            "follow_up_questions": {"type": "array", "items": text, "maxItems": MAX_QUESTIONS},
            "summary": text,
        },
    }


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    stop_reason: str = ""


class BedrockModel:
    mode = "normal"

    def __init__(self, model_id: str | None = None, region: str | None = None, client=None):
        self.model_id = model_id or os.environ.get("COUNTERPART_BEDROCK_MODEL_ID", "")
        if not self.model_id:
            raise ModelError("No Bedrock model ID configured (COUNTERPART_BEDROCK_MODEL_ID)")
        self.region = region or os.environ.get("AWS_REGION", "us-east-2")
        self._client = client
        self.last_usage = Usage()

    def _get_client(self):
        if self._client is None:
            import boto3  # Imported only when the real model is used
            from botocore.config import Config
            self._client = boto3.client(
                "bedrock-runtime", region_name=self.region,
                config=Config(read_timeout=TIMEOUT_SECONDS, connect_timeout=10, retries={"max_attempts": 2}))
        return self._client

    def invoke(self, prompt: Prompt) -> str:
        if len(prompt.user) > MAX_PROMPT_CHARS:
            raise ModelError(f"Documents are too long for one assessment ({len(prompt.user):,} characters; "
                             f"the limit is {MAX_PROMPT_CHARS:,})")
        started = time.monotonic()
        try:
            response = self._get_client().converse(
                modelId=self.model_id,
                system=[{"text": prompt.system}],
                messages=[{"role": "user", "content": [{"text": prompt.user}]}],
                inferenceConfig={"maxTokens": MAX_OUTPUT_TOKENS},
                toolConfig={
                    "tools": [{"toolSpec": {
                        "name": TOOL_NAME,
                        "description": "Report the evidence found in the vendor's documents. This is the only output allowed.",
                        "inputSchema": {"json": tool_schema()},
                    }}],
                    "toolChoice": {"tool": {"name": TOOL_NAME}},
                },
            )
        except Exception as error:  # Network, throttling, permissions: never a pass
            raise ModelError(f"Model call failed ({type(error).__name__})") from None

        usage = response.get("usage", {})
        self.last_usage = Usage(
            input_tokens=int(usage.get("inputTokens", 0)),
            output_tokens=int(usage.get("outputTokens", 0)),
            latency_ms=int((time.monotonic() - started) * 1000),
            stop_reason=str(response.get("stopReason", "")),
        )
        if self.last_usage.stop_reason == "max_tokens":
            raise ModelError("Model answer was cut off at the output limit")

        blocks = response.get("output", {}).get("message", {}).get("content", [])
        reports = [b["toolUse"] for b in blocks if isinstance(b, dict) and "toolUse" in b]
        if len(reports) != 1 or reports[0].get("name") != TOOL_NAME:
            raise ModelError("Model did not return exactly one findings report")
        # Hand the form back as text: schema.validate checks it exactly like any other answer
        return json.dumps(reports[0].get("input"))
