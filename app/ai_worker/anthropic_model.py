"""Claude through Anthropic's own API: a temporary test route (decision D-15).

Used while Amazon Bedrock is blocked for this AWS account. Bedrock stays the
production path. This adapter exists so the evaluation suite, and the local
demo, can run against the real model with SYNTHETIC data only.

Same shape and the same guardrails as the Bedrock adapter (SR-08, SR-10,
SR-12, SR-14, SR-15; OWASP LLM01, LLM06, LLM10):

- Exactly one tool, "report_findings", and the model is forced to use it. The
  form (tool_schema, shared with Bedrock) has no decision, approval or score
  field. Our code still validates the answer strictly (schema.validate).
- Hard limits: input size, output tokens, timeout. Temperature 0.
- The model ID is pinned in configuration, never "latest".

Unlike Bedrock this needs an API key, so (SR-10):
- The key is read from the ANTHROPIC_API_KEY environment variable only. It is
  never accepted as an argument from config files, never written anywhere,
  and never included in an error message or log.
- No new dependency: the call uses Python's standard library.
- Set a spend limit on the key's workspace, and delete the key after testing.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from .bedrock_model import MAX_OUTPUT_TOKENS, MAX_PROMPT_CHARS, TIMEOUT_SECONDS, TOOL_NAME, ModelError, Usage, tool_schema
from .prompt import Prompt

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"


def _post(url: str, headers: dict, body: bytes, timeout: int) -> dict:
    """The one network call. Replaced by a fake in tests."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed https URL)
        return json.loads(response.read().decode("utf-8"))


class AnthropicModel:
    mode = "normal"

    def __init__(self, model_id: str | None = None, transport=None):
        self.model_id = model_id or os.environ.get("COUNTERPART_ANTHROPIC_MODEL_ID", "")
        if not self.model_id:
            raise ModelError("No model ID configured (COUNTERPART_ANTHROPIC_MODEL_ID)")
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            raise ModelError("ANTHROPIC_API_KEY is not set in this shell")
        self._post = transport or _post
        self.last_usage = Usage()

    def request_body(self, prompt: Prompt) -> dict:
        return {
            "model": self.model_id,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0,
            "system": prompt.system,
            "messages": [{"role": "user", "content": prompt.user}],
            "tools": [{
                "name": TOOL_NAME,
                "description": "Report the evidence found in the vendor's documents. This is the only output allowed.",
                "input_schema": tool_schema(),
            }],
            "tool_choice": {"type": "tool", "name": TOOL_NAME},
        }

    def invoke(self, prompt: Prompt) -> str:
        if len(prompt.user) > MAX_PROMPT_CHARS:
            raise ModelError(f"Documents are too long for one assessment ({len(prompt.user):,} characters; "
                             f"the limit is {MAX_PROMPT_CHARS:,})")
        headers = {"content-type": "application/json", "anthropic-version": API_VERSION,
                   "x-api-key": os.environ.get("ANTHROPIC_API_KEY", "").strip()}
        started = time.monotonic()
        try:
            response = self._post(API_URL, headers, json.dumps(self.request_body(prompt)).encode("utf-8"),
                                  TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            raise ModelError(f"Model call failed (HTTP {error.code}{_api_error_type(error)})") from None
        except Exception as error:  # Network, timeout: never a pass. No details, so no key can leak
            raise ModelError(f"Model call failed ({type(error).__name__})") from None
        finally:
            headers.clear()

        usage = response.get("usage", {}) if isinstance(response, dict) else {}
        self.last_usage = Usage(
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            latency_ms=int((time.monotonic() - started) * 1000),
            stop_reason=str(response.get("stop_reason", "")) if isinstance(response, dict) else "",
        )
        if self.last_usage.stop_reason == "max_tokens":
            raise ModelError("Model answer was cut off at the output limit")

        blocks = response.get("content", []) if isinstance(response, dict) else []
        reports = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"]
        if len(reports) != 1 or reports[0].get("name") != TOOL_NAME:
            raise ModelError("Model did not return exactly one findings report")
        return json.dumps(reports[0].get("input"))


def _api_error_type(error: urllib.error.HTTPError) -> str:
    """Anthropic's error type (for example 'authentication_error'), never the full body."""
    try:
        kind = json.loads(error.read().decode("utf-8"))["error"]["type"]
    except Exception:
        return ""
    return f", {kind}" if isinstance(kind, str) and kind.replace("_", "").isalpha() and len(kind) < 40 else ""
