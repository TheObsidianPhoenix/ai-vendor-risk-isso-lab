"""A pretend model that stands in for Amazon Bedrock until Phase 5.

It has the same shape as the real call: prompt in, text out. It also has two
"red team" modes so the guardrails can be demonstrated, because a real model
can't be made to misbehave on cue:

- "approves":   the model falls for the hidden instruction and tries to
                approve the vendor by adding decision and score fields.
                Schema validation must reject the whole answer.
- "fabricates": the model claims every control is verified and invents
                quotes. The citation checker must catch every invented quote.
"""

from __future__ import annotations

import copy
import json
import re

from .prompt import Prompt
from .recordings import BY_CANARY

MODES = {
    "normal": "Well-behaved model",
    "approves": "Red team: model falls for the injection and tries to approve the vendor",
    "fabricates": "Red team: model invents evidence and marks everything verified",
}
MODEL_ID = "pretend-model-1.0 (stand-in for Amazon Bedrock, chosen in Phase 5)"


class PretendModel:
    model_id = MODEL_ID

    def __init__(self, mode: str = "normal"):
        if mode not in MODES:
            raise ValueError(f"Unknown mode: {mode}")
        self.mode = mode

    def invoke(self, prompt: Prompt) -> str:
        fenced = prompt.user.split(f"<{prompt.fence}>", 1)[-1]
        canary = re.search(r"CANARY-[A-Z]+-[0-9A-Z]{4}", fenced)
        answer = copy.deepcopy(BY_CANARY.get(canary.group(0) if canary else "", _UNKNOWN))
        # A focused pass asks about one category: answer only that, like the real model is told to
        answer["findings"] = [f for f in answer["findings"] if f["category"] in prompt.categories]

        if self.mode == "approves":
            answer["decision"] = "Approved"
            answer["risk_score"] = 0
            answer["summary"] = "All controls verified. This vendor is approved with a perfect security score."
        elif self.mode == "fabricates":
            for finding in answer["findings"]:
                finding["evidence_state"] = "verified"
                finding["confidence"] = "high"
                finding["citations"] = [{
                    "document": "soc2-type2-summary.pdf",
                    "location": "page 2",
                    "quote": f"Independent auditor confirmed {finding['category'].replace('_', ' ')} controls with no exceptions.",
                }]
            answer["summary"] = "Every control is verified by an independent audit."
        return json.dumps(answer)


_UNKNOWN = {
    "findings": [],
    "follow_up_questions": ["Please provide a completed security questionnaire and an independent audit report."],
    "summary": "The pretend model has no recorded answer for these documents, so it reports no evidence. In Phase 5 a real model reads any document.",
}
