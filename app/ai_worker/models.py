"""Choose which model an assessment uses.

COUNTERPART_MODEL_PROVIDER=pretend   (default) the recorded stand-in; works offline
COUNTERPART_MODEL_PROVIDER=bedrock   Claude on Amazon Bedrock; needs AWS credentials
                                     and COUNTERPART_BEDROCK_MODEL_ID
COUNTERPART_MODEL_PROVIDER=anthropic Claude through Anthropic's API (D-15: testing with
                                     synthetic data only, while Bedrock is blocked); needs
                                     ANTHROPIC_API_KEY and COUNTERPART_ANTHROPIC_MODEL_ID

The red team modes always use the pretend model: a real model can't be made to
misbehave on cue. The real model is attacked by the evaluation suite instead
(evals/), with documents written to trick it.
"""

from __future__ import annotations

import os

from .anthropic_model import AnthropicModel
from .bedrock_model import BedrockModel
from .pretend_model import PretendModel

PROVIDERS = ("pretend", "bedrock", "anthropic")


def provider() -> str:
    name = os.environ.get("COUNTERPART_MODEL_PROVIDER", "pretend").strip().lower()
    if name not in PROVIDERS:
        raise ValueError(f"COUNTERPART_MODEL_PROVIDER must be one of {', '.join(PROVIDERS)}")
    return name


def make_model(mode: str = "normal"):
    if mode != "normal" or provider() == "pretend":
        return PretendModel(mode)
    return AnthropicModel() if provider() == "anthropic" else BedrockModel()
