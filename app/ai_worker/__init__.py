"""AI extraction: build the prompt, call the model, and distrust what comes back.

The model reads, the code scores, and a person decides. This package is the
"model reads" part. It has no access to the decision service: nothing here
imports app.decision, and a test enforces that (SR-12, OWASP LLM06).
"""

from .pipeline import run_assessment
from .pretend_model import MODES, PretendModel

__all__ = ["MODES", "PretendModel", "run_assessment"]
