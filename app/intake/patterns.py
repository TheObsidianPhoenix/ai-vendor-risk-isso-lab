"""Text that reads like instructions to an AI rather than vendor evidence.

A match is a flag for the reviewer, not proof of an attack, and never a reason
to change a score. The list is deliberately small and easy to review; it will
miss rephrased attacks, which is why the prompt also fences document text as
data and the output schema can't carry a decision (defense in depth).
"""

from __future__ import annotations

import re

INSTRUCTION_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\b(ignore|disregard|forget)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|directions|rules|prompts?)",
    r"\b(system|assistant|developer)\s+(note|prompt|message|instruction)s?\b",
    r"\bnote\s+to\s+(the\s+)?(ai|assistant|model|reviewer)\b",
    r"\byou\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|language\s+model|chatbot)\b",
    r"\b(mark|rate|classify|score|set|treat)\s+(this|the)\s+vendor\s+(as\s+)?(approved|low[- ]risk|safe|trusted|verified)",
    r"\bapprove\s+this\s+vendor\b",
    r"\bperfect\s+(security\s+)?score\b",
    r"\bclassify\s+(every|all)\s+controls?\s+as\s+verified\b",
    r"\bdo\s+not\s+(flag|report|mention)\b",
))


def instruction_like(text: str) -> str | None:
    """Return the matching phrase if the text reads like an instruction to an AI."""
    for pattern in INSTRUCTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None
