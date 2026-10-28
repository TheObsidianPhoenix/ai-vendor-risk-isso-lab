"""Cost card: what one Counterpart assessment costs to run, and what a month costs.

    python evals/cost_card.py                                  # estimate from the sample vendors
    python evals/cost_card.py --from evals/results/X.json      # real token counts from a Bedrock eval run
    python evals/cost_card.py --price-in 2.00 --price-out 10.00 --vendors 50

Two sources of numbers, clearly labeled:
- ESTIMATE: the prompts Counterpart actually builds for the sample vendors are
  measured in characters and converted at about 4 characters per token. Output
  tokens are an assumption per call. This needs no AWS account.
- MEASURED: token counts reported by Bedrock in an eval result file.

Prices are inputs, not facts baked into the code. Check the current Amazon
Bedrock price for the pinned model before relying on any figure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.ai_worker import PretendModel, run_assessment  # noqa: E402
from app.ai_worker.retrieval import CATEGORY_BUDGET_CHARS, MAX_PASS_CHARS  # noqa: E402
from app.rules_engine import ruleset  # noqa: E402
from tests.helpers import VENDORS, expected, sample_documents  # noqa: E402

CHARS_PER_TOKEN = 4              # Common rule of thumb for English text
OUTPUT_TOKENS_SINGLE = 2_500     # Assumed: a full 12-category report
OUTPUT_TOKENS_PER_PASS = 400     # Assumed: one finding plus a short summary
SYSTEM_PROMPT_TOKENS = 300       # Sent with every call
TOOL_SCHEMA_TOKENS = 700         # The report_findings form, sent with every call


class Measuring(PretendModel):
    """The pretend model, also counting the size of every prompt it receives."""

    def __init__(self):
        super().__init__()
        self.calls = []

    def invoke(self, prompt):
        self.calls.append(len(prompt.system) + len(prompt.user))
        return super().invoke(prompt)


def worst_case(name: str, chars_per_pass: int) -> dict:
    """A full CAIQ for an AI vendor: all 12 passes, each filled to the given size."""
    calls = len(ruleset.CATEGORIES)
    per_call = chars_per_pass // CHARS_PER_TOKEN + SYSTEM_PROMPT_TOKENS + TOOL_SCHEMA_TOKENS
    return {"case": name, "strategy": "focused", "calls": calls, "input_tokens": calls * per_call,
            "output_tokens": calls * OUTPUT_TOKENS_PER_PASS, "source": "limit-based estimate"}


def estimate(name: str, vendor: str, documents: list[dict], strategy: str) -> dict:
    model = Measuring()
    info = expected(vendor)
    result = run_assessment(vendor_id=vendor, vendor_name=info["vendor"],
                            uses_ai_on_customer_data=info["uses_ai_on_customer_data"],
                            documents=documents, model=model, strategy=strategy)
    calls = len(model.calls)
    input_tokens = sum(c // CHARS_PER_TOKEN for c in model.calls) + calls * TOOL_SCHEMA_TOKENS
    per_call_out = OUTPUT_TOKENS_SINGLE if result["strategy"] == "single" else OUTPUT_TOKENS_PER_PASS
    return {"case": name, "strategy": result["strategy"], "calls": calls,
            "input_tokens": input_tokens, "output_tokens": calls * per_call_out, "source": "estimate"}


def measured(path: Path) -> list[dict]:
    report = json.loads(path.read_text())
    rows = []
    for run in report["accuracy"]:
        usage = run.get("usage")
        if usage:
            rows.append({"case": run["vendor"], "strategy": report["summary"].get("strategy", "auto"),
                         "calls": usage.get("calls", 1), "input_tokens": usage["input_tokens"],
                         "output_tokens": usage["output_tokens"], "source": f"measured ({report['model']})"})
    return rows


def dollars(row: dict, price_in: float, price_out: float) -> float:
    return row["input_tokens"] / 1e6 * price_in + row["output_tokens"] / 1e6 * price_out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from", dest="source", type=Path, help="eval result JSON with real token counts")
    parser.add_argument("--price-in", type=float, default=2.00, help="USD per million input tokens")
    parser.add_argument("--price-out", type=float, default=10.00, help="USD per million output tokens")
    parser.add_argument("--vendors", type=int, default=50, help="vendors assessed per month")
    parser.add_argument("--per-vendor", type=float, default=1.5,
                        help="assessments per vendor per month (re-runs after new evidence)")
    args = parser.parse_args()

    if args.source:
        rows = measured(args.source)
    else:
        rows = [estimate(v, v, list(sample_documents(v)), "auto") for v in VENDORS]
        rows.append(worst_case("Full CAIQ, typical worst case (every pass at its budget)", CATEGORY_BUDGET_CHARS))
        rows.append(worst_case("Absolute ceiling (every pass at the hard cap)", MAX_PASS_CHARS))

    print(f"## Counterpart cost card\n\nPrices: ${args.price_in:.2f} input / ${args.price_out:.2f} output "
          "per million tokens. Check the current Bedrock price for the pinned model.\n")
    print("| Case | Strategy | Calls | Input tokens | Output tokens | Cost per assessment | Source |")
    print("|---|---|---|---|---|---|---|")
    for row in rows:
        print(f"| {row['case']} | {row['strategy']} | {row['calls']} | {row['input_tokens']:,} | "
              f"{row['output_tokens']:,} | ${dollars(row, args.price_in, args.price_out):.4f} | {row['source']} |")
    typical = [r for r in rows if not r["case"].startswith("Absolute")]
    worst = max(dollars(r, args.price_in, args.price_out) for r in typical)
    ceiling = max(dollars(r, args.price_in, args.price_out) for r in rows)
    runs = args.vendors * args.per_vendor
    print(f"\nMonthly at {args.vendors} vendors x {args.per_vendor} assessments each: "
          f"**${worst * runs:.2f}** if every one is a full CAIQ; **${ceiling * runs:.2f}** at the absolute ceiling.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
