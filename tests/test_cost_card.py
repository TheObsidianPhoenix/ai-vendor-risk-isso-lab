"""The cost card's arithmetic (evals/cost_card.py), so the published figures can be trusted."""

from __future__ import annotations

import unittest

from evals.cost_card import dollars, worst_case
from app.ai_worker.retrieval import CATEGORY_BUDGET_CHARS


class CostCard(unittest.TestCase):
    def test_dollars_per_million_tokens(self):
        self.assertAlmostEqual(dollars({"input_tokens": 1_000_000, "output_tokens": 100_000}, 2.0, 10.0), 3.0)

    def test_full_caiq_worst_case_matches_the_published_card(self):
        row = worst_case("full", CATEGORY_BUDGET_CHARS)
        self.assertEqual((row["calls"], row["input_tokens"], row["output_tokens"]), (12, 84_000, 4_800))
        self.assertAlmostEqual(dollars(row, 2.0, 10.0), 0.216)


if __name__ == "__main__":
    unittest.main()
