# Cost card: what Counterpart costs to run

**Bottom line:** a typical assessment costs **about 3 cents** on Claude Sonnet 5.5 and **under a fifth of a cent** on Claude Haiku 5.5. A full CAIQ assessed in focused passes costs **about 22 cents** on Sonnet. At 50 vendors a month that's about **$16 on Sonnet, under $1 on Haiku**. With a $20 monthly spend limit, that makes the model choice a cost decision as well as a quality one.

These are **estimates** until the first Bedrock eval run replaces them with measured token counts (`python evals/cost_card.py --from evals/results/<run>.json`).

## Per assessment

Produced by `python evals/cost_card.py`, at Sonnet 5.5 prices of $2.00 per million input tokens and $10.00 per million output tokens:

| Case | Strategy | Model calls | Input tokens | Output tokens | Sonnet 5.5 | Haiku 5.5 |
|---|---|---|---|---|---|---|
| Nimbus Notes AI (sample) | One call | 1 | 3,690 | 2,500 | $0.032 | $0.002 |
| Copperline Backup (sample) | One call | 1 | 2,118 | 2,500 | $0.029 | $0.002 |
| Kestrel Payroll Cloud (sample) | One call | 1 | 3,080 | 2,500 | $0.031 | $0.002 |
| Full CAIQ, every pass at its 24,000-character budget | 12 focused passes | 12 | 84,000 | 4,800 | $0.216 | $0.011 |
| Absolute ceiling, every pass at the 100,000-character hard cap | 12 focused passes | 12 | 312,000 | 4,800 | $0.672 | $0.034 |

## Per month

| Volume | Sonnet 5.5 | Haiku 5.5 |
|---|---|---|
| 50 vendors × 1.5 assessments, all full CAIQs | $16.20 | $0.81 |
| Same, all at the absolute ceiling | $50.40 | $2.52 |

## How the estimate is made

| Input | Value | Where it comes from |
|---|---|---|
| Prompt size | Measured | The prompts Counterpart actually builds for the sample vendors |
| Characters per token | 4 | Common rule of thumb for English text |
| Output tokens | 2,500 per single call; 400 per focused pass | Assumed; the hard cap is 4,096 per call |
| Tool form and system prompt | About 1,000 tokens per call | Estimated from their length |
| Prices | Inputs to the script | See below; **check the Bedrock pricing page before relying on them** |

Price sources used (third-party summaries of Anthropic's announcements, October 2026; not confirmed against AWS directly):

- Claude Sonnet 5.5: $2.00 input and $10.00 output per million tokens ([Apidog summary](https://apidog.com/blog/claude-sonnet-5-5-pricing/)).
- Claude Haiku 5.5 on Bedrock: $0.10 input and $0.50 output per million tokens for requests up to 100,000 input tokens; $0.50 and $2.50 above that ([pi.dev model page](https://pi.dev/models/amazon-bedrock/anthropic-claude-haiku-5-5?name=pi)). Every Counterpart call stays under 100,000 input tokens, so the lower tier applies.

## What this changes

1. **Model choice.** Extraction with quote checking is a narrow task. The plan is to run the eval suite on both models: if Haiku matches Sonnet's accuracy and attack results, Haiku is the default, at about a twentieth of the cost. Quality decides; cost breaks the tie.
2. **Spend controls.** The $20 account limit is the backstop. The per-user and monthly assessment caps (limitation M-2) still need building, and the ceiling row shows why: a runaway loop at the hard cap could spend the month's budget in a few hundred runs (OWASP LLM10, unbounded consumption).
3. **Focused passes cost more than one call** when a document would have fit anyway, which is why "auto" uses a single call whenever it can.
