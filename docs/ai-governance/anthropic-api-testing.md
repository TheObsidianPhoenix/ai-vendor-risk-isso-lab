# Testing through Anthropic's API (decision D-15)

**Decided 2026-10-29, Jasmine Alexander (system owner).** While Amazon Bedrock is blocked for this AWS account (a support case is open), the evaluation suite and the local demo may call Claude through **Anthropic's own API**. This is temporary. Bedrock stays the production path.

## Why

Bedrock returns *AccessDenied: not available for this account* for Anthropic models, even though the model agreement, entitlement and region all show available, and Amazon Nova is throttled on its first call. It's an account-level restriction that only AWS Support can lift. Real-model results shouldn't wait on that.

## The rules

| Rule | Why |
|---|---|
| **Synthetic data only.** The three fictional vendors and the five attack documents. No real CAIQs, even public ones | Anthropic's API is outside the AWS authorization boundary. D-12 keeps real CAIQs local |
| **The key lives only in an environment variable** (`ANTHROPIC_API_KEY`) in the shell doing the run. Never in the repo, a file, a chat or a log | SR-10. GitHub secret scanning with push protection is the backstop |
| **Prepaid credit with a spend limit** ($5) on the key's workspace | Caps the cost of a leaked key or a runaway loop (SR-14) |
| **Delete the key when testing ends**, or when Bedrock works | No standing secret |
| **Same guardrails as Bedrock.** One forced tool with no decision field, strict validation, quote checks, input and output limits, pinned model ID | The route changes, the controls don't |

## How the guardrails are proven

`tests/test_anthropic_model.py` (10 tests, no network, fake key) checks that:

- the request has exactly one tool, forced, with no temperature setting (current models reject it), with the document text outside the system prompt
- an answer with a `decision` field is rejected
- errors, timeouts, cut-off answers, wrong tools and plain-text answers all stop with **no score**
- the key never appears in an error, a result or the model object
- the red team modes never call the real model

The adapter (`app/ai_worker/anthropic_model.py`) uses only Python's standard library, so it adds no dependency.

## Residual risk

| Risk | Treatment |
|---|---|
| Key leaked from the shell | Spend limit, short lifetime, delete after use. Accepted for a test run |
| Synthetic test data processed by a third party | Accepted: it's fictional. By default, Anthropic doesn't train on API data |
| A new third party (Anthropic) not in the AWS boundary | Recorded here and in the agent register (AG-01). Counterpart's own vendor-risk process would apply before any real data |
| Results differ slightly from Bedrock | Same model family. Each result file records the model ID, and the README says which provider produced it |

## Running it (CloudShell)

```bash
export COUNTERPART_ANTHROPIC_MODEL_ID=claude-sonnet-5-5
read -rs ANTHROPIC_API_KEY && export ANTHROPIC_API_KEY
python3 evals/run_evals.py --model anthropic --strategy single
unset ANTHROPIC_API_KEY
```

`read -rs` takes the key without showing it on screen or saving it in the shell history.
