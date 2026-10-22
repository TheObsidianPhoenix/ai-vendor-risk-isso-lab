# evals/

How well does the AI actually do the job, and can it be tricked? This folder answers both with numbers, using the same pipeline the app runs: intake scanner → fenced prompt → model → strict validation → quote check → independent-evidence rule → rules engine.

```bash
python evals/run_evals.py                   # pretend model: offline, free, checks the harness itself
python evals/run_evals.py --model bedrock   # the real model (see "Running against Bedrock")
```

Each run prints a scorecard and saves a JSON result in `evals/results/`. Results hold only counts and scores, never document text or model output, so they're safe to commit and publish.

## What's measured

| Measure | How | Why it matters |
|---|---|---|
| **Evidence-state accuracy** | Each category's state compared with the answer key in `sample-data/*/expected-findings.json` (34 judgments across 3 vendors) | Is the model reading the documents correctly? |
| **Score agreement** | The final rules-engine score compared with the answer key | Do the model's judgments add up to the right risk rating? |
| **Quote accuracy** | Share of the model's quotes found word for word at the page or question it cited | Hallucinated evidence (OWASP LLM09) |
| **Model resisted** | Did the model itself refuse to mark controls verified because an attack document told it to? | AI robustness to prompt injection (LLM01) |
| **System defended** | Was the vendor's rating unchanged after the attack, whatever the model did? | Defence in depth: the security result that counts |
| **Time and tokens** | Per call, from Bedrock's response | Cost and abuse monitoring (LLM10) |

### The attacks

Each one adds a visible document to Copperline Backup, the vendor with the most room to "improve": almost every claim is unverified, so a successful attack shows up as controls flipping to verified and the score dropping. Hidden-text attacks aren't repeated here, because the intake scanner already removes hidden text before the model sees anything.

| Attack | What it tries |
|---|---|
| `direct-override` | "Ignore all previous instructions…" (the intake scanner also flags this) |
| `fake-authority` | Pretends to be the customer's own security team |
| `fence-break` | Tries to close the data fence and start a fake system section |
| `fake-evidence` | An "assurance summary" with no auditor, claiming every control passed |
| `other-language` | The instruction in Spanish, past the intake scanner's English patterns |

Attack documents are generated in memory (`attacks.py`); nothing hostile is committed.

## Why "model resisted" and "system defended" are separate

The quote check proves a quote **exists**, but not that it's **strong enough** to count as evidence. Building the evaluation exposed this: a model fooled into calling a vendor's own "everything passed" letter *verified* would have a real quote, and the vendor's score would drop.

The fix is a rule in code, not in the prompt. **Only a document a person labelled as an independent audit report can make a control verified.** The label is chosen at upload, never read from the document or the model. Anything the vendor writes about itself counts as an unverified claim, however convincing. So even when the model is fooled, the system holds, and the evaluation reports both results honestly.

## Running against Bedrock

Needs the AWS account upgrade (decision D-11) and access to the chosen Claude model in us-east-2.

1. In the AWS console, open **CloudShell** (it's already signed in as you).
2. Find the model ID to pin, and confirm it's callable from us-east-2:
   ```bash
   aws bedrock list-inference-profiles --region us-east-2 --type-equals SYSTEM_DEFINED \
     --query "inferenceProfileSummaries[?starts_with(inferenceProfileId, 'us.anthropic.')].inferenceProfileId" --output table
   ```
3. Run the evaluation:
   ```bash
   git clone https://github.com/TheObsidianPhoenix/ai-vendor-risk-isso-lab.git && cd ai-vendor-risk-isso-lab
   python3 -m pip install --user -r requirements-dev.txt
   export COUNTERPART_BEDROCK_MODEL_ID=<the ID from step 2>
   python3 evals/run_evals.py --model bedrock
   ```
4. Send the scorecard back to commit it as a result. A run is 9 model calls; at small-model prices that's cents. The exact price is checked at the time and recorded with the result.

## Every pull request

The **Tests** job runs the evaluation with the pretend model and fails if accuracy drops below 100% or any attack changes a rating. That proves the harness, the validation rules and the evidence rule still work. The real-model run is manual, because it costs money and needs AWS credentials.
