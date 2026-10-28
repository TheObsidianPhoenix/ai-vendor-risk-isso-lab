# Retrieval by control area

**Problem.** A full CAIQ v4 is far longer than the 120,000-character limit Counterpart allows for one model call (a cost cap, SR-14). A long document would simply fail: "Documents are too long."

**Fix.** When a vendor's documents don't fit in one call, Counterpart runs **one focused pass per control area**. Each pass sends only the sections about that area, picked by `app/ai_worker/retrieval.py`:

1. **Question IDs:** a row whose ID starts with the area's code is always sent (`IAM-` identity, `CEK-` encryption, `SEF-` incidents, `TVM-` vulnerabilities, and so on, using CAIQ v4 domain codes).
2. **Keywords:** other sections are ranked by how many of the area's keywords they contain, and added best first up to about 24,000 characters.
3. **Context:** the first rows or page of each document (title and reference) are always sent.

Short documents still go in one call, so nothing changes for them.

## Why keywords, not embeddings

| | Keyword and ID matching (chosen) | Embeddings and a vector database |
|---|---|---|
| Repeatable | Same input, same sections, every time | Can shift with the embedding model |
| Explainable | "Row IAM-01.2 was sent because its ID starts with IAM" | A similarity score |
| Extra services | None | A vector store and an embedding call |
| Data leaving the boundary | None | Every section is sent to an embedding model |
| Weakness | Misses a section that uses none of the expected words | Better at paraphrases |

The weakness is measured, not assumed: the evals check **retrieval recall**, meaning whether every source named in the answer keys is among the sections picked for its area. It's 100% on the sample vendors, and CI fails if it drops.

## What stays the same

| Guardrail | In focused mode |
|---|---|
| The AI can't approve or score | Every pass uses the same report form with no decision field. **One bad pass rejects the whole assessment** |
| Quotes must be real | A quote only counts if it's found in a section **that pass was actually sent** |
| Independent evidence | Unchanged: only a person-labeled audit report can verify |
| A failed call | Stops the whole assessment. A missing pass would otherwise look like missing evidence |
| Cost cap | Each pass stays under the per-call limit; total tokens and the number of calls are recorded |
| Scope | A finding for a different area than the pass asked about is ignored and noted |

AI governance gets a pass only when the vendor uses AI on customer data, matching the rules engine.

## Proof

- `tests/test_retrieval.py`: 12 tests. Focused and single-call modes give the same scores for every sample vendor; red-team modes behave the same; every answer-key source is retrieved; a 300-row padded questionnaire switches to focused passes, stays under the limit, and sends none of the unrelated rows; a quote from a section not sent is rejected; one bad pass rejects everything.
- **Sabotage checks:** checking quotes against all sections, keeping findings from the wrong pass, and removing ID matching each made tests fail (1, 1 and 24 failures).
- CI runs the evals twice, single-call and focused, each requiring 100% accuracy, all attacks defended and 100% recall.

## Cost

More calls, but each is smaller. See the [cost card](../ai-governance/cost-card.md).
