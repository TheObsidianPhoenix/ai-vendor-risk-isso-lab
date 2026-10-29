# Agent register and risk tiers

Every AI agent in production gets one entry: who owns it, what data it touches, what it can do, and how risky that is. The tier decides how much review it needs before going live, so low-risk agents ship fast and high-risk ones get a closer look.

## Risk tiers

Answer the intake questions below. **The highest tier triggered wins.**

| Tier | Triggered when the agent... | Review before production | Ongoing |
|---|---|---|---|
| **1: Low** | Uses public or internal data only; is read-only; a person reads every output before using it | Owner completes this entry; peer check of the prompt and data sources | Owner reviews every 12 months |
| **2: Moderate** | Reads confidential data; **or** its output informs a decision about a person, customer or supplier; **or** it writes to an internal system | Security review; an evaluation set with pass/fail results; spend cap set | Evals re-run on every change; review every 6 months |
| **3: High** | Reads regulated or client data (personal data, client systems, financial records); **or** it takes actions outside the company (sends email, changes records in another system); **or** it can act without a person approving each action | Security **and** Privacy/Legal review; red-team testing (prompt injection, data leakage); human approval of each external action | Evals on every change; review every 3 months; incident runbook |
| **Not allowed** | Makes a final decision about a person, customer, supplier or money with no human approval; holds long-lived secrets; sends company data to a tool not approved by Security | No | |

### Intake questions

1. What problem does it solve, and how will we measure success (the baseline)?
2. Who owns it, and who is the business sponsor?
3. What data does it read? Classify each source: public, internal, confidential, regulated.
4. Where does that data go? Which model, which region, and is it stored or used for training?
5. What can it write or change? List every tool or connector and whether it's read or write.
6. Does it act outside the company (email, tickets in a customer's system, payments)?
7. Does a person approve each output or action before it takes effect?
8. What's the worst realistic failure (wrong answer, leaked data, manipulated by a document)?
9. How is it tested (evaluation set, red-team cases), and what's the pass bar?
10. What does it cost to run per use and per month, and what's the spend cap?

## Register

| ID | Agent | Owner | Purpose | Data it reads | What it can do | Human control | Model | Tier | Status |
|---|---|---|---|---|---|---|---|---|---|
| AG-01 | Counterpart assessment worker | Jasmine Alexander | Extracts security evidence from vendor documents, with quotes, for a human reviewer | Vendor security documents (confidential); synthetic only under the current authorization | Fills in one findings form. No other tools, no browsing, no writes | A named reviewer makes every decision; Critical approvals need two reviewers | Claude on Amazon Bedrock, pinned model ID (Anthropic's API for synthetic-data tests while Bedrock is blocked, D-15) | **2** | Built; local and test only |
| AG-02 | Counterpart MCP server | Jasmine Alexander | Lets an AI assistant (Claude, a Teams agent) look up vendor status, findings and follow-up questions | Counterpart's records: vendors, assessments, decisions | Read-only lookups. No decision, upload or delete tools | The assistant can only read; decisions stay in Counterpart | Whichever assistant connects (it's a server, not a model) | **2** | Built; local only |

### AG-01 in detail: Counterpart assessment worker

| Field | Entry |
|---|---|
| Why Tier 2 | Reads confidential vendor documents, and its output informs a supplier decision. Not Tier 3: it takes no action and can't decide; a person decides every vendor |
| Would become Tier 3 if | It processed client data, emailed vendors itself, or could change a vendor's status |
| Success measure | Review time per vendor against a manual baseline (to be measured); accuracy against answer keys (100% on the sample set) |
| Data residency | AWS us-east-2. The pinned Bedrock model ID must be a US inference profile (`us.` prefix), which keeps processing in US regions; a `global.` profile could process anywhere. EU customers would need an EU profile and region, plus a GDPR lawful basis, before any EU personal data is used |
| Retention | Records expire 3 years after last activity; the model call is not stored by the app |
| Guardrails | Intake scanner; fenced prompt; one forced tool with no decision field; strict validation; quote check; independent-evidence rule; deterministic scoring |
| Tests and evals | Unit tests plus the eval harness (accuracy, quote verification, 5 injection attacks, retrieval recall), run in CI on every change |
| Cost | About $0.03 per typical assessment and $0.22 per full CAIQ on Sonnet 5.5 ([cost card](cost-card.md)); $20 monthly account limit |
| Known gaps | No per-user assessment cap yet (M-2); no malware scanning (D-07); not yet run on the real model |
| Next review | 2027-01-21 |

### AG-02 in detail: Counterpart MCP server

| Field | Entry |
|---|---|
| Why Tier 2 | Exposes confidential vendor findings to an AI assistant. Not Tier 3: read-only, no external actions |
| Would become Tier 3 if | Any write tool were added (record a decision, upload, send a request) |
| Access control | Runs locally over standard input/output for one signed-in user; every tool checks that user's role, as the web app does |
| Guardrails | A fixed list of read-only tools, tested so no decision or write tool can appear; vendor document text is never returned, only findings and quotes |
| Tests | `tests/test_mcp_server.py` |
| Next review | 2027-01-21 |

## Blank entry (copy for a new agent)

| Field | Entry |
|---|---|
| ID and name | |
| Owner and business sponsor | |
| Problem and success measure (baseline) | |
| Data it reads, with classification | |
| Where data goes (model, region, stored or trained on) | |
| Tools and connectors (read or write) | |
| Actions outside the company | |
| Human control | |
| Tier, and why | |
| What would raise the tier | |
| Tests and pass bar | |
| Cost per use, per month, spend cap | |
| Known gaps | |
| Next review | |
