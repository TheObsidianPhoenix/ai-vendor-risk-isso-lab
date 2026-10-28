# Testing with real vendor documents (decision D-12)

**Decided 2026-10-25, Jasmine Alexander (system owner).** Counterpart may be tested with **public** documents that real companies publish on the [CSA STAR Registry](https://cloudsecurityalliance.org/star/registry), under the rules below. Everything committed to this repository stays synthetic.

## Why

The three synthetic vendors prove the controls work against problems I planted. They can't show how the app handles documents written by real security teams: real formatting, real length, real ways of answering. Public CAIQs are the safest real-world source, because the companies chose to publish them.

## Rules

| Rule | Reason |
|---|---|
| **Public documents only.** Nothing behind an NDA or a login I'd have to misrepresent myself to get | A portfolio project has no business relationship that would justify NDA documents |
| **Files are kept outside this repository** (`~/counterpart-real-tests/`) and are never committed | The repo is public, and the documents are the companies' work |
| **Local testing only** until a second authorization allows real data in AWS | The AWS deployment is authorized for synthetic data only |
| **Per-company results stay private.** Only totals are published (for example, "7 of 8 CAIQs accepted at intake") | A prototype's score is not a fair public rating of a real company |
| **Every Level 1 CAIQ is labeled `questionnaire`** at upload | It's a self-assessment, so it can't independently verify anything |
| **Expectations are written before each run** (the test worksheet) | Grading results against expectations written afterwards isn't a test |
| **Files are deleted when testing ends**, and the registry's terms of use are respected | Keep only what's needed, for as long as it's needed |

## The test set

Nine Level 1 CAIQs (spreadsheets), chosen to cover different industries:

| Industry | Companies |
|---|---|
| Cloud infrastructure | Amazon (AWS) |
| Observability | Datadog |
| Networking and security | Cisco |
| Collaboration and developer tools | Atlassian (Jira, Confluence) |
| Creative and marketing software | Adobe |
| Banking | GTBank |
| Application security | Aikido Security |
| AI security operations | Andesite |
| Legal technology (eDiscovery) | Everlaw |

## What to expect

- **No Level 1 vendor can score Low.** With only self-attested answers, the best possible result is **High: 66 points**, or **72** when the vendor uses AI on customer data. Any critical control left blank adds 25 points and usually makes it Critical. This is the independent-evidence rule working as designed, and under decision option D such a vendor would be sent an evidence request rather than rated as if its evidence were bad.
- **Intake may flag or reject some files.** Real CAIQs can contain hidden sheets, hidden columns or formulas. Each flag or rejection is recorded as a finding about the scanner's false-positive rate.
- **Full CAIQs exceed the 120,000-character limit** for one AI call, so they're assessed one control area at a time ([retrieval by control area](../system-security/retrieval-by-control-area.md)). Record in the worksheet how many passes each one took and whether any pass hit the size cap.
- **The local pretend model can't assess real companies.** It only knows the synthetic vendors. Real results need the Bedrock model.
