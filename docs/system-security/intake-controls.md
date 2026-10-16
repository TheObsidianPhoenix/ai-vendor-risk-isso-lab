# Intake Scanner Controls

| | |
|---|---|
| **System** | Counterpart, Meridian Trust Labs (fictional) |
| **Component** | `app/intake/` (becomes the `intake` Lambda function in Milestone 3) |
| **Phase** | 4 |
| **Version** | 1.0, draft for review |
| **Requirements** | SR-07, SR-08, SR-14, SR-16 ([Phase 1 brief](phase-1-requirements-security-brief.md)) |
| **Threats** | TR-06 Malicious file upload, TR-10 Denial of service and cost abuse, AR-02 Indirect prompt injection |

## 1. What it does, in one paragraph

Every file a user uploads is untrusted, because a vendor wrote it. The intake scanner is the checkpoint at trust boundary TB3 ([Phase 2 architecture](../architecture/phase-2-architecture.md), section 4). It either **rejects** the file with a plain reason or **accepts** it and passes on only the **visible text**, labelled with where it came from (`page 9`, `sheet 'Questionnaire' row 12`, `paragraph 4`) so every later AI finding can cite its source. Anything that looks like an attempt to steer the AI is **flagged** for the human reviewer. The scanner never decides anything about the vendor.

```
upload ──► size ──► real file type ──► format checks (in a separate, time-limited process) ──► visible text + flags
             │            │                      │
             └────────────┴──────── reject ──────┘
```

## 2. Controls

Each row reads left to right: the threat, the control, how the code implements it, the test that proves it, and the evidence. Tests are in [`tests/test_intake.py`](../../tests/test_intake.py).

### 2.1 Resource limits (TR-10, AR-08 → SR-14 → NIST 800-53 SC-5)

| Check | Default limit | Implementation | Test |
|---|---|---|---|
| File size | 10 MB | Checked first, before any parsing (`scanner.py`) | `test_oversized_file_is_rejected_before_parsing` |
| PDF pages | 100 | `pdf.py` | `test_too_many_pages` |
| Processing time | 20 seconds | Parsing runs in a separate process that is stopped when time runs out (`run_with_time_limit`). A thread can't be stopped from outside; a process can. | `test_slow_work_is_stopped` |
| Parts inside an Office file | 1,000 | `office.py`, before any library opens the file | `test_too_many_parts` |
| Expanded size of an Office file | 100 MB | Same | `test_total_expanded_size_is_limited` |
| Compression ratio (zip bomb) | 100× per part | Same | `test_zip_bomb_is_rejected_by_ratio` |

All limits live in one place, [`app/intake/limits.py`](../../app/intake/limits.py), so they can be reviewed and changed through a pull request (SR-15). **Why this matters here:** Dependabot found real denial-of-service flaws in the PDF library this project uses (fixed by upgrading to pypdf 6.20.1). Limits mean the next flaw like that costs at most 20 seconds of compute, not an outage.

### 2.2 File type and active content (TR-06 → SR-07 → SI-10)

| Check | Why | Test |
|---|---|---|
| Type comes from the file's own bytes (`%PDF-`, or the parts list inside a zip), never the name | Renaming `malware.exe` to `policy.pdf` changes nothing | `test_unsupported_type` |
| The name must agree with the content | A mismatch is a sign of tampering, and a confusing file for reviewers | `test_name_must_match_content` |
| Only the bare file name is kept | Blocks path tricks such as `../../etc/policy.pdf` | `test_only_the_file_name_is_kept_never_a_path` |
| PDF: JavaScript, automatic actions, launch actions, embedded files → reject | A policy document never needs code | `test_javascript_is_rejected`, `test_embedded_file_is_rejected` |
| PDF: encrypted → reject | Contents can't be checked | `test_encrypted_pdf_is_rejected` |
| Office: macros, embedded objects, ActiveX → reject | The classic way malware arrives in Office files | `test_macro_workbook_is_rejected`, `test_embedded_object_is_rejected` |
| Office: any XML part declaring a DTD → reject | DTDs are how "billion laughs" XML bombs and external-entity (XXE) attacks start; Office files never need one | `test_xml_with_a_dtd_is_rejected` |
| A parser crash → reject, never pass | Hostile input is designed to break parsers | `test_damaged_pdf_is_rejected_not_crashed` |
| No readable text → reject (decision D-04) | Scanned, image-only PDFs aren't supported; rejecting them is better than scoring an empty file | `test_image_only_pdf_is_rejected` |

Order matters: the zip archive is inspected **before** any Office library opens it, so a hostile archive is rejected without ever reaching the parser.

### 2.3 Hidden content and prompt injection (AR-02 → SR-08 → SI-10; OWASP LLM01)

This is where the planted Nimbus Notes AI attack is caught.

| Where it hides | How it's found | What happens |
|---|---|---|
| PDF text drawn in white | The scanner replays the page's drawing instructions and tracks the fill colour in effect when each piece of text is drawn | Flag `hidden_text`; the text is **removed** from what continues |
| PDF text under 4 pt, or in invisible render mode | Same replay tracks font size, scaling and render mode | Same |
| PDF and Office metadata (Title, Subject, Author, Keywords…) | Checked against instruction-like phrases | Flag `metadata_instruction`. Metadata is never passed on as text. |
| Excel hidden sheets, hidden rows and columns, white-font cells | Read from the workbook's formatting | Flag; that content is **excluded** |
| Word hidden runs, white text, text under 4 pt | Read from each run's formatting | Flag; excluded |
| Visible text that reads like an instruction ("ignore previous instructions", "approve this vendor"…) | Pattern list in [`patterns.py`](../../app/intake/patterns.py) | Flag `instruction_like_text`; the text is **kept**, because it is visible to the reviewer too |

**Why visible instructions are kept but hidden ones are removed:** a human reviewer can see visible text, so hiding it from the AI would make the AI and the reviewer disagree about what the document says. Hidden text has no legitimate reader. Either way, the flag goes to the reviewer.

Any of these flags sets `prompt_injection_flagged`. The rules engine records it **without changing the score** ([scoring methodology](../risk-management/scoring-methodology.md), section 5), and the reviewer must see it. The scanner is the first of several layers. The prompt still treats all document text as data (SR-08, Phase 5), and the AI still can't write a decision (SR-12).

**Test result on the planted attack** (`NimbusInjectionIsCaught`): the white text on page 9 and the metadata Subject are both flagged; the sentence "Ignore all previous instructions…" does not appear in the extracted text; the visible canary `CANARY-NIMBUS-7Q2F` does, proving the real content still gets through. The four clean sample files produce no flags.

### 2.4 Integrity and logging (SR-16 → AU-3)

Every result, accepted or rejected, carries the file's SHA-256 hash, so the exact file that was assessed can be proven later. Flag excerpts are capped at 160 characters and are for the reviewer screen only; audit logs record the flag kind and location, never document contents.

## 3. Proving the tests can fail

A test that can't fail proves nothing. Before this was committed, three protections were deliberately broken:

| Protection removed | Tests that failed |
|---|---|
| Removing hidden text from extracted text | `test_hidden_text_never_reaches_the_extracted_text`, `test_tiny_text_is_hidden` |
| Rejecting macros | `test_macro_workbook_is_rejected` |
| Checking the name matches the content | `test_name_must_match_content` |

All 56 tests passed again once the code was restored.

## 4. Known limitations (candidates for the POA&M)

These are stated honestly so a reviewer doesn't assume coverage that isn't there.

| # | Limitation | Risk | Planned response |
|---|---|---|---|
| L-1 | **No malware scanning.** The scanner blocks the common ways documents carry code, but doesn't compare files against known-malware signatures. | A novel exploit against the PDF or Excel library | POA&M item. Option to validate in Milestone 3: Amazon GuardDuty Malware Protection for S3 on the quarantine bucket (cost to confirm first). |
| L-2 | Text inside PDF **form XObjects** (reusable drawing blocks) isn't checked for hidden styling. | Hidden text drawn that way would reach the AI | Detect and flag in a later version. The prompt and output-validation layers still apply. |
| L-3 | Text coloured to match a **coloured background** (for example, dark blue on dark blue) isn't detected. Only white-on-white is. | Same as L-2 | Same as L-2 |
| L-4 | **No OCR.** Text inside images isn't read, so it can't be checked, but it also can't reach the AI. | A scanned page's content is ignored | Accepted by decision D-04; image-only files are rejected outright. |
| L-5 | The instruction pattern list catches common phrasings, not every possible one. | A cleverly worded visible instruction isn't flagged | Expected: patterns are a tripwire, not the main defence. The main defences are SR-08, SR-11 and SR-12. |
| L-6 | **Memory** isn't limited by this code. | A file crafted to use huge memory | Lambda's fixed memory size caps it in Milestone 3; size and expansion limits reduce it now. |

## 5. Framework mapping

| Framework | Reference | Confidence |
|---|---|---|
| NIST SP 800-53 Rev. 5 | SI-10 Information Input Validation; SC-5 Denial-of-Service Protection; AU-3 Content of Audit Records | From the Phase 1 brief |
| NIST SP 800-53 Rev. 5 | SI-3 Malicious Code Protection | Partial (see L-1). Mapping to validate in the control matrix. |
| OWASP Top 10 for LLM Applications 2025 | LLM01 Prompt Injection (indirect); LLM10 Unbounded Consumption | From the Phase 1 brief |
| MITRE ATLAS | LLM Prompt Injection, indirect | Technique ID to validate in the Phase 10 threat model |
| OWASP API Security Top 10 2023 | API4 Unrestricted Resource Consumption | To validate when the API is built |

## 6. Try it yourself

```bash
python scripts/scan_file.py sample-data/nimbus-notes-ai/security-policy-packet.pdf
python -m unittest tests.test_intake -v
```

The first command prints the outcome and each flag; it reports the length of the extracted text, never the text itself.
