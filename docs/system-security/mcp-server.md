# Counterpart MCP server (read-only)

Lets an AI assistant (Claude Desktop, or any client that speaks the Model Context Protocol) ask Counterpart questions in plain language: "Which vendors are waiting on a decision?", "Why is Copperline Critical?", "Draft the evidence request for Nimbus." The assistant reads Counterpart's records; it can't change them.

Run it locally:

```bash
COUNTERPART_MCP_USER=usr_dana python3 scripts/run_mcp_server.py
```

The launcher's docstring shows the Claude Desktop configuration. Registered as **AG-02** in the [agent register](../ai-governance/agent-register.md), Tier 2.

## Tools

| Tool | Returns |
|---|---|
| `list_vendors` | Vendors the user can see, with status and rating |
| `get_vendor_status` | Status, whether a person decided it, who and when, latest rating |
| `get_findings` | Each control area's evidence state and points, and the verified quotes behind it |
| `get_follow_up_questions` | The drafted questions for requesting missing evidence |

All four are marked read-only in the MCP tool annotations.

## Security design

| Risk | Control | Proof (`tests/test_mcp_server.py`) |
|---|---|---|
| An assistant approves or changes a vendor | A fixed list of four read-only tools. The module never references a write: no `record_decision`, no store write methods | The tool list is checked exactly; the code is scanned for write calls; record files are fingerprinted before and after every call |
| An assistant sees more than the user could | Runs as one signed-in user and uses the web app's own permission checks, including vendor ownership | A requester sees only their own vendor; an administrator sees none; an unknown user gets nothing |
| Probing for other vendors' IDs | "Not found" and "not yours" give the identical answer; IDs must match the exact ID format | Compared directly in the test |
| Indirect prompt injection through the assistant | Quotes, interpretations and follow-up questions trace back to vendor documents, so they're returned under `untrusted_vendor_text`, and the server's instructions tell the assistant to treat them as data | The label is checked in the test |
| Data leakage | Only findings and short verified quotes leave; never a document's extracted text | The test checks that no other document text appears |
| No record of who asked | Every call writes an `mcp.read` audit event (user, tool, vendor, outcome; no content) | Success, denied and error outcomes are checked |

**Sabotage checks:** adding a decision tool, removing the ownership check, and dropping the untrusted label each made tests fail.

## Design choices

- **The protocol is implemented directly** (JSON-RPC 2.0 over standard input and output: `initialize`, `ping`, `tools/list`, `tools/call`) instead of through an SDK. That's about 200 lines with no new dependencies, so nothing new enters the supply chain. The trade-off is maintaining protocol changes by hand; the official Python SDK is the alternative if the server grows.
- **Local only for now.** Over standard input and output, the server runs on the user's own machine with that user's identity. A hosted version would use MCP's HTTP transport with OAuth tokens issued by Cognito, the same sign-in the web app will use.
- **No write tools, deliberately.** Adding one (record a decision, send a vendor request) would make this Tier 3 in the register and need human approval of each action.
