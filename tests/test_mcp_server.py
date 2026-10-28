"""Tests for the read-only MCP server (agent register AG-02).

What must hold: an AI assistant connected through MCP can only read; it sees
exactly what the signed-in user could see in the web app; vendor text is
labeled untrusted; nothing it does can approve, reject or change anything.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from app.ai_worker import PretendModel, run_assessment
from app.common.audit import AuditLog
from app.common.auth import Session, get_user
from app.common.store import Store
from app.decision import record_decision
from app.mcp_server import CounterpartMCP, serve
from tests.helpers import expected, sample_documents

ROOT = Path(__file__).resolve().parent.parent
SERVER_SOURCE = (ROOT / "app" / "mcp_server" / "server.py").read_text()


def names_used(source: str) -> set[str]:
    """Every name, attribute and import in the code itself (docstrings and comments don't count)."""
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            found.update(alias.name for alias in node.names)
            found.add(getattr(node, "module", "") or "")
    return found
WRITE_WORDS = re.compile(r"decide|decision|approve|reject|record|upload|delete|create|update|run|set|send|assess",
                         re.IGNORECASE)


class MCPServer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        store, audit = Store(self.root), AuditLog(self.root / "audit.jsonl")
        self.vendors = {}
        for sample, owner in (("copperline-backup", "usr_priya"), ("kestrel-payroll-cloud", "usr_omar")):
            info = expected(sample)
            vendor = store.create_vendor(name=info["vendor"], service="s", data_shared="d",
                                         uses_ai_on_customer_data=info["uses_ai_on_customer_data"],
                                         owner_id=owner, owner_name=owner)
            for doc in sample_documents(sample):
                store.add_document(vendor["id"], None, filename=doc["filename"], sha256=doc["sha256"],
                                   doc_type=doc["doc_type"], status="accepted", flags=doc["flags"],
                                   segments=doc["segments"], uploaded_by=owner, uploaded_by_name=owner,
                                   size_bytes=1, file_type="pdf")
            record = run_assessment(vendor_id=vendor["id"], vendor_name=vendor["name"],
                                    uses_ai_on_customer_data=vendor["uses_ai_on_customer_data"],
                                    documents=store.list_documents(vendor["id"]), model=PretendModel())
            self.vendors[sample] = vendor
            self.assessment = store.add_assessment(record, started_by=owner, started_by_name=owner)
        self.store, self.audit_log = store, audit

    def tearDown(self):
        self.tmp.cleanup()

    def server(self, user="usr_dana"):
        return CounterpartMCP(self.root, user)

    def call(self, server, name, **arguments):
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": name, "arguments": arguments}})
        return response["result"]

    def fingerprint(self):
        files = sorted(p for p in self.root.rglob("*") if p.is_file() and p.name != "audit.jsonl")
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}

    # ----- protocol ---------------------------------------------------------------
    def test_handshake(self):
        response = self.server().handle({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                                         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                    "clientInfo": {"name": "test", "version": "1"}}})
        result = response["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertIn("tools", result["capabilities"])
        self.assertIn("untrusted_vendor_text", result["instructions"])
        self.assertIsNone(self.server().handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_unknown_method_and_bad_messages(self):
        server = self.server()
        self.assertEqual(server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/delete"})["error"]["code"], -32601)
        self.assertEqual(server.handle({"id": 3, "method": "ping"})["error"]["code"], -32600)
        self.assertEqual(server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                        "params": {"name": "record_decision"}})["error"]["code"], -32602)

    # ----- read-only, by construction ------------------------------------------------
    def test_only_read_only_tools_exist(self):
        tools = self.server().handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertEqual(names, {"list_vendors", "get_vendor_status", "get_findings", "get_follow_up_questions"})
        for tool in tools:
            with self.subTest(tool=tool["name"]):
                self.assertTrue(tool["annotations"]["readOnlyHint"])
                self.assertFalse(tool["annotations"]["destructiveHint"])
                self.assertIsNone(WRITE_WORDS.search(tool["name"].replace("get_", "").replace("list_", "")))

    def test_server_never_imports_or_calls_a_write(self):
        used = names_used(SERVER_SOURCE)
        for forbidden in ("record_decision", "create_vendor", "add_document", "add_assessment",
                          "append_decision", "purge_expired", "settings", "_put", "_write", "unlink"):
            with self.subTest(name=forbidden):
                self.assertNotIn(forbidden, used)

    def test_calls_change_no_records(self):
        before = self.fingerprint()
        server = self.server()
        for vendor in self.vendors.values():
            for tool in ("get_vendor_status", "get_findings", "get_follow_up_questions"):
                self.call(server, tool, vendor_id=vendor["id"])
        self.call(server, "list_vendors")
        self.assertEqual(self.fingerprint(), before)

    # ----- same permissions as the web app ------------------------------------------
    def test_requester_sees_only_their_own_vendors(self):
        server = self.server("usr_priya")
        listed = self.call(server, "list_vendors")["structuredContent"]["vendors"]
        self.assertEqual([v["name"] for v in listed], ["Copperline Backup"])
        other = self.call(server, "get_findings", vendor_id=self.vendors["kestrel-payroll-cloud"]["id"])
        missing = self.call(server, "get_findings", vendor_id="ven_000000000000")
        self.assertTrue(other["isError"])
        self.assertEqual(other["structuredContent"], missing["structuredContent"], "no way to probe other IDs")
        events = [e for e in self.audit_log.read() if e["action"] == "mcp.read"]
        self.assertEqual([e["outcome"] for e in events], ["success", "denied", "error"])

    def test_unknown_user_gets_nothing(self):
        result = self.call(CounterpartMCP(self.root, "usr_nobody"), "list_vendors")
        self.assertTrue(result["isError"])
        self.assertNotIn("vendors", result["structuredContent"])

    def test_role_without_vendor_access_is_denied(self):
        result = self.call(self.server("usr_sam"), "list_vendors")   # Administrator: no vendor access
        self.assertTrue(result["isError"])

    def test_bad_arguments_are_refused(self):
        server = self.server()
        self.assertTrue(self.call(server, "get_findings", vendor_id="../../etc/passwd")["isError"])
        self.assertTrue(self.call(server, "get_findings", vendor_id=self.vendors["copperline-backup"]["id"],
                                  extra="x")["isError"])

    # ----- what comes back ---------------------------------------------------------
    def test_vendor_text_is_labeled_untrusted_and_document_bodies_never_leave(self):
        vendor = self.vendors["copperline-backup"]
        result = self.call(self.server(), "get_findings", vendor_id=vendor["id"])["structuredContent"]
        self.assertEqual(result["classification"], "Critical")
        retention = next(f for f in result["findings"] if f["category"] == "data_retention")
        self.assertTrue(retention["untrusted_vendor_text"]["quotes"])
        text = json.dumps(result)
        self.assertNotIn("FICTIONAL DOCUMENT", text, "document text beyond the quotes must not be returned")
        self.assertNotIn("segments", text)

    def test_status_shows_a_human_decision(self):
        vendor = self.vendors["kestrel-payroll-cloud"]
        record_decision(store=self.store, audit=self.audit_log, session=Session(get_user("usr_dana"), time.time()),
                        assessment_id=self.store.latest_assessment(vendor["id"])["id"], decision="Approved",
                        rationale="Reviewed the SOC 2 evidence; every control verified.", evidence_confirmed=True,
                        conditions="")
        status = self.call(self.server(), "get_vendor_status", vendor_id=vendor["id"])["structuredContent"]
        self.assertEqual((status["status"], status["decided_by_a_person"], status["decision_by"]),
                         ("Approved", True, "Dana Whitfield"))

    # ----- over standard input/output, as a real client connects ------------------------
    def test_stdio_session(self):
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_vendors", "arguments": {}}},
        ]
        stdin = "\n".join(json.dumps(line) for line in lines) + "\nnot json\n"
        process = subprocess.run([sys.executable, str(ROOT / "scripts" / "run_mcp_server.py"), "--data", str(self.root)],
                                 input=stdin, capture_output=True, text=True, timeout=30,
                                 env=dict(os.environ, COUNTERPART_MCP_USER="usr_dana"))
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual([r.get("id") for r in responses], [1, 2, 3, None])
        self.assertEqual(len(responses[2]["result"]["structuredContent"]["vendors"]), 2)
        self.assertEqual(responses[3]["error"]["code"], -32700)

    def test_serve_writes_one_line_per_response(self):
        out = io.StringIO()
        serve(self.server(), io.StringIO('{"jsonrpc":"2.0","id":9,"method":"ping"}\n\n'), out)
        self.assertEqual(out.getvalue().splitlines(), ['{"jsonrpc": "2.0", "id": 9, "result": {}}'])


if __name__ == "__main__":
    unittest.main()
