"""Tamper-evident audit log (SR-16; NIST 800-53 AU-2, AU-3, AU-9, AU-12).

Each event records who did what, to what, when, and the outcome, and never
document contents, quotes or session tokens. Every event also carries a hash
of the event before it, so changing or deleting any earlier line breaks the
chain and verify() reports where.

Locally the log is a file. In AWS it is written to the audit bucket with
S3 Object Lock, which stops changes in the first place; the hash chain then
proves nothing was altered before it got there.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
FORBIDDEN_DETAIL_KEYS = {"text", "quote", "excerpt", "segments", "token", "password", "content"}


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._lock = threading.Lock()

    def record(self, *, actor: str, role: str, action: str, target: str = "", outcome: str = "success",
               details: dict | None = None) -> dict:
        details = dict(details or {})
        leaked = FORBIDDEN_DETAIL_KEYS & set(details)
        if leaked:
            raise ValueError(f"Audit details must not include document contents or secrets: {sorted(leaked)}")
        with self._lock:
            events = self.read()
            event = {
                "seq": len(events) + 1,
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "actor": actor,
                "role": role,
                "action": action,
                "target": target,
                "outcome": outcome,
                "details": details,
                "prev_hash": events[-1]["hash"] if events else GENESIS,
            }
            event["hash"] = _hash(event)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
            return event

    def read(self) -> list[dict]:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def verify(self) -> dict:
        """Recompute the chain. Reports the first event that doesn't match."""
        previous = GENESIS
        events = self.read()
        for event in events:
            if event.get("prev_hash") != previous or _hash(event) != event.get("hash"):
                return {"intact": False, "events": len(events), "first_bad_seq": event.get("seq")}
            previous = event["hash"]
        return {"intact": True, "events": len(events), "first_bad_seq": None}


def _hash(event: dict) -> str:
    body = {key: value for key, value in event.items() if key != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
