"""Local storage that mirrors the AWS design (Phase 2 architecture, section 7).

| Here (local)                  | In AWS (Milestone 3)                         |
|-------------------------------|----------------------------------------------|
| vendors.json, documents.json  | DynamoDB `vendors` table                     |
| assessments.json              | DynamoDB `assessments` table                 |
| decisions.jsonl (append-only) | DynamoDB `decisions` table, no update/delete |
| files/<vendor>/<sha256>       | S3 `documents` bucket, encrypted with KMS    |

Decisions are stored apart from assessments and can only be appended: this
class has no method that changes or deletes a decision (HR-01, no overwrites).
Rejected uploads are never stored, only a record that they were rejected.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"  # Random, so IDs can't be guessed or enumerated


class Store:
    TABLES = ("vendors", "documents", "assessments")

    def __init__(self, root: Path):
        self.root = Path(root)
        (self.root / "files").mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        for table in self.TABLES:
            path = self.root / f"{table}.json"
            if not path.exists():
                self._write(path, {})
        (self.root / "decisions.jsonl").touch(exist_ok=True)

    # ----- generic table access -------------------------------------------------
    def _path(self, table: str) -> Path:
        return self.root / f"{table}.json"

    def _write(self, path: Path, data) -> None:
        # Write to a temp file, then rename: a crash never leaves a half-written table
        fd, tmp = tempfile.mkstemp(dir=self.root, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=1)
        os.replace(tmp, path)

    def _all(self, table: str) -> dict:
        with self._lock:
            return json.loads(self._path(table).read_text(encoding="utf-8"))

    def _put(self, table: str, item: dict) -> dict:
        with self._lock:
            data = self._all(table)
            data[item["id"]] = item
            self._write(self._path(table), data)
            return item

    # ----- vendors ---------------------------------------------------------------
    def create_vendor(self, **fields) -> dict:
        return self._put("vendors", dict(fields, id=new_id("ven"), created_at=now()))

    def get_vendor(self, vendor_id: str) -> dict | None:
        return self._all("vendors").get(vendor_id)

    def list_vendors(self) -> list[dict]:
        return sorted(self._all("vendors").values(), key=lambda v: v["created_at"])

    # ----- documents -------------------------------------------------------------
    def add_document(self, vendor_id: str, data: bytes | None, **fields) -> dict:
        item = dict(fields, id=new_id("doc"), vendor_id=vendor_id, uploaded_at=now())
        if data is not None:  # Only accepted files are kept
            folder = self.root / "files" / vendor_id
            folder.mkdir(parents=True, exist_ok=True)
            (folder / fields["sha256"]).write_bytes(data)
        return self._put("documents", item)

    def list_documents(self, vendor_id: str) -> list[dict]:
        return sorted((d for d in self._all("documents").values() if d["vendor_id"] == vendor_id),
                      key=lambda d: d["uploaded_at"])

    # ----- assessments -----------------------------------------------------------
    def add_assessment(self, record: dict, **fields) -> dict:
        version = len(self.list_assessments(record["vendor_id"])) + 1
        return self._put("assessments", dict(record, **fields, id=new_id("asm"), version=version, created_at=now()))

    def get_assessment(self, assessment_id: str) -> dict | None:
        return self._all("assessments").get(assessment_id)

    def list_assessments(self, vendor_id: str) -> list[dict]:
        return sorted((a for a in self._all("assessments").values() if a["vendor_id"] == vendor_id),
                      key=lambda a: a["version"])

    def latest_assessment(self, vendor_id: str) -> dict | None:
        items = self.list_assessments(vendor_id)
        return items[-1] if items else None

    # ----- decisions: append-only ------------------------------------------------
    def append_decision(self, record: dict) -> dict:
        item = dict(record, id=new_id("dec"), recorded_at=now())
        with self._lock, (self.root / "decisions.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, sort_keys=True) + "\n")
        return item

    def list_decisions(self, vendor_id: str | None = None) -> list[dict]:
        with self._lock:
            lines = (self.root / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
        items = [json.loads(line) for line in lines if line.strip()]
        return [d for d in items if vendor_id is None or d["vendor_id"] == vendor_id]
