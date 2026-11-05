"""Prepare a local Counterpart for a DAST scan (see docs/system-security/dast-local-zap.md).

Run the app first (python3 scripts/run_app.py --reset), then:

    python3 scripts/dast/seed_local.py .dast

Creates a synthetic vendor with documents and an assessment, signs in one
user per role, and writes their IDs and session cookies to .dast/seed.json.
.dast/ is git-ignored: the cookies are local, short-lived and must never be
committed (they're secrets, even in a lab).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.helpers import doc_type_for  # noqa: E402
from tests.test_web import Client  # noqa: E402

BASE = "http://127.0.0.1:8000"


def main(out_dir: Path) -> None:
    out_dir.mkdir(exist_ok=True)
    priya = Client(BASE).sign_in("usr_priya")
    _, body, _ = priya.call("POST", "/api/vendors", {"name": "Nimbus Notes AI", "service": "Notes",
                                                     "data_shared": "Meeting notes", "uses_ai_on_customer_data": True,
                                                     "federal_data_impact": "none"})
    vendor = body["vendor"]["id"]
    for path in sorted((ROOT / "sample-data" / "nimbus-notes-ai").glob("*.*")):
        if path.suffix != ".json":
            priya.call("POST", f"/api/vendors/{vendor}/documents", raw=path.read_bytes(), filename=path.name,
                       doc_type=doc_type_for(path.name))
    _, body, _ = priya.call("POST", f"/api/vendors/{vendor}/assessments", {})
    cookies = {"priya": priya.cookie}
    for name in ("dana", "jasmine", "sam"):
        cookies[name] = Client(BASE).sign_in(f"usr_{name}").cookie
    (out_dir / "seed.json").write_text(json.dumps({"vendor": vendor, "assessment": body["assessment"]["id"],
                                                    "cookies": cookies}))
    print(f"Seeded vendor {vendor}; sessions for {', '.join(cookies)} written to {out_dir / 'seed.json'}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else ".dast"))
