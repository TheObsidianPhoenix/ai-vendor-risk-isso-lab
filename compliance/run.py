"""Run the AWS control checks and save the evidence.

    python3 -m compliance.run                    # prints a summary, saves evidence JSON
    python3 -m compliance.run --out evidence/controls

Read-only. Needs AWS credentials for the account (CloudShell has them).
Exit code 0 when every check passes or is an accepted exception; 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from compliance.checks import AWS, run_all

ROOT = Path(__file__).resolve().parent.parent
ACCOUNT = re.compile(r"\b\d{12}\b")
ICON = {"pass": "PASS", "fail": "FAIL", "error": "ERROR", "accepted": "ACCEPTED"}


def mask(value, account_id: str):
    """Mask the AWS account number everywhere in the evidence (redaction rule in evidence/README.md)."""
    text = json.dumps(value)
    text = text.replace(account_id, "*" * 8 + account_id[-4:])
    return json.loads(ACCOUNT.sub(lambda m: "*" * 8 + m.group(0)[-4:], text))


def report(account_id: str, results, now: datetime) -> dict:
    counts = {s: sum(r.status == s for r in results) for s in ICON}
    return mask({"run_at": now.isoformat(timespec="seconds"), "account": account_id,
                 "region": os.environ.get("AWS_REGION", "us-east-2"), "summary": counts,
                 "results": [asdict(r) for r in results]}, account_id)


def summary_text(data: dict) -> str:
    lines = [f"Counterpart AWS control checks: {data['run_at']} (account {data['account']}, {data['region']})", ""]
    for r in data["results"]:
        exc = f"  [{r['exception']['risk']}, review by {r['exception']['review_by']}]" if r.get("exception") else ""
        lines.append(f"{ICON[r['status']]:<9}{r['id']}  {r['title']}")
        lines.append(f"{'':9}      {r['detail']}{exc}")
    s = data["summary"]
    lines += ["", f"{s['pass']} passed, {s['accepted']} accepted exceptions, {s['fail']} failed, {s['error']} couldn't run"]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Counterpart's AWS control checks (read-only)")
    parser.add_argument("--out", type=Path, default=ROOT / "evidence" / "controls")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-2"))
    args = parser.parse_args()
    exceptions = json.loads((ROOT / "compliance" / "exceptions.json").read_text())["exceptions"]
    now = datetime.now(timezone.utc)
    account_id, results = run_all(AWS(args.region), exceptions, now)
    data = report(account_id, results, now)
    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out / f"{now:%Y-%m-%d}_aws_control-checks.json"
    out.write_text(json.dumps(data, indent=2) + "\n")
    print(summary_text(data))
    print(f"\nEvidence saved to {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    return 0 if data["summary"]["fail"] == 0 and data["summary"]["error"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
