"""Run the intake scanner on one file and print what it found.

Usage:
    python scripts/scan_file.py sample-data/nimbus-notes-ai/security-policy-packet.pdf

Prints the outcome, every flag, and where each piece of extracted text came
from. Extracted text itself is not printed, only its length, the same rule
the application follows for logs (SR-16: no document contents in logs).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.intake import scan_file  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    path = Path(sys.argv[1])
    result = scan_file(path.read_bytes(), path.name)
    print(f"File:      {result.filename}")
    print(f"SHA-256:   {result.sha256}")
    print(f"Type:      {result.file_type or 'unknown'}")
    print(f"Outcome:   {result.status.upper()}" + (f" - {result.rejection_reason}" if result.rejection_reason else ""))
    print(f"Possible prompt injection: {'YES' if result.prompt_injection_flagged else 'no'}")
    for flag in result.flags:
        print(f"  FLAG {flag.kind} at {flag.location}: {flag.detail}")
        if flag.excerpt:
            print(f"       \"{flag.excerpt}\"")
    if result.segments:
        print(f"Text passed on: {len(result.segments)} sections, {sum(len(s.text) for s in result.segments):,} characters")
    return 0 if result.status == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
