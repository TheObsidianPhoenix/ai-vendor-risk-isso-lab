"""Start Counterpart on this computer.

    python scripts/run_app.py            then open http://127.0.0.1:8000
    python scripts/run_app.py --reset    start again with no vendors

Data is kept in the .local-data/ folder, which git ignores. Synthetic data only.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.web.server import make_server  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Counterpart locally")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data", type=Path, default=ROOT / ".local-data")
    parser.add_argument("--reset", action="store_true", help="delete local data and start empty")
    args = parser.parse_args()
    if args.reset and args.data.exists():
        shutil.rmtree(args.data)
    server = make_server(args.data, port=args.port)
    print(f"Counterpart is running at http://127.0.0.1:{args.port}  (press Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
