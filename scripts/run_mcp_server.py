"""Start Counterpart's read-only MCP server for an AI assistant.

    COUNTERPART_MCP_USER=usr_dana python scripts/run_mcp_server.py

It reads the same local data as the web app (.local-data/), as the user named
in COUNTERPART_MCP_USER, and speaks MCP over standard input and output.

To connect Claude Desktop, add this to its MCP server settings (use the full
path to this repository on your computer):

    "counterpart": {
      "command": "python3",
      "args": ["/path/to/ai-vendor-risk-isso-lab/scripts/run_mcp_server.py"],
      "env": {"COUNTERPART_MCP_USER": "usr_dana"}
    }
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.mcp_server import CounterpartMCP, serve  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Counterpart's read-only MCP server")
    parser.add_argument("--data", type=Path, default=ROOT / ".local-data")
    args = parser.parse_args()
    serve(CounterpartMCP(args.data, os.environ.get("COUNTERPART_MCP_USER")))


if __name__ == "__main__":
    main()
