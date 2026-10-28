"""Read-only MCP server for AI assistants (see server.py)."""

from .server import CounterpartMCP, serve

__all__ = ["CounterpartMCP", "serve"]
