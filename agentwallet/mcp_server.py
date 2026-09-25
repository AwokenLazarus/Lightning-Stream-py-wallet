"""MCP surface. Talks only to the signer socket. No RPC, no keys.

The tool list is fixed: balance, quote_payment, pay, history.
approve and recover_vault are intentionally absent — a model cannot
self-approve. Humans use the out-of-band agentwallet-approve CLI.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .sanitize import assert_no_key_material, sanitize
from .signer import SignerClient

# Exact MCP surface. Tests assert this set.
MCP_TOOL_NAMES = frozenset({"balance", "quote_payment", "pay", "history"})
FORBIDDEN_MCP_TOOLS = frozenset({"approve", "recover_vault"})


def _client() -> SignerClient:
    root = Path(os.environ.get("B2_ROOT", Path(__file__).resolve().parent.parent))
    sock = Path(os.environ.get("B2_SIGNER_SOCK", root / ".run" / "signer.sock"))
    return SignerClient(sock)


def _pack(result) -> str:
    clean = sanitize(result)
    assert_no_key_material(clean)
    return json.dumps(clean, indent=2, sort_keys=True)


def _build_server():
    try:
        from mcp.server.mcpserver import MCPServer

        mcp = MCPServer("xbt-agent-wallet")
    except ImportError:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("xbt-agent-wallet")

    @mcp.tool()
    def balance() -> str:
        """Trusted / pending / immature wallet balance in sats. No keys."""
        return _pack(_client().call("balance"))

    @mcp.tool()
    def quote_payment(to: str, amount_xbt: float, memo: str = "") -> str:
        """Dry-run a payment through the policy engine (allow / deny / needs_human)."""
        return _pack(_client().call("quote_payment", to=to, amount_xbt=amount_xbt, memo=memo))

    @mcp.tool()
    def pay(to: str, amount_xbt: float, memo: str = "") -> str:
        """Policy-checked payment. Over the human threshold returns needs_human + approval token.

        The model cannot approve the token. A human must run agentwallet-approve
        with the device private key.
        """
        return _pack(_client().call("pay", to=to, amount_xbt=amount_xbt, memo=memo))

    @mcp.tool()
    def history(limit: int = 20) -> str:
        """Append-only policy audit log (decisions and commits)."""
        return _pack(_client().call("history", limit=limit))

    return mcp


def registered_tool_names(mcp=None) -> set[str]:
    """Synchronous tool-name set for tests (does not start stdio)."""
    server = mcp if mcp is not None else _build_server()
    infos = server._tool_manager.list_tools()
    return {getattr(t, "name", t) for t in infos}


mcp = _build_server()


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
