"""MCP surface. Talks only to the signer socket. No RPC, no keys."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .sanitize import assert_no_key_material, sanitize
from .signer import SignerClient


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
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("xbt-agent-wallet")
    except ImportError:
        from mcp.server.mcpserver import MCPServer

        mcp = MCPServer("xbt-agent-wallet")

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
        """Policy-checked payment. Over the human threshold returns needs_human + approval token."""
        return _pack(_client().call("pay", to=to, amount_xbt=amount_xbt, memo=memo))

    @mcp.tool()
    def approve(token: str, human: bool = False) -> str:
        """Human-only path: consume an approval token and sign. Agents must not set human=true."""
        return _pack(_client().call("approve", token=token, human=human))

    @mcp.tool()
    def history(limit: int = 20) -> str:
        """Append-only policy audit log (decisions and commits)."""
        return _pack(_client().call("history", limit=limit))

    return mcp


mcp = _build_server()


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
