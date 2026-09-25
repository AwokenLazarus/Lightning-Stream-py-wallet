#!/usr/bin/env python3
"""Agent-side MCP calls: balance, allow, deny, needs_human. No approve tool."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentwallet.mcp_server import MCP_TOOL_NAMES


def _text(result) -> dict:
    parts = []
    for c in result.content:
        text = getattr(c, "text", None)
        if text:
            parts.append(text)
    raw = "\n".join(parts) if parts else "{}"
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


async def run() -> int:
    root = Path(os.environ["B2_ROOT"])
    py = os.environ.get("B2_PYTHON", sys.executable)
    merchant = os.environ["B2_MERCHANT"]
    stranger = os.environ["B2_STRANGER"]
    pending_path = Path(os.environ.get("B2_PENDING", root / ".run" / "pending_approval.json"))
    params = StdioServerParameters(
        command=py,
        args=["-m", "agentwallet.mcp_server"],
        env={**os.environ, "B2_ROOT": str(root)},
        cwd=str(root),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            if tools != set(MCP_TOOL_NAMES):
                print(f"FAIL MCP tools {tools} != {set(MCP_TOOL_NAMES)}", file=sys.stderr)
                return 1
            if "approve" in tools or "recover_vault" in tools:
                print("FAIL approve/recover_vault must not be MCP tools", file=sys.stderr)
                return 1

            async def call(name, **args):
                res = await session.call_tool(name, arguments=args)
                data = _text(res)
                print(f"=== {name} {args} ===")
                print(json.dumps(data, indent=2, sort_keys=True))
                return data

            bal = await call("balance")
            if int(bal.get("trusted_sats") or 0) <= 0:
                print("FAIL wallet not funded", file=sys.stderr)
                return 1

            allow = await call("pay", to=merchant, amount_xbt=0.01, memo="demo-allow")
            if allow.get("verdict") != "allow" or not allow.get("txid"):
                print("FAIL expected allow+txid", file=sys.stderr)
                return 1

            deny = await call("pay", to=stranger, amount_xbt=0.01, memo="demo-deny")
            if deny.get("verdict") != "deny" or deny.get("rule") != "allowlist":
                print("FAIL expected deny allowlist", file=sys.stderr)
                return 1

            gated = await call("pay", to=merchant, amount_xbt=0.2, memo="demo-human")
            if gated.get("verdict") != "needs_human" or not gated.get("approval_token"):
                print("FAIL expected needs_human+token", file=sys.stderr)
                return 1
            if not gated.get("approval_expires"):
                print("FAIL needs_human missing approval_expires", file=sys.stderr)
                return 1

            # (a) agent calling approve through MCP is impossible
            try:
                sneaky = await session.call_tool(
                    "approve", arguments={"token": gated["approval_token"], "human": True}
                )
                sneaky_data = _text(sneaky)
                if not getattr(sneaky, "isError", False) and (
                    sneaky_data.get("verdict") == "allow" or sneaky_data.get("txid")
                ):
                    print("FAIL MCP exposed approve:", sneaky_data, file=sys.stderr)
                    return 1
                print("=== agent approve (must fail) ===")
                print(
                    json.dumps(
                        {"ok": False, "error": sneaky_data, "note": "no MCP approve tool"},
                        indent=2,
                    )
                )
            except Exception as e:
                print("=== agent approve (must fail) ===")
                print(json.dumps({"ok": False, "error": str(e), "note": "no MCP approve tool"}, indent=2))

            pending = {
                "token": gated["approval_token"],
                "dest": gated.get("dest") or merchant,
                "amount_sats": gated.get("amount_sats") or 20_000_000,
                "expiry": gated["approval_expires"],
            }
            pending_path.parent.mkdir(parents=True, exist_ok=True)
            pending_path.write_text(json.dumps(pending, indent=2), encoding="utf-8")
            print(f"PENDING_APPROVAL {pending_path}")

            hist = await call("history", limit=30)
            events = hist.get("events") or []
            verdicts = {e.get("verdict") for e in events if e.get("type") == "decision"}
            if not {"allow", "deny", "needs_human"} <= verdicts:
                print(f"FAIL history missing verdicts: {verdicts}", file=sys.stderr)
                return 1

    print("AGENT_PATH_OK tools=balance,quote_payment,pay,history (no approve)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
