#!/usr/bin/env python3
"""Five scripted MCP agent calls: balance, allow, deny, needs_human, approve."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


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
    params = StdioServerParameters(
        command=py,
        args=["-m", "agentwallet.mcp_server"],
        env={**os.environ, "B2_ROOT": str(root)},
        cwd=str(root),
    )
    calls = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            expect = {"balance", "quote_payment", "pay", "approve", "history"}
            missing = expect - tools
            if missing:
                print(f"FAIL missing tools: {missing}", file=sys.stderr)
                return 1

            async def call(name, **args):
                res = await session.call_tool(name, arguments=args)
                data = _text(res)
                calls.append((name, data))
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
            token = gated["approval_token"]

            # Agent cannot approve itself
            blocked = await call("approve", token=token, human=False)
            if blocked.get("verdict") != "deny":
                print("FAIL agent approve should deny", file=sys.stderr)
                return 1

            approved = await call("approve", token=token, human=True)
            if not approved.get("txid") or not approved.get("approved"):
                print("FAIL human approve should send", file=sys.stderr)
                return 1

            hist = await call("history", limit=30)
            events = hist.get("events") or []
            verdicts = {e.get("verdict") for e in events if e.get("type") == "decision"}
            if not {"allow", "deny", "needs_human"} <= verdicts:
                print(f"FAIL history missing verdicts: {verdicts}", file=sys.stderr)
                return 1

    print("DEMO_OK calls=5+ (balance, pay-allow, pay-deny, pay-needs_human, approve)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
