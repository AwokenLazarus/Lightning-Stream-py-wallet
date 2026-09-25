#!/usr/bin/env python3
"""Agent-side MCP calls: balance, channels, allow, deny, xbt402. No approve tool."""

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
    x402_url = os.environ.get("B2_X402_URL", "http://127.0.0.1:30310/v1/infer")
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
            if int(bal.get("trusted_sats") or 0) <= 0 and int((bal.get("hot") or {}).get("hot_sats") or 0) <= 0:
                print("FAIL wallet not funded", file=sys.stderr)
                return 1

            chans = await call("channels")
            if not isinstance(chans.get("channels"), list):
                print("FAIL channels missing list", file=sys.stderr)
                return 1

            allow = await call("pay", to=merchant, amount_xbt=0.01, memo="demo-allow")
            if allow.get("verdict") != "allow":
                print("FAIL expected allow", file=sys.stderr)
                return 1
            if allow.get("rail") != "channel" or not allow.get("chan"):
                print("FAIL expected channel rail", file=sys.stderr)
                return 1

            deny = await call("pay", to=stranger, amount_xbt=0.01, memo="demo-deny")
            if deny.get("verdict") != "deny" or deny.get("rule") != "allowlist":
                print("FAIL expected deny allowlist", file=sys.stderr)
                return 1

            paid = await call(
                "xbt402_pay",
                url=x402_url,
                method="GET",
                body="",
                max_sats=1000,
            )
            if paid.get("verdict") == "deny":
                print("FAIL xbt402 denied", paid, file=sys.stderr)
                return 1
            if int(paid.get("status") or 0) != 200:
                print("FAIL expected xbt402 HTTP 200", paid, file=sys.stderr)
                return 1
            if not (paid.get("untrusted_provider_response") or {}).get("receipt") and int(paid.get("charged_sats") or 0) <= 0:
                print("FAIL xbt402 produced no receipt", paid, file=sys.stderr)
                return 1

            gated = await call("pay", to=merchant, amount_xbt=0.2, memo="demo-human")
            if gated.get("verdict") != "needs_human" or not gated.get("approval_token"):
                print("FAIL expected needs_human+token", file=sys.stderr)
                return 1

            try:
                await session.call_tool("approve", arguments={"token": gated["approval_token"], "human": True})
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

    print("AGENT_PATH_OK tools=balance,quote_payment,pay,history,channels,xbt402_pay,close_channel (no approve)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
