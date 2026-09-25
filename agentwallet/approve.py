"""Human-only CLI: sign an approval with the device key and submit it to the signer.

This module is not an MCP tool. The agent process must not receive --key.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .approval import b2x, load_private_key, sign_approval
from .signer import SignerClient


def _refuse_agent_readable_key(key_path: Path, agent_root: Path) -> None:
    key = key_path.resolve()
    root = agent_root.resolve()
    try:
        key.relative_to(root)
    except ValueError:
        return
    raise SystemExit(
        f"refuse: human private key {key} is under the agent workspace {root}. "
        "Keep it on the human's device directory."
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agentwallet-approve",
        description="Sign a pending payment with the human ed25519 key (out of band).",
    )
    p.add_argument(
        "--key",
        required=True,
        help="Path to the human private key (32 raw bytes or hex). Must NOT be under B2_ROOT.",
    )
    p.add_argument("--token", required=True)
    p.add_argument("--dest", required=True)
    p.add_argument("--amount-sats", type=int, required=True)
    p.add_argument("--expiry", type=int, required=True, help="Unix timestamp from the needs_human response")
    p.add_argument(
        "--sock",
        default=os.environ.get("B2_SIGNER_SOCK", ""),
        help="Signer Unix socket (or B2_SIGNER_SOCK)",
    )
    p.add_argument(
        "--agent-root",
        default=os.environ.get("B2_ROOT", ""),
        help="Agent workspace; used only to refuse keys stored there",
    )
    args = p.parse_args(argv)

    key_path = Path(args.key).expanduser()
    if args.agent_root:
        _refuse_agent_readable_key(key_path, Path(args.agent_root))
    if not args.sock:
        raise SystemExit("need --sock or B2_SIGNER_SOCK")

    priv = load_private_key(key_path)
    sig = sign_approval(priv, args.token, args.dest, args.amount_sats, args.expiry)
    client = SignerClient(Path(args.sock))
    result = client.call(
        "approve",
        token=args.token,
        dest=args.dest,
        amount_sats=args.amount_sats,
        expiry=args.expiry,
        signature=b2x(sig),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if result.get("verdict") != "allow" or not result.get("txid"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
