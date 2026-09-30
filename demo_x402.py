#!/usr/bin/env python3
"""Tiny batch-settlement (XBT channel) provider for the B2 demo / claude session. Port 30310 by default."""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path

from agentwallet.b1path import ensure_b1
from agentwallet.rpc import KnotsRpc

ensure_b1()
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.x402_channel import XbtChannelProvider, network_id  # noqa: E402


class RpcAdapter:
    def __init__(self, knots: KnotsRpc):
        self.k = knots

    def getrawtransaction(self, txid, verbose=False):
        return self.k.call("getrawtransaction", txid, verbose)

    def getblockcount(self):
        return self.k.call("getblockcount")

    def sendrawtransaction(self, raw):
        return self.k.call("sendrawtransaction", raw)

    def getblockhash(self, h):
        return self.k.call("getblockhash", h)


def main() -> None:
    root = Path(os.environ["B2_ROOT"])
    datadir = Path(os.environ["B2_DATADIR"])
    conf = Path(os.environ["B2_CONF"])
    port = int(os.environ.get("B2_HTTP_PORT", "30310"))
    price = int(os.environ.get("B2_X402_PRICE", "150"))
    rpc = RpcAdapter(KnotsRpc(datadir, conf, wallet=os.environ.get("B2_WALLET", "agent")))
    height = rpc.getblockcount()
    blk = min(max(height, 101), 101) if height >= 101 else height
    net = network_id(rpc.getblockhash(101 if height >= 101 else blk))
    ledger = Path(os.environ.get("B2_X402_LEDGER", root / ".run" / "x402-provider.json"))

    def handler(method, path, body):
        return 200, {"Content-Type": "application/json"}, json.dumps({"ok": True, "path": path}).encode()

    provider = XbtChannelProvider(
        rpc,
        secrets.randbelow(2**255) + 1,
        net,
        str(ledger),
        lambda m, p: price,
        handler,
        billing="postpay",
        close_fee=600,
        policy=FundingPolicy(
            min_capacity=1_000,
            max_capacity=200_000_000,
            min_expiry_blocks=100,
            max_expiry_blocks=20_000,
            close_margin=36,
            min_conf=1,
        ),
    )
    pub_path = Path(os.environ.get("B2_X402_PAYTO", root / ".run" / "x402_payto.hex"))
    pub_path.write_text(provider.pay_to + "\n", encoding="utf-8")
    httpd = provider.http_server(port)
    print(f"x402 provider on 127.0.0.1:{port} payTo={provider.pay_to} net={net}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("demo_x402 failed:", e, file=sys.stderr)
        time.sleep(0.2)
        raise
