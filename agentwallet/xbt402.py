"""xbt402_pay inside the signer: B1 wire helpers, B2 keys.

XBT-060's client SDK should call the same socket methods (`fund`, `sign_state`,
`xbt402_pay`) so the model never sees a payer secret. See docs/B2_SIGNER_API.md.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from .b1path import ensure_b1
from .channels import ChannelBook
from .hot import HotWallet

ensure_b1()
from xbt402.channel import ChannelParams  # noqa: E402
from xbt402.x402_channel import (  # noqa: E402
    SCHEME,
    XbtChannelClient,
    b64json,
    network_id,
    unb64json,
)


def origin_of(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        raise ValueError("xbt402_pay needs an absolute URL")
    return f"{p.scheme}://{p.netloc}"


def pick_accept(pr: dict, network: str) -> dict:
    for acc in pr.get("accepts") or []:
        if acc.get("scheme") == SCHEME and acc.get("network") == network:
            return acc
    raise RuntimeError("no xbt-channel offer on this network")


class Xbt402Session:
    """One signer-owned client session: channels keyed by HTTP origin."""

    def __init__(self, book: ChannelBook, hot: HotWallet, rpc, height, mine=None):
        self.book = book
        self.hot = hot
        self.rpc = rpc
        self.height = height
        self.mine = mine

    def network(self) -> str:
        h = self.height()
        tip = h if h >= 101 else 101
        try:
            return network_id(self.rpc.call("getblockhash", min(tip, 101)))
        except Exception:
            return network_id("0" * 64)

    def open_from_offer(self, dest: str, acc: dict, cap_sats: int, expiry_blocks: int) -> dict:
        extra = acc.get("extra") or {}
        close_fee = int(extra.get("closeFeeSat") or 600)
        min_cap = int(extra.get("minCapacity") or 0)
        max_cap = int(extra.get("maxCapacity") or cap_sats)
        cap = max(cap_sats, min_cap)
        if cap > max_cap:
            raise RuntimeError(f"channel cap {cap} above provider max {max_cap}")
        min_exp = int(extra.get("minExpiryBlocks") or 1)
        max_exp = int(extra.get("maxExpiryBlocks") or 100_000)
        blocks = min(max(expiry_blocks, min_exp + 6), max_exp - 1)
        expiry = self.height() + blocks
        secret, payer_pub = self.book.new_payer_key()
        params = ChannelParams.derive(acc["payTo"], payer_pub, expiry, close_fee)
        funded = cap + close_fee
        txid, vout = self.hot.fund(params.spk, funded)
        params.funding_txid, params.funding_vout, params.capacity = txid, vout, funded
        if self.mine:
            self.mine(1)
        origin = dest
        open_url = origin + extra.get("openUrl", "/x402/xbt-channel/open")
        body = {
            "x402Version": 2,
            "network": acc["network"],
            "channel": {
                "txid": txid,
                "vout": vout,
                "capacity": funded,
                "expiry": expiry,
                "payerPub": params.payer_pub,
                "payerSpk": params.payer_spk,
                "redeemScript": params.script.hex(),
            },
        }
        st, _, out = XbtChannelClient.http("POST", open_url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        if st != 200:
            raise RuntimeError(f"open failed {st}: {out[:200]!r}")
        rec = self.book.add_funded(dest, secret=secret, params=params, origin=origin, cap_sats=cap)
        return rec.public()

    def pay_once(self, url: str, method: str, body: bytes, max_sats: int, expiry_blocks: int, cap_sats: int) -> dict:
        dest = origin_of(url)
        net = self.network()
        st, hdrs, out = XbtChannelClient.http(method, url, body or b"")
        if st != 402:
            return {
                "status": st,
                "charged_sats": 0,
                "body": out.decode("utf-8", "replace")[:500],
                "note": "no 402 (already free or error)",
            }
        pr = unb64json(hdrs["PAYMENT-REQUIRED"])
        acc = pick_accept(pr, net)
        price = int(acc["amount"])
        if price > max_sats:
            return {"verdict": "deny", "rule": "max_sats", "reason": f"quoted {price} > max_sats {max_sats}"}
        rec = self.book.get(dest)
        if rec is None:
            rec_pub = self.open_from_offer(dest, acc, cap_sats=cap_sats, expiry_blocks=expiry_blocks)
            rec = self.book.get(dest)
            opened = rec_pub
        else:
            opened = None
        rec, sig = self.book.increment(dest, price)
        payload = {"chan": rec.chan, "seq": rec.seq, "cum": str(rec.used_sats)}
        if sig:
            payload["sig"] = sig.hex()
        hdr = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc, "payload": payload})}
        st2, hdrs2, out2 = XbtChannelClient.http(method, url, body or b"", hdr)
        receipt = None
        if "PAYMENT-RESPONSE" in {k.upper(): v for k, v in hdrs2.items()}:
            receipt = unb64json({k.upper(): v for k, v in hdrs2.items()}["PAYMENT-RESPONSE"])
        return {
            "status": st2,
            "charged_sats": int((receipt or {}).get("charged") or price) if st2 < 400 else 0,
            "receipt": receipt,
            "chan": rec.chan,
            "cum": rec.used_sats,
            "opened": opened,
            "body": out2.decode("utf-8", "replace")[:500],
        }
