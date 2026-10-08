"""xbt402 v1.1 (AGP-004): the wallet opens only against the v2 payee-key derivation, checked before funding."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook
from agentwallet.xbt402 import Xbt402Session, charged_of

ensure_b1()
from xbt402 import ecc  # noqa: E402

NET = "bip122:" + "11" * 16


class Hot:
    spk = bytes.fromhex("0014" + "22" * 20)

    def __init__(self):
        self.funded = []

    def fund(self, spk, sats):
        self.funded.append((spk, sats))
        raise AssertionError("must not fund")


def offer(derivation):
    extra = {"minCapacity": "20000", "maxCapacity": "1000000", "minExpiryBlocks": 10, "maxExpiryBlocks": 5000,
             "closeFeeSat": "600", "openUrl": "/x402/xbt-channel/open", "closeUrl": "/x402/xbt-channel/close",
             "billing": "postpay"}
    if derivation is not None:
        extra["derivation"] = derivation
    return {"scheme": "xbt-channel", "network": NET, "amount": "150", "asset": "XBT:sat",
            "payTo": ecc.pubkey(0xB0B).hex(), "maxTimeoutSeconds": 30, "extra": extra}


class V11OfferTests(unittest.TestCase):
    def test_refuses_other_derivations_before_funding(self):
        tmp = Path(tempfile.mkdtemp())
        hot = Hot()
        s = Xbt402Session(ChannelBook(tmp / "c.json", tmp / "k.json"), hot, rpc=None, height=lambda: 1000)
        for d in (None, "v1", "v2"):
            with self.assertRaises(RuntimeError) as err:
                s.open_from_offer("http://127.0.0.1:9", offer(d), cap_sats=50_000, expiry_blocks=100)
            self.assertIn("derivation", str(err.exception))
        self.assertEqual(hot.funded, [])

    def test_charged_reads_the_settlement_response(self):
        resp = {"success": True, "transaction": "", "network": NET, "payer": "02" + "33" * 32, "amount": "",
                "extra": {"chargedAmount": "150", "receipt": {"scheme": "xbt-channel", "charged": "150"}}}
        self.assertEqual(charged_of(resp, 7), 150)
        self.assertEqual(charged_of({"charged": "150"}, 7), 7)           # the v1.0 shape is not a receipt
        self.assertEqual(charged_of(None, 0), 0)


if __name__ == "__main__":
    unittest.main()
