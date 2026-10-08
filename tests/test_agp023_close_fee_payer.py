"""AGP-023 (xbt402 v1.2 closeFeePayer): the wallet opens payee-pays channels when an offer says so.

Under payee-pays the payee's output carries the close fee (cum - closeFee) and ours is capacity - cum,
so the wallet funds no close fee on top of the cap, floors its first state at dust + closeFee, sends
closeFeePayer in the open and refuses a provider that opened anything else. Records from before
AGP-023 load as payer-pays, and payer-pays offers are funded and signed exactly as in v1.1.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook, ChannelRecord

from test_l12_error_text import DEST, Hot, Rpc  # noqa: E402
from test_v11_offer import NET, offer  # noqa: E402

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import DERIVATION, DUST, ChannelError, ChannelParams, Payee, channel_payee_secret  # noqa: E402

from agentwallet.xbt402 import Xbt402Session  # noqa: E402

V12 = "close_fee_payer" in ChannelParams.__dataclass_fields__     # the pinned B1 has AGP-023
needs_v12 = unittest.skipUnless(V12, "pinned B1 predates xbt402 v1.2 closeFeePayer (AGP-023)")


class FundingHot(Hot):
    def __init__(self):
        self.funded = []

    def prepare_fund(self, spk, sats):
        self.funded.append(sats)
        return super().prepare_fund(spk, sats)


def session():
    tmp = Path(tempfile.mkdtemp())
    hot = FundingHot()
    return Xbt402Session(ChannelBook(tmp / "c.json", tmp / "k.json"), hot, rpc=Rpc(), height=lambda: 1000), hot


def payee_offer(fee_payer="payee"):
    acc = offer(DERIVATION)
    acc["extra"]["closeFeePayer"] = fee_payer
    return acc


def provider(echo=True):
    """The provider's open endpoint: records the funded open, echoes closeFeePayer as a v1.2 provider
    does. With echo=False it is a v1.1 provider, which answers the review C2 preflight bad_request."""
    seen = []

    def http(method, url, body=b"", headers=None):
        req = json.loads(body)
        if req.get("preflight") is True:
            if not echo:
                return 400, {}, b'{"error": "bad_request", "detail": "vout"}'
            out = {"preflight": True, "expiry": req["channel"]["expiry"], "maxCum": "0", "minConf": 1}
            if req["channel"].get("closeFeePayer"):
                out["closeFeePayer"] = req["channel"]["closeFeePayer"]
            return 200, {}, json.dumps(out).encode()
        seen.append(req)
        out = {"chan": f"{req['channel']['txid']}:{req['channel']['vout']}", "maxCum": "0", "confirmations": 1}
        if echo and req["channel"].get("closeFeePayer"):
            out["closeFeePayer"] = req["channel"]["closeFeePayer"]
        return 200, {}, json.dumps(out).encode()
    return http, seen


class PayeePaysOffer(unittest.TestCase):
    @needs_v12
    def test_open_and_sign_payee_pays(self):
        s, hot = session()
        http, seen = provider()
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=http):
            opened = s.open_from_offer(DEST, payee_offer(), cap_sats=50_000, expiry_blocks=100)
        self.assertEqual(hot.funded, [50_000])                   # no close fee on top: the payee pays it
        self.assertEqual(seen[0]["channel"]["closeFeePayer"], "payee")
        self.assertEqual((opened["state"], opened["close_fee_payer"]), ("open", "payee"))
        rec = s.book.get(DEST)
        p = rec.params()
        self.assertEqual((p.close_fee_payer, p.min_amount, p.max_amount), ("payee", DUST + 600, 50_000))
        rec2, sig = s.book.increment(DEST, 1)                    # the first state: dust + closeFee
        self.assertEqual(rec2.used_sats, DUST + 600)
        payee = Payee(p, channel_payee_secret(NET, 0xB0B, bytes.fromhex(p.payer_pub), p.expiry))
        payee.accept(rec2.used_sats, sig)
        tx = payee.close_tx()
        self.assertEqual([o.value for o in tx.outputs], [DUST, 50_000 - DUST - 600])

    def test_payer_pays_offer_is_v11(self):
        s, hot = session()
        http, seen = provider()
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=http):
            opened = s.open_from_offer(DEST, offer(DERIVATION), cap_sats=50_000, expiry_blocks=100)
        self.assertEqual(hot.funded, [50_600])
        self.assertNotIn("closeFeePayer", seen[0]["channel"])
        self.assertNotIn("close_fee_payer", opened)
        rec, _ = s.book.increment(DEST, 1)
        self.assertEqual(rec.used_sats, DUST)

    @needs_v12
    def test_a_provider_that_ignores_close_fee_payer_is_not_marked_open(self):
        s, hot = session()
        http, _ = provider(echo=False)                           # a v1.1 provider: opens payer-pays
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=http):
            with self.assertRaises(RuntimeError) as err:
                s.open_from_offer(DEST, payee_offer(), cap_sats=50_000, expiry_blocks=100)
        self.assertIn("closeFeePayer", str(err.exception))
        self.assertEqual(s.book.get(DEST).state, "pending")      # refunded at expiry, never signed on
        with self.assertRaises(ChannelError):
            s.book.increment(DEST, 1)

    def test_unknown_fee_payer_refused_before_funding(self):
        s, hot = session()
        with self.assertRaises(RuntimeError):
            s.open_from_offer(DEST, payee_offer("hub"), cap_sats=50_000, expiry_blocks=100)
        self.assertEqual(hot.funded, [])

    def test_records_from_before_agp023_are_payer_pays(self):
        fields = {f: 0 for f in ("cap_sats", "used_sats", "expiry", "close_fee", "funding_vout")}
        rec = ChannelRecord(dest=DEST, chan="x", payer_pub=ecc.pubkey(1).hex(), payee_pub=ecc.pubkey(2).hex(),
                            payer_spk="0014" + "11" * 20, payee_spk="0014" + "22" * 20, funding_txid="ab" * 32,
                            **fields)
        self.assertEqual(rec.close_fee_payer, "payer")
        self.assertEqual(getattr(rec.params(), "close_fee_payer", "payer"), "payer")


if __name__ == "__main__":
    unittest.main()
