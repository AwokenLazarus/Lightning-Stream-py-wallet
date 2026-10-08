"""B2 xbt402_request_auth (H3) and 0xA3 never-lower (H5)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook
from agentwallet.signer import Signer

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelParams, channel_auth_key  # noqa: E402
from xbt402.tx import SIGHASH_SINGLE_ACP_UNIFIED  # noqa: E402
from xbt402.x402_channel import request_auth, request_digest_v2  # noqa: E402

DEST = "http://127.0.0.1:9"
SEC = Path.home() / "xbt-rnd" / "b1" / "tests" / "security"
if str(SEC) not in sys.path:
    sys.path.insert(0, str(SEC))

NET = "bip122:" + "11" * 16   # xbt402 v1.1 derives the payee key per network (the test providers' id)


def funded(tmp: Path, cap: int = 100_000, close_fee: int = 600):
    book = ChannelBook(tmp / "channels.json", tmp / "channel_keys.json")
    secret = 0xA11CE
    payee = 0xB0B
    p = ChannelParams.derive(ecc.pubkey(payee).hex(), ecc.pubkey(secret).hex(), 8_000, close_fee, network=NET)
    p.funding_txid = "11" * 32
    p.funding_vout = 0
    p.capacity = cap
    book.add_funded(DEST, secret=secret, params=p, origin=DEST, cap_sats=cap - close_fee)
    return book, secret, p


class RequestAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.book, self.secret, self.params = funded(self.tmp)

    def test_matches_b1_hmac(self):
        rec = self.book.get(DEST)
        req = request_digest_v2("GET", "/v1/x", b"")
        got = self.book.request_auth(rec.chan, 1, "3000", "sighex", req)
        key = channel_auth_key(self.secret, bytes.fromhex(rec.payee_pub))
        self.assertEqual(got, request_auth(key, rec.chan, 1, "3000", "sighex", req))

    def test_the_payload_binds_scheme_host_and_port(self):
        """AGP-068: the wallet binds the URL it calls, so a header cannot be moved to another origin."""
        from agentwallet.xbt402 import Xbt402Session

        rec = self.book.get(DEST)
        s = Xbt402Session(self.book, hot=None, rpc=None, height=lambda: 1000)
        pl = {"chan": rec.chan, "seq": 4, "cum": "3000"}
        got = s._with_auth(pl, "GET", "http://127.0.0.1:9/v1/a?x=1", b"")["auth"]
        key = channel_auth_key(self.secret, bytes.fromhex(rec.payee_pub))
        self.assertEqual(got, request_auth(key, rec.chan, 4, "3000", None,
                                           request_digest_v2("GET", "http://127.0.0.1:9/v1/a?x=1", b"")))
        for other in ("https://127.0.0.1:9/v1/a?x=1", "http://127.0.0.2:9/v1/a?x=1", "http://127.0.0.1:10/v1/a?x=1"):
            self.assertNotEqual(got, s._with_auth(pl, "GET", other, b"")["auth"], other)

    def test_tampered_request_does_not_match(self):
        rec = self.book.get(DEST)
        good = request_digest_v2("GET", "/v1/share-change?window=7d", b"")
        bad = request_digest_v2("GET", "/v1/report", b"")
        auth = self.book.request_auth(rec.chan, 2, "3000", "", good)
        self.assertNotEqual(auth, self.book.request_auth(rec.chan, 2, "3000", "", bad))

    def test_provider_rejects_tampered_path(self):
        from sechelp import FakeNode, make_provider, pay

        import xbt402.x402_channel as xc

        node = FakeNode()
        prov = make_provider(xc, node)
        p = self.params
        node.add_funding(p, confirmations=6)
        prov.open({
            "x402Version": 2,
            "network": prov.network,
            "channel": {
                "txid": p.funding_txid,
                "vout": 0,
                "capacity": p.capacity,
                "expiry": p.expiry,
                "payerPub": p.payer_pub,
                "redeemScript": p.script.hex(),
            },
        })
        rec, sig = self.book.increment(DEST, 3000)
        req = request_digest_v2("GET", "/v1/a", b"")
        payload = {
            "chan": rec.chan,
            "seq": rec.seq,
            "cum": str(rec.used_sats),
            "sig": sig.hex(),
            "auth": self.book.request_auth(rec.chan, rec.seq, str(rec.used_sats), sig.hex(), req),
        }
        self.assertEqual(pay(xc, prov, payload, path="/v1/a")[0], 200)
        st, err, _ = pay(xc, prov, payload, path="/v1/b")
        self.assertEqual(err, "bad_auth")
        self.assertEqual(st, 402)

    def test_signer_method_returns_auth(self):
        rec = self.book.get(DEST)
        req = request_digest_v2("GET", "/", b"")
        s = Signer.__new__(Signer)
        s.channels = self.book
        out = s._xbt402_request_auth({"chan": rec.chan, "seq": 3, "cum": "0", "sig": "", "req": req})
        self.assertIn("auth", out)
        self.assertEqual(len(out["auth"]), 64)

    def test_h5_a3_never_lower_and_change_first(self):
        rec = self.book.get(DEST)
        sig = self.book.sign_state_a3(DEST, 2_000)
        self.assertEqual(sig[-1], SIGHASH_SINGLE_ACP_UNIFIED)
        tx = self.params.state_tx_a3(2_000)
        # output 0 is the payer's change (H5)
        self.assertEqual(tx.outputs[0].script_pubkey.hex(), rec.payer_spk)
        self.assertGreater(tx.outputs[0].value, tx.outputs[1].value)
        with self.assertRaisesRegex(Exception, "stale"):
            self.book.sign_state_a3(DEST, 1_000)


if __name__ == "__main__":
    unittest.main()
