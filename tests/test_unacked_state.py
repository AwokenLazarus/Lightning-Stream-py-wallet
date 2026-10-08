"""AGP-020: B2 re-sends the last signed-but-unacknowledged state.

When xbt402_pay signs a new (cum, sig) and the request is refused before the
provider records it (a quote-level 402, or a network error), ChannelBook keeps
that signature. The next call re-sends the same (cum, sig) instead of signing a
higher one (M3: at most one call of slack). No double charge; the policy ledger
commits once.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from agentwallet.b1path import ensure_b1
from agentwallet.signer import Signer
from agentwallet.xbt402 import Xbt402Session

ensure_b1()
from xbt402.x402_channel import XbtChannelClient, b64json, network_id, unb64json  # noqa: E402

from test_request_auth import DEST, funded  # noqa: E402

SEC = Path.home() / "xbt-rnd" / "b1" / "tests" / "security"
if str(SEC) not in sys.path:
    sys.path.insert(0, str(SEC))


class Rpc:
    def call(self, method, *a):
        if method == "getblockhash":
            return "11" * 32
        raise AssertionError(method)


class Engine:
    allowlist = {DEST}

    def __init__(self):
        self.commits = []

    def evaluate(self, pay, human=False):
        from agentwallet.policy import Decision, Verdict
        return Decision(Verdict.ALLOW, "ok", "test")

    def commit(self, pay, txid=""):
        self.commits.append((pay.amount_sats, txid))

    def commit_once(self, pay, txid=""):
        if any(t == txid for _, t in self.commits):
            return False
        self.commit(pay, txid)
        return True


class UnackedStateBook(unittest.TestCase):
    def setUp(self):
        self.book, _, _ = funded(Path(tempfile.mkdtemp()))

    def test_sign_state_hands_back_the_cached_signature(self):
        rec, sig = self.book.increment(DEST, 1_000)
        self.assertTrue(sig)
        again = self.book.sign_state(DEST, rec.used_sats)
        self.assertEqual(again, sig)
        self.assertEqual(self.book.get(DEST).used_sats, rec.used_sats)

    def test_resend_does_not_raise_used_or_spent(self):
        rec, sig = self.book.increment(DEST, 1_000)
        self.assertEqual(rec.acked_sats, 0)
        again, sig2 = self.book.resend_state(DEST)
        self.assertEqual(sig2, sig)
        self.assertEqual(again.used_sats, rec.used_sats)
        self.assertEqual(again.spent(), rec.spent())
        self.assertGreater(again.seq, rec.seq)
        self.book.ack_state(DEST)
        with self.assertRaises(Exception) as ctx:
            self.book.resend_state(DEST)
        self.assertIn("no_unacked_state", str(ctx.exception))


class UnackedStatePay(unittest.TestCase):
    def setUp(self):
        from sechelp import FakeNode, make_provider

        import xbt402.x402_channel as xc

        self.book, _, p = funded(Path(tempfile.mkdtemp()))
        node = FakeNode()
        self.calls = []
        self.payloads = []
        self.refuse_paid = 0
        self.boom_paid = 0

        def api(method, path, body):
            self.calls.append(path)
            return 200, {"Content-Type": "text/plain"}, b"ok"

        self.prov = make_provider(xc, node)
        self.prov.handler = api
        self.assertEqual(self.prov.network, network_id("11" * 32))
        node.add_funding(p, confirmations=6)
        self.prov.open({"x402Version": 2, "network": self.prov.network, "channel": {
            "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
        self.chan = p.channel_id
        offer = self.prov.requirements(150)

        def http(method, url, body=b"", headers=None):
            hdrs = {k.upper(): v for k, v in (headers or {}).items()}
            path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
            if "PAYMENT-SIGNATURE" in hdrs:
                self.payloads.append(unb64json(hdrs["PAYMENT-SIGNATURE"]))
                if self.refuse_paid:
                    self.refuse_paid -= 1
                    return 402, {"PAYMENT-REQUIRED": b64json(
                        {"x402Version": 2, "accepts": [offer]})}, b'{"error":"stale_quote"}'
                if self.boom_paid:
                    self.boom_paid -= 1
                    raise OSError("connection reset")
            st, h, out = self.prov.serve(method, path, headers or {}, body or b"", url)
            return st, {k.upper(): v for k, v in h.items()}, out

        orig = XbtChannelClient.http
        XbtChannelClient.http = staticmethod(http)
        self.addCleanup(setattr, XbtChannelClient, "http", orig)
        self.signer = Signer.__new__(Signer)
        self.signer.engine = Engine()
        self.signer.config = SimpleNamespace(channel_expiry_blocks=2_000, per_counterparty_cap_sats=50_000)
        self.signer._xbt402 = Xbt402Session(self.book, hot=None, rpc=Rpc(), height=lambda: 1_000)
        self.signer._xbt402.set_spend_book(self.signer._book_signed_delta)

    def _pay(self):
        return self.signer._xbt402_pay_locked(
            {"url": DEST + "/v1/x", "method": "GET", "body": "", "max_sats": 500})

    def test_quote_refusal_then_resend_same_cum_sig(self):
        self.refuse_paid = 1
        first = self._pay()
        self.assertEqual(first.get("charged_sats"), 0)
        self.assertEqual(self.calls, [])
        rec = self.book.get(DEST)
        self.assertGreater(rec.used_sats, rec.acked_sats)
        self.assertTrue(rec.last_sig)
        # The signature already left, so the signed increase is in the ledger even though the
        # seller refused it. A resend of the same cum does not add a second row.
        self.assertEqual(self.signer.engine.commits, [(rec.used_sats, f"xbt402:{rec.chan}:{rec.used_sats}")])
        self.assertEqual(len(self.payloads), 1)
        lost = self.payloads[0]["payload"]

        second = self._pay()
        self.assertEqual((second["verdict"], second["status"], second["charged_sats"]), ("allow", 200, 150))
        self.assertEqual(self.calls, ["/v1/x"])
        self.assertEqual(self.signer.engine.commits, [(rec.used_sats, f"xbt402:{rec.chan}:{rec.used_sats}")])
        self.assertEqual(self.prov.ledger.channels[self.chan].spent_msat, 150_000)
        self.assertEqual(len(self.payloads), 2)
        resent = self.payloads[1]["payload"]
        self.assertEqual(resent["cum"], lost["cum"])
        self.assertEqual(resent["sig"], lost["sig"])
        self.assertNotEqual(resent["seq"], lost["seq"])
        rec = self.book.get(DEST)
        self.assertEqual(rec.used_sats, int(lost["cum"]))
        self.assertEqual(rec.acked_sats, rec.used_sats)
        self.assertEqual(rec.spent(), 150)

    def test_network_error_then_resend_succeeds(self):
        self.boom_paid = 1
        first = self._pay()
        self.assertEqual(first.get("verdict"), "deny")
        self.assertEqual(self.calls, [])
        lost = self.book.get(DEST)
        self.assertEqual(self.signer.engine.commits, [(lost.used_sats, f"xbt402:{lost.chan}:{lost.used_sats}")])
        lost_cum = lost.used_sats
        lost_sig = lost.last_sig

        second = self._pay()
        self.assertEqual(second["charged_sats"], 150)
        self.assertEqual(self.calls, ["/v1/x"])
        self.assertEqual(self.signer.engine.commits, [(lost_cum, f"xbt402:{lost.chan}:{lost_cum}")])
        resent = self.payloads[-1]["payload"]
        self.assertEqual(int(resent["cum"]), lost_cum)
        self.assertEqual(resent["sig"], lost_sig)

    def test_successful_ack_lets_the_next_call_sign_higher(self):
        self._pay()
        self.assertEqual(self.book.get(DEST).acked_sats, self.book.get(DEST).used_sats)
        first_cum = self.book.get(DEST).used_sats
        self._pay()
        rec = self.book.get(DEST)
        self.assertEqual(rec.spent(), 300)
        self.assertGreaterEqual(rec.used_sats, first_cum)
        self.assertEqual(self.calls, ["/v1/x", "/v1/x"])
        # The first state signs the dust floor. Both 150-sat calls fit under it, so the ledger
        # holds that one signed amount, not 150 twice.
        self.assertEqual(self.signer.engine.commits, [(first_cum, f"xbt402:{rec.chan}:{first_cum}")])
        self.assertEqual(self.prov.ledger.channels[self.chan].spent_msat, 300_000)


if __name__ == "__main__":
    unittest.main()
