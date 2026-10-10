"""AGP-087 second closure audit, transport area (T4), B2: tests written by the auditor.
A failing test here is a finding, not a regression."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agentwallet.b1path import ensure_b1
from agentwallet.forward import ForwardSession
from agentwallet.signer import Signer

ensure_b1()
from xbt402.x402_channel import XbtChannelClient, network_id  # noqa: E402

DEST = "http://127.0.0.1:9"


class ReceiptSeq(unittest.TestCase):
    """The signer's xbt402_pay against a B1 provider (the rig of test_agp081_closure_audit.PayerTransport),
    with someone between them who answers a paid request with the paid answer before."""

    def setUp(self):
        import test_request_auth
        import xbt402.x402_channel as xc
        from sechelp import FakeNode, make_provider
        from test_unacked_state import Engine, Rpc

        tmp = Path(tempfile.mkdtemp())
        self.book, _, p = test_request_auth.funded(tmp)
        node = FakeNode()
        prov = make_provider(xc, node)
        self.assertEqual(prov.network, network_id("11" * 32))
        node.add_funding(p, confirmations=6)
        prov.open({"x402Version": 2, "network": prov.network, "channel": {
            "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
        self.prov = prov
        self.paid = 0            # paid requests the provider saw
        self.replay = False
        self.last = None

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
            paid = "PAYMENT-SIGNATURE" in {k.upper() for k in headers or {}}
            if paid and self.replay and self.last:
                return self.last
            st, h, out = prov.serve(method, path, headers or {}, body or b"", url)
            h = {k.upper(): v for k, v in h.items()}
            if paid:
                self.paid += 1
                self.last = (st, dict(h), out)
            return st, h, out

        patch = mock.patch.object(XbtChannelClient, "http", staticmethod(http))
        patch.start()
        self.addCleanup(patch.stop)
        self.signer = Signer.__new__(Signer)
        self.signer.engine = Engine()
        self.signer.config = SimpleNamespace(channel_expiry_blocks=2_000, per_counterparty_cap_sats=50_000)
        self.session = ForwardSession(self.book, hot=None, rpc=Rpc(), height=lambda: 1_000, forward_path=tmp / "forward.json")
        self.signer._xbt402 = self.session
        self.session.set_spend_book(self.signer._book_signed_delta)

    def pay(self, url: str, max_sats: int = 500) -> dict:
        return self.signer._xbt402_pay_locked({"url": url, "method": "GET", "body": "", "max_sats": max_sats})

    def test_an_earlier_answer_replayed_with_its_receipt_is_refused(self):
        first = self.pay(DEST + "/v1/x")
        self.assertEqual(first["status"], 200, first)
        seq1, used1 = self.book.get(DEST).seq, self.book.get(DEST).used_sats
        self.replay = True
        r = self.pay(DEST + "/v1/x")
        rec = self.book.get(DEST)
        self.assertEqual(self.paid, 1, "the provider never saw the second paid request")
        self.assertEqual((r.get("verdict"), r.get("rule")), ("deny", "bad_receipt"),
                         f"the wallet took the first call's answer and receipt for its second paid request: status {r.get('status')}, "
                         f"charged_sats {r.get('charged_sats')}, wallet seq {seq1} -> {rec.seq}, signed {used1} -> {rec.used_sats} sat, "
                         f"acked {rec.acked_sats} sat (the provider holds {used1})")


if __name__ == "__main__":
    unittest.main()
