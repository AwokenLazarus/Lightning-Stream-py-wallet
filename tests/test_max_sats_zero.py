"""max_sats: 0 is allowed for free calls and refused when the quote is > 0."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from agentwallet.signer import Signer
from agentwallet.xbt402 import Xbt402Session


class MaxSatsZeroTests(unittest.TestCase):
    def _signer(self, session):
        s = Signer.__new__(Signer)
        s.engine = SimpleNamespace(allowlist={"http://127.0.0.1:9"})
        s.config = SimpleNamespace(channel_expiry_blocks=10, per_counterparty_cap_sats=1000)
        s._xbt402 = session
        return s

    def test_free_catalog_with_max_sats_0(self):
        calls = []

        class Sess:
            def pay_once(self, url, method, body, max_sats, expiry_blocks, cap_sats):
                calls.append((url, max_sats))
                self.assertEqual(max_sats, 0)
                return {"status": 200, "charged_sats": 0, "body": "catalog", "opened": None}

            def assertEqual(self, a, b):
                if a != b:
                    raise AssertionError((a, b))

        out = self._signer(Sess())._xbt402_pay_locked(
            {"url": "http://127.0.0.1:9/", "method": "GET", "body": "", "max_sats": 0}
        )
        self.assertEqual(out["verdict"], "allow")
        self.assertEqual(out["rule"], "free")
        self.assertEqual(out["charged_sats"], 0)
        self.assertIsNone(out.get("opened") or None)
        self.assertEqual(calls, [("http://127.0.0.1:9/", 0)])

    def test_paid_endpoint_refused_at_max_sats_0(self):
        class Sess:
            def pay_once(self, url, method, body, max_sats, expiry_blocks, cap_sats):
                return {"verdict": "deny", "rule": "max_sats", "reason": f"quoted 600 > max_sats {max_sats}"}

        out = self._signer(Sess())._xbt402_pay_locked(
            {"url": "http://127.0.0.1:9/v1/report", "method": "GET", "body": "", "max_sats": 0}
        )
        self.assertEqual(out["verdict"], "deny")
        self.assertEqual(out["rule"], "max_sats")

    def test_pay_once_zero_price_does_not_open(self):
        """A 402 with amount 0 is treated as free: no increment, no fund()."""

        class BoomHot:
            def fund(self, *a, **k):
                raise AssertionError("must not open a channel for a zero-priced call")

        class BoomBook:
            def get(self, dest):
                raise AssertionError("must not look up a channel for a zero-priced call")

        class Rpc:
            def call(self, method, *a):
                if method == "getblockhash":
                    return "11" * 32
                raise AssertionError(method)

        from agentwallet.b1path import ensure_b1

        ensure_b1()
        from xbt402.x402_channel import SCHEME, XbtChannelClient, b64json, network_id

        net = network_id("11" * 32)
        pr = {
            "x402Version": 2,
            "accepts": [{
                "scheme": SCHEME,
                "network": net,
                "amount": "0",
                "payTo": "02" + "11" * 32,
                "extra": {"closeFeeSat": "600"},
            }],
        }

        def fake_http(method, url, body=b"", headers=None):
            return 402, {"PAYMENT-REQUIRED": b64json(pr)}, b"{}"

        sess = Xbt402Session(BoomBook(), BoomHot(), Rpc(), height=lambda: 200)
        orig = XbtChannelClient.http
        XbtChannelClient.http = staticmethod(fake_http)
        try:
            out = sess.pay_once("http://127.0.0.1:9/free", "GET", b"", max_sats=0, expiry_blocks=10, cap_sats=1000)
        finally:
            XbtChannelClient.http = orig
        self.assertEqual(out["charged_sats"], 0)
        self.assertIn("no channel", out["note"])


if __name__ == "__main__":
    unittest.main()
