"""XBT-061 L7: a paid xbt402_pay whose provider body looks like key material still reports success.

Before AGP-001 the whole result, provider body included, went through sanitize() in the signer and
assert_no_key_material() in the MCP layer after the call was paid: a body with an xprv-shaped string
raised KeyMaterialError (and a WIF-shaped one was silently "[redacted]"), so the model saw a failed
call it had been charged for. Now only the tool's own fields are filtered; the provider body and
receipt come back verbatim under `untrusted_provider_response`, labelled untrusted.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from agentwallet.b1path import ensure_b1
from agentwallet.mcp_server import _pack
from agentwallet.policy import Decision, Verdict
from agentwallet.sanitize import UNTRUSTED_KEY, KeyMaterialError, assert_no_key_material, sanitize
from agentwallet.signer import Signer
from agentwallet.xbt402 import Xbt402Session

ensure_b1()
from xbt402.x402_channel import XbtChannelClient, network_id  # noqa: E402

from test_request_auth import DEST, funded  # noqa: E402

SEC = Path.home() / "xbt-rnd" / "b1" / "tests" / "security"
if str(SEC) not in sys.path:
    sys.path.insert(0, str(SEC))

BODY = json.dumps({
    "tip": "never paste your seed phrase or secret key anywhere",
    "seed": 42,
    "secret": "the sauce",
    "example": "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF",
}).encode()


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
        return Decision(Verdict.ALLOW, "ok", "test")

    def commit(self, pay, txid=""):
        self.commits.append((pay.amount_sats, txid))


class UntrustedBodyTests(unittest.TestCase):
    def setUp(self):
        from sechelp import FakeNode, make_provider

        import xbt402.x402_channel as xc

        self.book, _, p = funded(Path(tempfile.mkdtemp()))
        node = FakeNode()
        self.calls = []

        def api(method, path, body):
            self.calls.append(path)
            return 200, {"Content-Type": "application/json"}, BODY

        self.prov = make_provider(xc, node)
        self.prov.handler = api
        self.assertEqual(self.prov.network, network_id("11" * 32))
        node.add_funding(p, confirmations=6)
        self.prov.open({"x402Version": 2, "network": self.prov.network, "channel": {
            "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
        self.chan = p.channel_id

        def http(method, url, body=b"", headers=None):
            st, h, out = self.prov.serve(method, "/" + url.split("/", 3)[3], headers or {}, body or b"", url)
            return st, {k.upper(): v for k, v in h.items()}, out

        orig = XbtChannelClient.http
        XbtChannelClient.http = staticmethod(http)
        self.addCleanup(setattr, XbtChannelClient, "http", orig)
        self.signer = Signer.__new__(Signer)
        self.signer.engine = Engine()
        self.signer.config = SimpleNamespace(channel_expiry_blocks=2_000, per_counterparty_cap_sats=50_000)
        self.signer._xbt402 = Xbt402Session(self.book, hot=None, rpc=Rpc(), height=lambda: 1_000)

    def test_body_that_looks_like_key_material_was_the_hazard(self):
        with self.assertRaises(KeyMaterialError):
            assert_no_key_material({"body": BODY.decode()})      # what the old result shape hit

    def test_paid_call_succeeds_charged_once_body_untrusted(self):
        raw = sanitize(self.signer._xbt402_pay_locked(
            {"url": DEST + "/v1/x", "method": "GET", "body": "", "max_sats": 500}))
        res = json.loads(_pack(raw))                               # exactly what the MCP tool returns
        self.assertEqual((res["verdict"], res["status"], res["charged_sats"]), ("allow", 200, 150))
        self.assertEqual(self.calls, ["/v1/x"])                    # served once
        st = self.prov.ledger.channels[self.chan]
        self.assertEqual(st.spent_msat, 150_000)                   # charged once
        self.assertEqual(self.signer.engine.commits, [(150, self.chan)])
        u = res[UNTRUSTED_KEY]
        self.assertEqual(u["trust"], "untrusted")
        self.assertIn("untrusted", u["note"])
        self.assertEqual(u["body"].encode(), BODY)                 # verbatim: nothing redacted or dropped
        self.assertEqual(u["receipt"]["extra"]["receipt"]["charged"], "150")   # a v1.1 SettlementResponse
        self.assertEqual((u["receipt"]["extra"]["chargedAmount"], u["receipt"]["transaction"]), ("150", ""))
        self.assertNotIn("body", res)
        self.assertNotIn("receipt", res)

    def test_tool_fields_still_filtered(self):
        res = json.loads(_pack({"status": 200, "seed_words": "abandon", UNTRUSTED_KEY: {"body": "seed"}}))
        self.assertNotIn("seed_words", res)
        self.assertEqual(res[UNTRUSTED_KEY]["body"], "seed")
        with self.assertRaises(KeyMaterialError):
            assert_no_key_material({"status": 200, "xprv": "x", UNTRUSTED_KEY: {}})


if __name__ == "__main__":
    unittest.main()
