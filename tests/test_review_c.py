"""review C2 (AGP-067 follow-up, AGP-074): the agent wallet asks the provider to accept a channel's
exact terms (`/open` with `"preflight": true`, no outpoint) before it funds. The test names are
xbt-rs `crates/xbt402/tests/review_c.rs` and B1 `tests/security/test_agp067_review_c.py`.

Every flow runs a real B1 provider on the fake pruned node of test_mainnet_readiness.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

from test_mainnet_readiness import API, PAY_TO, URL, Rig, Rpc1

from xbt402.funding import FundingPolicy
from xbt402.x402_channel import XbtChannelProvider

OPEN = "/x402/xbt-channel/open"


def provider(rig: Rig, pay_to: int, name: str) -> XbtChannelProvider:
    return XbtChannelProvider(
        Rpc1(rig.node), pay_to, rig.node.network(), str(rig.tmp / f"{name}.sqlite"),
        lambda m, p: 500, lambda m, p, b: (200, {"Content-Type": "application/json"}, b'{"ok":true}'),
        close_fee=600, close_margin=144,
        policy=FundingPolicy(min_capacity=10_000, max_capacity=10_000, min_expiry_blocks=1_008, close_margin=144))


def pay(rig: Rig, http) -> dict:
    with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=http):
        return rig.signer.handle({"method": "xbt402_pay", "params": {"url": URL, "max_sats": 500}})


def path_of(url: str) -> str:
    return "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"


class ReviewC2(unittest.TestCase):
    def test_c2_a_refused_open_funds_nothing(self):
        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        after = provider(rig, PAY_TO + 1, "after")         # the payTo key changed after the 402

        def http(method, url, body=b"", headers=None):
            p = path_of(url)
            site = after if p.endswith("/open") else rig.provider
            return site.serve(method, p, headers or {}, body or b"", url)

        r = pay(rig, http)
        self.assertEqual(r["verdict"], "deny", r)
        self.assertIn("nothing was funded", r["reason"])
        self.assertEqual(rig.node.sent, [], "the buyer funded a channel the seller refused")
        self.assertIsNone(rig.channel())
        self.assertEqual(rig.signer.hot.balance_sats(), 12_000)
        self.assertEqual(after.ledger.channels, {})

    def test_c2_the_preflight_records_nothing(self):
        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        seen = []

        def http(method, url, body=b"", headers=None):
            out = rig.http(method, url, body, headers)
            req = json.loads(body) if body else {}
            if path_of(url) == OPEN and req.get("preflight") is True:
                seen.append({"req": req, "status": out[0], "body": json.loads(out[2]), "sent": len(rig.node.sent)})
            return out

        self.assertEqual(pay(rig, http)["verdict"], "allow")
        self.assertEqual(len(seen), 1, "one preflight before the funding")
        req, ans = seen[0]["req"], seen[0]["body"]
        self.assertEqual((seen[0]["status"], seen[0]["sent"]), (200, 0), ans)
        self.assertIs(ans["preflight"], True)
        self.assertNotIn("txid", req["channel"])
        self.assertNotIn("vout", req["channel"])
        rec = rig.channel()
        self.assertEqual((ans["expiry"], int(ans["maxCum"])), (rec.expiry, rec.params().max_amount))
        self.assertEqual(len(rig.provider.ledger.channels), 1, "the funded open only")
        # a preflight on its own changes nothing, and refuses what the funded open would
        st, _, out = rig.provider.serve("POST", OPEN, {}, json.dumps(req).encode(), API + OPEN)
        self.assertEqual((st, json.loads(out)["preflight"]), (200, True))
        self.assertEqual(len(rig.provider.ledger.channels), 1)
        req["channel"]["capacity"] = rig.provider.policy.max_capacity + 1
        st, _, out = rig.provider.serve("POST", OPEN, {}, json.dumps(req).encode(), API + OPEN)
        self.assertEqual((st, json.loads(out)["error"]), (400, "bad_capacity"), out)

    def test_c2_a_provider_without_preflight_still_opens(self):
        rig = Rig(regtest_mine=None)
        rig.fund_hot()

        def http(method, url, body=b"", headers=None):   # checks the terms, then fails on the missing vout
            if path_of(url) == OPEN and json.loads(body).get("preflight") is True:
                return 400, {"Content-Type": "application/json"}, b'{"error": "bad_request", "detail": "vout"}'
            return rig.http(method, url, body, headers)

        r = pay(rig, http)
        self.assertEqual((r["verdict"], r["charged_sats"]), ("allow", 500), r)
        self.assertEqual((len(rig.node.sent) >= 1, len(rig.provider.ledger.channels)), (True, 1))


if __name__ == "__main__":
    unittest.main()
