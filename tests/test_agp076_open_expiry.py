"""AGP-076: the expiry a wallet opens with is `minExpiryBlocks + minConf + closeMarginBlocks` at least,
every term from the offer (xbt-rs `xbt402::funding::open_expiry_blocks` is the same rule).

The provider compares the blocks left with `minExpiryBlocks` at its own tip when the funded open
reaches it (B1 `xbt402/funding.py` check_funding), so every block between choosing the expiry and
that open comes off the wallet's slack. AGP-074 answered a refusal with `minExpiryBlocks + 36`, a
number that mirrored one provider default and that no provider check reads.

The flow tests run a real B1 provider on the fake pruned node of test_mainnet_readiness.
"""

from __future__ import annotations

import unittest

from test_mainnet_readiness import Rig

from agentwallet.xbt402 import open_expiry_blocks

MIN_EXPIRY, MIN_CONF, CLOSE_MARGIN = 1_008, 1, 144     # the Rig provider's offer


class Rule(unittest.TestCase):
    def test_floor_is_min_expiry_plus_min_conf_plus_close_margin(self):
        # three margins, three answers: a slack that mirrors one provider's default fails two of them
        self.assertEqual(open_expiry_blocks(1_008, 1_008, 8_640, 1, 144), 1_153)
        self.assertEqual(open_expiry_blocks(1_008, 1_008, 8_640, 1, 36), 1_045)
        self.assertEqual(open_expiry_blocks(1_008, 1_008, 8_640, 3, 5), 1_016)
        self.assertEqual(open_expiry_blocks(1_008, 1_008, 8_640, 0, 0), 1_008)

    def test_want_above_the_floor_is_kept_and_the_offer_max_bounds_both(self):
        self.assertEqual(open_expiry_blocks(2_016, 1_008, 8_640, 1, 144), 2_016)
        self.assertEqual(open_expiry_blocks(9_000, 1_008, 8_640, 1, 144), 8_639)
        self.assertEqual(open_expiry_blocks(100, 1_008, 1_100, 1, 144), 1_099)
        self.assertEqual(open_expiry_blocks(100, 10, 0, 1, 5), 0)


class Flow(unittest.TestCase):
    def test_the_wallet_opens_at_the_offers_floor(self):
        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        h = rig.node.height
        self.assertEqual(rig.pay()["verdict"], "allow")
        rec = rig.channel()
        self.assertEqual(rec.expiry - h, MIN_EXPIRY + MIN_CONF + CLOSE_MARGIN)

    def test_a_funding_that_confirms_a_close_margin_late_still_opens(self):
        """The slack is all used: `closeMarginBlocks` pass before the funding's block. The provider
        sees exactly minExpiryBlocks left. At minExpiryBlocks + 36 (or + 6) it refuses bad_expiry
        on every retry and the coins stay locked until the refund."""
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        h = rig.node.height
        self.assertEqual(rig.pay()["verdict"], "pending")
        rig.node.mine(MIN_CONF + CLOSE_MARGIN)
        acts = rig.tick()
        self.assertEqual(acts[0]["open_retry"]["state"], "open", acts)
        self.assertEqual(rig.channel().expiry - rig.node.height, MIN_EXPIRY)
        self.assertEqual(rig.channel().expiry - h, MIN_EXPIRY + MIN_CONF + CLOSE_MARGIN)
        self.assertEqual(rig.pay()["charged_sats"], 500)

    def test_one_block_later_the_provider_refuses(self):
        """The allowance has an end, and it is where the rule says: one block more and the provider's
        own check (not a wallet guess) refuses."""
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        rig.pay()
        rig.node.mine(MIN_CONF + CLOSE_MARGIN + 1)
        rig.tick()
        rec = rig.channel()
        self.assertEqual((rec.state, rec.open_error), ("pending", "open refused: HTTP 400 bad_expiry"))

    def test_an_offer_without_close_margin_is_refused_before_funding(self):
        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        http = rig.http

        def no_margin(method, url, body=b"", headers=None):
            import base64
            import json
            st, hdrs, out = http(method, url, body, headers)
            if st == 402:
                pr = json.loads(out)
                for acc in pr["accepts"]:
                    acc["extra"].pop("closeMarginBlocks")
                out = json.dumps(pr).encode()
                hdrs = {**hdrs, "PAYMENT-REQUIRED": base64.b64encode(out).decode()}
            return st, hdrs, out

        rig.http = no_margin
        r = rig.pay()
        self.assertEqual(r["verdict"], "deny", r)
        self.assertIn("closeMarginBlocks", r["reason"])
        self.assertEqual((rig.node.sent, rig.preflights, rig.posts), ([], [], []))


if __name__ == "__main__":
    unittest.main()
