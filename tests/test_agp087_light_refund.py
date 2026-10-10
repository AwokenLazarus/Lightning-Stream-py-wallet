"""AGP-087 second closure audit, area LIGHT.

On the light (Electrum) backend `gettxout` answers None both when an output is proven spent and
when no server showed the transaction or listed it in the script's history. `Signer._refund_locked`
reads None, for a funding it once saw confirmed, as "the provider closed": it marks the channel
closed for good (not `close_unproven`) and never refunds it.

These tests FAIL on B2 `7eeedd6`. Each states what a closed E1/E2 would show: a funding the servers
stop showing at expiry is still refunded once a server shows it again.
"""

from __future__ import annotations

import unittest

from agentwallet.signer import Signer

from test_electrum_backend import API, FakeElectrum, LightRig, backend


class FlakyHistory(FakeElectrum):
    """An honest server that fails the two script queries (overloaded, rate-limited) and answers the
    rest: headers, transactions, proofs."""

    fail_history = False

    def answer(self, client, method, p):
        if self.fail_history and method in ("blockchain.scripthash.get_history", "blockchain.scripthash.listunspent"):
            raise ValueError("server busy")
        return super().answer(client, method, p)


class RefundOnTheLightBackend(unittest.TestCase):
    def opened(self):
        rig = LightRig(regtest_mine=False)
        self.addCleanup(rig.close_all)
        self.assertEqual(rig.fund_hot()["noticed"], 1)
        r = rig.call("xbt402_pay", url=API + "/agp087/echo", max_sats=500)
        self.assertEqual((r["verdict"], r["rule"]), ("pending", "funding_unconfirmed"), r)
        rig.mine(1)
        rig.tick()
        self.assertEqual(rig.channel().state, "open")
        r = rig.call("xbt402_pay", url=API + "/agp087/echo", max_sats=500)
        self.assertEqual((r["verdict"], r["charged_sats"]), ("allow", 500), r)
        return rig

    def restart(self, rig, *fakes):
        """The wallet was off and starts again (the verified-transaction cache is memory only)."""
        rig.light.close()
        rig.light = backend(*fakes, sim=rig.node)
        rig.signer = Signer(rig.tmp, rpc=rig.light)

    def test_a_funding_hidden_at_expiry_is_still_refunded_when_it_shows_again(self):
        rig = self.opened()
        rec = rig.channel()
        rig.mine(rec.expiry - rig.node.height)
        rig.fake.hide.add(rec.funding_txid)              # every server we have hides the funding
        self.restart(rig, rig.fake)
        acts = rig.tick()
        state = rig.channel().state
        rig.fake.hide.clear()                            # a server shows it again
        acts2 = rig.tick()
        self.assertNotEqual(state, "closed",
                            f"the hidden funding was booked as a provider close: {acts}")
        self.assertEqual(rig.channel().state, "refunded", f"never refunded: {acts2}")

    def test_one_lying_server_and_one_that_fails_history_do_not_cancel_the_refund(self):
        rig = self.opened()
        rec = rig.channel()
        honest = FlakyHistory(rig.node)
        self.addCleanup(honest.close)
        rig.mine(rec.expiry - rig.node.height)
        rig.fake.hide.add(rec.funding_txid)              # the liar hides the funding
        honest.fail_history = True                       # the honest one serves the tx, not the script's history
        self.restart(rig, rig.fake, honest)
        acts = rig.tick()
        state = rig.channel().state
        honest.fail_history = False
        acts2 = rig.tick()
        self.assertNotEqual(state, "closed",
                            f"one liar and one busy server made the wallet book a close: {acts}")
        self.assertEqual(rig.channel().state, "refunded", f"never refunded: {acts2}")


if __name__ == "__main__":
    unittest.main()
