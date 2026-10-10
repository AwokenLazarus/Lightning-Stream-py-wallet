"""AGP-087 second closure audit, area LIGHT: review E1 one step to the side of the header sync.

One hostile server beside an honest one lists history entries no server can supply and answers
each `blockchain.transaction.get` inside the request timeout. A `gettxout` of the funding then
costs entries x delay, on every call, and the server is never flagged. The header sync has a
deadline (`sync_deadline`, 4 x timeout); this path has none. On mainnet defaults that is 10,000
entries x just under 15 s: about 41 hours per call.

The module docstring of `agentwallet/electrum.py` states this delay ("a history of N entries is N
transaction requests"). The tests below FAIL on B2 `7eeedd6`: they state what "one server cannot
stall the light client" would mean for this call.
"""

from __future__ import annotations

import os
import time
import unittest

from agentwallet.electrum import ElectrumBackend, scripthash

from _electrum_sim import CHECKPOINT, FakeElectrum, SimChain


class SlowLiar(FakeElectrum):
    delay_s = 0.25

    def answer(self, client, method, p):
        if method == "blockchain.transaction.get" and p[0] not in self.sim.raw:
            time.sleep(self.delay_s)
        return super().answer(client, method, p)


class OneSlowServer(unittest.TestCase):
    def setUp(self):
        self.sim = SimChain(height=200)
        self.liar, self.honest = SlowLiar(self.sim), FakeElectrum(self.sim)
        self.addCleanup(self.liar.close)
        self.addCleanup(self.honest.close)
        self.spk = "0014" + os.urandom(20).hex()
        self.txid = self.sim.credit("", 0, 5_000, self.spk)
        sh = scripthash(bytes.fromhex(self.spk))
        self.liar.extra_history[sh] = [{"tx_hash": os.urandom(32).hex(), "height": 150} for _ in range(40)]
        self.b = ElectrumBackend([self.liar.url, self.honest.url], chain="regtest",
                                 checkpoint=(CHECKPOINT, self.sim.bhash(CHECKPOINT)), timeout=1)
        self.addCleanup(self.b.close)

    def test_one_slow_server_among_honest_ones_does_not_hold_gettxout(self):
        self.b.sync()
        t = time.monotonic()
        out = self.b.call("gettxout", self.txid, 0, False)
        took = time.monotonic() - t
        print(f"\nAGP-087 measure (B2): gettxout with 40 unfetchable entries, 0.25 s per transaction.get, "
              f"timeout 1 s: {took:.2f} s; flags: {[f['reason'] for f in self.b.flags]}")
        self.assertIsNotNone(out)
        self.assertLess(took, 4 * 1.0, "one slow server among honest ones held gettxout past 4 x timeout")

    def test_entries_no_server_can_supply_flag_the_server_that_listed_them(self):
        self.liar.delay_s = 0
        self.assertIsNotNone(self.b.call("gettxout", self.txid, 0, False))
        self.assertTrue(any(f["server"] == self.liar.url for f in self.b.flags), self.b.flags)


if __name__ == "__main__":
    unittest.main()
