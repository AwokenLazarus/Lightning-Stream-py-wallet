"""AGP-021: B2 signs adaptor-locked channel states for xbt402 hub routing, under policy.

sign_state_adaptor(chan, cum, point, route): the routing policy (allowed hub, that hub's fee caps,
max lock, 24 h routed budget) and the ordinary policy engine run first; one pending lock per channel;
(lock, r, T) are on disk before the pre-signature is returned; after a restart the lock is recovered
from the hub's ch1 close (t + r in its witness). A given-up lock is adopted only by its own cum.

Runs against whichever B1 is pinned (B1_ROOT): B1 agp-021's xbt402.adaptor, else B2's fwd.adaptor.
"""

from __future__ import annotations

import json
import secrets
import tempfile
import time
import unittest
from pathlib import Path

from agentwallet.channels import ChannelBook
from agentwallet.routing import RoutePolicy, RouteSigner, adaptor_mod, point_add
from agentwallet.signer import Signer

from _agp013 import FakeRpc, fund_channel, keyfile_env, write_policy

from xbt402 import ecc
from xbt402.channel import SIGHASH_ALL_UNIFIED

HUB = "http://hub.test"
A = adaptor_mod()
POLICY = {"hubs": {HUB: {"max_fee_ppm": 5_000, "max_fee_base_msat": 2_000}}, "max_lock_sats": 20_000,
          "daily_budget_sats": 50_000}


def invoice_point():
    t = secrets.randbelow(A.N - 1) + 1
    return t, A.enc(A.point_of(t)).hex()


class Book(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.rpc = FakeRpc()
        self.book = self._book()
        self.p = fund_channel(self.book, self.rpc, HUB)
        self.rs = RouteSigner(self.book, RoutePolicy.from_dict(POLICY), state_path=self.d / "routing.json")
        self.chan = self.p.channel_id

    def _book(self):
        return ChannelBook(self.d / "channels.json", self.d / "channel_keys.json")

    def lock(self, cum=1_000, amount=900, fee=2, rs=None):
        t, T = invoice_point()
        out = (rs or self.rs).sign_state_adaptor(self.chan, cum, T, {"hub": HUB, "amount": amount, "fee": fee,
                                                                      "lockId": "L1"})
        return t, T, out

    def test_presignature_verifies_under_T_plus_r_for_the_exact_state(self):
        t, T, out = self.lock()
        T1 = A.dec(bytes.fromhex(out["point"]))
        r = int(out["tweak"], 16)
        self.assertEqual(point_add(A.dec(bytes.fromhex(T)), A.point_of(r)), T1)
        z = self.p.sighash(self.p.state_tx(1_000))
        pre = A.PreSig.from_json(out["adaptor"])
        self.assertTrue(A.preverify(bytes.fromhex(self.p.payer_pub), z, T1, pre))
        sig = A.adapt(pre, (t + r) % A.N)
        self.assertTrue(ecc.verify(bytes.fromhex(self.p.payer_pub), z, sig))       # an ordinary 0x21 state

    def test_policy(self):
        cases = [
            ({"hub": "http://other.test", "amount": 900, "fee": 2}, 1_000, "route_hub"),
            ({"hub": HUB, "amount": 900, "fee": 50}, 1_000, "route_fee_cap"),       # cap: 2 + 4.5 -> 7 (+1 carry)
            ({"hub": HUB, "amount": 25_000, "fee": 2}, 25_002, "route_lock_max"),
        ]
        for route, cum, rule in cases:
            with self.subTest(rule):
                with self.assertRaises(Exception) as e:
                    self.rs.sign_state_adaptor(self.chan, cum, invoice_point()[1], route)
                self.assertEqual(e.exception.code, rule)
                self.assertFalse(self.book.get(HUB).pending_lock)
        off = RouteSigner(self.book, RoutePolicy.from_dict({}))
        with self.assertRaises(Exception) as e:
            off.sign_state_adaptor(self.chan, 1_000, invoice_point()[1], {"hub": HUB, "amount": 900, "fee": 2})
        self.assertEqual(e.exception.code, "routing_disabled")

    def test_daily_routed_budget_counts_resolved_and_pending(self):
        for i in range(2):
            t, T, out = self.lock(cum=20_000 * (i + 1), amount=19_990, fee=10)
            self.rs.resolve_lock(self.chan, f"{t:064x}")
        with self.assertRaises(Exception) as e:
            self.lock(cum=40_000 + 10_001, amount=9_999, fee=2)                    # 40,000 + 10,001 > 50,000
        self.assertEqual(e.exception.code, "route_daily_budget")

    def test_one_pending_lock_and_plain_states_under_it(self):
        t, T, out = self.lock(cum=1_000)
        with self.assertRaises(Exception) as e:
            self.lock(cum=1_500)
        self.assertEqual(e.exception.code, "lock_outstanding")
        with self.assertRaises(Exception) as e:
            self.book.sign_state(HUB, 800)                                           # below the lock
        self.assertEqual(e.exception.code, "lock_outstanding")
        self.book.sign_state(HUB, 1_000)                                            # at it: dominates it
        self.assertFalse(self.book.get(HUB).pending_lock)

    def test_write_ahead_and_recovery_after_a_restart(self):
        t, T, out = self.lock(cum=1_000)
        r = int(out["tweak"], 16)
        again = self._book()                                          # a restart: everything from disk
        lk = again.get(HUB).pending_lock
        self.assertEqual((lk["cum"], lk["r"], lk["T"], lk["pre"]), (1_000, out["tweak"], T, out["adaptor"]))
        # the hub closes ch1 with the completed pre-signature; its witness carries t + r
        tx = self.p.state_tx(1_000)
        sig = A.adapt(A.PreSig.from_json(lk["pre"]), (t + r) % A.N) + bytes([SIGHASH_ALL_UNIFIED])
        tx.inputs[0].witness = [sig, b"\x00" * 71, b"\x01", self.p.script]
        rs2 = RouteSigner(again, RoutePolicy.from_dict(POLICY), state_path=self.d / "routing.json")
        got = rs2.recover_lock(self.chan, tx)
        self.assertEqual(int(got, 16), t)
        self.assertEqual((again.get(HUB).used_sats, again.get(HUB).pending_lock), (1_000, {}))
        self.assertEqual(rs2.spend.since(time.time() - 60), 1_000)

    def test_resolve_with_t_or_t_plus_r_and_refuse_anything_else(self):
        t, T, out = self.lock(cum=1_000)
        with self.assertRaises(Exception) as e:
            self.rs.resolve_lock(self.chan, f"{(t + 1) % A.N:064x}")
        self.assertEqual(e.exception.code, "bad_secret")
        self.assertEqual(int(self.rs.resolve_lock(self.chan, f"{t:064x}"), 16), t)     # the provider's receipt
        t2, T2, out2 = self.lock(cum=2_000)
        s = (t2 + int(out2["tweak"], 16)) % A.N
        self.assertEqual(int(self.rs.resolve_lock(self.chan, f"{s:064x}"), 16), t2)   # the hub's answer
        self.assertEqual(self.book.get(HUB).used_sats, 2_000)

    def test_adopt_only_a_lock_this_wallet_gave_up(self):
        t, T, out = self.lock(cum=1_000)
        self.rs.void_lock(self.chan)
        with self.assertRaises(Exception) as e:
            self.rs.adopt_lock(self.chan, 1_001)
        self.assertEqual(e.exception.code, "bad_amount")
        self.rs.adopt_lock(self.chan, 1_000)
        self.assertEqual(self.book.get(HUB).used_sats, 1_000)
        with self.assertRaises(Exception):
            self.rs.adopt_lock(self.chan, 1_000)                                    # once


class SignerSocket(unittest.TestCase):
    def test_signer_methods_under_routing_and_engine_policy(self):
        tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        write_policy(tmp, routing=POLICY, allowlist=["http://api.test", HUB])
        rpc = FakeRpc(height=7000)
        s = Signer(tmp, rpc=rpc)
        p = fund_channel(s.channels, rpc, HUB, expiry=8000)
        t, T = invoice_point()
        r = s.handle({"method": "xbt402_sign_state_adaptor",
                      "params": {"chan": p.channel_id, "cum": 1_000, "point": T,
                                 "route": {"hub": HUB, "amount": 990, "fee": 2, "lockId": "L"}}})
        self.assertEqual(r["verdict"], "allow", r)
        deny = s.handle({"method": "xbt402_sign_state_adaptor",
                         "params": {"chan": p.channel_id, "cum": 1_500, "point": T,
                                    "route": {"hub": HUB, "amount": 490, "fee": 2}}})
        self.assertEqual((deny["verdict"], deny["rule"]), ("deny", "lock_outstanding"))
        ok = s.handle({"method": "xbt402_resolve_lock", "params": {"chan": p.channel_id,
                                                                   "secret": f"{t:064x}"}})
        self.assertEqual(int(ok["t"], 16), t)
        fee = s.handle({"method": "xbt402_sign_state_adaptor",
                        "params": {"chan": p.channel_id, "cum": 2_000, "point": T,
                                   "route": {"hub": HUB, "amount": 900, "fee": 100}}})
        self.assertEqual((fee["verdict"], fee["rule"]), ("deny", "route_fee_cap"))
        st = s.handle({"method": "routing_status", "params": {}})
        self.assertEqual(st["spent_24h_sats"], 1_000)
        kinds = [json.loads(line)["kind"] for line in (tmp / ".run" / "signatures.jsonl").read_text().splitlines()]
        self.assertIn("adaptor_presig", kinds)                   # every pre-signature is in the audit log


if __name__ == "__main__":
    unittest.main()
