"""AGP-128: the routed signing is gone from this wallet, as it is from the Rust signer.

It paid through a hub (adaptor-locked channel states); the hub was retired and nothing was left for
it to pay. What stays, and is tested here and in `test_agp055_rust_wallet.py`:

  * a policy file that still has a `routing` section loads, and the signer says, at start and in
    `health`, that it ignores the section (the Rust signer's sentence);
  * the signer has no lock method left: each is an unknown method, and signs nothing;
  * a channel record with a pending lock keeps it, and a plain state over a lock that was booked
    books only the rest (the lock's own booking is in the ledger already).
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

from agentwallet.policy import PolicyConfig, policy_warnings
from agentwallet.signer import Signer

from _agp013 import HUMAN_PUB, FakeRpc, fund_channel, keyfile_env, write_policy

from xbt402.channel import ChannelError

HUB = "http://hub.test"
ROUTING = {"hubs": {HUB: {"max_fee_ppm": 5_000, "max_fee_base_msat": 2_000}}, "max_lock_sats": 20_000, "daily_budget_sats": 3_000}
RETIRED = ("xbt402_sign_state_adaptor", "xbt402_resolve_lock", "xbt402_void_lock", "xbt402_adopt_lock", "xbt402_recover_lock",
           "routing_status")
WARNING = "policy.json routing: payments through a hub were retired; the signer ignores this section and it can be removed"


def signer(tmp: Path, **policy) -> tuple[Signer, str]:
    keyfile_env()
    write_policy(tmp, **{"per_counterparty_cap_sats": 100_000, "split_window_s": 0, "human_pubkey": HUMAN_PUB.hex(), **policy})
    said = io.StringIO()
    with contextlib.redirect_stdout(said):
        s = Signer(tmp, rpc=FakeRpc(height=1000))
    s.hot.notice_utxo("aa" * 32, 0, 300_000)
    return s, said.getvalue()


def ledger_sum(s: Signer) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


class RoutingRemoved(unittest.TestCase):
    def test_a_policy_with_a_routing_section_loads_with_a_warning(self):
        s, said = signer(Path(tempfile.mkdtemp()), routing=ROUTING, allowlist=[HUB])
        self.assertIn("routing", json.loads((s.root / "policy.json").read_text()), "the file still has the section")
        self.assertEqual(s.policy_warnings, [WARNING])
        self.assertIn(f"warning: {WARNING}", said)
        self.assertEqual(s.handle({"method": "health"})["warnings"], [WARNING])
        self.assertFalse(hasattr(s.config, "routing"))
        self.assertNotIn("routing", s.config.to_dict())
        # a policy without the section says nothing
        s, said = signer(Path(tempfile.mkdtemp()), allowlist=[HUB])
        self.assertEqual((s.policy_warnings, "warning" in said, "warnings" in s.handle({"method": "health"})), ([], False, False))
        self.assertEqual(policy_warnings({"routing": {}}), [WARNING], "an empty section is still a section")
        self.assertEqual(PolicyConfig.from_dict({"allowlist": [HUB], "routing": ROUTING}).allowlist, frozenset({HUB}))

    def test_the_lock_methods_are_unknown_and_sign_nothing(self):
        s, _ = signer(Path(tempfile.mkdtemp()), routing=ROUTING, allowlist=[HUB])
        chan = fund_channel(s.channels, s.rpc, HUB).channel_id
        before = (s.handle({"method": "signatures", "params": {"limit": 1000}}), s.channels.get(HUB).used_sats, ledger_sum(s))
        for m in RETIRED:
            with self.assertRaises(ValueError) as c:
                s.handle({"method": m, "params": {"chan": chan, "cum": 1_000, "point": "02" + "11" * 32, "secret": "22" * 32,
                                                  "route": {"hub": HUB, "amount": 900, "fee": 2}}})
            self.assertEqual(str(c.exception), f"unknown method {m}")
        self.assertEqual((s.handle({"method": "signatures", "params": {"limit": 1000}}), s.channels.get(HUB).used_sats, ledger_sum(s)), before)
        self.assertFalse(hasattr(s, "routing"))
        self.assertIsNone(importlib.util.find_spec("agentwallet.routing"))
        self.assertFalse((s.root / ".run" / "routing.json").exists(), "no routed-spend log is created")

    def test_a_plain_state_over_a_booked_lock_books_only_the_rest(self):
        """What an earlier version left on a channel: a lock pre-signed for 1,000 and booked when it
        was pre-signed (AGP-080). The owner's ledger holds those 1,000; a plain state for 1,400
        books 400 more, and a plain state below the lock is refused."""
        s, _ = signer(Path(tempfile.mkdtemp()), allowlist=[HUB])
        chan = fund_channel(s.channels, s.rpc, HUB).channel_id
        with s.channels._lock:
            rec = s.channels._records[HUB]
            rec.pending_lock = {"cum": 1_000, "pre": {}, "r": "11" * 32, "T": "02" + "11" * 32, "route": {"hub": HUB}, "at": 1.0,
                                "prev_used": 0, "booked": True, "booked_sats": 1_000}
            rec.ledger_booked_sats = 1_000
            s.channels._persist()
        with self.assertRaises(ChannelError) as c:      # refused as it always was: the socket answers an error
            s.handle({"method": "sign_state", "params": {"chan": chan, "cum": 900}})
        self.assertEqual((c.exception.code, ledger_sum(s)), ("lock_outstanding", 0))
        self.assertEqual(s.handle({"method": "channels"})["channels"][0]["pending_lock_cum"], 1_000)
        r = s.handle({"method": "sign_state", "params": {"chan": chan, "cum": 1_400}})
        self.assertEqual(r["verdict"], "allow", r)
        self.assertEqual((ledger_sum(s), s.channels.get(HUB).pending_lock), (400, {}))


if __name__ == "__main__":
    unittest.main()
