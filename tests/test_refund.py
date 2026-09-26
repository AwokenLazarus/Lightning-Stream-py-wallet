"""AGP-013 payer refund: `xbt402_refund` and the expiry watcher broadcast B1's CLTV refund for a
channel the provider never closed. Refused before expiry, idempotent after, refused after a provider
close, always paid to the signer's own hot key, and no new states inside the expiry margin."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentwallet.signer import Signer

from _agp013 import FakeRpc, fund_channel, keyfile_env, write_policy

from xbt402 import ecc
from xbt402.tx import SIGHASH_ALL_UNIFIED, Tx

API = "http://api.test"


class Refund(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        write_policy(self.tmp, refund_margin_blocks=6)
        self.rpc = FakeRpc(height=1000)
        self.s = Signer(self.tmp, rpc=self.rpc)
        # the provider's change / refund output is the hot key, as in open_from_offer
        self.p = fund_channel(self.s.channels, self.rpc, API, expiry=1100, payer_spk=self.s.hot.spk.hex())

    def refund(self, who=API):
        return self.s.handle({"method": "xbt402_refund", "params": {"counterparty": who}})

    def test_refund_before_expiry_refused_and_nothing_signed(self):
        for h in (1000, 1099):
            self.rpc.height = h
            r = self.refund()
            self.assertEqual((r["verdict"], r["rule"]), ("deny", "refund_early"), r)
        self.assertEqual(self.rpc.sent, [])
        self.assertEqual(self.s.sigaudit.read(), [], "no refund signature exists before expiry")

    def test_refund_at_expiry_pays_the_hot_key_and_is_valid(self):
        self.rpc.height = 1100
        r = self.refund()
        self.assertEqual((r["verdict"], r["rule"]), ("allow", "refund"), r)
        tx = Tx.parse(bytes.fromhex(self.rpc.sent[-1]))
        self.assertEqual(tx.locktime, 1100)
        self.assertEqual(tx.inputs[0].sequence, 0xFFFFFFFE)
        self.assertEqual((tx.inputs[0].txid[::-1].hex(), tx.inputs[0].vout), (self.p.funding_txid, 0))
        self.assertEqual([(o.script_pubkey, o.value) for o in tx.outputs], [(self.s.hot.spk, 100_000)])
        sig, empty, script = tx.inputs[0].witness
        self.assertEqual((empty, script, sig[-1]), (b"", self.p.script, SIGHASH_ALL_UNIFIED))
        self.assertTrue(ecc.verify(bytes.fromhex(self.p.payer_pub), self.p.sighash(tx), sig[:-1]))
        self.assertEqual(self.s.hot.balance_sats(), 100_000)
        self.assertEqual(self.s.channels.get(API).state, "refunded")
        row = self.s.sigaudit.read()[-1]
        self.assertEqual((row["kind"], row["chan"], row["rule"], row["locktime"]),
                         ("refund", self.p.channel_id, "policy:refund_enabled", 1100))

    def test_no_double_refund(self):
        self.rpc.height = 1100
        first = self.refund()
        again = self.refund(self.p.channel_id)       # by channel id this time
        self.assertTrue(again["already"])
        self.assertEqual(again["txid"], first["txid"])
        self.assertEqual(len(self.rpc.sent), 1, "one refund broadcast, never two")
        self.assertEqual(self.s.watch_tick(), [], "the watcher leaves a refunded channel alone")
        self.assertEqual(len(self.rpc.sent), 1)

    def test_no_refund_after_a_provider_close(self):
        self.rpc.utxos.pop((self.p.funding_txid, 0))         # the provider's close spent the funding
        self.rpc.spenders[(self.p.funding_txid, 0)] = "ee" * 32
        self.rpc.height = 1200
        r = self.refund()
        self.assertEqual((r["verdict"], r["rule"], r["closed_txid"]), ("deny", "channel_closed", "ee" * 32), r)
        self.assertEqual(self.s.channels.get(API).state, "closed")
        self.assertEqual(self.rpc.sent, [])
        self.assertEqual(self.refund()["rule"], "channel_closed")
        self.assertEqual([x["kind"] for x in self.s.sigaudit.read()], [], "nothing signed")

    def test_cooperative_close_marks_the_channel_closed(self):
        self.s.channels.mark_closed(API, "dd" * 32)
        self.rpc.height = 1200
        self.assertEqual(self.refund()["rule"], "channel_closed")
        self.assertEqual(self.rpc.sent, [])

    def test_watcher_refunds_at_expiry_only(self):
        self.rpc.height = 1099
        self.assertEqual(self.s.watch_tick(), [])
        self.assertEqual(self.rpc.sent, [])
        self.rpc.height = 1100
        acts = self.s.watch_tick()
        self.assertEqual([(a["dest"], a["verdict"], a["rule"]) for a in acts], [(API, "allow", "refund")])
        row = self.s.sigaudit.read()[-1]
        self.assertEqual((row["kind"], row["method"], row["rule"]), ("refund", "watcher", "watcher:auto_refund"))
        self.assertEqual(self.s.channels.get(API).state, "refunded")

    def test_no_new_state_inside_the_expiry_margin(self):
        self.rpc.height = 1093                      # expiry 1100 - margin 6 = 1094
        r = self.s.handle({"method": "sign_state", "params": {"dest": API, "cum": 1000}})
        self.assertTrue(r.get("sig"), r)
        self.rpc.height = 1094
        with self.assertRaises(Exception) as cm:
            self.s.handle({"method": "sign_state", "params": {"dest": API, "cum": 2000}})
        self.assertIn("channel_expiring", str(cm.exception))
        r = self.s.handle({"method": "pay", "params": {"to": API, "amount_sats": 1000}})
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "channel_expiring"), r)

    def test_refused_by_policy_and_for_unknown_channels(self):
        self.assertEqual(self.refund("http://nobody.test")["rule"], "unknown_channel")
        write_policy(self.tmp, refund_enabled=False)
        s2 = Signer(self.tmp, rpc=self.rpc)
        self.rpc.height = 1200
        r = s2.handle({"method": "xbt402_refund", "params": {"counterparty": API}})
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "refund_disabled"))
        self.assertEqual(self.rpc.sent, [])

    def test_refund_destination_cannot_be_chosen(self):
        self.rpc.height = 1100
        r = self.s.handle({"method": "xbt402_refund", "params": {"counterparty": API, "to": "bcrt1qattacker",
                                                                  "dest_spk": "0014" + "66" * 20}})
        self.assertEqual(r["verdict"], "allow")
        self.assertEqual(Tx.parse(bytes.fromhex(self.rpc.sent[-1])).outputs[0].script_pubkey, self.s.hot.spk)

    def test_node_rejection_leaves_the_channel_open(self):
        self.rpc.height = 1100
        self.rpc.reject = "non-final"
        r = self.refund()
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "refund_rejected"))
        self.assertEqual(self.s.channels.get(API).state, "open")
        self.rpc.reject = None
        self.assertEqual(self.refund()["rule"], "refund")

    def test_refund_after_rotation_pays_the_new_hot_key(self):
        self.s.handle({"method": "rotate_hot_key"})
        self.rpc.height = 1100
        self.refund()
        self.assertEqual(Tx.parse(bytes.fromhex(self.rpc.sent[-1])).outputs[0].script_pubkey, self.s.hot.spk)


if __name__ == "__main__":
    unittest.main()
