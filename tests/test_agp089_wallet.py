"""AGP-089 (fix wave 4, wallet): the paths beside the ones the AGP-087 audit tests name, in B2. Each
test states the rule its fix keeps; "fails on 3fab1c9" marks the ones that failed there for that reason.
"""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.approval import b2x, sign, sweep_message, treasury_fund_message, treasury_recover_message
from agentwallet.rpc import KnotsRpcRefused
from agentwallet.signer import Signer
from agentwallet.xbt402 import CallBudget, max_expiry_blocks

from _agp013 import HUMAN_PRIV, FakeRpc
from test_agp087_wallet_b2 import own_rail

from xbt402.tx import Tx as BTx, segwit_address
from xbt402.x402_channel import b64json, unb64json

API = "http://api.test"


def restart(s: Signer) -> Signer:
    return Signer(s.root, rpc=s.rpc)


class OneSignatureOneOperation(unittest.TestCase):
    """Rule: one signed message authorises one operation, once (`UsedSigs`)."""

    def sweep(self, s: Signer, exp: int) -> dict:
        to = segwit_address("bcrt", bytes.fromhex("0014" + "77" * 20))
        return {"to": to, "amount_sats": 50_000, "expiry": exp,
                "signature": b2x(sign(HUMAN_PRIV, sweep_message(s.hot.address, to, 50_000, exp)))}

    def test_a_restart_does_not_forget_a_used_signature_and_a_new_one_works(self):
        """Fails on 3fab1c9: the replay after the restart sweeps again."""
        s = own_rail(FakeRpc(height=1000, track_outputs=True))
        exp = int(s.engine.clock()) + 600
        p = self.sweep(s, exp)
        self.assertTrue(s.handle({"method": "sweep_hot", "params": dict(p)}).get("ok"))
        s2 = restart(s)
        again = s2.handle({"method": "sweep_hot", "params": dict(p)})
        self.assertEqual((again.get("ok"), again.get("rule")), (False, "human_sig_replay"), again)
        self.assertEqual(len(s.rpc.sent), 1)
        fresh = s2.handle({"method": "sweep_hot", "params": self.sweep(s2, exp + 1)})   # the human signs again
        self.assertTrue(fresh.get("ok"), fresh)

    def test_an_unreadable_used_signature_file_refuses_the_operation(self):
        """Never taken for empty: with the file unreadable no human-signed operation runs."""
        s = own_rail(FakeRpc(height=1000, track_outputs=True))
        (s.root / ".run" / "human_sigs.json").write_text("{ not json")
        r = s.handle({"method": "sweep_hot", "params": self.sweep(s, int(s.engine.clock()) + 600)})
        self.assertFalse(r.get("ok"), r)
        self.assertEqual(s.rpc.sent, [])

    def test_a_sweep_refused_for_its_address_does_not_cost_the_signature(self):
        s = own_rail(FakeRpc(height=1000, track_outputs=True))
        exp = int(s.engine.clock()) + 600
        bad = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"          # another network's address
        p = {"to": bad, "amount_sats": 50_000, "expiry": exp,
             "signature": b2x(sign(HUMAN_PRIV, sweep_message(s.hot.address, bad, 50_000, exp)))}
        self.assertFalse(s.handle({"method": "sweep_hot", "params": p}).get("ok"))
        self.assertFalse((s.root / ".run" / "human_sigs.json").exists(), "a refused request used a signature")


class TreasuryForgetsNoOutpoint(unittest.TestCase):
    def fund(self, s: Signer, sats: int, exp: int) -> dict:
        sig = sign(HUMAN_PRIV, treasury_fund_message(s.hot.address, s.treasury.address, sats, exp))
        return s.handle({"method": "fund_treasury", "params": {"sats": sats, "expiry": exp, "signature": b2x(sig)}})

    def test_two_fundings_the_human_signed_are_both_recorded_and_both_recovered(self):
        """Fails on 3fab1c9: the second funding overwrote the one recorded outpoint, and
        recover_treasury then reached only the second (AGP-085 found-not-fixed 5)."""
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = own_rail(rpc)
        exp = int(s.engine.clock()) + 600
        first = self.fund(s, 100_000, exp)["treasury_outpoint"]
        second = self.fund(s, 60_000, exp + 1)["treasury_outpoint"]
        self.assertNotEqual(first, second)
        st = restart(s).treasury.status()
        self.assertEqual((st["treasury_outpoint"], st["treasury_earlier_outpoints"], st["treasury_earlier_sats"]),
                         (second, [first], 100_000))
        dest = segwit_address("bcrt", bytes.fromhex("0014" + "55" * 20))
        rexp = int(s.engine.clock()) + 600
        sig = sign(HUMAN_PRIV, treasury_recover_message(s.treasury.address, dest, rexp))
        before = len(rpc.sent)
        r = s.handle({"method": "recover_treasury", "params": {"to": dest, "expiry": rexp, "signature": b2x(sig)}})
        self.assertTrue(r.get("ok"), r)
        spent = {f"{i.txid[::-1].hex()}:{i.vout}" for raw in rpc.sent[before:] for i in BTx.parse(bytes.fromhex(raw)).inputs}
        self.assertEqual(spent, {first, second}, r)

    def test_a_malformed_earlier_funding_is_refused_not_read_as_none(self):
        s = own_rail(FakeRpc(height=1000, track_outputs=True))
        path = s.root / ".run" / "treasury.json"
        doc = json.loads(path.read_text())
        doc["earlier_fundings"] = [{"txid": "zz", "vout": 0}]
        path.write_text(json.dumps(doc))
        with self.assertRaises(Exception):
            restart(s)


class SellerNumbers(unittest.TestCase):
    """Rule: a call never raises what its channel's ledger holds by more than max_sats, and a seller's
    offer never locks coins past the owner's bound, whatever the seller's numbers are."""

    def test_the_budget_counts_from_the_ledger(self):
        b = CallBudget(1_000, 500)
        self.assertTrue(b.fits(1_500))
        self.assertFalse(b.fits(1_501))
        self.assertEqual(b.left(1_200), 300)

    def test_a_manifest_whose_numbers_are_not_whole_is_refused_with_nothing_signed(self):
        """Fails on 3fab1c9 for the negative price (-1000 x 4 is "under budget") and raises for the
        others (a float n, a string price) from inside the call."""
        from test_m7_final_chunk import ORIGIN, PRICE, Rig

        for key, value in (("price", -PRICE), ("price", "1000"), ("n", 4.0), ("n", True), ("n", 0)):
            r = Rig()
            m = copy.deepcopy(r.c.manifest)
            m[key] = value
            before = r.book.get(ORIGIN).used_sats
            with mock.patch("agentwallet.xbt402.check_manifest", lambda m, pay_to: None):
                out = r.s.stream(ORIGIN, {"payTo": m["payTo"]}, {"manifest": m, "chunkUrl": "/c/{i}"}, 1_000_000)
            self.assertFalse(out["stream"]["ok"], (key, value, out))
            self.assertEqual(r.book.get(ORIGIN).used_sats, before, (key, value))

    def test_min_conf_and_close_margin_are_held_to_the_owners_bound_too(self):
        """Fails on 3fab1c9: only the offer's own maxExpiryBlocks bounded these."""
        from test_mainnet_readiness import URL, Rig

        self.assertEqual(max_expiry_blocks(1_008), 4_032)
        for key, value in (("minConf", 400_000), ("closeMarginBlocks", 10**12), ("minExpiryBlocks", 4_100)):
            rig = Rig(regtest_mine=None)
            rig.fund_hot()

            def http(method, url, body=b"", headers=None, key=key, value=value, rig=rig):
                path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
                if path.endswith("/open") and json.loads(body or b"{}").get("preflight") is True:
                    return 200, {}, json.dumps({"preflight": True}).encode()
                st, h, out = rig.provider.serve(method, path, headers or {}, body or b"", url)
                if st == 402 and "PAYMENT-REQUIRED" in h:
                    pr = unb64json(h["PAYMENT-REQUIRED"])
                    for acc in pr["accepts"]:
                        acc["extra"][key] = value
                        acc["extra"]["maxExpiryBlocks"] = 10**13
                    h = {**h, "PAYMENT-REQUIRED": b64json(pr)}
                return st, h, out

            with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=http):
                r = rig.signer.handle({"method": "xbt402_pay", "params": {"url": URL, "max_sats": 500}})
            self.assertEqual((r.get("verdict"), r.get("rule")), ("deny", "expiry"), (key, r))
            self.assertIsNone(rig.channel(), key)
            self.assertEqual(rig.node.sent, [], key)


class DeadFunding(unittest.TestCase):
    """Rule: a kept funding frees its destination only on proof that it can never confirm: our node
    names another transaction that spent one of its inputs. (The audit's evidence test keeps the
    other half: with no such proof the record stays pending.)"""

    def test_a_kept_funding_whose_input_another_transaction_spent_frees_its_destination(self):
        """Fails on 3fab1c9: the refund answers funding_unknown for good."""
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = own_rail(rpc)
        real = rpc.call

        def call(method, *p):
            if method == "sendrawtransaction" and call.answer is not None:
                raise call.answer
            return real(method, *p)

        call.answer = TimeoutError("timed out")                 # the node never got the funding
        rpc.call = call
        try:
            s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000}})
        except Exception:
            pass
        rec = s.channels.get(API)
        self.assertEqual(rec.state, "pending")
        call.answer = KnotsRpcRefused('{"code":-25,"message":"bad-txns-inputs-missingorspent"}')
        rpc.height = rec.expiry + 10
        self.assertEqual(s.watch_tick()[0].get("rule"), "funding_unknown", "no proof yet: it stays pending")
        # another transaction spent the funding's input, and our node names it
        for i in BTx.parse(bytes.fromhex(rec.funding_hex)).inputs:
            op = (i.txid[::-1].hex(), i.vout)
            rpc.utxos.pop(op, None)
            rpc.spenders[op] = "ee" * 32
        acts = s.watch_tick()
        self.assertEqual(acts[0].get("rule"), "funding_dead", acts)
        self.assertEqual(s.channels.get(API).state, "closed")
        self.assertTrue(s.channels._secrets.get(rec.chan), "the dead funding's key is still in the book")
        call.answer = None
        s.hot.notice_utxo("bb" * 32, 0, 300_000)
        r = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000}})
        self.assertEqual(r.get("verdict"), "allow", r)


class RustRecordFields(unittest.TestCase):
    def test_a_record_with_the_rust_signers_rolled_next_loads_and_is_written_back(self):
        """The Rust signer keeps the next channels a rollover may fund in `rolled_next` (AGP-089). B2
        signs no rollover; a file that has the field must load and keep it."""
        from agentwallet.channels import ChannelRecord, _omit_legacy_booking
        from dataclasses import asdict

        nxt = [{"spk": "00" * 34, "next": {"expiry": 5}}]
        rec = ChannelRecord(**{**asdict(ChannelRecord(dest=API, chan="c", cap_sats=1, used_sats=0, expiry=9, payer_pub="", payee_pub="",
                                                      close_fee=0, payer_spk="", payee_spk="", funding_txid="", funding_vout=0,
                                                      funding_sats=1, seq=0)), "rolled_next": nxt})
        self.assertEqual(_omit_legacy_booking(asdict(rec))["rolled_next"], nxt)
        self.assertNotIn("rolled_next", _omit_legacy_booking(asdict(ChannelRecord(**{**asdict(rec), "rolled_next": []}))))


if __name__ == "__main__":
    unittest.main()
