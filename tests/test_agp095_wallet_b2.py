"""AGP-095, fix wave 5, B2 wallet. The third audit's own tests for these items are in
test_agp093_wallet_b2.py; the tests here cover what the audit had "from reading" or ran in Rust
only, the paths beside each named one, and each rule this wave added at its bound. `test_control_`
tests passed before the fix too: they pin what a rule must not change.

item 3   one new state per call, only when the seller holds the last one (xbt402.py pay_once)
item 4   the offer's expiry window has a floor; a negative price funds nothing (open_from_offer)
item 9   a lot belongs to its own channel: the next channel's refund does not void it (signer.py)
item 16  a used human signature and the highest clock the file has seen (approval.py UsedSigs)
item 17  a close that is only in the mempool is not proven (close_channel, funding_spent)
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.approval import SigExpired, UsedSigs, b2x, sign, sweep_message

from _agp013 import HUMAN_PRIV, FakeRpc, fund_channel
from test_agp087_wallet_b2 import own_rail
from test_agp087_wallet_b2_evidence import API, signer
import test_agp093_wallet_b2 as t93          # the module, so its test classes are not collected here again

from xbt402.tx import segwit_address
from xbt402.x402_channel import XbtChannelClient, b64json, unb64json


def ledger_sum(s) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


DEST = t93.DEST


# --- item 3 -----------------------------------------------------------------------------------------------
class OneNewStatePerCall(t93.LostAnswers):
    """The rig of the audit's LostAnswers (B1's provider behind the wallet's own pay rail)."""

    test_hole_one_lost_answer_does_not_end_a_channel_to_a_prepay_provider = None
    test_hole_two_lost_answers_do_not_end_a_channel_to_a_postpay_provider = None
    test_control_no_lost_answer_and_one_lost_answer_on_postpay_go_on = None

    def pay(self, max_sats: int = 2_000) -> dict:
        return self.signer._xbt402_pay_locked({"url": DEST + "/v1/x", "method": "GET", "body": "", "max_sats": max_sats})

    def test_a_lost_answer_costs_one_new_state_and_the_channel_goes_on(self):
        """Failed before the fix: every call after the lost answer was 402 (the audit's test); this
        one also pins what the resync signs."""
        self.rig("prepay")
        self.assertEqual(self.pay()["status"], 200)
        self.lose = 1
        self.assertIsNone(self.pay().get("status"))
        lost = self.book.get(DEST).used_sats
        r = self.pay()
        rec = self.book.get(DEST)
        self.assertEqual((r["status"], r["booked_sats"]), (200, self.PRICE), r)
        self.assertEqual((rec.used_sats, rec.acked_sats), (lost + self.PRICE, lost + self.PRICE))
        for _ in range(3):
            before = self.book.get(DEST).used_sats
            self.assertEqual(self.pay()["status"], 200)
            self.assertEqual(self.book.get(DEST).used_sats, before + self.PRICE)

    def test_control_a_request_lost_on_the_way_out_is_paid_once(self):
        """Why a state is sent again at all: a request that never reached the seller was not served,
        so the call after it is paid by the same state."""
        self.rig("prepay")
        self.assertEqual(self.pay()["status"], 200)
        real = XbtChannelClient.http

        def dropped(method, url, body=b"", headers=None):
            if "PAYMENT-SIGNATURE" in (headers or {}):
                raise ConnectionError("the request never left")
            return real(method, url, body, headers)

        with mock.patch.object(XbtChannelClient, "http", staticmethod(dropped)):
            self.assertIsNone(self.pay().get("status"))
        signed = self.book.get(DEST).used_sats
        r = self.pay()
        self.assertEqual((r["status"], r["booked_sats"], self.book.get(DEST).used_sats), (200, 0, signed), r)

    def forged(self, make):
        """Every paid request is answered by `make(payload)` and never shown to the provider."""
        real = XbtChannelClient.http

        def http(method, url, body=b"", headers=None):
            if "PAYMENT-SIGNATURE" in (headers or {}):
                return make(unb64json(headers["PAYMENT-SIGNATURE"])["payload"])
            return real(method, url, body, headers)

        return mock.patch.object(XbtChannelClient, "http", staticmethod(http))

    @staticmethod
    def refusal(error, chan, cum, seq):
        pr = {"x402Version": 2, "error": error, "accepts": [], "channel": {"chan": chan, "cum": cum, "seq": seq, "spentMsat": "0"}}
        return 402, {"PAYMENT-REQUIRED": b64json(pr)}, b""

    def test_a_402_signs_one_state_only_when_it_names_the_state_just_sent(self):
        """The 402 is the seller's unsigned word, so anyone on the path can write one. What it can do
        is bounded by the rule: one new state per call, inside that call's max_sats and booked. A
        402 that does not name this channel's last state and this request, or that refuses for
        another reason, signs nothing."""
        wrong = {
            "another reason": lambda p: self.refusal("channel_closing", p["chan"], p["cum"], p["seq"]),
            "a lower cum": lambda p: self.refusal("insufficient_payment", p["chan"], "546", p["seq"]),
            "another request's seq": lambda p: self.refusal("insufficient_payment", p["chan"], p["cum"], 1),
            "another channel": lambda p: self.refusal("insufficient_payment", "00" * 32 + ":0", p["cum"], p["seq"]),
            "no channel in the 402": lambda p: (402, {"PAYMENT-REQUIRED": b64json({"error": "insufficient_payment"})}, b""),
            "numbers that are not numbers": lambda p: self.refusal("insufficient_payment", p["chan"], "x", None),
        }
        for what, make in wrong.items():
            self.rig("prepay")
            self.assertEqual(self.pay()["status"], 200)
            self.lose = 1
            self.pay()
            signed = self.book.get(DEST).used_sats
            with self.forged(make):
                for _ in range(3):
                    self.assertEqual(self.pay().get("booked_sats", 0), 0, what)
            self.assertEqual(self.book.get(DEST).used_sats, signed, what)
        self.rig("prepay")
        self.assertEqual(self.pay()["status"], 200)
        self.lose = 1
        self.pay()
        signed = self.book.get(DEST).used_sats
        with self.forged(lambda p: self.refusal("insufficient_payment", p["chan"], p["cum"], p["seq"])):
            for call in range(1, 5):
                self.pay()
                self.assertEqual(self.book.get(DEST).used_sats, signed + self.PRICE * call,
                                 f"call {call}: one state of one price, never two")


# --- item 4 -----------------------------------------------------------------------------------------------
class OfferWindow(unittest.TestCase):
    def pay(self, *, min_expiry: int, max_expiry: int, amount: str | None = None, max_sats: int = 500, **policy):
        from test_mainnet_readiness import URL, Rig

        rig = Rig(regtest_mine=None, **policy)
        rig.fund_hot()

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
            if path.endswith("/open") and json.loads(body or b"{}").get("preflight") is True:
                return 200, {}, json.dumps({"preflight": True}).encode()       # the seller's word
            st, h, out = rig.provider.serve(method, path, headers or {}, body or b"", url)
            if st == 402 and "PAYMENT-REQUIRED" in h:
                pr = unb64json(h["PAYMENT-REQUIRED"])
                for acc in pr["accepts"]:
                    acc["extra"].update(minExpiryBlocks=min_expiry, maxExpiryBlocks=max_expiry, closeMarginBlocks=0)
                    if amount is not None:
                        acc["amount"] = amount
                h = {**h, "PAYMENT-REQUIRED": b64json(pr)}
            return st, h, out

        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=http):
            r = rig.signer.handle({"method": "xbt402_pay", "params": {"url": URL, "max_sats": max_sats}})
        return rig, r

    def test_a_sellers_window_shorter_than_a_day_is_not_funded(self):
        """The audit ran this in Rust only (item 4); B2's open_from_offer had the same test,
        `0 < blocks <= most`. Failed before the fix: funded, with 1, 7, 49 and 143 blocks to expiry."""
        for window in (2, 8, 50, 144):
            rig, r = self.pay(min_expiry=1, max_expiry=window)
            self.assertIsNone(rig.channel(), f"window {window}: {r}")
            self.assertEqual((r["verdict"], len(rig.node.sent)), ("deny", 0), f"window {window}: {r}")

    def test_control_a_day_long_window_is_funded(self):
        rig, r = self.pay(min_expiry=1, max_expiry=145)
        rec = rig.channel()
        self.assertIsNotNone(rec, r)
        self.assertEqual(rec.expiry - rec.open_height, 144)

    def test_a_negative_price_funds_nothing(self):
        """Failed before the fix: a free-only call (max_sats 0) and a paying one both funded a channel
        at price -1."""
        for max_sats in (0, 500):
            rig, r = self.pay(min_expiry=1_008, max_expiry=8_640, amount="-1", max_sats=max_sats)
            self.assertIsNone(rig.channel(), f"max_sats {max_sats}: {r}")
            self.assertEqual(len(rig.node.sent), 0)


# --- item 9 -----------------------------------------------------------------------------------------------
class ALotAndTheNextChannelsRefund(unittest.TestCase):
    def test_the_next_channels_refund_does_not_void_a_lot_of_the_channel_before_it(self):
        """The audit had this from reading (signer.py:591-594). The market closed the lot's channel,
        in a block, with the completed state; a plain call opened the next channel; that one is
        refunded at its expiry. The earlier lot was paid for and must stay recoverable.

        Failed before the fix: the watcher filed the lot void on the other channel's refund and
        released its booking; forward_recover then had nothing to recover."""
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.m.withhold = True
        t.buy()
        close = t.m.close_with_last_state()
        t.rpc.txs[close]["confirmations"] = 6
        t.rpc.height = 8000
        t.s.watch_tick()
        self.assertEqual(t.s.channels.get(MARKET).state, "closed")
        nxt = fund_channel(t.s.channels, t.rpc, MARKET, secret=0xA11CF, expiry=9000, capacity=10_000_600,
                           payer_spk=t.s.hot.spk.hex())
        t.rpc.height = 9000
        r = t.s.handle({"method": "xbt402_refund", "params": {"counterparty": MARKET}})
        self.assertEqual((r["rule"], t.s.channels.get(MARKET).chan), ("refund", nxt.channel_id), r)
        t.rpc.height = 9002                                    # the refund is in a block
        acts = t.s.watch_tick()
        st = t.s.handle({"method": "forward_status"})
        self.assertIn(MARKET, st["pending"], f"the next channel's refund voided the earlier channel's lot: {acts}")
        self.assertEqual(st["spent_24h_sats"], PRICE)
        rec = t.s.handle({"method": "forward_recover", "params": {"txid": close}})
        self.assertTrue(rec.get("recovered"), rec)
        self.assertEqual(t.s.channels.get(MARKET).chan, nxt.channel_id, "the dest's record is still the next channel")
        self.assertEqual(t.s.channels.get(MARKET).state, "refunded")


# --- item 16 ----------------------------------------------------------------------------------------------
class UsedSignaturesAndTheClock(unittest.TestCase):
    def test_a_used_signature_stays_used_when_the_clock_goes_back(self):
        """The audit's Rust test (hole 5), in B2. Failed before the fix: the second sweep ran."""
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = own_rail(rpc)
        now = [int(s.engine.clock())]
        s.engine.clock = lambda: now[0]
        to = segwit_address("bcrt", bytes.fromhex("0014" + "77" * 20))

        def sweep(sats: int, exp: int) -> dict:
            return {"to": to, "amount_sats": sats, "expiry": exp,
                    "signature": b2x(sign(HUMAN_PRIV, sweep_message(s.hot.address, to, sats, exp)))}

        t0 = now[0]
        first = sweep(20_000, t0 + 60)
        self.assertTrue(s.handle({"method": "sweep_hot", "params": dict(first)}).get("ok"))
        now[0] = t0 + 120
        self.assertTrue(s.handle({"method": "sweep_hot", "params": sweep(21_000, t0 + 400)}).get("ok"))   # prunes the first
        now[0] = t0 + 30                                        # the clock steps back inside the first one's window
        sent = len(rpc.sent)
        again = s.handle({"method": "sweep_hot", "params": dict(first)})
        self.assertFalse(again.get("ok"), again)
        self.assertEqual(len(rpc.sent), sent, "nothing was swept a second time")
        # a signature whose expiry is ahead of every clock the file has seen still works
        self.assertTrue(s.handle({"method": "sweep_hot", "params": sweep(22_000, t0 + 500)}).get("ok"))

    def test_the_store_keeps_the_highest_clock_and_refuses_what_is_behind_it(self):
        path = Path(tempfile.mkdtemp()) / "human_sigs.json"
        u = UsedSigs(path)
        self.assertTrue(u.spend(b"a", 1_060, 1_000))
        self.assertFalse(u.spend(b"a", 1_060, 1_000))
        self.assertTrue(u.spend(b"b", 1_400, 1_120))             # prunes a: its expiry is behind 1,120
        doc = json.loads(path.read_text())
        self.assertEqual((doc["clock"], len(doc["used"])), (1_120, 1))
        with self.assertRaises(SigExpired):
            u.spend(b"a", 1_060, 1_030)                          # the clock went back; a is not in the file any more
        with self.assertRaises(SigExpired):
            u.spend(b"never used", 1_100, 1_030)                 # nor can it be told from one that was
        self.assertEqual(json.loads(path.read_text())["clock"], 1_120, "a step back does not lower the stored clock")

    def test_a_file_from_before_the_clock_loads_and_a_bad_clock_refuses(self):
        path = Path(tempfile.mkdtemp()) / "human_sigs.json"
        path.write_text(json.dumps({"used": {"ab": 1_050}}))
        u = UsedSigs(path)
        self.assertTrue(u.spend(b"x", 1_060, 1_000))
        doc = json.loads(path.read_text())
        self.assertEqual((doc["clock"], sorted(doc["used"].values())), (1_000, [1_050, 1_060]))
        for bad in ("soon", True, None, [1]):
            path.write_text(json.dumps({"used": {}, "clock": bad}))
            with self.assertRaises(RuntimeError) as e:
                u.spend(b"y", 1_070, 1_000)
            self.assertNotIsInstance(e.exception, SigExpired, bad)


# --- item 17 ----------------------------------------------------------------------------------------------
class ACooperativeCloseInTheMempool(unittest.TestCase):
    def test_a_close_the_provider_broadcast_is_proven_by_its_block_not_by_the_mempool(self):
        """The audit's test takes the refund path; this is `close_channel` and the watcher's proof.
        The provider answers 200 and its close is in our mempool: closed, not proven, the dest not
        free for a new channel. In a block: proven. Failed before the fix: proven at once."""
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = signer(Path(tempfile.mkdtemp()), rpc, regtest_mine=False)     # no block is mined for the close
        r = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000, "expiry_blocks": 50}})
        self.assertEqual(r["state"], "open", r)
        rec = s.channels.get(API)
        sig = s.handle({"method": "sign_state", "params": {"dest": API, "cum": 10_000}})["sig"]
        p = rec.params()
        close = p.state_tx(10_000)
        close.inputs[0].witness = [b"", bytes.fromhex(sig), os.urandom(71), p.script]

        def http(method, url, body=b"", headers=None):
            txid = rpc.call("sendrawtransaction", close.hex())      # on our node too: in the mempool at height 1000
            return 200, {}, json.dumps({"txid": txid, "cum": 10_000, "unpaidMsat": 0}).encode()

        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            r = s.handle({"method": "close_channel", "params": {"counterparty": API}})
        got = s.channels.get(API)
        self.assertEqual((r["verdict"], r["close_proven"], got.state, got.close_unproven), ("allow", False, "closed", True), r)
        again = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000, "expiry_blocks": 50}})
        self.assertEqual(again.get("rule"), "close_unproven", again)
        rpc.height = 1001                                           # the close is mined
        acts = s.handle({"method": "watch_tick"})["actions"]
        got = s.channels.get(API)
        self.assertEqual((got.state, got.close_unproven, got.closed_txid), ("closed", False, close.txid()), acts)

    def test_a_close_that_leaves_the_mempool_unmined_is_refunded_at_expiry(self):
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = signer(Path(tempfile.mkdtemp()), rpc)
        self.assertEqual(s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000, "expiry_blocks": 50}})["state"], "open")
        rec = s.channels.get(API)
        sig = s.handle({"method": "sign_state", "params": {"dest": API, "cum": 10_000}})["sig"]
        p = rec.params()
        close = p.state_tx(10_000)
        close.inputs[0].witness = [b"", bytes.fromhex(sig), os.urandom(71), p.script]
        txid = rpc.call("sendrawtransaction", close.hex())
        rpc.unmined.add(txid)                                       # no block ever takes it
        rpc.height = rec.expiry
        acts = s.handle({"method": "watch_tick"})["actions"]
        self.assertEqual([a.get("rule") for a in acts if a.get("chan") == rec.chan], ["close_unconfirmed"], acts)
        self.assertEqual(s.channels.get(API).state, "open", "still with the watcher")
        # it leaves the mempool: the funding output is unspent again
        rpc.utxos[(rec.funding_txid, 0)] = rpc.spent.pop((rec.funding_txid, 0))
        del rpc.spenders[(rec.funding_txid, 0)], rpc.txs[txid]
        rpc.height += 1
        acts = s.handle({"method": "watch_tick"})["actions"]
        self.assertEqual([a.get("rule") for a in acts if a.get("chan") == rec.chan], ["refund"], acts)


if __name__ == "__main__":
    unittest.main()
