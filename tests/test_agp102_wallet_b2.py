"""AGP-102 (fourth closure audit), area wallet_b2: what is still open on B2 ce81710 after fix wave 5.
Every test whose name starts with `test_hole_` FAILS today and names the rule that should hold; the
`test_control_` tests pass and show the honest path in the same rig. No fix here. The numbers are the
report's (xbt-rs-agp-102/run/agp102_wallet_b2.md, section Holes).

hole 1  forward rail, new in wave 5. AGP-095 made `forward_recover` find a lot by its own channel,
    live or archived (forward.py:261), and `_delivered` raise the archived record (forward.py:231-232).
    The signer then books the recovered lot with `_book_forward(res["dest"], ...)` (signer.py:355),
    which ends in `mark_ledger_booked(dest, cum)` (signer.py:1176-1177): by dest, so on the dest's
    CURRENT channel. After a replacement that is the next channel, whose booked high-water mark jumps
    to the earlier lot's cum. Every state the next channel signs below that mark is then signed with
    no ledger row and no policy evaluation (`_booked_increase` signer.py:918-928, `_book_unbooked`
    xbt402.py:499-501, `_book_through` xbt402.py:485-487).
hole 2  the rule AGP-095 added, "a channel leaves the refund watch only when our node shows its funding
    spent in a block", is not kept by `forward_recover`: a close that carries the completed lot state
    and is only in the mempool marks the live record closed, proven (forward.py:271-272,
    channels.py:746-748), and the watcher never looks at it again. On a node without txindex the
    MCP tool finds a close only while it is unconfirmed, so that is the path it takes there.
hole 3  AGP-095 found-not-fixed 3, run here against B1's provider: on a postpay channel that is one
    call behind (one lost answer, served on credit), a stream's first chunk is asked for with the
    unchanged state (xbt402.py:759-761), the provider answers 402 `insufficient_payment`
    (b1 x402_channel.py:1693-1696), and the stream path ends the stream on any non-200
    (xbt402.py:763-764). The manifest call was paid; this repeats on every stream for the rest of
    the channel's life.
hole 4  (Low, left from before) a refund that loses to the seller's close is never noticed: the record
    stays `refunded` with a txid that is in no block, and the hot wallet keeps counting the refund's
    output (signer.py:520-522) and never learns the close's change.
hole 5  (Low, new in wave 5) "a void lot's row is never lowered below what the voiding close paid":
    `paid` is every output of the spend that is not the record's `payer_spk` (forward.py:296). The
    wallet's own refund pays the CURRENT hot key (signer.py:515), which is another script once the
    hot key was rotated after the channel opened, so `forward_recover(refund txid)` reports the whole
    refund as paid away and the ledger keeps the lot's row for a payment that came back.
hole 6  (Low, new in wave 5) `spent_in_mempool_only` answers False when the node cannot be asked
    (netparams.py:147-152, "the caller's other checks decide"), and the callers' other checks then
    take the funding for spent in a block: `_refund_locked` marks the record closed on
    `rec.funding_height or get_tx(funding)` (signer.py:488-496) and `funding_spent` answers ""
    (xbt402.py:1018-1024). So a node that answers the first `gettxout` and fails the next two calls
    turns a mempool-only close into "closed for good": the rule fails open on its own node's error.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agentwallet.forward import ForwardSession
from agentwallet.signer import Signer
from agentwallet.stream import Commitment

from _agp013 import PAY_TO, FakeRpc, fund_channel
from test_agp087_wallet_b2_evidence import API, signer
import test_agp093_wallet_b2 as t93          # the module, so its test classes are not collected here again

from xbt402.tx import Tx as BTx
from xbt402.x402_channel import XbtChannelClient, network_id


def ledger_sum(s) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


def spends(rpc, txid: str) -> list[str]:
    """The transactions sent to the node that spend output 0 of `txid`."""
    return [raw for raw in rpc.sent
            if any((i.txid[::-1].hex(), i.vout) == (txid, 0) for i in BTx.parse(bytes.fromhex(raw)).inputs)]


# --- hole 1 -----------------------------------------------------------------------------------------------
class ARecoveredLotAndTheNextChannelsLedger(unittest.TestCase):
    MORE = 2_000_000           # what the next channel signs afterwards

    def run_it(self, recover: bool, lot: bool = False):
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.m.withhold = True
        t.buy()                                   # the market holds the pre-signature and answers nothing,
        close = t.m.close_with_last_state()       # then closes with the completed state, in a block
        t.rpc.txs[close]["confirmations"] = 6
        t.rpc.height = 8000
        t.s.watch_tick()
        self.assertEqual(t.s.channels.get(MARKET).state, "closed")
        nxt = fund_channel(t.s.channels, t.rpc, MARKET, secret=0xA11CF, expiry=9000, capacity=10_000_600,
                           payer_spk=t.s.hot.spk.hex())          # a plain call opened the next channel
        self.assertEqual((ledger_sum(t.s), t.s.channels.get(MARKET).ledger_booked_sats), (PRICE, 0))
        if recover:
            r = t.s.handle({"method": "forward_recover", "params": {"txid": close}})
            self.assertTrue(r.get("recovered"), r)
        rec = t.s.channels.get(MARKET)
        self.assertEqual((rec.chan, rec.used_sats), (nxt.channel_id, 0))
        if lot:                                   # the next lot, on the next channel; the market withholds again
            t.m.p = nxt
            r = t.buy(1)
            self.assertEqual((r.get("delivered"), t.m.last["cum"]), (False, PRICE), r)
        else:
            r = t.s.handle({"method": "sign_state", "params": {"dest": MARKET, "cum": self.MORE}})
            self.assertEqual((r.get("verdict"), bool(r.get("sig"))), ("allow", True), r)
        return t, PRICE, rec

    def test_hole_a_lot_recovered_after_its_channel_was_replaced_does_not_unbook_the_next_channel(self):
        t, PRICE, rec = self.run_it(recover=True)
        self.assertEqual(
            ledger_sum(t.s), PRICE + self.MORE,
            f"the earlier channel paid the market {PRICE} sat for the lot and the next channel has now signed a state "
            f"for {self.MORE} sat more; the ledger holds {ledger_sum(t.s)} sat in {len(t.s.engine.store.payments())} "
            f"row(s). forward_recover set the next channel's ledger_booked_sats to {rec.ledger_booked_sats} (the "
            f"earlier lot's cum), so that state was signed with no policy evaluation and no row")

    def test_hole_the_next_lots_pre_signature_on_the_next_channel_is_booked_before_it_leaves(self):
        t, PRICE, _ = self.run_it(recover=True, lot=True)
        self.assertEqual(
            ledger_sum(t.s), 2 * PRICE,
            f"the market was paid {PRICE} sat for the first lot and now holds a pre-signature worth {PRICE} sat on the "
            f"next channel, which it completes alone; the ledger holds {ledger_sum(t.s)} sat (AGP-080 W1: a lot is "
            f"booked before its pre-signature exists)")

    def test_control_without_the_recovery_the_next_channels_state_is_booked(self):
        t, PRICE, _ = self.run_it(recover=False)
        self.assertEqual(ledger_sum(t.s), PRICE + self.MORE)


# --- hole 2 -----------------------------------------------------------------------------------------------
class ForwardRecoverAndACloseInTheMempool(unittest.TestCase):
    def run_it(self, recover: bool):
        from test_forward_rail import MARKET, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.m.withhold = True
        t.buy()
        close = t.m.close_with_last_state()       # in our node's mempool: no block, no confirmations
        fop = (t.p.funding_txid, 0)
        named = t.rpc.call("gettxspendingprevout", [{"txid": fop[0], "vout": 0}])[0]
        self.assertEqual(named.get("spendingtxid"), close, "the double names it as a mempool spender")
        rec = None
        if recover:
            r = t.s.handle({"method": "forward_recover", "params": {"txid": close}})
            self.assertTrue(r.get("recovered"), r)
            rec = t.s.channels.get(MARKET)
        # that close is never mined and leaves the mempool: the funding output is unspent again
        del t.rpc.spenders[fop], t.rpc.txs[close]
        t.rpc.utxos[fop] = {"value": t.p.capacity / 1e8, "scriptPubKey": {"hex": t.p.spk.hex()}}
        for h in (8000, 8001, 8200):              # the channel's expiry is 8000
            t.rpc.height = h
            t.s.watch_tick()
        last = t.s.handle({"method": "xbt402_refund", "params": {"counterparty": MARKET}})
        return t, rec, last

    def test_hole_a_close_seen_only_in_the_mempool_by_forward_recover_does_not_end_the_refund_watch(self):
        t, rec, last = self.run_it(recover=True)
        self.assertEqual(
            len(spends(t.rpc, t.p.funding_txid)), 1,
            f"the funding output ({t.p.capacity} sat) is unspent 200 blocks past its expiry; forward_recover booked a "
            f"close that was only in the mempool as closed for good (state {rec.state!r}, close_unproven "
            f"{rec.close_unproven}) and the wallet never refunds it: {last.get('rule')}")

    def test_control_the_same_close_never_shown_to_forward_recover_is_refunded_at_expiry(self):
        t, _, last = self.run_it(recover=False)
        self.assertEqual(len(spends(t.rpc, t.p.funding_txid)), 1, last)


# --- hole 3 -----------------------------------------------------------------------------------------------
DEST = t93.DEST


class AStreamOneCallBehind(unittest.TestCase):
    """The rig of the third audit's LostAnswers (B1's provider behind the wallet's own pay rail), with a
    handler that sells a three-chunk stream: the manifest at /v1/report/r1, its plain chunks at
    /v1/report/r1/chunk/{i}. Every path costs PRICE. (B1's provider is given no hash-locked offer for
    the last chunk, so a whole stream ends at its last chunk here; the two plain chunks are the test.)"""

    PRICE = 600
    RID = "r1"

    def rig(self):
        import test_request_auth
        import xbt402.x402_channel as xc
        from sechelp import FakeNode, make_provider
        from test_unacked_state import Engine, Rpc

        tmp = Path(tempfile.mkdtemp())
        self.book, _, p = test_request_auth.funded(tmp)
        chunks = Commitment.split(b"".join(b"line %02d of the report\n" % i for i in range(9)), 72)
        self.assertEqual(len(chunks), 3)
        c = Commitment(self.RID, chunks, self.PRICE, PAY_TO, os.urandom(32))
        doc = json.dumps({"stream": "xbt402-merkle-v1", "manifest": c.manifest,
                          "chunkUrl": f"/v1/report/{self.RID}/chunk/{{i}}"}).encode()

        def handler(method, path, body):
            if path == f"/v1/report/{self.RID}":
                return 200, {}, doc
            if path.startswith(f"/v1/report/{self.RID}/chunk/"):
                return 200, {}, json.dumps(c.chunk(int(path.rsplit("/", 1)[1]))).encode()
            return 200, {}, b"ok"

        node = FakeNode()
        prov = make_provider(xc, node, billing="postpay")
        prov.price, prov.handler = (lambda method, path: self.PRICE), handler
        self.assertEqual(prov.network, network_id("11" * 32))
        node.add_funding(p, confirmations=6)
        prov.open({"x402Version": 2, "network": prov.network, "channel": {
            "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
        self.lose, self.chunk_answers = 0, []

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
            st, h, out = prov.serve(method, path, headers or {}, body or b"", url)
            if "PAYMENT-SIGNATURE" in {k.upper() for k in headers or {}}:
                if "/chunk/" in path:
                    self.chunk_answers.append((path.rsplit("/", 1)[1], st))
                if self.lose and st == 200:
                    self.lose -= 1
                    raise ConnectionError("the answer was lost")
            return st, {k.upper(): v for k, v in h.items()}, out

        patch = mock.patch.object(XbtChannelClient, "http", staticmethod(http))
        patch.start()
        self.addCleanup(patch.stop)
        self.signer = Signer.__new__(Signer)
        self.signer.engine = Engine()
        self.signer.config = SimpleNamespace(channel_expiry_blocks=2_000, per_counterparty_cap_sats=50_000)
        session = ForwardSession(self.book, hot=None, rpc=Rpc(), height=lambda: 1_000, forward_path=tmp / "forward.json")
        self.signer._xbt402 = session
        session.set_spend_book(self.signer._book_signed_delta)

    def pay(self, path: str, max_sats: int) -> dict:
        return self.signer._xbt402_pay_locked({"url": DEST + path, "method": "GET", "body": "", "max_sats": max_sats})

    def buy_a_stream(self, lost: int) -> tuple[dict, int]:
        self.rig()
        self.assertEqual(self.pay("/v1/x", 2_000)["status"], 200)
        self.lose = lost
        for _ in range(lost):
            self.assertIsNone(self.pay("/v1/x", 2_000).get("status"), "the answer was lost: an error to the caller")
        self.assertEqual(self.pay("/v1/x", 2_000)["status"], 200, "plain calls go on (the audit's control)")
        before = self.book.get(DEST).used_sats
        r = self.pay(f"/v1/report/{self.RID}", 4 * self.PRICE)
        self.assertEqual(r.get("status"), 200, r)
        return r, self.book.get(DEST).used_sats - before

    def test_hole_a_stream_is_served_on_a_postpay_channel_after_one_lost_answer(self):
        r, signed = self.buy_a_stream(lost=1)
        st = r["stream"]
        self.assertEqual(
            st.get("verified_chunks"), 2,
            f"one answer was lost earlier on this postpay channel, so the seller is owed one call; the wallet paid "
            f"{signed} sat for the manifest and asked for chunk 0 with the unchanged state, the seller answered "
            f"{self.chunk_answers}, and the stream ended: {st.get('reason')!r}. Every later stream on this channel ends "
            f"the same way")

    def test_control_with_no_lost_answer_the_plain_chunks_are_served_and_paid(self):
        r, signed = self.buy_a_stream(lost=0)
        self.assertEqual((r["stream"].get("verified_chunks"), signed), (2, 3 * self.PRICE), r["stream"])
        self.assertEqual(self.chunk_answers, [("0", 200), ("1", 200)])


# --- hole 4 -----------------------------------------------------------------------------------------------
class ARefundThatLosesToTheClose(unittest.TestCase):
    def test_hole_a_refund_that_lost_to_the_sellers_close_is_noticed(self):
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = signer(Path(tempfile.mkdtemp()), rpc)
        self.assertEqual(s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000,
                                                                        "expiry_blocks": 50}})["state"], "open")
        rec = s.channels.get(API)
        fop = (rec.funding_txid, 0)
        sig = s.handle({"method": "sign_state", "params": {"dest": API, "cum": 10_000}})["sig"]
        p = rec.params()
        close = p.state_tx(10_000)
        close.inputs[0].witness = [b"", bytes.fromhex(sig), os.urandom(71), p.script]
        txid = rpc.call("sendrawtransaction", close.hex())          # the seller's close, in our mempool
        rpc.unmined.add(txid)
        rpc.height = rec.expiry
        acts = s.handle({"method": "watch_tick"})["actions"]
        self.assertEqual([a.get("rule") for a in acts if a.get("chan") == rec.chan], ["close_unconfirmed"], acts)
        # our node drops it (expiry, eviction); a miner still has it
        funding = rpc.spent.pop(fop)
        rpc.utxos[fop] = funding
        kept = rpc.txs.pop(txid)
        del rpc.spenders[fop]
        for n in range(len(close.outputs)):
            rpc.utxos.pop((txid, n), None)
        rpc.height += 1
        acts = s.handle({"method": "watch_tick"})["actions"]
        refund = next(a["txid"] for a in acts if a.get("rule") == "refund")
        hot_with_refund = s.hot.balance_sats()
        # the close is mined after all: the refund conflicts with it and is in no block, ever
        rpc.utxos.pop(fop, None)
        rpc.spent.pop(fop, None)
        rpc.spenders[fop] = txid
        rpc.txs[txid] = {**kept, "confirmations": 1}
        rpc.utxos.pop((refund, 0), None)
        rpc.txs.pop(refund, None)
        rpc.sent_at.pop(refund, None)
        for n, o in enumerate(close.outputs):
            rpc.utxos[(txid, n)] = {"value": o.value / 1e8, "confirmations": 1, "scriptPubKey": {"hex": o.script_pubkey.hex()}}
        for _ in range(3):
            rpc.height += 1
            s.handle({"method": "watch_tick"})
        got = s.channels.get(API)
        self.assertEqual(
            (got.state, got.closed_txid), ("closed", txid),
            f"the seller's close {txid[:16]} is in a block and paid it 10,000 sat; the record still says "
            f"{got.state!r} by {got.refund_txid[:16]}, which is in no block, and the hot wallet counts "
            f"{s.hot.balance_sats()} sat (it counted {hot_with_refund} with the refund's output) while the close's "
            f"change is not among its coins")


# --- hole 6 -----------------------------------------------------------------------------------------------
class FlakyNode(FakeRpc):
    """FakeRpc whose node fails the two calls that tell a mempool spend from a block spend while
    `flaky` is set (a node that is overloaded or restarting answers some calls and not others)."""

    flaky = False

    def call(self, method, *params):
        if self.flaky and (method == "gettxspendingprevout" or (method == "gettxout" and len(params) > 2 and not params[2])):
            from agentwallet.rpc import KnotsRpcError
            raise KnotsRpcError("work queue depth exceeded")
        return super().call(method, *params)


class ANodeThatCannotBeAskedIsNotABlock(unittest.TestCase):
    def run_it(self, flaky: bool):
        rpc = FlakyNode(height=1000, track_outputs=True)
        s = signer(Path(tempfile.mkdtemp()), rpc)
        self.assertEqual(s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000,
                                                                        "expiry_blocks": 50}})["state"], "open")
        rec = s.channels.get(API)
        fop = (rec.funding_txid, 0)
        sig = s.handle({"method": "sign_state", "params": {"dest": API, "cum": 10_000}})["sig"]
        p = rec.params()
        close = p.state_tx(10_000)
        close.inputs[0].witness = [b"", bytes.fromhex(sig), os.urandom(71), p.script]
        txid = rpc.call("sendrawtransaction", close.hex())          # the seller's close: in the mempool, never mined
        rpc.unmined.add(txid)
        rpc.height = rec.expiry
        rpc.flaky = flaky
        first = [a.get("rule") for a in s.handle({"method": "watch_tick"})["actions"] if a.get("chan") == rec.chan]
        rpc.flaky = False
        state = s.channels.get(API).state
        rpc.utxos[fop] = rpc.spent.pop(fop)                         # the close leaves the mempool
        del rpc.spenders[fop], rpc.txs[txid]
        for _ in range(3):
            rpc.height += 1
            s.handle({"method": "watch_tick"})
        return rpc, rec, first, state

    def test_hole_a_mempool_close_is_not_closed_for_good_because_the_node_failed_two_calls(self):
        rpc, rec, first, state = self.run_it(flaky=True)
        self.assertEqual(
            len(spends(rpc, rec.funding_txid)) - 1, 1,     # minus the close itself
            f"the close was only ever in the mempool; at the expiry tick the node answered gettxout (with the mempool) "
            f"and failed gettxout (without it) and gettxspendingprevout, the wallet answered {first} and marked the "
            f"record {state!r}; the funding ({rec.funding_sats} sat) is unspent again and is never refunded")

    def test_control_with_a_node_that_answers_the_close_is_unconfirmed_and_then_refunded(self):
        rpc, rec, first, state = self.run_it(flaky=False)
        self.assertEqual((first, state, len(spends(rpc, rec.funding_txid)) - 1), (["close_unconfirmed"], "open", 1))


# --- hole 5 -----------------------------------------------------------------------------------------------
class AVoidLotAndTheWalletsOwnRefund(unittest.TestCase):
    def run_it(self, rotate: bool):
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.m.withhold = True
        t.buy()                                   # the market holds the pre-signature and never uses it
        self.assertEqual(ledger_sum(t.s), PRICE)
        if rotate:
            t.s.hot.rotate()                      # what rotate_hot_key does once the human's signature is checked
        t.rpc.height = 8000
        r = t.s.handle({"method": "xbt402_refund", "params": {"counterparty": MARKET}})
        self.assertEqual(r.get("rule"), "refund", r)
        t.rpc.txs[r["txid"]]["confirmations"] = 1          # the refund is in a block
        t.rpc.height = 8001
        v = t.s.handle({"method": "forward_recover", "params": {"txid": r["txid"]}})   # before the watcher's next tick
        self.assertTrue(v.get("void"), v)
        t.s.watch_tick()
        return t, v, r

    def test_hole_a_lot_voided_by_the_wallets_own_refund_is_released_whatever_key_the_refund_pays(self):
        t, v, r = self.run_it(rotate=True)
        self.assertEqual(
            ledger_sum(t.s), 0,
            f"the channel was refunded ({r['sats']} sat back to the hot wallet) and the market was paid nothing; "
            f"forward_recover took the refund's output for a payment (paid {v.get('paid')}) and the ledger still holds "
            f"{ledger_sum(t.s)} sat for the lot")

    def test_control_without_a_rotation_the_refund_releases_the_lot(self):
        t, v, _ = self.run_it(rotate=False)
        self.assertEqual((v.get("paid"), ledger_sum(t.s)), (0, 0))


if __name__ == "__main__":
    unittest.main()
