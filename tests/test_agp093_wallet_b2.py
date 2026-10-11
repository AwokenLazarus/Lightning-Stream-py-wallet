"""AGP-093 (third closure audit), area WALLET-B2: what is still open on B2 6fd0e24. Every test whose
name starts with `test_hole_` FAILS today and names the claim that should hold; the `test_control_`
tests pass and show the honest path in the same rig. No fix here. The numbers are the report's
(xbt-rs-agp-093/run/agp093_wallet_b2.md, section 2).

hole 3  forward rail, AGP-089's rule "a release takes back only what no other signed state of the channel
    can claim": `_release_forward` keeps what plain states reach (`used_sats`) and nothing else. A
    stream's hash-locked last chunk rides on the lot's booking too (`_book_through` books 0), does not
    move `used_sats`, and is released with the lot (signer.py:564-583, xbt402.py:835-839).
hole 5  AGP-089's rule "the watcher voids a refunded channel's lot once the refund is in a block":
    `_settle_forward_refunds` learns "in a block" from `gettxout(refund, 0, False)` or from
    `getrawtransaction(refund, true)`. On a node without txindex the second never answers for a
    confirmed transaction, and the first is empty once the refund's output is spent (the hot wallet
    counts that output from the broadcast on). The lot then stays pending for good and the market is
    refused `forward_pending` (signer.py:585-609). The tests' FakeRpc answers getrawtransaction for
    every transaction, as a node with txindex does.
hole 2  AGP-089 found-not-fixed 3: a spend of a funding that is only in our node's mempool is taken for
    "the provider closed" (`_refund_locked` and `funding_spent` ask gettxout with the mempool
    included and take the mempool spender). The record is closed, proven, and leaves the refund
    watcher; when that transaction never confirms the funding is never refunded
    (signer.py:466-489, xbt402.py:928-955).
hole 4  one lost answer still ends a channel for B2 (the second audit's item 9 says B2 is not affected):
    a state is acked only by a receipt, an unacked state is sent again and nothing higher is signed,
    and a provider that already counted that state answers 402 with no receipt, every time
    (xbt402.py:602-627). One lost answer on a prepay provider, two in a row on a postpay one.
hole 1  forward rail: `forward_recover` and `_settle_forward_refunds` look a pending lot's channel up by its
    dest (`book.get(dest)`), which is the dest's current channel. Once the lot's channel was closed and a
    plain call opened the next one, the close that paid for the lot is answered "closes no channel with
    a pending forward purchase", and the lot is later filed void on the refund of the other channel
    (forward.py:252-256, signer.py:591-594).
hole 6  `recover_treasury`: "one [funding] that is spent or not yet mature does not hold up the others"
    (signer.py:1317-1320), but one recorded at or below the 600 sat fee raises out of the loop before
    any other is tried (treasury.py:247-249).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agentwallet.approval import b2x, sign, treasury_fund_message, treasury_recover_message
from agentwallet.forward import ForwardSession
from agentwallet.rpc import KnotsRpcError
from agentwallet.signer import Signer
from agentwallet.stream import Commitment

from _agp013 import HUMAN_PRIV, NETWORK, PAY_TO, FakeRpc, fund_channel
from test_agp087_wallet_b2 import own_rail
from test_agp087_wallet_b2_evidence import API, signer

from xbt402 import ecc
from xbt402.channel import DERIVATION, channel_payee_secret
from xbt402.conditional import ConditionalParams
from xbt402.tx import Tx as BTx, segwit_address
from xbt402.x402_channel import (SCHEME, XbtChannelClient, b64json, body_hash, network_id, receipt_message,
                                 request_digest_v2, unb64json)


def ledger_sum(s: Signer) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


# --- hole 3 -----------------------------------------------------------------------------------------------
class HashLockRidesOnALot(unittest.TestCase):
    CH = 1_000                 # the price of the manifest call and of each of the stream's two chunks
    RID = "r1"

    def rig(self):
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.m.withhold = True
        r = t.buy()                               # the market holds a pre-signature worth PRICE; it delivers nothing
        self.assertEqual((r["delivered"], ledger_sum(t.s)), (False, PRICE), r)
        chunks = Commitment.split(b"".join(b"line %02d of the report\n" % i for i in range(6)), 72)
        self.assertEqual(len(chunks), 2)
        c = Commitment(self.RID, chunks, self.CH, PAY_TO, os.urandom(32))
        doc = {"stream": "xbt402-merkle-v1", "manifest": c.manifest, "chunkUrl": f"/v1/report/{self.RID}/chunk/{{i}}"}
        payee = channel_payee_secret(NETWORK, PAY_TO, bytes.fromhex(t.p.payer_pub), t.p.expiry)
        acc = {"scheme": SCHEME, "network": NETWORK, "amount": str(self.CH), "payTo": ecc.pubkey(PAY_TO).hex(),
               "asset": "XBT", "extra": {"derivation": DERIVATION}}
        held, real = [], t.m.http

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3]
            paid = "PAYMENT-SIGNATURE" in (headers or {})
            pl = unb64json(headers["PAYMENT-SIGNATURE"])["payload"] if paid else None
            if path == f"/v1/report/{self.RID}":
                if not paid:
                    return 402, {"PAYMENT-REQUIRED": b64json({"x402Version": 2, "accepts": [acc]})}, b"{}"
                out = json.dumps(doc).encode()          # the manifest, with the seller's own receipt for this seq
                rc = {"scheme": SCHEME, "chan": pl["chan"], "seq": pl["seq"], "cum": pl["cum"], "charged": str(self.CH),
                      "spentMsat": str(self.CH * 1000), "req": request_digest_v2(method, url, body or b""),
                      "status": 200, "bodyHash": body_hash(out)}
                rc["sig"] = ecc.sign(payee, receipt_message(rc)).hex()
                return 200, {"PAYMENT-RESPONSE": b64json({"success": True, "extra": {"chargedAmount": rc["charged"],
                                                                                     "receipt": rc}})}, out
            if path == "/x402/verify":
                return 200, {}, b'{"isValid": true}'
            if path == f"/v1/report/{self.RID}/chunk/0":
                return 200, {}, json.dumps(c.chunk(0)).encode()
            if path == f"/v1/report/{self.RID}/chunk/1":
                if not paid:
                    cond = {"hash": c.manifest["lock"], "amount": self.CH, "cipher": c.final_ct.hex(), "csvDelta": 10}
                    a = {**acc, "extra": {**acc["extra"], "conditional": cond}}
                    return 402, {"PAYMENT-REQUIRED": b64json({"x402Version": 2, "accepts": [a]})}, b"{}"
                held.append(pl)                         # the hash-locked state; the key never comes
                return 504, {}, b""
            return real(method, url, body, headers)

        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            r = t.s.handle({"method": "xbt402_pay", "params": {"url": f"{MARKET}/v1/report/{self.RID}",
                                                               "max_sats": 3 * self.CH}})
        rec = t.s.channels.get(MARKET)
        self.assertEqual((len(held), rec.used_sats), (1, 2 * self.CH), r)
        cp = ConditionalParams(t.p, bytes.fromhex(c.manifest["lock"]), self.CH, 10)
        state = cp.state_tx(rec.used_sats)
        sig = bytes.fromhex(held[0]["sig"])
        self.assertTrue(ecc.verify(bytes.fromhex(t.p.payer_pub), cp.sighash(state), sig[:-1]),
                        "the market holds a valid hash-locked state: 2,000 sat plain and 1,000 sat it claims with k")
        self.assertEqual(ledger_sum(t.s), PRICE, "all of it rode on the lot's booking and booked nothing of its own")
        return t, state, sig

    def close(self, t, tx: BTx, sig: bytes) -> str:
        """The market closes with `tx`, in a block; the witness carries no adaptor state."""
        tx.inputs[0].witness = [b"", sig, os.urandom(71), t.p.script]
        txid = tx.txid()
        t.rpc.txs[txid] = {"txid": txid, "hex": tx.hex(), "confirmations": 6}
        t.rpc.utxos.pop((t.p.funding_txid, 0), None)
        t.rpc.spenders[(t.p.funding_txid, 0)] = txid
        return txid

    def test_hole_a_void_lot_does_not_release_a_hash_locked_state_that_rode_on_its_booking(self):
        t, state, sig = self.rig()
        paid = 3 * self.CH                         # 2,000 to the payee's output, 1,000 hash-locked to the key it holds
        self.assertEqual(sum(o.value for o in state.outputs[:2]), paid)
        rec = t.s.handle({"method": "forward_recover", "params": {"txid": self.close(t, state, sig)}})
        self.assertTrue(rec.get("void"), rec)
        self.assertGreaterEqual(
            ledger_sum(t.s), paid,
            f"the market closed, in a block, with the hash-locked state the wallet signed (2,000 sat plain + 1,000 sat "
            f"under its own key's hash lock = {paid} sat); the void released the lot's row down to used_sats and the "
            f"ledger holds {ledger_sum(t.s)} sat")

    def test_control_a_void_lot_keeps_what_the_plain_states_reach(self):
        t, _, _ = self.rig()
        got = []

        def http(method, url, body=b"", headers=None):       # one more call: the wallet hands its last plain state again
            if "PAYMENT-SIGNATURE" not in (headers or {}):
                acc = {"scheme": SCHEME, "network": NETWORK, "amount": str(self.CH), "payTo": ecc.pubkey(PAY_TO).hex(),
                       "asset": "XBT", "extra": {"derivation": DERIVATION}}
                return 402, {"PAYMENT-REQUIRED": b64json({"x402Version": 2, "accepts": [acc]})}, b"{}"
            got.append(unb64json(headers["PAYMENT-SIGNATURE"])["payload"])
            return 500, {}, b""

        from test_forward_rail import MARKET
        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            t.s.handle({"method": "xbt402_pay", "params": {"url": f"{MARKET}/api", "max_sats": self.CH}})
        self.assertEqual(int(got[0]["cum"]), 2 * self.CH)
        txid = self.close(t, t.p.state_tx(2 * self.CH), bytes.fromhex(got[0]["sig"]))    # the market closes with it
        self.assertTrue(t.s.handle({"method": "forward_recover", "params": {"txid": txid}}).get("void"))
        self.assertEqual(ledger_sum(t.s), 2 * self.CH, "paid 2,000 sat, ledger 2,000 sat")


# --- hole 5 -----------------------------------------------------------------------------------------------
class NoTxindexNode(FakeRpc):
    """FakeRpc with a real node's answers for a confirmed transaction when the node has no txindex:
    getrawtransaction needs the block hash, gettxspendingprevout names mempool spenders only, and
    the block itself is read with getblock. `confirmed`: txid -> height."""

    confirmed: dict = {}

    def call(self, method, *params):
        if method == "getrawtransaction" and params[0] in self.confirmed:
            h = self.confirmed[params[0]]
            if len(params) < 3 or params[2] != f"{h:064x}":
                raise KnotsRpcError("No such mempool transaction. Use -txindex or provide a block hash to enable "
                                    "blockchain transaction queries. Use gettransaction for wallet transactions.")
            return {**self.txs[params[0]], "confirmations": self.height - h + 1, "blockhash": f"{h:064x}"}
        if method == "gettxspendingprevout":
            return [{"txid": o["txid"], "vout": o["vout"],
                     **({"spendingtxid": self.spenders[(o["txid"], o["vout"])]}
                        if self.spenders.get((o["txid"], o["vout"])) not in (None, *self.confirmed) else {})}
                    for o in params[0]]
        if method == "getblockhash":
            return f"{int(params[0]):064x}"
        if method == "getblock":
            h = int(params[0], 16)
            txs = []
            for txid, at in self.confirmed.items():
                if at == h:
                    tx = BTx.parse(bytes.fromhex(self.txs[txid]["hex"]))
                    txs.append({"txid": txid, "hex": self.txs[txid]["hex"],
                                "vin": [{"txid": i.txid[::-1].hex(), "vout": i.vout} for i in tx.inputs]})
            return {"hash": params[0], "height": h, "tx": txs}
        return super().call(method, *params)


class RefundedLotOnANodeWithoutTxindex(unittest.TestCase):
    def rig(self):
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.rpc.__class__, t.rpc.confirmed = NoTxindexNode, {}
        t.m.withhold = True
        t.buy()
        t.rpc.height = 8000
        r = t.s.handle({"method": "xbt402_refund", "params": {"counterparty": MARKET}})
        self.assertEqual(r["rule"], "refund", r)
        t.s.watch_tick()
        self.assertEqual(t.s.handle({"method": "forward_status"})["spent_24h_sats"], PRICE, "only broadcast: still pending")
        return t, r["txid"], PRICE

    def test_hole_a_lot_is_void_once_its_channels_refund_is_in_a_block_whatever_became_of_the_refunds_output(self):
        t, refund, PRICE = self.rig()
        # the refund confirms at 8001. Its output went to the hot key, which counted it from the broadcast on
        # and has spent it since (a new channel, a sweep): both are in the block, so no gettxout shows it
        t.rpc.height = 8001
        t.rpc.confirmed[refund] = 8001
        self.assertIsNone(t.rpc.call("gettxout", refund, 0, False))
        self.assertEqual(t.rpc.call("getrawtransaction", refund, True, f"{8001:064x}")["confirmations"], 1,
                         "the node does show the refund in its block to whoever names the block")
        for _ in range(3):
            t.rpc.height += 1
            t.s.watch_tick()
        st = t.s.handle({"method": "forward_status"})
        self.assertEqual(
            st["pending"], {},
            f"the channel's refund is {t.rpc.height - 8000} blocks deep and the market's pre-signature can never be "
            f"completed; the lot is still pending ({st['spent_24h_sats']} sat counted) and every new lot from this market "
            f"is refused forward_pending")

    def test_control_with_the_refunds_output_unspent_the_watcher_voids_the_lot(self):
        t, refund, PRICE = self.rig()
        t.rpc.height = 8001
        t.rpc.confirmed[refund] = 8001
        t.rpc.utxos[(refund, 0)] = {"value": 0.1, "confirmations": 1, "scriptPubKey": {"hex": t.s.hot.spk.hex()}}
        t.s.watch_tick()
        self.assertEqual(t.s.handle({"method": "forward_status"})["pending"], {})


# --- hole 1 -----------------------------------------------------------------------------------------------
class ALotWhoseChannelWasReplaced(unittest.TestCase):
    def run_it(self, replaced: bool) -> dict:
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.m.withhold = True
        t.buy()                                   # the market holds the pre-signature and answers nothing
        close = t.m.close_with_last_state()       # then closes with the completed state: it is paid PRICE,
        t.rpc.txs[close]["confirmations"] = 6     # and the transfer's s is on the chain
        t.rpc.height = 8000                       # nobody asked forward_recover; at expiry the watcher sees the close
        acts = t.s.watch_tick()
        self.assertEqual((t.s.channels.get(MARKET).state, acts[0].get("rule")), ("closed", "channel_closed"), acts)
        if replaced:                              # the next paid call to this origin opens the next channel
            nxt = fund_channel(t.s.channels, t.rpc, MARKET, secret=0xA11CF, expiry=9000, capacity=10_000_600,
                               payer_spk=t.s.hot.spk.hex())
            self.assertNotEqual(t.s.channels.get(MARKET).chan, t.p.channel_id)
            self.assertEqual(t.s.channels.get(MARKET).chan, nxt.channel_id)
        return t.s.handle({"method": "forward_recover", "params": {"txid": close}})

    def test_hole_a_lot_is_recovered_from_the_close_that_paid_for_it_after_its_channel_was_replaced(self):
        rec = self.run_it(replaced=True)
        self.assertTrue(rec.get("recovered"),
                        f"the market's close paid it 2,305,541 sat for the lot and carries the transfer's s; the wallet, "
                        f"which opened the next channel to this market meanwhile, answers: {rec}")

    def test_control_the_same_close_recovers_the_lot_while_the_channel_is_the_dests_record(self):
        self.assertTrue(self.run_it(replaced=False).get("recovered"))


# --- hole 2 -----------------------------------------------------------------------------------------------
class MempoolNode(FakeRpc):
    """FakeRpc with a real node's gettxout: an output a mempool transaction spends is absent with
    include_mempool=true and still there without. `mempool_spends`: outpoint -> txid."""

    mempool_spends: dict = {}

    def call(self, method, *params):
        if method == "gettxout":
            op = (params[0], int(params[1]))
            if (len(params) < 3 or params[2]) and op in self.mempool_spends:
                return None
            return self.utxos.get(op)
        if method == "gettxspendingprevout":
            return [{"txid": o["txid"], "vout": o["vout"],
                     **({"spendingtxid": self.mempool_spends[(o["txid"], o["vout"])]}
                        if (o["txid"], o["vout"]) in self.mempool_spends else {})} for o in params[0]]
        return super().call(method, *params)


class ACloseOnlyInTheMempool(unittest.TestCase):
    def rig(self):
        rpc = MempoolNode(height=1000)
        rpc.mempool_spends = {}
        s = signer(Path(tempfile.mkdtemp()), rpc)
        s._xbt402.network = lambda: NETWORK
        p = fund_channel(s.channels, rpc, API, payer_spk=s.hot.spk.hex())          # expiry 1100, 100,600 sat
        sig = s.handle({"method": "sign_state", "params": {"dest": API, "cum": 10_000}})["sig"]
        close = p.state_tx(10_000)
        close.inputs[0].witness = [b"", bytes.fromhex(sig), os.urandom(71), p.script]
        return s, rpc, p, close

    @staticmethod
    def refunds(rpc, p) -> list[str]:
        return [raw for raw in rpc.sent
                if any((i.txid[::-1].hex(), i.vout) == (p.funding_txid, 0) for i in BTx.parse(bytes.fromhex(raw)).inputs)]

    def test_hole_a_close_that_was_only_ever_in_the_mempool_does_not_end_the_refund_watch(self):
        s, rpc, p, close = self.rig()
        txid = close.txid()
        rpc.txs[txid] = {"txid": txid, "hex": close.hex()}                    # in our mempool: no block, no confirmations
        rpc.mempool_spends[(p.funding_txid, 0)] = txid
        rpc.height = 1100
        acts = s.watch_tick()
        self.assertEqual(self.refunds(rpc, p), [], acts)
        # that close is never mined and leaves the mempool (expired, evicted, or replaced by nothing)
        del rpc.mempool_spends[(p.funding_txid, 0)], rpc.txs[txid]
        self.assertTrue(rpc.call("gettxout", p.funding_txid, 0, True), "the funding output is unspent again")
        for h in (1101, 1150, 1300):
            rpc.height = h
            s.watch_tick()
        r = s.handle({"method": "xbt402_refund", "params": {"counterparty": API}})
        rec = s.channels.get(API)
        self.assertEqual(
            len(self.refunds(rpc, p)), 1,
            f"the funding output ({p.capacity} sat) is unspent 200 blocks past its expiry; a close seen only in the "
            f"mempool was booked as the provider's close (state {rec.state!r}, close_unproven {rec.close_unproven}, "
            f"closed_txid {rec.closed_txid[:16]}) and the watcher never refunds it: {r.get('rule')}")

    def test_control_an_unspent_funding_is_refunded_at_expiry(self):
        s, rpc, p, close = self.rig()
        rpc.height = 1100
        s.watch_tick()
        self.assertEqual(len(self.refunds(rpc, p)), 1)


# --- hole 4 -----------------------------------------------------------------------------------------------
DEST = "http://127.0.0.1:9"


class LostAnswers(unittest.TestCase):
    """The signer's xbt402_pay against B1's provider (the rig of test_agp087_transport.ReceiptSeq). The
    provider serves a paid request and the answer never reaches the wallet."""

    PRICE = 600                # at or above the channel's least state, so a state pays for exactly one call

    def rig(self, billing: str):
        import test_request_auth
        import xbt402.x402_channel as xc
        from sechelp import FakeNode, make_provider
        from test_unacked_state import Engine, Rpc

        tmp = Path(tempfile.mkdtemp())
        self.book, _, p = test_request_auth.funded(tmp)
        node = FakeNode()
        prov = make_provider(xc, node, billing=billing)
        prov.price = lambda method, path: self.PRICE
        self.assertEqual(prov.network, network_id("11" * 32))
        node.add_funding(p, confirmations=6)
        prov.open({"x402Version": 2, "network": prov.network, "channel": {
            "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
        self.lose, self.served = 0, 0

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
            st, h, out = prov.serve(method, path, headers or {}, body or b"", url)
            if "PAYMENT-SIGNATURE" in {k.upper() for k in headers or {}}:
                self.served += st == 200
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

    def statuses(self, n: int) -> list:
        return [self.signer._xbt402_pay_locked({"url": DEST + "/v1/x", "method": "GET", "body": "",
                                                "max_sats": 2_000}).get("status") for _ in range(n)]

    def after(self, billing: str, lost: int) -> str:
        self.rig(billing)
        self.lose = lost
        first = self.statuses(lost)
        self.assertEqual(first, [None] * lost, "the calls whose answers were lost are errors to the caller")
        later = self.statuses(6)
        rec = self.book.get(DEST)
        self.assertIn(
            200, later,
            f"{billing}: after {lost} lost answer(s) the next 6 calls answered {later}; the wallet sends the state for "
            f"{rec.used_sats} sat again each time (acked {rec.acked_sats}, seq {rec.seq}) and signs nothing higher, and "
            f"the provider, which served {self.served} call(s), has already counted that state")
        return billing

    def test_hole_one_lost_answer_does_not_end_a_channel_to_a_prepay_provider(self):
        self.after("prepay", 1)

    def test_hole_two_lost_answers_do_not_end_a_channel_to_a_postpay_provider(self):
        self.after("postpay", 2)

    def test_control_no_lost_answer_and_one_lost_answer_on_postpay_go_on(self):
        for billing in ("prepay", "postpay"):
            self.rig(billing)
            self.assertEqual(self.statuses(4), [200] * 4, billing)
        self.after("postpay", 1)


# --- hole 6 -----------------------------------------------------------------------------------------------
class TreasuryRecoversEveryFunding(unittest.TestCase):
    def fund(self, s: Signer, sats: int, exp: int) -> str:
        sig = sign(HUMAN_PRIV, treasury_fund_message(s.hot.address, s.treasury.address, sats, exp))
        return s.handle({"method": "fund_treasury", "params": {"sats": sats, "expiry": exp,
                                                               "signature": b2x(sig)}})["treasury_outpoint"]

    def recover(self, small: int):
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = own_rail(rpc)
        exp = int(s.engine.clock()) + 600
        first = self.fund(s, 100_000, exp)
        self.fund(s, small, exp + 1)                 # a second funding the human signed
        dest = segwit_address("bcrt", bytes.fromhex("0014" + "55" * 20))
        sig = sign(HUMAN_PRIV, treasury_recover_message(s.treasury.address, dest, exp))
        before = len(rpc.sent)
        try:
            r = s.handle({"method": "recover_treasury", "params": {"to": dest, "expiry": exp, "signature": b2x(sig)}})
        except Exception as e:                       # what the socket answers as an error
            r = {"error": str(e)}
        spent = {f"{i.txid[::-1].hex()}:{i.vout}" for raw in rpc.sent[before:] for i in BTx.parse(bytes.fromhex(raw)).inputs}
        return first, spent, r

    def test_hole_a_recorded_funding_at_or_below_the_fee_does_not_hold_up_the_other_recoveries(self):
        first, spent, r = self.recover(600)
        self.assertIn(first, spent,
                      f"the treasury records 100,000 sat at {first[:16]}.. and 600 sat after it; recover_treasury, signed "
                      f"by the human, recovered nothing: {r}")

    def test_control_two_fundings_above_the_fee_are_both_recovered(self):
        first, spent, r = self.recover(60_000)
        self.assertIn(first, spent, r)
        self.assertEqual(len(spent), 2, r)


if __name__ == "__main__":
    unittest.main()
