"""AGP-013 forward rail in B2: a B5 forward lot bought through xbt402_pay with an adaptor-signed
channel state, under its own policy limits (allowed markets, per-lot max, 24 h forward budget).

The market is simulated in pure Python (MuSig2 over the escrow's tweaked key, the adaptor completion
with the transfer signature's s). The on-node run against b5's real market is AGP-013's interop
evidence (b5 demo_settle with this rail)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.fwd import adaptor, musig2, schnorr
from agentwallet.fwd import ecc as fecc
from agentwallet.fwd.buyer import receipt_digest
from agentwallet.fwd.escrow import MATURITY_419, Escrow
from agentwallet.signer import Signer

from _agp013 import NETWORK, PAY_TO, FakeRpc, fund_channel, keyfile_env, write_policy

from xbt402 import ecc as becc
from xbt402.channel import DERIVATION, SIGHASH_ALL_UNIFIED
from xbt402.tx import Tx as BTx, TxIn, TxOut
from xbt402.x402_channel import SCHEME, XbtChannelClient, b64json, unb64json

MARKET = "http://market.test"
PRICE = 2_305_541
VALUE = 2_441_406
MINER, MKT = 0x31337, 0xFEED


class Market:
    """One lot per quote: an escrow coinbase on the fake node, a MuSig2 session with both nonces
    fixed at quote time, and the adaptor completion when the buyer's pre-signed state arrives."""

    def __init__(self, rpc: FakeRpc, buyer_spk: bytes, chan_params, height=500):
        self.rpc, self.buyer_spk, self.p = rpc, buyer_spk, chan_params
        self.withhold = False
        self.bad_transfer_to = None
        self.lots = {}
        self.height = height
        self.calls = []

    def quote(self, n: int) -> dict:
        esc = Escrow(fecc.pubkey(MINER), fecc.pubkey(MKT), MATURITY_419 + 300)
        txid = os.urandom(32).hex()
        self.rpc.utxos[(txid, 0)] = {"value": VALUE / 1e8, "coinbase": True, "scriptPubKey": {"hex": esc.spk.hex()}}
        tx = esc.transfer(txid, 0, VALUE, self.height + n, MATURITY_419, self.bad_transfer_to or self.buyer_spk, 2)
        msg = esc.tr_digest(tx, VALUE)
        (sa, pa), (sb, pb) = musig2.nonce_gen(), musig2.nonce_gen()
        agg = musig2.nonce_agg([pa, pb])
        rx = adaptor.musig2_rx(agg, esc.out.xonly(), msg)
        S = adaptor.sig_point(rx, esc.out.xonly(), msg)
        sig = musig2.partial_sig_agg([musig2.sign(sa, MINER, esc.out, agg, msg), musig2.sign(sb, MKT, esc.out, agg, msg)],
                                     esc.out, agg, msg)
        offer = {"outpoint": f"{txid}:0", "kind": "p2tr", "minerPub": fecc.pubkey(MINER).hex(),
                 "marketPub": becc.pubkey(MKT).hex(), "escapeCsv": MATURITY_419 + 300, "value": VALUE,
                 "coinbaseHeight": self.height + n, "maturity": MATURITY_419,
                 "deliverHeight": self.height + n + MATURITY_419, "feeRate": 2,
                 "transfer": tx.serialize(with_witness=False).hex(), "buyerSpk": self.buyer_spk.hex(),
                 "nonceRx": rx.hex(), "adaptorPoint": adaptor.enc(S).hex(), "atomic": "ecdsa-adaptor/bip340-s"}
        self.lots[f"/forward/quote?lot={n}"] = (offer, esc, tx, sig)
        return offer

    def acc(self, offer: dict) -> dict:
        return {"scheme": SCHEME, "network": NETWORK, "amount": str(PRICE), "payTo": becc.pubkey(PAY_TO).hex(),
                "asset": "XBT", "extra": {"derivation": DERIVATION, "forward": offer}}

    def http(self, method, url, body=b"", headers=None):
        path = "/" + url.split("/", 3)[3]
        offer, esc, tx, sig = self.lots[path]
        acc = self.acc(offer)
        self.calls.append("paid" if "PAYMENT-SIGNATURE" in (headers or {}) else "unpaid")
        if "PAYMENT-SIGNATURE" not in (headers or {}):
            return 402, {"PAYMENT-REQUIRED": b64json({"x402Version": 2, "accepts": [acc]})}, b"{}"
        payload = unb64json(headers["PAYMENT-SIGNATURE"])["payload"]
        pre = adaptor.PreSig.from_json(payload["adaptor"])
        z = self.p.sighash(self.p.state_tx(int(payload["cum"])))
        assert adaptor.preverify(bytes.fromhex(self.p.payer_pub), z, adaptor.dec(bytes.fromhex(offer["adaptorPoint"])), pre)
        state_sig = adaptor.adapt(pre, int.from_bytes(sig[32:], "big")) + bytes([SIGHASH_ALL_UNIFIED])
        self.last = {"cum": int(payload["cum"]), "state_sig": state_sig, "z": z}
        if self.withhold:
            return 504, {}, b""
        done = esc.finalize_sale(type(tx).parse(tx.serialize()), sig)
        r = {"outpoint": offer["outpoint"], "transferTxid": done.txid(), "price": PRICE,
             "deliverHeight": offer["deliverHeight"], "chan": payload["chan"], "cum": int(payload["cum"]),
             "marketPub": offer["marketPub"]}
        r["sig"] = becc.sign(MKT, receipt_digest(r)).hex()
        return 200, {}, json.dumps({"transfer": done.hex(), "stateSig": state_sig.hex(), "forwardReceipt": r}).encode()

    def close_with_last_state(self) -> str:
        """The market closes the channel alone with the completed state (as B1's payee would)."""
        tx = BTx(version=2, inputs=[TxIn(bytes.fromhex(self.p.funding_txid)[::-1], 0)],
                 outputs=[TxOut(self.last["cum"], bytes.fromhex(self.p.payee_spk))], locktime=0)
        tx.inputs[0].witness = [b"", self.last["state_sig"], os.urandom(71), self.p.script]
        txid = tx.txid()
        self.rpc.txs[txid] = {"txid": txid, "hex": tx.hex()}
        self.rpc.utxos.pop((self.p.funding_txid, 0), None)
        self.rpc.spenders[(self.p.funding_txid, 0)] = txid
        return txid


class ForwardRail(unittest.TestCase):
    def make(self, **forward):
        self.tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        fwd = {"markets": [MARKET], "per_lot_max_sats": 3_000_000, "daily_budget_sats": 10_000_000}
        fwd.update(forward)
        write_policy(self.tmp, forward=fwd, per_counterparty_cap_sats=20_000_000, max_per_tx_sats=5_000_000,
                     daily_budget_sats=50_000_000)
        self.rpc = FakeRpc(height=7000)
        self.rpc.deployments = {"deployments": {"long_coinbase_maturity": {      # AGP-080 M1: the node's rule
            "coinbase_start_height": 0, "height": 0, "height_end": 4_000_000, "maturity": MATURITY_419}}}
        self.s = Signer(self.tmp, rpc=self.rpc)
        self.s._xbt402.network = lambda: NETWORK
        self.p = fund_channel(self.s.channels, self.rpc, MARKET, expiry=8000, capacity=10_000_600,
                              payer_spk=self.s.hot.spk.hex())
        self.m = Market(self.rpc, self.s.hot.spk, self.p)
        self.patch = mock.patch.object(XbtChannelClient, "http", staticmethod(self.m.http))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def buy(self, n=0, max_sats=PRICE):
        self.m.quote(n)
        return self.s.handle({"method": "xbt402_pay", "params": {"url": f"{MARKET}/forward/quote?lot={n}",
                                                                 "max_sats": max_sats}})

    def test_lot_delivered_atomically_and_charged_once(self):
        self.make()
        r = self.buy()
        self.assertEqual((r["verdict"], r["rail"], r["delivered"], r["charged_sats"]), ("allow", "xbt402", True, PRICE), r)
        self.assertTrue(r["forward_receipt_ok"])
        self.assertEqual(self.m.calls, ["unpaid", "paid"], "one 402 request, one paid request")
        tx = BTx.parse(bytes.fromhex(r["transfer_hex"]))
        offer = self.m.lots["/forward/quote?lot=0"][0]
        esc = self.m.lots["/forward/quote?lot=0"][1]
        self.assertEqual(tx.outputs[0].script_pubkey, self.s.hot.spk, "the lot pays the wallet's own key")
        self.assertTrue(schnorr.verify(esc.out.xonly(), esc.tr_digest(self.m.lots["/forward/quote?lot=0"][2], VALUE),
                                       tx.inputs[0].witness[0]))
        self.assertTrue(becc.verify(bytes.fromhex(self.p.payer_pub), self.m.last["z"], self.m.last["state_sig"][:-1]),
                        "the market's completed state is a valid channel signature")
        self.assertEqual(self.s.channels.get(MARKET).used_sats, PRICE)
        st = self.s.handle({"method": "forward_status"})
        self.assertEqual(st["spent_24h_sats"], PRICE)
        self.assertIn(offer["outpoint"], st["delivered"])
        self.assertEqual(st["pending"], {})
        row = [x for x in self.s.sigaudit.read() if x["kind"] == "adaptor_presig"][0]
        self.assertEqual((row["chan"], row["cum"], row["rule"], row["outpoint"]),
                         (self.p.channel_id, PRICE, "policy:ok+forward", offer["outpoint"]))
        self.assertEqual([e.amount_sats for e in self.s.engine.store.payments()], [PRICE])

    def test_market_not_allowed(self):
        self.make(markets=["http://other-market.test"])
        r = self.buy()
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "forward_market"), r)
        self.assertEqual(self.s.sigaudit.read(), [], "nothing pre-signed")

    def test_per_lot_max(self):
        self.make(per_lot_max_sats=PRICE - 1)
        r = self.buy()
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "forward_lot_max"), r)

    def test_daily_forward_budget(self):
        self.make(daily_budget_sats=PRICE * 2 - 1)
        self.assertTrue(self.buy(0)["delivered"])
        r = self.buy(1)
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "forward_daily_budget"), r)
        self.assertEqual(self.s.channels.get(MARKET).used_sats, PRICE)

    def test_rail_off_without_forward_policy(self):
        self.make(markets=[])
        self.assertEqual(self.buy()["rule"], "forward_disabled")

    def test_ordinary_max_sats_still_applies(self):
        self.make()
        r = self.buy(max_sats=PRICE - 1)
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "max_sats"), r)

    def test_transfer_to_someone_else_refused_before_signing(self):
        self.make()
        self.m.bad_transfer_to = bytes.fromhex("0014" + "66" * 20)
        r = self.buy()
        self.assertEqual((r["verdict"], r["rule"], r["reason"]), ("deny", "forward_offer", "wrong_transfer"), r)
        self.assertEqual(self.s.sigaudit.read(), [])

    def test_withheld_answer_recovered_from_the_close(self):
        self.make()
        self.m.withhold = True
        r = self.buy()
        self.assertEqual((r["delivered"], r["charged_sats"]), (False, 0), r)
        self.assertEqual(self.buy(1)["rule"], "forward_pending", "one unsettled purchase per channel")
        close = self.m.close_with_last_state()
        rec = self.s.handle({"method": "forward_recover", "params": {"txid": close}})
        self.assertTrue(rec["recovered"], rec)
        tx = BTx.parse(bytes.fromhex(rec["transfer_hex"]))
        self.assertEqual(tx.outputs[0].script_pubkey, self.s.hot.spk)
        self.assertEqual(self.s.channels.get(MARKET).state, "closed")
        self.assertEqual([e.amount_sats for e in self.s.engine.store.payments()], [PRICE],
                         "the policy ledger learns the recovered spend")
        self.rpc.height = 8000
        self.assertEqual(self.s.handle({"method": "xbt402_refund", "params": {"counterparty": MARKET}})["rule"],
                         "channel_closed", "a buyer who got the transfer can't refund the payment away")

    def test_withheld_then_refunded_voids_the_purchase(self):
        self.make()
        self.m.withhold = True
        self.buy()
        self.assertEqual(self.s.handle({"method": "forward_status"})["spent_24h_sats"], PRICE, "pending counts")
        self.rpc.height = 8000
        r = self.s.handle({"method": "xbt402_refund", "params": {"counterparty": MARKET}})
        self.assertEqual(r["rule"], "refund", r)
        st = self.s.handle({"method": "forward_status"})
        self.assertEqual((st["pending"], st["spent_24h_sats"]), ({}, 0))


if __name__ == "__main__":
    unittest.main()
