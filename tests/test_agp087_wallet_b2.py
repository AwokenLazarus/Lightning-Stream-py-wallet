"""AGP-087 (second closure audit), area WALLET-B2: holes still open on B2 7eeedd6. Every test here FAILS.

W1  the seller's receipt still sets how much one call signs: `_pay_once` gives the stream what
    `max_sats - charged` leaves, and `charged` is the seller's number (xbt402.py:583). The Rust signer
    uses `max_sats - booked` (session.rs:664).
W1  a forward lot's booking is taken back whole when the lot is "void", though plain states signed
    after it rode on that booking and booked nothing of their own (signer.py:351-352, 509-513).
W1  `forward_recover` acts on a close that is only in the node's mempool: it voids the lot, drops the
    pre-signature record and releases the booking; the close that then confirms cannot be recovered.
A1  `approve` runs outside the spend lock and `hold_approval` reads and writes the token in two
    steps: two connections pay one approval twice (signer.py:255-256, policy.py:533-553).
W3  human-signed operations carry an expiry and no nonce: one `sweep_hot` or `fund_treasury`
    signature works again until it expires; a repeated `fund_treasury` also overwrites the one
    recorded treasury outpoint (AGP-085 found-not-fixed 5 and 6).
C2  the seller's `minExpiryBlocks` sets how long the funding is locked, with no owner bound
    (xbt402.py:223-240); the socket's `open_channel` is held to `_max_expiry_blocks`.
"""

from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agentwallet.approval import b2x, generate_keypair, sign, sign_approval, sweep_message, treasury_fund_message
from agentwallet.policy import AuditLog, PolicyConfig, PolicyEngine, PolicyStore
from agentwallet.signer import Signer

from _agp013 import HUMAN_PRIV, HUMAN_PUB, NETWORK, PAY_TO, FakeRpc, keyfile_env, write_policy

from xbt402 import ecc
from xbt402.channel import DERIVATION, channel_payee_secret
from xbt402.tx import Tx as BTx, TxIn, TxOut, segwit_address
from xbt402.x402_channel import SCHEME, XbtChannelClient, b64json, receipt_message, unb64json


def ledger_sum(s: Signer) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


class SellerNumberSetsTheStreamBudget(unittest.TestCase):
    """W1, the review's sentence "Never book the seller's number": the booking is the signed delta, but
    how much more the same call may sign is still read from the seller's `charged`."""

    MANIFEST = "/v1/report/r1"

    def run_call(self, lie: bool):
        from test_m7_final_chunk import LAST, ORIGIN, PRICE, RID, Rig

        r = Rig()
        m = copy.deepcopy(r.c.manifest)
        doc = {"stream": "xbt402-merkle-v1", "manifest": m, "chunkUrl": f"/v1/report/{RID}/chunk/{{i}}"}
        cost = m["n"] * PRICE                                   # what the stream costs: 4 x 1000
        r.prov.price = lambda method, path: cost                # the manifest call costs max_sats, all of it
        r.prov.handler = lambda method, path, body: (200, {}, json.dumps(doc).encode())

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3]
            if path.startswith(f"/v1/report/{RID}/chunk/") and path != LAST:
                return 200, {}, json.dumps(r.c.chunk(int(path.rsplit("/", 1)[1]))).encode()
            st, h, out = r.http(method, url, body, headers)
            if lie and path == self.MANIFEST and "PAYMENT-RESPONSE" in h:
                resp = unb64json(h["PAYMENT-RESPONSE"])         # the seller's own receipt, signed by its key
                rc = resp["extra"]["receipt"]
                rc["charged"] = type(rc["charged"])(0)
                key = channel_payee_secret(r.prov.network, 0xB0B, bytes.fromhex(r.p.payer_pub), r.p.expiry)
                rc["sig"] = ecc.sign(key, receipt_message(rc)).hex()   # the channel's payee key, as every receipt
                resp["extra"]["chargedAmount"] = rc["charged"]
                h["PAYMENT-RESPONSE"] = b64json(resp)
            return st, h, out

        tmp = Path(tempfile.mkdtemp())
        s = Signer.__new__(Signer)
        s.engine = PolicyEngine(PolicyConfig(allowlist=frozenset({ORIGIN}), max_per_tx_sats=cost, daily_budget_sats=cost,
                                             weekly_budget_sats=cost, per_counterparty_cap_sats=50_000, split_window_s=0,
                                             velocity_max=50),
                                PolicyStore(tmp / "ledger.json"), AuditLog(tmp / "audit.jsonl"))
        s.config = SimpleNamespace(channel_expiry_blocks=2_000, per_counterparty_cap_sats=50_000)
        s._xbt402 = r.s
        r.s.set_spend_book(s._book_signed_delta)
        r.s.set_spend_check(lambda dest, asked, delta: s._floor_check(dest, asked, delta, human=False))
        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            out = s._xbt402_pay_locked({"url": ORIGIN + self.MANIFEST, "method": "GET", "body": "", "max_sats": cost})
        return cost, r.book.get(ORIGIN).used_sats, ledger_sum(s), out

    def test_w1_the_sellers_charged_does_not_set_what_one_call_signs(self):
        cost, signed, booked, out = self.run_call(lie=False)
        self.assertEqual((signed, booked), (cost, cost), f"control: an honest receipt leaves the stream nothing: {out}")
        cost, signed, booked, out = self.run_call(lie=True)
        self.assertLessEqual(
            signed, cost,
            f"max_sats, max_per_tx and the daily budget are all {cost}; the seller's receipt said charged 0 and the "
            f"wallet signed {signed} sat in one xbt402_pay (ledger {booked})")


class ForwardVoid(unittest.TestCase):
    PLAIN = 1_000_000

    def rig(self):
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.m.withhold = True
        r = t.buy()                              # the market holds a pre-signature worth PRICE; it delivers nothing
        self.assertEqual((r["delivered"], ledger_sum(t.s)), (False, PRICE), r)
        got, real = [], t.m.http

        def http(method, url, body=b"", headers=None):
            if "/" + url.split("/", 3)[3] != "/api":
                return real(method, url, body, headers)
            if "PAYMENT-SIGNATURE" not in (headers or {}):
                acc = {"scheme": SCHEME, "network": NETWORK, "amount": str(self.PLAIN), "payTo": ecc.pubkey(PAY_TO).hex(),
                       "asset": "XBT", "extra": {"derivation": DERIVATION}}
                return 402, {"PAYMENT-REQUIRED": b64json({"x402Version": 2, "accepts": [acc]})}, b"{}"
            got.append(unb64json(headers["PAYMENT-SIGNATURE"])["payload"])
            return 500, {}, b""

        # the same origin sells an ordinary paid call: a plain state for PLAIN (< PRICE) leaves the wallet
        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            r = t.s.handle({"method": "xbt402_pay", "params": {"url": f"{MARKET}/api", "max_sats": self.PLAIN}})
        self.assertEqual(len(got), 1, r)
        sig = bytes.fromhex(got[0]["sig"])
        self.assertEqual(int(got[0]["cum"]), self.PLAIN)
        self.assertTrue(ecc.verify(bytes.fromhex(t.p.payer_pub), t.p.sighash(t.p.state_tx(self.PLAIN)), sig[:-1]),
                        "the market holds a valid plain state")
        self.assertEqual(ledger_sum(t.s), PRICE, "the plain state rode on the lot's booking and booked nothing")
        return t, MARKET, PRICE, sig

    def plain_close(self, t, sig: bytes, *, confirmed: bool) -> str:
        """The market closes with the plain state (no adaptor state in the witness)."""
        tx = BTx(version=2, inputs=[TxIn(bytes.fromhex(t.p.funding_txid)[::-1], 0)],
                 outputs=[TxOut(self.PLAIN, bytes.fromhex(t.p.payee_spk))], locktime=0)
        tx.inputs[0].witness = [b"", sig, os.urandom(71), t.p.script]
        txid = tx.txid()
        t.rpc.txs[txid] = {"txid": txid, "hex": tx.hex(), "confirmations": 6 if confirmed else 0}
        if confirmed:
            t.rpc.utxos.pop((t.p.funding_txid, 0), None)
            t.rpc.spenders[(t.p.funding_txid, 0)] = txid
        return txid

    def test_w1_a_void_lot_does_not_release_the_plain_states_that_rode_on_its_booking(self):
        t, MARKET, PRICE, sig = self.rig()
        txid = self.plain_close(t, sig, confirmed=True)
        rec = t.s.handle({"method": "forward_recover", "params": {"txid": txid}})
        self.assertTrue(rec.get("void"), rec)
        self.assertGreaterEqual(
            ledger_sum(t.s), self.PLAIN,
            f"the market closed with a plain state and was paid {self.PLAIN} sat; the ledger holds {ledger_sum(t.s)}")

    def test_w1_a_close_that_is_only_in_the_mempool_does_not_void_a_forward_lot(self):
        t, MARKET, PRICE, sig = self.rig()
        first = self.plain_close(t, sig, confirmed=False)          # shown to our node only, never mined
        t.s.handle({"method": "forward_recover", "params": {"txid": first}})
        real = t.m.close_with_last_state()                         # the close that confirms: the completed lot state
        rec = t.s.handle({"method": "forward_recover", "params": {"txid": real}})
        self.assertTrue(
            rec.get("recovered"),
            f"the market was paid {PRICE} sat by the close that confirmed; the wallet voided the lot on an unconfirmed "
            f"close, dropped its pre-signature and holds {ledger_sum(t.s)} sat in the ledger: {rec}")


MERCHANT = "bcrt1qmerchant0000000000000000000000000000qq"


class ApproveNode:
    wallet = "agent"

    def __init__(self):
        self.sent: list[tuple] = []

    def call(self, method, *args):
        if method == "getbalances":
            return {"mine": {"trusted": 50, "untrusted_pending": 0, "immature": 0}}
        if method == "sendtoaddress":
            self.sent.append((args[0], args[1]))
            return os.urandom(32).hex()
        if method == "listunspent":
            return []
        if method == "getblockchaininfo":
            return {"chain": "regtest", "blocks": 200, "initialblockdownload": False}
        raise RuntimeError(method)


class ApproveTwice(unittest.TestCase):
    def test_a1_two_connections_approving_one_token_pay_once(self):
        tmp = Path(tempfile.mkdtemp(prefix="b2-agp087-"))
        priv, pub = generate_keypair()
        write_policy(tmp, allowlist=[MERCHANT], counterparties={}, max_per_tx_sats=100_000_000,
                     daily_budget_sats=200_000_000, weekly_budget_sats=500_000_000, per_counterparty_cap_sats=100_000_000,
                     human_threshold_sats=400_000, approval_ttl_s=120, human_pubkey=b2x(pub), split_window_s=0)
        keyfile_env()
        node = ApproveNode()
        s = Signer(tmp, rpc=node)
        d = s.handle({"method": "pay", "params": {"to": MERCHANT, "amount_sats": 400_000, "memo": "gate"}})
        self.assertEqual(d["verdict"], "needs_human", d)
        token, exp = d["approval_token"], d["approval_expires"]
        params = {"token": token, "dest": MERCHANT, "amount_sats": 400_000, "expiry": exp,
                  "signature": b2x(sign_approval(priv, token, MERCHANT, 400_000, exp))}
        # the signer serves every connection on its own thread (signer.py:1351). Both threads are let through
        # hold_approval's read before either writes; a signer that serialises `approve` never gets both there,
        # the barrier times out and the second approve is refused
        gate, calls, real = threading.Barrier(2, timeout=3), threading.local(), s.engine.store.get_approval

        def get_approval(tok):
            out = real(tok)
            calls.n = getattr(calls, "n", 0) + 1
            if calls.n == 2:                     # 1: _approve_signed's own read; 2: hold_approval's
                try:
                    gate.wait()
                except threading.BrokenBarrierError:
                    pass
            return out

        s.engine.store.get_approval = get_approval
        results = []
        ts = [threading.Thread(target=lambda: results.append(s.handle({"method": "approve", "params": dict(params)})))
              for _ in range(2)]
        for th in ts:
            th.start()
        for th in ts:
            th.join(20)
        self.assertEqual(len(node.sent), 1,
                         f"one human approval of 400,000 sat was paid {len(node.sent)} times: "
                         f"{[r.get('verdict') for r in results]}")


def own_rail(rpc: FakeRpc) -> Signer:
    tmp = Path(tempfile.mkdtemp(prefix="b2-agp087-"))
    keyfile_env()
    write_policy(tmp, per_counterparty_cap_sats=100_000, split_window_s=0, human_pubkey=HUMAN_PUB.hex())
    s = Signer(tmp, rpc=rpc)
    s.hot.notice_utxo("aa" * 32, 0, 300_000)
    return s


class HumanSignedReplay(unittest.TestCase):
    def test_w3_one_sweep_hot_signature_sweeps_once(self):
        s = own_rail(FakeRpc(height=1000, track_outputs=True))
        to = segwit_address("bcrt", bytes.fromhex("0014" + "77" * 20))
        exp = int(s.engine.clock()) + 600
        params = {"to": to, "amount_sats": 50_000, "expiry": exp,
                  "signature": b2x(sign(HUMAN_PRIV, sweep_message(s.hot.address, to, 50_000, exp)))}
        first = s.handle({"method": "sweep_hot", "params": dict(params)})
        self.assertTrue(first.get("ok"), first)
        again = [s.handle({"method": "sweep_hot", "params": dict(params)}).get("ok") for _ in range(2)]
        self.assertEqual(again, [False, False],
                         f"the human signed one sweep of 50,000 sat; the same signature swept {1 + sum(map(bool, again))} "
                         f"times ({len(s.rpc.sent)} transactions sent)")

    def test_w3_one_fund_treasury_signature_funds_once_and_no_outpoint_is_forgotten(self):
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = own_rail(rpc)
        exp = int(s.engine.clock()) + 600
        params = {"sats": 100_000, "expiry": exp,
                  "signature": b2x(sign(HUMAN_PRIV, treasury_fund_message(s.hot.address, s.treasury.address, 100_000, exp)))}
        first = s.handle({"method": "fund_treasury", "params": dict(params)})
        outpoint = first["treasury_outpoint"]
        second = s.handle({"method": "fund_treasury", "params": dict(params)})
        st = s.treasury.status()
        self.assertEqual(
            (len(rpc.sent), st["treasury_outpoint"]), (1, outpoint),
            f"one signature for 100,000 sat funded the treasury {len(rpc.sent)} times; the record now holds only "
            f"{st['treasury_outpoint']} ({st['treasury_funded_sats']} sat) and recovery_tx spends only that: {second}")


class SellerSetsTheLockTime(unittest.TestCase):
    def test_c2_the_sellers_min_expiry_does_not_set_how_long_the_funding_is_locked(self):
        from test_mainnet_readiness import URL, Rig

        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        asked = 1_000_000                                         # about 19 years of blocks

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
            if path.endswith("/open"):
                if json.loads(body or b"{}").get("preflight") is True:
                    return 200, {}, json.dumps({"preflight": True}).encode()       # the seller's word
                return 400, {}, b'{"error": "bad_expiry"}'                          # then it refuses the funded open
            st, h, out = rig.provider.serve(method, path, headers or {}, body or b"", url)
            if st == 402 and "PAYMENT-REQUIRED" in h:
                pr = unb64json(h["PAYMENT-REQUIRED"])
                for acc in pr["accepts"]:
                    acc["extra"]["minExpiryBlocks"] = asked
                    acc["extra"]["maxExpiryBlocks"] = 2 * asked
                h = {**h, "PAYMENT-REQUIRED": b64json(pr)}
            return st, h, out

        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=http):
            r = rig.signer.handle({"method": "xbt402_pay", "params": {"url": URL, "max_sats": 500}})
        rec = rig.channel()
        if rec is None:
            return                                                # refused before funding: the fixed behaviour
        locked = rec.expiry - rec.open_height
        most = rig.signer._max_expiry_blocks()                    # what the socket's open_channel is held to
        self.assertLessEqual(
            locked, most,
            f"the offer said minExpiryBlocks {asked}; the wallet funded {rec.funding_sats} sat ({len(rig.node.sent)} tx) "
            f"locked for {locked} blocks (owner's policy: {rig.signer.config.channel_expiry_blocks}, socket bound {most}); "
            f"state {rec.state}: {r.get('reason') or r.get('verdict')}")


if __name__ == "__main__":
    unittest.main()
