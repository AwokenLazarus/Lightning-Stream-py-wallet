"""AGP-085: what is written ahead of a broadcast is taken back only on the node's own refusal.

F1  a channel funding keeps its pending record and payer key on every broadcast failure but the node's
    own JSON-RPC refusal (AGP-084 found item 4). Before, a send and a follow-up `gettxout` that both
    timed out forgot the key of a funding the node had taken.
T1  `fund_treasury` records the outpoint before the broadcast (found item 5). Before, a crash between
    the broadcast and `record_funding` left no record of it.
A1  `approve` holds its token while the payment runs and gives it back when the node refuses (found
    item 6). Before, the token was spent first and a refusal left no payment and no token. A payment of
    unknown fate never frees the token.

Same names as xbt-rs crates/xbt-signer/tests/agp085_write_ahead.rs where the Rust signer has the path.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.approval import b2x, generate_keypair, sign, sign_approval, treasury_fund_message
from agentwallet.electrum import ElectrumError
from agentwallet.rpc import KnotsRpcError, KnotsRpcRefused
from agentwallet.signer import Signer

from _agp013 import HUMAN_PRIV, HUMAN_PUB, FakeRpc, keyfile_env, write_policy
from test_mainnet_readiness import API, Rig

from xbt402.tx import Tx

MERCHANT = "bcrt1qmerchant0000000000000000000000000000qq"
REFUSAL = '{"code":-26,"message":"bad-txns-inputs-missingorspent"}'


class Killed(BaseException):
    """The signer process dies (not an Exception: nothing in the signer catches it)."""


class Link:
    """The signer's connection to its node. `send` and `lookup` say what happens to the next
    sendrawtransaction and gettxout: None (the node answers), "lost" (the node runs the call and the
    answer never arrives), "killed" (the node runs the call and the signer dies), or an exception the
    call raises without reaching the node."""

    def __init__(self, node):
        self.node, self.real = node, node.call
        self.send: object = None
        self.lookup: object = None
        self.sends = 0
        self.on_send = None
        node.call = self

    def __call__(self, method, *p):
        if method == "sendrawtransaction":
            self.sends += 1
            if self.on_send:
                self.on_send(p[0])
            if self.send in ("lost", "killed"):
                self.real(method, *p)
                raise TimeoutError("timed out") if self.send == "lost" else Killed()
            if isinstance(self.send, BaseException):
                raise self.send
        if method == "gettxout" and isinstance(self.lookup, BaseException):
            raise self.lookup
        return self.real(method, *p)

    def heal(self):
        self.send = self.lookup = None


def attempt(fn):
    """What `fn` returned, or the exception it raised."""
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        return e


def own_rail(rpc: FakeRpc, **policy) -> Signer:
    """A signer whose `open_channel` / `pay` rail funds a channel with no provider open."""
    tmp = Path(tempfile.mkdtemp(prefix="b2-agp085-"))
    keyfile_env()
    write_policy(tmp, **{"per_counterparty_cap_sats": 100_000, "split_window_s": 0, "open_retry_s": 0,
                         "human_pubkey": HUMAN_PUB.hex(), **policy})
    s = Signer(tmp, rpc=rpc)
    s.hot.notice_utxo("aa" * 32, 0, 300_000)
    return s


def restart(s: Signer) -> Signer:
    return Signer(s.root, rpc=s.rpc)


def open_own(s: Signer) -> object:
    return attempt(lambda: s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000}}))


class FundingKeepsItsKey(unittest.TestCase):
    """F1, the provider rail (`xbt402_pay` -> Xbt402Session.open)."""

    def rig(self):
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        return rig, Link(rig.node)

    def test_f1_a_funding_whose_send_and_lookup_both_time_out_keeps_its_payer_key(self):
        rig, link = self.rig()
        link.send, link.lookup = "lost", TimeoutError("timed out")
        out = attempt(rig.pay)
        self.assertEqual(len(rig.node.sent), 1, "the node took the funding")
        rec = rig.channel()
        self.assertIsNotNone(rec, f"the node holds the funding and its pending record is gone: {out!r}")
        self.assertEqual((rec.state, rec.funding_txid), ("pending", Tx.parse(bytes.fromhex(rig.node.sent[0])).txid()))
        self.assertIn(rec.chan, rig.signer.channels._secrets, "the payer key")
        # a restart still has it, and the watcher opens the channel once the node answers again
        link.heal()
        rig.restart()
        self.assertIn(rec.chan, rig.signer.channels._secrets)
        rig.node.mine(1)
        acts = rig.tick()
        self.assertEqual(acts[0]["open_retry"]["state"], "open", acts)
        self.assertEqual(rig.pay()["charged_sats"], 500)

    def test_f1_a_funding_the_node_never_got_is_kept_and_sent_again(self):
        rig, link = self.rig()
        link.send = TimeoutError("timed out")           # nothing reached the node, and it says so afterwards
        attempt(rig.pay)
        rec = rig.channel()
        self.assertIsNotNone(rec, "a timeout is not the node's refusal: the record stays")
        self.assertEqual((rec.state, rig.node.sent), ("pending", []))
        spent = Tx.parse(bytes.fromhex(rec.funding_hex)).inputs[0]
        self.assertFalse(rig.signer.hot.holds(spent.txid[::-1].hex(), spent.vout),
                         "the coin the kept funding spends is not offered to another funding")
        link.heal()
        rig.tick()
        self.assertEqual([Tx.parse(bytes.fromhex(h)).txid() for h in rig.node.sent], [rec.funding_txid],
                         "the watcher sent the kept funding")
        rig.node.mine(1)
        self.assertEqual(rig.tick()[0]["open_retry"]["state"], "open")

    def test_f1_a_funding_the_node_refused_is_forgotten(self):
        rig, link = self.rig()
        link.send = KnotsRpcRefused(REFUSAL)
        before = rig.signer.hot.balance_sats()
        attempt(rig.pay)
        self.assertIsNone(rig.channel(), "the node refused the funding: there is nothing to keep")
        self.assertEqual(rig.signer.channels._secrets, {})
        self.assertEqual(rig.signer.hot.balance_sats(), before, "the coin is still ours to spend")

    def test_f1_a_refused_funding_the_node_cannot_be_asked_about_is_kept(self):
        """A refusal can be `already in the mempool`: only the node's answer that it has no such
        output makes the refusal final."""
        rig, link = self.rig()
        link.send, link.lookup = KnotsRpcRefused(REFUSAL), TimeoutError("timed out")
        attempt(rig.pay)
        self.assertIsNotNone(rig.channel())
        self.assertEqual(rig.channel().state, "pending")

    def test_f1_a_crash_in_the_broadcast_keeps_the_record(self):
        rig, link = self.rig()
        link.send = "killed"
        with self.assertRaises(Killed):
            rig.pay()
        link.heal()
        rig.restart()
        rec = rig.channel()
        self.assertEqual((rec.state, rec.chan in rig.signer.channels._secrets), ("pending", True))


class OwnRailFundingKeepsItsKey(unittest.TestCase):
    """F1, the signer's own rail (`open_channel`, `pay` to a registered payTo): no provider open."""

    def setUp(self):
        self.rpc = FakeRpc(height=1000, track_outputs=True)
        self.s = own_rail(self.rpc)
        self.link = Link(self.rpc)

    def test_f1_a_funding_whose_send_and_lookup_both_time_out_keeps_its_payer_key(self):
        self.link.send, self.link.lookup = "lost", TimeoutError("timed out")
        out = open_own(self.s)
        self.assertEqual(len(self.rpc.sent), 1, "the node took the funding")
        rec = self.s.channels.get(API)
        self.assertIsNotNone(rec, f"the node holds the funding and its pending record is gone: {out!r}")
        self.assertEqual(rec.state, "pending")
        self.assertIn(rec.chan, self.s.channels._secrets)
        self.assertFalse(self.s.hot.holds("aa" * 32, 0), "the coin the funding spent")
        # the node answers again: the next call finds the funding and the channel is open
        self.link.heal()
        s = restart(self.s)
        r = s.handle({"method": "pay", "params": {"to": API, "amount_sats": 700, "memo": "a"}})
        self.assertEqual((r["verdict"], r["chan"]), ("allow", rec.chan), r)
        self.assertEqual((s.channels.get(API).state, len(self.rpc.sent)), ("open", 1))

    def test_f1_the_watcher_opens_a_kept_funding(self):
        self.link.send = TimeoutError("timed out")      # the node never got it
        open_own(self.s)
        rec = self.s.channels.get(API)
        self.assertIsNotNone(rec)
        self.assertEqual((rec.state, self.rpc.sent), ("pending", []))
        self.link.heal()
        self.s.watch_tick()
        self.assertEqual([Tx.parse(bytes.fromhex(h)).txid() for h in self.rpc.sent], [rec.funding_txid])
        self.assertEqual(self.s.channels.get(API).state, "open")

    def test_f1_a_second_open_does_not_fund_a_second_channel(self):
        self.link.send, self.link.lookup = "lost", TimeoutError("timed out")
        open_own(self.s)
        again = open_own(self.s)                        # the node still does not answer
        self.assertEqual(len(self.rpc.sent), 1, f"one funding only: {again!r}")
        self.assertEqual(self.s.channels.get(API).state, "pending")

    def test_f1_a_funding_the_node_refused_is_forgotten(self):
        self.link.send = KnotsRpcRefused(REFUSAL)
        open_own(self.s)
        self.assertIsNone(self.s.channels.get(API))
        self.assertEqual(self.s.channels._secrets, {})
        self.assertTrue(self.s.hot.holds("aa" * 32, 0))

    def test_f1_an_electrum_servers_error_is_not_the_nodes_refusal(self):
        """The light backend's servers are not ours: what they answer never forgets a key."""
        self.link.send = ElectrumError("bad-txns-inputs-missingorspent")
        open_own(self.s)
        rec = self.s.channels.get(API)
        self.assertIsNotNone(rec, "a server's word forgot the payer key")
        self.assertEqual(rec.state, "pending")


_SIGNED = iter(range(1, 1_000_000))


def fund_treasury(s: Signer, sats: int = 100_000) -> object:
    # each call is a funding the human signed for itself (AGP-089: a signature is used once)
    exp = int(s.engine.clock()) + 600 + next(_SIGNED)
    sig = sign(HUMAN_PRIV, treasury_fund_message(s.hot.address, s.treasury.address, sats, exp))
    return attempt(lambda: s.handle({"method": "fund_treasury",
                                     "params": {"sats": sats, "expiry": exp, "signature": b2x(sig)}}))


def treasury_file(s: Signer) -> dict:
    return json.loads((s.root / ".run" / "treasury.json").read_text(encoding="utf-8"))


class TreasuryFundingWriteAhead(unittest.TestCase):
    def setUp(self):
        self.rpc = FakeRpc(height=1000, track_outputs=True)
        self.s = own_rail(self.rpc)
        self.link = Link(self.rpc)

    def test_t1_the_treasury_funding_is_on_disk_before_it_is_broadcast(self):
        seen = []
        self.link.on_send = lambda raw: seen.append((Tx.parse(bytes.fromhex(raw)).txid(),
                                                     (treasury_file(self.s).get("pending_funding") or {}).get("txid")))
        r = fund_treasury(self.s)
        self.assertEqual(len(seen), 1, r)
        self.assertEqual(seen[0][1], seen[0][0], "the outpoint was not on disk when the funding was sent")
        self.assertEqual(r["treasury_outpoint"], f"{seen[0][0]}:0", r)
        self.assertIsNone(treasury_file(self.s).get("pending_funding"), "a sent funding is no longer pending")

    def test_t1_a_crash_after_the_broadcast_leaves_the_outpoint_recorded(self):
        self.link.send = "killed"
        with self.assertRaises(Killed):
            self.s.handle({"method": "fund_treasury", "params": self._params()})
        txid = Tx.parse(bytes.fromhex(self.rpc.sent[0])).txid()
        self.link.heal()
        again = restart(self.s)
        st = again.treasury.status()
        self.assertEqual((st["treasury_outpoint"], st["treasury_funded_sats"]), (f"{txid}:0", 100_000),
                         "the treasury's coins are on the chain and the signer has no record of them")
        self.assertFalse(again.hot.holds("aa" * 32, 0))

    def _params(self, sats: int = 100_000) -> dict:
        exp = int(self.s.engine.clock()) + 600
        sig = sign(HUMAN_PRIV, treasury_fund_message(self.s.hot.address, self.s.treasury.address, sats, exp))
        return {"sats": sats, "expiry": exp, "signature": b2x(sig)}

    def test_t1_a_funding_the_node_refused_is_not_recorded(self):
        self.link.send = KnotsRpcRefused(REFUSAL)
        r = fund_treasury(self.s)
        self.assertIsInstance(r, KnotsRpcRefused)
        self.assertIsNone(treasury_file(self.s).get("pending_funding"))
        self.assertEqual(self.s.treasury.status()["treasury_outpoint"], "")
        self.assertTrue(self.s.hot.holds("aa" * 32, 0))

    def test_t1_a_funding_of_unknown_fate_stays_recorded_and_is_not_funded_twice(self):
        self.link.send, self.link.lookup = "lost", TimeoutError("timed out")
        r = fund_treasury(self.s)
        self.assertIsInstance(r, KnotsRpcError)
        self.assertNotIsInstance(r, KnotsRpcRefused)
        txid = Tx.parse(bytes.fromhex(self.rpc.sent[0])).txid()
        self.assertEqual((treasury_file(self.s).get("pending_funding") or {}).get("txid"), txid,
                         "the node took the funding and the signer has no record of its outpoint")
        again = fund_treasury(self.s)                   # the node still does not answer
        self.assertEqual(len(self.rpc.sent), 1, f"a second funding went out: {again!r}")
        self.assertIn("treasury_pending_outpoint", self.s.treasury.status())
        # the node answers again: the watcher finds the output
        self.link.heal()
        self.s.watch_tick()
        st = self.s.treasury.status()
        self.assertEqual((st["treasury_outpoint"], st["treasury_funded_sats"]), (f"{txid}:0", 100_000))
        self.assertNotIn("treasury_pending_outpoint", st)

    def test_t1_a_funding_the_node_never_got_is_sent_again(self):
        self.link.send = TimeoutError("timed out")
        fund_treasury(self.s)
        self.assertEqual(self.rpc.sent, [])
        pend = treasury_file(self.s).get("pending_funding") or {}
        self.assertTrue(pend.get("txid"), "nothing was recorded")
        self.link.heal()
        again = restart(self.s)                         # the start settles it too
        self.assertEqual([Tx.parse(bytes.fromhex(h)).txid() for h in self.rpc.sent], [pend["txid"]])
        self.assertEqual(again.treasury.status()["treasury_outpoint"], f"{pend['txid']}:0")

    def test_t1_a_kept_funding_the_node_then_refuses_no_longer_blocks_and_stays_on_record(self):
        """The node has no such output and will not take the transaction again. The first send may
        have left the node all the same, so the outpoint stays in the file; a new funding is allowed."""
        self.link.send = TimeoutError("timed out")
        fund_treasury(self.s)
        txid = (treasury_file(self.s).get("pending_funding") or {}).get("txid")
        self.assertTrue(txid, "nothing was recorded")
        self.link.send = KnotsRpcRefused(REFUSAL)
        self.s.watch_tick()
        doc = treasury_file(self.s)
        self.assertEqual((doc.get("pending_funding"), [p["txid"] for p in doc.get("unsettled_fundings") or []]),
                         (None, [txid]))
        self.assertEqual(self.s.treasury.status()["treasury_unsettled_outpoints"], [f"{txid}:0"])
        self.link.heal()
        self.s.hot.notice_utxo("bb" * 32, 0, 300_000)
        r = fund_treasury(self.s)
        self.assertTrue(isinstance(r, dict) and r.get("treasury_outpoint"), r)
        self.assertEqual(restart(self.s).treasury.status()["treasury_unsettled_outpoints"], [f"{txid}:0"])

    def test_t1_an_unsettled_funding_that_confirms_after_all_is_recorded(self):
        self.link.send = TimeoutError("timed out")
        fund_treasury(self.s)
        pend = treasury_file(self.s).get("pending_funding") or {}
        self.assertTrue(pend.get("txid"), "nothing was recorded")
        self.link.send = KnotsRpcRefused(REFUSAL)
        self.s.watch_tick()
        self.link.heal()
        self.rpc.utxos[(pend["txid"], 0)] = {"value": 100_000 / 1e8, "scriptPubKey": {"hex": self.s.treasury.spk.hex()}}
        self.s.watch_tick()
        st = self.s.treasury.status()
        self.assertEqual((st["treasury_outpoint"], st["treasury_funded_sats"]), (f"{pend['txid']}:0", 100_000))
        self.assertNotIn("treasury_unsettled_outpoints", st)

    def test_t1_a_malformed_pending_funding_is_refused_not_read_as_none(self):
        self.link.send = TimeoutError("timed out")
        fund_treasury(self.s)
        path = self.s.root / ".run" / "treasury.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("pending_funding", doc, "nothing was recorded")
        doc["pending_funding"] = {"txid": "zz"}
        path.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaises(Exception) as cm:
            restart(self.s)
        self.assertIn("pending_funding", str(cm.exception))


class ApproveNode:
    """The node of test_approval_attacks, with a `sendtoaddress` that can fail."""

    wallet = "agent"

    def __init__(self):
        self.sent: list[tuple] = []
        self.answer: object = "ab" * 32
        self.seen: list[object] = []
        self.signer: Signer | None = None
        self.token = ""

    def call(self, method, *args):
        if method == "getbalances":
            return {"mine": {"trusted": 50, "untrusted_pending": 0, "immature": 0}}
        if method == "sendtoaddress":
            if self.signer is not None:
                self.seen.append((self.signer.engine.store.get_approval(self.token) or {}).get("used"))
            if isinstance(self.answer, BaseException):
                raise self.answer
            self.sent.append((args[0], args[1]))
            return self.answer
        if method == "listunspent":
            return []
        if method == "estimatesmartfee":
            return {"feerate": 0.00001}
        if method == "getblockchaininfo":
            return {"chain": "regtest", "blocks": 200, "initialblockdownload": False}
        raise RuntimeError(method)


class ApprovalHeldNotSpent(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="b2-agp085-"))
        self.priv, self.pub = generate_keypair()
        write_policy(self.tmp, allowlist=[MERCHANT], counterparties={}, max_per_tx_sats=100_000_000,
                     daily_budget_sats=200_000_000, weekly_budget_sats=500_000_000,
                     per_counterparty_cap_sats=100_000_000, human_threshold_sats=400_000, approval_ttl_s=120,
                     human_pubkey=b2x(self.pub))
        keyfile_env()
        self.node = ApproveNode()
        self.s = Signer(self.tmp, rpc=self.node)
        self.node.signer = self.s
        d = self.s.handle({"method": "pay", "params": {"to": MERCHANT, "amount_sats": 400_000, "memo": "gate"}})
        self.assertEqual(d["verdict"], "needs_human", d)
        self.token, self.exp = d["approval_token"], d["approval_expires"]
        self.node.token = self.token

    def approve(self, s: Signer | None = None) -> object:
        sig = sign_approval(self.priv, self.token, MERCHANT, 400_000, self.exp)
        return attempt(lambda: (s or self.s).handle({"method": "approve", "params": {
            "token": self.token, "dest": MERCHANT, "amount_sats": 400_000, "expiry": self.exp, "signature": b2x(sig)}}))

    def test_a1_a_payment_the_node_refused_does_not_spend_the_approval(self):
        self.node.answer = KnotsRpcRefused('{"code":-6,"message":"Insufficient funds"}')
        self.assertIsInstance(self.approve(), KnotsRpcRefused)
        self.assertEqual(self.node.sent, [])
        self.node.answer = "ab" * 32                    # the human tops the wallet up and signs nothing new
        r = self.approve()
        self.assertEqual((getattr(r, "get", lambda *_: r)("verdict"), len(self.node.sent)), ("allow", 1),
                         f"the node refused the payment and the approval was spent on it: {r!r}")
        self.assertTrue(r.get("approved"))
        self.assertIsNone(self.s.engine.store.get_approval(self.token), "a paid approval is gone")
        replay = self.approve()
        self.assertEqual((replay["verdict"], len(self.node.sent)), ("deny", 1), replay)

    def test_a1_a_payment_the_policy_denied_does_not_spend_the_approval(self):
        self.s.light = True                             # the node is gone: on-chain pay is refused before any send
        r = self.approve()
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "light_backend"), r)
        self.s.light = False
        r = self.approve()
        self.assertEqual((getattr(r, "get", lambda *_: r)("verdict"), len(self.node.sent)), ("allow", 1),
                         f"nothing was sent and the approval was spent: {r!r}")

    def test_a1_the_approval_is_held_while_the_payment_runs(self):
        self.approve()
        self.assertEqual(self.node.seen, [True], "the token was not marked used on disk when the node was asked")

    def test_a1_an_approval_whose_payment_fate_is_unknown_is_never_reusable(self):
        for unknown in (TimeoutError("timed out"), KnotsRpcError("RPC HTTP 503"), ConnectionResetError("reset")):
            with self.subTest(unknown=unknown):
                self.setUp()
                self.node.answer = unknown
                r = self.approve()
                self.assertIsInstance(r, KnotsRpcError)
                self.assertNotIsInstance(r, KnotsRpcRefused)
                self.node.answer = "ab" * 32
                for s in (self.s, Signer(self.tmp, rpc=self.node)):       # and after a restart
                    again = self.approve(s)
                    self.assertEqual((again["verdict"], again["rule"]), ("deny", "approval_replay"), again)
                self.assertEqual(self.node.sent, [], "the node may have paid once already")

    def test_a1_a_crash_in_the_payment_leaves_the_approval_spent(self):
        self.node.answer = Killed()
        with self.assertRaises(Killed):
            self.s.handle({"method": "approve", "params": {
                "token": self.token, "dest": MERCHANT, "amount_sats": 400_000, "expiry": self.exp,
                "signature": b2x(sign_approval(self.priv, self.token, MERCHANT, 400_000, self.exp))}})
        self.node.answer = "ab" * 32
        again = self.approve(Signer(self.tmp, rpc=self.node))
        self.assertEqual((again["verdict"], self.node.sent), ("deny", []), again)

    def test_a1_a_released_approval_still_expires(self):
        self.node.answer = KnotsRpcRefused('{"code":-6,"message":"Insufficient funds"}')
        self.approve()
        self.node.answer = "ab" * 32
        with mock.patch.object(self.s.engine, "clock", return_value=self.s.engine.clock() + 121):
            r = self.approve()
        self.assertEqual((r["verdict"], r["rule"], self.node.sent), ("deny", "approval_expired", []), r)


if __name__ == "__main__":
    unittest.main()
