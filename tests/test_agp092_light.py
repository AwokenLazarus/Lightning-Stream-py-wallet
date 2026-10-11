"""AGP-092 (fix wave 4, light client): the two rules of `agentwallet/electrum.py`, from the sides the
AGP-087 tests do not take (the Rust tests of the same names are in xbt-rs:
crates/xbt-electrum/tests/agp092_light.rs).

  * Unknown is not absent: "not there" is answered only when every server asked answered, and a close
    is booked only on a confirmed spend proven into our header chain.
  * A call has a deadline, and a server is asked only for what it listed itself.

Every test fails on B2 `3fab1c9` (the fix's base) except those named `test_evidence_*`.
"""

from __future__ import annotations

import os
import socket
import ssl
import threading
import time
import unittest

from agentwallet import chain as chainbackend
from agentwallet.b1path import ensure_b1
from agentwallet.electrum import ElectrumBackend, ElectrumConnection, ElectrumError, scripthash
from agentwallet.signer import Signer

ensure_b1()
from xbt402.tx import Tx, TxIn, TxOut  # noqa: E402

from _electrum_sim import CHECKPOINT, FakeElectrum, SimChain  # noqa: E402
from test_electrum_backend import API, LightRig, backend  # noqa: E402

BUSY = "server busy"


class Knobs(FakeElectrum):
    """FakeElectrum that answers chosen methods with an error (`busy`), or after a sleep (`slow`)."""

    def __init__(self, sim):
        super().__init__(sim)
        self.busy: set[str] = set()
        self.slow: dict[str, float] = {}

    def answer(self, client, method, p):
        if method in self.slow:
            time.sleep(self.slow[method])
        if method in self.busy:
            raise ValueError(BUSY)
        return super().answer(client, method, p)


def spk() -> str:
    return "0014" + os.urandom(20).hex()


def reasons(b, server) -> list[str]:
    return [f["reason"] for f in b.flags if f["server"] == server.url]


class UnknownIsNotAbsent(unittest.TestCase):
    def setUp(self):
        self.sim = SimChain(height=200)
        self.liar, self.honest = Knobs(self.sim), Knobs(self.sim)
        self.addCleanup(self.liar.close)
        self.addCleanup(self.honest.close)
        self.spk = spk()
        self.txid = self.sim.credit("", 0, 70_000, self.spk)

    def light(self, *servers, **kw):
        kw.setdefault("timeout", 3)
        b = ElectrumBackend([s.url for s in servers], chain="regtest", checkpoint=(CHECKPOINT, self.sim.bhash(CHECKPOINT)), **kw)
        self.addCleanup(b.close)
        return b

    def test_a_hiding_server_and_a_busy_honest_one_are_unknown_not_absent(self):
        self.liar.hide.add(self.txid)
        self.honest.busy.add("blockchain.scripthash.get_history")
        b = self.light(self.liar, self.honest)
        for mempool in (True, False):
            with self.assertRaises(ElectrumError):
                b.call("gettxout", self.txid, 0, mempool)
        with self.assertRaisesRegex(ElectrumError, "not known"):
            b.call("getrawtransaction", self.txid, True)
        self.honest.busy.clear()
        self.assertEqual(b.call("gettxout", self.txid, 0, True)["confirmations"], 1)

    def test_an_unanswered_proof_is_unknown_not_unconfirmed(self):
        self.liar.claim_height[self.txid] = 0
        self.liar.busy.add("blockchain.transaction.get_merkle")
        self.honest.busy.add("blockchain.transaction.get_merkle")
        b = self.light(self.liar, self.honest)
        with self.assertRaises(ElectrumError):
            b.call("gettxout", self.txid, 0, False)
        # with the mempool the liar's claim is an answer a caller cannot be hurt by: 0 confirmations
        self.assertEqual(b.call("gettxout", self.txid, 0, True)["confirmations"], 0)
        with self.assertRaises(ElectrumError):
            b.call("scantxoutset", "start", [f"raw({self.spk})"])
        self.honest.busy.clear()
        self.assertEqual(b.call("gettxout", self.txid, 0, False)["confirmations"], 1)
        self.assertEqual(len(b.call("scantxoutset", "start", [f"raw({self.spk})"])["unspents"]), 1)

    def test_a_busy_error_is_not_no_such_transaction(self):
        self.honest.busy.add("blockchain.transaction.get")
        b = self.light(self.honest)
        with self.assertRaisesRegex(ElectrumError, "not known"):
            b.call("gettxout", self.txid, 0, True)
        with self.assertRaises(ElectrumError):
            b.call("gettxspendingprevout", [{"txid": self.txid, "vout": 0}])
        # a server's own "no such transaction" still is one
        self.honest.busy.clear()
        self.assertIsNone(b.call("gettxout", "ab" * 32, 0, True))

    def test_a_coin_whose_transaction_went_unanswered_fails_the_scan(self):
        self.honest.slow["blockchain.transaction.get"] = 1.2
        b = self.light(self.honest, timeout=0.4)
        with self.assertRaises(ElectrumError):
            b.call("scantxoutset", "start", [f"raw({self.spk})"])
        self.honest.slow.clear()
        self.assertEqual(len(b.call("scantxoutset", "start", [f"raw({self.spk})"])["unspents"]), 1)

    def test_evidence_a_wrong_height_refused_in_the_servers_own_words_is_a_withdrawn_claim(self):
        """Passes before and after: "not in block at height" answers the proof request, so the claim is
        void and the output reads as not found (a busy error would leave it unknown)."""
        self.liar.claim_height[self.txid] = 150
        b = self.light(self.liar)
        self.assertIsNone(b.call("gettxout", self.txid, 0, True))

    def test_evidence_every_server_hiding_reads_as_absent(self):
        """The stated limit: with every configured server hiding a transaction the backend cannot know
        better. So a close is never booked on this answer: `proven_spend` is what is asked."""
        self.liar.hide.add(self.txid)
        b = self.light(self.liar)
        self.assertIsNone(b.call("gettxout", self.txid, 0, True))
        self.assertIsNone(b.proven_spend(self.txid, 0, self.spk), "and no spend is claimed for it")
        self.assertEqual(chainbackend.spend_is_evidence(b, self.txid, 0, self.spk), (False, ""))

    def test_a_confirmed_spend_is_proven_while_the_funding_itself_is_hidden(self):
        spend = Tx(version=2, inputs=[TxIn(bytes.fromhex(self.txid)[::-1], 0)],
                   outputs=[TxOut(60_000, bytes.fromhex(spk()))], locktime=0)
        self.sim.call("sendrawtransaction", spend.hex())
        b = self.light(self.honest)
        self.assertIsNone(b.proven_spend(self.txid, 0, self.spk), "a spend in a mempool proves nothing")
        self.sim.mine(1)
        self.honest.hide.add(self.txid)
        self.assertEqual(b.proven_spend(self.txid, 0, self.spk)[0], spend.txid())
        self.assertEqual(chainbackend.spend_is_evidence(b, self.txid, 0, self.spk), (True, spend.txid()))
        # an invented spend, listed as confirmed with no proof, is not one
        other = self.sim.credit("", 0, 5_000, self.spk)
        fake = Tx(version=2, inputs=[TxIn(bytes.fromhex(other)[::-1], 0)], outputs=[TxOut(4_000, bytes.fromhex(spk()))], locktime=0)
        self.honest.extra_raw[fake.txid()] = fake.hex()
        self.honest.extra_history[scripthash(bytes.fromhex(self.spk))] = [{"tx_hash": fake.txid(), "height": 150}]
        self.assertIsNone(b.proven_spend(other, 0, self.spk))


class ACallHasADeadline(unittest.TestCase):
    def setUp(self):
        self.sim = SimChain(height=200)
        self.liar, self.honest = Knobs(self.sim), FakeElectrum(self.sim)
        self.addCleanup(self.liar.close)
        self.addCleanup(self.honest.close)
        self.spk = spk()
        self.txid = self.sim.credit("", 0, 70_000, self.spk)
        self.sh = scripthash(bytes.fromhex(self.spk))

    def light(self, **kw):
        kw.setdefault("timeout", 1)
        b = ElectrumBackend([self.liar.url, self.honest.url], chain="regtest",
                            checkpoint=(CHECKPOINT, self.sim.bhash(CHECKPOINT)), **kw)
        self.addCleanup(b.close)
        return b

    def test_a_list_of_real_unrelated_transactions_ends_at_the_first(self):
        unrelated = [self.sim.credit("", 0, 1_000 + k, spk()) for k in range(40)]
        self.liar.extra_history[self.sh] = [{"tx_hash": t, "height": 150} for t in unrelated]
        b = self.light()
        b.sync()
        self.liar.slow["blockchain.transaction.get"] = 0.25
        before = self.liar.calls.count("blockchain.transaction.get")
        t = time.monotonic()
        self.assertIsNotNone(b.call("gettxout", self.txid, 0, False))
        self.assertLess(time.monotonic() - t, 2.0)
        self.assertLessEqual(self.liar.calls.count("blockchain.transaction.get") - before, 3)
        self.assertIn("get_history lists a transaction that neither pays nor spends the script", reasons(b, self.liar))

    def test_a_slow_list_of_payments_ends_at_the_call_deadline(self):
        """Entries that pay the script cannot be told from unconfirmed payments, so nothing cuts the list
        short but the call's deadline; the honest server's proof still answers."""
        rows = []
        for n in range(200):
            tx = Tx(version=2, inputs=[TxIn(bytes([0x77]) * 32, n)], outputs=[TxOut(1_000, bytes.fromhex(self.spk))], locktime=0)
            self.liar.extra_raw[tx.txid()] = tx.hex()
            rows.append({"tx_hash": tx.txid(), "height": 0})
        self.liar.extra_history[self.sh] = rows
        b = self.light(call_deadline=1.5)
        b.sync()
        self.liar.slow["blockchain.transaction.get"] = 0.3
        t = time.monotonic()
        self.assertEqual(b.call("gettxout", self.txid, 0, False)["confirmations"], 1)
        took = time.monotonic() - t
        self.assertLess(took, 2.6, f"held {took:.2f} s with a call deadline of 1.5 s")
        self.assertTrue(any("transaction.get" in r for r in reasons(b, self.liar)), b.flags)

    def test_a_transaction_listed_twice_is_one_claim(self):
        self.liar.extra_history[self.sh] = [{"tx_hash": self.txid, "height": 150 + x} for x in range(30)]
        b = ElectrumBackend([self.liar.url], chain="regtest", checkpoint=(CHECKPOINT, self.sim.bhash(CHECKPOINT)), timeout=3)
        self.addCleanup(b.close)
        self.assertEqual(b.call("gettxout", self.txid, 0, False)["confirmations"], 1)
        self.assertLessEqual(self.liar.calls.count("blockchain.transaction.get_merkle"), 2)
        self.assertTrue(any("more than once" in r for r in reasons(b, self.liar)), b.flags)

    def test_claims_above_the_tip_force_one_sync_round(self):
        self.liar.claim_height[self.txid] = 999_999
        self.liar.extra_history[self.sh] = [{"tx_hash": self.txid, "height": 1_000_000 + x} for x in range(50)]
        b = self.light(timeout=3)
        b.sync()
        before = self.honest.calls.count("blockchain.headers.subscribe")
        self.assertIsNotNone(b.call("gettxout", self.txid, 0, False))
        self.assertLessEqual(self.honest.calls.count("blockchain.headers.subscribe") - before, 5)
        self.assertTrue(any("above the tip it reports" in r for r in reasons(b, self.liar)), b.flags)


class ConnectHasOneDeadline(unittest.TestCase):
    def test_evidence_a_trickled_tls_handshake_ends_at_the_timeout(self):
        """Passes before and after (CPython holds one do_handshake() to the socket timeout as a deadline);
        the Rust client did not, and connect() now spends one deadline on TCP and TLS together."""
        l = socket.socket()
        l.bind(("127.0.0.1", 0))
        l.listen(1)
        self.addCleanup(l.close)

        def serve():
            try:
                s, _ = l.accept()
                s.recv(4096)
                s.sendall(bytes([0x16, 0x03, 0x03, 0x40, 0x00]))      # a handshake record of 16,384 bytes...
                for _ in range(40):
                    time.sleep(0.1)
                    s.sendall(b"\0")                                   # ...one byte at a time
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        c = ElectrumConnection(f"ssl://localhost:{l.getsockname()[1]}", timeout=0.3)
        t = time.monotonic()
        with self.assertRaises((ElectrumError, ssl.SSLError, OSError)):
            c.connect()
        self.assertLess(time.monotonic() - t, 1.2)

    def test_a_server_that_trickles_its_subscriptions_does_not_hold_connect(self):
        """Reconnecting re-sends every subscription; each used to wait a full timeout of its own."""
        sim = SimChain(height=200)
        srv = Knobs(sim)
        self.addCleanup(srv.close)
        c = ElectrumConnection(srv.url, timeout=0.5)
        self.addCleanup(c.close)
        c.connect()
        for _ in range(8):
            c.subscribe("blockchain.scripthash.subscribe", scripthash(bytes.fromhex(spk())))
        c.close()
        srv.slow["blockchain.scripthash.subscribe"] = 0.3
        t = time.monotonic()
        with self.assertRaises(ElectrumError):
            c.connect()
        self.assertLess(time.monotonic() - t, 1.2, "8 subscriptions at 0.3 s each under a 0.5 s timeout")


class ACloseIsBookedOnProof(unittest.TestCase):
    """B2's wallet on the light backend: the two places that read an empty gettxout as "the funding was
    spent" (`Signer._refund_locked`, `Xbt402Session.funding_spent`) now ask for the proven spend."""

    def opened(self):
        rig = LightRig(regtest_mine=False)
        self.addCleanup(rig.close_all)
        self.assertEqual(rig.fund_hot()["noticed"], 1)
        r = rig.call("xbt402_pay", url=API + "/agp092/echo", max_sats=500)
        self.assertEqual((r["verdict"], r["rule"]), ("pending", "funding_unconfirmed"), r)
        rig.mine(1)
        rig.tick()
        self.assertEqual(rig.channel().state, "open")
        return rig

    def restart(self, rig):
        rig.light.close()
        rig.light = backend(rig.fake, sim=rig.node)
        rig.signer = Signer(rig.tmp, rpc=rig.light)

    def test_funding_spent_is_not_proven_by_servers_that_hide_the_funding(self):
        rig = self.opened()
        rec = rig.channel()
        self.assertTrue(rec.funding_height, "the wallet saw the funding confirmed")
        rig.fake.hide.add(rec.funding_txid)
        self.restart(rig)
        self.assertIsNone(rig.signer._xbt402.funding_spent(rig.channel(), scan=True),
                          "every server hides the funding: that is not a spend")
        rig.fake.hide.clear()
        self.assertIsNone(rig.signer._xbt402.funding_spent(rig.channel(), scan=True), "unspent")

    def test_a_refund_that_cannot_be_decided_books_nothing_and_says_why(self):
        rig = self.opened()
        rec = rig.channel()
        rig.mine(rec.expiry - rig.node.height)
        rig.fake.hide.add(rec.funding_txid)
        self.restart(rig)
        r = rig.call("xbt402_refund", dest=API)
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "funding_unknown"), r)
        self.assertEqual(rig.channel().state, "open")

    def test_evidence_a_proven_close_is_still_booked_at_expiry(self):
        """The other direction: a real, confirmed spend of the funding closes the channel on the light
        backend as before (the refund is denied, the close is named)."""
        rig = self.opened()
        rec = rig.channel()
        close = Tx(version=2, inputs=[TxIn(bytes.fromhex(rec.funding_txid)[::-1], rec.funding_vout)],
                   outputs=[TxOut(rec.funding_sats - 600, bytes.fromhex(spk()))], locktime=0)
        rig.node.call("sendrawtransaction", close.hex())
        rig.mine(rec.expiry - rig.node.height)
        self.restart(rig)
        r = rig.call("xbt402_refund", dest=API)
        self.assertEqual((r["rule"], r.get("closed_txid")), ("channel_closed", close.txid()), r)
        self.assertEqual(rig.channel().state, "closed")


if __name__ == "__main__":
    unittest.main()
