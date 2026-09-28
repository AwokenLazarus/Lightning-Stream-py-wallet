"""AGP-022: a cooperative close's change is counted even when the payer's node gets the close late.

Over real P2P (lab-host, AGP-018) B1 broadcasts the close on the provider's node and the payer's node
sees it ~2 s after close_channel has looked for it; without txindex that one look found nothing, and
nothing looked again. Now the close is recorded with close_change "pending" and the watcher (and any
balance read) retries until the change is counted, proven spent or proven absent, never twice.

Also the single-host B.G5 race: a reader could see the channel "closed" before its change was counted.
The change is now learned first and the channel marked closed with the answer.
"""

from __future__ import annotations

import unittest
from unittest import mock

from agentwallet.hot import HotWallet

from test_mainnet_readiness import API, Rig

from xbt402.tx import Tx


class LaggedNode:
    """The provider's own node: what it broadcasts reaches the payer's node only on deliver()."""

    def __init__(self, chain):
        self.chain = chain
        self.held: list[str] = []

    def __getattr__(self, m):
        if m == "sendrawtransaction":
            return self._hold
        return lambda *a: self.chain.call(m, *a)

    def _hold(self, raw):
        self.held.append(raw)
        return Tx.parse(bytes.fromhex(raw)).txid()

    def getrawtransaction(self, txid, *a):   # the provider's node has what it sent
        for raw in self.held:
            if Tx.parse(bytes.fromhex(raw)).txid() == txid:
                return raw
        return self.chain.call("getrawtransaction", txid, *a)

    def deliver(self):
        for raw in self.held:
            self.chain.call("sendrawtransaction", raw)
        self.held.clear()


def p2p_rig(pays=2):
    """A channel with `pays` paid calls; the provider's node relays late. Returns (rig, lagged node)."""
    rig = Rig(regtest_mine=False)        # as on mainnet (and the rehearsal): B2 never mines
    rig.fund_hot()
    rig.pay()
    rig.node.mine(1)                     # the funding gets its minConf; the watcher finishes the open
    rig.tick()
    for _ in range(pays - 1):
        rig.pay()
    lag = LaggedNode(rig.node)
    rig.provider.rpc = lag
    return rig, lag


def close(rig):
    with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=rig.http):
        return rig.signer.handle({"method": "close_channel", "params": {"counterparty": API}})


def change_of(rig):
    rec = rig.channel()
    return rec.funding_sats - rec.close_fee - rec.used_sats


class LateClose(unittest.TestCase):
    def test_close_not_yet_on_the_payers_node_is_counted_on_a_later_tick(self):
        rig, lag = p2p_rig()
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400)
        r = close(rig)
        self.assertEqual((r["verdict"], r["close_change"]), ("allow", "pending"), r)
        rec = rig.channel()
        self.assertEqual((rec.state, rec.close_change, rec.closed_txid), ("closed", "pending", r["txid"]))
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400, "nothing to count yet")
        self.assertEqual(rig.tick(), [], "still not on our node: the watcher keeps it pending")
        lag.deliver()                                    # P2P: ~2 s later the close reaches our mempool
        acts = rig.tick()
        self.assertEqual([(a["close_change"], a["closed_txid"]) for a in acts], [("counted", r["txid"])])
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400 + change_of(rig))
        self.assertEqual(rig.channel().close_change, "counted")
        self.assertEqual(rig.tick(), [], "counted: the watcher stops")

    def test_a_balance_read_counts_a_pending_close_first(self):
        rig, lag = p2p_rig()
        r = close(rig)
        st = rig.signer.handle({"method": "hot_address", "params": {}})
        self.assertEqual((st["hot_sats"], st["hot_pending_close_change"]), (1_400, [r["txid"]]))
        lag.deliver()
        rig.node.mine(1)                                 # (the rehearsal's G5 block)
        st = rig.signer.handle({"method": "hot_address", "params": {}})
        self.assertEqual((st["hot_sats"], st["hot_pending_close_change"]), (1_400 + change_of(rig), []))
        bal = rig.signer.handle({"method": "balance", "params": {}})
        self.assertEqual(bal["hot"]["hot_sats"], 1_400 + change_of(rig))
        self.assertEqual([c["close_change"] for c in bal["channels"]], ["counted"])

    def test_close_confirmed_before_it_is_ever_in_our_mempool(self):
        rig, lag = p2p_rig()
        r = close(rig)
        lag.deliver()
        rig.node.mine(2)                                 # straight into a block: our mempool never had it
        with self.assertRaises(Exception):
            rig.node.call("getrawtransaction", r["txid"], True)   # no txindex
        acts = rig.tick()
        self.assertEqual([a["close_change"] for a in acts], ["counted"])
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400 + change_of(rig))

    def test_a_different_close_confirmed_is_found_by_the_funding_it_spends(self):
        """The reply's txid never shows up; the close that did spend the funding is found in a block."""
        rig, lag = p2p_rig()
        serve = rig.provider.close
        rig.provider.close = lambda req: {**serve(req), "txid": "ab" * 32}
        r = close(rig)
        self.assertEqual((r["txid"], r["close_change"]), ("ab" * 32, "pending"))
        lag.deliver()
        rig.node.mine(1)
        real = Tx.parse(bytes.fromhex(rig.node.sent[-1])).txid()
        acts = rig.tick()
        self.assertEqual([(a["close_change"], a["closed_txid"]) for a in acts], [("counted", real)])
        self.assertEqual(rig.channel().closed_txid, real)
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400 + change_of(rig))

    def test_change_already_spent_is_final_and_never_counted(self):
        rig, lag = p2p_rig()
        r = close(rig)
        lag.deliver()
        rig.node.mine(1)
        hot_spk = rig.signer.hot.spk.hex()
        [n] = [n for (t, n), u in rig.node.utxos.items() if t == r["txid"] and u["spk"] == hot_spk]
        rig.node.utxos.pop((r["txid"], n))               # spent elsewhere before we ever looked
        self.assertEqual([a["close_change"] for a in rig.tick()], ["spent"])
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400)
        self.assertEqual(rig.tick(), [])

    def test_block_scan_resumes_where_it_stopped(self):
        rig, lag = p2p_rig()
        close(rig)
        rig.node.mine(5)                                  # empty blocks while the close is still held
        rig.tick()
        rec = rig.channel()
        self.assertEqual((rec.close_change, rec.close_scan_from), ("pending", rig.node.height + 1))
        lag.deliver()
        rig.node.mine(1)
        rig.node.calls.clear()
        rig.tick()
        self.assertLessEqual(rig.node.calls.count("getblock"), 1, "old blocks are not read again")
        self.assertEqual(rig.channel().close_change, "counted")


class NoDoubleCount(unittest.TestCase):
    def test_counted_once_across_ticks_reads_restart_and_reconcile(self):
        rig, lag = p2p_rig()
        close(rig)
        lag.deliver()
        rig.node.mine(1)
        want = 1_400 + change_of(rig)
        for _ in range(3):
            rig.tick()
            rig.signer.handle({"method": "hot_address", "params": {}})
            rig.signer.handle({"method": "xbt402_refund", "params": {"counterparty": API}})
        self.assertEqual(rig.signer.hot.balance_sats(), want)
        s = rig.restart()                                 # reconcile's scantxoutset sees the same coin
        self.assertEqual(s.hot.balance_sats(), want)
        rig.tick()
        self.assertEqual(s.hot.balance_sats(), want)
        self.assertEqual(len(s.hot._utxos), 2)

    def test_reconcile_found_it_first_then_the_retry_adds_nothing(self):
        rig, lag = p2p_rig()
        close(rig)
        lag.deliver()
        rig.node.mine(1)
        s = rig.restart()                                 # at start: the change is found by scantxoutset
        want = 1_400 + change_of(rig)
        self.assertEqual((s.hot.balance_sats(), rig.channel().close_change), (want, "pending"))
        self.assertEqual([a["close_change"] for a in rig.tick()], ["counted"])
        self.assertEqual(s.hot.balance_sats(), want)

    def test_swept_after_it_was_counted_is_not_counted_again(self):
        rig, lag = p2p_rig()
        close(rig)
        lag.deliver()
        rig.node.mine(1)
        rig.tick()
        rig.signer.hot._utxos.clear()                     # (a sweep took both coins)
        rig.tick()
        rig.signer.handle({"method": "xbt402_refund", "params": {"counterparty": API}})
        self.assertEqual(rig.signer.hot.balance_sats(), 0)

    def test_learn_close_change_is_idempotent(self):
        rig, lag = p2p_rig()
        r = close(rig)
        lag.deliver()
        rec = rig.channel()
        hot: HotWallet = rig.signer.hot
        a = hot.learn_close_change(r["txid"], (rec.funding_txid, rec.funding_vout), rig.node.height)
        b = hot.learn_close_change(r["txid"], (rec.funding_txid, rec.funding_vout), rig.node.height)
        self.assertEqual((a["status"], a["added"], b["status"], b["added"]), ("counted", 1, "counted", 0))


class ClosedMeansCounted(unittest.TestCase):
    """The single-host B.G5 race: the channel became "closed" on disk (and to a `channels` reader)
    before the watcher had counted the change, so a `hot_address` read in between saw 1,400."""

    def watch_mark_closed(self, rig):
        seen = []
        orig = rig.signer.channels.mark_closed

        def mark_closed(key, *a, **kw):
            orig(key, *a, **kw)
            seen.append((rig.signer.hot.balance_sats(), rig.signer.channels.get(key).close_change))
        rig.signer.channels.mark_closed = mark_closed
        return seen

    def test_provider_self_close_found_by_the_watcher(self):
        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        for _ in range(2):
            rig.pay()
        rec = rig.channel()
        rig.node.height = rec.expiry - 144
        closed = rig.provider.close_due()
        rig.node.mine(3)
        rig.node.height = rec.expiry
        seen = self.watch_mark_closed(rig)
        rig.tick()
        change = rec.funding_sats - rec.close_fee - rig.channel().used_sats
        self.assertEqual(seen, [(1_400 + change, "counted")], "closed only once the change is counted")
        self.assertEqual(rig.channel().closed_txid, closed[0])

    def test_cooperative_close_on_one_node(self):
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        rig.pay()
        rig.node.mine(1)
        rig.tick()
        rig.pay()
        seen = self.watch_mark_closed(rig)
        r = close(rig)
        self.assertEqual(seen, [(1_400 + change_of(rig), "counted")])
        self.assertEqual(r["close_change"], "counted")

    def test_a_reader_waits_for_a_close_in_progress(self):
        """hot_address takes the spend lock while a close change is pending, so it never reports the
        balance of a half-finished close."""
        rig, lag = p2p_rig()
        close(rig)
        lag.deliver()
        got = []
        with rig.signer._spend_lock:                     # the watcher is mid-tick
            import threading
            t = threading.Thread(target=lambda: got.append(rig.signer.handle({"method": "hot_address", "params": {}})))
            t.start()
            t.join(0.3)
            self.assertTrue(t.is_alive(), "the read waits for the lock")
        t.join(5)
        self.assertEqual(got[0]["hot_sats"], 1_400 + change_of(rig))


class CloseHex(unittest.TestCase):
    def test_a_close_hex_from_the_provider_is_handed_to_our_node(self):
        rig, lag = p2p_rig()
        serve = rig.provider.close

        def close_with_hex(req):
            out = serve(req)
            return {**out, "hex": lag.held[-1]}
        rig.provider.close = close_with_hex
        r = close(rig)
        self.assertEqual(r["close_change"], "counted", "our node was given the close at once")
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400 + change_of(rig))
        self.assertTrue(rig.channel().close_hex)

    def test_a_close_hex_for_another_tx_is_ignored(self):
        rig, lag = p2p_rig()
        serve = rig.provider.close
        rig.provider.close = lambda req: {**serve(req), "hex": rig.node.sent[0]}   # the funding, not the close
        r = close(rig)
        self.assertEqual((r["close_change"], rig.channel().close_hex), ("pending", ""))


if __name__ == "__main__":
    unittest.main()
