"""AGP-106 (fix wave 6, light client): the neighbours of the fourth audit's holes in B2's light
client, each named as the rule that holds. The audit's own tests are `test_agp102_light.py`.

  * Every number a server sends is a finite float or an integer of at most 64 bits before anything
    reads it (`read_line`), and a height or a position is an integer in its range (`whole`).
  * A header sync is not paid for out of a call's time, and a call syncs once before its budget
    and at most once inside it.
  * One channel's error does not end the watcher's tick for what comes after it.
  * Over TLS a write ends at its deadline by a timer, which hangs up on nothing once the write is
    done.
  * A connection keeps a slot for at most MAX_GIVEN_UP requests nobody waits for; the answer to a
    forgotten one is dropped unread.
  * In a scan only "no such transaction", in the server's words, withdraws a coin its server listed.

Ports: the listeners made here use 27900-27919 (the fake servers of `_electrum_sim` pick their own).
"""

from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from unittest import mock

from agentwallet import electrum
from agentwallet.electrum import MAX_GIVEN_UP, ElectrumConnection, ElectrumError, Late, read_line, whole

import test_agp102_light as audit102  # noqa: E402
from test_agp093_light import Knobs, Rig, reasons  # noqa: E402
from test_agp102_light import Staller, TlsSilent  # noqa: E402

PORTS = iter(range(27900, 27920))


class Numbers(Rig):
    def test_a_line_with_a_number_no_float_or_64_bit_integer_holds_is_refused_where_it_is_read(self):
        for bad in ("1e999", "-1e999", "Infinity", "-Infinity", "NaN", "1" + "0" * 30, "-9223372036854775809",
                    "18446744073709551616"):
            with self.subTest(bad), self.assertRaises(electrum._Dropped):
                read_line(b'{"id": 1, "result": [{"height": %s}]}' % bad.encode())
        ok = read_line(b'{"id": 1, "result": [0.00012, -1, 18446744073709551615, -9223372036854775808, 1e3]}')
        self.assertEqual(ok["result"], [0.00012, -1, (1 << 64) - 1, -(1 << 63), 1000.0])
        with self.assertRaises(ValueError):
            read_line(b"not json")

    def test_a_field_that_must_be_an_integer_takes_nothing_else(self):
        self.assertEqual([whole(0), whole(7), whole(0xFFFF_FFFF), whole(-1, lo=-1)], [0, 7, 0xFFFF_FFFF, -1])
        for bad in (1.0, 1.5, "7", True, None, [1], -1, 1 << 32, float("inf"), float("nan")):
            with self.subTest(repr(bad)), self.assertRaises(ValueError):
                whole(bad)

    def test_a_server_that_sends_such_a_number_is_dropped_and_flagged_and_the_honest_one_answers(self):
        """Every place a server's number is read, through the wire: a history height, a listunspent
        height and position, a proof position, a tip height and a fee. None leaves the backend as
        anything but its own error type, and what the honest server proves is answered."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        inf = float("inf")          # the fake server's JSON writer sends it as `Infinity`

        class Odd(Knobs):
            field = ""

            def answer(self, client, method, p):
                got = super().answer(client, method, p)
                name = method.rsplit(".", 1)[-1]
                if name == "get_history" and self.field == "history":
                    got = [dict(e, height=inf) for e in got]
                elif name == "listunspent" and self.field in ("unspent_height", "unspent_pos"):
                    key = "height" if self.field == "unspent_height" else "tx_pos"
                    got = [dict(u, **{key: inf}) for u in got]
                elif name == "get_merkle" and self.field == "pos":
                    got = dict(got, pos=inf)
                elif name == "estimatefee" and self.field == "fee":
                    got = inf
                return got

        odd = Odd(self.sim)
        self.addCleanup(odd.close)
        for field in ("history", "unspent_height", "unspent_pos", "pos", "fee"):
            with self.subTest(field):
                odd.field = field
                b = self.light(odd.url, self.honest.url)
                self.assertEqual(b.call("gettxout", funding, 0, True)["confirmations"], 1)
                self.assertEqual(len(b.call("scantxoutset", "start", [f"raw({self.spk})"])["unspents"]), 1)
                self.assertIsNone(b.proven_spend(funding, 0, self.spk))
                fee = b.call("estimatesmartfee", 2)
                self.assertNotEqual(fee.get("feerate"), inf)
                self.assertEqual(reasons(b, self.honest.url), [])
                if field != "fee" or "feerate" in fee:
                    self.assertTrue(any("a number" in r for r in reasons(b, odd.url)), reasons(b, odd.url))

    def test_a_height_that_is_a_float_or_a_string_is_a_malformed_entry(self):
        """Not an infinity: `1.5` and `"201"` reach the entry, where `int()` took them for 1 and
        201. The entry is malformed (flagged, skipped), the connection stays, and the honest
        server's claim is the one that is proven."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        sh = electrum.scripthash(bytes.fromhex(self.spk))
        for odd in (1.5, "201", True):
            with self.subTest(repr(odd)):
                self.a.extra_history[sh] = [{"tx_hash": funding, "height": odd}]
                b = self.light(self.a.url, self.honest.url)
                self.assertEqual(b.call("gettxout", funding, 0, True)["confirmations"], 1)
                self.assertIn("get_history: malformed entry", reasons(b, self.a.url))
                self.assertTrue(b.conns[0].connected)


class SyncAndTheCallsTime(Rig):
    def test_a_call_runs_one_sync_before_its_budget_and_none_inside_it_beside_a_server_that_asks_for_one_each_time(self):
        """The Staller notifies a new tip with every header it serves, so a sync is due whenever
        one is asked for. Each of the four calls that sync first runs exactly one round, and its
        budget is not touched by it: the lookup ends inside the sync deadline plus the call's."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.sim.mine(2)
        hostile = Staller(self.sim, hold=0.28, notify=True)
        self.addCleanup(hostile.close)
        b = self.light(self.honest.url, hostile.url, timeout=0.4)
        b.call("getblockcount")
        for method, params in (("gettxout", (funding, 0, True)), ("getrawtransaction", (funding,)),
                               ("gettxspendingprevout", ([{"txid": funding, "vout": 0}],)),
                               ("scantxoutset", ("start", [f"raw({self.spk})"]))):
            with self.subTest(method):
                rounds, t0 = b._round, time.monotonic()
                b.call(method, *params)
                took = time.monotonic() - t0
                self.assertEqual(b._round - rounds, 1, "sync rounds run for one call")
                self.assertLess(took, b.sync_deadline + b.call_deadline)
        self.assertEqual(reasons(b, self.honest.url), [])
        self.assertTrue(any(r.startswith("headers:") for r in reasons(b, hostile.url)), reasons(b, hostile.url))

    def test_the_time_of_a_sync_run_under_a_budget_is_given_back_to_it_and_to_no_other(self):
        b = self.light(self.honest.url, timeout=1)
        b.call("getblockcount")

        def slow_round():
            time.sleep(0.3)
            return 7

        with mock.patch.object(b, "_sync_now", slow_round):
            with b._budget() as call:
                before = call.deadline
                self.assertEqual(b._sync_round(force=True), 7)
                self.assertAlmostEqual(call.deadline - before, 0.3, delta=0.1)
            other = electrum._Call(time.monotonic() + 5)
            before = other.deadline
            b._sync_round(force=True, call=other)
            self.assertAlmostEqual(other.deadline - before, 0.3, delta=0.1)
            b._sync_round(force=True)                   # no budget on this thread: nothing to move
            self.assertEqual(getattr(b._tl, "call", None), None)

    def test_a_call_forces_one_sync_however_many_claims_are_above_the_tip(self):
        """What bounds the move: one forced sync per call (`_Call.synced`)."""
        coins = [self.sim.credit("", 0, 5_000, self.spk) for _ in range(4)]
        for t in coins:
            self.a.claim_height[t] = self.sim.height + 5
        b = self.light(self.a.url, self.honest.url)
        b.call("getblockcount")
        rounds = b._round
        with b._budget():
            for t in coins:
                b._locate(t)
        self.assertEqual(b._round - rounds, 1)


class TheTick(unittest.TestCase):
    def test_a_channel_whose_refund_raises_is_reported_and_the_tick_goes_on(self):
        rig, rec = audit102.TheWatcher.opened(self)
        swept = []
        real_sweep = rig.signer.hot.sweep_retired
        with mock.patch.object(rig.signer, "_refund_locked", side_effect=OverflowError("cannot convert float infinity")), \
                mock.patch.object(rig.signer.hot, "sweep_retired", lambda: swept.append(1) or real_sweep()):
            acts = rig.tick()
        mine = [a for a in acts if a.get("dest") == rec.dest]
        self.assertEqual([(a["verdict"], a["rule"]) for a in mine], [("deny", "watcher_error")], acts)
        self.assertIn("refund: OverflowError", mine[0]["reason"])
        self.assertEqual(swept, [1], "the steps after the refund loop ran in the same tick")
        self.assertEqual(rig.channel().state, "open")
        rig.tick()                                      # and the same step runs again at the next tick
        self.assertEqual(rig.channel().state, "refunded")


class TheWire(Rig):
    def test_a_tls_write_that_ended_in_time_is_not_hung_up_on_later_and_one_that_did_not_reconnects(self):
        holes = audit102.Holes
        cert, key = holes.tls_fixture(self)
        srv = TlsSilent(cert, key)
        self.addCleanup(srv.close)
        c = ElectrumConnection(srv.url, timeout=0.4)
        self.addCleanup(c.close)
        timers = []
        real = threading.Timer

        def counting(*a, **kw):
            timers.append(real(*a, **kw))
            return timers[-1]

        with mock.patch.object(electrum.threading, "Timer", counting):
            c.connect()                                 # `server.version` is written over TLS
            self.assertEqual(len(timers), 1, "over TLS the timer is the write's deadline")
            sock = c._sock
            time.sleep(0.6)
            self.assertIs(c._sock, sock, "the timer of a write that ended hung up on nothing")
            t0 = time.monotonic()
            with self.assertRaises(ElectrumError):
                c.request("blockchain.transaction.broadcast", "00" * 100_000)
            self.assertLess(time.monotonic() - t0, 1.2)
            self.assertFalse(c.connected)
            c.connect()                                 # the next request reconnects
            self.assertTrue(c.connected)

    def test_a_plain_write_still_uses_the_send_timeout_and_no_timer(self):
        srv = TlsSilent(None, None)
        self.addCleanup(srv.close)
        c = ElectrumConnection(srv.url, timeout=0.4)
        self.addCleanup(c.close)
        with mock.patch.object(electrum.threading, "Timer", side_effect=AssertionError("no timer on a plain socket")):
            c.connect()

    def test_the_answer_to_a_forgotten_request_is_dropped_unread_and_the_connection_stays(self):
        """At the bound of MAX_GIVEN_UP the oldest given-up request is forgotten. Its late answer
        is matched by nobody and, being small, is within what the others allow."""
        held, sent = [], threading.Event()

        def serve(c, f):
            for line in f:
                req = json.loads(line)
                if req["method"] == "server.ping":
                    if req["params"] == ["late"]:       # now answer the oldest history request, late
                        c.sendall((json.dumps({"id": held[0], "result": []}) + "\n").encode())
                        sent.set()
                    c.sendall((json.dumps({"id": req["id"], "result": None}) + "\n").encode())
                else:
                    held.append(req["id"])

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", next(PORTS)))
        listener.listen(2)
        self.addCleanup(listener.close)

        def accept():
            try:
                c, _ = listener.accept()
            except OSError:
                return
            f = c.makefile("rb")
            req = json.loads(f.readline())
            c.sendall((json.dumps({"id": req["id"], "result": ["never", "1.8"]}) + "\n").encode())
            serve(c, f)

        threading.Thread(target=accept, daemon=True).start()
        c = ElectrumConnection(f"tcp://127.0.0.1:{listener.getsockname()[1]}", timeout=2)
        self.addCleanup(c.close)
        c.connect()
        for n in range(MAX_GIVEN_UP + 4):
            got = c.batch_by(time.monotonic() + 0.005, [("blockchain.scripthash.get_history", ("00" * 32,))])
            self.assertIsInstance(got[0], Late)
            c.request("server.ping")
            self.assertEqual(len(c._pending), min(n + 1, MAX_GIVEN_UP))
        self.assertNotIn(held[0], c._pending, "the oldest was forgotten")
        self.assertIn(held[-1], c._pending, "the newest are kept")
        self.assertIsNone(c.request("server.ping", "late"))
        self.assertTrue(sent.is_set() and c.connected)
        self.assertEqual(len(c._pending), MAX_GIVEN_UP)

    def test_a_request_of_the_next_connection_is_not_failed_by_the_close_of_the_last(self):
        """`close` fails the requests that were waiting on the socket it closes. It took that list
        after it let go of the lock `connect` sets the next socket under, so a reconnect in
        between had its `server.version` failed with the old connection's reason."""
        c = ElectrumConnection(self.honest.url, timeout=2)
        self.addCleanup(c.close)
        c.connect()
        newer = electrum._Pending(electrum.AnswerCap())
        real_shutdown = socket.socket.shutdown

        def reconnect_meanwhile(sock, how):
            c._pending[10_000] = newer                  # a request made after `_sock` was cleared
            return real_shutdown(sock, how)

        with mock.patch.object(socket.socket, "shutdown", reconnect_meanwhile):
            c.close("dropped: the old connection's reason")
        self.assertFalse(newer.done.is_set(), newer.msg)


class TheScan(Rig):
    def test_control_a_lister_that_says_no_such_transaction_has_answered_and_the_scan_goes_on(self):
        coin = self.sim.credit("", 0, 9_000, self.spk)
        self.a.hide.add(coin)

        class Withdraws(Knobs):
            def answer(self, client, method, p):
                if method == "blockchain.transaction.get":
                    raise ValueError("No such mempool or blockchain transaction")
                return super().answer(client, method, p)

        lister = Withdraws(self.sim)
        self.addCleanup(lister.close)
        b = self.light(lister.url, self.a.url)
        got = b.call("scantxoutset", "start", [f"raw({self.spk})"])
        self.assertEqual((len(got["unspents"]), got["complete"]), (0, True))
        self.assertTrue(any("lists a transaction it does not supply" in r for r in reasons(b, lister.url)))

    def test_a_busy_server_in_the_search_for_a_spend_is_flagged_and_does_not_fail_the_lookup(self):
        """`_supply` also serves the search for a spend, which does not wait for every server (by
        design, AGP-092). There a busy server is flagged and its part ends; the lookup answers."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        b = self.light(self.honest.url, self.a.url)
        self.assertEqual(b.call("gettxout", funding, 0, True)["confirmations"], 1)
        spend = self.sim.credit("", 0, 1_000, self.spk)      # another transaction in the script's history

        class Busy(Knobs):
            def answer(self, client, method, p):
                if method == "blockchain.transaction.get" and p and p[0] == spend:
                    raise ValueError("server busy, try again later")
                return super().answer(client, method, p)

        busy = Busy(self.sim)
        self.addCleanup(busy.close)
        b = self.light(busy.url, self.honest.url)
        self.assertEqual(b.call("gettxout", funding, 0, True)["confirmations"], 2)


if __name__ == "__main__":
    unittest.main()
