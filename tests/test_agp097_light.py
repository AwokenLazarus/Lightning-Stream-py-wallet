"""AGP-097, fix wave 5, the light client in B2: the rules the fixes keep, at the neighbours of the
paths the third audit named (its own tests are in `test_agp093_light.py`).

Ports: the listeners made here use 27520-27539 (the fake servers of `_electrum_sim` pick their own).
"""

from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from unittest import mock

from agentwallet.electrum import ElectrumConnection, ElectrumError, Late, ServerError, Unknown, says_not_there

from agentwallet.b1path import ensure_b1

ensure_b1()
from xbt402.tx import Tx, TxIn, TxOut  # noqa: E402

import test_agp093_light as audit  # noqa: E402
from test_agp093_light import HoldProxy, Rig, reasons  # noqa: E402

audit_ports = audit.PORTS
PORTS = iter(range(27520, 27540))


class Proxy(HoldProxy):
    """The audit's proxy, on this file's ports."""

    def __init__(self, upstream_port: int, needle: bytes, hold_s: float):
        audit.PORTS = PORTS
        try:
            super().__init__(upstream_port, needle, hold_s)
        finally:
            audit.PORTS = audit_ports


def versions(server) -> int:
    """Connections a fake server has seen (each begins with server.version)."""
    return server.calls.count("server.version")


class Scan(Rig):
    """The rule: what a scan asks a server for does not grow with the number of coins beyond what
    each coin needs once."""

    def coins(self, n: int = 20) -> list[str]:
        return [self.sim.credit("", 0, 5_000, self.spk) for _ in range(n)]

    def scan(self, b):
        return b.call("scantxoutset", "start", [f"raw({self.spk})"])

    def test_a_scan_asks_for_the_scripts_history_once(self):
        coins = self.coins()
        b = self.light(self.a.url, self.honest.url)
        for n in (1, 2):
            got = self.scan(b)
            self.assertEqual((len(got["unspents"]), got["complete"]), (20, True))
            for s in (self.a, self.honest):
                self.assertEqual(s.calls.count("blockchain.scripthash.get_history"), n, f"after scan {n}")
        # a spent coin is still left out: the one history serves every coin's search
        spend = Tx(version=2, inputs=[TxIn(bytes.fromhex(coins[0])[::-1], 0)],
                   outputs=[TxOut(4_000, bytes.fromhex("0014" + "11" * 20))], locktime=0)
        self.sim.call("sendrawtransaction", spend.hex())
        self.sim.mine(1)
        left = {u["txid"] for u in self.scan(b)["unspents"]}
        self.assertEqual((len(left), coins[0] in left), (19, False))

    def test_a_cold_scan_of_many_coins_succeeds_beside_a_server_slow_to_prove(self):
        """A server that takes 0.3 timeouts for a proof request, lies about nothing, and is the
        first to claim every coin. One request a coin was 20 round trips to it, six timeouts
        against a deadline of four; one write a server is one."""
        self.coins()
        slow = Proxy(self.a.port, b"blockchain.transaction.get_merkle", 0.3)
        self.addCleanup(slow.close)
        b = self.light(slow.url, self.honest.url, timeout=1)              # call deadline: 4 s
        b.call("getblockcount")
        t0 = time.monotonic()
        try:
            got = len(self.scan(b)["unspents"])
        except ElectrumError as e:
            got = e
        print(f"\nAGP-097 measure (B2): cold scantxoutset of 20 coins, the first server 0.3 s per proof request, "
              f"timeout 1 s: {got!r} after {time.monotonic() - t0:.2f} s")
        self.assertEqual(got, 20)
        self.assertEqual(b.flags, [])

    def test_a_proof_asked_ahead_that_does_not_hold_is_still_judged_and_flagged(self):
        """`_prove_ahead` judges nothing: a server that forges its proofs is flagged by the request
        that follows, and the honest server's proofs decide."""
        self.coins(3)
        self.a.forge_merkle = True
        b = self.light(self.a.url, self.honest.url)
        self.assertEqual(len(self.scan(b)["unspents"]), 3)
        only = self.light(self.a.url)
        self.assertEqual(self.scan(only)["unspents"], [])
        self.assertTrue(any("get_merkle" in r for r in reasons(only, self.a.url)), only.flags)


class Deadline(Rig):
    """The rule: a server is hung up on only for a request that went a whole timeout unanswered."""

    def test_a_request_the_calls_deadline_cuts_short_does_not_hang_up_or_flag(self):
        slow = Proxy(self.a.port, b"blockchain.scripthash.get_history", 0.0)
        self.addCleanup(slow.close)
        first = self.sim.credit("", 0, 70_000, self.spk)
        b = self.light(slow.url, self.honest.url, timeout=3, call_deadline=0.4)
        self.assertEqual(b.call("gettxout", first, 0, True)["confirmations"], 1)
        before = (versions(self.a), versions(self.honest))
        # the history now takes longer than the whole call may: unknown, not "not there"
        slow.hold_s = 0.9
        fresh = self.sim.credit("", 0, 60_000, self.spk)
        with self.assertRaises(Unknown):
            b.call("gettxout", fresh, 0, True)
        self.assertEqual((versions(self.a), versions(self.honest), b.flags), (*before, []), "a server was hung up on or flagged")
        self.assertTrue(all(c.connected for c in b.conns))
        # its late answers arrive on the connection it kept and are dropped; the next call is answered there
        slow.hold_s = 0.0
        time.sleep(1.0)
        self.assertEqual([len(c._pending) for c in b.conns], [0, 0], "a request given up at the deadline is still pending")
        self.assertEqual(b.call("gettxout", fresh, 0, True)["confirmations"], 1)
        self.assertEqual((versions(self.a), versions(self.honest), b.flags), (*before, []))

    def test_a_request_that_goes_a_whole_timeout_unanswered_still_hangs_up(self):
        slow = Proxy(self.a.port, b"blockchain.scripthash.get_history", 0.0)
        self.addCleanup(slow.close)
        first = self.sim.credit("", 0, 70_000, self.spk)
        b = self.light(slow.url, self.honest.url, timeout=0.3)
        self.assertEqual(b.call("gettxout", first, 0, True)["confirmations"], 1)
        before = versions(self.a)
        slow.hold_s = 5.0
        fresh = self.sim.credit("", 0, 60_000, self.spk)
        # the honest server's proof still answers (a proven coin needs no word from the silent one)
        self.assertEqual(b.call("gettxout", fresh, 0, True)["confirmations"], 1)
        self.assertTrue(any("timed out" in r for r in reasons(b, slow.url)), b.flags)
        slow.hold_s = 0.0
        self.assertEqual(b.call("gettxout", fresh, 0, True)["confirmations"], 1)
        self.assertGreater(versions(self.a), before, "it was connected to again")

    def test_a_request_with_no_time_left_is_not_sent(self):
        c = ElectrumConnection(self.honest.url, timeout=2)
        self.addCleanup(c.close)
        c.connect()
        sent = len(self.honest.calls)
        with self.assertRaises(Late):
            c.request_by(time.monotonic() - 0.01, "blockchain.estimatefee", 1)
        got = c.batch_by(time.monotonic() - 0.01, [("blockchain.estimatefee", (1,)), ("blockchain.estimatefee", (2,))])
        self.assertTrue(all(isinstance(g, Late) for g in got) and len(got) == 2)
        self.assertEqual((len(self.honest.calls), c.connected, len(c._pending)), (sent, True, 0))

    def test_every_entry_that_makes_requests_runs_under_one_budget(self):
        """`proven_spend` asked without the script fetches the transaction first: one deadline and
        one forced sync for both steps. And a budget entered inside another is that budget."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.invented_spends(self.a, funding, 20, self.sim.height + 1000)
        b = self.light(self.a.url, self.honest.url)
        b.call("getblockcount")
        before = self.honest.calls.count("blockchain.headers.subscribe")
        self.assertIsNone(b.proven_spend(funding, 0))
        self.assertLessEqual(self.honest.calls.count("blockchain.headers.subscribe") - before, 2)
        with b._budget() as outer:
            with b._budget() as inner:
                self.assertIs(inner, outer)
            self.assertIs(b._call(), outer)
        self.assertIsNone(getattr(b._tl, "call", None))


class RawServer:
    """A server that answers `server.version` and then does what `after(conn, file)` says."""

    def __init__(self, after):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.port = next(PORTS)
        self.listener.bind(("127.0.0.1", self.port))
        self.listener.listen(4)
        self.url = f"tcp://127.0.0.1:{self.port}"
        self.held: list = []

        def serve():
            while True:
                try:
                    c, _ = self.listener.accept()
                except OSError:
                    return
                self.held.append(c)
                f = c.makefile("rb")
                req = json.loads(f.readline())
                c.sendall((json.dumps({"id": req["id"], "result": ["fake", "1.8"]}) + "\n").encode())
                threading.Thread(target=after, args=(c, f), daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()

    def close(self):
        self.listener.close()
        for c in self.held:
            c.close()


class Write(unittest.TestCase):
    """The rule: a request is written by one deadline, however slowly the server reads, or not at
    all."""

    def write_to(self, after, **patch) -> float:
        srv = RawServer(after)
        self.addCleanup(srv.close)
        c = ElectrumConnection(srv.url, timeout=0.5)
        self.addCleanup(c.close)
        c.connect()
        big = "00" * 4_000_000              # 8 MB as a request line: above the loopback buffers of both ends
        t0 = time.monotonic()
        with self.assertRaises(ElectrumError):
            if patch:
                with mock.patch.object(socket.socket, "setsockopt", side_effect=OSError("no SO_SNDTIMEO here")):
                    c.request("blockchain.transaction.broadcast", big)
            else:
                c.request("blockchain.transaction.broadcast", big)
        took = time.monotonic() - t0
        self.assertFalse(c.connected, "a line half written leaves the connection unusable: it is closed")
        return took

    def test_a_server_that_stops_reading_holds_a_write_for_one_timeout(self):
        took = self.write_to(lambda c, f: None)
        print(f"\nAGP-097 measure (B2): an 8 MB request to a server that stops reading, timeout 0.5 s: {took:.2f} s")
        self.assertLess(took, 1.5)

    def test_a_server_that_reads_a_little_at_a_time_holds_a_write_for_one_timeout(self):
        def trickle(c, f):
            try:
                while c.recv(256 << 10):
                    time.sleep(0.05)
            except OSError:
                pass
        took = self.write_to(trickle)
        print(f"\nAGP-097 measure (B2): an 8 MB request to a server that reads 256 kB every 50 ms, timeout 0.5 s: {took:.2f} s")
        self.assertLess(took, 1.5)

    def test_where_the_send_timeout_cannot_be_set_a_timer_ends_the_write(self):
        took = self.write_to(lambda c, f: None, no_sndtimeo=True)
        self.assertLess(took, 1.5)


class Words(unittest.TestCase):
    """"Not there" is a server's own words about the transaction; an error about the method is not."""

    def test_method_not_found_by_its_code_whatever_the_words(self):
        answers = iter([{"code": -32601, "message": "not found"}, {"code": -32601, "message": "missing"},
                        {"code": -32601, "message": "Method not found"},
                        {"code": 2, "message": "No such mempool or blockchain transaction"}])

        def after(c, f):
            for line in f:
                req = json.loads(line)
                c.sendall((json.dumps({"id": req["id"], "error": next(answers)}) + "\n").encode())
        srv = RawServer(after)
        self.addCleanup(srv.close)
        c = ElectrumConnection(srv.url, timeout=2)
        self.addCleanup(c.close)
        got = []
        for _ in range(4):
            with self.assertRaises(ServerError) as e:
                c.request("blockchain.transaction.get", "00" * 32)
            got.append((str(e.exception), says_not_there(e.exception)))
        self.assertEqual([g[1] for g in got], [False, False, False, True], got)
        self.assertTrue(all("method" in g[0].lower() for g in got[:3]), got)
        self.assertEqual(got[3][0], "No such mempool or blockchain transaction")

    def test_the_words_that_do_and_do_not_say_not_there(self):
        for words, there in [("No such mempool or blockchain transaction", True), ("tx not found in block", True),
                             ("missing transaction", True), ("Method not found", False),
                             ("unknown method blockchain.transaction.get: not found", False),
                             ("server busy", False), ("method missing", False)]:
            self.assertEqual(says_not_there(ServerError(words)), there, words)
        self.assertFalse(says_not_there(ElectrumError("not found")), "our own error, not the server's words")
        self.assertFalse(says_not_there(Late("no such")))


if __name__ == "__main__":
    unittest.main()
