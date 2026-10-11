"""AGP-093 (third closure audit, area LIGHT): what wave 4's two light-client rules leave open in B2.

Each test is named as the claim that should hold. Those in `Holes` FAIL on B2 `6fd0e24`; those named
`test_control_*` pass and show that the honest path works in the same rig.

  * `proven_spend` (the evidence a refund and `funding_spent` rest on) is called outside
    `ElectrumBackend.call`, so it has no call budget: every step gets a fresh `call_deadline` and
    every claimed height above our tip forces a header sync of its own.
  * A claim above the tip a server last reported is read as a lie (an answer) when our forced sync
    was skipped because another sync was in flight: "not confirmed" is then answered as known.
  * The call deadline is over the whole scan, and the scan asks for the script's history once per
    coin: one server that answers each request well inside the timeout makes a scan of a script
    with many coins fail for good.
  * A request is written with no send timeout: a server that stops reading holds the caller.

Ports: the listeners made here use 27500-27519 (the fake servers of `_electrum_sim` pick their own,
as in every other test of this suite).
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import unittest

from agentwallet import chain as chainbackend
from agentwallet.b1path import ensure_b1
from agentwallet.electrum import ElectrumBackend, ElectrumError, scripthash

ensure_b1()
from xbt402.tx import Tx, TxIn, TxOut  # noqa: E402

from _electrum_sim import CHECKPOINT, FakeElectrum, SimChain  # noqa: E402

PORTS = iter(range(27500, 27520))


class Knobs(FakeElectrum):
    """FakeElectrum that answers chosen methods after a sleep (`slow`)."""

    def __init__(self, sim):
        super().__init__(sim)
        self.slow: dict[str, float] = {}

    def answer(self, client, method, p):
        if method in self.slow:
            time.sleep(self.slow[method])
        return super().answer(client, method, p)


class HoldProxy:
    """A TCP proxy in front of one server that holds every request line containing `needle` for
    `hold_s` and passes every other line at once: a server that is slow to answer one method while
    it answers the rest (a real server works its requests in parallel; the fake works one
    connection's requests in order)."""

    def __init__(self, upstream_port: int, needle: bytes, hold_s: float):
        self.needle, self.hold_s = needle, hold_s
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port = next(PORTS)
        self.listener.bind(("127.0.0.1", self.port))
        self.listener.listen(8)
        self.url = f"tcp://127.0.0.1:{self.port}"
        self.upstream_port = upstream_port
        self.closed = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.closed:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            try:
                up = socket.create_connection(("127.0.0.1", self.upstream_port))
            except OSError:
                client.close()
                continue
            wlock = threading.Lock()

            def down(up=up, client=client):
                try:
                    while (d := up.recv(1 << 16)):
                        client.sendall(d)
                except OSError:
                    pass
                finally:
                    client.close()

            def send(line, up=up, wlock=wlock):
                try:
                    with wlock:
                        up.sendall(line)
                except OSError:
                    pass

            def upward(up=up, client=client, send=send):
                try:
                    for line in client.makefile("rb"):
                        if self.needle in line and self.hold_s:
                            threading.Timer(self.hold_s, send, args=(line,)).start()
                        else:
                            send(line)
                except OSError:
                    pass
                finally:
                    try:
                        up.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

            threading.Thread(target=down, daemon=True).start()
            threading.Thread(target=upward, daemon=True).start()

    def close(self):
        self.closed = True
        self.listener.close()


def spk() -> str:
    return "0014" + os.urandom(20).hex()


def reasons(b, url) -> list[str]:
    return [f["reason"] for f in b.flags if f["server"] == url]


class Rig(unittest.TestCase):
    def setUp(self):
        self.sim = SimChain(height=200)
        self.a, self.honest = Knobs(self.sim), Knobs(self.sim)
        self.addCleanup(self.a.close)
        self.addCleanup(self.honest.close)
        self.spk = spk()

    def light(self, *urls, **kw):
        kw.setdefault("timeout", 3)
        b = ElectrumBackend(list(urls), chain="regtest", checkpoint=(CHECKPOINT, self.sim.bhash(CHECKPOINT)), **kw)
        self.addCleanup(b.close)
        return b

    def invented_spends(self, server, funding: str, n: int, height: int) -> None:
        """`server` lists `n` transactions that spend funding:0, each at `height`, and supplies them."""
        rows = []
        for k in range(n):
            tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(funding)[::-1], 0)],
                    outputs=[TxOut(1_000 + k, bytes.fromhex(spk()))], locktime=0)
            server.extra_raw[tx.txid()] = tx.hex()
            rows.append({"tx_hash": tx.txid(), "height": height})
        server.extra_history[scripthash(bytes.fromhex(self.spk))] = rows


class Holes(Rig):
    def test_proven_spend_forces_one_header_sync_however_many_heights_a_server_claims(self):
        """The refund's evidence (`chain.spend_is_evidence` -> `proven_spend`) must cost what one call
        costs: one forced header sync. Wave 4 gave `call()` that budget; `proven_spend` is not
        called through `call()`, so each claim above our tip syncs again."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.invented_spends(self.a, funding, 20, self.sim.height + 1000)
        b = self.light(self.a.url, self.honest.url)
        b.call("getblockcount")
        before = self.honest.calls.count("blockchain.headers.subscribe")
        self.assertEqual(chainbackend.spend_is_evidence(b, funding, 0, self.spk), (False, ""))
        rounds = self.honest.calls.count("blockchain.headers.subscribe") - before
        print(f"\nAGP-093 measure (B2): proven_spend with 20 claimed heights above the tip: {rounds} header sync rounds")
        self.assertLessEqual(rounds, 2, "one sync before the call and one forced by it")

    def test_proven_spend_ends_at_the_call_deadline(self):
        """Limit 6 of AGP-092: one call costs its header sync, then `call_deadline`, then one forced
        sync. A server that lists spends above its tip and answers each header request just inside
        the timeout must not hold the refund's evidence longer than that."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.invented_spends(self.a, funding, 30, self.sim.height + 1000)
        b = self.light(self.a.url, self.honest.url, timeout=0.5)          # call and sync deadline: 2 s each
        b.call("getblockcount")
        self.a.slow["blockchain.headers.subscribe"] = 0.4
        t0 = time.monotonic()
        try:
            chainbackend.spend_is_evidence(b, funding, 0, self.spk)
        except ElectrumError:
            pass
        took = time.monotonic() - t0
        print(f"\nAGP-093 measure (B2): proven_spend, 30 claims above the tip, 0.4 s per headers.subscribe, "
              f"timeout 0.5 s (call deadline 2 s, sync deadline 2 s): {took:.2f} s")
        self.assertLess(took, b.sync_deadline + b.call_deadline + b.sync_deadline,
                        "a header sync, the call deadline, one forced sync")

    def test_a_claim_above_the_tip_a_server_last_reported_is_not_a_lie_while_our_sync_is_skipped(self):
        """No server lies here. One is slow to answer `headers.subscribe`, so a sync round is in
        flight when a block arrives. A call in that window cannot sync (the gate is held), so it has
        no header for the new block; the servers' true claim at that height must leave the answer
        unknown, not "no such output", and must not flag them."""
        slow = HoldProxy(self.a.port, b"blockchain.headers.subscribe", 0.0)
        self.addCleanup(slow.close)
        b = self.light(slow.url, self.honest.url)
        b.call("getblockcount")
        slow.hold_s = 2.0
        holder = threading.Thread(target=lambda: b.sync(force=True), daemon=True)
        holder.start()
        time.sleep(0.4)                                  # the honest server's part of the round is done
        txid = self.sim.credit("", 0, 70_000, self.spk)  # a block arrives: both servers list it at the new height
        try:
            got = b.call("gettxout", txid, 0, True)
        except ElectrumError as e:
            got = e
        flags = reasons(b, self.honest.url)
        holder.join(10)
        print(f"\nAGP-093 measure (B2): gettxout of an output confirmed while a sync was in flight: {got!r}; "
              f"flags on the honest server: {flags}")
        self.assertIsNotNone(got, "a confirmed, unspent output two honest servers list was answered as not there")
        self.assertFalse(any("above the tip it reports" in r for r in flags), "an honest server was flagged as lying")

    def test_a_scan_of_many_coins_succeeds_when_every_server_answers_inside_a_third_of_the_timeout(self):
        """The call deadline is four timeouts for the whole scan, and the scan asks every server for
        the script's history once per coin. A server that takes 0.3 timeouts per answer, and lies
        about nothing, must not make the hot wallet's coins unlistable."""
        for _ in range(20):
            self.sim.credit("", 0, 5_000, self.spk)
        b = self.light(self.a.url, self.honest.url, timeout=1)            # call deadline: 4 s
        b.call("getblockcount")
        self.a.slow["blockchain.scripthash.get_history"] = 0.3
        t0 = time.monotonic()
        try:
            got = len(b.call("scantxoutset", "start", [f"raw({self.spk})"])["unspents"])
        except ElectrumError as e:
            got = e
        print(f"\nAGP-093 measure (B2): scantxoutset of 20 coins, one server 0.3 s per get_history, timeout 1 s: "
              f"{got!r} after {time.monotonic() - t0:.2f} s; get_history requests to it: "
              f"{self.a.calls.count('blockchain.scripthash.get_history')}")
        self.assertEqual(got, 20)

    def test_method_not_found_is_not_no_such_transaction(self):
        """"Not there" is read from a server's words (NOT_THERE), and "not found" is one of them.
        JSON-RPC's own error for a method a server does not serve is "Method not found". Such a
        server has said nothing about this transaction; with one server hiding it the lookup must
        stay unknown."""
        txid = self.sim.credit("", 0, 70_000, self.spk)
        self.a.hide.add(txid)
        real = self.honest.answer

        def answer(client, method, p):
            if method == "blockchain.transaction.get":
                raise ValueError("Method not found")
            return real(client, method, p)
        self.honest.answer = answer
        b = self.light(self.a.url, self.honest.url)
        try:
            got = b.call("gettxout", txid, 0, True)
        except ElectrumError as e:
            got = e
        print(f"\nAGP-093 measure (B2): one server hides the funding, the other answers transaction.get "
              f"'Method not found': gettxout = {got!r}")
        self.assertIsInstance(got, ElectrumError, "answered as not there")


    def test_a_server_that_stops_reading_does_not_hold_a_broadcast(self):
        """A request is written with `sendall` on a socket with no timeout. A server that completes
        the handshake and then never reads holds a broadcast larger than the socket buffers for as
        long as it likes; the call deadline does not apply to the write."""
        port = next(PORTS)
        lst = socket.socket()
        lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lst.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        lst.bind(("127.0.0.1", port))
        lst.listen(4)
        self.addCleanup(lst.close)
        held = []

        def serve():
            while True:
                try:
                    c, _ = lst.accept()
                except OSError:
                    return
                held.append(c)
                f = c.makefile("rb")
                req = json.loads(f.readline())             # server.version, then nothing is read again
                c.sendall((json.dumps({"id": req["id"], "result": ["fake", "1.8"]}) + "\n").encode())

        threading.Thread(target=serve, daemon=True).start()
        b = self.light(f"tcp://127.0.0.1:{port}", timeout=0.5)            # call deadline: 2 s
        # 2.6 MB raw, 5.2 MB as a request line: above this host's loopback send buffer (3 MB, measured;
        # 2 MB still fits). Over a real link the buffer starts at the kernel's 16 kB (tcp_wmem), so a
        # sweep of a few hundred coins is enough there (from reading: not measured off loopback).
        big = Tx(version=2, inputs=[TxIn(os.urandom(32), 0) for _ in range(64_000)],
                 outputs=[TxOut(1_000, bytes.fromhex(spk()))], locktime=0)
        done = threading.Event()

        def send():
            try:
                b.call("sendrawtransaction", big.hex())
            except Exception:
                pass
            done.set()

        t0 = time.monotonic()
        threading.Thread(target=send, daemon=True).start()
        finished = done.wait(8.0)
        print(f"\nAGP-093 measure (B2): sendrawtransaction of a {len(big.hex()) // 2} byte transaction to a server "
              f"that stops reading, timeout 0.5 s: {'returned after %.2f s' % (time.monotonic() - t0) if finished else 'still blocked after 8 s'}")
        for c in held:
            c.close()
        self.assertTrue(finished, "the write is not held to the timeout or the call deadline")


class Controls(Rig):
    def test_control_gettxout_through_call_forces_one_sync_for_the_same_listing(self):
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.invented_spends(self.a, funding, 20, self.sim.height + 1000)
        b = self.light(self.a.url, self.honest.url)
        b.call("getblockcount")
        before = self.honest.calls.count("blockchain.headers.subscribe")
        self.assertEqual(b.call("gettxout", funding, 0, True)["confirmations"], 1)
        self.assertLessEqual(self.honest.calls.count("blockchain.headers.subscribe") - before, 2)

    def test_control_the_same_output_is_found_when_no_sync_is_in_flight(self):
        slow = HoldProxy(self.a.port, b"blockchain.headers.subscribe", 0.0)
        self.addCleanup(slow.close)
        b = self.light(slow.url, self.honest.url)
        b.call("getblockcount")
        txid = self.sim.credit("", 0, 70_000, self.spk)
        self.assertEqual(b.call("gettxout", txid, 0, True)["confirmations"], 1)
        self.assertEqual(reasons(b, self.honest.url), [])

    def test_control_the_same_scan_succeeds_with_no_slow_server(self):
        for _ in range(20):
            self.sim.credit("", 0, 5_000, self.spk)
        b = self.light(self.a.url, self.honest.url, timeout=1)
        self.assertEqual(len(b.call("scantxoutset", "start", [f"raw({self.spk})"])["unspents"]), 20)

    def test_control_a_small_broadcast_to_a_server_that_stops_reading_ends_at_the_timeout(self):
        tx = Tx(version=2, inputs=[TxIn(os.urandom(32), 0)], outputs=[TxOut(1_000, bytes.fromhex(spk()))], locktime=0)
        self.a.slow["blockchain.transaction.broadcast"] = 5
        b = self.light(self.a.url, timeout=0.5)
        t0 = time.monotonic()
        with self.assertRaises(ElectrumError):
            b.call("sendrawtransaction", tx.hex())
        self.assertLess(time.monotonic() - t0, 2.5)


if __name__ == "__main__":
    unittest.main()
