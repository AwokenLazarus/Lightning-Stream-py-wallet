"""AGP-102 (fourth closure audit, area LIGHT): what fix wave 5 leaves open in B2's light client.

Each test is named as the rule that should hold. Those in `Holes` FAIL on B2 `ce81710`; those named
`test_control_*` pass in the same rig, and `test_limit_*` / `test_measure_*` pass and pin a number.

AGP-107 (close-out): every test here passes. Fix wave 6 (AGP-106) closed the holes but one, the
scan of many hot keys, which it wrote down; that test is a `test_limit_` test now and says which
sentence of docs/LIMITS.md it pins.

  * A request is written by one deadline only on a plain socket. On a TLS socket (the only kind
    mainnet allows to a server that is not on the loopback) `SO_SNDTIMEO` makes the kernel's send
    return "try again", OpenSSL reports "want write", and CPython's `SSLSocket.send` on a socket
    with no timeout of its own tries again for ever: a server that stops reading still holds the
    write for good.
  * One configured server among honest ones makes the lookup of a confirmed coin an honest server
    proves fail on every call: a header sync runs inside the call's budget, has a deadline of its
    own that is as long, and any server can ask for one (a tip notification) or force one (a claim
    above the tip, when it is listed first).
  * A height (or a proof position) that no integer holds (`1e999`, which Python's JSON reader takes
    for infinity) leaves the backend as an `OverflowError`, which is not the `KnotsRpcError` every
    caller catches.
  * The call's deadline covers a scan of every hot key, and the scan asks key by key.
  * Requests given up at the call's deadline stay pending without a bound on their number, and
    each adds to the JSON values a line may hold.

Ports: the listeners made here use 27870-27899 (the fake servers of `_electrum_sim` pick their own).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from agentwallet.b1path import ensure_b1
from agentwallet.electrum import (MAX_HISTORY, ElectrumBackend, ElectrumConnection, ElectrumError, Late,
                                  scripthash)
from agentwallet.rpc import KnotsRpcError

ensure_b1()
from xbt402.tx import Tx, TxIn, TxOut  # noqa: E402

import test_agp093_light as audit  # noqa: E402
from test_agp093_light import HoldProxy, Knobs, Rig, reasons  # noqa: E402
from _electrum_sim import CHECKPOINT, T0, junk_header, mine_header  # noqa: E402

audit_ports = audit.PORTS
PORTS = iter(range(27870, 27900))


class Proxy(HoldProxy):
    """The third audit's proxy, on this file's ports."""

    def __init__(self, upstream_port: int, needle: bytes, hold_s: float):
        audit.PORTS = PORTS
        try:
            super().__init__(upstream_port, needle, hold_s)
        finally:
            audit.PORTS = audit_ports


class Staller(Knobs):
    """A server that holds its part of every header sync to the sync deadline, and lies about
    nothing a proof could catch: its tip is a header of its own at a height below ours (valid
    proof of work at the regtest target, on no chain we hold), every `blockchain.block.header` it
    serves is another header again, and each of those answers comes `hold` seconds late (less
    than a timeout: it is never hung up on for it). With `notify` it also sends a tip
    notification with each of them, as any server may at any time."""

    def __init__(self, sim, hold: float, notify: bool):
        super().__init__(sim)
        self.fake_tip = mine_header("ee" * 32, b"\x07" * 32, sim.height - 1, 1, T0 + 60 * sim.height)
        self.junk_above = CHECKPOINT
        self.slow["blockchain.block.header"] = hold
        self.notify = notify

    def answer(self, client, method, p):
        if method == "blockchain.block.header" and self.notify:
            client.send({"jsonrpc": "2.0", "method": "blockchain.headers.subscribe",
                         "params": [{"hex": self.fake_tip.hex(), "height": int(p[0])}]})
        return super().answer(client, method, p)


class TlsSilent:
    """A TLS (or, with `tls=False`, plain) server that answers `server.version` and then stops
    reading. Its segment size is an Ethernet path's, so the kernel's buffers are a real link's
    and not the loopback's (which take megabytes)."""

    def __init__(self, certfile: str | None, keyfile: str | None):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1400)
        self.port = next(PORTS)
        self.listener.bind(("127.0.0.1", self.port))
        self.listener.listen(4)
        self.url = f"{'ssl' if certfile else 'tcp'}://localhost:{self.port}"
        self.held: list = []
        ctx = None
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)

        def serve():
            while True:
                try:
                    c, _ = self.listener.accept()
                except OSError:
                    return
                try:
                    if ctx:
                        c = ctx.wrap_socket(c, server_side=True)
                    self.held.append(c)
                    req = json.loads(c.makefile("rb").readline())
                    c.sendall((json.dumps({"id": req["id"], "result": ["silent", "1.8"]}) + "\n").encode())
                except (OSError, ValueError):
                    continue

        threading.Thread(target=serve, daemon=True).start()

    def close(self):
        self.listener.close()
        for c in self.held:
            try:
                c.close()
            except OSError:
                pass


class Holes(Rig):
    # --- a request is written by one deadline, whatever the transport ------------------------------
    def held(self, server, line_hex_chars: int, wait: float) -> tuple[bool, float, str]:
        """(still writing after `wait` seconds, seconds it took, how it ended) for one request of
        `line_hex_chars` to `server`, at a timeout of 0.5 s."""
        c = ElectrumConnection(server.url, timeout=0.5)
        self.addCleanup(c.close)
        c.connect()
        out = {}

        def go():
            t0 = time.monotonic()
            try:
                c.request("blockchain.transaction.broadcast", "00" * (line_hex_chars // 2))
                out["end"] = "answered"
            except Exception as e:      # noqa: BLE001 - reported
                out["end"] = f"{type(e).__name__}: {e}"[:90]
            out["took"] = time.monotonic() - t0

        t = threading.Thread(target=go, daemon=True)
        t.start()
        t.join(wait)
        return t.is_alive(), out.get("took", wait), out.get("end", "still writing")

    def tls_fixture(self) -> tuple[str, str]:
        if not shutil.which("openssl"):
            self.skipTest("no openssl to make a test certificate with")
        d = tempfile.mkdtemp(prefix="agp102-light-")
        self.addCleanup(shutil.rmtree, d, True)
        cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
        real = ssl.create_default_context

        def trusting(*a, **kw):
            ctx = real(*a, **kw)
            ctx.load_verify_locations(cert)
            return ctx

        p = mock.patch.object(ssl, "create_default_context", trusting)
        p.start()
        self.addCleanup(p.stop)
        return cert, key

    def test_a_tls_server_that_stops_reading_holds_a_write_for_one_timeout(self):
        """The rule (AGP-097, `ElectrumConnection._write`): a request is written by one deadline,
        however slowly the server reads, or not at all. The request is a 100 kB transaction's
        broadcast (200,000 hex characters): a standard transaction."""
        cert, key = self.tls_fixture()
        srv = TlsSilent(cert, key)
        self.addCleanup(srv.close)
        stuck, took, end = self.held(srv, 200_000, 4.0)
        print(f"\nAGP-102 measure (B2): a 200 kB request line to a TLS server that stops reading, timeout 0.5 s: "
              f"{'still writing after' if stuck else 'ended after'} {took:.2f} s ({end})")
        self.assertFalse(stuck, "the write was still held 4 s after a deadline of 0.5 s")
        self.assertLess(took, 1.5)

    def test_control_the_same_request_to_a_plain_server_ends_at_the_timeout(self):
        srv = TlsSilent(None, None)
        self.addCleanup(srv.close)
        stuck, took, end = self.held(srv, 200_000, 4.0)
        print(f"\nAGP-102 measure (B2): the same line to a plain TCP server that stops reading: {took:.2f} s ({end})")
        self.assertFalse(stuck)
        self.assertLess(took, 1.5)

    def test_measure_the_smallest_line_a_silent_tls_server_holds(self):
        """Not a rule: the size from which the write was held, on a path with 1400-byte segments.
        On `ce81710` this pinned `{20_000: False, 60_000: True}`; since AGP-106 a TLS write ends at
        its deadline whatever its size, so neither is held."""
        cert, key = self.tls_fixture()
        got = {}
        for chars in (20_000, 60_000):
            srv = TlsSilent(cert, key)
            self.addCleanup(srv.close)
            got[chars] = self.held(srv, chars, 2.0)[0]
        print(f"\nAGP-102 measure (B2): held for good by a silent TLS server, by request size in hex characters: {got}")
        self.assertEqual(got, {20_000: False, 60_000: False})

    # --- what a server proves keeps working beside one hostile server ------------------------------
    def lookups(self, b, funding: str, n: int = 3) -> int:
        failed = 0
        for k in range(1, n + 1):
            t0 = time.monotonic()
            try:
                got = b.call("gettxout", funding, 0, True)
                end = f"{got and got['confirmations']} confirmations"
            except Exception as e:      # noqa: BLE001 - counted and reported
                failed += 1
                end = f"{type(e).__name__}: {str(e)[:100]}"
            print(f"\nAGP-102 measure (B2): lookup {k} of a coin 3 blocks deep beside one hostile server, timeout "
                  f"{b.conns[0].timeout} s: {end} after {time.monotonic() - t0:.2f} s")
        return failed

    def test_a_confirmed_coin_an_honest_server_proves_is_found_beside_a_server_that_asks_for_syncs_and_holds_them(self):
        """The hostile server is listed second and makes no claim about the coin at all. It sends
        tip notifications (so the `sync()` inside `_rpc_gettxout`, which runs under the call's
        budget, starts a round) and holds its part of each round to the sync deadline, which is as
        long as the call's: when the round ends the call is over and every request is `Late`.
        The refund asks exactly this (`signer.py:459`, answered `refund_rpc` and tried again)."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.sim.mine(2)
        hostile = Staller(self.sim, hold=0.28, notify=True)
        self.addCleanup(hostile.close)
        b = self.light(self.honest.url, hostile.url, timeout=0.4)
        failed = self.lookups(b, funding)
        print(f"\nAGP-102 measure (B2): flags on the honest server: {reasons(b, self.honest.url)}")
        self.assertEqual(failed, 0, f"{failed} of 3 lookups of a confirmed, provable coin failed")

    def test_control_the_same_coin_is_found_when_that_server_sends_no_notifications(self):
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.sim.mine(2)
        hostile = Staller(self.sim, hold=0.28, notify=False)
        self.addCleanup(hostile.close)
        b = self.light(self.honest.url, hostile.url, timeout=0.4)
        self.assertEqual(self.lookups(b, funding, 2), 0)

    def test_a_confirmed_coin_is_found_beside_a_server_listed_first_that_claims_it_above_the_tip_and_holds_the_sync(self):
        """The Rust backend's case (`agp102_light.rs`), which B2 shares: the hostile server sends
        no notification; it is listed first and claims the coin one block above the tip, which
        forces the call's one header sync (`electrum.py:1144-1148`) inside the call's budget."""
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.sim.mine(2)
        hostile = Staller(self.sim, hold=0.28, notify=False)
        self.addCleanup(hostile.close)
        hostile.claim_height[funding] = self.sim.height + 1
        b = self.light(hostile.url, self.honest.url, timeout=0.4)
        failed = self.lookups(b, funding)
        self.assertEqual(failed, 0, f"{failed} of 3 lookups of a confirmed, provable coin failed")

    # --- numbers from a server ---------------------------------------------------------------------
    def test_a_height_no_integer_holds_is_a_malformed_entry_and_not_a_crash(self):
        """`int(e["height"])` (`electrum.py:968`) raises OverflowError for an infinite float, and
        Python's JSON reader makes one of `1e999` as well as of `Infinity`. The handlers beside it
        catch KeyError, TypeError and ValueError. The rule every other malformed entry keeps:
        flagged, skipped, and the honest server's proof answers. At the least the failure must be
        the backend's own error type, which is the one its callers catch (`signer.py:460`)."""
        self.assertEqual(json.loads("1e999"), float("inf"), "strict JSON reaches the same value")
        funding = self.sim.credit("", 0, 70_000, self.spk)
        self.a.extra_history[scripthash(bytes.fromhex(self.spk))] = [{"tx_hash": funding, "height": float("inf")}]
        b = self.light(self.honest.url, self.a.url)
        ends = {}
        for name, ask in (("gettxout", lambda: b.call("gettxout", funding, 0, True)),
                          ("proven_spend", lambda: b.proven_spend(funding, 0, self.spk)),
                          ("gettxspendingprevout", lambda: b.call("gettxspendingprevout", [{"txid": funding, "vout": 0}]))):
            try:
                ask()
                ends[name] = "answered"
            except KnotsRpcError as e:
                ends[name] = f"backend error: {str(e)[:60]}"
            except Exception as e:      # noqa: BLE001 - this is the finding
                ends[name] = type(e).__name__
        print(f"\nAGP-102 measure (B2): one server lists the funding at height 1e999: {ends}")
        self.assertEqual(ends, dict.fromkeys(ends, "answered"))

    def test_a_proof_position_no_integer_holds_is_a_proof_that_does_not_hold(self):
        """The same for `int(m["pos"])` in `_proves` (`electrum.py:1080`), reached through
        `_confirmed` in the caller's thread: the server claims the real height and answers the
        proof request with `"pos": 1e999`."""
        funding = self.sim.credit("", 0, 70_000, self.spk)

        class BadProof(Knobs):
            def answer(self, client, method, p):
                got = super().answer(client, method, p)
                if method == "blockchain.transaction.get_merkle":
                    got["pos"] = float("inf")
                return got

        bad = BadProof(self.sim)
        self.addCleanup(bad.close)
        b = self.light(bad.url, self.honest.url)
        try:
            end = f"{b.call('gettxout', funding, 0, True)['confirmations']} confirmations"
        except KnotsRpcError as e:
            end = f"backend error: {str(e)[:60]}"
        except Exception as e:          # noqa: BLE001 - this is the finding
            end = type(e).__name__
        print(f"\nAGP-102 measure (B2): the first server answers the proof with pos 1e999: {end}")
        self.assertEqual(end, "1 confirmations")

    # --- the scan of every hot key -----------------------------------------------------------------
    def test_limit_a_scan_of_many_keys_fails_beside_a_server_a_third_of_a_timeout_late(self):
        """`hot.reconcile` scans every hot key, current and retired, in one `scantxoutset`, and the
        call's deadline covers all of them. The scan asks key by key, so one honest server 0.3
        timeouts late on each listing uses the deadline up at the fourteenth key: the many-coins
        failure of the third audit, by keys.

        LIMIT (AGP-107; the fourth audit's list 1 item 17, LIGHT 5, written down by AGP-106, which
        found that both fixes add surface). Written by the audit as
        test_a_scan_of_many_keys_succeeds_when_every_server_answers_inside_a_third_of_the_timeout.
        The sentence it pins (docs/LIMITS.md, light client): "In the Python wallet one scan's
        deadline covers every hot key, current and retired: a light wallet whose hot key was
        rotated about a dozen times can fail its coin scan beside a server a third of a timeout
        late. No coin is lost; the reconcile reports a scan error." The last assertion is turned
        round; it fails when the scan gets a budget per key or asks for all keys at once: then
        restore the audit's (`end == "1 coin"`)."""
        keys = [self.spk] + [audit.spk() for _ in range(15)]
        self.sim.credit("", 0, 5_000, self.spk)
        slow = Proxy(self.a.port, b"blockchain.scripthash.listunspent", 0.3)
        self.addCleanup(slow.close)
        b = self.light(slow.url, self.honest.url, timeout=1)
        b.call("getblockcount")
        t0 = time.monotonic()
        try:
            end = f"{len(b.call('scantxoutset', 'start', [f'raw({k})' for k in keys])['unspents'])} coin"
        except ElectrumError as e:
            end = f"{type(e).__name__}: {str(e)[:70]}"
        print(f"\nAGP-102 measure (B2): a scan of 16 keys beside a server 0.3 timeouts late on each listing, "
              f"timeout 1 s: {end} after {time.monotonic() - t0:.2f} s")
        self.assertTrue(end.startswith("Unknown: no server answered listunspent"), f"the limit is lifted or moved: {end}")

    def test_control_the_same_scan_of_many_keys_succeeds_with_no_slow_server(self):
        keys = [self.spk] + [audit.spk() for _ in range(15)]
        self.sim.credit("", 0, 5_000, self.spk)
        b = self.light(self.a.url, self.honest.url, timeout=1)
        self.assertEqual(len(b.call("scantxoutset", "start", [f"raw({k})" for k in keys])["unspents"]), 1)

    # --- unknown is not absent, in a scan -----------------------------------------------------------
    def test_a_coin_whose_only_lister_is_busy_for_its_transaction_fails_the_scan(self):
        """A coin a server lists is left out of a scan only on an answer, and "busy" is no answer
        (`says_not_there`). `_fetch_tx` keeps that; `_supply` (`electrum.py:1043-1053`) takes any
        error of the server for a transaction it listed as "does not supply it". One server hides
        the coin, the honest one lists it and is busy when asked for its transaction: the scan
        answers "no coins", marked complete. Left from AGP-092; not a wave 5 change."""
        coin = self.sim.credit("", 0, 9_000, self.spk)
        self.a.hide.add(coin)

        class Busy(Knobs):
            def answer(self, client, method, p):
                if method == "blockchain.transaction.get":
                    raise ValueError("server busy, try again later")
                return super().answer(client, method, p)

        busy = Busy(self.sim)
        self.addCleanup(busy.close)
        b = self.light(busy.url, self.a.url)
        try:
            got = b.call("scantxoutset", "start", [f"raw({self.spk})"])
            end = f"{len(got['unspents'])} coins, complete={got['complete']}"
        except ElectrumError as e:
            end = f"{type(e).__name__}"
        print(f"\nAGP-102 measure (B2): a scan beside a hiding server while the honest one is busy for the coin's "
              f"transaction: {end}")
        self.assertEqual(end, "Unknown")


    # --- requests given up at the deadline ---------------------------------------------------------
    def test_requests_given_up_at_the_deadline_do_not_add_up_without_bound(self):
        """A request the call's deadline cuts short stays pending so that its late answer is
        within what the connection allows (`electrum.py:241-244`). Nothing bounds how many: a
        server that answers what it is given a whole timeout for and never the requests it sees
        late keeps one more slot per call, and each history request adds 60,016 to the JSON values
        its next line may hold (`_allowance`: only the bytes are capped). AGP-081's cap for what a
        line may cost to parse was one history's values."""
        asked = threading.Event()

        def serve(c, f):
            for line in f:
                req = json.loads(line)
                if req["method"] == "server.ping":
                    c.sendall((json.dumps({"id": req["id"], "result": None}) + "\n").encode())
                asked.set()                 # get_history: never answered

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
        one = 16 + 6 * MAX_HISTORY
        for _ in range(200):
            got = c.batch_by(time.monotonic() + 0.005, [("blockchain.scripthash.get_history", ("00" * 32,))])
            self.assertIsInstance(got[0], Late)
            self.assertIsNone(c.request("server.ping"))         # the connection answers and stays
        print(f"\nAGP-102 measure (B2): after 200 calls cut short on one connection: {len(c._pending)} requests pending, "
              f"a line may hold {c._allowance().values:,} JSON values in {c._allowance().size:,} bytes "
              f"(one history request allows {one:,})")
        self.assertTrue(c.connected)
        self.assertLessEqual(len(c._pending), 16, "pending requests nobody waits for")
        self.assertLessEqual(c._allowance().values, 64 + 16 * one)


class TheWatcher(unittest.TestCase):
    """What the two failures above come to in the wallet: the refund of a channel past its expiry,
    asked by the watcher's tick (`Signer.watch_tick` -> `_refund_locked` -> `gettxout`)."""

    def opened(self):
        from test_agp087_light_refund import RefundOnTheLightBackend
        rig = RefundOnTheLightBackend.opened(self)
        rec = rig.channel()
        rig.mine(rec.expiry - rig.node.height)
        return rig, rec

    def restart(self, rig, *fakes, **kw):
        from agentwallet.signer import Signer
        from test_electrum_backend import backend
        rig.light.close()
        rig.light = backend(*fakes, sim=rig.node, **kw)
        rig.signer = Signer(rig.tmp, rpc=rig.light)

    def test_a_channel_past_its_expiry_is_refunded_beside_a_server_that_lists_its_funding_at_a_height_no_integer_holds(self):
        """The honest server shows the funding confirmed and unspent; the other lists it in the
        funding script's history at height 1e999. `gettxout` leaves the backend as OverflowError,
        `_refund_locked` catches KnotsRpcError only (`signer.py:460`), and the refund loop of the
        tick has no guard of its own (`signer.py`, `for rec in self.channels.unsettled_records()`):
        the tick ends there, on every tick, before any later channel, the forward and treasury
        settlements, the close changes, the retired sweep and the anchor."""
        from test_electrum_backend import FakeElectrum
        from xbt402.channel import funding_script
        from xbt402.tx import p2wsh_spk
        rig, rec = self.opened()
        hostile = FakeElectrum(rig.node)
        self.addCleanup(hostile.close)
        script = p2wsh_spk(funding_script(bytes.fromhex(rec.payer_pub), bytes.fromhex(rec.payee_pub), rec.expiry))
        hostile.extra_history[scripthash(script)] = [{"tx_hash": rec.funding_txid, "height": float("inf")}]
        self.restart(rig, rig.fake, hostile)
        try:
            end = f"tick returned {[a.get('rule') for a in rig.tick() if a.get('dest') == rec.dest]}"
        except Exception as e:          # noqa: BLE001 - this is the finding
            end = f"tick raised {type(e).__name__}: {e}"
        state = rig.channel().state
        print(f"\nAGP-102 measure (B2): watcher tick at expiry beside one server that lists the funding at height "
              f"1e999: {end}; channel state {state!r}")
        self.assertEqual(state, "refunded", end)

    def test_control_the_same_channel_is_refunded_beside_an_honest_second_server(self):
        from test_electrum_backend import FakeElectrum
        rig, rec = self.opened()
        second = FakeElectrum(rig.node)
        self.addCleanup(second.close)
        self.restart(rig, rig.fake, second)
        rig.tick()
        self.assertEqual(rig.channel().state, "refunded")

    def test_a_channel_past_its_expiry_is_refunded_beside_a_server_that_asks_for_syncs_and_holds_them(self):
        """The same refund beside the `Staller`: listed second, no claim about the funding. Every
        tick answers `refund_rpc` and tries again, for as long as that server is configured."""
        rig, rec = self.opened()
        hostile = Staller(rig.node, hold=0.28, notify=True)
        self.addCleanup(hostile.close)
        self.restart(rig, rig.fake, hostile, sync_deadline=1.6, call_deadline=1.6)
        for c in rig.light.conns:
            c.timeout = 0.4
        ends = []
        for _ in range(3):
            try:
                ends += [(a.get("rule"), str(a.get("reason"))[:60]) for a in rig.tick() if a.get("dest") == rec.dest] or ["nothing"]
            except Exception as e:      # noqa: BLE001 - reported
                ends.append(f"{type(e).__name__}: {str(e)[:60]}")
        state = rig.channel().state
        print(f"\nAGP-102 measure (B2): three watcher ticks at expiry beside one server that holds the header syncs: "
              f"{ends}; channel state {state!r}")
        self.assertEqual(state, "refunded", ends)


class Limits(Rig):
    def test_limit_one_missed_history_answer_lists_every_spent_coin_a_liar_shows(self):
        """Not a failure of a stated rule (the search for a spend does not wait for every server,
        by design, AGP-092): this pins what "one history per scan" changes. The liar lists five
        coins that are spent, with their real proofs, and leaves the spends out of its history;
        the honest server answers the listing and misses the one history request of the scan.
        All five are then listed as unspent, and `complete` is true (it speaks of the listing)."""
        coins = [self.sim.credit("", 0, 5_000, self.spk) for _ in range(5)]
        spends = []
        for t in coins:
            tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(t)[::-1], 0)],
                    outputs=[TxOut(4_000, bytes.fromhex("0014" + "11" * 20))], locktime=0)
            self.sim.call("sendrawtransaction", tx.hex())
            spends.append(tx.txid())
        self.sim.mine(1)
        heights = {t: self.sim.conf_height[t] for t in coins}

        class Liar(Knobs):
            def answer(self, client, method, p):
                got = super().answer(client, method, p)
                if method == "blockchain.scripthash.listunspent":
                    got = got + [{"tx_hash": t, "tx_pos": 0, "height": h, "value": 5_000} for t, h in heights.items()]
                return got

        liar = Liar(self.sim)
        self.addCleanup(liar.close)
        liar.hide = set()
        liar._history = lambda sh, real=liar._history: [e for e in real(sh) if e["tx_hash"] not in spends]
        late = Proxy(self.honest.port, b"blockchain.scripthash.get_history", 0.0)
        self.addCleanup(late.close)
        b = self.light(liar.url, late.url, timeout=0.5)
        scan = lambda: b.call("scantxoutset", "start", [f"raw({self.spk})"])      # noqa: E731
        self.assertEqual(scan()["unspents"], [], "with the honest history the spent coins are left out")
        late.hold_s = 5.0
        got = scan()
        print(f"\nAGP-102 measure (B2): the honest server missed the scan's one history request: "
              f"{len(got['unspents'])} of 5 spent coins listed as unspent, complete={got['complete']}")
        self.assertEqual((len(got["unspents"]), got["complete"]), (5, True))


if __name__ == "__main__":
    unittest.main()
