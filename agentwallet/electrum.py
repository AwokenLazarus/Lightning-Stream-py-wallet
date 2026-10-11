"""A light chain backend: Electrum servers, checked against our own BLAKE2b header chain (AGP-024).

`ElectrumBackend.call(method, *params)` answers the node RPCs B2's client path makes (the table in
`chain.py`), so the signer, the hot wallet and the xbt402 session run unchanged on it. Knots-wallet
RPCs (getbalances, sendtoaddress, fundrawtransaction, ...) and mining are not available: a light
client has no node wallet and never mines.

Trust (see docs/B2_CHAIN_BACKEND.md for the full threat model):
  * Headers: our own chain from a pinned post-fork checkpoint, each header's BLAKE2b PoW, nBits,
    flags, version and median time checked as it arrives, chunk by chunk (headers.py); the most-work
    chain any server shows wins. A server cannot move us to a chain with less work, or below the
    checkpoint; a claimed tip beyond one block per 150 s since our tip (plus 2016) is not fetched.
  * Mainnet: until the chain reaches Knots' pinned block 964264, carries Knots' nMinimumChainWork and
    its tip is not implausibly far behind the clock, every chain answer is withheld (ImplausibleChain).
    Servers must be ssl:// (certificates verified); plain tcp:// only to a loopback host.
  * No lock is held across a network read: one sync runs at a time, servers in parallel, and a
    caller with a verified chain answers from it rather than wait for a sync in flight.
  * Transactions: a raw tx is accepted only if it re-serializes byte for byte and hashes to the txid
    asked for. A transaction counts as confirmed only with a Merkle proof into one of our headers
    whose committed transaction count fits the proof. Confirmations, the funding's block, a close
    and a refund's spent/unspent status all rest on proofs, never on a server's word.
  * Several servers: histories and unspent lists are the union over every reachable server (proofs
    stop fabrication; the union means one honest server defeats hiding), headers are cross-checked
    (a server whose tip is not on the best chain is reported), broadcasts go to all of them.
  * Mempool facts cannot be proven. A spend seen only in a mempool never makes an output count as
    spent (gettxout keeps it), so a lying server cannot talk the wallet out of a refund; an
    unconfirmed transaction is reported with 0 confirmations and nothing waits on it as confirmed.
  * What one server can cost (AGP-081). Every request has an answer cap known from its method and
    params (`answer_cap`); a line longer or denser than the pending requests allow drops the server
    before it is parsed. A history or unspent list above MAX_HISTORY entries is not used, an entry
    that neither pays nor spends the script is flagged, and verified transactions are cached up to
    TX_CACHE_BYTES. A server's part of a header sync ends at its first short answer and at
    `sync_deadline`, keeping what it proved. Transactions above MAX_TX_BYTES are not fetched.
  * Unknown is not absent (AGP-092). A lookup says "not there" (no such transaction or output, not
    in a block, no such coin) only when every configured server answered. If one did not, or is
    down, the call raises (`min_servers` is the floor for what is proven). gettxout says "spent" (None for a known funding) only for a confirmed spend with a proof;
    `proven_spend` names that spend, and it is what a caller must ask before it books a close.
  * A call has a deadline (`call_deadline`, AGP-092): every request made for it ends there, and it
    forces one header sync at most. A server is asked only for the transactions it listed itself,
    in parallel with the others; the first it does not supply, or that cannot belong to the
    script, ends its list and flags it. Connecting costs one timeout for TCP and TLS together.
  * AGP-097. Every entry that makes requests runs under one call budget (`_budget`: `call` and
    `proven_spend`). A scan asks for the script's history once and for the coins' proofs in one
    write per server (`_spends`, `_prove_ahead`). A request is written by one deadline (`_write`).
    A request the call's deadline cuts short, or leaves no time for, hangs up on nobody and flags
    nobody (`Late`); one that goes a whole timeout unanswered still does. A claim above a server's
    tip is a lie only against a tip it reported in the sync this call forced (`_Call.round`); an
    error about the method ("Method not found", JSON-RPC -32601) is never "not there".
What a malicious server can still do: hide a transaction (a close, a funding) from us until another
server or a block shows it; if every configured server hides it, gettxout reads it as absent, which
is why a close is booked on `proven_spend` and not on that. It can make calls fail or slow, never
answer wrongly: by not answering, or by being down, it turns a "not there" into an error for as
long as it is configured, and by listing transactions that pay the script and supplying them slowly it holds
each call that reads that script up to `call_deadline`. Both are flagged (`status()`); the cure is
to remove the server. It can lie about fee estimates and learn which scripts we watch. Hiding a
close delays counting the change (AGP-022's retry keeps asking) and makes the refund at expiry fail
at broadcast; neither loses coins. "No such transaction" and "not in that block" are read from the
server's words (NOT_THERE); an error worded otherwise counts as no answer.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .b1path import ensure_b1
from .headers import (
    MAINNET_CHECKPOINT,
    V2_SIZE,
    HeaderChain,
    HeaderError,
    check_pow,
    mainnet_min_work_above,
    merkle_root_from_proof,
    parse_header,
    rules_for,
    sha256,
    split_headers,
)
from .netparams import HRP
from .rpc import KnotsRpcError

ensure_b1()
from xbt402.tx import Tx, segwit_address  # noqa: E402

XBT_SATS = 100_000_000
PROTOCOL = ["1.4", "1.8"]          # electrs refuses < 1.8 on a chain with v2 headers
HEADERS_CHUNK = 2016
CLIENT_NAME = "b2-agentwallet"
STALE_TIP_S = 3 * 60 * 60
TIP_CAP_SPACING_S = 150            # a quarter of the target spacing: claimed tips beyond it are not fetched
MAX_LINE = 8 << 20                 # no line is longer than this, whatever is pending
NOTIFY_SLACK = 16 << 10            # bytes a line may hold beyond what the pending requests allow (a notification)
VALUE_SLACK = 64                   # the same, in JSON values
MAX_HISTORY = 10_000               # entries of one script in one server's get_history or listunspent answer
MAX_TX_BYTES = 1_000_000           # a transaction above this (raw) is not fetched
TX_BATCH = 16                      # proof requests written to one server together (`_prove_ahead`)
TX_CACHE_BYTES = 32 << 20          # raw bytes of verified transactions kept; the oldest leave first
SYNC_DEADLINE_TIMEOUTS = 4         # the default sync_deadline, in request timeouts
CALL_DEADLINE_TIMEOUTS = 4         # the default call_deadline, in request timeouts
# a server's words for "I have no such transaction" and "it is not in that block"
NOT_THERE = ("no such", "not found", "not in block", "not confirmed", "no transaction", "missing")
METHOD_NOT_FOUND = -32601          # JSON-RPC 2.0: the server has no such method
NODE_ONLY = {
    "getbalances", "getbalance", "sendtoaddress", "listunspent", "createrawtransaction", "fundrawtransaction",
    "signrawtransactionwithwallet", "getnewaddress", "generatetoaddress", "generatetodescriptor", "generateblock",
    "generate", "getblock", "getwalletinfo", "sendmany",
}


class ElectrumError(KnotsRpcError):
    """A light-backend failure. A KnotsRpcError, so every caller that tolerates a node error tolerates it."""


class CheckpointMismatch(ElectrumError):
    """Servers answered, but none is on the pinned checkpoint: the wrong chain (or the wrong checkpoint)."""


class LightBackendError(ElectrumError):
    """The call needs a full node (a node wallet, blocks, or mining)."""


class ImplausibleChain(ElectrumError):
    """The verified chain is not believable yet (Plausibility): nothing is answered from it."""


class ServerError(ElectrumError):
    """The server answered the request with a JSON-RPC error: its own words."""


class Unknown(ElectrumError):
    """A server did not answer, so "not there" is not known (AGP-092): nothing is concluded from it."""


class Late(ElectrumError):
    """The call's own deadline came before a request was sent, or before its answer (AGP-097). The
    deadline is shared by every server of the call, so this says nothing about the one that was
    being asked: it is not flagged and not hung up on for it."""


class _OffCheckpoint(HeaderError):
    pass


def says_not_there(e: Exception) -> bool:
    """A server's own "I have no such transaction" (or, asked for a proof, "it is not in that block").
    Any other error is no answer: busy, rate-limited, gone, or a wording not known here, which fails
    closed.

    An error that speaks of the method is one of those (AGP-097): "Method not found" is JSON-RPC's
    answer for a method the server does not serve, and two of the words ("not found", "missing")
    are in it. Such a server has said nothing about this transaction. `ElectrumConnection` puts the
    error code -32601 into the same words when the server's own do not name the method."""
    m = str(e).lower()
    return isinstance(e, ServerError) and "method" not in m and any(w in m for w in NOT_THERE)


@dataclass
class _Call:
    """One call's budget: its requests end at `deadline` (monotonic), it forces one header sync, and
    it tries once to reach a server that is down (`gone`: the urls it could not reach; a dead server
    used to cost every step of a call one timeout)."""
    deadline: float
    synced: bool = False
    gone: set = field(default_factory=set)
    # The sync round this call itself ran when it forced one (0: none, or it found another sync in
    # flight and ran nothing). Only against a tip a server reported in that round, or a later one,
    # is a claim above the server's tip a lie (AGP-097).
    round: int = 0

    def left(self, conn) -> float:
        """The wait for a connect: the request timeout, or less when the deadline is nearer."""
        t = self.deadline - time.monotonic()
        if t <= 0:
            raise Late("call deadline")
        return min(conn.timeout, t)

    @property
    def over(self) -> bool:
        return time.monotonic() >= self.deadline


class _Hist(dict):
    """txid -> [(conn, claimed height)]. `complete`: every configured server gave a usable answer;
    without it "not listed" is not known."""
    complete = True


class _Dropped(Exception):
    """A server sent a line no pending request allows: its connection is closed."""


@dataclass(frozen=True)
class AnswerCap:
    """The most one request's answer may be: bytes of its line, and JSON values in it."""
    size: int = 16 << 10
    values: int = 64


def answer_cap(method: str, params) -> AnswerCap:
    """What the answer to this request can be, at its largest (twice the hex of what was asked for,
    plus the envelope). A method not named here answers with a hash, a header or a status."""
    if method == "blockchain.block.headers":
        try:
            count = max(0, int(params[1]))
        except (IndexError, TypeError, ValueError):
            return AnswerCap()
        return AnswerCap(4096 + 2 * V2_SIZE * count)
    if method == "blockchain.transaction.get":
        return AnswerCap(2 * MAX_TX_BYTES + 1024)
    if method in ("blockchain.scripthash.get_history", "blockchain.scripthash.listunspent"):
        return AnswerCap(4096 + 160 * MAX_HISTORY, 16 + 6 * MAX_HISTORY)
    if method == "blockchain.transaction.get_merkle":
        return AnswerCap(8192, 128)
    return AnswerCap()


def json_values(line: bytes) -> int:
    """An upper bound on the JSON values in a line, from a byte count (strings are not tracked: the
    answers are hex strings and small objects). Parsing costs memory per value, not per byte."""
    return line.count(b",") + line.count(b"[") + line.count(b"{") + 1


@dataclass
class _Pending:
    """A request waiting for its answer: the reader fills `msg` and sets `done`."""
    cap: AnswerCap
    done: threading.Event = field(default_factory=threading.Event)
    msg: dict | None = None
    # Its caller stopped waiting at a deadline that was not the server's (`request_by`): the slot
    # stays so that an answer that still comes is within what the connection allows, and goes when
    # the answer or the end of the connection does.
    kept: bool = False


@dataclass(frozen=True)
class Plausibility:
    """When the verified chain is believable (HeaderChain.implausible)."""
    min_work_above: int              # work the chain must carry above the checkpoint
    floor_spacing_s: int = 600       # the tip may trail one block per floor_spacing_s since the newest
    floor_slack: int = HEADERS_CHUNK  # pinned block held (or the checkpoint) by at most floor_slack

    @classmethod
    def mainnet(cls, checkpoint: tuple[int, str]) -> "Plausibility":
        """Knots' nMinimumChainWork less the checkpoint's chainwork (0 for a checkpoint of unknown
        chainwork, which must still reach the pinned block 964264)."""
        return cls(min_work_above=mainnet_min_work_above(checkpoint) or 0)


def is_loopback_host(host: str) -> bool:
    """localhost, 127.0.0.0/8, ::1 or an IPv4-mapped loopback address."""
    h = host.rstrip(".").strip("[]")
    if h.lower() == "localhost":
        return True
    try:
        a = ipaddress.ip_address(h)
    except ValueError:
        return False
    mapped = getattr(a, "ipv4_mapped", None)
    return a.is_loopback or bool(mapped and mapped.is_loopback)


def scripthash(spk: bytes) -> str:
    return sha256(spk)[::-1].hex()


def parse_server(url: str) -> tuple[str, int, bool]:
    """tcp://host:port, ssl://host:port, or Electrum's host:port:t / host:port:s."""
    if "://" in url:
        u = urlparse(url)
        if u.scheme not in ("tcp", "ssl") or not u.hostname or not u.port:
            raise ValueError(f"bad Electrum server {url!r}: use tcp://host:port or ssl://host:port")
        return u.hostname, int(u.port), u.scheme == "ssl"
    parts = url.rsplit(":", 2)
    if len(parts) == 3 and parts[2] in ("t", "s"):
        return parts[0], int(parts[1]), parts[2] == "s"
    raise ValueError(f"bad Electrum server {url!r}: use tcp://host:port or ssl://host:port")


class ElectrumConnection:
    """One newline-delimited JSON-RPC connection. Notifications go to `on_notify(conn, method, params)`.
    Subscriptions are re-sent after a reconnect. A line above what the pending requests can be
    answered with (`_allowance`) closes the connection before it is parsed, and `on_drop(conn, why)`
    is told."""

    def __init__(self, url: str, *, timeout: float = 15.0, on_notify=None, on_drop=None):
        self.url = url
        self.host, self.port, self.tls = parse_server(url)
        self.timeout = float(timeout)
        self.on_notify = on_notify
        self.on_drop = on_drop
        self.proto = ""
        self.server_id = ""
        self._sock: socket.socket | None = None
        self._wlock = threading.Lock()
        self._clock = threading.Lock()
        self._ids = itertools.count(1)
        self._pending: dict[int, _Pending] = {}
        self._subs: dict[tuple, None] = {}
        self._reader: threading.Thread | None = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self, timeout: float | None = None) -> None:
        """Rule (AGP-092): reaching a server costs one deadline, `timeout` (the request timeout if
        None), for the TCP connect, the TLS handshake, `server.version` and the subscriptions
        together, whatever the server sends and however slowly."""
        deadline = time.monotonic() + (self.timeout if timeout is None else min(timeout, self.timeout))

        def left() -> float:
            t = deadline - time.monotonic()
            if t <= 0:
                raise ElectrumError(f"{self.url}: not connected by its deadline")
            return t

        with self._clock:
            if self._sock is not None:
                return
            try:
                raw = socket.create_connection((self.host, self.port), timeout=left())
                if self.tls:
                    ctx = ssl.create_default_context()
                    raw = ctx.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
                    raw.settimeout(left())      # CPython holds one do_handshake() call to this, as a deadline
                    raw.do_handshake()
            except OSError as e:
                raise ElectrumError(f"{self.url}: {type(e).__name__}: {str(e)[:120]}") from e
            raw.settimeout(None)
            self._sock = raw
            self._reader = threading.Thread(target=self._read_loop, args=(raw,), name=f"electrum:{self.url}",
                                            daemon=True)
            self._reader.start()
        try:
            sid, proto = self.request("server.version", CLIENT_NAME, PROTOCOL, timeout=left())
            self.server_id, self.proto = str(sid), str(proto)
            for method, params in list(self._subs):
                self.request(method, *params, timeout=left())
        except Exception:
            self.close()
            raise

    def close(self, why: str = "connection closed") -> None:
        with self._clock:
            s, self._sock = self._sock, None
        if s is not None:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
        for rid, slot in list(self._pending.items()):
            slot.msg = {"error": {"message": why}, "closed": True}      # ours, not the server's words
            slot.done.set()
            if slot.kept:                    # nobody waits for it and no answer can come now
                self._pending.pop(rid, None)

    def _allowance(self) -> AnswerCap:
        """What the next line may hold: the caps of the requests now pending and the slack for a
        notification, at most MAX_LINE."""
        caps = [slot.cap for slot in list(self._pending.values())]
        return AnswerCap(min(MAX_LINE, NOTIFY_SLACK + sum(c.size for c in caps)),
                         VALUE_SLACK + sum(c.values for c in caps))

    def _admit(self, size: int, line: bytes | None = None) -> None:
        """Hold a line, or with no `line` the `size` bytes of one still arriving, to the allowance."""
        cap = self._allowance()
        if size > cap.size:
            raise _Dropped(f"a line of {size} bytes{'' if line is not None else ' so far'}, above the "
                           f"{cap.size} allowed for what was asked")
        if line is not None and json_values(line) > cap.values:
            raise _Dropped(f"a line of {json_values(line)} JSON values, above the {cap.values} allowed "
                           "for what was asked")

    def _read_loop(self, sock: socket.socket) -> None:
        buf, seen, why = bytearray(), 0, ""
        try:
            while True:
                chunk = sock.recv(1 << 16)
                if not chunk:
                    break
                buf += chunk
                while (end := buf.find(b"\n", seen)) >= 0:
                    line, seen = bytes(buf[:end]), 0
                    del buf[:end + 1]
                    self._admit(len(line), line)        # before it is parsed
                    if line.strip():
                        self._dispatch(json.loads(line))
                seen = len(buf)
                self._admit(seen)
        except OSError:
            pass
        except ValueError:
            why = "dropped: a line that is not JSON"
        except _Dropped as e:
            why = f"dropped: {e}"
        finally:
            if self._sock is sock:
                if why and self.on_drop:
                    self.on_drop(self, why)
                self.close(why or "connection closed")

    def _dispatch(self, msg) -> None:
        for m in msg if isinstance(msg, list) else [msg]:
            if not isinstance(m, dict):
                raise _Dropped("a line that is not a JSON-RPC message")
            rid = m.get("id")
            slot = self._pending.get(rid) if type(rid) is int else None
            if slot is not None:
                slot.msg = m
                slot.done.set()
                if slot.kept:                # its caller gave up at the call's deadline: dropped unread
                    self._pending.pop(rid, None)
            elif m.get("method") and self.on_notify:
                try:
                    self.on_notify(self, m["method"], m.get("params") or [])
                except Exception:
                    pass

    def _write(self, s, line: bytes, timeout: float) -> None:
        """Write `line`, all of it, within `timeout` seconds.

        The rule (AGP-097): **a request is written by one deadline, however slowly the server
        reads, or not at all.** The socket has no timeout of its own (its reader blocks on it), and
        `sendall` on it waited for as long as the server did not read: a broadcast larger than the
        socket buffers was held for good, under the signer's lock. Each `send` here gets what is
        left of the deadline as the socket's send timeout (SO_SNDTIMEO: sends only, the reader is
        untouched). Where that option cannot be set, a timer hangs up at the deadline, which ends
        the write. A write that fails leaves a line half written: the caller hangs up."""
        deadline = time.monotonic() + timeout
        view, guard = memoryview(line), None
        try:
            while view:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("the request was not written by its deadline")
                if guard is None:
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                                     struct.pack("@ll", int(left), max(1, int((left % 1) * 1_000_000))))
                    except (OSError, AttributeError, struct.error):
                        guard = threading.Timer(left, self.close, args=("write deadline",))
                        guard.daemon = True
                        guard.start()
                view = view[s.send(view):]
        finally:
            if guard is not None:
                guard.cancel()

    def request(self, method: str, *params, timeout: float | None = None):
        """One request. A server that does not answer within `timeout` (the request timeout if None)
        is hung up on; the next request reconnects."""
        got = self._exchange([(method, params)], self.timeout if timeout is None else timeout, False)[0]
        if isinstance(got, Exception):
            raise got
        return got

    def request_by(self, deadline: float, method: str, *params):
        """One request of a call whose requests all end at `deadline` (monotonic).

        The rule (AGP-097): **a server is hung up on only for a request that went a whole timeout
        unanswered.** The call's deadline is shared by every server it asks. A request it leaves no
        time for is not sent, and one it cuts short is given up without hanging up: the time was
        used up elsewhere (by another server, as a rule), and hanging up would cost this server a
        reconnect and a flag for nothing it did. Both raise `Late`. Before, the second ended as a
        timeout: the server was dropped and flagged."""
        got = self.batch_by(deadline, [(method, params)])[0]
        if isinstance(got, Exception):
            raise got
        return got

    def batch_by(self, deadline: float, reqs: list) -> list:
        """`request_by` for several requests written together: [(method, params)] -> each one's
        result, or the exception it would have raised."""
        left = deadline - time.monotonic()
        if left <= 0:
            return [Late(f"{self.url}: the call's deadline came before {m} was sent") for m, _ in reqs]
        return self._exchange(reqs, min(self.timeout, left), left < self.timeout)

    def _exchange(self, reqs: list, timeout: float, shared: bool) -> list:
        """Write `reqs` and wait `timeout` seconds in all for their answers. `shared`: the wait was
        shortened by a deadline that is not this server's own; when it runs out the requests are
        given up (`Late`) and the connection stays."""
        if self._sock is None:
            self.connect(timeout)
        until = time.monotonic() + timeout
        slots = []
        for method, params in reqs:
            rid = next(self._ids)
            slots.append((rid, method, _Pending(answer_cap(method, params)),
                          json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": list(params)})))
            self._pending[rid] = slots[-1][2]
        out, lost = [], None
        try:
            with self._wlock:
                s = self._sock
                if s is None:
                    raise ElectrumError(f"{self.url}: not connected")
                self._write(s, "".join(line + "\n" for _, _, _, line in slots).encode(), max(until - time.monotonic(), 0.001))
            for rid, method, slot, _ in slots:
                msg = None
                if lost is None and not slot.done.wait(max(until - time.monotonic(), 0)):
                    if shared:
                        lost = Late(f"{self.url}: the call's deadline came before the answer to {method}")
                    else:
                        self.close()    # a server that stops answering is dropped; the next request reconnects
                        lost = ElectrumError(f"{self.url}: {method} timed out")
                elif slot.done.is_set():
                    msg = slot.msg
                if msg is None:
                    slot.kept = isinstance(lost, Late)
                    out.append(lost)
                elif msg.get("error"):
                    err = msg["error"]
                    words = str(err.get("message") if isinstance(err, dict) else err)[:400]
                    # an error about the method says nothing about what was asked for: its code is
                    # put in words when the server's own leave the method out (`says_not_there`)
                    if isinstance(err, dict) and err.get("code") == METHOD_NOT_FOUND and "method" not in words.lower():
                        words = f"method not found: {words}"
                    out.append((ElectrumError if msg.get("closed") else ServerError)(words))
                else:
                    out.append(msg.get("result"))
        except OSError as e:
            self.close()
            raise ElectrumError(f"{self.url}: {type(e).__name__}") from e
        finally:
            for rid, _, slot, _ in slots:
                # kept only while an answer can still come (one that came meanwhile is done with)
                if not slot.kept or slot.done.is_set() or self._sock is None:
                    self._pending.pop(rid, None)
        return out

    def subscribe(self, method: str, *params, timeout: float | None = None):
        self._subs[(method, tuple(params))] = None
        return self.request(method, *params, timeout=timeout)


class ElectrumBackend:
    """The node RPCs of B2's client path over Electrum servers, verified (module docstring)."""

    light = True
    backend = "electrum"

    def __init__(self, servers: list[str], *, chain: str, checkpoint: tuple[int, str] | None = None,
                 store_path: Path | None = None, timeout: float = 15.0, min_servers: int | None = None,
                 sync_interval: float = 1.0, connection=ElectrumConnection, clock=time.time,
                 plausibility: Plausibility | None = None, tip_cap_spacing_s: int | None = None,
                 sync_deadline: float | None = None, call_deadline: float | None = None):
        """`tip_cap_spacing_s`: a claimed tip is believed up to one block per this many seconds since our
        tip's time, plus HEADERS_CHUNK. None: TIP_CAP_SPACING_S on mainnet, no cap elsewhere (regtest
        mines blocks as fast as it is asked to).
        `sync_deadline`: seconds one server has for its part of a sync round (None: SYNC_DEADLINE_TIMEOUTS
        request timeouts). What it proved by then is kept.
        `call_deadline`: seconds every request of one call has together (None: CALL_DEADLINE_TIMEOUTS
        request timeouts); the header sync before it has its own deadline."""
        if not servers:
            raise ElectrumError("no Electrum servers configured (B2_ELECTRUM_SERVERS)")
        try:
            rules_for(chain)
        except HeaderError as e:
            raise ElectrumError(str(e)) from e
        if chain == "main":
            for u in servers:
                host, _, tls = parse_server(u)
                if not tls and not is_loopback_host(host):
                    raise ElectrumError(f"{u}: mainnet needs ssl:// (TLS); plain tcp:// only to a loopback host")
        if checkpoint is None:
            if chain != "main":
                raise ElectrumError(f"a {chain} light backend needs a pinned checkpoint (B2_ELECTRUM_CHECKPOINT)")
            checkpoint = MAINNET_CHECKPOINT
        self.chain = chain
        self.hrp = HRP[chain]
        self.wallet = "light"
        self.allow_generate = False
        self.clock = clock
        self.headers = HeaderChain(chain, checkpoint, store_path, clock=clock)
        self.plausibility = plausibility or (Plausibility.mainnet(checkpoint) if chain == "main" else None)
        self.tip_cap_spacing_s = tip_cap_spacing_s or (TIP_CAP_SPACING_S if chain == "main" else None)
        self.sync_deadline = float(sync_deadline or SYNC_DEADLINE_TIMEOUTS * float(timeout))
        self.call_deadline = float(call_deadline or CALL_DEADLINE_TIMEOUTS * float(timeout))
        self._tl = threading.local()             # the call this thread is answering (_call)
        self.conns = [connection(u, timeout=timeout, on_notify=self._on_notify, on_drop=self._flag) for u in servers]
        self.min_servers = max(1, min(len(self.conns), int(min_servers if min_servers is not None
                                                           else (2 if chain == "main" else 1))))
        self.sync_interval = float(sync_interval)
        self._sync_gate = threading.Lock()       # the one sync in flight; never held by a caller that only reads
        self._flag_lock = threading.Lock()
        self._last_sync = 0.0
        self._round = 0                          # sync rounds started (only under _sync_gate)
        self._tip_round: dict[str, int] = {}     # server url -> the round in which it last reported its tip
        self._tip_dirty = True
        self._changed = threading.Event()
        self._watched: set[str] = set()
        self._cache_lock = threading.Lock()
        self._tx: dict[str, Tx] = {}             # verified transactions, oldest first (_remember)
        self._tx_size: dict[str, int] = {}
        self._tx_bytes = 0
        self._conf: dict[str, tuple[int, str]] = {}   # proven confirmations of transactions in _tx
        self.server_state: dict[str, dict] = {c.url: {} for c in self.conns}
        self.flags: list[dict] = []

    # --- plumbing ------------------------------------------------------------------------------------
    def _flag(self, conn, reason: str) -> None:
        """A server answered something that failed verification (or failed to answer)."""
        with self._flag_lock:
            st = self.server_state.setdefault(conn.url, {})
            st["last_error"] = str(reason)[:200]
            st["errors"] = int(st.get("errors") or 0) + 1
            self.flags = (self.flags + [{"server": conn.url, "reason": str(reason)[:200], "t": round(time.time(), 3)}])[-50:]

    @staticmethod
    def _each(conns: list, fn) -> list:
        """fn(conn) for every connection, in parallel; each result or the exception it raised."""
        def run(c):
            try:
                return fn(c)
            except Exception as e:     # noqa: BLE001 - handed back to the caller, per server
                return e
        if len(conns) <= 1:
            return [run(c) for c in conns]
        with ThreadPoolExecutor(max_workers=len(conns)) as ex:
            return list(ex.map(run, conns))

    def _call(self) -> _Call:
        """The budget of the call this thread is answering (`_budget` sets it; a helper used with
        none set gets one of its own, for that one step)."""
        cur = getattr(self._tl, "call", None)
        return cur if cur is not None else _Call(time.monotonic() + self.call_deadline)

    @contextmanager
    def _budget(self):
        """One call's budget for everything this thread does inside the block.

        The rule (AGP-097): **every entry into the backend that makes requests runs under one
        budget**: one deadline for all its requests, one forced header sync, one try at a server
        that is down. `call` set it; `proven_spend`, which the refund's evidence calls directly,
        did not, so each of its steps had a deadline of its own and each height a server claimed
        forced a sync of its own. Entered inside another budget it is that budget."""
        outer = getattr(self._tl, "call", None)
        if outer is None:
            self._tl.call = _Call(time.monotonic() + self.call_deadline)
        try:
            yield self._tl.call
        finally:
            self._tl.call = outer

    def _all_answer(self, answered: int) -> bool:
        """Did every configured server answer? Only then is "none of them shows it" an answer. A server
        that is down has not said so, whether it was down before the call or dropped in the middle of
        it: with it left out, one lying server and one failing honest one would read as "not there".
        (`min_servers` is the floor for what is proven.)"""
        return answered == len(self.conns)

    def _live(self, call: _Call | None = None) -> list:
        """The connected servers, after one try per call to connect those that are down."""
        call = call or self._call()

        def up(c):
            c.connect(call.left(c))
            self.server_state[c.url].update(proto=c.proto, server=c.server_id)
            for sh in list(self._watched):
                c.subscribe("blockchain.scripthash.subscribe", sh, timeout=call.left(c))
        # a call whose time is over reaches for nobody: a server that is down would only be
        # flagged for a connect it was given no time for
        down = [] if call.over else [c for c in self.conns if not c.connected and c.url not in call.gone]
        for c, r in zip(down, self._each(down, up)):
            if isinstance(r, Exception):
                self._flag(c, f"unreachable: {r}")
                call.gone.add(c.url)
        live = [c for c in self.conns if c.connected]
        if len(live) < self.min_servers:
            raise ElectrumError(f"{len(live)} of {len(self.conns)} Electrum servers reachable; "
                                f"at least {self.min_servers} needed")
        return live

    def _ask(self, conn, method, *params, timeout: float | None = None):
        try:
            return conn.request(method, *params, timeout=timeout)
        except ElectrumError as e:
            self._flag(conn, f"{method}: {e}")
            raise

    def _ask_by(self, call: _Call, conn, method, *params):
        """`_ask` inside a call's deadline: a request the deadline cuts short (`Late`) is not the
        server's doing and is not flagged."""
        try:
            return conn.request_by(call.deadline, method, *params)
        except Late:
            raise
        except ElectrumError as e:
            self._flag(conn, f"{method}: {e}")
            raise

    def _on_notify(self, conn, method: str, params) -> None:
        if method == "blockchain.headers.subscribe":
            self._tip_dirty = True
        self._changed.set()

    # --- headers -------------------------------------------------------------------------------------
    def sync(self, force: bool = False) -> int:
        """Bring the header chain up to the most-work tip any live server shows; returns our tip. With a
        verified chain, a call that finds another sync in flight answers from the chain as it is."""
        self._sync_round(force)
        return self._believable()

    def _sync_round(self, force: bool = False) -> int:
        """`sync` without the answer: the number of the round this call ran, 0 when none was due or
        another sync was in flight (then nothing was run, and the chain is as it was)."""
        ran = 0
        if force or self._tip_dirty or time.time() - self._last_sync >= self.sync_interval or not self.headers.ready:
            if self._sync_gate.acquire(blocking=not self.headers.ready):
                try:
                    ran = self._sync_now()
                finally:
                    self._sync_gate.release()
        return ran

    def _sync_now(self) -> int:
        """One sync round; returns its number."""
        self._tip_dirty = False
        self._round += 1
        this = self._round
        live = self._live(_Call(time.monotonic() + self.sync_deadline))
        off_chain = []
        for c, r in zip(live, self._each(live, lambda c: self._sync_from(c, this))):
            if isinstance(r, _OffCheckpoint):
                off_chain.append(f"{c.url}: {r}")
                self._flag(c, f"headers: {r}")
            elif isinstance(r, Exception):
                self._flag(c, f"headers: {r}")
        self._last_sync = time.time()
        for c in self.conns:
            st = self.server_state.get(c.url) or {}
            if st.get("tip_hash") and self.headers.ready:
                mine = self.headers.at(int(st.get("tip") or 0))
                st["on_best_chain"] = bool(mine and mine.hash == st["tip_hash"])
        if not self.headers.ready and off_chain:
            raise CheckpointMismatch(f"no server is on the {self.chain} checkpoint "
                                     f"{self.headers.cp_height}:{self.headers.cp_hash[:16]}.. ({'; '.join(off_chain)[:300]})")
        return this

    def _implausible(self) -> str | None:
        p = self.plausibility
        return self.headers.implausible(p.min_work_above, (p.floor_spacing_s, p.floor_slack)) if p else None

    def _believable(self) -> int:
        """Our tip, if the chain can be answered from."""
        if not self.headers.ready:
            raise ElectrumError("no Electrum server served the pinned checkpoint")
        why = self._implausible()
        if why:
            raise ImplausibleChain(f"the verified chain is not believable yet: {why}")
        return self.headers.tip_height

    def _header(self, conn, height: int, timeout: float | None = None) -> bytes:
        return bytes.fromhex(self._ask(conn, "blockchain.block.header", int(height), timeout=timeout))

    def _fetch_checkpoint(self, conn, left) -> None:
        """The checkpoint header and the headers below it that the median-time rule needs."""
        cp, n = self.headers.cp_height, self.headers.prior_needed
        try:
            raw = self._header(conn, cp, left())
            prior = []
            if n:
                r = self._ask(conn, "blockchain.block.headers", cp - n, n, timeout=left())
                prior = split_headers(bytes.fromhex(r.get("hex") or ""))
            self.headers.set_checkpoint(raw, prior)
        except (HeaderError, ElectrumError, ValueError, AttributeError) as e:
            raise _OffCheckpoint(str(e)) from e

    def _sync_from(self, conn, round_no: int = 0) -> None:
        """One server's part of a sync round. It ends at `sync_deadline`, and at the first answer
        with fewer headers than asked for below the tip the server claims; either way the headers
        proven by then are adopted and the server is flagged (by the caller, from what is raised)."""
        deadline = time.monotonic() + self.sync_deadline

        def left() -> float:
            """The wait for the next request: the request timeout, or less when the deadline is nearer."""
            t = deadline - time.monotonic()
            if t <= 0:
                raise ElectrumError("sync deadline")
            return min(conn.timeout, t)

        try:
            tip = conn.subscribe("blockchain.headers.subscribe", timeout=left())
        except ServerError:
            # A server that refuses its tip is of no use on this connection, and the refusal can be the
            # connection's: electrs negotiates protocol 1.4 until it has indexed a v2 header and then
            # refuses headers to that client for good. Hang up; the next round negotiates again.
            conn.close()
            raise
        th = int(tip["height"])
        tip_h = parse_header(bytes.fromhex(tip["hex"]))
        self.server_state[conn.url].update(tip=th, tip_hash=tip_h.hash)
        self._tip_round[conn.url] = round_no
        cp = self.headers.cp_height
        if th < cp:
            raise _OffCheckpoint(f"server tip {th} is below the checkpoint {cp}")
        if tip_h.height != th:
            raise HeaderError(f"tip at {th} commits height {tip_h.height}")
        try:
            check_pow(tip_h, self.headers.rules)
        except HeaderError as e:                     # before we hold a chain: another chain's PoW
            raise (HeaderError if self.headers.ready else _OffCheckpoint)(f"tip at {th}: {e}") from e
        if not self.headers.ready:
            self._fetch_checkpoint(conn, left)
        ours, our_time = self.headers.tip_height, self.headers.tip().time
        mine = self.headers.at(th)
        if mine is not None and mine.hash == tip_h.hash:
            return                                   # its tip is on our chain already
        cap = th
        if self.tip_cap_spacing_s:
            cap = ours + max(0, int(self.clock()) - our_time) // self.tip_cap_spacing_s + HEADERS_CHUNK
        end = min(th, cap)
        if th > cap:
            self._flag(conn, f"headers: claims tip {th}, beyond the plausible {cap}: nothing above it is fetched")
        # the highest height where the server agrees with us (the checkpoint at worst)
        h, step = min(end, ours), 1
        while h > cp:
            theirs = parse_header(self._header(conn, h, left()))
            m = self.headers.at(h)
            if m is not None and theirs.hash == m.hash:
                break
            h, step = max(cp, h - step), step * 2
        b = self.headers.branch(h)
        start, bad, failed = h + 1, None, None
        while start <= end:
            want = min(HEADERS_CHUNK, end - start + 1)
            try:
                r = self._ask(conn, "blockchain.block.headers", start, want, timeout=left())
                chunk = split_headers(bytes.fromhex(r.get("hex") or ""))[:want]
            except (ElectrumError, ValueError, AttributeError, TypeError) as e:
                failed = e                           # no answer, or not one: the branch so far is still adopted
                break
            before = len(b)
            try:
                b.extend(chunk)
            except HeaderError as e:
                bad = e
            start += len(b) - before
            if bad or len(chunk) < want:
                break                                # short of what was asked, below its own tip: withheld
        if len(b):
            self.headers.adopt(b)
        if bad:
            raise HeaderError(f"block.headers: {bad} (the headers before it were kept)")
        if failed is not None:
            if time.monotonic() >= deadline:
                raise ElectrumError(f"sync deadline: served up to {start - 1}, claims tip {th}") from failed
            raise failed
        if start <= end:
            raise ElectrumError(f"withheld headers: served up to {start - 1}, claims tip {th}")

    # --- verified transactions -----------------------------------------------------------------------
    @staticmethod
    def _verify_raw(txid: str, raw) -> Tx | None:
        """A raw tx counts only if it re-serializes byte for byte and hashes to the txid asked for."""
        try:
            tx = Tx.parse(bytes.fromhex(raw))
            return tx if tx.hex() == str(raw).lower() and tx.txid() == txid else None
        except Exception:
            return None

    def _fetch_tx(self, txid: str) -> Tx | None:
        """The transaction, from the cache or the first server that supplies it (all are asked at
        once). None only when every server asked said it has no such transaction; if one did not
        answer, whether it exists is not known and Unknown is raised."""
        txid = txid.lower()
        cached = self._tx.get(txid)
        if cached is not None:
            return cached
        call = self._call()
        live = self._live(call)

        def get(c):
            return c.request_by(call.deadline, "blockchain.transaction.get", txid)

        silent = []
        ex = ThreadPoolExecutor(max_workers=len(live))
        try:
            asked = {ex.submit(get, c): c for c in live}
            for f in as_completed(asked):
                c = asked[f]
                try:
                    raw = f.result()
                except Exception as e:       # noqa: BLE001 - judged per server just below
                    if not says_not_there(e):
                        if not isinstance(e, Late):      # the call ran out of time: not its doing
                            self._flag(c, f"transaction.get: {e}")
                        silent.append(c.url)
                    continue
                tx = self._verify_raw(txid, raw)
                if tx is None:               # a lie is an answer: this server does not supply it
                    self._flag(c, f"transaction.get {txid[:16]}: not the transaction asked for")
                    continue
                self._remember(txid, tx, len(raw) // 2)
                return tx
        finally:
            ex.shutdown(wait=False)          # a slower server's answer is not waited for
        silent += [c.url for c in self.conns if c not in live]
        if silent:
            raise Unknown(f"whether transaction {txid[:16]}.. exists is not known: no answer from {', '.join(silent)}")
        return None

    def _remember(self, txid: str, tx: Tx, size: int) -> None:
        """Cache a verified transaction of `size` raw bytes. Above TX_CACHE_BYTES the oldest leave,
        each with its cached confirmation: one that is asked for again is fetched and proven again."""
        with self._cache_lock:
            if txid in self._tx:
                return
            self._tx[txid], self._tx_size[txid] = tx, size
            self._tx_bytes += size
            while self._tx_bytes > TX_CACHE_BYTES and self._tx:
                old = next(iter(self._tx))
                del self._tx[old]
                self._tx_bytes -= self._tx_size.pop(old)
                self._conf.pop(old, None)

    def _listing(self, conn, method: str, sh: str, call: _Call) -> list | None:
        """One server's get_history or listunspent answer for a script, or None when it has none we
        can use: no answer, or more than MAX_HISTORY entries (flagged)."""
        try:
            rows = self._ask_by(call, conn, method, sh) or []
        except ElectrumError:
            return None
        name = method.rsplit(".", 1)[-1]
        if not isinstance(rows, list):
            self._flag(conn, f"{name}: not a list")
            return None
        if len(rows) > MAX_HISTORY:
            self._flag(conn, f"{name}: {len(rows)} entries, above the {MAX_HISTORY} allowed: the answer is not used")
            return None
        return rows

    def _listings(self, method: str, sh: str) -> tuple[list, bool]:
        """[(conn, rows)] for every live server whose answer can be used, asked in parallel, and
        whether that is all of them. With no such answer it raises: an empty list means the servers
        say there is nothing."""
        call = self._call()
        live = self._live(call)
        got = [(c, r) for c, r in zip(live, self._each(live, lambda c: self._listing(c, method, sh, call)))
               if isinstance(r, list)]
        if not got:
            raise Unknown(f"no server answered {method.rsplit('.', 1)[-1]} for the script")
        return got, self._all_answer(len(got))

    def _history(self, spk: bytes) -> _Hist:
        """The union of the servers' histories of a script, one claim per server and transaction."""
        got, complete = self._listings("blockchain.scripthash.get_history", scripthash(spk))
        out = _Hist()
        out.complete = complete
        for c, hist in got:
            two_heights = False
            for e in hist:
                try:
                    txid, height = str(e["tx_hash"]).lower(), int(e["height"])
                except (KeyError, TypeError, ValueError):
                    self._flag(c, "get_history: malformed entry")
                    continue
                claims = out.setdefault(txid, [])
                # One claim per server and transaction. An honest server can list one twice (in its
                # mempool and in a block, as a block arrives: electrs does), so a block height replaces
                # a mempool entry and a repeat is dropped. A second block height is not a claim: each
                # one used to cost a proof request, and a header sync when above our tip.
                at = next((n for n, (k, _) in enumerate(claims) if k is c), None)
                if at is None:
                    claims.append((c, height))
                elif claims[at][1] <= 0 < height:
                    claims[at] = (c, height)
                elif height > 0 and claims[at][1] != height:
                    two_heights = True
            if two_heights:
                self._flag(c, "get_history lists a transaction at two heights: only the first is used")
        return out

    def _invented(self, tx: Tx, spk: bytes, listed: dict) -> bool | None:
        """Can `tx` not belong to the history of `spk` at all? It pays the script, or spends an output
        that does, and then the paying transaction is in the history too. None: a possible funder is
        listed and not held, so it cannot be told yet."""
        if any(o.script_pubkey == spk for o in tx.outputs):
            return False
        unheld = False
        for i in tx.inputs:
            prev = i.txid[::-1].hex()
            if prev not in listed:
                continue
            funder = self._tx.get(prev)
            if funder is None:
                unheld = True
            elif i.vout < len(funder.outputs) and funder.outputs[i.vout].script_pubkey == spk:
                return False
        return None if unheld else True

    def _supply(self, listed: dict, spk: bytes | None = None) -> set:
        """Fetch the transactions of `listed` that are not held, each from the servers that listed
        it, every server in parallel. A server's part ends at the first transaction it does not
        supply, at the first that cannot belong to `spk` (when given), and at the call's deadline;
        each ends with a flag. Returns the urls that went silent: what only they listed is not known.

        Why from the server that listed it: a transaction no server can supply used to be asked of
        every server, on every call, one timeout each (AGP-087: 41 hours for one gettxout)."""
        call = self._call()
        work: dict = {}
        for txid in sorted(listed):
            if txid not in self._tx:
                for c, _ in listed[txid]:
                    work.setdefault(c, []).append(txid)

        def part(c) -> bool:
            """True when the server went silent."""
            todo = work[c]
            # Was this server asked for anything in this part? Only then is running into the
            # call's deadline flagged (a list too long, or supplied too slowly). A server whose
            # part began when the time was already used up was never asked (AGP-097).
            asked = False

            def late(n: int) -> bool:
                if asked:
                    self._flag(c, f"transaction.get: {len(todo) - n} of the transactions it listed were not "
                                  f"supplied by the call deadline ({self.call_deadline:g} s)")
                return True

            for n, txid in enumerate(todo):
                if txid in self._tx:
                    continue
                if call.over:
                    return late(n)
                asked = True
                try:
                    raw = c.request_by(call.deadline, "blockchain.transaction.get", txid)
                except ServerError:
                    raw = None
                except Late:
                    return late(n)
                except ElectrumError as e:
                    self._flag(c, f"transaction.get: {e}")
                    return True
                tx = self._verify_raw(txid, raw) if isinstance(raw, str) and len(raw) <= 2 * MAX_TX_BYTES else None
                if tx is None:
                    self._flag(c, f"lists a transaction it does not supply ({txid[:16]}..): the rest of its list is not asked for")
                    return False
                if spk is not None and self._invented(tx, spk, listed) is True:
                    # the rest of its list is not asked for; the reason is worded as _flag_invented words it
                    self._flag(c, "get_history lists a transaction that neither pays nor spends the script")
                    return False
                self._remember(txid, tx, len(raw) // 2)
            return False

        conns = list(work)
        return {c.url for c, silent in zip(conns, self._each(conns, part)) if silent is True or isinstance(silent, Exception)}

    def _flag_invented(self, spk: bytes, hist: dict) -> None:
        """Flag every server that listed an entry which, from the transactions we hold, neither pays
        `spk` nor spends an output of this history that pays it (AGP-081)."""
        liars = {}
        for txid, claims in hist.items():
            tx = self._tx.get(txid)
            if tx is not None and self._invented(tx, spk, hist) is True:
                liars.update({c.url: c for c, _ in claims})
        for c in liars.values():
            self._flag(c, "get_history lists a transaction that neither pays nor spends the script")

    @staticmethod
    def _proves(txid: str, hdr, height: int, m) -> str:
        """Does the server's get_merkle answer tie the transaction to our header at `height`? ""
        when it does, else why not."""
        try:
            root = merkle_root_from_proof(txid, list(m["merkle"]), int(m["pos"]), hdr.txcount)
            at = int(m.get("block_height", height))
        except (HeaderError, KeyError, TypeError, ValueError, AttributeError) as e:
            return str(e) or type(e).__name__
        return "" if root == hdr.merkle_root and at == height else "proof does not reach our header"

    def _prove_ahead(self, items: list) -> None:
        """Ask every server, in one write each and all servers at once, for the proofs of the claims
        it made about `items` ([(txid, claims)]) at heights we hold a header for, and keep those
        that hold. Nothing is judged here: a claim this leaves unproven is asked for again, judged
        and flagged by `_confirmed`, one request at a time.

        Why (AGP-097): a scan proved its coins one request after another, each from the first
        server that claimed it. With N coins that is N round trips to one server inside one call
        deadline, so a server that answers every request well inside the timeout still used the
        deadline up, and the scan of an address with many coins failed."""
        call = self._call()
        work: dict = {}
        for txid, claims in items:
            if txid in self._conf:
                continue
            for c, height in claims:
                hdr = self.headers.at(height) if height > 0 else None
                if hdr is not None:
                    work.setdefault(c, []).append((txid, height, hdr))

        def part(c) -> None:
            todo = work[c]
            for at in range(0, len(todo), TX_BATCH):
                # proven by another server meanwhile: not asked for again
                want = [w for w in todo[at:at + TX_BATCH] if w[0] not in self._conf]
                if not want or call.over:
                    continue
                answers = c.batch_by(call.deadline, [("blockchain.transaction.get_merkle", (t, h)) for t, h, _ in want])
                for (txid, height, hdr), m in zip(want, answers):
                    if isinstance(m, Exception) or self._proves(txid, hdr, height, m):
                        continue
                    with self._cache_lock:
                        # kept only with its transaction, and while its block is on our chain
                        mine = self.headers.at(height)
                        if txid in self._tx and mine is not None and mine.hash == hdr.hash:
                            self._conf[txid] = (height, hdr.hash)

        conns = list(work)
        self._each(conns, part)

    def _confirmed(self, txid: str, claims: list) -> tuple:
        """(status, checked). status: (height, blockhash) once a Merkle proof ties txid to our header
        at a claimed height; 0 if only mempool claims remain; None if no claim holds. `checked` is
        False when a claim could not be judged: its server did not answer for it, or it names a block
        we do not hold after the call's one forced sync. Then "not confirmed" is not known."""
        cached = self._conf.get(txid)
        if cached:
            h = self.headers.at(cached[0])
            if h is not None and h.hash == cached[1]:
                return cached, True
            self._conf.pop(txid, None)                  # reorged out: prove it again
        call = self._call()
        mempool, checked = False, True
        for c, height in claims:
            if height <= 0:
                mempool = True
                continue
            hdr = self.headers.at(height)
            if hdr is None and not call.synced:
                call.synced = True
                call.round = self._sync_round(force=True)
                self._believable()
                hdr = self.headers.at(height)
            if hdr is None:
                # The rule (AGP-097): a claim is a lie only against a tip the server reported after
                # it made the claim. That is a tip it reported in the round this call forced, or in
                # a later one. When the forced sync found another in flight and ran nothing, or the
                # server did not report its tip in our round, the tip we hold for it is older than
                # its claim: a block may have come in between (both servers then list it,
                # truthfully). That is "not known", never "above the tip it reports". Before, the
                # old tip was used, the claim was called a lie and the lookup answered "not there".
                fresh = call.round and self._tip_round.get(c.url, 0) >= call.round
                own_tip = (self.server_state.get(c.url) or {}).get("tip") if fresh else None
                # above the tip it then reported it is a lie; at or below, a block we could not
                # fetch: not known
                if own_tip is not None and height > int(own_tip):
                    self._flag(c, f"get_history: {txid[:16]}.. at height {height}, above the tip it reports")
                else:
                    checked = False
                continue
            try:
                m = self._ask_by(call, c, "blockchain.transaction.get_merkle", txid, height)
            except ElectrumError as e:
                # "not in that block", in its own words, withdraws its claim (flagged by _ask_by);
                # busy, gone, silent or cut short by the call's deadline leaves the claim unjudged
                checked = checked and says_not_there(e)
                continue
            why = self._proves(txid, hdr, height, m)
            if why:
                self._flag(c, f"get_merkle {txid[:16]}@{height}: {why}")
                continue
            with self._cache_lock:
                if txid in self._tx:                    # evicted meanwhile: proven, but not kept
                    self._conf[txid] = (height, hdr.hash)
            return (height, hdr.hash), True
        return (0 if mempool else None), checked

    def _locate(self, txid: str) -> tuple:
        """(tx, status, complete). status: (height, blockhash), 0 (mempool), or None (no claim holds).
        `complete` is False when a server did not answer on the way and the status is short of
        confirmed: then it is not known, and a caller that would answer "not there" raises instead."""
        txid = txid.lower()
        tx = self._fetch_tx(txid)
        if tx is None:
            return None, None, True
        cached = self._conf.get(txid)
        if cached and (h := self.headers.at(cached[0])) is not None and h.hash == cached[1]:
            return tx, cached, True
        complete = True
        for spk in self._index_spks(tx):
            hist = self._history(spk)
            complete = complete and hist.complete
            claims = hist.get(txid)
            if claims:
                st, checked = self._confirmed(txid, claims)
                return tx, st, isinstance(st, tuple) or (complete and checked)
        return tx, None, complete

    @staticmethod
    def _index_spks(tx: Tx) -> list[bytes]:
        """Scripts whose history lists this tx: its outputs (OP_RETURN has no history)."""
        spks = [o.script_pubkey for o in tx.outputs if o.script_pubkey and o.script_pubkey[0] != 0x6A]
        return spks[:2]

    def _spends(self, spk: bytes) -> _Hist:
        """The union of the servers' histories of `spk`, with the transactions it lists fetched and
        the invented ones flagged: what the search for a spend reads. One round of requests for a
        script, however many of its outputs are then looked at."""
        hist = self._history(spk)
        self._supply(hist, spk)
        self._flag_invented(spk, hist)
        return hist

    def _spender(self, hist: dict, txid: str, vout: int, *, mempool: bool) -> tuple[str, int] | None:
        """(spending txid, height or 0) from the union of the script's histories (`_spends`). A
        confirmed spend comes before a mempool one, which is returned only with `mempool`.

        This search does not wait for every server: a spend that only a silent server lists, or whose
        proof went unanswered, is not reported. Were it an error, one server could hold a refund back
        by listing a spend and never proving it; the answer "unspent" can only be acted on by a
        broadcast, which the network refuses if it is wrong."""
        unconfirmed = None
        for t in sorted(hist):
            stx = self._tx.get(t)
            if t == txid or stx is None:                 # not supplied: its server is flagged
                continue
            if not any(i.txid[::-1].hex() == txid and i.vout == int(vout) for i in stx.inputs):
                continue
            st, _ = self._confirmed(t, hist[t])
            if isinstance(st, tuple):
                return t, st[0]
            if st == 0 and mempool:
                unconfirmed = (t, 0)
        return unconfirmed

    def proven_spend(self, txid: str, vout: int, spk: bytes | str | None = None) -> tuple[str, int] | None:
        """(spending txid, its height) of a confirmed spend of the outpoint, proven by a Merkle proof
        into our header chain; None when no server shows one. This, and not an empty gettxout, is the
        evidence a close is booked on (AGP-092): gettxout is also empty when every server hides the
        funding. `spk` is the outpoint's script, so the question can be asked while the funding
        transaction itself is hidden; without it the transaction is fetched for it (Unknown if no
        server supplies it)."""
        self.sync()                         # the header sync has its own deadline; the call's starts after it
        txid, vout = str(txid).lower(), int(vout)
        with self._budget():                # as `call` does (AGP-097): it is called on its own
            if spk is None:
                tx = self._fetch_tx(txid)
                if tx is None or not 0 <= vout < len(tx.outputs):
                    raise Unknown(f"no server shows transaction {txid[:16]}..: whether its output is spent is not known")
                spk = tx.outputs[vout].script_pubkey
            hist = self._spends(bytes.fromhex(spk) if isinstance(spk, str) else bytes(spk))
            return self._spender(hist, txid, vout, mempool=False)

    def _address(self, spk: bytes) -> str | None:
        if len(spk) in (22, 34) and spk[0] in (0x00, 0x51) and spk[1] == len(spk) - 2:
            try:
                return segwit_address(self.hrp, spk)
            except Exception:
                return None
        return None

    def _spk_json(self, spk: bytes) -> dict:
        d = {"hex": spk.hex()}
        a = self._address(spk)
        if a:
            d["address"] = a
        return d

    def _verbose(self, tx: Tx, st) -> dict:
        coinbase = len(tx.inputs) == 1 and tx.inputs[0].txid == bytes(32) and tx.inputs[0].vout == 0xFFFF_FFFF
        d = {
            "txid": tx.txid(),
            "hex": tx.hex(),
            "vin": [{"coinbase": i.script_sig.hex()} if coinbase else {"txid": i.txid[::-1].hex(), "vout": i.vout}
                    for i in tx.inputs],
            "vout": [{"n": n, "value": o.value / XBT_SATS, "scriptPubKey": self._spk_json(o.script_pubkey)}
                     for n, o in enumerate(tx.outputs)],
        }
        if isinstance(st, tuple):
            d.update(blockhash=st[1], height=st[0], confirmations=self.headers.tip_height - st[0] + 1)
        else:
            d["confirmations"] = 0
        return d

    # --- the RPC surface -------------------------------------------------------------------------------
    def call(self, method: str, *params):
        m = method.lower()
        if m in NODE_ONLY:
            raise LightBackendError(f"{method} needs a full node: not available on the light Electrum backend")
        fn = getattr(self, f"_rpc_{m}", None)
        if fn is None:
            raise LightBackendError(f"{method} is not served by the light Electrum backend")
        if m in ("gettxout", "gettxspendingprevout", "getrawtransaction", "scantxoutset"):
            self.sync()                     # the header sync has its own deadline; the call's starts after it
        with self._budget():
            return fn(*params)

    def _rpc_getblockchaininfo(self):
        tip = self.sync()
        return {"chain": self.chain, "blocks": tip, "headers": tip, "bestblockhash": self.headers.tip().hash,
                "initialblockdownload": False, "pruned": True, "light": True, "backend": self.backend}

    def _rpc_getblockcount(self):
        return self.sync()

    def _rpc_getblockhash(self, height):
        self.sync()
        h = self.headers.at(int(height))
        if h is None:
            raise ElectrumError(f"Block height {height} out of range (verified chain {self.headers.cp_height}.."
                                f"{self.headers.tip_height})")
        return h.hash

    def _rpc_getblockheader(self, block_hash, verbose=True):
        self.sync()
        height = self.headers.height_of(str(block_hash).lower())
        if height is None:
            raise ElectrumError("Block not found")
        h = self.headers.at(height)
        if not verbose:
            return h.raw.hex()
        prev = self.headers.at(height - 1)
        return {"hash": h.hash, "height": height, "confirmations": self.headers.tip_height - height + 1,
                "time": h.time, "bits": f"{h.bits:08x}", "nTx": h.txcount,
                "merkleroot": h.merkle_root[::-1].hex(), **({"previousblockhash": prev.hash} if prev else {})}

    def _rpc_gettxout(self, txid, vout, include_mempool=True):
        """None means one of: a confirmed spend is proven; the transaction has no such output; every
        server asked says there is no such transaction, or none lists it; it is unconfirmed and
        `include_mempool` is off. When a server did not answer, the last three are not known and the
        call raises instead (AGP-092: None used to cover "nobody answered", which callers read as
        spent)."""
        self.sync()
        tx, st, complete = self._locate(str(txid))
        if tx is None or int(vout) >= len(tx.outputs) or int(vout) < 0:
            return None
        if st is None or (st == 0 and not include_mempool):
            if not complete:
                raise Unknown(f"whether a block holds transaction {str(txid)[:16]}.. is not known: a server "
                              "did not answer for it (see verification_failures)")
            return None
        out = tx.outputs[int(vout)]
        if self._spender(self._spends(out.script_pubkey), str(txid).lower(), int(vout), mempool=False):
            return None                      # proven spent (a mempool-only spend is not proof: see docstring)
        height = st[0] if isinstance(st, tuple) else 0
        tip = self.headers.tip()
        coinbase = len(tx.inputs) == 1 and tx.inputs[0].txid == bytes(32)
        return {"bestblock": tip.hash, "confirmations": (self.headers.tip_height - height + 1) if height else 0,
                "value": out.value / XBT_SATS, "scriptPubKey": self._spk_json(out.script_pubkey), "coinbase": coinbase}

    def _rpc_gettxspendingprevout(self, outpoints):
        self.sync()
        res = []
        for op in outpoints or []:
            txid, vout = str(op["txid"]).lower(), int(op["vout"])
            row = {"txid": txid, "vout": vout}
            tx = self._fetch_tx(txid)
            if tx is not None and vout < len(tx.outputs):
                sp = self._spender(self._spends(tx.outputs[vout].script_pubkey), txid, vout, mempool=True)
                if sp:
                    row["spendingtxid"] = sp[0]
            res.append(row)
        return res

    def _rpc_getrawtransaction(self, txid, verbose=False, blockhash=None):
        self.sync()
        tx, st, complete = self._locate(str(txid))
        if tx is not None and st is None and not complete:
            raise Unknown(f"where transaction {str(txid)[:16]}.. is, is not known: a server did not answer for it")
        if tx is None or st is None:
            raise ElectrumError("No such mempool or blockchain transaction")
        if blockhash and not (isinstance(st, tuple) and st[1] == str(blockhash).lower()):
            raise ElectrumError("No such transaction found in the provided block")
        return self._verbose(tx, st) if verbose else tx.hex()

    def _rpc_sendrawtransaction(self, hex_tx, *_):
        try:
            tx = Tx.parse(bytes.fromhex(hex_tx))
        except Exception as e:
            raise ElectrumError(f"TX decode failed: {type(e).__name__}") from e
        txid, errors, accepted = tx.txid(), [], False
        call = self._call()
        for c in self._live(call):
            try:
                got = c.request_by(call.deadline, "blockchain.transaction.broadcast", hex_tx)
            except ElectrumError as e:
                errors.append(str(e))
                continue
            if str(got).lower() != txid:
                self._flag(c, "broadcast answered another txid")
                continue
            accepted = True
        if not accepted:            # every server refused it: the node's reason, as sendrawtransaction gives it
            raise ElectrumError(errors[0] if errors else "no server accepted the transaction")
        self._remember(txid, tx, len(hex_tx) // 2)
        return txid

    def _rpc_scantxoutset(self, action, descriptors=()):
        if action != "start":
            raise ElectrumError(f"scantxoutset {action}: only 'start'")
        self.sync()
        unspents, total, complete = [], 0, True
        for desc in descriptors:
            d = desc if isinstance(desc, str) else desc.get("desc", "")
            if not (d.startswith("raw(") and d.endswith(")")):
                raise ElectrumError(f"scantxoutset: the light backend takes raw(<script>) descriptors, not {d!r}")
            spk = bytes.fromhex(d[4:-1])
            got, every = self._listings("blockchain.scripthash.listunspent", scripthash(spk))
            complete = complete and every
            claims: dict[tuple, list] = {}
            for c, rows in got:
                for u in rows:
                    try:
                        cl = claims.setdefault((str(u["tx_hash"]).lower(), int(u["tx_pos"])), [])
                        if not any(k is c for k, _ in cl):
                            cl.append((c, int(u["height"])))
                    except (KeyError, TypeError, ValueError):
                        self._flag(c, "listunspent: malformed entry")
            listed: dict[str, list] = {}                 # who listed each transaction, for _supply
            for (txid, _), cl in claims.items():
                listed.setdefault(txid, []).extend(x for x in cl if not any(k is x[0] for k, _ in listed[txid]))
            silent = self._supply(listed)
            # The rule (AGP-097): what a scan asks a server for does not grow with the number of
            # coins beyond what each coin needs once. The call's deadline covers the whole scan,
            # and anyone can add coins to an address by paying it dust. So the coins' proofs are
            # asked for in one write per server (`_prove_ahead`), and the script's history, which
            # every coin's search for a spend reads, once for the scan (`_spends`). Before, every
            # server was asked for the whole history once per coin and the proofs came one request
            # at a time: with 20 coins, one honest server a third of the timeout late made every
            # scan fail.
            self._prove_ahead([(t, cl) for t, cl in sorted(listed.items()) if t in self._tx])
            hist = None                         # asked for once, when a coin needs it
            # A coin a server lists is left out only on an answer: the server does not supply its
            # transaction, the output does not pay the script, the claims were checked and none is a
            # proof, or a confirmed spend is proven. If the server went silent instead, the scan
            # raises: a shorter list would read as "no such coin" (AGP-092).
            for (txid, n), cl in sorted(claims.items(), key=lambda kv: kv[0]):
                tx = self._tx.get(txid)
                if tx is None:
                    if any(c.url in silent for c, _ in listed[txid]):
                        raise Unknown(f"whether the script holds a coin of transaction {txid[:16]}.. is not known: "
                                      "the server that listed it did not answer for it")
                    continue                    # every server that listed it was asked and did not supply it
                if not 0 <= n < len(tx.outputs) or tx.outputs[n].script_pubkey != spk:
                    for c in {c for c, _ in cl}:
                        self._flag(c, "listunspent lists an output that does not pay the script")
                    continue
                st, checked = self._confirmed(txid, cl)
                if not isinstance(st, tuple):   # the UTXO set holds confirmed coins only
                    if not checked:
                        raise Unknown(f"whether a block holds transaction {txid[:16]}.. is not known: a server "
                                      "did not answer for it")
                    continue
                if hist is None:
                    hist = self._spends(spk)
                if self._spender(hist, txid, n, mempool=False):
                    continue
                value = tx.outputs[n].value
                total += value
                coinbase = len(tx.inputs) == 1 and tx.inputs[0].txid == bytes(32) and tx.inputs[0].vout == 0xFFFF_FFFF
                unspents.append({"txid": txid, "vout": n, "scriptPubKey": spk.hex(), "desc": d,
                                 "amount": value / XBT_SATS, "coinbase": coinbase, "height": st[0], "blockhash": st[1]})
        # `complete`: every configured server answered the listing. Every coin listed is proven either
        # way; without it a coin that is not listed may be one only the missing server shows (AGP-092:
        # the shorter list is marked, since a scan that failed whenever one server was down would
        # leave the wallet without its coins).
        return {"success": True, "height": self.headers.tip_height, "bestblock": self.headers.tip().hash,
                "unspents": unspents, "total_amount": total / XBT_SATS, "complete": complete}

    def _rpc_estimatesmartfee(self, blocks=1, *_):
        call = self._call()
        for c in self._live(call):
            try:
                fee = float(self._ask_by(call, c, "blockchain.estimatefee", int(blocks)))
            except (ElectrumError, TypeError, ValueError):
                continue
            if fee > 0:
                return {"feerate": fee, "blocks": int(blocks), "source": "electrum (unverified)"}
            return {"errors": ["Insufficient data or no feerate found"], "blocks": int(blocks)}
        raise ElectrumError("no server answered estimatefee")

    # --- subscriptions (the watcher wakes on them) -----------------------------------------------------
    def watch(self, spks) -> int:
        """Subscribe every live server to these scripts: a change (a close, a refund, a funding
        confirming) wakes `wait_for_change`. Returns how many are watched."""
        new = [scripthash(bytes.fromhex(s) if isinstance(s, str) else s) for s in spks]
        new = [sh for sh in new if sh not in self._watched]
        if new:
            call = self._call()
            for c in self._live(call):
                for sh in new:
                    try:
                        c.subscribe("blockchain.scripthash.subscribe", sh, timeout=call.left(c))
                    except Late:
                        pass                    # no time left in this call (as before, minus the flag)
                    except ElectrumError as e:
                        self._flag(c, f"subscribe: {e}")
            self._watched.update(new)
        return len(self._watched)

    def wait_for_change(self, timeout: float) -> bool:
        """Block until a subscribed script or the tip changes, or `timeout`. True if something did."""
        fired = self._changed.wait(timeout)
        self._changed.clear()
        return fired

    def status(self) -> dict:
        tip = self.headers.tip_height if self.headers.ready else None
        tip_age = round(time.time() - self.headers.tip().time) if self.headers.ready else None
        return {"backend": self.backend, "chain": self.chain,
                "checkpoint": [self.headers.cp_height, self.headers.cp_hash], "tip": tip,
                "tip_hash": self.headers.tip().hash if self.headers.ready else None,
                # a tip hours old on mainnet means every server is behind, or withholding blocks
                "tip_age_s": tip_age, "tip_stale": bool(tip_age is not None and self.chain == "main"
                                                        and tip_age > STALE_TIP_S),
                # why every chain answer is withheld, or None
                "implausible": self._implausible() if self.headers.ready else "no verified headers yet",
                "min_servers": self.min_servers, "watched_scripts": len(self._watched),
                "servers": [{"url": c.url, "connected": c.connected, **(self.server_state.get(c.url) or {})}
                            for c in self.conns],
                "verification_failures": self.flags[-10:]}

    def close(self) -> None:
        for c in self.conns:
            c.close()


def checkpoint_from_env(value: str | None) -> tuple[int, str] | None:
    """B2_ELECTRUM_CHECKPOINT: "<height>:<blockhash>"."""
    if not value:
        return None
    h, _, bh = value.strip().partition(":")
    if not h.isdigit() or len(bh) != 64:
        raise ElectrumError("B2_ELECTRUM_CHECKPOINT must be <height>:<64-hex block hash>")
    return int(h), bh.lower()


def servers_from_env(value: str | None) -> list[str]:
    return [s.strip() for s in (value or "").split(",") if s.strip()]


__all__ = ["ElectrumBackend", "ElectrumConnection", "ElectrumError", "ServerError", "Unknown", "CheckpointMismatch",
           "LightBackendError",
           "ImplausibleChain", "Plausibility", "AnswerCap", "answer_cap", "is_loopback_host", "scripthash",
           "checkpoint_from_env", "servers_from_env"]
