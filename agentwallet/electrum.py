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
What a malicious server can still do: hide a transaction (a close, a funding) from us until another
server or a block shows it, delay a call that asks it by up to the request timeout per request
(a history of N entries is N transaction requests), lie about fee estimates, and learn which
scripts we watch. Hiding a close delays counting the change (AGP-022's retry keeps
asking) and makes the refund at expiry fail at broadcast; neither loses coins.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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
TX_CACHE_BYTES = 32 << 20          # raw bytes of verified transactions kept; the oldest leave first
SYNC_DEADLINE_TIMEOUTS = 4         # the default sync_deadline, in request timeouts
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


class _OffCheckpoint(HeaderError):
    pass


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

    def connect(self) -> None:
        with self._clock:
            if self._sock is not None:
                return
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.tls:
                ctx = ssl.create_default_context()
                raw = ctx.wrap_socket(raw, server_hostname=self.host)
            raw.settimeout(None)
            self._sock = raw
            self._reader = threading.Thread(target=self._read_loop, args=(raw,), name=f"electrum:{self.url}",
                                            daemon=True)
            self._reader.start()
        try:
            sid, proto = self.request("server.version", CLIENT_NAME, PROTOCOL)
            self.server_id, self.proto = str(sid), str(proto)
            for method, params in list(self._subs):
                self.request(method, *params)
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
        for slot in list(self._pending.values()):
            slot.msg = {"error": {"message": why}}
            slot.done.set()

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
            elif m.get("method") and self.on_notify:
                try:
                    self.on_notify(self, m["method"], m.get("params") or [])
                except Exception:
                    pass

    def request(self, method: str, *params, timeout: float | None = None):
        if self._sock is None:
            self.connect()
        rid = next(self._ids)
        slot = _Pending(answer_cap(method, params))
        self._pending[rid] = slot
        try:
            line = (json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": list(params)}) + "\n").encode()
            with self._wlock:
                s = self._sock
                if s is None:
                    raise ElectrumError(f"{self.url}: not connected")
                s.sendall(line)
            if not slot.done.wait(self.timeout if timeout is None else timeout):
                self.close()        # a server that stops answering is dropped; the next request reconnects
                raise ElectrumError(f"{self.url}: {method} timed out")
        except OSError as e:
            self.close()
            raise ElectrumError(f"{self.url}: {type(e).__name__}") from e
        finally:
            self._pending.pop(rid, None)
        msg = slot.msg or {}
        if msg.get("error"):
            err = msg["error"]
            raise ElectrumError(str(err.get("message") if isinstance(err, dict) else err)[:400])
        return msg.get("result")

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
                 sync_deadline: float | None = None):
        """`tip_cap_spacing_s`: a claimed tip is believed up to one block per this many seconds since our
        tip's time, plus HEADERS_CHUNK. None: TIP_CAP_SPACING_S on mainnet, no cap elsewhere (regtest
        mines blocks as fast as it is asked to).
        `sync_deadline`: seconds one server has for its part of a sync round (None: SYNC_DEADLINE_TIMEOUTS
        request timeouts). What it proved by then is kept."""
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
        self.conns = [connection(u, timeout=timeout, on_notify=self._on_notify, on_drop=self._flag) for u in servers]
        self.min_servers = max(1, min(len(self.conns), int(min_servers if min_servers is not None
                                                           else (2 if chain == "main" else 1))))
        self.sync_interval = float(sync_interval)
        self._sync_gate = threading.Lock()       # the one sync in flight; never held by a caller that only reads
        self._flag_lock = threading.Lock()
        self._last_sync = 0.0
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

    def _live(self) -> list:
        def up(c):
            c.connect()
            self.server_state[c.url].update(proto=c.proto, server=c.server_id)
            for sh in list(self._watched):
                c.subscribe("blockchain.scripthash.subscribe", sh)
        down = [c for c in self.conns if not c.connected]
        for c, r in zip(down, self._each(down, up)):
            if isinstance(r, Exception):
                self._flag(c, f"unreachable: {r}")
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

    def _on_notify(self, conn, method: str, params) -> None:
        if method == "blockchain.headers.subscribe":
            self._tip_dirty = True
        self._changed.set()

    # --- headers -------------------------------------------------------------------------------------
    def sync(self, force: bool = False) -> int:
        """Bring the header chain up to the most-work tip any live server shows; returns our tip. With a
        verified chain, a call that finds another sync in flight answers from the chain as it is."""
        if force or self._tip_dirty or time.time() - self._last_sync >= self.sync_interval or not self.headers.ready:
            if self._sync_gate.acquire(blocking=not self.headers.ready):
                try:
                    self._sync_now()
                finally:
                    self._sync_gate.release()
        return self._believable()

    def _sync_now(self) -> None:
        self._tip_dirty = False
        live = self._live()
        off_chain = []
        for c, r in zip(live, self._each(live, self._sync_from)):
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

    def _sync_from(self, conn) -> None:
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

        tip = conn.subscribe("blockchain.headers.subscribe", timeout=left())
        th = int(tip["height"])
        tip_h = parse_header(bytes.fromhex(tip["hex"]))
        self.server_state[conn.url].update(tip=th, tip_hash=tip_h.hash)
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
    def _fetch_tx(self, txid: str) -> Tx | None:
        txid = txid.lower()
        cached = self._tx.get(txid)
        if cached is not None:
            return cached
        for c in self._live():
            try:
                raw = c.request("blockchain.transaction.get", txid)   # "not found" is an answer, not a fault
            except ElectrumError:
                continue
            try:
                tx = Tx.parse(bytes.fromhex(raw))
                ok = tx.hex() == str(raw).lower() and tx.txid() == txid
            except Exception:
                ok = False
            if not ok:
                self._flag(c, f"transaction.get {txid[:16]}: not the transaction asked for")
                continue
            self._remember(txid, tx, len(raw) // 2)
            return tx
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

    def _listing(self, conn, method: str, sh: str) -> list | None:
        """One server's get_history or listunspent answer for a script, or None when it has none we
        can use: no answer, or more than MAX_HISTORY entries (flagged)."""
        try:
            rows = self._ask(conn, method, sh) or []
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

    def _history(self, spk: bytes) -> dict[str, list]:
        """txid -> [(conn, claimed height)], the union over every live server whose answer can be
        used. With no such answer it raises: an empty history means the servers say there is none."""
        sh = scripthash(spk)
        out: dict[str, list] = {}
        answered = 0
        for c in self._live():
            hist = self._listing(c, "blockchain.scripthash.get_history", sh)
            if hist is None:
                continue
            answered += 1
            for e in hist:
                try:
                    out.setdefault(str(e["tx_hash"]).lower(), []).append((c, int(e["height"])))
                except (KeyError, TypeError, ValueError):
                    self._flag(c, "get_history: malformed entry")
        if not answered:
            raise ElectrumError("no server answered get_history for the script")
        return out

    def _history_txs(self, spk: bytes, hist: dict[str, list]):
        """Yield (txid, Tx) for each transaction of a script's history that a server supplies, one
        at a time. Once all are seen, an entry that neither pays `spk` nor spends an output of this
        history that pays it was invented: every server that listed it is flagged. An entry whose
        prevout transaction is in the history but was not supplied is left alone (unknown)."""
        pays: dict[str, frozenset[int]] = {}             # txid -> its outputs that pay spk
        spends: dict[str, list[tuple[str, int]]] = {}    # txid -> its prevouts in this history, if it pays nothing
        for txid in hist:
            tx = self._fetch_tx(txid)
            if tx is None:
                continue
            pays[txid] = frozenset(n for n, o in enumerate(tx.outputs) if o.script_pubkey == spk)
            if not pays[txid]:
                spends[txid] = [(prev, i.vout) for i in tx.inputs if (prev := i.txid[::-1].hex()) in hist]
            yield txid, tx
        liars = set()
        for txid, prevouts in spends.items():
            if not any(prev not in pays or vout in pays[prev] for prev, vout in prevouts):
                liars.update(c for c, _ in hist[txid])
        for c in liars:
            self._flag(c, "get_history lists a transaction that neither pays nor spends the script")

    def _confirmed(self, txid: str, claims: list) -> tuple[int, str] | int | None:
        """(height, blockhash) once a Merkle proof ties txid to our header at a claimed height; 0 if
        only mempool claims remain; None if no claim holds."""
        cached = self._conf.get(txid)
        if cached:
            h = self.headers.at(cached[0])
            if h is not None and h.hash == cached[1]:
                return cached
            self._conf.pop(txid, None)                  # reorged out: prove it again
        tried = set()
        mempool = False
        for c, height in claims:
            if height <= 0:
                mempool = True
                continue
            if (c.url, height) in tried:
                continue
            tried.add((c.url, height))
            hdr = self.headers.at(height)
            if hdr is None:
                self.sync(force=True)
                hdr = self.headers.at(height)
                if hdr is None:
                    continue                            # a height beyond our best chain: not proven
            try:
                m = self._ask(c, "blockchain.transaction.get_merkle", txid, height)
                root = merkle_root_from_proof(txid, list(m["merkle"]), int(m["pos"]), hdr.txcount)
            except (ElectrumError, HeaderError, KeyError, TypeError, ValueError) as e:
                self._flag(c, f"get_merkle {txid[:16]}@{height}: {e}")
                continue
            if root != hdr.merkle_root or int(m.get("block_height", height)) != height:
                self._flag(c, f"get_merkle {txid[:16]}@{height}: proof does not reach our header")
                continue
            with self._cache_lock:
                if txid in self._tx:                    # evicted meanwhile: proven, but not kept
                    self._conf[txid] = (height, hdr.hash)
            return height, hdr.hash
        return 0 if mempool else None

    def _locate(self, txid: str) -> tuple[Tx | None, tuple[int, str] | int | None]:
        """The transaction and its status: (height, blockhash), 0 (mempool), or None (unknown)."""
        tx = self._fetch_tx(txid)
        if tx is None:
            return None, None
        cached = self._conf.get(txid.lower())
        if cached and (h := self.headers.at(cached[0])) is not None and h.hash == cached[1]:
            return tx, cached
        for spk in self._index_spks(tx):
            claims = self._history(spk).get(txid.lower())
            if claims:
                return tx, self._confirmed(txid.lower(), claims)
        return tx, None

    @staticmethod
    def _index_spks(tx: Tx) -> list[bytes]:
        """Scripts whose history lists this tx: its outputs (OP_RETURN has no history)."""
        spks = [o.script_pubkey for o in tx.outputs if o.script_pubkey and o.script_pubkey[0] != 0x6A]
        return spks[:2]

    def _spender(self, txid: str, vout: int, spk: bytes, *, mempool: bool) -> tuple[str, int] | None:
        """(spending txid, height or 0) from the union of the script's histories. A confirmed spend
        comes before a mempool one, which is returned only with `mempool`."""
        hist = self._history(spk)
        confirmed = unconfirmed = None
        for t, stx in self._history_txs(spk, hist):      # run to the end: it flags invented entries
            if t == txid or confirmed:
                continue
            if not any(i.txid[::-1].hex() == txid and i.vout == int(vout) for i in stx.inputs):
                continue
            st = self._confirmed(t, hist[t])
            if isinstance(st, tuple):
                confirmed = (t, st[0])
            elif st == 0 and mempool:
                unconfirmed = (t, 0)
        return confirmed or unconfirmed

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
        self.sync()
        tx, st = self._locate(str(txid))
        if tx is None or st is None or int(vout) >= len(tx.outputs) or int(vout) < 0:
            return None
        if st == 0 and not include_mempool:
            return None
        out = tx.outputs[int(vout)]
        if self._spender(str(txid).lower(), int(vout), out.script_pubkey, mempool=False):
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
                sp = self._spender(txid, vout, tx.outputs[vout].script_pubkey, mempool=True)
                if sp:
                    row["spendingtxid"] = sp[0]
            res.append(row)
        return res

    def _rpc_getrawtransaction(self, txid, verbose=False, blockhash=None):
        self.sync()
        tx, st = self._locate(str(txid))
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
        for c in self._live():
            try:
                got = c.request("blockchain.transaction.broadcast", hex_tx)
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
        unspents, total = [], 0
        for desc in descriptors:
            d = desc if isinstance(desc, str) else desc.get("desc", "")
            if not (d.startswith("raw(") and d.endswith(")")):
                raise ElectrumError(f"scantxoutset: the light backend takes raw(<script>) descriptors, not {d!r}")
            spk = bytes.fromhex(d[4:-1])
            claims: dict[tuple, list] = {}
            answered = 0
            for c in self._live():
                rows = self._listing(c, "blockchain.scripthash.listunspent", scripthash(spk))
                if rows is None:
                    continue
                answered += 1
                for u in rows:
                    try:
                        claims.setdefault((str(u["tx_hash"]).lower(), int(u["tx_pos"])), []).append((c, int(u["height"])))
                    except (KeyError, TypeError, ValueError):
                        self._flag(c, "listunspent: malformed entry")
            if not answered:                    # as _history: no answer is not "nothing unspent"
                raise ElectrumError("no server answered listunspent for the script")
            for (txid, n), cl in claims.items():
                tx = self._fetch_tx(txid)
                if tx is None:
                    continue
                if not 0 <= n < len(tx.outputs) or tx.outputs[n].script_pubkey != spk:
                    for c in {c for c, _ in cl}:
                        self._flag(c, "listunspent lists an output that does not pay the script")
                    continue
                st = self._confirmed(txid, cl)
                if not isinstance(st, tuple):   # the UTXO set holds confirmed coins only
                    continue
                if self._spender(txid, n, spk, mempool=False):
                    continue
                value = tx.outputs[n].value
                total += value
                coinbase = len(tx.inputs) == 1 and tx.inputs[0].txid == bytes(32) and tx.inputs[0].vout == 0xFFFF_FFFF
                unspents.append({"txid": txid, "vout": n, "scriptPubKey": spk.hex(), "desc": d,
                                 "amount": value / XBT_SATS, "coinbase": coinbase, "height": st[0], "blockhash": st[1]})
        return {"success": True, "height": self.headers.tip_height, "bestblock": self.headers.tip().hash,
                "unspents": unspents, "total_amount": total / XBT_SATS}

    def _rpc_estimatesmartfee(self, blocks=1, *_):
        for c in self._live():
            try:
                fee = float(self._ask(c, "blockchain.estimatefee", int(blocks)))
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
            for c in self._live():
                for sh in new:
                    try:
                        c.subscribe("blockchain.scripthash.subscribe", sh)
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


__all__ = ["ElectrumBackend", "ElectrumConnection", "ElectrumError", "CheckpointMismatch", "LightBackendError",
           "ImplausibleChain", "Plausibility", "AnswerCap", "answer_cap", "is_loopback_host", "scripthash",
           "checkpoint_from_env", "servers_from_env"]
