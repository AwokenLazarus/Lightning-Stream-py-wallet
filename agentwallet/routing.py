"""Routed xbt402 payments in B2 (AGP-021): adaptor-locked channel states through a hub, under policy.

xbt402 hub routing (B1 `xbt402/hub.py`, `xbt402/route_client.py`) pays many providers over ONE
channel to a hub. Each payment is a pre-signature of the next channel state under a point
T1 = T + r*G, where T is the provider's per-window invoice point. The hub can complete it only with
t + r, which it gets only when the provider reveals t (after completing the hub's own lock on its
channel to the provider). So B2 signs something the hub can use only if the provider was paid.

`sign_state_adaptor(chan, cum, point, route)` is the one new signing operation. Before it signs:
  * routing policy (policy.json "routing"): the hub is allowed, its fee is within that hub's caps
    (`max_fee_ppm`, `max_fee_base_msat`, carried: at most 1 sat above the exact fee), the lock
    (amount + fee) is within `max_lock_sats`, and the 24 h routed spend (resolved locks, plus the
    pending one) stays within `daily_budget_sats`;
  * the channel book: one pending lock per channel, cum above what is signed, within the channel's
    cap; the lock (cum, pre-signature, r, T) is written to disk before the pre-signature leaves.
After a restart the pending lock is still there: `recover_lock` reads t + r off the hub's ch1 close
(its witness carries our completed pre-signature) and resolves it.

policy.json:
  "routing": {"hubs": {"http://hub:port": {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}},
              "max_lock_sats": 20000, "daily_budget_sats": 5000000}
No "routing" section, or no hubs, means routing is off.

`RouteSigner` adapts a ChannelBook to the signer API B1's RoutePayer uses (new_key/attach/fund,
sign_state, sign_close, sign_refund, request_auth, sign_state_adaptor, resolve_lock, void_lock), so
the routed client runs with its keys in B2. The Signer's socket exposes the same operations as
`xbt402_sign_state_adaptor`, `xbt402_resolve_lock`, `xbt402_void_lock`, `xbt402_recover_lock`.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .applog import AppendLog, LogError, replace_log
from .b1path import ensure_b1
from .policy import normalize_dest

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelError, ChannelParams  # noqa: E402

DAY_S = 24 * 3600


def adaptor_mod():
    """B1's production adaptor (libsecp256k1 for secret multiplications, blinded inversions; B1
    agp-021+) when the pinned B1 has it, else B2's own copy of the same construction (AGP-013)."""
    try:
        from xbt402 import adaptor as a            # B1 agp-021
        return a
    except ImportError:
        from .fwd import adaptor as a
        return a


def point_add(a, b):
    A = adaptor_mod()
    if hasattr(A, "add"):
        return A.add(a, b)
    from xbt402 import ecc_oracle
    return ecc_oracle._add(a, b)


@dataclass
class RoutePolicy:
    hubs: dict = field(default_factory=dict)          # normalized hub origin -> {max_fee_ppm, max_fee_base_msat}
    max_lock_sats: int = 0
    daily_budget_sats: int = 0

    @classmethod
    def from_dict(cls, raw) -> "RoutePolicy":
        raw = raw or {}
        hubs = {normalize_dest(h): {"max_fee_ppm": int((v or {}).get("max_fee_ppm", 0)),
                                    "max_fee_base_msat": int((v or {}).get("max_fee_base_msat", 0))}
                for h, v in (raw.get("hubs") or {}).items() if normalize_dest(h)}
        return cls(hubs, int(raw.get("max_lock_sats") or 0), int(raw.get("daily_budget_sats") or 0))

    @property
    def enabled(self) -> bool:
        return bool(self.hubs) and self.max_lock_sats > 0 and self.daily_budget_sats > 0

    def public(self) -> dict:
        return {"enabled": self.enabled, "hubs": self.hubs, "max_lock_sats": self.max_lock_sats,
                "daily_budget_sats": self.daily_budget_sats}

    def fee_cap_sat(self, hub: str, amount: int) -> int:
        """The most this hub may charge for a lock of `amount` sat: its caps on the exact fee, plus
        1 sat for the carried remainder (the hub charges the ceil of its running total)."""
        c = self.hubs[normalize_dest(hub)]
        exact_msat = c["max_fee_base_msat"] + amount * 1000 * c["max_fee_ppm"] // 1_000_000
        return -(-exact_msat // 1000) + 1


RETAIN_S = 7 * DAY_S          # rows older than this are never read (the budget looks back 24 h)
PRUNE_EVERY = 1024           # rows added between two prunes: a prune is O(rows), so it is not per lock


class RouteSpend:
    """Resolved routed spend, for the 24 h routing budget.

    AGP-055: an append-only log (applog.py), one line and one fsync per resolved lock; it used to be
    seven days of rows rewritten on every lock. Rows older than RETAIN_S leave memory at a prune, and
    the file is compacted to the rows still in memory once it holds over twice as many (plus
    PRUNE_EVERY). A file in the old format ({"resolved": [...]}) is converted at open, in one rename."""

    def __init__(self, path: Path | None):
        self.path, self.lock = (Path(path) if path else None), threading.Lock()
        self.rows: list = []
        self._keys: set = set()
        self._log: AppendLog | None = None
        self._unpruned = 0
        if self.path:
            old = self._legacy_rows()
            if old is not None:
                replace_log(self.path, "route-spend", old)
            self._log = AppendLog(self.path, "route-spend")
            self.rows = self._log.take_rows()
            for n, r in enumerate(self.rows, start=2):
                if not isinstance(r.get("at"), (int, float)) or not isinstance(r.get("amount"), int):
                    raise LogError(f"{self.path}: line {n} is not a spend row")
            self._prune(time.time())

    def _legacy_rows(self) -> list | None:
        """The rows of a pre-AGP-055 file, or None when the file is absent or already a log."""
        if not self.path.exists():
            return None
        try:
            doc = json.loads(self.path.read_bytes())
        except ValueError:
            return None              # not one JSON document: the append-only log (opened strictly next)
        if isinstance(doc, dict) and isinstance(doc.get("resolved"), list):
            return doc["resolved"]
        return None

    def _prune(self, now: float) -> None:
        self._unpruned = 0
        self.rows = [r for r in self.rows if r["at"] >= now - RETAIN_S]
        self._keys = {r["key"] for r in self.rows if r.get("key")}
        if self._log is not None and self._log.file_rows > 2 * len(self.rows) + PRUNE_EVERY:
            self._log.compact(self.rows)

    def add(self, row: dict) -> bool:
        """Book a row. A row with a "key" this log already holds is not booked again (False)."""
        with self.lock:
            if row.get("key") and row["key"] in self._keys:
                return False
            if self._log is not None:
                self._log.append(row)            # durable before it counts
            self.rows.append(row)
            if row.get("key"):
                self._keys.add(row["key"])
            self._unpruned += 1
            if self._unpruned >= PRUNE_EVERY:
                self._prune(time.time())
            return True

    def since(self, t: float) -> int:
        with self.lock:
            return sum(int(r["amount"]) for r in self.rows if r["at"] >= t)


def check_route(policy: RoutePolicy, spend: RouteSpend, hub: str, amount: int, fee: int, increase: int,
                pending: int = 0, now: float | None = None) -> dict | None:
    """None if the routing policy allows this lock, else a deny {verdict, rule, reason}."""
    now = time.time() if now is None else now
    if not policy.enabled:
        return {"verdict": "deny", "rule": "routing_disabled", "reason": "routing is off in this policy"}
    if normalize_dest(hub) not in policy.hubs:
        return {"verdict": "deny", "rule": "route_hub", "reason": f"{hub} is not an allowed hub"}
    if amount < 1 or fee < 0 or increase < 1:
        return {"verdict": "deny", "rule": "route_amount", "reason": "a lock pays at least 1 sat"}
    if fee > policy.fee_cap_sat(hub, amount):
        return {"verdict": "deny", "rule": "route_fee_cap",
                "reason": f"fee {fee} sat > this hub's cap {policy.fee_cap_sat(hub, amount)} for {amount} sat"}
    if increase > policy.max_lock_sats:
        return {"verdict": "deny", "rule": "route_lock_max",
                "reason": f"lock {increase} sat > max_lock_sats {policy.max_lock_sats}"}
    spent = spend.since(now - DAY_S)
    if spent + pending + increase > policy.daily_budget_sats:
        return {"verdict": "deny", "rule": "route_daily_budget",
                "reason": f"routed spend {spent} + {increase} > daily_budget_sats {policy.daily_budget_sats}"}
    return None


class RouteSigner:
    """B1's signer API over a B2 ChannelBook, with the routing policy on every adaptor lock.
    Channels are keyed by their hub origin in the book (one ch1 per hub)."""

    def __init__(self, book, policy: RoutePolicy, *, fund=None, state_path=None, engine=None):
        self.book, self.policy, self.fund_fn, self.engine = book, policy, fund, engine
        self.spend = RouteSpend(Path(state_path) if state_path else None)
        self._pending_keys: dict = {}
        self.denials: list = []
        # AGP-055: a crash between a resolve reaching disk and its rows left the budgets short. Book it now
        in_ledger = {e.txid for e in engine.store.payments()} if engine is not None else set()
        self.recovered_bookings = sum(self._book(chan, b, in_ledger=in_ledger) for chan, b in book.resolved_bookings()
                                      if b["at"] >= time.time() - RETAIN_S)

    # --- channel lifecycle (B1 XbtChannelClient with a signer) --------------------------------------
    def new_key(self, origin: str) -> str:
        secret, pub = self.book.new_payer_key()
        self._pending_keys[origin] = secret
        return pub

    def attach(self, origin: str, params: ChannelParams) -> str:
        secret = self._pending_keys.pop(origin)
        if ecc.pubkey(secret).hex() != params.payer_pub:
            raise ChannelError("bad_key", "attached params do not match the issued key")
        self.book.add_funded(normalize_dest(origin), secret=secret, params=params, origin=origin,
                             cap_sats=params.max_amount)
        return params.channel_id

    def fund(self, address: str, sats: int):
        if not self.fund_fn:
            raise ChannelError("no_wallet", "no fund hook")
        return self.fund_fn(address, sats)

    def _dest(self, chan: str) -> str:
        d = self.book.find_dest(chan)
        if d is None:
            raise ChannelError("unknown_channel", chan)
        return d

    def sign_refund(self, chan: str) -> str:
        rec = self.book.get(self._dest(chan))
        tx, _ = self.book.refund_tx(self._dest(chan), bytes.fromhex(rec.payer_spk))
        return tx.hex()

    def sign_close(self, chan: str) -> str:
        return self.book.sign_close(self._dest(chan))

    def request_auth(self, chan: str, seq, cum, sig, req: str) -> str:
        return self.book.request_auth(chan, seq, cum, sig, req)

    def sign_state(self, chan: str, amount: int) -> str:
        return self.book.sign_state(self._dest(chan), int(amount)).hex()

    # --- routed locks ---------------------------------------------------------------------------------
    def sign_state_adaptor(self, chan: str, cum: int, point: str, route: dict | None = None) -> dict:
        route = dict(route or {})
        dest = self._dest(chan)
        rec = self.book.get(dest)
        hub = route.get("hub") or rec.origin or dest
        increase = int(cum) - rec.used_sats
        denied = check_route(self.policy, self.spend, hub, int(route.get("amount", 0)), int(route.get("fee", 0)),
                             increase, pending=self.pending_sats())
        if denied is None and self.engine is not None:
            from .policy import Payment, Verdict
            d = self.engine.evaluate(Payment(dest=normalize_dest(hub), amount_sats=increase,
                                             memo=f"routed lock {route.get('lockId', '')}"), human=False)
            if d.verdict is not Verdict.ALLOW:
                denied = d.as_dict()
        if denied:
            self.denials.append(denied)
            raise ChannelError(denied["rule"], denied["reason"])
        return self.book.sign_state_adaptor(dest, int(cum), point, {**route, "hub": hub})

    def pending_lock(self, chan: str) -> dict:
        rec = self.book.get(self._dest(chan))
        return dict(rec.pending_lock) if rec else {}

    def _book(self, chan: str, b: dict, *, in_ledger: frozenset | set = frozenset(), **how) -> bool:
        """Book a resolved lock in the 24 h routing budget and the policy ledger, under its key. A lock
        resolves once, so a live call always writes both rows. At start the record's remembered locks
        come through here again: the spend log skips a key it holds, and `in_ledger` (the ledger's
        txids) skips a payment it holds. True if anything was written."""
        wrote = self.spend.add({"at": b["at"], "amount": b["amount"], "chan": chan, "lockId": b.get("lockId", ""),
                                "key": b["key"], **how})
        if self.engine is not None and b["key"] not in in_ledger:
            from .policy import Payment
            self.engine.commit(Payment(dest=normalize_dest(b.get("hub") or chan), amount_sats=b["amount"],
                                       memo="routed lock", ts=b["at"]), txid=b["key"])
            wrote = True
        return wrote

    def resolve_lock(self, chan: str, secret: str) -> str:
        res = self.book.resolve_lock(self._dest(chan), secret)
        self._book(chan, res["booking"])
        return res["t"]

    def void_lock(self, chan: str) -> dict:
        return self.book.void_lock(self._dest(chan))

    def adopt_lock(self, chan: str, cum: int) -> None:
        res = self.book.adopt_lock(self._dest(chan), int(cum))
        if res["amount"]:
            self._book(chan, res["booking"], adopted=True)

    def recover_lock(self, chan: str, close_tx) -> str:
        wit = close_tx.inputs[0].witness if hasattr(close_tx, "inputs") else close_tx
        res = self.book.recover_lock(self._dest(chan), wit)
        self._book(chan, res["booking"], recovered=True)
        return res["t"]

    def pending_sats(self) -> int:
        """The routed amount out in pending locks, on every channel of the book."""
        return sum(int(r.pending_lock["cum"]) - int(r.pending_lock.get("prev_used", 0))
                   for r in self.book.unsettled_records() if r.pending_lock)

    def status(self) -> dict:
        return {"policy": self.policy.public(), "spent_24h_sats": self.spend.since(time.time() - DAY_S),
                "pending": {r.chan: {"cum": r.pending_lock["cum"], "route": r.pending_lock.get("route")}
                            for r in self.book.unsettled_records() if r.pending_lock}}
