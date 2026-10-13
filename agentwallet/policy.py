"""Pure policy engine: budgets, allowlist, caps, velocity, split-bypass, audit.

Decisions are allow / deny / needs_human. This module has no RPC and no keys.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

from .applog import AppendLog, LogError, write_all


DAY_S = 24 * 3600
WEEK_S = 7 * DAY_S


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_HUMAN = "needs_human"


def normalize_dest(dest: str) -> str:
    """Bech32 addresses fold case; HTTP dests collapse to origin; anything else is stripped."""
    dest = (dest or "").strip()
    if not dest:
        return ""
    if dest.lower().startswith(("bc1", "bcrt1", "tb1")):
        return dest.lower()
    if dest.startswith(("http://", "https://")):
        p = urlparse(dest)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    return dest


@dataclass(frozen=True)
class Payment:
    dest: str
    amount_sats: int
    memo: str = ""
    ts: float = 0.0

    def normalized(self, now: float) -> "Payment":
        return Payment(
            dest=normalize_dest(self.dest),
            amount_sats=int(self.amount_sats),
            memo=self.memo or "",
            ts=self.ts or now,
        )


def policy_warnings(raw) -> list[str]:
    """What a policy file holds that the signer loads and does not act on. A `routing` section is
    one: it set the caps of payments through a hub, which were retired with the hub (the Rust signer
    says the same, in the same words)."""
    out = []
    if isinstance(raw, dict) and "routing" in raw:
        out.append("policy.json routing: payments through a hub were retired; the signer ignores this section and it can be removed")
    return out


@dataclass
class Decision:
    verdict: Verdict
    reason: str
    rule: str
    approval_token: str | None = None
    approval_expires: int | None = None
    dest: str = ""
    amount_sats: int = 0
    residual_daily_sats: int = 0
    residual_weekly_sats: int = 0
    residual_counterparty_sats: int = 0

    def as_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


@dataclass
class PolicyConfig:
    allowlist: frozenset[str] = field(default_factory=frozenset)
    max_per_tx_sats: int = 10_000_000
    daily_budget_sats: int = 50_000_000
    weekly_budget_sats: int = 200_000_000
    per_counterparty_cap_sats: int = 30_000_000
    velocity_max: int = 8
    velocity_window_s: int = 3600
    human_threshold_sats: int = 10_000_000
    split_window_s: int = 600
    approval_ttl_s: int = 900
    channel_expiry_blocks: int = 1008
    treasury_csv: int = 4320
    counterparties: dict = field(default_factory=dict)
    # AGP-013
    refund_enabled: bool = True          # xbt402_refund / the expiry watcher may refund our own channels
    refund_margin_blocks: int = 6        # no new states this close to a channel's expiry
    hot_balance_cap_sats: int = 0        # 0 = no cap; above it no new channel is funded (human sweep)
    forward: dict = field(default_factory=dict)  # forward rail limits (agentwallet/forward.py)
    # AGP-016: the signature-log anchor (agentwallet/anchor.py; the witness socket is B2_ANCHOR_SOCK)
    anchor_interval_s: int = 60          # periodic anchor; 0 = only on closes, refunds, sweeps, rotations
    anchor_required: bool = False        # true: the signer refuses to start without a reachable witness
    # AGP-017 (mainnet readiness)
    regtest_mine: bool | None = None     # the signer mines a block after its own spends; None = regtest only.
                                         # True on any other chain: the signer refuses to start (P3)
    open_wait_s: int = 1800              # xbt402_pay waits this long for the offer's minConf, then returns
                                         # "pending" (the open is retried; unopened fundings are refunded) (P2)
    open_retry_s: int = 60               # the watcher re-posts a pending open at most this often
    close_fee_max_sats: int = 2000       # refuse an offer whose closeFeeSat is above this (spec SHOULD)

    def normalized_allowlist(self) -> frozenset[str]:
        out = set()
        for a in self.allowlist:
            a = normalize_dest(a)
            if a:
                out.add(a)
        return frozenset(out)

    def pay_to_for(self, dest: str) -> str:
        dest = normalize_dest(dest)
        info = (self.counterparties or {}).get(dest) or {}
        return (info.get("pay_to") or "").strip()

    @classmethod
    def from_dict(cls, raw: dict) -> "PolicyConfig":
        allow = raw.get("allowlist") or []
        fields = {
            "max_per_tx_sats",
            "daily_budget_sats",
            "weekly_budget_sats",
            "per_counterparty_cap_sats",
            "velocity_max",
            "velocity_window_s",
            "human_threshold_sats",
            "split_window_s",
            "approval_ttl_s",
            "channel_expiry_blocks",
            "treasury_csv",
            "refund_margin_blocks",
            "hot_balance_cap_sats",
            "anchor_interval_s",
            "open_wait_s",
            "open_retry_s",
            "close_fee_max_sats",
        }
        kwargs = {k: int(raw[k]) for k in fields if k in raw}
        if "refund_enabled" in raw:
            kwargs["refund_enabled"] = bool(raw["refund_enabled"])
        if "anchor_required" in raw:
            kwargs["anchor_required"] = bool(raw["anchor_required"])
        if raw.get("regtest_mine") is not None:
            kwargs["regtest_mine"] = bool(raw["regtest_mine"])
        if isinstance(raw.get("forward"), dict):
            kwargs["forward"] = dict(raw["forward"])
        cps = raw.get("counterparties") or {}
        kwargs["counterparties"] = {normalize_dest(k): v for k, v in cps.items()}
        return cls(allowlist=frozenset(allow), **kwargs)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["allowlist"] = sorted(self.allowlist)
        return d


@dataclass
class LedgerEntry:
    dest: str
    amount_sats: int
    ts: float
    txid: str = ""
    memo: str = ""


def _row_key(row: dict) -> tuple:
    return (row["dest"], int(row["amount_sats"]), float(row["ts"]), row.get("txid", ""), row.get("memo", ""))


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        line = json.dumps(event, sort_keys=True, separators=(",", ":"))
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                write_all(fd, (line + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)

    def read(self, limit: int = 50) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


PRUNE_EVERY = 1024           # commits between two prunes of the in-memory payments


class PolicyStore:
    """On-disk committed payments and pending human approvals.

    AGP-055: `ledger.json` holds the approvals. The payments are an append-only log next to it
    (`ledger.payments.jsonl`, applog.py): a commit is one line and one fsync, and the engine reads
    the payments from memory. Both used to be one JSON document, read and rewritten whole on every
    commit. Payments found in `ledger.json` (the old format) move to the log at open.

    `retain_s` (the engine sets it to its longest window plus a day) bounds what stays in memory
    and what a compaction keeps; None keeps everything. The audit log has every commit regardless.
    A line {"amend": txid, "amount_sats": n | null} (the Rust signer's Lightning bookings) changes
    or removes the last payment with that txid."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path = self.path.with_name(self.path.stem + ".payments.jsonl")
        self.retain_s: float | None = None
        self._lock = threading.Lock()
        self._unpruned = 0
        if not self.path.exists():
            self._write({"approvals": {}, "payments_log": self.log_path.name})
        self._log = AppendLog(self.log_path, "payments")
        self._entries: list[LedgerEntry] = []
        for n, row in enumerate(self._log.take_rows(), start=2):
            self._apply(row, n)
        self._migrate()

    def _apply(self, row: dict, n: int) -> None:
        if "amend" not in row:
            try:
                amount = int(row["amount_sats"])
            except (KeyError, TypeError, ValueError):
                raise LogError(f"{self.log_path}: line {n} is not a payment")
            if amount < 0:
                raise LogError(f"{self.log_path}: line {n} is a negative payment")
            self._entries.append(LedgerEntry(**row))
            return
        i = next((i for i in range(len(self._entries) - 1, -1, -1) if self._entries[i].txid == row["amend"]), None)
        if i is None:
            raise LogError(f"{self.log_path}: line {n} amends {row['amend']!r}, which the log does not hold")
        if row.get("amount_sats") is None:
            del self._entries[i]
        else:
            amount = int(row["amount_sats"])
            if amount < 0:
                raise LogError(f"{self.log_path}: line {n} amends {row['amend']!r} to a negative amount")
            self._entries[i].amount_sats = amount

    def _migrate(self) -> None:
        """Move the payments of an old-format ledger.json to the log. Safe to run again after a crash
        between its two writes: only rows the log does not already hold are added."""
        data = self._read()
        if "payments" not in data:
            return
        missing = Counter(_row_key(e) for e in data["payments"]) - Counter(_row_key(asdict(e)) for e in self._entries)
        if missing:
            add = []
            for e in data["payments"]:
                if missing[_row_key(e)] > 0:
                    missing[_row_key(e)] -= 1
                    add.append(LedgerEntry(**e))
            self._entries += add
            self._log.compact([asdict(e) for e in self._entries])
        del data["payments"]
        data["payments_log"] = self.log_path.name
        self._write(data)

    def _read(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict) -> None:
        """AGP-063 K1: the approvals document like every other state file (fsync, rename, dir fsync, 0600)."""
        from .keystore import write_private

        write_private(self.path, json.dumps(data, indent=2, sort_keys=True))

    def payments(self) -> list[LedgerEntry]:
        with self._lock:
            return list(self._entries)

    def amend(self, txid: str, amount_sats: int | None) -> bool:
        """Change (or, with None, drop) the latest row for `txid`: one {"amend"} log line, the Rust
        signer's format. False when the ledger holds no such row."""
        if amount_sats is not None and int(amount_sats) < 0:
            raise LogError("negative ledger entry refused")
        with self._lock:
            i = next((i for i in range(len(self._entries) - 1, -1, -1) if self._entries[i].txid == txid), None)
            if i is None:
                return False
            self._log.append({"amend": txid, "amount_sats": None if amount_sats is None else int(amount_sats)})
            if amount_sats is None:
                del self._entries[i]
            else:
                self._entries[i].amount_sats = int(amount_sats)
            return True

    def commit(self, entry: LedgerEntry) -> None:
        if entry.amount_sats < 0:
            raise LogError("negative ledger entry refused")
        with self._lock:
            self._log.append(asdict(entry))          # durable before it counts
            self._entries.append(entry)
            self._unpruned += 1
            if self._unpruned >= PRUNE_EVERY:
                self._prune(entry.ts)

    def _prune(self, now: float) -> None:
        self._unpruned = 0
        if self.retain_s is not None:
            self._entries = [e for e in self._entries if e.ts >= now - self.retain_s]
        if self._log.file_rows > 2 * len(self._entries) + PRUNE_EVERY:
            self._log.compact([asdict(e) for e in self._entries])

    def put_approval(self, token: str, payload: dict) -> None:
        with self._lock:
            data = self._read()
            data.setdefault("approvals", {})[token] = payload
            self._write(data)

    def pop_approval(self, token: str) -> dict | None:
        with self._lock:
            data = self._read()
            approvals = data.setdefault("approvals", {})
            payload = approvals.pop(token, None)
            self._write(data)
        return payload

    def get_approval(self, token: str) -> dict | None:
        with self._lock:
            return (self._read().get("approvals") or {}).get(token)


class PolicyEngine:
    def __init__(
        self,
        config: PolicyConfig,
        store: PolicyStore,
        audit: AuditLog,
        clock: Callable[[], float] | None = None,
    ):
        self.config = config
        self.allowlist = config.normalized_allowlist()
        self.store = store
        # the store keeps what the longest window below can still read, and a day more
        store.retain_s = max(WEEK_S, config.velocity_window_s, config.split_window_s) + DAY_S
        self.audit = audit
        self.clock = clock or (lambda: __import__("time").time())

    def _spent(self, payments: Iterable[LedgerEntry], window_s: int, now: float, dest: str | None = None) -> int:
        total = 0
        for p in payments:
            if now - p.ts > window_s:
                continue
            if dest is not None and p.dest != dest:
                continue
            if p.amount_sats < 0:
                raise LogError("negative ledger entry")
            total += p.amount_sats
        return total

    def _count(self, payments: Iterable[LedgerEntry], window_s: int, now: float) -> int:
        return sum(1 for p in payments if now - p.ts <= window_s)

    def evaluate(self, payment: Payment, *, human: bool = False) -> Decision:
        return self.evaluate_booking(payment, payment.amount_sats, human=human)

    def evaluate_booking(self, payment: Payment, booked_sats: int, *, human: bool = False) -> Decision:
        """AGP-063 W1: `payment.amount_sats` is what the caller asked for (per-tx and human threshold,
        approvals); `booked_sats` is the most the ledger gains from it (the sums). They differ on a
        channel, where the signed increase is known only from its state."""
        now = self.clock()
        p = payment.normalized(now)
        cfg = self.config
        ledger = self.store.payments()
        daily = self._spent(ledger, DAY_S, now)
        weekly = self._spent(ledger, WEEK_S, now)
        cpty = self._spent(ledger, WEEK_S, now, dest=p.dest)
        residual_daily = max(0, cfg.daily_budget_sats - daily)
        residual_weekly = max(0, cfg.weekly_budget_sats - weekly)
        residual_cpty = max(0, cfg.per_counterparty_cap_sats - cpty)

        def decide(
            verdict: Verdict,
            rule: str,
            reason: str,
            token: str | None = None,
            expires: int | None = None,
        ) -> Decision:
            d = Decision(
                verdict=verdict,
                reason=reason,
                rule=rule,
                approval_token=token,
                approval_expires=expires,
                dest=p.dest,
                amount_sats=p.amount_sats,
                residual_daily_sats=residual_daily,
                residual_weekly_sats=residual_weekly,
                residual_counterparty_sats=residual_cpty,
            )
            self.audit.append(
                {
                    "type": "decision",
                    "verdict": verdict.value,
                    "rule": rule,
                    "reason": reason,
                    "dest": p.dest,
                    "amount_sats": p.amount_sats,
                    "human": human,
                    "ts": now,
                    "approval_token": token,
                }
            )
            return d

        if p.amount_sats <= 0:
            return decide(Verdict.DENY, "amount", "amount_sats must be a positive integer")
        if not p.dest:
            return decide(Verdict.DENY, "dest", "destination address required")
        if p.dest not in self.allowlist:
            return decide(Verdict.DENY, "allowlist", f"destination not on allowlist: {p.dest}")
        if p.amount_sats > cfg.max_per_tx_sats:
            return decide(
                Verdict.DENY,
                "max_per_tx",
                f"{p.amount_sats} sats exceeds max_per_tx {cfg.max_per_tx_sats}",
            )

        split_sum = self._spent(ledger, cfg.split_window_s, now, dest=p.dest) + booked_sats
        if split_sum > cfg.max_per_tx_sats:
            return decide(
                Verdict.DENY,
                "split_bypass",
                f"split window sum {split_sum} would exceed max_per_tx {cfg.max_per_tx_sats}",
            )
        if not human and split_sum >= cfg.human_threshold_sats and p.amount_sats < cfg.human_threshold_sats:
            return decide(
                Verdict.DENY,
                "split_bypass",
                f"split window sum {split_sum} evades human_threshold {cfg.human_threshold_sats}",
            )

        if daily + booked_sats > cfg.daily_budget_sats:
            return decide(
                Verdict.DENY,
                "daily_budget",
                f"daily spend {daily + booked_sats} exceeds budget {cfg.daily_budget_sats}",
            )
        if weekly + booked_sats > cfg.weekly_budget_sats:
            return decide(
                Verdict.DENY,
                "weekly_budget",
                f"weekly spend {weekly + booked_sats} exceeds budget {cfg.weekly_budget_sats}",
            )
        if cpty + booked_sats > cfg.per_counterparty_cap_sats:
            return decide(
                Verdict.DENY,
                "per_counterparty",
                f"counterparty spend {cpty + booked_sats} exceeds cap {cfg.per_counterparty_cap_sats}",
            )
        if self._count(ledger, cfg.velocity_window_s, now) >= cfg.velocity_max:
            return decide(
                Verdict.DENY,
                "velocity",
                f"already {cfg.velocity_max} payments in the last {cfg.velocity_window_s}s",
            )

        if not human and p.amount_sats >= cfg.human_threshold_sats:
            token = secrets.token_urlsafe(24)
            expires = int(now + cfg.approval_ttl_s)
            self.store.put_approval(
                token,
                {
                    "dest": p.dest,
                    "amount_sats": p.amount_sats,
                    "memo": p.memo,
                    "expires": expires,
                    "ts": now,
                    "used": False,
                },
            )
            return decide(
                Verdict.NEEDS_HUMAN,
                "human_threshold",
                f"{p.amount_sats} sats is at or above human_threshold {cfg.human_threshold_sats}",
                token=token,
                expires=expires,
            )

        return decide(Verdict.ALLOW, "ok", "all policy rules passed")

    def quote(self, payment: Payment) -> Decision:
        return self.evaluate(payment, human=False)

    def consume_approval(self, token: str) -> Payment | None:
        """Pop a still-valid unused token. Signature checks happen in the signer."""
        if not token:
            return None
        now = self.clock()
        payload = self.store.get_approval(token)
        if not payload:
            self.audit.append({"type": "approval_miss", "token": token, "ts": now})
            return None
        if payload.get("used"):
            self.audit.append({"type": "approval_replay", "token": token, "ts": now})
            return None
        if payload.get("expires", 0) < now:
            self.store.pop_approval(token)
            self.audit.append({"type": "approval_expired", "token": token, "ts": now})
            return None
        self.store.pop_approval(token)
        return Payment(
            dest=payload["dest"],
            amount_sats=int(payload["amount_sats"]),
            memo=payload.get("memo") or "",
            ts=now,
        )

    def hold_approval(self, token: str) -> Payment | None:
        """AGP-085: `consume_approval`, but the token stays on disk marked used while its payment
        runs. The caller pops it when the payment is made, or calls `release_approval` when it was
        not; a token left held is never valid again."""
        if not token:
            return None
        now = self.clock()
        payload = self.store.get_approval(token)
        if not payload:
            self.audit.append({"type": "approval_miss", "token": token, "ts": now})
            return None
        if payload.get("used"):
            self.audit.append({"type": "approval_replay", "token": token, "ts": now})
            return None
        if payload.get("expires", 0) < now:
            self.store.pop_approval(token)
            self.audit.append({"type": "approval_expired", "token": token, "ts": now})
            return None
        self.store.put_approval(token, {**payload, "used": True})
        return Payment(dest=payload["dest"], amount_sats=int(payload["amount_sats"]), memo=payload.get("memo") or "",
                       ts=now)

    def release_approval(self, token: str) -> None:
        """Nothing was paid on a held token: it is valid again until it expires."""
        payload = self.store.get_approval(token)
        if payload and payload.get("used"):
            self.store.put_approval(token, {**payload, "used": False})
            self.audit.append({"type": "approval_released", "token": token, "ts": self.clock()})

    def commit_once(self, payment: Payment, txid: str = "") -> bool:
        """Commit `txid` once. A repeat (the write-ahead ran, then the process restarted) does not
        add a second row. False when this txid was already in the ledger."""
        if txid and any(e.txid == txid for e in self.store.payments()):
            return False
        self.commit(payment, txid)
        return True

    def commit(self, payment: Payment, txid: str = "") -> None:
        if int(payment.amount_sats) < 0:
            raise LogError("negative ledger entry refused")
        now = self.clock()
        p = payment.normalized(now)
        self.store.commit(
            LedgerEntry(
                dest=p.dest,
                amount_sats=p.amount_sats,
                ts=p.ts or now,
                txid=txid,
                memo=p.memo,
            )
        )
        self.audit.append(
            {
                "type": "commit",
                "dest": p.dest,
                "amount_sats": p.amount_sats,
                "txid": txid,
                "ts": p.ts or now,
            }
        )
