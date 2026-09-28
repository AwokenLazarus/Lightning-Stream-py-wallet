"""Pure policy engine: budgets, allowlist, caps, velocity, split-bypass, audit.

Decisions are allow / deny / needs_human. This module has no RPC and no keys.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse


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


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        line = json.dumps(event, sort_keys=True, separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())

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


class PolicyStore:
    """On-disk committed payments and pending human approvals."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if not self.path.exists():
            self._write({"payments": [], "approvals": {}})

    def _read(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def payments(self) -> list[LedgerEntry]:
        with self._lock:
            raw = self._read().get("payments") or []
        return [LedgerEntry(**e) for e in raw]

    def commit(self, entry: LedgerEntry) -> None:
        with self._lock:
            data = self._read()
            data.setdefault("payments", []).append(
                {
                    "dest": entry.dest,
                    "amount_sats": entry.amount_sats,
                    "ts": entry.ts,
                    "txid": entry.txid,
                    "memo": entry.memo,
                }
            )
            self._write(data)

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
        self.audit = audit
        self.clock = clock or (lambda: __import__("time").time())

    def _spent(self, payments: Iterable[LedgerEntry], window_s: int, now: float, dest: str | None = None) -> int:
        total = 0
        for p in payments:
            if now - p.ts > window_s:
                continue
            if dest is not None and p.dest != dest:
                continue
            total += p.amount_sats
        return total

    def _count(self, payments: Iterable[LedgerEntry], window_s: int, now: float) -> int:
        return sum(1 for p in payments if now - p.ts <= window_s)

    def evaluate(self, payment: Payment, *, human: bool = False) -> Decision:
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

        split_sum = self._spent(ledger, cfg.split_window_s, now, dest=p.dest) + p.amount_sats
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

        if daily + p.amount_sats > cfg.daily_budget_sats:
            return decide(
                Verdict.DENY,
                "daily_budget",
                f"daily spend {daily + p.amount_sats} exceeds budget {cfg.daily_budget_sats}",
            )
        if weekly + p.amount_sats > cfg.weekly_budget_sats:
            return decide(
                Verdict.DENY,
                "weekly_budget",
                f"weekly spend {weekly + p.amount_sats} exceeds budget {cfg.weekly_budget_sats}",
            )
        if cpty + p.amount_sats > cfg.per_counterparty_cap_sats:
            return decide(
                Verdict.DENY,
                "per_counterparty",
                f"counterparty spend {cpty + p.amount_sats} exceeds cap {cfg.per_counterparty_cap_sats}",
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

    def commit(self, payment: Payment, txid: str = "") -> None:
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
