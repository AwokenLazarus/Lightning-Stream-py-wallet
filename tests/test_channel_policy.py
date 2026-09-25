"""Every policy rule still applies when the rail is a channel increment."""

from __future__ import annotations

import secrets
import tempfile
import unittest
from pathlib import Path

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook, ChannelCapError
from agentwallet.policy import (
    AuditLog,
    Payment,
    PolicyConfig,
    PolicyEngine,
    PolicyStore,
    Verdict,
    normalize_dest,
)

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelParams  # noqa: E402

MERCHANT = "bcrt1qmerchant0000000000000000000000000000qq"
OTHER = "bcrt1qother000000000000000000000000000000qq"
STRANGER = "bcrt1qstranger00000000000000000000000000qq"
API = "http://127.0.0.1:30310/v1/infer"

NET = "bip122:" + "11" * 16   # xbt402 v1.1 derives the payee key per network (the test providers' id)


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def engine(tmp: Path, clock: Clock, **overrides) -> PolicyEngine:
    kwargs = dict(
        allowlist=frozenset({MERCHANT, OTHER, "http://127.0.0.1:30310"}),
        max_per_tx_sats=1_000_000,
        daily_budget_sats=2_500_000,
        weekly_budget_sats=4_000_000,
        per_counterparty_cap_sats=1_500_000,
        velocity_max=3,
        velocity_window_s=60,
        human_threshold_sats=400_000,
        split_window_s=30,
        approval_ttl_s=120,
    )
    kwargs.update(overrides)
    cfg = PolicyConfig(**kwargs)
    return PolicyEngine(cfg, PolicyStore(tmp / "ledger.json"), AuditLog(tmp / "audit.jsonl"), clock=clock)


def open_chan(tmp: Path, dest: str, cap: int) -> ChannelBook:
    book = ChannelBook(tmp / "channels.json", tmp / "channel_keys.json")
    secret = secrets.randbelow(ecc.N - 1) + 1
    payee = secrets.randbelow(ecc.N - 1) + 1
    p = ChannelParams.derive(ecc.pubkey(payee).hex(), ecc.pubkey(secret).hex(), 8_000, 0, network=NET)
    p.funding_txid = "22" * 32
    p.funding_vout = 0
    p.capacity = cap
    book.add_funded(dest, secret=secret, params=p, cap_sats=cap)
    return book


def try_channel_pay(eng: PolicyEngine, book: ChannelBook, dest: str, amount: int, human=False):
    d = eng.evaluate(Payment(dest=dest, amount_sats=amount), human=human)
    if d.verdict is not Verdict.ALLOW:
        return d, None
    try:
        rec, _ = book.increment(dest, amount)
    except ChannelCapError as e:
        return type("D", (), {"verdict": Verdict.DENY, "rule": "channel_cap", "reason": str(e)})(), None
    eng.commit(Payment(dest=dest, amount_sats=amount), txid=rec.chan)
    return d, rec


class ChannelPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.clock = Clock()
        self.eng = engine(self.tmp, self.clock)
        self.book = open_chan(self.tmp, MERCHANT, 10_000_000)

    def test_allowlist_still_denies_stranger(self):
        d, rec = try_channel_pay(self.eng, self.book, STRANGER, 100_000)
        self.assertEqual(d.rule, "allowlist")
        self.assertIsNone(rec)
        self.assertEqual(self.book.get(MERCHANT).used_sats, 0)

    def test_max_per_tx(self):
        d, rec = try_channel_pay(self.eng, self.book, MERCHANT, 1_000_001)
        self.assertEqual(d.rule, "max_per_tx")
        self.assertIsNone(rec)

    def test_daily_budget(self):
        self.eng = engine(
            self.tmp,
            self.clock,
            max_per_tx_sats=3_000_000,
            human_threshold_sats=9_000_000,
            per_counterparty_cap_sats=10_000_000,
        )
        d, rec = try_channel_pay(self.eng, self.book, MERCHANT, 2_000_000)
        self.assertEqual(d.verdict, Verdict.ALLOW)
        self.assertIsNotNone(rec)
        d2, rec2 = try_channel_pay(self.eng, self.book, MERCHANT, 600_000)
        self.assertEqual(d2.rule, "daily_budget")
        self.assertIsNone(rec2)

    def test_weekly_budget(self):
        self.eng = engine(
            self.tmp,
            self.clock,
            max_per_tx_sats=3_000_000,
            daily_budget_sats=10_000_000,
            weekly_budget_sats=1_000_000,
            human_threshold_sats=9_000_000,
            per_counterparty_cap_sats=10_000_000,
        )
        try_channel_pay(self.eng, self.book, MERCHANT, 700_000)
        d, rec = try_channel_pay(self.eng, self.book, MERCHANT, 400_000)
        self.assertEqual(d.rule, "weekly_budget")
        self.assertIsNone(rec)

    def test_per_counterparty(self):
        self.eng = engine(
            self.tmp,
            self.clock,
            max_per_tx_sats=2_000_000,
            daily_budget_sats=10_000_000,
            weekly_budget_sats=10_000_000,
            per_counterparty_cap_sats=500_000,
            human_threshold_sats=9_000_000,
        )
        try_channel_pay(self.eng, self.book, MERCHANT, 400_000)
        d, rec = try_channel_pay(self.eng, self.book, MERCHANT, 200_000)
        self.assertEqual(d.rule, "per_counterparty")
        self.assertIsNone(rec)

    def test_velocity(self):
        self.eng = engine(self.tmp, self.clock, velocity_max=2, human_threshold_sats=9_000_000)
        try_channel_pay(self.eng, self.book, MERCHANT, 10_000)
        try_channel_pay(self.eng, self.book, MERCHANT, 10_000)
        d, rec = try_channel_pay(self.eng, self.book, MERCHANT, 10_000)
        self.assertEqual(d.rule, "velocity")
        self.assertIsNone(rec)

    def test_split_bypass(self):
        self.eng = engine(
            self.tmp,
            self.clock,
            max_per_tx_sats=150_000,
            human_threshold_sats=9_000_000,
            split_window_s=30,
        )
        try_channel_pay(self.eng, self.book, MERCHANT, 90_000)
        d, rec = try_channel_pay(self.eng, self.book, MERCHANT, 90_000)
        self.assertEqual(d.rule, "split_bypass")
        self.assertIsNone(rec)

    def test_human_threshold(self):
        d, rec = try_channel_pay(self.eng, self.book, MERCHANT, 400_000)
        self.assertEqual(d.verdict, Verdict.NEEDS_HUMAN)
        self.assertIsNone(rec)

    def test_channel_cap_even_when_policy_allows(self):
        small = Path(tempfile.mkdtemp())
        book = open_chan(small, MERCHANT, 50_000)
        eng = engine(
            small,
            self.clock,
            max_per_tx_sats=1_000_000,
            human_threshold_sats=9_000_000,
            per_counterparty_cap_sats=1_000_000,
            daily_budget_sats=10_000_000,
            weekly_budget_sats=10_000_000,
        )
        d, rec = try_channel_pay(eng, book, MERCHANT, 40_000)
        self.assertEqual(d.verdict, Verdict.ALLOW)
        d2, rec2 = try_channel_pay(eng, book, MERCHANT, 20_000)
        self.assertEqual(d2.rule, "channel_cap")
        self.assertIsNone(rec2)
        self.assertEqual(book.get(MERCHANT).used_sats, 40_000)

    def test_http_origin_normalize_for_allowlist(self):
        self.assertEqual(normalize_dest(API), "http://127.0.0.1:30310")
        d = self.eng.evaluate(Payment(dest=API, amount_sats=150))
        self.assertEqual(d.verdict, Verdict.ALLOW)
        d2 = self.eng.evaluate(Payment(dest="http://evil.example/v1", amount_sats=150))
        self.assertEqual(d2.rule, "allowlist")


if __name__ == "__main__":
    unittest.main()
