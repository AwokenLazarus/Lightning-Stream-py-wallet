"""Unit tests for every policy rule and split-payment bypass attempts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentwallet.policy import (
    AuditLog,
    Payment,
    PolicyConfig,
    PolicyEngine,
    PolicyStore,
    Verdict,
)

MERCHANT = "bcrt1qmerchant0000000000000000000000000000qq"
OTHER = "bcrt1qother000000000000000000000000000000qq"
STRANGER = "bcrt1qstranger00000000000000000000000000qq"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def engine(tmp: Path, clock: Clock, **overrides) -> PolicyEngine:
    kwargs = dict(
        allowlist=frozenset({MERCHANT, OTHER}),
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


def commit(eng: PolicyEngine, dest: str, amount: int, clock: Clock):
    p = Payment(dest=dest, amount_sats=amount, ts=clock())
    d = eng.evaluate(p)
    if d.verdict is not Verdict.ALLOW:
        raise AssertionError(d)
    eng.commit(p, txid="t" * 64)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.clock = Clock()
        self.eng = engine(self.tmp, self.clock)

    def ev(self, dest, amount, human=False):
        return self.eng.evaluate(Payment(dest=dest, amount_sats=amount), human=human)

    def test_allow_under_all_caps(self):
        d = self.ev(MERCHANT, 100_000)
        self.assertEqual(d.verdict, Verdict.ALLOW)
        self.assertEqual(d.rule, "ok")

    def test_deny_not_on_allowlist(self):
        d = self.ev(STRANGER, 100_000)
        self.assertEqual(d.verdict, Verdict.DENY)
        self.assertEqual(d.rule, "allowlist")

    def test_deny_zero_and_negative(self):
        self.assertEqual(self.ev(MERCHANT, 0).rule, "amount")
        self.assertEqual(self.ev(MERCHANT, -1).rule, "amount")

    def test_deny_empty_dest(self):
        self.assertEqual(self.ev("", 100).rule, "dest")

    def test_deny_over_max_per_tx(self):
        d = self.ev(MERCHANT, 1_000_001)
        self.assertEqual(d.verdict, Verdict.DENY)
        self.assertEqual(d.rule, "max_per_tx")

    def test_needs_human_at_threshold(self):
        d = self.ev(MERCHANT, 400_000)
        self.assertEqual(d.verdict, Verdict.NEEDS_HUMAN)
        self.assertEqual(d.rule, "human_threshold")
        self.assertTrue(d.approval_token)

    def test_human_path_allows_threshold_amount(self):
        d = self.ev(MERCHANT, 400_000, human=True)
        self.assertEqual(d.verdict, Verdict.ALLOW)

    def test_daily_budget(self):
        commit(self.eng, MERCHANT, 200_000, self.clock)
        commit(self.eng, OTHER, 200_000, self.clock)
        # 400k committed; daily 2.5m so still room, push over with human so we skip threshold
        d = self.eng.evaluate(Payment(dest=MERCHANT, amount_sats=2_200_000), human=True)
        # 2.2m > max_per_tx 1m
        self.assertEqual(d.rule, "max_per_tx")
        # fill daily with three 200k + more via raising max
        self.eng = engine(
            self.tmp,
            self.clock,
            max_per_tx_sats=3_000_000,
            human_threshold_sats=9_000_000,
            per_counterparty_cap_sats=10_000_000,
            velocity_max=20,
        )
        commit(self.eng, MERCHANT, 2_000_000, self.clock)
        d = self.ev(OTHER, 600_000)
        self.assertEqual(d.rule, "daily_budget")

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
        commit(self.eng, MERCHANT, 700_000, self.clock)
        d = self.ev(OTHER, 400_000)
        self.assertEqual(d.rule, "weekly_budget")

    def test_per_counterparty_cap(self):
        self.eng = engine(
            self.tmp,
            self.clock,
            max_per_tx_sats=2_000_000,
            daily_budget_sats=10_000_000,
            weekly_budget_sats=10_000_000,
            per_counterparty_cap_sats=500_000,
            human_threshold_sats=9_000_000,
        )
        commit(self.eng, MERCHANT, 400_000, self.clock)
        d = self.ev(MERCHANT, 200_000)
        self.assertEqual(d.rule, "per_counterparty")
        d2 = self.ev(OTHER, 200_000)
        self.assertEqual(d2.verdict, Verdict.ALLOW)

    def test_velocity(self):
        self.eng = engine(self.tmp, self.clock, velocity_max=2, human_threshold_sats=9_000_000)
        commit(self.eng, MERCHANT, 10_000, self.clock)
        commit(self.eng, OTHER, 10_000, self.clock)
        d = self.ev(MERCHANT, 10_000)
        self.assertEqual(d.rule, "velocity")
        self.clock.advance(61)
        d2 = self.ev(MERCHANT, 10_000)
        self.assertEqual(d2.verdict, Verdict.ALLOW)

    def test_split_bypass_evades_max_per_tx(self):
        self.eng = engine(
            self.tmp,
            self.clock,
            max_per_tx_sats=150_000,
            human_threshold_sats=9_000_000,
            split_window_s=30,
        )
        commit(self.eng, MERCHANT, 90_000, self.clock)
        d = self.ev(MERCHANT, 90_000)
        self.assertEqual(d.verdict, Verdict.DENY)
        self.assertEqual(d.rule, "split_bypass")
        # different dest is not a split of the same payment
        d2 = self.ev(OTHER, 90_000)
        self.assertEqual(d2.verdict, Verdict.ALLOW)

    def test_split_bypass_evades_human_threshold(self):
        # 250k + 200k = 450k >= human 400k, each piece under the threshold
        commit(self.eng, MERCHANT, 250_000, self.clock)
        d = self.ev(MERCHANT, 200_000)
        self.assertEqual(d.verdict, Verdict.DENY)
        self.assertEqual(d.rule, "split_bypass")
        self.assertIn("human_threshold", d.reason)

    def test_split_window_expires(self):
        commit(self.eng, MERCHANT, 250_000, self.clock)
        self.clock.advance(31)
        d = self.ev(MERCHANT, 200_000)
        self.assertEqual(d.verdict, Verdict.ALLOW)

    def test_many_tiny_splits(self):
        self.eng = engine(
            self.tmp,
            self.clock,
            max_per_tx_sats=1_000_000,
            human_threshold_sats=100_000,
            daily_budget_sats=10_000_000,
            weekly_budget_sats=10_000_000,
            per_counterparty_cap_sats=10_000_000,
            velocity_max=50,
            split_window_s=60,
        )
        for _ in range(9):
            commit(self.eng, MERCHANT, 10_000, self.clock)
        # 90k committed; the 10th 10k piece would make 100k, which is the
        # human threshold — treat as a split bypass, not a silent allow.
        d = self.ev(MERCHANT, 10_000)
        self.assertEqual(d.rule, "split_bypass")

    def test_approval_round_trip_and_expiry(self):
        d = self.ev(MERCHANT, 400_000)
        token = d.approval_token
        pay = self.eng.consume_approval(token)
        self.assertIsNotNone(pay)
        self.assertEqual(pay.amount_sats, 400_000)
        self.assertIsNone(self.eng.consume_approval(token))
        d2 = self.ev(MERCHANT, 400_000)
        self.clock.advance(121)
        self.assertIsNone(self.eng.consume_approval(d2.approval_token))

    def test_bech32_case_normalize(self):
        d = self.ev(MERCHANT.upper(), 50_000)
        self.assertEqual(d.verdict, Verdict.ALLOW)

    def test_audit_log_written(self):
        self.ev(STRANGER, 10_000)
        events = self.eng.audit.read()
        self.assertTrue(any(e.get("rule") == "allowlist" for e in events))

    def test_residuals_reported(self):
        commit(self.eng, MERCHANT, 100_000, self.clock)
        d = self.ev(MERCHANT, 50_000)
        self.assertEqual(d.residual_daily_sats, 2_400_000)
        self.assertEqual(d.residual_counterparty_sats, 1_400_000)


if __name__ == "__main__":
    unittest.main()
