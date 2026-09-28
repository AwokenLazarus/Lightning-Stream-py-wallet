"""AGP-036: sats_from_xbt parses sub-0.0001 XBT exactly; quote_payment for 0.00001 works."""

from __future__ import annotations

import math
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from agentwallet.policy import AuditLog, PolicyConfig, PolicyEngine, PolicyStore
from agentwallet.rpc import KnotsRpcError
from agentwallet.signer import (
    ERR_NEGATIVE,
    ERR_NOT_DECIMAL,
    ERR_NOT_FINITE,
    ERR_PRECISION,
    Signer,
    sats_from_xbt,
)

MERCHANT = "bcrt1qmerchant0000000000000000000000000000qq"


class SatsFromXbtTests(unittest.TestCase):
    def test_tiny_amounts_are_exact(self):
        self.assertEqual(sats_from_xbt(0.00001), 1000)
        self.assertEqual(sats_from_xbt(1e-05), 1000)
        self.assertEqual(sats_from_xbt("1e-05"), 1000)
        self.assertEqual(sats_from_xbt(0.00000001), 1)
        self.assertEqual(sats_from_xbt("0.00000001"), 1)

    def test_max_supply_and_ordinary_values(self):
        self.assertEqual(sats_from_xbt(21e6), 2_100_000_000_000_000)
        self.assertEqual(sats_from_xbt("21e6"), 2_100_000_000_000_000)
        self.assertEqual(sats_from_xbt(0), 0)
        self.assertEqual(sats_from_xbt("0"), 0)
        self.assertEqual(sats_from_xbt(1), 100_000_000)
        self.assertEqual(sats_from_xbt(0.5), 50_000_000)
        self.assertEqual(sats_from_xbt(".5"), 50_000_000)
        self.assertEqual(sats_from_xbt("0.00000546"), 546)
        self.assertEqual(sats_from_xbt(2.00000001), 200_000_001)
        self.assertEqual(sats_from_xbt(Decimal("0.00001")), 1000)

    def test_ninth_place_is_refused_not_truncated(self):
        with self.assertRaises(ValueError) as ctx:
            sats_from_xbt(0.000000001)
        self.assertEqual(str(ctx.exception), ERR_PRECISION)
        with self.assertRaises(ValueError) as ctx:
            sats_from_xbt("0.000000001")
        self.assertEqual(str(ctx.exception), ERR_PRECISION)
        with self.assertRaises(ValueError) as ctx:
            sats_from_xbt("0.123456789")
        self.assertEqual(str(ctx.exception), ERR_PRECISION)

    def test_negatives_nan_inf_and_garbage(self):
        for bad, err in (
            (-1, ERR_NEGATIVE),
            ("-1", ERR_NEGATIVE),
            (-0.00001, ERR_NEGATIVE),
            (float("nan"), ERR_NOT_FINITE),
            (float("inf"), ERR_NOT_FINITE),
            (float("-inf"), ERR_NOT_FINITE),
            ("nan", ERR_NOT_FINITE),
            ("NaN", ERR_NOT_FINITE),
            ("inf", ERR_NOT_FINITE),
            ("Infinity", ERR_NOT_FINITE),
            ("abc", ERR_NOT_DECIMAL),
            ("1.x", ERR_NOT_DECIMAL),
            (True, ERR_NOT_DECIMAL),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    sats_from_xbt(bad)
                self.assertEqual(str(ctx.exception), err)
        self.assertTrue(math.isnan(float("nan")))


class QuotePaymentTinyAmountTests(unittest.TestCase):
    def test_quote_payment_for_1e_5_xbt(self):
        tmp = Path(tempfile.mkdtemp())
        cfg = PolicyConfig(allowlist=frozenset({MERCHANT}))
        engine = PolicyEngine(cfg, PolicyStore(tmp / "ledger.json"), AuditLog(tmp / "audit.jsonl"))

        class Rpc:
            def call(self, method, *a):
                if method == "estimatesmartfee":
                    return {"feerate": 0.00001}
                raise KnotsRpcError(method)

        s = Signer.__new__(Signer)
        s.engine = engine
        s.rpc = Rpc()
        out = s._handle("quote_payment", {"to": MERCHANT, "amount_xbt": 0.00001, "memo": "agp-036"})
        self.assertEqual(out["amount_sats"], 1000)
        self.assertEqual(out["dest"], MERCHANT)
        self.assertEqual(out["verdict"], "allow")
        self.assertEqual(out["fee_estimate"], {"feerate": 0.00001})

        again = s._handle("quote_payment", {"to": MERCHANT, "amount_xbt": "1e-05"})
        self.assertEqual(again["amount_sats"], 1000)


if __name__ == "__main__":
    unittest.main()
