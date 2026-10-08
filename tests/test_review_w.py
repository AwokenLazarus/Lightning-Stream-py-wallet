"""AGP-063 W1 and W2: the seller does not decide the budget, and minCapacity cannot raise the cap.

Same names as crates/xbt-signer/tests/review_w.rs.
"""

from __future__ import annotations

import secrets
import tempfile
import unittest
from pathlib import Path

from agentwallet.applog import LogError
from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook
from agentwallet.policy import AuditLog, Payment, PolicyConfig, PolicyEngine, PolicyStore
from agentwallet.xbt402 import Xbt402Session

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelError, ChannelParams  # noqa: E402
from xbt402.x402_channel import receipt_message, request_digest, settlement_response, SCHEME  # noqa: E402

DEST = "http://127.0.0.1:9"
NET = "bip122:" + "11" * 16
URL = "http://127.0.0.1:9/agp015/echo"


def funded_book(tmp: Path) -> ChannelBook:
    book = ChannelBook(tmp / "channels.json", tmp / "channel_keys.json")
    secret = secrets.randbelow(ecc.N - 1) + 1
    payee = secrets.randbelow(ecc.N - 1) + 1
    p = ChannelParams.derive(ecc.pubkey(payee).hex(), ecc.pubkey(secret).hex(), 5_000, 0, network=NET)
    p.funding_txid = "11" * 32
    p.funding_vout = 0
    p.capacity = 10_000
    book.add_funded(DEST, secret=secret, params=p, cap_sats=10_000)
    return book


class ReviewWTests(unittest.TestCase):
    def test_w1_a_seller_reporting_zero_still_books_the_signed_delta(self):
        tmp = Path(tempfile.mkdtemp())
        book = funded_book(tmp)
        booked = []

        def spend(dest, delta, chan, cum):
            booked.append((dest, delta, chan, cum))

        s = Xbt402Session(book, hot=None, rpc=None, height=lambda: 1000)
        s.set_spend_book(spend)
        rec, _sig = book.increment(DEST, 500)
        delta = s._book_unbooked(DEST)
        self.assertGreater(delta, 0)
        self.assertEqual(delta, rec.used_sats)
        self.assertEqual(booked, [(DEST, rec.used_sats, rec.chan, rec.used_sats)])
        self.assertEqual(s._book_unbooked(DEST), 0, "the same cum is not booked twice")
        self.assertEqual(book.get(DEST).ledger_booked_sats, rec.used_sats)

    def test_w1_w2_a_huge_min_capacity_and_a_zero_receipt_are_stopped_by_the_owners_cap(self):
        tmp = Path(tempfile.mkdtemp())
        s = Xbt402Session(ChannelBook(tmp / "c.json", tmp / "k.json"), hot=None, rpc=None, height=lambda: 1000)
        extra = {"minCapacity": "1000000000", "maxCapacity": "1000000000", "minExpiryBlocks": "10",
                 "maxExpiryBlocks": "5000", "closeFeeSat": "600", "derivation": "v2"}
        acc = {"scheme": SCHEME, "network": NET, "amount": "500", "payTo": ecc.pubkey(0xB0B).hex(), "extra": extra}
        with self.assertRaises(ChannelError) as err:
            s.open_from_offer(DEST, acc, cap_sats=9_400, expiry_blocks=100)
        self.assertEqual(err.exception.code, "min_capacity")
        self.assertIn("minCapacity", str(err.exception))
        self.assertEqual(s.book.list_public(), [])

    def test_w1_a_negative_or_oversized_charged_is_refused(self):
        sk = secrets.randbelow(ecc.N - 1) + 1
        pk = ecc.pubkey(sk)
        rec = type("R", (), {"chan": "aa" * 32 + ":0", "payee_pub": pk.hex(), "used_sats": 546})()
        req = request_digest("GET", "/agp015/echo", b"")

        def resp(charged: str):
            r = {"scheme": SCHEME, "chan": rec.chan, "seq": "1", "cum": "546", "charged": charged,
                 "spentMsat": "0", "req": req}
            r["sig"] = ecc.sign(sk, receipt_message(r)).hex()
            return settlement_response(r, NET, pk.hex(), True)

        with self.assertRaises(ChannelError) as neg:
            Xbt402Session.check_seller_receipt(rec, resp("-5"), "GET", URL, b"", 500)
        self.assertEqual(neg.exception.code, "bad_receipt")
        self.assertIn("negative", str(neg.exception))
        with self.assertRaises(ChannelError) as over:
            Xbt402Session.check_seller_receipt(rec, resp("9000"), "GET", URL, b"", 500)
        self.assertIn("exceeds", str(over.exception))
        self.assertEqual(Xbt402Session.check_seller_receipt(rec, resp("0"), "GET", URL, b"", 500), 0)

    def test_a_negative_entry_is_refused_and_a_negative_log_does_not_open(self):
        tmp = Path(tempfile.mkdtemp())
        eng = PolicyEngine(PolicyConfig(allowlist=frozenset({DEST}), max_per_tx_sats=1000, daily_budget_sats=6000,
                                         weekly_budget_sats=6000, per_counterparty_cap_sats=9400),
                           PolicyStore(tmp / "ledger.json"), AuditLog(tmp / "audit.jsonl"))
        with self.assertRaises(LogError):
            eng.commit(Payment(dest=DEST, amount_sats=-5), txid="n")
        bad = Path(tempfile.mkdtemp())
        (bad / "ledger.payments.jsonl").write_text(
            '{"kind":"payments","v":1}\n'
            '{"dest":"http://seller","amount_sats":-5,"ts":1.0,"txid":"n","memo":""}\n')
        (bad / "ledger.json").write_text('{"approvals":{},"payments_log":"ledger.payments.jsonl"}')
        with self.assertRaises(LogError):
            PolicyStore(bad / "ledger.json")


if __name__ == "__main__":
    unittest.main()
