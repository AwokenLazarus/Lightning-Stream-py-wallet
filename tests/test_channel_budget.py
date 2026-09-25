"""Channel-as-budget: cap, increment, concurrent pays cannot overshoot."""

from __future__ import annotations

import secrets
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook, ChannelCapError

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelParams  # noqa: E402
from xbt402.x402_channel import close_message  # noqa: E402

DEST = "bcrt1qmerchant0000000000000000000000000000qq"

NET = "bip122:" + "11" * 16   # xbt402 v1.1 derives the payee key per network (the test providers' id)


def funded_book(tmp: Path, cap: int = 10_000, dest: str = DEST) -> tuple[ChannelBook, int]:
    book = ChannelBook(tmp / "channels.json", tmp / "channel_keys.json")
    secret = secrets.randbelow(ecc.N - 1) + 1
    payee = secrets.randbelow(ecc.N - 1) + 1
    p = ChannelParams.derive(ecc.pubkey(payee).hex(), ecc.pubkey(secret).hex(), 5_000, 0, network=NET)
    p.funding_txid = "11" * 32
    p.funding_vout = 0
    p.capacity = cap
    book.add_funded(dest, secret=secret, params=p, cap_sats=cap)
    return book, cap


class ChannelBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.book, self.cap = funded_book(self.tmp)

    def test_increment_and_list(self):
        rec, sig = self.book.increment(DEST, 1_000)
        self.assertEqual(rec.used_sats, 1_000)
        self.assertTrue(sig)
        self.assertEqual(sig[-1], 0x21)
        pub = self.book.list_public()
        self.assertEqual(len(pub), 1)
        self.assertEqual(pub[0]["used_sats"], 1_000)
        self.assertEqual(pub[0]["cap_sats"], self.cap)
        self.assertEqual(pub[0]["residual_sats"], self.cap - 1_000)
        blob = (self.tmp / "channel_keys.json").read_text()
        self.assertNotIn("secret", pub[0])

    def test_cap_refuses_overshoot(self):
        self.book.increment(DEST, 9_000)
        with self.assertRaises(ChannelCapError):
            self.book.increment(DEST, 2_000)
        self.assertEqual(self.book.get(DEST).used_sats, 9_000)

    def test_exact_cap_ok(self):
        rec, _ = self.book.increment(DEST, self.cap)
        self.assertEqual(rec.used_sats, self.cap)
        with self.assertRaises(ChannelCapError):
            self.book.increment(DEST, 1)

    def test_concurrent_cannot_exceed_cap(self):
        errors = []
        ok = []

        def one(_i):
            try:
                rec, _ = self.book.increment(DEST, 1_000)
                ok.append(rec.used_sats)
            except ChannelCapError:
                errors.append("cap")

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(one, range(20)))
        self.assertEqual(self.book.get(DEST).used_sats, self.cap)
        self.assertEqual(len(ok), 10)
        self.assertEqual(len(errors), 10)

    def test_public_list_has_no_keys(self):
        rec = self.book.get(DEST)
        pub = rec.public()
        joined = " ".join(f"{k}={v}" for k, v in pub.items())
        self.assertNotIn("secret", joined)
        self.assertNotIn(rec.payer_pub, "")  # pubkeys of the channel are ok on chain later
        self.assertTrue(self.book.has(DEST))

    def test_sign_close_and_find_dest(self):
        rec = self.book.get(DEST)
        sig = self.book.sign_close(DEST)
        self.assertTrue(ecc.verify(bytes.fromhex(rec.payer_pub), close_message(rec.chan), bytes.fromhex(sig)))
        self.assertEqual(self.book.find_dest(DEST), DEST)
        self.assertEqual(self.book.find_dest(rec.chan), DEST)


class ChannelLockSmoke(unittest.TestCase):
    def test_lock_is_reentrant_safe_for_list_during_increment(self):
        tmp = Path(tempfile.mkdtemp())
        book, _ = funded_book(tmp, cap=50_000)
        seen = []

        def reader():
            for _ in range(50):
                seen.append(len(book.list_public()))

        t = threading.Thread(target=reader)
        t.start()
        for _ in range(10):
            book.increment(DEST, 1_000)
        t.join()
        self.assertTrue(seen)
        self.assertEqual(book.get(DEST).used_sats, 10_000)


if __name__ == "__main__":
    unittest.main()
