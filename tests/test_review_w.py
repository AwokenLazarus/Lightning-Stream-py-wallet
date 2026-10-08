"""AGP-063 W1 and W2: the seller does not decide the budget, and minCapacity cannot raise the cap.
W3: nothing on the agent socket sends coins anywhere but a policy-bound channel, nor rotates for the
human. K1: the scrypt cost is recorded per blob and a keyfile open to others is refused.

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
from agentwallet.keystore import KeyStore, KeyStoreError, SCRYPT_LOG_N, SCRYPT_LOG_N_LEGACY, load_or_create_keyfile
from agentwallet.signer import Signer
from agentwallet.xbt402 import Xbt402Session

from _agp013 import HUMAN_PRIV, HUMAN_PUB, FakeRpc, keyfile_env, rotate_hot_key, write_policy

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


API = "http://api.test"


def ledger_sum(s: Signer) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


def rule(r: dict) -> str:
    return r.get("rule", "")


class ReviewWSignerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        write_policy(self.tmp, per_counterparty_cap_sats=100_000, split_window_s=0, human_pubkey=HUMAN_PUB.hex())
        self.rpc = FakeRpc(height=1000)
        self.s = Signer(self.tmp, rpc=self.rpc)
        self.s.hot.notice_utxo("aa" * 32, 0, 300_000)

    def test_w1_a_channel_payment_books_the_signed_delta_ahead_of_the_signature(self):
        r = self.s.handle({"method": "pay", "params": {"to": API, "amount_sats": 100, "memo": "a"}})
        self.assertEqual((r["verdict"], r["rail"]), ("allow", "channel"), r)
        floor = r["cum"]
        self.assertGreater(floor, 100, "the first state is the dust floor")
        self.assertEqual(ledger_sum(self.s), floor, "the ledger holds the signed floor, not the 100 asked")
        r = self.s.handle({"method": "pay", "params": {"to": API, "amount_sats": 100, "memo": "b"}})
        self.assertEqual((r["verdict"], r["cum"]), ("allow", floor), r)
        self.assertEqual(ledger_sum(self.s), floor, "a charge inside the signed floor books nothing new")
        r = self.s.handle({"method": "pay", "params": {"to": API, "amount_sats": 400, "memo": "c"}})
        self.assertEqual(r["cum"], 600, r)
        self.assertEqual(ledger_sum(self.s), 600)
        self.assertIn(f"xbt402:{r['chan']}:600", [e.txid for e in self.s.engine.store.payments()])

    def test_w3_fund_pays_only_a_channel_for_an_issued_key_to_the_sellers_verified_terms(self):
        r = self.s.handle({"method": "fund", "params": {"address": "bcrt1qattacker", "sats": 5_000}})
        self.assertEqual(rule(r), "fund_unbound", r)
        p = ChannelParams.derive(ecc.pubkey(0xB0B).hex(), ecc.pubkey(0xC0DE).hex(), 1100, 600, network=NET)
        r = self.s.handle({"method": "fund", "params": {"origin": API, "params": p.to_dict(), "sats": 5_000}})
        self.assertEqual(rule(r), "bad_key", r)
        self.assertEqual(self.rpc.sent, [], "nothing was funded")

    def test_w3_open_channel_takes_pay_to_only_from_the_policy(self):
        attacker = ecc.pubkey(0xBAD).hex()
        for params, want in [({"dest": API, "pay_to": attacker}, "pay_to"), ({"dest": API, "cap_sats": 100_001}, "channel_cap"),
                             ({"dest": API, "expiry_blocks": 100_000}, "expiry"), ({"dest": API, "close_fee": 1_000_000}, "close_fee"),
                             ({"dest": "http://127.0.0.1:1"}, "allowlist")]:
            self.assertEqual(rule(self.s.handle({"method": "open_channel", "params": params})), want, params)
        self.assertEqual(self.rpc.sent, [], "nothing was funded")
        r = self.s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 10_000}})
        self.assertEqual(r["verdict"], "allow", r)

    def test_w3_rotate_hot_key_and_deny_approval_need_the_human_signature(self):
        # B2 has no deny_approval (the web UI is the Rust signer's); the name stays the Rust test's
        from agentwallet.approval import b2x, generate_keypair, rotate_message, sign

        before = self.s.hot.address
        exp = int(self.s.engine.clock()) + 600
        other, _ = generate_keypair()
        for params in [{}, {"expiry": exp, "signature": "zz"},
                       {"expiry": exp, "signature": b2x(sign(other, rotate_message(before, exp)))},
                       {"expiry": exp, "signature": b2x(sign(HUMAN_PRIV, rotate_message(before, exp + 1)))}]:
            self.assertEqual(rule(self.s.handle({"method": "rotate_hot_key", "params": params})), "human_sig", params)
        old = int(self.s.engine.clock()) - 1
        r = self.s.handle({"method": "rotate_hot_key",
                           "params": {"expiry": old, "signature": b2x(sign(HUMAN_PRIV, rotate_message(before, old)))}})
        self.assertEqual(rule(r), "expired", r)
        self.assertEqual(self.s.hot.address, before)
        r = rotate_hot_key(self.s)
        self.assertEqual(r["old_address"], before, r)
        self.assertNotEqual(self.s.hot.address, before)
        self.assertEqual(self.s.sigaudit.read()[-1]["rule"], "human:rotate_signature")


class ReviewK1Tests(unittest.TestCase):
    def test_k1_scrypt_cost_is_recorded_per_blob(self):
        ks = KeyStore(passphrase=b"pw")
        blob = ks.seal(b"x", "a")
        self.assertEqual((blob["log_n"], SCRYPT_LOG_N), (17, 17))
        legacy = {k: v for k, v in blob.items() if k != "log_n"}
        with self.assertRaises(KeyStoreError):
            KeyStore(passphrase=b"pw").open(legacy, "a")
        salt = bytes.fromhex(blob["salt"])
        old = KeyStore(key=ks._wrap_key(salt, SCRYPT_LOG_N_LEGACY)).seal(b"old", "a", salt=salt)
        old["kdf"] = "scrypt"
        self.assertEqual(KeyStore(passphrase=b"pw").open(old, "a"), b"old")
        for bad in (14, 19, 30, 255, "17", 17.0):
            with self.assertRaisesRegex(KeyStoreError, "log_n"):
                KeyStore(passphrase=b"pw").open({**blob, "log_n": bad}, "a")
        self.assertNotIn("log_n", KeyStore(key=b"\x01" * 32).seal(b"x", "a"))

    def test_k1_a_keyfile_open_to_others_or_a_symlink_is_refused(self):
        import os

        d = Path(tempfile.mkdtemp())
        p = d / "k" / "hot.key"
        k = load_or_create_keyfile(p)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        self.assertEqual(load_or_create_keyfile(p), k)
        os.chmod(p, 0o644)
        with self.assertRaisesRegex(KeyStoreError, "mode 644"):
            load_or_create_keyfile(p)
        os.chmod(p, 0o400)
        self.assertEqual(load_or_create_keyfile(p), k)
        link = d / "link.key"
        link.symlink_to(p)
        self.assertEqual(load_or_create_keyfile(link), k)
        os.chmod(p, 0o640)
        with self.assertRaisesRegex(KeyStoreError, "mode 640"):
            load_or_create_keyfile(link)
        with self.assertRaisesRegex(KeyStoreError, "not a regular file"):
            load_or_create_keyfile(d)


if __name__ == "__main__":
    unittest.main()
