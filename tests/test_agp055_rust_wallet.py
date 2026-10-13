"""B2 opens a wallet directory the Rust signer wrote while both still signed routed locks (ledger +
payments log with the Rust-only amend lines, channel records with a pending lock), and treats what
the retired routed signing left behind as the Rust signer does (AGP-128):

  * the ledger reads as Rust wrote it, amend lines applied;
  * the channel record keeps its pending lock, its given-up locks and its resolved bookings as
    they were written: nothing completes, gives up or books a lock any more;
  * no plain state is signed below the pending lock's amount; one at or above it is signed, and the
    lock is then no longer pending.

`fixtures/rust_routed_wallet.json` was written by the Rust workspace's
`XBT_GEN_VECTORS=1 cargo test -p xbt-signer --test custody_compat writes_a_routed_wallet_for_b2`
before the hub was retired. The wallet is opened as of the minute it was written.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook
from agentwallet.keystore import KeyStore
from agentwallet.policy import AuditLog, PolicyConfig, PolicyEngine, PolicyStore

ensure_b1()
from xbt402.channel import ChannelError  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "rust_routed_wallet.json"


class RustWallet(unittest.TestCase):
    def setUp(self):
        self.v = json.loads(FIXTURE.read_text())
        self.d = Path(tempfile.mkdtemp(prefix="agp055-rust-"))
        for f in ("channels.json", "channel_keys.json", "ledger.json"):
            (self.d / f).write_text(json.dumps(self.v[f]))
        for f in ("routing.json", "ledger.payments.jsonl"):
            (self.d / f).write_text(self.v[f])
        clock = mock.patch("time.time", return_value=self.v["created"] + 60)
        clock.start()
        self.addCleanup(clock.stop)

    def start(self):
        ks = KeyStore(key=bytes.fromhex(self.v["keyfile_hex"]))
        book = ChannelBook(self.d / "channels.json", self.d / "channel_keys.json", keystore=ks)
        cfg = PolicyConfig(allowlist=frozenset({self.v["hub"]}), velocity_max=100)
        return book, PolicyEngine(cfg, PolicyStore(self.d / "ledger.json"), AuditLog(self.d / "audit.jsonl"))

    def on_disk(self):
        return json.loads((self.d / "channels.json").read_text())["channels"][self.v["hub"]]

    def test_the_ledger_and_the_record_read_as_rust_wrote_them(self):
        v, hub = self.v, self.v["hub"]
        book, engine = self.start()
        ln = {e.txid: e.amount_sats for e in engine.store.payments() if e.txid.startswith("ln:")}
        self.assertEqual(ln, {v["ln"]["txid"]: v["ln"]["amount"]})  # one amended to 7, one dropped
        # the lock Rust had booked is in the ledger; the one it had resolved and not yet booked is
        # booked by nothing now (docs/LIMITS.md)
        locks = [(e.txid, e.amount_sats) for e in engine.store.payments() if e.txid.startswith("lock:")]
        self.assertEqual(locks, [(v["booked"]["key"], v["booked"]["amount"])])
        rec = book.get(hub)
        self.assertEqual((rec.used_sats, rec.pending_lock["cum"], len(rec.resolved)), (1500, 1800, 2))
        self.assertEqual(rec.pending_lock["pre"], v["pending"]["adaptor"])
        self.assertEqual((self.d / "routing.json").read_text(), v["routing.json"], "the routed-spend log is left as it is")
        self.assertEqual((self.d / "ledger.payments.jsonl").read_text(), v["ledger.payments.jsonl"])

    def test_no_plain_state_is_signed_below_the_pending_lock_and_one_above_it_ends_it(self):
        v, hub = self.v, self.v["hub"]
        book, _ = self.start()
        was = self.on_disk()
        for sign in (lambda: book.sign_state(hub, 1700), lambda: book.increment(hub, 100)):
            with self.assertRaises(ChannelError) as c:
                sign()
            self.assertEqual(c.exception.code, "lock_outstanding")
        self.assertEqual(self.on_disk(), was, "a refused state changes nothing on disk")
        for name in ("sign_state_adaptor", "resolve_lock", "void_lock", "adopt_lock", "recover_lock"):
            self.assertFalse(hasattr(book, name), name)
        self.assertTrue(book.sign_state(hub, 1800), "a plain state at the locked amount is signed")
        now = self.on_disk()
        self.assertEqual((now["used_sats"], now["pending_lock"]), (1800, {}))
        self.assertEqual((now["resolved"], now["given_up"]), (was["resolved"], was["given_up"]), "kept as they were written")
        self.assertEqual(sorted(now), sorted(v["channels.json"]["channels"][hub]), "the record keeps its field set")


if __name__ == "__main__":
    unittest.main()
