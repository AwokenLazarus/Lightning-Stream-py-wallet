"""AGP-055: B2 opens a routed wallet directory the Rust signer wrote (spend log, ledger + payments
log with the Rust-only amend lines, channel records), books the lock Rust left unbooked, once, and
resolves the pending one. The other direction is xbt-rs `tests/custody_compat.rs`.

`fixtures/rust_routed_wallet.json` is xbt-rs `vectors/rust_routed_wallet.json`, written by
`XBT_GEN_VECTORS=1 cargo test -p xbt-signer --test custody_compat writes_a_routed_wallet_for_b2`.
The wallet is opened as of the minute it was written (the spend window is 7 days).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.channels import ChannelBook
from agentwallet.keystore import KeyStore
from agentwallet.policy import AuditLog, PolicyConfig, PolicyEngine, PolicyStore
from agentwallet.routing import RoutePolicy, RouteSigner

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
        engine = PolicyEngine(cfg, PolicyStore(self.d / "ledger.json"), AuditLog(self.d / "audit.jsonl"))
        return book, engine, RouteSigner(book, RoutePolicy.from_dict(self.v["routing_policy"]),
                                         state_path=self.d / "routing.json", engine=engine)

    @staticmethod
    def locks(engine):
        return [(e.txid, e.amount_sats) for e in engine.store.payments() if e.txid.startswith("lock:")]

    def test_opens_books_the_unbooked_lock_once_and_resolves_the_pending_one(self):
        v, hub = self.v, self.v["hub"]
        book, engine, rs = self.start()
        self.assertEqual(rs.recovered_bookings, 1)                # L2: resolved on disk, booked by this start
        self.assertEqual(rs.spend.since(0), 1500)
        self.assertEqual(self.locks(engine), [(v[k]["key"], v[k]["amount"]) for k in ("booked", "unbooked")])
        ln = {e.txid: e.amount_sats for e in engine.store.payments() if e.txid.startswith("ln:")}
        self.assertEqual(ln, {v["ln"]["txid"]: v["ln"]["amount"]})  # one amended to 7, one dropped
        rec = book.get(hub)
        self.assertEqual((rec.used_sats, rec.pending_lock["cum"], len(rec.resolved)), (1500, 1800, 2))
        self.assertEqual(rec.pending_lock["pre"], v["pending"]["adaptor"])
        rs.spend._log.close()
        engine.store._log.close()

        book, engine, rs = self.start()                           # a second start books nothing more
        self.assertEqual((rs.recovered_bookings, rs.spend.since(0), len(self.locks(engine))), (0, 1500, 2))
        self.assertEqual(rs.resolve_lock(v["chan"], v["pending"]["secret"]), v["pending"]["t"])
        self.assertEqual((rs.spend.since(0), book.get(hub).used_sats), (1800, 1800))
        self.assertEqual(self.locks(engine)[-1], (f"lock:{v['chan']}:1800", 300))
        for f in ("routing.json", "ledger.payments.jsonl"):       # append-only: Rust's bytes are still the head
            now = (self.d / f).read_text()
            self.assertTrue(now.startswith(v[f]) and len(now) > len(v[f]), f)
            self.assertEqual(sorted(json.loads(now.splitlines()[-1])), sorted(json.loads(v[f].splitlines()[1])), f)
        mine = json.loads((self.d / "channels.json").read_text())["channels"][hub]
        self.assertEqual(sorted(mine), sorted(v["channels.json"]["channels"][hub]))
        self.assertEqual(mine["resolved"][0], v["channels.json"]["channels"][hub]["resolved"][0])


if __name__ == "__main__":
    unittest.main()
