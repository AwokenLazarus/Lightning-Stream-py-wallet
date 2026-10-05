"""AGP-055: the lock path writes only what changed, and a crash at any write step loses nothing signed.

  * the keys file is not rewritten by a lock (or any state), only when a key is added or dropped;
  * a resolved lock is booked once per key, and a restart books one a crash left unbooked;
  * routed-spend rows and ledger payments are appended (applog.py): one line, one fsync, no rename;
  * a torn last line is cut off at open, a damaged complete line refuses to load, compaction is
    atomic, and old-format files are converted once (and again safely after a crash in between);
  * `Crash`: every os.write / os.fsync / os.replace / os.ftruncate of a lock (sign_state_adaptor +
    resolve_lock) is made the last thing the process does, in turn, both cleanly and with the write
    torn in half. The wallet is then opened again from its files and checked.
"""

from __future__ import annotations

import json
import os
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
import tempfile

from agentwallet import applog
from agentwallet.applog import AppendLog, LogError
from agentwallet.policy import LedgerEntry, PolicyStore
from agentwallet.routing import DAY_S, RouteSpend, adaptor_mod, point_add
from agentwallet import policy as policy_mod, routing as routing_mod
from agentwallet.sigaudit import check_chain

from lock_io import HUB, Count, lock, rig

A = adaptor_mod()


class Crash(BaseException):
    """The process died here. Not an Exception: no handler in the wallet may swallow it."""


@contextmanager
def crash_at(step: int, *, torn: bool = False):
    """Let `step` write-path syscalls through, then die at the next one. With `torn`, a dying
    os.write first lands half its bytes. Yields a counter: .n is the syscalls seen."""
    real = {k: getattr(os, k) for k in ("write", "fsync", "replace", "ftruncate")}

    class Seen:
        n = 0
    seen = Seen()

    def wrap(name):
        def f(*a, **k):
            seen.n += 1
            if seen.n > step >= 0:
                if torn and name == "write":
                    real["write"](a[0], bytes(a[1])[:max(1, len(a[1]) // 2)])
                raise Crash(f"{name} (step {seen.n})")
            return real[name](*a, **k)
        return f
    for k in real:
        setattr(os, k, wrap(k))
    try:
        yield seen
    finally:
        for k, v in real.items():
            setattr(os, k, v)


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="agp055-t-"))


class Log(unittest.TestCase):
    def test_torn_last_line_is_cut_at_every_length_and_the_next_row_lands_clean(self):
        line = applog._line({"at": 1.5, "amount": 7})
        for cut in range(1, len(line)):
            p = tmpdir() / "x.jsonl"
            a = AppendLog(p, "k")
            a.append({"at": 1.0, "amount": 1})
            a.close()
            with open(p, "ab") as f:
                f.write(line[:cut])                       # a crash mid-append: no newline yet
            b = AppendLog(p, "k")
            self.assertEqual((b.take_rows(), b.torn_bytes), ([{"at": 1.0, "amount": 1}], cut))
            b.append({"at": 2.0, "amount": 2})
            b.close()
            self.assertEqual(AppendLog(p, "k").take_rows(), [{"at": 1.0, "amount": 1}, {"at": 2.0, "amount": 2}])

    def test_a_damaged_complete_line_or_another_header_refuses_to_load(self):
        p = tmpdir() / "x.jsonl"
        a = AppendLog(p, "k")
        a.append({"n": 1})
        a.close()
        good = p.read_bytes()
        p.write_bytes(good + b'{"n": 2\n' + applog._line({"n": 3}))
        with self.assertRaises(LogError):
            AppendLog(p, "k")                             # never "the rows before the damage"
        p.write_bytes(good + b"[1]\n")
        with self.assertRaises(LogError):
            AppendLog(p, "k")
        p.write_bytes(good)
        with self.assertRaises(LogError):
            AppendLog(p, "other")
        p.write_bytes(b'{"resolved": []}\n')
        with self.assertRaises(LogError):
            AppendLog(p, "k")

    def test_a_crash_at_every_step_of_create_and_compact_leaves_a_whole_log(self):
        for torn in (False, True):
            step = 0
            while True:                                   # creation
                p = tmpdir() / "x.jsonl"
                try:
                    with crash_at(step, torn=torn):
                        AppendLog(p, "k").close()
                    break
                except Crash:
                    self.assertEqual(AppendLog(p, "k").take_rows(), [], f"create step {step} torn={torn}")
                step += 1
            old, new = [{"n": i} for i in range(5)], [{"n": 3}, {"n": 4}]
            step = 0
            while True:                                   # compaction: the old rows or the new, whole
                p = tmpdir() / "x.jsonl"
                a = AppendLog(p, "k")
                for r in old:
                    a.append(r)
                try:
                    with crash_at(step, torn=torn):
                        a.compact(new)
                    self.assertEqual(AppendLog(p, "k").take_rows(), new)
                    break
                except Crash:
                    self.assertIn(AppendLog(p, "k").take_rows(), (old, new), f"compact step {step} torn={torn}")
                step += 1
            self.assertGreater(step, 2)


class Spend(unittest.TestCase):
    def test_add_appends_one_line_with_one_fsync_and_no_rename(self):
        p = tmpdir() / "routing.json"
        s = RouteSpend(p)
        now = time.time()
        s.add({"at": now, "amount": 5, "chan": "c"})
        size = p.stat().st_size
        with Count() as c:
            s.add({"at": now, "amount": 6, "chan": "c"})
        self.assertEqual((c.fsync, c.replace), (1, 0))
        self.assertEqual(p.read_bytes()[size:], applog._line({"at": now, "amount": 6, "chan": "c"}))
        self.assertEqual(RouteSpend(p).since(now - 1), 11)

    def test_old_format_is_converted_once_and_a_crash_in_between_keeps_every_row(self):
        now = time.time()
        rows = [{"at": now - 10, "amount": 3, "chan": "c"}, {"at": now - 5, "amount": 4, "chan": "c"}]
        step = 0
        while True:
            p = tmpdir() / "routing.json"
            p.write_text(json.dumps({"resolved": rows}))
            try:
                with crash_at(step, torn=True):
                    RouteSpend(p)
                break
            except Crash:
                self.assertEqual(RouteSpend(p).since(now - DAY_S), 7, f"step {step}")
            step += 1
        s = RouteSpend(p)
        self.assertEqual(s.since(now - DAY_S), 7)
        self.assertEqual(p.read_bytes().split(b"\n")[0], applog.header("route-spend").rstrip())

    def test_window_is_bounded_and_the_file_is_compacted(self):
        p = tmpdir() / "routing.json"
        now = time.time()
        old_every, routing_mod.PRUNE_EVERY = routing_mod.PRUNE_EVERY, 8
        self.addCleanup(setattr, routing_mod, "PRUNE_EVERY", old_every)
        s = RouteSpend(p)
        for i in range(40):                               # 8 days old: outside the 7 day window
            s.add({"at": now - 8 * DAY_S, "amount": 1, "chan": "old"})
        for i in range(4):
            s.add({"at": now, "amount": 10, "chan": "new"})
        for i in range(8):
            s.add({"at": now, "amount": 10, "chan": "new"})
        self.assertEqual(len(s.rows), 12)                 # memory: the window only
        lines = len(p.read_bytes().splitlines()) - 1      # file: compacted, at most 2 x live + PRUNE_EVERY
        self.assertTrue(12 <= lines <= 2 * 12 + 8 < 52, lines)
        self.assertEqual(RouteSpend(p).since(now - DAY_S), 120)
        with open(p, "ab") as f:
            f.write(b'{"at": 1')                          # a torn row
        self.assertEqual(RouteSpend(p).since(now - DAY_S), 120)


class Ledger(unittest.TestCase):
    def entry(self, i, ts=None):
        return LedgerEntry(dest="http://api.test", amount_sats=10 + i, ts=ts or 1000.0 + i, txid=f"t{i}", memo="m")

    def test_commit_appends_one_line_and_does_not_grow_with_the_ledger(self):
        d = tmpdir()
        s = PolicyStore(d / "ledger.json")
        for i in range(50):
            s.commit(self.entry(i))
        before = (d / "ledger.json").read_bytes()
        size = s.log_path.stat().st_size
        with Count() as c:
            s.commit(self.entry(50))
        self.assertEqual((c.fsync, c.replace), (1, 0))
        self.assertLess(s.log_path.stat().st_size - size, 120)
        self.assertEqual((d / "ledger.json").read_bytes(), before)   # the approvals file is not touched
        self.assertNotIn("payments", json.loads(before))             # no empty list a reader could trust
        self.assertEqual([e.txid for e in PolicyStore(d / "ledger.json").payments()], [f"t{i}" for i in range(51)])

    def test_old_ledger_moves_to_the_log_and_a_crash_at_any_step_loses_or_doubles_nothing(self):
        rows = [{"dest": "d", "amount_sats": 5, "ts": 7.0, "txid": "same", "memo": ""}] * 2 + \
               [{"dest": "d", "amount_sats": 9, "ts": 8.0, "txid": "x", "memo": ""}]
        step = 0
        while True:
            d = tmpdir()
            (d / "ledger.json").write_text(json.dumps({"payments": rows, "approvals": {"tok": {"dest": "d"}}}))
            try:
                with crash_at(step, torn=True):
                    PolicyStore(d / "ledger.json")
                break
            except Crash:
                pass
            s = PolicyStore(d / "ledger.json")            # the restart finishes the move
            self.assertEqual(sorted(e.amount_sats for e in s.payments()), [5, 5, 9], f"step {step}")
            self.assertEqual(s.get_approval("tok"), {"dest": "d"})
            step += 1
        self.assertGreater(step, 3)
        s = PolicyStore(d / "ledger.json")
        self.assertEqual(sorted(e.amount_sats for e in s.payments()), [5, 5, 9])
        self.assertEqual(json.loads((d / "ledger.json").read_text()),
                         {"approvals": {"tok": {"dest": "d"}}, "payments_log": "ledger.payments.jsonl"})

    def test_retention_and_compaction(self):
        d = tmpdir()
        old_every, policy_mod.PRUNE_EVERY = policy_mod.PRUNE_EVERY, 8
        self.addCleanup(setattr, policy_mod, "PRUNE_EVERY", old_every)
        s = PolicyStore(d / "ledger.json")
        s.retain_s = 100.0
        for i in range(40):
            s.commit(self.entry(i, ts=1000.0 + i))
        for i in range(40, 48):
            s.commit(self.entry(i, ts=5000.0 + i))
        self.assertEqual([e.txid for e in s.payments()], [f"t{i}" for i in range(40, 48)])
        self.assertEqual(len(s.log_path.read_bytes().splitlines()), 1 + 8)
        keep_all = PolicyStore(tmpdir() / "ledger.json")  # no engine, no retain_s: nothing is dropped
        for i in range(40):
            keep_all.commit(self.entry(i, ts=float(i)))
        self.assertEqual(len(keep_all.payments()), 40)

    def test_amend_lines_from_the_rust_signer_are_applied(self):
        d = tmpdir()
        s = PolicyStore(d / "ledger.json")
        for i in range(3):
            s.commit(self.entry(i))
        with open(s.log_path, "ab") as f:
            f.write(applog._line({"amend": "t1", "amount_sats": 99}) + applog._line({"amend": "t2", "amount_sats": None}))
        self.assertEqual([(e.txid, e.amount_sats) for e in PolicyStore(d / "ledger.json").payments()],
                         [("t0", 10), ("t1", 99)])
        with open(s.log_path, "ab") as f:
            f.write(applog._line({"amend": "nope", "amount_sats": 1}))
        with self.assertRaises(LogError):
            PolicyStore(d / "ledger.json")


class Keys(unittest.TestCase):
    def test_a_lock_does_not_rewrite_the_keys_file_and_a_new_key_does(self):
        for setup in ("keyfile", "passphrase", "bare"):
            with self.subTest(setup):
                r = rig(setup)
                keys = r.d / "channel_keys.json"
                before, ino = keys.read_bytes(), keys.stat().st_ino
                _, y = lock(r.rs, r.chan, 1000, "L1")
                r.rs.resolve_lock(r.chan, y)
                r.book.sign_state(HUB, 1500)
                r.book.fresh_seq(HUB)
                self.assertEqual((keys.read_bytes(), keys.stat().st_ino), (before, ino))
                secret, pub = r.book.new_payer_key()
                from _agp013 import FakeRpc, fund_channel
                fund_channel(r.book, FakeRpc(), "http://other.test", secret=0xB0B0)
                self.assertNotEqual(keys.read_bytes(), before)
                again = rig(setup, d=r.d, ks=r.ks, chan=r.chan)   # both keys open after a restart
                again.book.sign_close(HUB)
                again.book.sign_close("http://other.test")

    def test_fsyncs_per_lock(self):
        want = {"bare": 5, "keyfile": 9}                  # 2 of each: the directory fsync after a records rename
        for setup, n in want.items():
            r = rig(setup)
            _, y = lock(r.rs, r.chan, 1000, "warm")
            r.rs.resolve_lock(r.chan, y)
            with Count() as c:
                _, y = lock(r.rs, r.chan, 1010, "L")
                r.rs.resolve_lock(r.chan, y)
            self.assertEqual((setup, c.fsync), (setup, n))


class CrashAtEveryStep(unittest.TestCase):
    CUM = 2000

    def one(self, step: int, torn: bool) -> tuple[bool, int]:
        """A wallet with one resolved lock; the next lock dies at `step`. Returns (lock finished, syscalls)."""
        r = rig("keyfile", ledger=2)
        first, y = lock(r.rs, r.chan, 1000, "L0")
        r.rs.resolve_lock(r.chan, y)
        seq0 = r.book.get(HUB).seq
        spent0, paid0 = r.rs.spend.since(0), len(r.rs.engine.store.payments())
        out = secret = None
        resolved = False
        tag = f"step {step} torn={torn}"
        try:
            with crash_at(step, torn=torn) as seen:
                out, secret = lock(r.rs, r.chan, self.CUM, "L1")
                r.rs.resolve_lock(r.chan, secret)
                resolved = True
        except Crash:
            pass
        r.rs.spend._log.close()
        r.rs.engine.store._log.close()

        b = rig("keyfile", d=r.d, ks=r.ks, chan=r.chan)   # the restart: every file loads
        rec = b.book.get(HUB)
        lk = rec.pending_lock
        self.assertTrue(check_chain(b.d / "signatures.jsonl")["ok"], tag)
        self.assertGreaterEqual(rec.seq, seq0, tag)
        if out is not None:                               # a pre-signature left: its record is durable
            self.assertTrue(rec.used_sats == self.CUM or lk.get("pre") == out["adaptor"], tag)
        if lk:                                            # a pending lock is whole, and logged
            self.assertEqual(int(lk["cum"]), self.CUM, tag)
            self.assertEqual(point_add(A.dec(bytes.fromhex(lk["T"])), A.point_of(int(lk["r"], 16))),
                             A.dec(bytes.fromhex(lk["T1"])), tag)
            self.assertEqual(rec.used_sats, 1000, tag)
            rows = [json.loads(x) for x in (b.d / "signatures.jsonl").read_text().splitlines()]
            self.assertTrue(any(x["kind"] == "adaptor_presig" and x.get("cum") == self.CUM for x in rows), tag)
            with self.assertRaises(Exception) as e:       # never a second pre-signature for a state
                lock(b.rs, b.chan, self.CUM, "again")
            self.assertEqual(e.exception.code, "lock_outstanding", tag)
        elif rec.used_sats != self.CUM:
            self.assertEqual(rec.used_sats, 1000, tag)    # nothing happened
        spent, paid = b.rs.spend.since(0) - spent0, len(b.rs.engine.store.payments()) - paid0
        if resolved:
            self.assertEqual((rec.used_sats, lk), (self.CUM, {}), tag)
        # a resolve that reached disk is booked exactly once in both budgets, whether the rows were
        # written before the crash or by the restart (b.rs.recovered_bookings); nothing else is booked
        want = (1000, 1) if rec.used_sats == self.CUM else (0, 0)
        self.assertEqual((spent, paid), want, tag)
        again = rig("keyfile", d=r.d, ks=r.ks, chan=r.chan)   # a second restart books nothing more
        self.assertEqual((again.rs.recovered_bookings, again.rs.spend.since(0) - spent0), (0, want[0]), tag)
        again.rs.spend._log.close()
        again.rs.engine.store._log.close()
        b = rig("keyfile", d=r.d, ks=r.ks, chan=r.chan)

        # the wallet goes on: finish or replace the lock; no nonce and no tweak is used twice
        if lk and secret:
            b.rs.resolve_lock(b.chan, secret)
        elif lk:                                          # on disk, but it never left: the caller gives it up
            b.rs.void_lock(b.chan)
        nxt, y = lock(b.rs, b.chan, self.CUM + 500, "L2")
        b.rs.resolve_lock(b.chan, y)
        pres = [first, nxt] + ([out] if out else []) + ([{"adaptor": lk["pre"], "tweak": lk["r"]}] if lk else [])
        uniq = {(p["adaptor"]["R1"], p["tweak"]) for p in pres}
        self.assertEqual(len({u[0] for u in uniq}), len(uniq), tag)
        self.assertEqual(len({u[1] for u in uniq}), len(uniq), tag)
        self.assertEqual(b.book.get(HUB).used_sats, self.CUM + 500, tag)
        self.assertTrue(check_chain(b.d / "signatures.jsonl")["ok"], tag)
        return resolved, seen.n

    def test_crash_at_every_write_step_of_a_lock(self):
        for torn in (False, True):
            step, total = 0, None
            while True:
                done, n = self.one(step, torn)
                if done:
                    total = n
                    break
                step += 1
            self.assertEqual(step, total)                 # every syscall of the lock was the last one once
            self.assertEqual(total, 9 + 7 + 2)            # 9 fsyncs, 7 writes, 2 renames


if __name__ == "__main__":
    unittest.main()
