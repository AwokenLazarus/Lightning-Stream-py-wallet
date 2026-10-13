"""AGP-055: the wallet's append-only files (the log format and the policy ledger).

  * ledger payments are appended (applog.py): one line, one fsync, no rename;
  * a torn last line is cut off at open, a damaged complete line refuses to load, compaction is
    atomic, and an old-format ledger is converted once (and again safely after a crash in between);
  * `Crash`: a write step is made the last thing the process does, both cleanly and with the write
    torn in half, and the file is then opened again and checked.

The routed-lock half of this file (the routed-spend log, the keys file under a lock, a crash at
every write step of a lock) went with the routed signing it tested (AGP-128); the file keeps its name.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from agentwallet import applog
from agentwallet import policy as policy_mod
from agentwallet.applog import AppendLog, LogError
from agentwallet.policy import LedgerEntry, PolicyStore


class Count:
    """How many fsyncs and renames a block of code makes."""

    def __init__(self):
        self.fsync = self.replace = 0
        self._f, self._r = os.fsync, os.replace

    def __enter__(self):
        def fsync(fd):
            self.fsync += 1
            return self._f(fd)

        def replace(*a, **k):
            self.replace += 1
            return self._r(*a, **k)
        os.fsync, os.replace = fsync, replace
        return self

    def __exit__(self, *exc):
        os.fsync, os.replace = self._f, self._r


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


if __name__ == "__main__":
    unittest.main()
