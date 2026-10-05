"""AGP-055: fsyncs, renames and time per routed lock (sign_state_adaptor + resolve_lock).

Counts are taken by wrapping os.fsync and os.replace (Path.replace goes through os.replace), so they
do not depend on the host. It runs unchanged on the code before AGP-055:

    cd tests && B1_ROOT=~/xbt-rnd/b1 PYTHONPATH=.. python lock_io.py [--locks 200] [--ledger 5000] [--json]
    cd tests && B1_ROOT=~/xbt-rnd/b1 PYTHONPATH=~/xbt-rnd/b2 python lock_io.py     # before (b2 master)

Setups: "bare" (no key store, no signature log, no policy engine), "keyfile" and "passphrase" (sealed
keys, signature log, policy engine with `--ledger` payments already committed).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import statistics
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from agentwallet.channels import ChannelBook
from agentwallet.keystore import KeyStore
from agentwallet.policy import AuditLog, PolicyConfig, PolicyEngine, PolicyStore
from agentwallet.routing import RoutePolicy, RouteSigner, adaptor_mod
from agentwallet.sigaudit import SigAudit

from _agp013 import FakeRpc, fund_channel

HUB = "http://hub.test"
A = adaptor_mod()


class Count:
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


@dataclass
class Rig:
    d: Path
    ks: KeyStore | None
    book: ChannelBook
    rs: RouteSigner
    chan: str
    audit: SigAudit | None


def rig(setup: str, ledger: int = 0, *, d: Path | None = None, ks: KeyStore | None = None, chan: str = "") -> Rig:
    """A funded channel to HUB under a RouteSigner. With `d` (and its `ks`, `chan`): the same wallet
    opened again from its files, as after a restart."""
    fresh = d is None
    d = Path(tempfile.mkdtemp(prefix="agp055-")) if fresh else d
    audit = engine = None
    if setup != "bare":
        if fresh:
            ks = KeyStore(key=secrets.token_bytes(32)) if setup == "keyfile" else KeyStore(passphrase=b"correct horse")
            now = time.time()
            rows = [{"dest": "http://api.test", "amount_sats": 1, "ts": now - 3600 + i * 0.001, "txid": f"t{i}",
                     "memo": ""} for i in range(ledger)]
            (d / "ledger.json").write_text(json.dumps({"payments": rows, "approvals": {}}))
        audit = SigAudit(d / "signatures.jsonl")
        cfg = PolicyConfig(allowlist=frozenset({HUB, "http://api.test"}), velocity_max=10**9,
                           daily_budget_sats=10**12, weekly_budget_sats=10**12, per_counterparty_cap_sats=10**12)
        engine = PolicyEngine(cfg, PolicyStore(d / "ledger.json"), AuditLog(d / "audit.jsonl"))
    book = ChannelBook(d / "channels.json", d / "channel_keys.json", keystore=ks, audit=audit)
    if fresh:
        chan = fund_channel(book, FakeRpc(), HUB, capacity=10_000_600).channel_id
    policy = RoutePolicy.from_dict({"hubs": {HUB: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}},
                                    "max_lock_sats": 20_000, "daily_budget_sats": 10**9})
    return Rig(d, ks, book, RouteSigner(book, policy, state_path=d / "routing.json", engine=engine), chan, audit)


def lock(rs: RouteSigner, chan: str, cum: int, lock_id: str) -> tuple[dict, str]:
    """Pre-sign one lock; returns it and the secret (t + r) that resolves it."""
    t = secrets.randbelow(A.N - 1) + 1
    out = rs.sign_state_adaptor(chan, cum, A.enc(A.point_of(t)).hex(), {"hub": HUB, "amount": 9, "fee": 1,
                                                                        "lockId": lock_id})
    return out, f"{(t + int(out['tweak'], 16)) % A.N:064x}"


def run(setup: str, locks: int, ledger: int) -> dict:
    r = rig(setup, ledger)
    d, rs, chan = r.d, r.rs, r.chan
    ms, cum = [], 1000
    with Count() as c:
        for i in range(locks):
            t0 = time.perf_counter()
            _, y = lock(rs, chan, cum, f"L{i}")
            rs.resolve_lock(chan, y)
            ms.append((time.perf_counter() - t0) * 1000)
            cum += 10
    q = statistics.quantiles(ms, n=4)
    return {"setup": setup, "locks": locks, "ledger_rows_before": ledger if setup != "bare" else 0,
            "fsync_per_lock": round(c.fsync / locks, 2), "rename_per_lock": round(c.replace / locks, 2),
            "ms_median": round(statistics.median(ms), 3), "ms_p25": round(q[0], 3), "ms_p75": round(q[2], 3),
            "bytes_on_disk": sum(f.stat().st_size for f in d.iterdir() if f.is_file())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--locks", type=int, default=200)
    ap.add_argument("--ledger", type=int, default=5000)
    ap.add_argument("--setups", default="bare,keyfile,passphrase")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    load1 = os.getloadavg()[0]
    rows = [run(s, a.locks, a.ledger) for s in a.setups.split(",")]
    if a.json:
        print(json.dumps({"load1": load1, "rows": rows}))
        return
    print(f"load1 {load1:.2f}  locks {a.locks}  ledger rows before {a.ledger}")
    print(f"{'setup':<11}{'fsync/lock':>11}{'rename/lock':>12}{'ms median':>11}{'p25':>9}{'p75':>9}{'bytes on disk':>15}")
    for r in rows:
        print(f"{r['setup']:<11}{r['fsync_per_lock']:>11}{r['rename_per_lock']:>12}{r['ms_median']:>11}{r['ms_p25']:>9}"
              f"{r['ms_p75']:>9}{r['bytes_on_disk']:>15}")


if __name__ == "__main__":
    main()
