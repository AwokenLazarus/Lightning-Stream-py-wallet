"""AGP-081 E1: what one hostile Electrum server costs the light client, measured.

    B1_ROOT=<b1 tree> <python> tests/e1_attacks.py [--tree <b2 tree>] [attack ...]

Each attack runs in a fresh process against the simulator (tests/_electrum_sim.py) and prints its
wall time and the peak resident memory of that process. `--tree` picks the B2 tree whose
`agentwallet` is measured (default: the tree this file is in), so the same script gives the numbers
before and after a fix. The hostile server is `HostileElectrum` below; the tests of
test_agp081_closure_audit.py use it too.

Attacks:
  trickle       one of two servers serves the real chain one header per blockchain.block.headers
                answer, each just inside the request timeout (120 headers, 0.4 s each, timeout 0.5 s)
  dense-line    an unasked 16 MiB line of dense JSON, `[[],[],...]`
  endless-line  300 MiB with no newline in it
  history       8,000 invented history entries for a script the wallet watches, each with a
                10 kB transaction that the server serves
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import struct
import subprocess
import sys
import time
from pathlib import Path

MIB = 1 << 20
ATTACKS = ("trickle", "dense-line", "endless-line", "history")


def use_tree(tree: Path) -> None:
    """Import `agentwallet` and the simulator from this B2 tree, ahead of the directory of this file."""
    sys.path[:0] = [str(tree), str(tree / "tests")]


if __name__ == "__main__":       # the tree has to be chosen before the simulator is imported
    _args = argparse.ArgumentParser(add_help=False)
    _args.add_argument("--tree", type=Path, default=Path(__file__).resolve().parent.parent)
    use_tree(_args.parse_known_args()[0].tree.resolve())

from _electrum_sim import CHECKPOINT, FakeElectrum, SimChain  # noqa: E402
from xbt402.tx import Tx, TxIn, TxOut  # noqa: E402

DENSE = b"[],"


class HostileElectrum(FakeElectrum):
    """FakeElectrum with the E1 attacks: a trickle of headers, lines nobody asked for, methods that
    are refused or answered with raw bytes, and invented histories and unspent outputs."""

    def __init__(self, sim: SimChain):
        super().__init__(sim)
        self.headers_per_answer: int | None = None   # serve at most this many headers above trickle_above
        self.trickle_above = CHECKPOINT
        self.trickle_delay_s = 0.0
        self.refuse: set[str] = set()                # methods answered with an error
        self.raw_answer: dict[str, bytes] = {}       # method -> a line written in place of the answer
        self.invented: dict[str, tuple[int, int]] = {}   # txid -> (index, raw size) of an invented transaction
        self.extra_unspent: dict[str, list] = {}     # scripthash -> extra listunspent entries

    def answer(self, client, method: str, p: list):
        if method in self.refuse:
            self.calls.append(method)
            raise ValueError("refused")
        if method in self.raw_answer:
            self.calls.append(method)
            with client.lock:
                client.connection.sendall(self.raw_answer[method])
            raise ValueError("answered raw")
        if method == "blockchain.block.headers" and self.headers_per_answer and int(p[0]) > self.trickle_above:
            time.sleep(self.trickle_delay_s)
            p = [p[0], min(int(p[1]), self.headers_per_answer)]
        if method == "blockchain.transaction.get" and p[0] in self.invented:
            self.calls.append(method)
            return invented_tx(*self.invented[p[0]]).hex()
        if method == "blockchain.scripthash.listunspent":
            return super().answer(client, method, p) + list(self.extra_unspent.get(p[0], []))
        return super().answer(client, method, p)

    def invent(self, sh: str, n: int, size: int = 100, height: int = 0) -> list[str]:
        """Add `n` history entries for scripthash `sh`, each a transaction of about `size` raw bytes
        that neither pays nor spends the script. Returns their txids."""
        txids = []
        for i in range(len(self.invented), len(self.invented) + n):
            txid = invented_tx(i, size).txid()
            self.invented[txid] = (i, size)
            txids.append(txid)
        self.extra_history.setdefault(sh, []).extend({"tx_hash": t, "height": height} for t in txids)
        return txids

    def push(self, total: int, piece: bytes = DENSE, *, newline: bool = True) -> int:
        """Write a line nobody asked for to every client: `[`, `piece` repeated up to `total` bytes,
        `[]]`, and a newline unless `newline` is False. Returns the bytes the clients took before
        they closed (all of them, if none did)."""
        sent = 0
        block = piece * max(1, (1 << 16) // len(piece))
        for c in list(self._clients):
            with c.lock:
                try:
                    c.connection.sendall(b"[")
                    for _ in range(total // len(block)):
                        c.connection.sendall(block)
                        sent += len(block)
                    c.connection.sendall(b"[]]" + (b"\n" if newline else b""))
                except OSError:
                    pass
        return sent


def invented_tx(i: int, size: int) -> Tx:
    """Transaction number `i` of an invented history: one unknown input, one OP_RETURN output."""
    return Tx(version=2, inputs=[TxIn(struct.pack("<I", i).ljust(32, b"\x77"), 0)],
              outputs=[TxOut(0, b"\x6a" + bytes(max(0, size - 61)))], locktime=0)


def rss_mib() -> float:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    return 0.0


def peak_mib() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def backend(sim: SimChain, *servers, timeout: float = 5.0):
    from agentwallet.electrum import ElectrumBackend

    return ElectrumBackend([s.url for s in servers], chain="regtest", checkpoint=(CHECKPOINT, sim.bhash(CHECKPOINT)),
                           timeout=timeout)


def flagged(b, server) -> list[str]:
    return sorted({f["reason"][:90] for f in b.flags if f["server"] == server.url})


def measure(run) -> dict:
    """`run()` -> (what happened, the backend, the hostile server), with its wall time and memory."""
    before = rss_mib()
    t = time.monotonic()
    out, b, hostile = run()
    wall = time.monotonic() - t
    return {"wall_s": round(wall, 3), "rss_before_mib": round(before, 1), "peak_rss_mib": round(peak_mib(), 1),
            "connected": hostile.url in {c.url for c in b.conns if c.connected}, "flags": flagged(b, hostile), **out}


def attack_trickle() -> dict:
    sim = SimChain(height=CHECKPOINT + 20)
    hostile, honest = HostileElectrum(sim), FakeElectrum(sim)
    b = backend(sim, hostile, honest, timeout=0.5)
    b.sync(force=True)
    sim.mine(120)
    hostile.headers_per_answer, hostile.trickle_above, hostile.trickle_delay_s = 1, CHECKPOINT + 20, 0.4
    honest.delay_headers_s = 0.2     # a server whose tip we already hold is not asked: the trickler is asked first

    def run():
        tip = b.sync(force=True)
        return {"tip": tip, "want_tip": sim.height,
                "header_requests": hostile.calls.count("blockchain.block.headers")}, b, hostile
    return measure(run)


def attack_line(total: int, *, newline: bool) -> dict:
    sim = SimChain(height=CHECKPOINT + 20)
    hostile = HostileElectrum(sim)
    b = backend(sim, hostile)
    b.sync(force=True)

    def run():
        sent = hostile.push(total, newline=newline)
        try:                        # answered after the line: by then the reader has dealt with it
            b.sync(force=True)
        except Exception as e:      # noqa: BLE001 - reported, either tree
            return {"sent_mib": round(sent / MIB, 2), "after": type(e).__name__}, b, hostile
        return {"sent_mib": round(sent / MIB, 2), "after": "sync ok"}, b, hostile
    return measure(run)


def attack_history(n: int = 8_000, size: int = 10_000) -> dict:
    from agentwallet.electrum import scripthash

    sim = SimChain(height=CHECKPOINT + 20)
    spk = "0014" + "5a" * 20
    txid = sim.credit("", 0, 50_000, spk)
    hostile = HostileElectrum(sim)
    hostile.invent(scripthash(bytes.fromhex(spk)), n, size)
    b = backend(sim, hostile, timeout=15.0)
    b.sync(force=True)

    def run():
        out = b.call("gettxout", txid, 0, True)
        cached = sum(len(tx.hex()) // 2 for tx in list(b._tx.values()))
        return {"gettxout_value": (out or {}).get("value"), "tx_requests": hostile.calls.count("blockchain.transaction.get"),
                "cached_txs": len(b._tx), "cached_raw_mib": round(cached / MIB, 2)}, b, hostile
    return measure(run)


def run_attack(name: str) -> dict:
    if name == "trickle":
        return attack_trickle()
    if name == "dense-line":
        return attack_line(16 * MIB, newline=True)
    if name == "endless-line":
        return attack_line(300 * MIB, newline=False)
    if name == "history":
        return attack_history()
    raise SystemExit(f"unknown attack {name!r}: one of {', '.join(ATTACKS)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tree", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--run", help="run this one attack here and print its result as JSON")
    ap.add_argument("attacks", nargs="*", default=list(ATTACKS))
    args = ap.parse_args()
    if args.run:
        import agentwallet.electrum as e
        print(json.dumps({"attack": args.run, "module": e.__file__, **run_attack(args.run)}))
        return
    for name in args.attacks:
        cmd = [sys.executable, str(Path(__file__).resolve()), "--tree", str(args.tree.resolve()), "--run", name]
        p = subprocess.run(cmd, capture_output=True, text=True, check=False,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
        try:
            r = json.loads(line)
        except ValueError:
            print(f"{name}: failed (exit {p.returncode}): {p.stderr.strip()[-300:]}")
            continue
        extra = {k: v for k, v in r.items() if k not in ("attack", "module", "wall_s", "rss_before_mib", "peak_rss_mib")}
        print(f"{name:13} wall {r['wall_s']:8.3f} s  peak RSS {r['peak_rss_mib']:7.1f} MiB "
              f"(before the attack {r['rss_before_mib']:.1f})  {json.dumps(extra)}")
        print(f"{'':13} measured: {r['module']}")


if __name__ == "__main__":
    main()
