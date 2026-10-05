"""Append-only audit log of every signature the signer makes (AGP-013).

One JSON line per signature: what was signed (`kind`), for which channel / destination, the amount,
the SHA-256 of the signature bytes (not the signature), the signer method that asked for it, and the
policy rule that allowed it. Lines are hash-chained (`prev` = SHA-256 of the previous line), written
with O_APPEND and fsynced, so a removed or edited line breaks `verify_chain`.

AGP-016: the chain head is anchored with a witness process the signer's user cannot rewrite
(anchor.py), and `verify_chain(path, anchor)` also checks the log against the latest anchor, so a
whole-file rewrite is detected too.

The method and rule come from a per-thread context the signer sets while it handles a request
(`context(...)`), so the low-level signing code (channel book, hot wallet) does not need to know
which policy decision is behind it.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
import time
from pathlib import Path

from .applog import cut_torn_tail

_ctx = threading.local()
GENESIS = "0" * 64


def current() -> dict:
    return dict(getattr(_ctx, "fields", None) or {})


@contextlib.contextmanager
def context(**fields):
    """Set (and on exit restore) the method / rule that the next signatures are made under."""
    prev = getattr(_ctx, "fields", None)
    _ctx.fields = {**(prev or {}), **{k: v for k, v in fields.items() if v is not None}}
    try:
        yield
    finally:
        _ctx.fields = prev


def set_rule(rule: str) -> None:
    """Record the policy rule that allowed the current request (inside `context`)."""
    f = getattr(_ctx, "fields", None)
    if f is not None:
        f["rule"] = rule


class SigAuditError(RuntimeError):
    pass


class SigAudit:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # AGP-055: a crash mid-append leaves a line without its newline. That signature never left
        # (it is logged before it is returned), and the next line must not be glued onto it.
        self.torn_bytes = cut_torn_tail(self.path)
        self._last = self._tail_hash()

    def _tail_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = b""
        with self.path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    last = line.rstrip(b"\n")
        return hashlib.sha256(last).hexdigest() if last else GENESIS

    def record(self, kind: str, *, sig: bytes | str = b"", chan: str = "", dest: str = "", **extra) -> dict:
        if isinstance(sig, str):
            sig = bytes.fromhex(sig) if sig else b""
        ctx = current()
        with self._lock:
            entry = {
                "ts": round(time.time(), 3),
                "kind": kind,
                "chan": chan,
                "dest": dest,
                "sig_sha256": hashlib.sha256(sig).hexdigest() if sig else "",
                "method": ctx.get("method", ""),
                "rule": extra.pop("rule", None) or ctx.get("rule", "") or "unattributed",
                **extra,
                "prev": self._last,
            }
            line = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            self._last = hashlib.sha256(line).hexdigest()
            return entry

    def raw_lines(self) -> list[bytes]:
        """The log's lines as written (what the chain hashes), read under the append lock."""
        with self._lock:
            if not self.path.exists():
                return []
            return [x for x in self.path.read_bytes().splitlines() if x.strip()]

    def read(self, limit: int = 0) -> list[dict]:
        if not self.path.exists():
            return []
        rows = [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines() if x.strip()]
        return rows[-limit:] if limit else rows


def check_chain(path: Path, anchor: dict | None = None) -> dict:
    """Walk the chain; with `anchor` ({"n", "head"} from the anchor witness, anchor.py) also require
    that the log still has the anchored first n lines, i.e. that the hash of line n is the anchored
    head. A log rewritten from scratch, even with a self-consistent chain, fails that check."""
    prev, n, bad = GENESIS, 0, ""
    heads = [GENESIS]
    p = Path(path)
    for raw in (p.read_bytes().splitlines() if p.exists() else []):
        if not raw.strip():
            continue
        if json.loads(raw).get("prev") != prev:
            bad = f"line {n + 1} does not chain from line {n}"
            break
        prev = hashlib.sha256(raw).hexdigest()
        heads.append(prev)
        n += 1
    out = {"ok": not bad, "lines": n, "head": prev, "reason": bad}
    if anchor is not None and not bad:
        an, ah = int(anchor.get("n") or 0), anchor.get("head") or GENESIS
        out["anchored_n"] = an
        if n < an:
            out.update(ok=False, reason=f"the log has {n} lines but {an} were anchored (truncated or rewritten)")
        elif heads[an] != ah:
            out.update(ok=False, reason=f"line {an} does not hash to the anchored head (the log was rewritten)")
        else:
            out["unanchored_lines"] = n - an
    return out


def verify_chain(path: Path, anchor: dict | None = None) -> tuple[bool, int]:
    """(ok, lines checked). ok is False at the first line whose `prev` does not match, or (with an
    anchor from the witness) when the log no longer holds the anchored head."""
    r = check_chain(path, anchor)
    return r["ok"], r["lines"]


class NullAudit:
    def record(self, *a, **kw) -> dict:
        return {}
