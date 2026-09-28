"""Anchor the signature log's hash-chain head outside the signer's reach (AGP-016).

`signatures.jsonl` (sigaudit.py) is hash-chained, so an edited or dropped line is detected. But the
signer's Unix user can rewrite the *whole* file with a fresh, self-consistent chain. The fix is to
publish the head somewhere that user cannot rewrite, and to check the log against it.

Design: a **witness process** (`python -m agentwallet.anchor serve`). In production it runs as its
own Unix user and keeps its store in a directory the signer's user cannot write; the signer reaches
it over a Unix socket. On each submission the witness receives the log lines added since its last
anchor and checks that they extend the head it already holds (each line's `prev` chains from it). So
the witness enforces append-only on the log itself: a rewind, a fork or a rewritten history is
refused and written to its alert file, and it never stores a head that does not extend the last one.
Its own store is an O_APPEND, fsynced, hash-chained file.

Why this and not the alternatives the task lists:
  * an OP_RETURN in the next wallet transaction anchors only when the wallet spends, costs a fee
    each time on mainnet, and cannot ride on provider-built closes or B1's fixed-shape refunds. So
    "periodically, and on every close" would mean extra transactions;
  * a signed checkpoint to the treasury cosigner: in B2 the cosigner secret sits in the signer's own
    run dir, so the signer's user could forge the checkpoint. It is only independent once the
    cosigner is remote, and then it is this witness with a key attached.
The witness costs nothing per anchor, works offline on regtest and mainnet alike, and can anchor as
often as we like. Its limit: root, or the witness's own user, can still rewrite both files.

Configuration (the signer's environment and policy.json):
  B2_ANCHOR_SOCK=/path/witness.sock   the witness socket; unset means no anchoring
  policy "anchor_interval_s": 60      periodic anchor (the signer also anchors on every close,
                                      refund, sweep, rotation and treasury recovery)
  policy "anchor_required": false     true: the signer refuses to start without a reachable witness
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import threading
import time
from pathlib import Path

from .sigaudit import GENESIS, check_chain

ENV_SOCK = "B2_ANCHOR_SOCK"
MAX_LINES = 100_000  # per submission


class AnchorError(RuntimeError):
    pass


def _h(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class AnchorStore:
    """The witness's append-only record of (n lines, head) for one signature log."""

    def __init__(self, store_dir: Path):
        self.dir = Path(store_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "anchors.jsonl"
        self.alerts_path = self.dir / "alerts.jsonl"
        self._lock = threading.Lock()
        self._rows: list[dict] = []
        self._last_line_hash = GENESIS
        if self.path.exists():
            prev = GENESIS
            for raw in self.path.read_bytes().splitlines():
                if not raw.strip():
                    continue
                row = json.loads(raw)
                if row.get("prev") != prev:
                    raise AnchorError(f"witness store {self.path} is not a valid chain")
                prev = _h(raw)
                self._rows.append(row)
            self._last_line_hash = prev

    def _append(self, path: Path, row: dict) -> bytes:
        line = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            os.write(fd, line + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        return line

    def latest(self) -> dict:
        with self._lock:
            return dict(self._rows[-1]) if self._rows else {"n": 0, "head": GENESIS, "seq": 0}

    def _alert(self, kind: str, detail: dict) -> dict:
        row = {"ts": round(time.time(), 3), "alert": kind, **detail}
        self._append(self.alerts_path, row)
        return {"ok": False, "alert": kind, **detail}

    def alerts(self) -> list[dict]:
        if not self.alerts_path.exists():
            return []
        return [json.loads(x) for x in self.alerts_path.read_text(encoding="utf-8").splitlines() if x.strip()]

    def submit(self, n: int, head: str, lines: list[str], reason: str = "") -> dict:
        """Accept (n, head) only if `lines` are exactly the log lines after the last anchor and chain
        from its head to `head`. Anything else is refused and recorded as an alert."""
        n = int(n)
        with self._lock:
            last = self._rows[-1] if self._rows else {"n": 0, "head": GENESIS, "seq": 0}
            if n < last["n"]:
                if any(r["n"] == n and r["head"] == head for r in self._rows):
                    return {"ok": True, "n": last["n"], "head": last["head"], "seq": last["seq"], "stale": True}
                return self._alert("rewind", {"n": n, "head": head, "anchored_n": last["n"], "reason": reason})
            if len(lines) != n - last["n"] or len(lines) > MAX_LINES:
                return self._alert("bad_submission", {"n": n, "lines": len(lines), "anchored_n": last["n"]})
            prev = last["head"]
            for i, raw in enumerate(lines):
                b = raw.encode() if isinstance(raw, str) else bytes(raw)
                try:
                    link = json.loads(b).get("prev")
                except ValueError:
                    link = None
                if link != prev:
                    return self._alert("fork", {"n": n, "head": head, "anchored_n": last["n"], "at_line": last["n"] + i + 1,
                                                "reason": reason})
                prev = _h(b)
            if prev != head:
                return self._alert("head_mismatch", {"n": n, "head": head, "computed": prev})
            if n == last["n"]:
                return {"ok": True, "n": last["n"], "head": last["head"], "seq": last["seq"], "unchanged": True}
            row = {"seq": last["seq"] + 1, "n": n, "head": head, "ts": round(time.time(), 3), "reason": reason,
                   "prev": self._last_line_hash}
            line = self._append(self.path, row)
            self._last_line_hash = _h(line)
            self._rows.append(row)
            return {"ok": True, **{k: row[k] for k in ("seq", "n", "head", "ts")}}


class AnchorWitness:
    """The witness server: newline-delimited JSON over a Unix socket (submit / latest / alerts)."""

    def __init__(self, store_dir: Path, sock_path: Path, *, sock_mode: int = 0o660):
        self.store = AnchorStore(store_dir)
        self.sock_path = Path(sock_path)
        self.sock_mode = sock_mode
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def handle(self, req: dict) -> dict:
        m, p = req.get("method"), req.get("params") or {}
        if m == "latest":
            return self.store.latest()
        if m == "submit":
            return self.store.submit(int(p.get("n") or 0), str(p.get("head") or ""), list(p.get("lines") or []),
                                     str(p.get("reason") or ""))
        if m == "alerts":
            return {"alerts": self.store.alerts()}
        raise ValueError(f"unknown method {m}")

    def bind(self) -> None:
        if self.sock_path.exists():
            self.sock_path.unlink()
        self.sock_path.parent.mkdir(parents=True, exist_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(self.sock_path))
        os.chmod(self.sock_path, self.sock_mode)
        s.listen(8)
        self._sock = s

    def serve_forever(self) -> None:
        if self._sock is None:
            self.bind()
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def start_thread(self) -> threading.Thread:
        """For tests and the flagship: bind now, serve in a daemon thread."""
        self.bind()
        t = threading.Thread(target=self.serve_forever, name="anchor-witness", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            self._sock.close()

    def _client(self, conn: socket.socket) -> None:
        buf = b""
        try:
            while True:
                chunk = conn.recv(1 << 20)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    req = json.loads(line)
                    try:
                        resp = {"id": req.get("id"), "result": self.handle(req)}
                    except Exception as e:
                        resp = {"id": req.get("id"), "error": {"message": str(e)}}
                    conn.sendall((json.dumps(resp) + "\n").encode())
        finally:
            conn.close()


class AnchorClient:
    def __init__(self, sock_path: Path, timeout: float = 10.0):
        self.sock_path = Path(sock_path)
        self.timeout = timeout

    def call(self, method: str, **params):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(str(self.sock_path))
            s.sendall((json.dumps({"id": 1, "method": method, "params": params}) + "\n").encode())
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(1 << 16)
                if not chunk:
                    break
                buf += chunk
        except OSError as e:
            raise AnchorError(f"anchor witness unreachable at {self.sock_path}: {e}") from e
        finally:
            s.close()
        resp = json.loads(buf or b"{}")
        if resp.get("error") or "result" not in resp:
            raise AnchorError((resp.get("error") or {}).get("message") or "empty reply from the anchor witness")
        return resp["result"]

    def latest(self) -> dict:
        return self.call("latest")

    def submit(self, n: int, head: str, lines: list[str], reason: str = "") -> dict:
        return self.call("submit", n=n, head=head, lines=lines, reason=reason)


class Anchorer:
    """The signer side: sends the log's new lines and head to the witness, one anchor at a time."""

    def __init__(self, audit, client: AnchorClient | None, interval_s: float = 60.0):
        self.audit = audit
        self.client = client
        self.interval_s = float(interval_s)
        self._lock = threading.Lock()
        self.last: dict = {}
        self.last_error = ""
        self.last_at = 0.0

    @property
    def enabled(self) -> bool:
        return self.client is not None

    def check(self) -> dict:
        """The local log against the witness's latest anchor (sigaudit.check_chain)."""
        if self.client is None:
            return {**check_chain(self.audit.path), "anchor": None}
        latest = self.client.latest()
        return {**check_chain(self.audit.path, latest), "anchor": latest}

    def anchor(self, reason: str) -> dict:
        if self.client is None:
            return {"ok": False, "reason": "anchoring is off (no B2_ANCHOR_SOCK)"}
        with self._lock:
            try:
                latest = self.client.latest()
                lines = self.audit.raw_lines()
                if len(lines) < int(latest["n"]):
                    raise AnchorError(f"the signature log has {len(lines)} lines, fewer than the {latest['n']} anchored")
                new = lines[int(latest["n"]):]
                head = _h(lines[-1]) if lines else GENESIS
                r = self.client.submit(len(lines), head, [x.decode() for x in new], reason)
            except (AnchorError, OSError, ValueError, KeyError) as e:
                self.last_error = str(e)[:300]
                return {"ok": False, "reason": self.last_error}
            if r.get("ok"):
                self.last, self.last_error, self.last_at = r, "", time.time()
            else:
                self.last_error = f"witness refused: {r.get('alert')}"
            return r

    def due(self) -> bool:
        return self.enabled and self.interval_s > 0 and time.time() - self.last_at >= self.interval_s

    def status(self) -> dict:
        n = len(self.audit.raw_lines())
        return {"enabled": self.enabled, "interval_s": self.interval_s,
                "anchored_n": self.last.get("n"), "anchored_head": self.last.get("head"),
                "anchored_at": self.last.get("ts"), "log_lines": n,
                "unanchored_lines": (n - int(self.last.get("n") or 0)) if self.enabled else None,
                "error": self.last_error or None}


def client_from_env() -> AnchorClient | None:
    p = os.environ.get(ENV_SOCK, "").strip()
    return AnchorClient(Path(p)) if p else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agentwallet.anchor",
                                 description="Signature-log anchor witness (run it as its own Unix user)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--store", required=True, help="the witness's own directory (not writable by the signer)")
    sv.add_argument("--sock", required=True)
    sv.add_argument("--sock-mode", default="660", help="octal socket mode (the signer's user must be able to connect)")
    ck = sub.add_parser("check", help="verify a signature log against a witness store")
    ck.add_argument("--store", required=True)
    ck.add_argument("--log", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "serve":
        w = AnchorWitness(Path(a.store), Path(a.sock), sock_mode=int(a.sock_mode, 8))
        w.bind()
        print(f"anchor witness on {a.sock}, store {a.store}, latest {w.store.latest()}", flush=True)
        w.serve_forever()
        return 0
    res = check_chain(Path(a.log), AnchorStore(Path(a.store)).latest())
    print(json.dumps(res))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
