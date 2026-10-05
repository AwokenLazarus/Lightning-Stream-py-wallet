"""Append-only JSON-lines log with one fsync per row (AGP-055).

The routed-spend rows and the payment ledger used to be rewritten whole on every lock. Here a row is
one line appended to an open file and fsynced: the cost of a row no longer depends on how many rows
came before it.

File: a header line `{"kind": <kind>, "v": 1}`, then one JSON object per line.

Torn last line: a row counts once its line ends in a newline. A crash in the middle of an append
leaves bytes after the last newline; `append` had not returned for that row, so nothing was built
on it. Opening the log cuts those bytes off (and fsyncs) before anything is appended after them.
Any complete line that does not parse is damage, not a crash: opening fails with `LogError`, it
never reads as a shorter log.

Compaction: `compact(rows)` writes the header and `rows` to a temp file, fsyncs it, renames it over
the log and fsyncs the directory. A crash leaves the old log or the new one, both complete.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

VERSION = 1


class LogError(RuntimeError):
    pass


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _line(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def cut_torn_tail(path: Path) -> int:
    """Cut the bytes after the last newline off an append-only file (a crash mid-append), fsync,
    and return how many were cut. A missing file has no tail."""
    path = Path(path)
    if not path.exists():
        return 0
    data = path.read_bytes()
    good = data.rfind(b"\n") + 1
    if good == len(data):
        return 0
    fd = os.open(path, os.O_WRONLY)
    try:
        os.ftruncate(fd, good)
        os.fsync(fd)
    finally:
        os.close(fd)
    return len(data) - good


def header(kind: str) -> bytes:
    return _line({"kind": kind, "v": VERSION})


def replace_log(path: Path, kind: str, rows: list[dict]) -> None:
    """Write a whole log (header + rows) to a temp file, fsync, rename over `path`, fsync the directory."""
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        write_all(fd, header(kind) + b"".join(_line(r) for r in rows))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _fsync_dir(path.parent)


class AppendLog:
    """The owner keeps the rows: `take_rows()` hands over what the file held at open, `file_rows`
    counts the lines since. Not thread-safe: the owner serializes calls."""

    def __init__(self, path: Path, kind: str):
        self.path, self.kind = Path(path), kind
        self._header = header(kind)
        self.rows: list[dict] = []
        self.file_rows = 0
        self.torn_bytes = 0          # bytes of a torn last line cut off at open
        self._fd = -1
        self._open()
        self.file_rows = len(self.rows)

    def take_rows(self) -> list[dict]:
        rows, self.rows = self.rows, []
        return rows

    def _open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        created = not self.path.exists()
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            data = b""
            while chunk := os.read(fd, 1 << 20):
                data += chunk
            good = data.rfind(b"\n") + 1
            if good < len(data):                     # a torn last line: never acknowledged, cut it off
                self.torn_bytes = len(data) - good
                os.ftruncate(fd, good)
                os.fsync(fd)
                data = data[:good]
            if not data:
                write_all(fd, self._header)
                os.fsync(fd)
                data = self._header
            lines = data.split(b"\n")[:-1]
            if lines[0] + b"\n" != self._header:
                raise LogError(f"{self.path}: not a v{VERSION} {self.kind} log (first line {lines[0][:80]!r})")
            for n, raw in enumerate(lines[1:], start=2):
                try:
                    row = json.loads(raw)
                except ValueError as e:
                    raise LogError(f"{self.path}: line {n} is damaged ({e}); the log is not read past it") from e
                if not isinstance(row, dict):
                    raise LogError(f"{self.path}: line {n} is not an object")
                self.rows.append(row)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        if created:
            _fsync_dir(self.path.parent)

    def append(self, row: dict) -> None:
        """One write and one fsync; returns once the row is durable."""
        write_all(self._fd, _line(row))
        os.fsync(self._fd)
        self.file_rows += 1

    def compact(self, rows: list[dict]) -> None:
        """Replace the log's rows with `rows`, atomically."""
        replace_log(self.path, self.kind, rows)
        os.close(self._fd)
        self._fd = os.open(self.path, os.O_RDWR | os.O_APPEND)
        self.file_rows = len(rows)

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __del__(self):
        self.close()
