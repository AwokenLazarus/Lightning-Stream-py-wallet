"""At-rest encryption for the signer's hot keys (AGP-013).

The hot key (`hot.json`) and the per-channel payer keys (`channel_keys.json`) are sealed with
AES-256-GCM. The 32-byte wrapping key comes from the signer's environment, never from the MCP side:

  B2_HOT_KEYFILE=/path/to/key     32 random bytes (raw or hex). Created 0600 if missing. It must live
                                  outside the signer's run directory, next to nothing it protects.
  B2_HOT_PASSPHRASE=...           scrypt(N=2^15, r=8, p=1) with a per-blob salt. The signer removes
                                  it from os.environ once read.

With neither set the signer refuses to start, unless B2_HOT_ALLOW_PLAINTEXT=1 (unit tests, old
demos). A plaintext key file found on disk is re-sealed the first time a wrapping key is available.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ENV_KEYFILE = "B2_HOT_KEYFILE"
ENV_PASSPHRASE = "B2_HOT_PASSPHRASE"
ENV_ALLOW_PLAINTEXT = "B2_HOT_ALLOW_PLAINTEXT"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1


class KeyStoreError(RuntimeError):
    pass


class KeyStore:
    """Seals and opens small secrets. `kind` is "keyfile" or "passphrase"."""

    def __init__(self, *, key: bytes | None = None, passphrase: bytes | None = None):
        if (key is None) == (passphrase is None):
            raise ValueError("exactly one of key / passphrase")
        if key is not None and len(key) != 32:
            raise ValueError("wrapping key must be 32 bytes")
        self._key = key
        self._pass = passphrase
        self._kdf_cache: dict[bytes, bytes] = {}
        self.kind = "keyfile" if key is not None else "passphrase"

    @classmethod
    def from_env(cls, run_dir: Path | None = None, *, pop: bool = True) -> "KeyStore | None":
        """The signer's key source, or None when the environment names none."""
        pw = os.environ.pop(ENV_PASSPHRASE, None) if pop else os.environ.get(ENV_PASSPHRASE)
        path = os.environ.get(ENV_KEYFILE, "").strip()
        if pw and path:
            raise KeyStoreError(f"set only one of {ENV_KEYFILE} / {ENV_PASSPHRASE}")
        if pw:
            return cls(passphrase=pw.encode())
        if path:
            return cls(key=load_or_create_keyfile(Path(path), run_dir))
        return None

    @staticmethod
    def plaintext_allowed() -> bool:
        return os.environ.get(ENV_ALLOW_PLAINTEXT, "") == "1"

    def _wrap_key(self, salt: bytes) -> bytes:
        if self._key is not None:
            return self._key
        k = self._kdf_cache.get(salt)
        if k is None:
            k = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(self._pass)
            self._kdf_cache[salt] = k
        return k

    def seal(self, plaintext: bytes, aad: str, *, salt: bytes | None = None) -> dict:
        """`salt` lets a file that is re-sealed often (the hot UTXO set) reuse one scrypt derivation;
        every seal still gets a fresh random nonce."""
        salt = salt or secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._wrap_key(salt)).encrypt(nonce, plaintext, aad.encode())
        return {"v": 1, "alg": "aes-256-gcm", "kdf": "scrypt" if self._pass is not None else "keyfile",
                "salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex(), "aad": aad}

    def open(self, blob: dict, aad: str) -> bytes:
        if blob.get("v") != 1 or blob.get("alg") != "aes-256-gcm":
            raise KeyStoreError("unknown sealed-key format")
        if blob.get("aad") != aad:
            raise KeyStoreError(f"sealed blob is for {blob.get('aad')!r}, not {aad!r}")
        kdf = "scrypt" if self._pass is not None else "keyfile"
        if blob.get("kdf") != kdf:
            raise KeyStoreError(f"key sealed with {blob.get('kdf')}, signer has a {kdf}")
        try:
            return AESGCM(self._wrap_key(bytes.fromhex(blob["salt"]))).decrypt(
                bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["ct"]), aad.encode())
        except Exception as e:  # InvalidTag: wrong key or tampered file
            raise KeyStoreError("cannot open sealed key: wrong wrapping key or tampered file") from e


def load_or_create_keyfile(path: Path, run_dir: Path | None = None) -> bytes:
    path = Path(path).expanduser().resolve()
    if run_dir is not None:
        rd = Path(run_dir).resolve()
        if path == rd or rd in path.parents:
            raise KeyStoreError(f"{ENV_KEYFILE} must not live inside the signer run dir {rd}")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(secrets.token_bytes(32))
    raw = path.read_bytes()
    if len(raw) == 32:
        return raw
    txt = raw.strip()
    try:
        key = bytes.fromhex(txt.decode())
    except (UnicodeDecodeError, ValueError):
        key = b""
    if len(key) != 32:
        raise KeyStoreError(f"{ENV_KEYFILE} must hold 32 bytes (raw or 64 hex chars)")
    return key


def write_private(path: Path, text: str) -> None:
    """Atomic 0600 write (the temp file is 0600 before any byte lands)."""
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        view = memoryview(text.encode("utf-8"))
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
