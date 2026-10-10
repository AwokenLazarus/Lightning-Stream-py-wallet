"""Ed25519 human-approval messages. The signer holds only the public key.

Canonical signed payload is (token, dest, amount_sats, expiry) as specified
by XBT-054 rework. The matching private key must live on the human's device,
never under the agent/MCP workspace.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

DOMAIN = b"xbt-agentwallet-approve-v1"
RECOVER_DOMAIN = b"xbt-agentwallet-recover-v1"
SWEEP_DOMAIN = b"xbt-agentwallet-hot-sweep-v1"
# AGP-063 W3 (the Rust signer's AGP-039 message): rotate the hot key whose address is the second line.
ROTATE_DOMAIN = b"xbt-agentwallet-hot-rotate-v1"


def canonical_message(token: str, dest: str, amount_sats: int, expiry: int) -> bytes:
    return b"\n".join(
        [
            DOMAIN,
            (token or "").encode("utf-8"),
            (dest or "").encode("utf-8"),
            str(int(amount_sats)).encode("ascii"),
            str(int(expiry)).encode("ascii"),
        ]
    )


def recover_message(recovery_address: str, expiry: int) -> bytes:
    return b"\n".join(
        [
            RECOVER_DOMAIN,
            (recovery_address or "").encode("utf-8"),
            str(int(expiry)).encode("ascii"),
        ]
    )


def sweep_message(hot_address: str, dest: str, amount_sats: int, expiry: int) -> bytes:
    """AGP-013: a human moves `amount_sats` out of the hot key (above its balance cap) to `dest`."""
    return b"\n".join(
        [
            SWEEP_DOMAIN,
            (hot_address or "").encode("utf-8"),
            (dest or "").encode("utf-8"),
            str(int(amount_sats)).encode("ascii"),
            str(int(expiry)).encode("ascii"),
        ]
    )


def rotate_message(hot_address: str, expiry: int) -> bytes:
    """AGP-063 W3: a human rotates the hot key whose address is `hot_address` (its coins sweep to the new key)."""
    return b"\n".join([ROTATE_DOMAIN, (hot_address or "").encode("utf-8"), str(int(expiry)).encode("ascii")])


TREASURY_FUND_DOMAIN = b"xbt-agentwallet-treasury-fund-v1"
TREASURY_RECOVER_DOMAIN = b"xbt-agentwallet-treasury-recover-v1"


def treasury_fund_message(hot_address: str, treasury_address: str, amount_sats: int, expiry: int) -> bytes:
    """AGP-080 W3: a human moves `amount_sats` from the hot key into the CSV treasury."""
    return b"\n".join([TREASURY_FUND_DOMAIN, (hot_address or "").encode("utf-8"), (treasury_address or "").encode("utf-8"),
                       str(int(amount_sats)).encode("ascii"), str(int(expiry)).encode("ascii")])


def treasury_recover_message(treasury_address: str, dest: str, expiry: int) -> bytes:
    """AGP-080 W3: a human recovers the treasury to `dest`. `recover_message` named only the treasury,
    so one signature paid whatever address the caller passed."""
    return b"\n".join([TREASURY_RECOVER_DOMAIN, (treasury_address or "").encode("utf-8"), (dest or "").encode("utf-8"),
                       str(int(expiry)).encode("ascii")])


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_raw_32, public_raw_32)."""
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def sign(priv: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(bytes(priv)).sign(message)


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pub)).verify(bytes(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_approval(priv: bytes, token: str, dest: str, amount_sats: int, expiry: int) -> bytes:
    return sign(priv, canonical_message(token, dest, amount_sats, expiry))


def verify_approval(
    pub: bytes, token: str, dest: str, amount_sats: int, expiry: int, signature: bytes
) -> bool:
    return verify(pub, canonical_message(token, dest, amount_sats, expiry), signature)


def b2x(data: bytes) -> str:
    return bytes(data).hex()


def x2b(hexstr: str) -> bytes:
    return bytes.fromhex((hexstr or "").strip())


def write_human_device(device_dir: Path) -> dict[str, str]:
    """Create a marked human-device directory with a fresh ed25519 key.

    The private key is 0600. Callers must keep device_dir outside the
    agent/MCP workspace.
    """
    device_dir = Path(device_dir)
    device_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(device_dir, 0o700)
    readme = device_dir / "THIS_IS_THE_HUMANS_DEVICE.txt"
    readme.write_text(
        "THE HUMAN'S DEVICE\n"
        "This directory simulates a phone/HSM the agent cannot read.\n"
        "ed25519.sk must never be copied into ~/xbt-rnd/b2/ (agent workspace),\n"
        "the MCP process, or any path the model can list.\n"
        "The signer is configured with ed25519.pk only.\n",
        encoding="utf-8",
    )
    priv, pub = generate_keypair()
    sk = device_dir / "ed25519.sk"
    pk = device_dir / "ed25519.pk"
    sk.write_bytes(priv)
    pk.write_bytes(pub)
    os.chmod(sk, 0o600)
    os.chmod(pk, 0o644)
    return {"device_dir": str(device_dir), "sk": str(sk), "pk": str(pk), "public_hex": b2x(pub)}


def load_private_key(path: Path) -> bytes:
    raw = Path(path).read_bytes()
    if len(raw) == 32:
        return raw
    # hex file
    return x2b(raw.decode("ascii"))


def load_public_key(path: Path) -> bytes:
    raw = Path(path).read_bytes()
    if len(raw) == 32:
        return raw
    return x2b(raw.decode("ascii"))
