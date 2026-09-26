"""TEST ORACLE ONLY. Pure-Python BIP340 Schnorr + BIP341 taproot helpers (not constant time).

The live code uses libsecp256k1 (fwd/schnorr.py); tests/test_offline.py cross-checks the two.

In B2 (AGP-013) this file is b5 agp-merge 25d3541 fwd/ref/schnorr.py, copied verbatim apart from this
paragraph and the import path. The wallet's forward rail uses only its public-data operations
(BIP340 verify, lift_x, tapleaf hash); the secret-key functions are for the tests' simulated market.
"""
from . import ecc
from .tx import sha256, tagged_hash, varbytes

N, P, G = ecc.N, ecc.P, ecc.G


def _lift_x(x: int):
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P:
        raise ValueError("x not on curve")
    return x, y if y % 2 == 0 else P - y


def xonly(secret: int) -> bytes:
    return ecc._mul(secret)[0].to_bytes(32, "big")


def sign(secret: int, msg32: bytes, aux: bytes = b"\x00" * 32) -> bytes:
    pt = ecc._mul(secret)
    d = secret if pt[1] % 2 == 0 else N - secret
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    px = pt[0].to_bytes(32, "big")
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + px + msg32), "big") % N
    R = ecc._mul(k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    rx = R[0].to_bytes(32, "big")
    e = int.from_bytes(tagged_hash("BIP0340/challenge", rx + px + msg32), "big") % N
    return rx + ((k + e * d) % N).to_bytes(32, "big")


def verify(px: bytes, msg32: bytes, sig: bytes) -> bool:
    try:
        Pt = _lift_x(int.from_bytes(px, "big"))
    except ValueError:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig[:32] + px + msg32), "big") % N
    R = ecc._add(ecc._mul(s), ecc._mul(N - e, Pt))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def leaf_hash(script: bytes) -> bytes:
    return tagged_hash("TapLeaf", b"\xc0" + varbytes(script))


def taproot_output(internal_secret: int, leaf_script: bytes = None):
    """Single-leaf (or key-only) taproot output.

    Returns (scriptPubKey, tweaked_secret_for_key_path, control_block_or_None)."""
    pt = ecc._mul(internal_secret)
    d = internal_secret if pt[1] % 2 == 0 else N - internal_secret
    px = pt[0].to_bytes(32, "big")
    root = leaf_hash(leaf_script) if leaf_script is not None else b""
    t = int.from_bytes(tagged_hash("TapTweak", px + root), "big")
    Q = ecc._mul((d + t) % N)
    spk = b"\x51\x20" + Q[0].to_bytes(32, "big")
    control = bytes([0xC0 | (Q[1] & 1)]) + px if leaf_script is not None else None
    return spk, (d + t) % N, control


__all__ = ["sign", "verify", "xonly", "leaf_hash", "taproot_output", "sha256"]
