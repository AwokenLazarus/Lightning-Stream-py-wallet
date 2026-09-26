"""TEST ORACLE ONLY. Pure-Python secp256k1 ECDSA (RFC 6979 nonces, low-S, DER).

Not constant time. Nothing under fwd/ imports this outside fwd/ref: the live code signs with
libsecp256k1 (fwd/ecc.py). tests/test_offline.py cross-checks the two.

In B2 (AGP-013) this file is b5 agp-merge 25d3541 fwd/ref/ecc.py, copied verbatim apart from this
paragraph and the import path. The wallet's forward rail uses only its public-data operations
(point arithmetic and pubkey decoding); the secret-key functions are for the tests' simulated market.
"""
import hashlib
import hmac

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(k, pt=G):
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def pubkey(secret: int) -> bytes:
    """Compressed SEC1 public key."""
    x, y = _mul(secret)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def _decode_pub(pub: bytes):
    if len(pub) != 33 or pub[0] not in (2, 3):
        raise ValueError("compressed pubkey expected")
    x = int.from_bytes(pub[1:], "big")
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P:
        raise ValueError("not on curve")
    if (y & 1) != (pub[0] & 1):
        y = P - y
    return x, y


def _rfc6979(secret: int, msg32: bytes) -> int:
    x = secret.to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _der_int(i: int) -> bytes:
    b = i.to_bytes(32, "big").lstrip(b"\x00")
    if not b or b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def sign(secret: int, msg32: bytes) -> bytes:
    """DER signature (low-S) over a 32-byte digest, without the hash-type byte."""
    z = int.from_bytes(msg32, "big")
    k = _rfc6979(secret, msg32)
    r = _mul(k)[0] % N
    s = pow(k, N - 2, N) * (z + r * secret) % N
    if s > N // 2:
        s = N - s
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def _parse_der(sig: bytes):
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2 or sig[2] != 2:
        raise ValueError("bad DER")
    rl = sig[3]
    r = int.from_bytes(sig[4:4 + rl], "big")
    if sig[4 + rl] != 2:
        raise ValueError("bad DER")
    sl = sig[5 + rl]
    s = int.from_bytes(sig[6 + rl:6 + rl + sl], "big")
    if 6 + rl + sl != len(sig):
        raise ValueError("bad DER")
    return r, s


def verify(pub: bytes, msg32: bytes, der: bytes) -> bool:
    """Verify a DER signature; rejects high-S like the node's standardness rules."""
    try:
        r, s = _parse_der(der)
        pt = _decode_pub(pub)
    except ValueError:
        return False
    if not (1 <= r < N and 1 <= s <= N // 2):
        return False
    w = pow(s, N - 2, N)
    z = int.from_bytes(msg32, "big")
    q = _add(_mul(z * w % N), _mul(r * w % N, pt))
    return q is not None and q[0] % N == r
