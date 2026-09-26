"""ECDSA adaptor signatures bound to a BIP340 signature scalar (AGP-008 atomic settlement).

The buyer pays for a forward lot with an xbt402 channel state it has *pre-signed* under an
adaptor point Y. The pre-signature is not a valid ECDSA signature. Anyone who knows y (Y = y*G)
can turn it into one, and anyone who sees both the pre-signature and the completed signature
learns y. We choose Y to be the **signature point of the market's final transfer signature**:

    S = R + e*P,  e = H_BIP340/challenge(R.x || P.x || msg)      (from public data only)

The final BIP340 signature is (R.x, s) with s*G = S. So:
  * the market can complete the buyer's channel state only with s, which is exactly the missing
    half of the transfer signature, and
  * the completed state, wherever it appears (the HTTP answer, or the close transaction's
    witness on-chain), hands the buyer s: y = s'/s.

The scheme is the one-time verifiably encrypted ECDSA signature (Fournier 2019; Aumayr et al.,
"Generalized Channels", 2021):

    pre-sign(x, z, Y):  k random; R' = k*G; R = k*Y; r = R.x mod n; s' = k^-1 (z + r*x)
                        pi = DLEQ proof that log_G(R') = log_Y(R)
    pre-verify:         pi holds and s'*R' == z*G + r*X
    adapt(y):           s = s' * y^-1 (then low-S)     -> (r, s) is a valid ECDSA signature
    extract(s):         y = +-(s' * s^-1)              (the sign fixed by y*G == Y)

Prototype: pure Python on the pinned B1 point helpers. Secret-scalar multiplications (x, k, the
DLEQ nonce) use B1's fixed-sequence ladder; the modular inversions and the rest are still plain
Python, so this is not constant time. Production would use libsecp256k1-zkp's ecdsa_adaptor module.

B2 (AGP-013): b5 agp-merge 25d3541 fwd/adaptor.py, verbatim but for the B1 import path (b1path).
"""
import secrets
from dataclasses import dataclass
from typing import Optional

from ..b1path import ensure_b1

ensure_b1()
from .tx import tagged_hash
from xbt402 import ecc_oracle as ecc   # pinned B1 point arithmetic (b1 d8eb2c8): public-data helpers
from xbt402.ecc import _mul_secret    # B1 fixed-sequence ladder (XBT-061 H4) for secret scalars

N, P, G = ecc.N, ecc.P, ecc.G


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def enc(pt) -> bytes:
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def dec(b: bytes):
    return ecc._decode_pub(b)


def _neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def point_of(y: int):
    return ecc._mul(y % N)


def _lift_x(x: int):
    if x >= P:
        raise ValueError("x not a field element")
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P:
        raise ValueError("x not on curve")
    return x, y if y % 2 == 0 else P - y


# --- the adaptor point: a BIP340 signature's s*G, before anyone knows s -------------------------
def musig2_rx(aggnonce: bytes, qx: bytes, msg: bytes) -> bytes:
    """R.x of the final BIP327 MuSig2 signature from the aggregate nonce alone (BIP327 GetSessionValues:
    b = H_noncecoef(aggnonce || Q.x || msg), R = R1 + b*R2, infinity -> G)."""
    def pt(b33):
        return None if b33 == b"\x00" * 33 else dec(b33)
    b = _int(tagged_hash("MuSig/noncecoef", aggnonce + qx + msg)) % N
    R = ecc._add(pt(aggnonce[:33]), ecc._mul(b, pt(aggnonce[33:])) if pt(aggnonce[33:]) else None) or G
    return R[0].to_bytes(32, "big")


def sig_point(rx: bytes, px: bytes, msg: bytes):
    """S = lift_x(R.x) + e*lift_x(P.x): what s*G must equal for (R.x, s) to verify under P.x."""
    e = _int(tagged_hash("BIP0340/challenge", rx + px + msg)) % N
    return ecc._add(_lift_x(_int(rx)), ecc._mul(e, _lift_x(_int(px))))


# --- DLEQ (Chaum-Pedersen, Fiat-Shamir) ---------------------------------------------------------
def _dleq_challenge(X: bytes, z: bytes, Y, R1, R, A1, A2) -> int:
    return _int(tagged_hash("b5/adaptor/dleq", X + z + enc(Y) + enc(R1) + enc(R) + enc(A1) + enc(A2))) % N


def _dleq_prove(k: int, X: bytes, z: bytes, Y, R1, R):
    w = secrets.randbelow(N - 1) + 1
    A1, A2 = _mul_secret(w), _mul_secret(w, Y)
    c = _dleq_challenge(X, z, Y, R1, R, A1, A2)
    return c, (w + c * k) % N


def _dleq_verify(c: int, zz: int, X: bytes, z: bytes, Y, R1, R) -> bool:
    if not (0 <= c < N and 0 < zz < N):
        return False
    A1 = ecc._add(ecc._mul(zz), _neg(ecc._mul(c, R1)))
    A2 = ecc._add(ecc._mul(zz, Y), _neg(ecc._mul(c, R)))
    if A1 is None or A2 is None:
        return False
    return c == _dleq_challenge(X, z, Y, R1, R, A1, A2)


# --- pre-signatures ---------------------------------------------------------------------------
@dataclass
class PreSig:
    R: bytes      # k*Y, 33 bytes: r = R.x mod n is the r of the completed signature
    R1: bytes     # k*G, 33 bytes
    s1: int       # s' = k^-1 (z + r*x)
    c: int        # DLEQ challenge
    zz: int       # DLEQ response

    @property
    def r(self) -> int:
        return dec(self.R)[0] % N

    def to_json(self) -> dict:
        return {"R": self.R.hex(), "R1": self.R1.hex(), "s1": f"{self.s1:064x}",
                "c": f"{self.c:064x}", "z": f"{self.zz:064x}"}

    @classmethod
    def from_json(cls, d: dict) -> "PreSig":
        R, R1 = bytes.fromhex(d["R"]), bytes.fromhex(d["R1"])
        if len(R) != 33 or len(R1) != 33:
            raise ValueError("adaptor points must be 33-byte compressed")
        s1, c, zz = int(d["s1"], 16), int(d["c"], 16), int(d["z"], 16)
        if not (0 < s1 < N and 0 <= c < N and 0 < zz < N):
            raise ValueError("adaptor scalar out of range")
        return cls(R, R1, s1, c, zz)


def presign(x: int, z: bytes, Y) -> PreSig:
    """Pre-sign digest z with secret x under adaptor point Y."""
    X = enc(_mul_secret(x))
    zi = _int(z)
    while True:
        k = secrets.randbelow(N - 1) + 1
        R1, R = _mul_secret(k), _mul_secret(k, Y)
        r = R[0] % N
        s1 = pow(k, N - 2, N) * (zi + r * x) % N
        if r and s1:
            c, zz = _dleq_prove(k, X, z, Y, R1, R)
            return PreSig(enc(R), enc(R1), s1, c, zz)


def preverify(X: bytes, z: bytes, Y, pre: PreSig) -> bool:
    """True iff completing `pre` with log_G(Y) yields a valid ECDSA signature by X on z."""
    try:
        R, R1 = dec(pre.R), dec(pre.R1)
        Xp = dec(X)
    except (ValueError, TypeError):
        return False
    if not _dleq_verify(pre.c, pre.zz, X, z, Y, R1, R):
        return False
    r = R[0] % N
    if r == 0:
        return False
    si = pow(pre.s1, N - 2, N)
    return ecc._add(ecc._mul(_int(z) * si % N), ecc._mul(r * si % N, Xp)) == R1


def _der_int(i: int) -> bytes:
    b = i.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def der(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def parse_der(sig: bytes):
    """(r, s) of a strict-DER signature without its hash-type byte."""
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2 or sig[2] != 0x02:
        raise ValueError("not DER")
    lr = sig[3]
    r = _int(sig[4:4 + lr])
    if sig[4 + lr] != 0x02:
        raise ValueError("not DER")
    ls = sig[5 + lr]
    return r, _int(sig[6 + lr:6 + lr + ls])


def adapt(pre: PreSig, y: int) -> bytes:
    """The completed, low-S, strict-DER ECDSA signature (no hash-type byte)."""
    y %= N
    if not y:
        raise ValueError("zero adaptor secret")
    s = pre.s1 * pow(y, N - 2, N) % N
    if s > N // 2:
        s = N - s
    return der(pre.r, s)


def extract(pre: PreSig, sig: bytes, Y) -> Optional[int]:
    """y with y*G == Y from a completed signature (DER, with or without the hash-type byte), or
    None if `sig` is not a completion of `pre` (e.g. an ordinary signature over another state)."""
    if sig and len(sig) == sig[1] + 3:          # trailing hash-type byte
        sig = sig[:-1]
    try:
        r, s = parse_der(sig)
    except (ValueError, IndexError):
        return None
    if r != pre.r or not 0 < s < N:
        return None
    y = pre.s1 * pow(s, N - 2, N) % N
    for cand in (y, N - y):
        if point_of(cand) == Y:
            return cand
    return None


def complete_schnorr(rx: bytes, y: int) -> bytes:
    """The BIP340 signature (R.x, s) once s = y is known."""
    return rx + (y % N).to_bytes(32, "big")
