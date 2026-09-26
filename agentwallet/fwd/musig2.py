"""TEST ORACLE ONLY. Pure-Python BIP327 MuSig2 (the subset B5 needs) + BIP341 sighash.

Not constant time. The live code is fwd/musig2.py on libsecp256k1's musig module (coincurve);
tests/test_offline.py cross-checks every step against this file. The algorithms
follow BIP327 names (KeyAgg, ApplyTweak, NonceAgg, Sign, PartialSigAgg) so a reviewer can
check them line by line.

Nonce rule (the one that matters for a market): a secnonce is used for exactly one Sign call
and then destroyed. `SecNonce.take()` enforces that in-process.

In B2 (AGP-013) this file is b5 agp-merge 25d3541 fwd/ref/musig2.py, copied verbatim apart from this
paragraph and the import path. The wallet's forward rail uses only its public-data operations
(KeyAgg, the taproot tweak and the BIP341 sighash); the secret-key functions are for the tests' simulated market.
"""
import os
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from . import ecc, schnorr
from .tx import Tx, TxOut, sha256, tagged_hash, varbytes

N, P, G = ecc.N, ecc.P, ecc.G


def _xb(pt) -> bytes:
    return pt[0].to_bytes(32, "big")


def _cb(pt) -> bytes:
    return bytes([2 + (pt[1] & 1)]) + _xb(pt)


def _even(pt) -> bool:
    return pt[1] % 2 == 0


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _neg(pt):
    return (pt[0], P - pt[1])


# --- key aggregation -------------------------------------------------------------------------
@dataclass
class KeyAggCtx:
    Q: tuple
    gacc: int = 1
    tacc: int = 0
    pubkeys: List[bytes] = field(default_factory=list)

    def xonly(self) -> bytes:
        return _xb(self.Q)


def _second_key(pks):
    for pk in pks[1:]:
        if pk != pks[0]:
            return pk
    return b"\x00" * 33


def key_agg_coeff(pks: List[bytes], pk: bytes) -> int:
    if pk == _second_key(pks):
        return 1
    L = tagged_hash("KeyAgg list", b"".join(pks))
    return _int(tagged_hash("KeyAgg coefficient", L + pk)) % N


def key_agg(pks: List[bytes]) -> KeyAggCtx:
    Q = None
    for pk in pks:
        Q = ecc._add(Q, ecc._mul(key_agg_coeff(pks, pk), ecc._decode_pub(pk)))
    if Q is None:
        raise ValueError("aggregate key is infinity")
    return KeyAggCtx(Q, 1, 0, list(pks))


def apply_xonly_tweak(ctx: KeyAggCtx, tweak: bytes) -> KeyAggCtx:
    t = _int(tweak)
    if t >= N:
        raise ValueError("tweak out of range")
    g = 1 if _even(ctx.Q) else N - 1
    Q = ecc._add(ecc._mul(g, ctx.Q), ecc._mul(t))
    if Q is None:
        raise ValueError("tweaked key is infinity")
    return KeyAggCtx(Q, g * ctx.gacc % N, (t + g * ctx.tacc) % N, ctx.pubkeys)


def taproot_tweak(ctx: KeyAggCtx, merkle_root: bytes) -> KeyAggCtx:
    """BIP341 output key: internal key = the MuSig2 aggregate, tweaked by the script tree."""
    return apply_xonly_tweak(ctx, tagged_hash("TapTweak", ctx.xonly() + merkle_root))


# --- nonces and signing ------------------------------------------------------------------------
class SecNonce:
    """Secret nonce pair. `take()` hands it out once; a second use raises (nonce reuse leaks
    the secret key, which here would let the market forge a double-sale alone)."""

    def __init__(self, k1: int, k2: int):
        self._k = (k1, k2)

    def take(self):
        if self._k is None:
            raise RuntimeError("secnonce already used")
        k, self._k = self._k, None
        return k


def nonce_gen() -> (SecNonce, bytes):
    k1 = _int(os.urandom(32)) % N or 1
    k2 = _int(os.urandom(32)) % N or 1
    return SecNonce(k1, k2), _cb(ecc._mul(k1)) + _cb(ecc._mul(k2))


def nonce_agg(pubnonces: List[bytes]) -> bytes:
    out = b""
    for j in (0, 1):
        R = None
        for pn in pubnonces:
            R = ecc._add(R, ecc._decode_pub(pn[33 * j:33 * (j + 1)]))
        out += b"\x00" * 33 if R is None else _cb(R)
    return out


def _session(ctx: KeyAggCtx, aggnonce: bytes, msg: bytes):
    R1 = ecc._decode_pub(aggnonce[:33])
    R2 = ecc._decode_pub(aggnonce[33:])
    b = _int(tagged_hash("MuSig/noncecoef", aggnonce + ctx.xonly() + msg)) % N
    R = ecc._add(R1, ecc._mul(b, R2)) or G
    e = _int(tagged_hash("BIP0340/challenge", _xb(R) + ctx.xonly() + msg)) % N
    return b, R, e


def sign(secnonce: SecNonce, secret: int, ctx: KeyAggCtx, aggnonce: bytes, msg: bytes) -> int:
    k1, k2 = secnonce.take()
    b, R, e = _session(ctx, aggnonce, msg)
    if not _even(R):
        k1, k2 = N - k1, N - k2
    pk = ecc.pubkey(secret)
    if pk not in ctx.pubkeys:
        raise ValueError("signer is not a participant")
    g = 1 if _even(ctx.Q) else N - 1
    d = g * ctx.gacc * secret % N
    a = key_agg_coeff(ctx.pubkeys, pk)
    return (k1 + b * k2 + e * a * d) % N


def partial_sig_verify(psig: int, pubnonce: bytes, pk: bytes, ctx: KeyAggCtx,
                       aggnonce: bytes, msg: bytes) -> bool:
    b, R, e = _session(ctx, aggnonce, msg)
    Re = ecc._add(ecc._decode_pub(pubnonce[:33]), ecc._mul(b, ecc._decode_pub(pubnonce[33:])))
    if not _even(R):
        Re = _neg(Re)
    g = 1 if _even(ctx.Q) else N - 1
    a = key_agg_coeff(ctx.pubkeys, pk)
    rhs = ecc._add(Re, ecc._mul(e * a * g * ctx.gacc % N, ecc._decode_pub(pk)))
    return ecc._mul(psig) == rhs


def partial_sig_agg(psigs: List[int], ctx: KeyAggCtx, aggnonce: bytes, msg: bytes) -> bytes:
    _, R, e = _session(ctx, aggnonce, msg)
    g = 1 if _even(ctx.Q) else N - 1
    s = (sum(psigs) + e * g * ctx.tacc) % N
    return _xb(R) + s.to_bytes(32, "big")


# --- BIP341 signature hash ---------------------------------------------------------------------
SIGHASH_DEFAULT = 0x00


def bip341_sighash(tx: Tx, prevouts: List[TxOut], index: int, hash_type: int = SIGHASH_DEFAULT,
                   leaf_hash: Optional[bytes] = None) -> bytes:
    """TapSighash for SIGHASH_DEFAULT/ALL, no annex. `leaf_hash` set = script-path spend."""
    if hash_type not in (0x00, 0x01):
        raise ValueError("prototype supports DEFAULT/ALL only")
    m = bytes([0x00, hash_type]) + struct.pack("<i", tx.version) + struct.pack("<I", tx.locktime)
    m += sha256(b"".join(i.outpoint() for i in tx.inputs))
    m += sha256(b"".join(struct.pack("<q", p.value) for p in prevouts))
    m += sha256(b"".join(varbytes(p.script_pubkey) for p in prevouts))
    m += sha256(b"".join(struct.pack("<I", i.sequence) for i in tx.inputs))
    m += sha256(b"".join(o.serialize() for o in tx.outputs))
    m += bytes([2 if leaf_hash is not None else 0]) + struct.pack("<I", index)
    if leaf_hash is not None:
        m += leaf_hash + b"\x00" + b"\xff\xff\xff\xff"
    return tagged_hash("TapSighash", m)


def schnorr_sig(hash_type: int, sig64: bytes) -> bytes:
    return sig64 if hash_type == SIGHASH_DEFAULT else sig64 + bytes([hash_type])


__all__ = ["key_agg", "taproot_tweak", "nonce_gen", "nonce_agg", "sign", "partial_sig_verify",
           "partial_sig_agg", "bip341_sighash", "schnorr"]
