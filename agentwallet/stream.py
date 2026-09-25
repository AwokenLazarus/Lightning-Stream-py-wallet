"""Streamed fair-exchange verify (P-003 B4) inside the B2 signer.

Provider commits to a result, then sells it chunk by chunk. The model never hashes:
this module runs next to the channel keys.

  manifest = {id, n, size, root, lock, finalCt, price} signed by the provider's payTo key
    root     Merkle root (sha256) over leaf_i = H("leaf" | i | sha256(chunk_i))
    lock     sha256(k): the last chunk is sold encrypted under k
    finalCt  sha256(ciphertext of the last chunk)
"""

from __future__ import annotations

import hashlib

from .b1path import ensure_b1

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.conditional import encrypt  # noqa: E402
from xbt402.tx import tagged_hash  # noqa: E402


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf(i: int, chunk: bytes) -> bytes:
    return H(b"leaf" + i.to_bytes(4, "big") + H(chunk))


def _up(level):
    if len(level) % 2:
        level = level + [level[-1]]
    return [H(b"node" + level[j] + level[j + 1]) for j in range(0, len(level), 2)]


def merkle_root(leaves):
    level = list(leaves)
    while len(level) > 1:
        level = _up(level)
    return level[0]


def merkle_proof(leaves, i):
    level, proof = list(leaves), []
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        proof.append(level[i ^ 1].hex())
        level, i = _up(level), i // 2
    return proof


def verify_proof(root_hex: str, i: int, chunk: bytes, proof) -> bool:
    h = leaf(i, chunk)
    for sib in proof:
        s = bytes.fromhex(sib)
        h = H(b"node" + h + s) if i % 2 == 0 else H(b"node" + s + h)
        i //= 2
    return h.hex() == root_hex


def manifest_message(m: dict) -> bytes:
    keys = ("id", "n", "size", "root", "lock", "finalCt", "price", "payTo")
    return tagged_hash("xbt402/stream-manifest", "|".join(str(m[k]) for k in keys).encode())


class StreamError(Exception):
    pass


def check_manifest(m: dict, pay_to: str):
    if m.get("payTo") != pay_to:
        raise StreamError("manifest not from this provider's payTo key")
    try:
        good = ecc.verify(bytes.fromhex(pay_to), manifest_message(m), bytes.fromhex(m["sig"]))
    except Exception:  # noqa: BLE001
        good = False
    if not good:
        raise StreamError("bad manifest signature")


def check_chunk(m: dict, c: dict) -> bytes:
    i = c["i"]
    if c.get("encrypted"):
        if i != m["n"] - 1:
            raise StreamError(f"chunk {i}: only the last chunk may be encrypted")
        ct = bytes.fromhex(c["ct"])
        if H(ct).hex() != m["finalCt"]:
            raise StreamError(f"chunk {i}: ciphertext does not match the committed finalCt")
        return ct
    data = bytes.fromhex(c["data"])
    if not verify_proof(m["root"], i, data, c["proof"]):
        raise StreamError(f"chunk {i}: Merkle proof fails against the committed root (tampered)")
    return data


def open_final(m: dict, ct: bytes, key: bytes) -> bytes:
    if H(ct).hex() != m["finalCt"]:
        raise StreamError("last chunk ciphertext does not match the committed finalCt")
    if H(key).hex() != m["lock"]:
        raise StreamError("revealed key does not match the hash lock")
    pt = encrypt(ct, key)
    if not verify_proof(m["root"], m["n"] - 1, pt, m["lastProof"]):
        raise StreamError("decrypted last chunk fails the Merkle proof (provably bad commitment)")
    return pt


class Commitment:
    """Provider-side helper (tests / demo). `key` is the hash-lock preimage."""

    def __init__(self, rid: str, chunks, price: int, pay_to_secret: int, key: bytes):
        self.rid, self.key, self.chunks = rid, key, list(chunks)
        self.leaves = [leaf(i, c) for i, c in enumerate(self.chunks)]
        self.final_ct = encrypt(self.chunks[-1], key)
        m = {
            "id": rid,
            "n": len(self.chunks),
            "size": sum(map(len, self.chunks)),
            "root": merkle_root(self.leaves).hex(),
            "lock": H(key).hex(),
            "finalCt": H(self.final_ct).hex(),
            "price": price,
            "payTo": ecc.pubkey(pay_to_secret).hex(),
        }
        m["sig"] = ecc.sign(pay_to_secret, manifest_message(m)).hex()
        m["lastProof"] = merkle_proof(self.leaves, len(self.chunks) - 1)
        self.manifest = m

    @staticmethod
    def split(data: bytes, chunk_size: int):
        return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

    def chunk(self, i: int, tamper: bool = False) -> dict:
        if i == len(self.chunks) - 1:
            return {"i": i, "encrypted": True, "ct": self.final_ct.hex()}
        data = self.chunks[i]
        if tamper:
            data = data[:10] + bytes(b ^ 0x20 for b in data[10:40]) + data[40:]
        return {"i": i, "encrypted": False, "data": data.hex(), "proof": merkle_proof(self.leaves, i)}
