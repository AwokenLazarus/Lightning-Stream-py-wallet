"""Wallet-side streamed fair-exchange verify (upstreamed from the flagship)."""

from __future__ import annotations

import secrets
import unittest

from agentwallet.b1path import ensure_b1
from agentwallet.stream import (
    Commitment,
    StreamError,
    check_chunk,
    check_manifest,
    merkle_root,
    open_final,
    verify_proof,
)

ensure_b1()
from xbt402 import ecc  # noqa: E402


class StreamVerifyTests(unittest.TestCase):
    def setUp(self):
        self.secret = secrets.randbelow(ecc.N - 1) + 1
        self.key = secrets.token_bytes(32)
        chunks = [b"chunk-%d-%s" % (i, b"x" * 40) for i in range(4)]
        self.c = Commitment("r1", chunks, 600, self.secret, self.key)

    def test_honest_manifest_and_chunks(self):
        check_manifest(self.c.manifest, self.c.manifest["payTo"])
        for i in range(3):
            pt = check_chunk(self.c.manifest, self.c.chunk(i))
            self.assertEqual(pt, self.c.chunks[i])
        last = open_final(self.c.manifest, self.c.final_ct, self.key)
        self.assertEqual(last, self.c.chunks[-1])

    def test_tampered_chunk_refused(self):
        bad = self.c.chunk(1, tamper=True)
        with self.assertRaisesRegex(StreamError, "tampered"):
            check_chunk(self.c.manifest, bad)

    def test_forged_manifest_refused(self):
        m = dict(self.c.manifest)
        m["sig"] = "30" * 32
        with self.assertRaisesRegex(StreamError, "bad manifest"):
            check_manifest(m, m["payTo"])

    def test_wrong_hashlock_key_refused(self):
        with self.assertRaisesRegex(StreamError, "hash lock"):
            open_final(self.c.manifest, self.c.final_ct, b"\x11" * 32)

    def test_merkle_root_matches_proofs(self):
        root = merkle_root(self.c.leaves).hex()
        self.assertEqual(root, self.c.manifest["root"])
        self.assertTrue(verify_proof(root, 0, self.c.chunks[0], self.c.chunk(0)["proof"]))


if __name__ == "__main__":
    unittest.main()
