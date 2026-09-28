"""AGP-016: treasury.json's demo human, cosigner and recovery secrets are sealed like hot.json
(AES-256-GCM, a wrapping key from the signer's environment) and re-sealed on the first start."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentwallet.keystore import KeyStore, KeyStoreError
from agentwallet.sanitize import assert_no_key_material
from agentwallet.signer import Signer
from agentwallet.treasury import Treasury

from _agp013 import FakeRpc, keyfile_env, write_policy

from xbt402.tx import SIGHASH_ALL_UNIFIED


def secrets_of(t: Treasury) -> list[str]:
    return [f"{x:064x}" for x in (t.human_secret, t.cosigner_secret, t.recovery_secret)]


class Sealed(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.path = self.tmp / "treasury.json"
        self.ks = KeyStore(key=os.urandom(32))

    def test_no_plaintext_secret_on_disk_and_reopens(self):
        t = Treasury(self.path, keystore=self.ks)
        text = self.path.read_text()
        for s in secrets_of(t):
            self.assertNotIn(s, text)
        doc = json.loads(text)
        self.assertTrue(doc["encrypted"])
        self.assertEqual(set(doc) & {"human", "cosigner", "recovery"}, set(), "no secret fields in the clear")
        self.assertEqual(doc["pubs"]["recovery"], t.recovery_pub.hex())
        self.assertEqual(oct(self.path.stat().st_mode & 0o777), "0o600")
        t.record_funding("ab" * 32, 1, 100_000)            # every rewrite stays sealed
        self.assertNotIn(secrets_of(t)[2], self.path.read_text())
        again = Treasury(self.path, keystore=self.ks)
        self.assertEqual((again.address, secrets_of(again)), (t.address, secrets_of(t)))
        self.assertEqual(again.status()["treasury_outpoint"], "ab" * 32 + ":1")
        tx = again.recovery_tx(bytes.fromhex("0014" + "11" * 20))
        self.assertEqual(tx.inputs[0].witness[0][-1], SIGHASH_ALL_UNIFIED)

    def test_wrong_key_missing_key_or_tampered_refused(self):
        Treasury(self.path, keystore=self.ks)
        with self.assertRaises(KeyStoreError):
            Treasury(self.path, keystore=KeyStore(key=os.urandom(32)))
        with self.assertRaises(KeyStoreError):
            Treasury(self.path, keystore=None)
        doc = json.loads(self.path.read_text())
        ct = bytearray(bytes.fromhex(doc["sealed"]["ct"]))
        ct[-1] ^= 1
        doc["sealed"]["ct"] = ct.hex()
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(KeyStoreError):
            Treasury(self.path, keystore=self.ks)

    def test_swapped_pubs_refused(self):
        Treasury(self.path, keystore=self.ks)
        doc = json.loads(self.path.read_text())
        doc["pubs"]["human"], doc["pubs"]["cosigner"] = doc["pubs"]["cosigner"], doc["pubs"]["human"]
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(KeyStoreError):
            Treasury(self.path, keystore=self.ks)

    def test_hot_key_blob_cannot_stand_in_for_the_treasury(self):
        from agentwallet.hot import HotWallet
        hot = HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=self.ks)
        Treasury(self.path, keystore=self.ks)
        doc = json.loads(self.path.read_text())
        doc["sealed"] = json.loads((self.tmp / "hot.json").read_text())["current"]["sealed"]
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(KeyStoreError):                 # bound to its own AAD
            Treasury(self.path, keystore=self.ks)
        self.assertTrue(hot.encrypted)

    def test_passphrase(self):
        t = Treasury(self.path, keystore=KeyStore(passphrase=b"treasury pass"))
        self.assertEqual(json.loads(self.path.read_text())["sealed"]["kdf"], "scrypt")
        self.assertEqual(Treasury(self.path, keystore=KeyStore(passphrase=b"treasury pass")).address, t.address)
        with self.assertRaises(KeyStoreError):
            Treasury(self.path, keystore=KeyStore(passphrase=b"nope"))

    def test_plaintext_file_resealed_on_first_start(self):
        old = Treasury(self.path)                             # AGP-013 behaviour: no keystore, secrets in clear
        self.assertIn(secrets_of(old)[0], self.path.read_text())
        # the exact AGP-013 file shape (no pubs, no version)
        self.path.write_text(json.dumps({"human": secrets_of(old)[0], "cosigner": secrets_of(old)[1],
                                         "recovery": secrets_of(old)[2], "csv": 4320, "funding_txid": "cd" * 32,
                                         "funding_vout": 0, "capacity": 50_000}))
        new = Treasury(self.path, keystore=self.ks)
        self.assertEqual((new.address, new.capacity), (old.address, 50_000))
        text = self.path.read_text()
        for s in secrets_of(old):
            self.assertNotIn(s, text)


class SignerTreasury(unittest.TestCase):
    def test_signer_seals_the_treasury_and_never_returns_its_keys(self):
        tmp = Path(tempfile.mkdtemp())
        write_policy(tmp)
        run = tmp / ".run"
        run.mkdir()
        old = Treasury(run / "treasury.json")                 # a wallet from before AGP-016
        for k in ("B2_HOT_KEYFILE", "B2_HOT_PASSPHRASE", "B2_HOT_ALLOW_PLAINTEXT"):
            os.environ.pop(k, None)
        with self.assertRaises(KeyStoreError):                # no wrapping key: the signer won't start
            Signer(tmp, rpc=FakeRpc())
        keyfile_env()
        s = Signer(tmp, rpc=FakeRpc())
        self.assertTrue(s.treasury.encrypted)
        self.assertEqual(s.treasury.address, old.address)
        text = (run / "treasury.json").read_text()
        for sec in secrets_of(old):
            self.assertNotIn(sec, text)
        for method in ("balance", "hot_address", "channels", "signatures"):
            out = s.handle({"method": method})
            assert_no_key_material(out)
            for sec in secrets_of(old):
                self.assertNotIn(sec, json.dumps(out))


if __name__ == "__main__":
    unittest.main()
