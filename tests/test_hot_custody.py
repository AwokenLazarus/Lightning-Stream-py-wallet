"""AGP-013 hot-key custody: sealed at rest, rotation with a sweep, a balance cap with a human sweep,
and an append-only, hash-chained log of every signature. The model still never sees key material."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentwallet import sigaudit
from agentwallet.approval import b2x, generate_keypair, sign, sweep_message
from agentwallet.channels import ChannelBook
from agentwallet.hot import HotCapError, HotWallet
from agentwallet.keystore import KeyStore, KeyStoreError, load_or_create_keyfile
from agentwallet.sanitize import assert_no_key_material, sanitize
from agentwallet.signer import Signer

from _agp013 import FakeRpc, fund_channel, keyfile_env, write_policy

from xbt402 import ecc
from xbt402.tx import SIGHASH_ALL_UNIFIED, ST_WITNESS_V0, Tx, TxOut, p2wpkh_script_code, p2wpkh_spk, unified_sighash

REPO = Path(__file__).resolve().parents[1]


def keystore() -> KeyStore:
    return KeyStore(key=os.urandom(32))


def verify_p2wpkh_inputs(raw_hex: str, prevouts: list[TxOut]) -> bool:
    tx = Tx.parse(bytes.fromhex(raw_hex))
    for i, inp in enumerate(tx.inputs):
        sig, pub = inp.witness
        if sig[-1] != SIGHASH_ALL_UNIFIED or p2wpkh_spk(pub) != prevouts[i].script_pubkey:
            return False
        d = unified_sighash(tx, prevouts, i, ST_WITNESS_V0, p2wpkh_script_code(pub), SIGHASH_ALL_UNIFIED)
        if not ecc.verify(pub, d, sig[:-1]):
            return False
    return True


class Encryption(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_hot_key_file_holds_no_plaintext_secret(self):
        ks = keystore()
        hot = HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=ks)
        text = (self.tmp / "hot.json").read_text()
        self.assertNotIn(f"{hot.secret:064x}", text)
        self.assertNotIn('"secret"', text)
        self.assertEqual(oct((self.tmp / "hot.json").stat().st_mode & 0o777), "0o600")
        again = HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=ks)
        self.assertEqual(again.secret, hot.secret)
        self.assertTrue(again.status()["hot_encrypted"])

    def test_wrong_wrapping_key_or_tampered_file_refused(self):
        HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=keystore())
        with self.assertRaises(KeyStoreError):
            HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=keystore())
        with self.assertRaises(KeyStoreError):
            HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=None)
        ks = keystore()
        HotWallet(self.tmp / "h2.json", FakeRpc(), keystore=ks)
        doc = json.loads((self.tmp / "h2.json").read_text())
        ct = bytearray(bytes.fromhex(doc["current"]["sealed"]["ct"]))
        ct[0] ^= 1
        doc["current"]["sealed"]["ct"] = ct.hex()
        (self.tmp / "h2.json").write_text(json.dumps(doc))
        with self.assertRaises(KeyStoreError):
            HotWallet(self.tmp / "h2.json", FakeRpc(), keystore=ks)

    def test_passphrase_scrypt_and_env_is_consumed(self):
        os.environ.pop("B2_HOT_KEYFILE", None)
        os.environ["B2_HOT_PASSPHRASE"] = "correct horse battery staple"
        ks = KeyStore.from_env(self.tmp)
        self.assertEqual(ks.kind, "passphrase")
        self.assertNotIn("B2_HOT_PASSPHRASE", os.environ, "the signer drops the passphrase from its environment")
        hot = HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=ks)
        self.assertEqual(json.loads((self.tmp / "hot.json").read_text())["current"]["sealed"]["kdf"], "scrypt")
        same = HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=KeyStore(passphrase=b"correct horse battery staple"))
        self.assertEqual(same.secret, hot.secret)
        with self.assertRaises(KeyStoreError):
            HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=KeyStore(passphrase=b"wrong"))

    def test_keyfile_inside_run_dir_refused(self):
        run = self.tmp / ".run"
        run.mkdir()
        with self.assertRaises(KeyStoreError):
            load_or_create_keyfile(run / "hot.key", run)
        key = load_or_create_keyfile(self.tmp / "outside" / "hot.key", run)
        self.assertEqual(len(key), 32)
        self.assertEqual(oct((self.tmp / "outside" / "hot.key").stat().st_mode & 0o777), "0o600")

    def test_plaintext_file_is_resealed(self):
        secret = 0x1234567
        (self.tmp / "hot.json").write_text(json.dumps({"secret": f"{secret:064x}", "pub": ecc.pubkey(secret).hex()}))
        hot = HotWallet(self.tmp / "hot.json", FakeRpc(), keystore=keystore())
        self.assertEqual(hot.secret, secret)
        self.assertNotIn(f"{secret:064x}", (self.tmp / "hot.json").read_text())

    def test_channel_keys_sealed(self):
        ks, rpc = keystore(), FakeRpc()
        book = ChannelBook(self.tmp / "channels.json", self.tmp / "channel_keys.json", keystore=ks)
        fund_channel(book, rpc, "http://api.test", secret=0xC0FFEE)
        text = (self.tmp / "channel_keys.json").read_text()
        self.assertNotIn(f"{0xC0FFEE:064x}", text)
        self.assertIn("sealed", text)
        again = ChannelBook(self.tmp / "channels.json", self.tmp / "channel_keys.json", keystore=ks)
        self.assertTrue(again.sign_close("http://api.test"))

    def test_signer_refuses_to_start_without_a_wrapping_key(self):
        for k in ("B2_HOT_KEYFILE", "B2_HOT_PASSPHRASE", "B2_HOT_ALLOW_PLAINTEXT"):
            os.environ.pop(k, None)
        write_policy(self.tmp)
        with self.assertRaises(KeyStoreError):
            Signer(self.tmp, rpc=FakeRpc())
        keyfile_env()
        s = Signer(self.tmp, rpc=FakeRpc())
        self.assertTrue(s.hot.encrypted)
        self.assertNotIn(f"{s.hot.secret:064x}", (self.tmp / ".run" / "hot.json").read_text())

    def test_mcp_side_never_reads_the_wrapping_key(self):
        src = (REPO / "agentwallet" / "mcp_server.py").read_text()
        code = src.split('"""', 2)[2]          # past the module docstring
        for needle in ("B2_HOT_KEYFILE", "B2_HOT_PASSPHRASE", "keystore", "KeyStore"):
            self.assertNotIn(needle, code)
        keyfile_env()
        write_policy(self.tmp)
        s = Signer(self.tmp, rpc=FakeRpc())
        for method in ("balance", "hot_address", "forward_status", "channels"):
            out = s.handle({"method": method})
            assert_no_key_material(out)
            self.assertNotIn(f"{s.hot.secret:064x}", json.dumps(out))


class Rotation(unittest.TestCase):
    def test_rotate_sweeps_old_coins_and_keeps_old_key_sealed(self):
        tmp, ks, rpc = Path(tempfile.mkdtemp()), keystore(), FakeRpc()
        audit = sigaudit.SigAudit(tmp / "sig.jsonl")
        hot = HotWallet(tmp / "hot.json", rpc, keystore=ks, audit=audit)
        old_spk, old_secret = hot.spk, hot.secret
        hot.notice_utxo("aa" * 32, 0, 50_000)
        hot.notice_utxo("bb" * 32, 1, 30_000)
        out = hot.rotate()
        self.assertNotEqual(hot.spk, old_spk)
        raw = rpc.sent[-1]
        tx = Tx.parse(bytes.fromhex(raw))
        self.assertEqual(len(tx.inputs), 2)
        self.assertEqual([o.script_pubkey for o in tx.outputs], [hot.spk], "everything sweeps to the new key")
        self.assertEqual(tx.outputs[0].value, 80_000 - out["sweep"]["fee_sats"])
        self.assertTrue(verify_p2wpkh_inputs(raw, [TxOut(50_000, old_spk), TxOut(30_000, old_spk)]))
        self.assertEqual(hot.balance_sats(), tx.outputs[0].value)
        # restart: the new key is current, the old one is retired and still sealed
        again = HotWallet(tmp / "hot.json", rpc, keystore=ks)
        self.assertEqual(again.spk, hot.spk)
        self.assertEqual(again.status()["hot_retired_keys"], 1)
        self.assertNotIn(f"{old_secret:064x}", (tmp / "hot.json").read_text())
        # a late coin to the old address (a close's change) is swept by the watcher's pass
        again.notice_utxo("cc" * 32, 0, 20_000, old_spk.hex())
        sw = again.sweep_retired()
        self.assertTrue(verify_p2wpkh_inputs(rpc.sent[-1], [TxOut(20_000, old_spk)]))
        self.assertEqual(Tx.parse(bytes.fromhex(rpc.sent[-1])).outputs[0].script_pubkey, again.spk)
        self.assertEqual(sw["swept_sats"], 20_000 - sw["fee_sats"])
        kinds = [r["kind"] for r in audit.read()]
        self.assertEqual(kinds, ["rotation_sweep", "rotation_sweep"])

    def test_signer_rotation_is_not_an_mcp_tool(self):
        from agentwallet.mcp_server import FORBIDDEN_MCP_TOOLS, MCP_TOOL_NAMES
        self.assertIn("rotate_hot_key", FORBIDDEN_MCP_TOOLS)
        self.assertIn("sweep_hot", FORBIDDEN_MCP_TOOLS)
        self.assertTrue(FORBIDDEN_MCP_TOOLS.isdisjoint(MCP_TOOL_NAMES))


class BalanceCap(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        self.priv, self.pub = generate_keypair()
        write_policy(self.tmp, hot_balance_cap_sats=200_000, human_pubkey=b2x(self.pub))
        self.rpc = FakeRpc()
        self.s = Signer(self.tmp, rpc=self.rpc)

    def test_over_cap_refuses_new_channels_and_asks_for_a_human_sweep(self):
        self.s.hot.notice_utxo("aa" * 32, 0, 300_000)
        r = self.s.handle({"method": "open_channel", "params": {"dest": "http://api.test", "cap_sats": 10_000}})
        self.assertEqual((r["verdict"], r["rule"], r["action"]), ("deny", "hot_balance_cap", "human_sweep"))
        self.assertEqual(self.rpc.sent, [], "nothing was funded")
        with self.assertRaises(HotCapError):
            self.s.hot.check_channel_funding()
        # the model can't sweep: no signature, or one over other terms, is refused
        expiry = int(self.s.engine.clock()) + 600
        from xbt402.tx import segwit_address
        dest = segwit_address("bcrt", p2wpkh_spk(ecc.pubkey(0xD00D)))
        bad = sign(self.priv, sweep_message(self.s.hot.address, dest, 150_000, expiry))
        r = self.s.handle({"method": "sweep_hot", "params": {"to": dest, "amount_sats": 150_001, "expiry": expiry,
                                                              "signature": b2x(bad)}})
        self.assertFalse(r["ok"])
        r = self.s.handle({"method": "sweep_hot", "params": {"to": dest, "amount_sats": 150_000, "expiry": expiry}})
        self.assertFalse(r["ok"])
        good = sign(self.priv, sweep_message(self.s.hot.address, dest, 150_000, expiry))
        r = self.s.handle({"method": "sweep_hot", "params": {"to": dest, "amount_sats": 150_000, "expiry": expiry,
                                                              "signature": b2x(good)}})
        self.assertTrue(r["ok"], r)
        self.assertFalse(r["hot_over_cap"])
        tx = Tx.parse(bytes.fromhex(self.rpc.sent[-1]))
        self.assertEqual(tx.outputs[0].value, 150_000)
        self.assertEqual(tx.outputs[0].script_pubkey, p2wpkh_spk(ecc.pubkey(0xD00D)))
        # below the cap again: a channel may be funded
        r = self.s.handle({"method": "open_channel", "params": {"dest": "http://api.test", "cap_sats": 10_000}})
        self.assertEqual(r["verdict"], "allow", r)
        rows = self.s.sigaudit.read()
        self.assertEqual([(x["kind"], x["rule"]) for x in rows],
                         [("human_sweep", "human:sweep_signature"), ("funding", "method:open_channel")])


class SignatureAudit(unittest.TestCase):
    def test_every_signature_logged_with_channel_and_rule_and_chained(self):
        tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        write_policy(tmp, allowlist=["http://api.test", "bcrt1qexample"], per_counterparty_cap_sats=100_000)
        rpc = FakeRpc()
        s = Signer(tmp, rpc=rpc)
        s.hot.notice_utxo("aa" * 32, 0, 500_000)
        r = s.handle({"method": "pay", "params": {"to": "http://api.test", "amount_sats": 1500}})
        self.assertEqual(r["verdict"], "allow", r)
        r = s.handle({"method": "sign_state", "params": {"dest": "http://api.test", "cum": 3000}})
        self.assertEqual(r["verdict"], "allow", r)
        chan = r["chan"]
        s.channels.sign_close("http://api.test")
        rows = s.sigaudit.read()
        self.assertEqual([x["kind"] for x in rows], ["funding", "channel_state", "channel_state", "close_auth"])
        self.assertEqual([x["rule"] for x in rows], ["policy:ok", "policy:ok", "policy:ok", "unattributed"])
        self.assertEqual([x["method"] for x in rows], ["pay", "pay", "sign_state", ""])
        self.assertEqual([x["chan"] for x in rows[1:]], [chan] * 3)
        self.assertEqual([x.get("cum") for x in rows[1:3]], [1500, 3000])
        self.assertTrue(all(len(x["sig_sha256"]) == 64 for x in rows))
        self.assertNotIn("sig", rows[0], "the log holds a hash of each signature, not the signature")
        self.assertEqual(sigaudit.verify_chain(s.sigaudit.path), (True, 4))
        # append-only: dropping or editing a line breaks the chain
        lines = s.sigaudit.path.read_text().splitlines()
        (tmp / "cut.jsonl").write_text("\n".join(lines[:1] + lines[2:]) + "\n")
        self.assertFalse(sigaudit.verify_chain(tmp / "cut.jsonl")[0])
        (tmp / "edit.jsonl").write_text("\n".join([lines[0], lines[1].replace('"cum":1500', '"cum":15')] + lines[2:]) + "\n")
        self.assertFalse(sigaudit.verify_chain(tmp / "edit.jsonl")[0])
        # a restarted signer continues the chain
        s2 = Signer(tmp, rpc=rpc)
        s2.channels.sign_close("http://api.test")
        self.assertEqual(sigaudit.verify_chain(s2.sigaudit.path), (True, 5))
        out = s.handle({"method": "signatures", "params": {"limit": 3}})
        self.assertTrue(out["chain_ok"])
        self.assertEqual(sanitize(out), out)


if __name__ == "__main__":
    unittest.main()
