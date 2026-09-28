"""AGP-016: the hot key's UTXO set survives a restart (sealed on disk, reconciled against the node at
start), and a rotation after a restart sweeps every coin, including ones only the node knew about."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentwallet.hot import HotWallet
from agentwallet.keystore import KeyStore, KeyStoreError
from agentwallet.signer import Signer

from _agp013 import FakeRpc, keyfile_env, write_policy
from test_hot_custody import verify_p2wpkh_inputs

from xbt402 import ecc
from xbt402.tx import Tx, TxOut, p2wpkh_spk


def coin(rpc: FakeRpc, spk: bytes, sats: int, txid: str | None = None, vout: int = 0) -> tuple[str, int]:
    """A confirmed output to `spk` that the node knows."""
    txid = txid or os.urandom(32).hex()
    rpc.utxos[(txid, vout)] = {"value": sats / 1e8, "scriptPubKey": {"hex": spk.hex()}}
    return txid, vout


class Persist(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ks = KeyStore(key=os.urandom(32))
        self.rpc = FakeRpc(track_outputs=True)

    def hot(self, ks=None, **kw) -> HotWallet:
        return HotWallet(self.tmp / "hot.json", self.rpc, keystore=ks or self.ks, **kw)

    def test_restart_with_coins_still_spendable(self):
        h1 = self.hot()
        a = coin(self.rpc, h1.spk, 120_000)
        b = coin(self.rpc, h1.spk, 40_000)
        h1.notice_utxo(*a, 120_000)
        h1.notice_utxo(*b, 40_000)
        text = (self.tmp / "hot_utxos.json").read_text()
        self.assertNotIn(a[0], text, "the UTXO set is sealed, not just stored")
        self.assertIn("sealed", text)
        self.assertEqual(oct((self.tmp / "hot_utxos.json").stat().st_mode & 0o777), "0o600")

        h2 = self.hot()                                   # restart: coins come back from the sealed file
        self.assertEqual(h2.balance_sats(), 160_000)
        r = h2.reconcile(scan=False)
        self.assertEqual((r["ok"], r["kept"], r["stale"]), (True, 2, 0))
        dest = p2wpkh_spk(ecc.pubkey(0xD00D))
        txid, _ = h2.fund(dest, 100_000)
        raw = self.rpc.sent[-1]
        self.assertTrue(verify_p2wpkh_inputs(raw, [TxOut(120_000, h2.spk)]))
        self.assertEqual(Tx.parse(bytes.fromhex(raw)).outputs[0].script_pubkey, dest)
        h3 = self.hot()                                   # the spend and its change persisted too
        h3.reconcile(scan=False)
        self.assertEqual(sorted(u["value"] for u in h3._utxos), [19_400, 40_000])
        self.assertEqual(h3.balance_sats(), h2.balance_sats())

    def test_reconcile_marks_spent_stale_restores_and_finds_unknown_coins(self):
        h1 = self.hot()
        a = coin(self.rpc, h1.spk, 70_000)
        b = coin(self.rpc, h1.spk, 30_000)
        c = coin(self.rpc, h1.spk, 25_000)
        for op, v in ((a, 70_000), (b, 30_000), (c, 25_000)):
            h1.notice_utxo(*op, v)
        # while the signer is down: b is spent elsewhere, c's recorded value is wrong on disk,
        # and a close's change (d) lands on the hot key without the signer seeing it
        gone = self.rpc.utxos.pop(b)
        self.rpc.utxos[c]["value"] = 26_000 / 1e8
        d = coin(self.rpc, h1.spk, 9_000)
        h2 = self.hot()
        r = h2.reconcile()
        self.assertEqual((r["kept"], r["stale"], r["dropped"], r["found"]), (1, 1, 1, 2), r)
        self.assertEqual(sorted((u["txid"], u["value"]) for u in h2._utxos),
                         sorted([(a[0], 70_000), (c[0], 26_000), (d[0], 9_000)]))
        self.assertEqual(h2.status()["hot_stale_utxos"], 1)
        self.assertNotIn(b[0], [u["txid"] for u in h2._utxos], "a stale coin is neither spent nor counted")
        # the node had only lagged: b comes back at the next reconcile
        self.rpc.utxos[b] = gone
        r = self.hot().reconcile(scan=False)
        self.assertEqual((r["restored"], r["stale"]), (1, 0))

    def test_rotation_after_restart_sweeps_everything(self):
        h1 = self.hot()
        old_spk = h1.spk
        ops = [coin(self.rpc, old_spk, v) for v in (50_000, 30_000)]
        for op, v in zip(ops, (50_000, 30_000)):
            h1.notice_utxo(*op, v)
        late = coin(self.rpc, old_spk, 20_000)             # never noticed: only the node knows it
        h2 = self.hot()
        h2.reconcile()
        out = h2.rotate()
        raw = self.rpc.sent[-1]
        tx = Tx.parse(bytes.fromhex(raw))
        self.assertEqual(sorted((i.txid[::-1].hex(), i.vout) for i in tx.inputs), sorted(ops + [late]))
        self.assertTrue(verify_p2wpkh_inputs(raw, [TxOut(v, old_spk) for v in
                                                    [dict(zip(ops + [late], (50_000, 30_000, 20_000)))[
                                                        (i.txid[::-1].hex(), i.vout)] for i in tx.inputs]]))
        self.assertEqual([o.script_pubkey for o in tx.outputs], [h2.spk])
        self.assertEqual(out["sweep"]["inputs"], 3)
        h3 = self.hot()                                    # and that survives the next restart
        r = h3.reconcile()
        self.assertEqual(h3.balance_sats(), 100_000 - out["sweep"]["fee_sats"])
        self.assertEqual((r["kept"], r["found"]), (1, 0))

    def test_retired_key_coins_found_after_restart(self):
        h1 = self.hot()
        old = h1.spk
        h1.rotate()                                        # no coins yet: nothing to sweep
        refund = coin(self.rpc, old, 15_000)               # a refund to the old key while the signer was down
        h2 = self.hot()
        h2.reconcile()
        self.assertEqual(h2.status()["hot_retired_sats"], 15_000)
        sw = h2.sweep_retired()
        self.assertEqual(Tx.parse(bytes.fromhex(self.rpc.sent[-1])).inputs[0].txid[::-1].hex(), refund[0])
        self.assertEqual(sw["inputs"], 1)

    def test_tampered_or_wrong_key_refused_and_plaintext_resealed(self):
        h1 = self.hot()
        h1.notice_utxo(*coin(self.rpc, h1.spk, 10_000), 10_000)
        p = self.tmp / "hot_utxos.json"
        doc = json.loads(p.read_text())
        ct = bytearray(bytes.fromhex(doc["sealed"]["ct"]))
        ct[3] ^= 1
        doc["sealed"]["ct"] = ct.hex()
        p.write_text(json.dumps(doc))
        with self.assertRaises(KeyStoreError):
            self.hot()
        # a plaintext set (as a keystore-less test wallet leaves it) is re-sealed on the next keyed start
        p.unlink()
        plain = HotWallet(self.tmp / "p.json", self.rpc, keystore=None)
        op = coin(self.rpc, plain.spk, 11_000)
        plain.notice_utxo(*op, 11_000)
        self.assertIn(op[0], (self.tmp / "p_utxos.json").read_text())
        (self.tmp / "p.json").write_text(json.dumps({"secret": f"{plain.secret:064x}", "pub": plain.pub.hex()}))
        sealed = HotWallet(self.tmp / "p.json", self.rpc, keystore=self.ks)
        self.assertEqual(sealed.balance_sats(), 11_000)
        self.assertNotIn(op[0], (self.tmp / "p_utxos.json").read_text())
        with self.assertRaises(KeyStoreError):
            HotWallet(self.tmp / "p.json", self.rpc, keystore=KeyStore(key=os.urandom(32)))

    def test_node_unreachable_keeps_coins_unverified(self):
        h1 = self.hot()
        h1.notice_utxo(*coin(self.rpc, h1.spk, 10_000), 10_000)

        class Down(FakeRpc):
            def call(self, method, *params):
                raise ConnectionRefusedError("node down")

        h2 = HotWallet(self.tmp / "hot.json", Down(), keystore=self.ks)
        r = h2.reconcile()
        self.assertFalse(r["ok"])
        self.assertIn("unreachable", r["reason"])
        self.assertEqual(h2.balance_sats(), 10_000)


class SignerRestart(unittest.TestCase):
    def test_signer_restart_keeps_hot_coins_and_funds_a_channel(self):
        tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        write_policy(tmp, per_counterparty_cap_sats=100_000)
        rpc = FakeRpc(track_outputs=True)
        s1 = Signer(tmp, rpc=rpc)
        s1.hot.notice_utxo(*coin(rpc, s1.hot.spk, 500_000), 500_000)
        s2 = Signer(tmp, rpc=rpc)                          # restart
        self.assertEqual(s2.hot.status()["hot_sats"], 500_000)
        self.assertTrue(s2.hot.last_reconcile["ok"])
        at_start = s2.handle({"method": "hot_reconcile", "params": {"last": True}})
        self.assertEqual((at_start["kept"], at_start["found"], at_start["hot_sats"]), (1, 0, 500_000))
        r = s2.handle({"method": "pay", "params": {"to": "http://api.test", "amount_sats": 1500}})
        self.assertEqual(r["verdict"], "allow", r)
        r = s2.handle({"method": "hot_reconcile", "params": {"scan": True}})
        self.assertEqual((r["kept"], r["stale"], r["found"]), (1, 0, 0), r)
        self.assertEqual(r["hot_sats"], s2.hot.balance_sats())


if __name__ == "__main__":
    unittest.main()
