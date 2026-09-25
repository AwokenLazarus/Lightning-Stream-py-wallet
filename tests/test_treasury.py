"""Treasury script is CSV older(4320); recovery signature is 0x21."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentwallet.b1path import ensure_b1
from agentwallet.treasury import TREASURY_CSV, Treasury, treasury_script

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.tx import SIGHASH_ALL_UNIFIED, script_num  # noqa: E402


class TreasuryTests(unittest.TestCase):
    def test_csv_constant(self):
        self.assertEqual(TREASURY_CSV, 4320)

    def test_script_contains_csv_and_if(self):
        a, b, c = (ecc.pubkey(i) for i in (1, 2, 3))
        script = treasury_script(a, b, c, 4320)
        self.assertIn(bytes([0x63]), script)  # OP_IF
        self.assertIn(script_num(4320), script)
        self.assertIn(bytes([0xB2]), script)  # OP_CHECKSEQUENCEVERIFY
        self.assertEqual(script[-1], 0x68)  # OP_ENDIF

    def test_recovery_tx_is_0x21_and_csv_sequence(self):
        tmp = Path(tempfile.mkdtemp()) / "treasury.json"
        t = Treasury(tmp, csv=4320)
        t.record_funding("ab" * 32, 0, 100_000)
        dest = bytes.fromhex("0014" + "11" * 20)
        tx = t.recovery_tx(dest, fee=600)
        self.assertEqual(tx.inputs[0].sequence, 4320)
        wit = tx.inputs[0].witness
        self.assertEqual(wit[0][-1], SIGHASH_ALL_UNIFIED)
        self.assertEqual(wit[1], b"")
        self.assertEqual(wit[2], t.script)
        st = t.status()
        self.assertEqual(st["treasury_csv"], 4320)
        self.assertNotIn("secret", st)
        self.assertNotIn("human", st)

    def test_status_omits_keys(self):
        tmp = Path(tempfile.mkdtemp()) / "t.json"
        t = Treasury(tmp)
        st = t.status()
        self.assertTrue(st["treasury_address"].startswith("bcrt1"))
        dumped = str(st)
        self.assertNotIn(f"{t.recovery_secret:x}", dumped)


if __name__ == "__main__":
    unittest.main()
