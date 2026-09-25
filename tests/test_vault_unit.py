"""Vault status never includes the presigned hex."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from agentwallet.vault import PresignedVault


class VaultTests(unittest.TestCase):
    def test_status_omits_hex(self):
        tmp = Path(tempfile.mkdtemp()) / "vault.json"
        rpc = MagicMock()
        v = PresignedVault(tmp, rpc, "bcrt1qrecovery")
        tmp.write_text(
            json.dumps(
                {
                    "presigned_hex": "deadbeef" * 20,
                    "recovery_address": "bcrt1qrecovery",
                    "txid": None,
                }
            )
        )
        st = v.status()
        self.assertTrue(st["recovery_ready"])
        self.assertNotIn("presigned_hex", st)
        self.assertNotIn("hex", st)

    def test_recover_requires_human(self):
        tmp = Path(tempfile.mkdtemp()) / "vault.json"
        v = PresignedVault(tmp, MagicMock(), "bcrt1qrecovery")
        with self.assertRaises(PermissionError):
            v.recover(human=False)


if __name__ == "__main__":
    unittest.main()
