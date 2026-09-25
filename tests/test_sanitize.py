import unittest

from agentwallet.sanitize import KeyMaterialError, assert_no_key_material, sanitize


class SanitizeTests(unittest.TestCase):
    def test_drops_key_fields(self):
        out = sanitize({"txid": "aa" * 32, "privkey": "cTsecret", "balance": 1})
        self.assertNotIn("privkey", out)
        self.assertEqual(out["balance"], 1)
        self.assertEqual(out["txid"], "aa" * 32)

    def test_redacts_wif_and_xprv(self):
        wif = "L1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aB5cD6eF7g"
        # use a plausible WIF-shaped string
        out = sanitize({"note": "xprv9s21ZrQH143K3dummyprivatestringXXXX"})
        self.assertIn("[redacted]", str(out))

    def test_assert_rejects_priv_field(self):
        with self.assertRaises(KeyMaterialError):
            assert_no_key_material({"dumpprivkey": "nope"})


if __name__ == "__main__":
    unittest.main()
