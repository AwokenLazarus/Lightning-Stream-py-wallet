"""Close change is the signer's hot key, not the per-channel payer key."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelParams  # noqa: E402
from xbt402.tx import p2wpkh_spk  # noqa: E402


class ChangeSweepTests(unittest.TestCase):
    def test_state_change_is_hot_spk(self):
        secret = 0xA11CE
        payee = 0xB0B
        hot = p2wpkh_spk(ecc.pubkey(0x0707))
        chan_spk = p2wpkh_spk(ecc.pubkey(secret))
        self.assertNotEqual(hot.hex(), chan_spk.hex())
        p = ChannelParams.derive(ecc.pubkey(payee).hex(), ecc.pubkey(secret).hex(), 8_000, 600, hot.hex())
        p.funding_txid = "22" * 32
        p.funding_vout = 0
        p.capacity = 100_000
        tx = p.state_tx(8_500)
        self.assertEqual(tx.outputs[0].value, 8_500)
        self.assertEqual(tx.outputs[1].script_pubkey, hot)
        self.assertNotEqual(tx.outputs[1].script_pubkey, chan_spk)
        self.assertEqual(tx.outputs[1].value, 100_000 - 600 - 8_500)

    def test_book_stores_hot_change_spk(self):
        tmp = Path(tempfile.mkdtemp())
        book = ChannelBook(tmp / "channels.json", tmp / "channel_keys.json")
        secret = 0xA11CE
        hot = p2wpkh_spk(ecc.pubkey(0x0707)).hex()
        p = ChannelParams.derive(ecc.pubkey(0xB0B).hex(), ecc.pubkey(secret).hex(), 8_000, 600, hot)
        p.funding_txid = "33" * 32
        p.funding_vout = 0
        p.capacity = 50_000
        rec = book.add_funded("http://127.0.0.1:9", secret=secret, params=p, cap_sats=49_400)
        self.assertEqual(rec.payer_spk, hot)
        self.assertNotEqual(rec.payer_spk, p2wpkh_spk(ecc.pubkey(secret)).hex())


if __name__ == "__main__":
    unittest.main()
