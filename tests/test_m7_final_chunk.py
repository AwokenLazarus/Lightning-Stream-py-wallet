"""AGP-005 M7 in the wallet's stream: the last chunk's hash lock was signed before the ciphertext.

The manifest commits to `finalCt` = H(ciphertext of the last chunk), but the wallet signed the
hash-locked increment on a 402 that carried only H, and took the ciphertext from the paid response.
Since M6 a provider closes with a signed hash lock and claims it; the claim reveals k and nothing
else. A provider that drops (or loses) the paid response is paid the chunk's price and the payer
holds a key with nothing to decrypt. The loss is one chunk's price per stream.

Fixed: the last chunk's 402 must carry `extra.conditional.cipher` with H(cipher) == finalCt, checked
before anything is signed; otherwise the offer is refused. The ciphertext is kept with the channel
record (`pending_cond`), so `recover_conditional()` opens the chunk from the provider's claim, and the
wallet decrypts the offered ciphertext, never one a response substitutes.

`test_repro_*` runs the wallet as shipped at ef3c787 (b2 agp-005) and must reproduce; the rest run
this tree. The provider is B1's XbtChannelProvider on a fake node.
"""

from __future__ import annotations

import atexit
import copy
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook
from agentwallet.stream import Commitment, StreamError
from agentwallet.xbt402 import Xbt402Session

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.tx import Tx  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, b64json, unb64json  # noqa: E402

SEC = Path(ensure_b1()) / "tests" / "security"
if str(SEC) not in sys.path:
    sys.path.insert(0, str(SEC))
from sechelp import FakeNode, make_channel, make_provider  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
BASE = "ef3c787"            # b2 agp-005: the wallet before this fix
ORIGIN = "http://api.test"
PRICE = 1000
RID = "r1"
LAST = f"/v1/report/{RID}/chunk/3"
_old = {}


def shipped():
    """agentwallet as shipped at BASE, importable as `agentwallet_ef3c787`."""
    if "mod" not in _old:
        tmp = tempfile.mkdtemp(prefix="b2-ef3c787-")
        atexit.register(shutil.rmtree, tmp, True)
        try:
            arc = subprocess.run(["git", "-C", str(REPO), "archive", BASE, "agentwallet"], check=True,
                                 capture_output=True).stdout
            subprocess.run(["tar", "-x", "-C", tmp], input=arc, check=True)
        except (subprocess.CalledProcessError, OSError):
            raise unittest.SkipTest(f"{BASE} unavailable")
        shutil.move(os.path.join(tmp, "agentwallet"), os.path.join(tmp, "agentwallet_ef3c787"))
        sys.path.insert(0, tmp)
        _old["mod"] = importlib.import_module("agentwallet_ef3c787.xbt402")
    return _old["mod"]


class Hot:
    spk = bytes.fromhex("0014" + "22" * 20)


class Rig:
    """A B1 provider selling one report's last chunk under the manifest's hash lock, a funded channel
    in the wallet's book, and HTTP straight into provider.serve. `strip_cipher` / `bad_cipher` model a
    provider whose 402 leaves the ciphertext out or offers another one; `drop` one whose paid answer
    never arrives; `swap` one whose paid answer carries a different ciphertext."""

    def __init__(self, session_mod=None):
        import xbt402.channel as ch
        self.node = FakeNode()
        self.prov = make_provider(__import__("xbt402.x402_channel", fromlist=["x"]), self.node)
        chunks = Commitment.split(b"".join(b"line %02d of the report\n" % i for i in range(12)), 72)
        self.chunks = chunks
        _, _, k = self.prov.offer_conditional(LAST, PRICE, chunks[-1])
        self.c = Commitment(RID, chunks, PRICE, 0xB0B, k)
        self.p, _ = make_channel(ch, self.prov, self.node, a=0xA11CE, capacity=100_000)
        tmp = Path(tempfile.mkdtemp())
        self.book = ChannelBook(tmp / "channels.json", tmp / "channel_keys.json")
        self.book.add_funded(ORIGIN, secret=0xA11CE, params=self.p, origin=ORIGIN, cap_sats=99_000)
        mod = session_mod or sys.modules["agentwallet.xbt402"]
        self.s = mod.Xbt402Session(self.book, Hot(), rpc=None, height=lambda: 1000)
        self.s.network = lambda: self.prov.network
        if hasattr(self.s, "set_spend_book"):
            self.s.set_spend_book(lambda *_args: None)  # this fixture is not the signer; the signer books
        self.strip_cipher = self.bad_cipher = self.drop = self.swap = False

    def http(self, method, url, body=b"", headers=None):
        path = "/" + url.split("/", 3)[3]
        st, h, out = self.prov.serve(method, path, headers or {}, body or b"", url)
        h = {k.upper(): v for k, v in h.items()}
        paid = "PAYMENT-SIGNATURE" in (headers or {})
        if st == 402 and (self.strip_cipher or self.bad_cipher):
            pr = unb64json(h["PAYMENT-REQUIRED"])
            cond = pr["accepts"][0]["extra"]["conditional"]
            if self.strip_cipher:
                cond.pop("cipher")
            else:
                cond["cipher"] = bytes(len(self.c.final_ct)).hex()
            h["PAYMENT-REQUIRED"] = b64json(pr)
            out = json.dumps(pr).encode()
        if path == LAST and paid and self.drop:
            return 504, {}, b""                  # served and signed for, the answer never arrives
        if path == LAST and paid and self.swap and st == 200:
            d = json.loads(out)
            d["cipher"] = bytes(len(self.c.final_ct)).hex()
            out = json.dumps(d).encode()
        return st, h, out

    def buy_last(self):
        doc = {"chunkUrl": f"/v1/report/{RID}/chunk/{{i}}"}
        with mock.patch.object(XbtChannelClient, "http", staticmethod(self.http)):
            return self.s._final_chunk(ORIGIN, doc, copy.deepcopy(self.c.manifest))

    @property
    def chan(self):
        return next(iter(self.prov.ledger.channels.values()))

    def close_and_claim(self):
        self.node.height = self.chan.params.expiry - self.prov.close_margin
        self.prov.close_due()
        close_txid = self.chan.closed_txid
        return next(hx for hx in self.node.sent
                    if any(i.txid[::-1].hex() == close_txid for i in Tx.parse(bytes.fromhex(hx)).inputs))


class FinalChunkM7(unittest.TestCase):
    def test_repro_signs_the_hash_lock_without_the_ciphertext(self):
        r = Rig(shipped())
        r.strip_cipher, r.drop = True, True
        with self.assertRaises(Exception):
            r.buy_last()
        self.assertTrue(r.chan.cond_sig, f"did not reproduce on {BASE}: provider holds no signed hash lock")
        claim = r.close_and_claim()                                   # the provider is paid on-chain...
        k = r.prov._cond_state(r.chan)[2]
        self.assertIn(k, Tx.parse(bytes.fromhex(claim)).inputs[0].witness)
        rec = r.book.get(ORIGIN)                                      # ...the payer has k and no ciphertext
        self.assertNotIn(r.c.final_ct.hex(), json.dumps(rec.__dict__))
        sys.stderr.write(f"\n    REPRODUCED on {BASE}: last chunk's hash lock signed on a 402 without the "
                         f"ciphertext; provider closed and claimed {PRICE} sat, payer holds k only ")

    def test_fixed_offer_without_cipher_refused_before_signing(self):
        r = Rig()
        r.strip_cipher = True
        seq = r.book.get(ORIGIN).seq
        with self.assertRaisesRegex(StreamError, "no ciphertext; refused before signing"):
            r.buy_last()
        self.assertFalse(r.chan.cond_sig)
        self.assertEqual(r.book.get(ORIGIN).seq, seq)
        self.assertEqual(r.book.get(ORIGIN).pending_cond, {})

    def test_fixed_offer_with_other_cipher_refused_before_signing(self):
        r = Rig()
        r.bad_cipher = True
        with self.assertRaisesRegex(StreamError, "does not match the committed finalCt; refused before signing"):
            r.buy_last()
        self.assertFalse(r.chan.cond_sig)

    def test_fixed_dropped_response_recovered_from_the_claim(self):
        r = Rig()
        r.drop = True
        with self.assertRaisesRegex(StreamError, "recover_conditional"):
            r.buy_last()
        self.assertTrue(r.chan.cond_sig)
        # the ciphertext survives a restart: a new book reads it from disk
        book2 = ChannelBook(r.book.records_path, r.book.keys_path)
        self.assertEqual(book2.get(ORIGIN).pending_cond["cipher"], r.c.final_ct.hex())
        s2 = Xbt402Session(book2, Hot(), rpc=None, height=lambda: 1000)
        claim = r.close_and_claim()
        self.assertEqual(s2.recover_conditional(ORIGIN, claim), r.chunks[-1])
        self.assertEqual(book2.get(ORIGIN).pending_cond, {})
        with self.assertRaisesRegex(StreamError, "no pending"):
            s2.recover_conditional(ORIGIN, claim)

    def test_fixed_recover_refuses_a_transaction_without_k(self):
        r = Rig()
        r.drop = True
        with self.assertRaises(StreamError):
            r.buy_last()
        with self.assertRaisesRegex(StreamError, "does not reveal"):
            r.s.recover_conditional(ORIGIN, Tx(version=2, inputs=[], outputs=[], locktime=0))

    def test_fixed_honest_offer_decrypts_the_offered_cipher(self):
        r = Rig()
        r.swap = True                                  # the paid answer carries another ciphertext
        pt, _ = r.buy_last()
        self.assertEqual(pt, r.chunks[-1])
        self.assertEqual(r.book.get(ORIGIN).pending_cond, {})
        self.assertEqual(r.book.get(ORIGIN).used_sats, PRICE)


if __name__ == "__main__":
    unittest.main()
