"""AGP-016: the signature log's head is anchored with a witness process the signer's user can't
rewrite. A whole-file rewrite (a fresh, self-consistent chain) passes the plain chain walk, but not
the check against the latest anchor; the witness refuses to anchor it, and the signer refuses to start."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from agentwallet import sigaudit
from agentwallet.anchor import AnchorClient, AnchorError, AnchorStore, AnchorWitness, main as anchor_main
from agentwallet.signer import Signer

from _agp013 import FakeRpc, fund_channel, keyfile_env, write_policy


def rewrite_whole_log(path: Path, n: int) -> None:
    """What an attacker with the signer's Unix user can do: replace the log with a new valid chain."""
    fake = Path(tempfile.mkdtemp()) / "forged.jsonl"
    a = sigaudit.SigAudit(fake)
    for i in range(n):
        a.record("channel_state", sig=os.urandom(64), chan="forged", cum=i, rule="policy:ok")
    path.write_bytes(fake.read_bytes())


class Witness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = sigaudit.SigAudit(self.tmp / "signatures.jsonl")
        self.store = AnchorStore(self.tmp / "witness")

    def submit(self, reason=""):
        lines = self.log.raw_lines()
        last = self.store.latest()
        head = sigaudit.check_chain(self.log.path)["head"]
        return self.store.submit(len(lines), head, [x.decode() for x in lines[last["n"]:]], reason)

    def test_append_only_and_whole_rewrite_detected(self):
        for i in range(3):
            self.log.record("channel_state", sig=os.urandom(64), chan="c1", cum=i)
        r = self.submit("close")
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["n"], r["seq"]), (3, 1))
        self.log.record("refund", sig=os.urandom(64), chan="c1")
        r = self.submit("refund")
        self.assertEqual((r["ok"], r["n"], r["seq"]), (True, 4, 2))
        anchor = self.store.latest()
        self.assertEqual(sigaudit.verify_chain(self.log.path, anchor), (True, 4))

        rewrite_whole_log(self.log.path, 5)
        self.assertEqual(sigaudit.verify_chain(self.log.path), (True, 5), "the forged chain is self-consistent")
        chk = sigaudit.check_chain(self.log.path, anchor)
        self.assertFalse(chk["ok"])
        self.assertIn("rewritten", chk["reason"])
        self.assertFalse(sigaudit.verify_chain(self.log.path, anchor)[0])
        # the witness will not anchor the forged history either
        forged = self.log.__class__(self.log.path)
        lines = forged.raw_lines()
        r = self.store.submit(len(lines), sigaudit.check_chain(self.log.path)["head"],
                              [x.decode() for x in lines[4:]], "forged")
        self.assertEqual((r["ok"], r["alert"]), (False, "fork"))
        self.assertEqual(self.store.latest()["n"], 4, "the anchor did not move")
        self.assertEqual([a["alert"] for a in self.store.alerts()], ["fork"])

    def test_truncation_and_rewind_refused(self):
        for i in range(4):
            self.log.record("funding", sig=os.urandom(64), chan="c", cum=i)
        self.submit()
        anchor = self.store.latest()
        lines = self.log.path.read_text().splitlines()
        self.log.path.write_text("\n".join(lines[:2]) + "\n")
        chk = sigaudit.check_chain(self.log.path, anchor)
        self.assertFalse(chk["ok"])
        self.assertIn("truncated", chk["reason"])
        r = self.store.submit(2, sigaudit.check_chain(self.log.path)["head"], [], "rewind")
        self.assertEqual(r.get("alert"), "rewind")
        # re-sending an anchor the witness already holds is harmless
        first = sigaudit.GENESIS
        r = self.store.submit(anchor["n"], anchor["head"], [], "again")
        self.assertTrue(r["ok"] and r.get("unchanged"))
        self.assertNotEqual(first, anchor["head"])

    def test_head_must_match_the_lines(self):
        self.log.record("funding", sig=os.urandom(64))
        lines = [x.decode() for x in self.log.raw_lines()]
        r = self.store.submit(1, "ab" * 32, lines)
        self.assertEqual(r.get("alert"), "head_mismatch")
        r = self.store.submit(2, "ab" * 32, lines)
        self.assertEqual(r.get("alert"), "bad_submission")

    def test_store_survives_restart_and_is_itself_chained(self):
        self.log.record("funding", sig=os.urandom(64))
        self.submit()
        self.log.record("refund", sig=os.urandom(64))
        self.submit()
        again = AnchorStore(self.tmp / "witness")
        self.assertEqual(again.latest()["n"], 2)
        rows = (self.tmp / "witness" / "anchors.jsonl").read_text().splitlines()
        edited = json.loads(rows[0])
        edited["head"] = "00" * 32
        (self.tmp / "witness" / "anchors.jsonl").write_text(
            json.dumps(edited, sort_keys=True, separators=(",", ":")) + "\n" + rows[1] + "\n")
        with self.assertRaises(AnchorError):
            AnchorStore(self.tmp / "witness")

    def test_cli_check(self):
        self.log.record("funding", sig=os.urandom(64))
        self.submit()
        args = ["check", "--store", str(self.tmp / "witness"), "--log", str(self.log.path)]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(anchor_main(args), 0)
            rewrite_whole_log(self.log.path, 3)
            self.assertEqual(anchor_main(args), 1)
        self.assertIn("rewritten", out.getvalue())


class SignerAnchoring(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        wdir = Path(tempfile.mkdtemp(prefix="b2w-"))
        self.witness = AnchorWitness(wdir / "store", wdir / "w.sock")
        self.witness.start_thread()
        self.addCleanup(self.witness.stop)
        os.environ["B2_ANCHOR_SOCK"] = str(wdir / "w.sock")
        self.addCleanup(os.environ.pop, "B2_ANCHOR_SOCK", None)
        write_policy(self.tmp, anchor_interval_s=0, per_counterparty_cap_sats=100_000)
        self.rpc = FakeRpc()

    def test_anchored_on_start_close_refund_and_rewrite_refuses_start(self):
        s = Signer(self.tmp, rpc=self.rpc)
        self.assertEqual(s.anchor.status()["anchored_n"], 0)
        s.hot.notice_utxo("aa" * 32, 0, 500_000)
        r = s.handle({"method": "pay", "params": {"to": "http://api.test", "amount_sats": 1500}})
        self.assertEqual(r["verdict"], "allow", r)
        self.assertEqual(s.anchor.status()["unanchored_lines"], 2, "funding + state wait for the next anchor")
        s.handle({"method": "close_channel", "params": {"counterparty": "http://api.test"}})  # the provider is not up
        st = s.anchor.status()
        self.assertEqual((st["anchored_n"], st["unanchored_lines"]), (3, 0), "the close (auth signature) is anchored")
        # a refund anchors too
        fund_channel(s.channels, self.rpc, "http://market.test", secret=0xBEEF, expiry=1010)
        self.rpc.height = 1010
        r = s.handle({"method": "xbt402_refund", "params": {"counterparty": "http://market.test"}})
        self.assertEqual(r["verdict"], "allow", r)
        self.assertEqual(s.anchor.status()["anchored_n"], 4)
        out = s.handle({"method": "signatures"})
        self.assertTrue(out["chain_ok"])
        self.assertEqual(out["chain"]["anchored_n"], 4)
        latest = AnchorClient(Path(os.environ["B2_ANCHOR_SOCK"])).latest()
        self.assertEqual(sigaudit.verify_chain(s.sigaudit.path, latest), (True, 4))

        rewrite_whole_log(s.sigaudit.path, 6)
        self.assertFalse(s.handle({"method": "signatures"})["chain_ok"])
        with self.assertRaises(sigaudit.SigAuditError):
            Signer(self.tmp, rpc=self.rpc)
        r = s.handle({"method": "anchor_now"})
        self.assertEqual(r["result"].get("alert"), "fork")
        self.assertEqual(AnchorClient(Path(os.environ["B2_ANCHOR_SOCK"])).latest()["n"], 4)

    def test_sweep_and_rotation_anchor_and_periodic_tick(self):
        write_policy(self.tmp, anchor_interval_s=1)
        s = Signer(self.tmp, rpc=self.rpc)
        s.hot.notice_utxo("aa" * 32, 0, 50_000)
        s.handle({"method": "rotate_hot_key"})
        self.assertEqual(s.anchor.status()["anchored_n"], 1)
        s.hot.notice_utxo("bb" * 32, 0, 30_000, s.hot._retired[0].spk.hex())
        s.anchor.last_at = 0
        acts = s.watch_tick()
        self.assertTrue(any("retired_sweep" in a for a in acts), acts)
        self.assertEqual(s.anchor.status()["anchored_n"], 2)
        s.sigaudit.record("close_auth", sig=os.urandom(64), rule="test")
        s.anchor.last_at = 0
        acts = s.watch_tick()
        self.assertEqual([a["anchor"]["n"] for a in acts if "anchor" in a], [3], "the periodic anchor")

    def test_anchor_required(self):
        write_policy(self.tmp, anchor_required=True)
        os.environ["B2_ANCHOR_SOCK"] = str(self.tmp / "nobody.sock")
        with self.assertRaises(sigaudit.SigAuditError):
            Signer(self.tmp, rpc=self.rpc)
        os.environ.pop("B2_ANCHOR_SOCK")
        with self.assertRaises(sigaudit.SigAuditError):
            Signer(self.tmp, rpc=self.rpc)
        # not required: an unreachable witness is reported, and signing goes on
        write_policy(self.tmp)
        os.environ["B2_ANCHOR_SOCK"] = str(self.tmp / "nobody.sock")
        s = Signer(self.tmp, rpc=self.rpc)
        self.assertIn("unreachable", s.anchor.status()["error"])

    def test_anchoring_off_without_socket(self):
        os.environ.pop("B2_ANCHOR_SOCK", None)
        s = Signer(self.tmp, rpc=self.rpc)
        self.assertFalse(s.anchor.status()["enabled"])
        self.assertTrue(s.handle({"method": "signatures"})["chain_ok"])


if __name__ == "__main__":
    unittest.main()
