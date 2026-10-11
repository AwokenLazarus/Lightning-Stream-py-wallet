"""AGP-087, area WALLET-B2: evidence tests for the audit's "fixed" and "limit" rows. Every test here PASSES
on B2 7eeedd6; each asserts what the code does today (some of it is a limit, said so in the docstring).
The holes are in test_agp087_wallet_b2.py (those fail).
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.approval import b2x, rotate_message, sign
from agentwallet.mcp_server import FORBIDDEN_MCP_TOOLS, MCP_TOOL_NAMES
from agentwallet.rpc import KnotsRpcRefused
from agentwallet.signer import Signer

from _agp013 import HUMAN_PRIV, HUMAN_PUB, NETWORK, PAY_TO, FakeRpc, fund_channel, keyfile_env, write_policy

from xbt402 import ecc
from xbt402.channel import DERIVATION
from xbt402.x402_channel import SCHEME, XbtChannelClient, b64json, unb64json

API = "http://api.test"
SRC = Path(__file__).resolve().parents[1] / "agentwallet" / "signer.py"

# every method `Signer._handle` accepts on 7eeedd6, and what authorises it
DISPATCH = {
    # read-only
    "balance", "quote_payment", "history", "health", "chain_backend", "channels", "hot_address", "routing_status",
    "forward_status", "forward_pending", "forward_transfers", "signatures", "anchor_status",
    # policy engine, booked before the signature
    "pay", "sign_state", "xbt402_pay", "xbt402_sign_state_a3", "xbt402_sign_state_adaptor", "open_channel",
    # human signature
    "approve", "recover_vault", "fund_treasury", "recover_treasury", "rotate_hot_key", "sweep_hot",
    # unsigned, no new amount (see the audit's table)
    "fund", "xbt402_request_auth", "xbt402_resolve_lock", "xbt402_void_lock", "xbt402_adopt_lock", "xbt402_recover_lock",
    "close_channel", "xbt402_refund", "refund_channel", "watch_tick", "forward_recover", "notice_hot_txid",
    "anchor_now", "hot_reconcile",
}


def ledger_sum(s: Signer) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


def signer(tmp: Path, rpc: FakeRpc | None = None, **policy) -> Signer:
    keyfile_env()
    write_policy(tmp, **{"per_counterparty_cap_sats": 100_000, "split_window_s": 0, "human_pubkey": HUMAN_PUB.hex(),
                         **policy})
    s = Signer(tmp, rpc=rpc or FakeRpc(height=1000))
    s.hot.notice_utxo("aa" * 32, 0, 300_000)
    return s


class Killed(BaseException):
    pass


class Dispatch(unittest.TestCase):
    def test_the_socket_accepts_exactly_these_methods(self):
        src = SRC.read_text(encoding="utf-8")
        body = src[src.index("def _handle("):src.index("def _height(")]
        names = set(re.findall(r'method == "([a-z0-9_]+)"', body))
        for group in re.findall(r"method in \(([^)]*)\)", body):
            names |= set(re.findall(r'"([a-z0-9_]+)"', group))
        self.assertEqual(names, DISPATCH)
        s = signer(Path(tempfile.mkdtemp()))
        for gone in ("xbt402_attach", "xbt402_sign_rollover", "xbt402_mark_closed", "xbt402_new_key", "deny_approval",
                     "xbt402_sign_conditional", "xbt402_sign_refund", "xbt402_sign_close", "policy_set",
                     "human_key_enroll", "human_key_rotate", "backup_export"):
            with self.assertRaisesRegex(ValueError, "unknown method"):
                s.handle({"method": gone, "params": {}})

    def test_the_mcp_tools_are_a_subset_and_none_is_human_only(self):
        self.assertTrue(MCP_TOOL_NAMES <= DISPATCH)
        self.assertFalse(MCP_TOOL_NAMES & FORBIDDEN_MCP_TOOLS)
        self.assertEqual(FORBIDDEN_MCP_TOOLS, {"approve", "recover_vault", "recover_treasury", "fund_treasury",
                                               "sweep_hot", "rotate_hot_key"})


class A3(unittest.TestCase):
    def test_w1_a3_bookings_survive_a_restart_and_a_crash_never_undercounts(self):
        tmp = Path(tempfile.mkdtemp())
        rpc = FakeRpc(height=1000)
        s = signer(tmp, rpc, max_per_tx_sats=1_000, daily_budget_sats=3_000, weekly_budget_sats=3_000)
        chan = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 100_000}})["chan"]
        for cum in (1_000, 2_000):
            self.assertIn("sig", s.handle({"method": "xbt402_sign_state_a3", "params": {"chan": chan, "amount": cum}}))
        # a crash inside the signing call: the row written ahead stays
        with mock.patch.object(s.channels, "sign_state_a3", side_effect=Killed()):
            with self.assertRaises(Killed):
                s.handle({"method": "xbt402_sign_state_a3", "params": {"chan": chan, "amount": 3_000}})
        self.assertEqual(ledger_sum(s), 3_000)
        again = Signer(tmp, rpc=rpc)
        self.assertEqual((ledger_sum(again), again.channels.get(API).used_sats), (3_000, 2_000))
        r = again.handle({"method": "xbt402_sign_state_a3", "params": {"chan": chan, "amount": 3_000}})
        self.assertEqual(r.get("rule"), "daily_budget", "the crashed state is counted twice, never not at all")
        # a lower amount, a jump over max_per_tx and an unknown channel sign nothing
        for params, rule in (({"chan": chan, "amount": 1_500}, "amount"), ({"chan": chan, "amount": 9_000}, "max_per_tx"),
                             ({"chan": "nope", "amount": 5}, "allowlist")):
            self.assertEqual(again.handle({"method": "xbt402_sign_state_a3", "params": params}).get("rule"), rule, params)
        self.assertEqual(ledger_sum(again), 3_000)


class RotateReplay(unittest.TestCase):
    def test_w3_a_rotate_signature_cannot_be_used_twice(self):
        """rotate_hot_key's message names the hot address, which the rotation changes."""
        s = signer(Path(tempfile.mkdtemp()), FakeRpc(height=1000, track_outputs=True))
        exp = int(s.engine.clock()) + 600
        params = {"expiry": exp, "signature": b2x(sign(HUMAN_PRIV, rotate_message(s.hot.address, exp)))}
        self.assertIn("new_address", s.handle({"method": "rotate_hot_key", "params": dict(params)}))
        self.assertEqual(s.handle({"method": "rotate_hot_key", "params": dict(params)}).get("rule"), "human_sig")


class AckBeforeVerify(unittest.TestCase):
    """AGP-081 "noticed": any PAYMENT-RESPONSE header acked the state before the receipt was checked.
    AGP-089 changed the second test: it pinned that limit ([600, 1200, 1800], all booked), and the fix
    for the receipt's seq removes it: a state is acked only by a receipt the payee signed for that
    request, so a made-up header gets the same state again, as no header does."""

    def rig(self, header):
        rpc = FakeRpc(height=1000)
        s = signer(Path(tempfile.mkdtemp()), rpc)
        s._xbt402.network = lambda: NETWORK
        fund_channel(s.channels, rpc, API, payer_spk=s.hot.spk.hex())
        seen = []

        def http(method, url, body=b"", headers=None):
            if "PAYMENT-SIGNATURE" not in (headers or {}):
                acc = {"scheme": SCHEME, "network": NETWORK, "amount": "600", "payTo": ecc.pubkey(PAY_TO).hex(),
                       "asset": "XBT", "extra": {"derivation": DERIVATION}}
                return 402, {"PAYMENT-REQUIRED": b64json({"x402Version": 2, "accepts": [acc]})}, b"{}"
            seen.append(int(unb64json(headers["PAYMENT-SIGNATURE"])["payload"]["cum"]))
            return 500, dict(header), b""

        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            for _ in range(3):
                s.handle({"method": "xbt402_pay", "params": {"url": API + "/x", "max_sats": 600}})
        return seen, ledger_sum(s), s.channels.get(API)

    def test_an_error_answer_without_the_header_gets_the_same_state_again(self):
        seen, booked, rec = self.rig({})
        self.assertEqual((seen, booked, rec.acked_sats), ([600, 600, 600], 600, 0))

    def test_an_error_answer_with_any_header_gets_a_higher_state_each_call_all_booked(self):
        """Was the limit "an unverified header turns the one-call slack off" (the name is kept so the
        audit's reference still finds it). Now: an unverified header acks nothing."""
        seen, booked, rec = self.rig({"PAYMENT-RESPONSE": b64json({"junk": 1})})
        self.assertEqual((seen, booked, rec.acked_sats, rec.used_sats), ([600, 600, 600], 600, 0, 600))


class AllowlistBeforeAnyRequest(unittest.TestCase):
    def test_x1_no_request_leaves_for_an_origin_off_the_allowlist(self):
        s = signer(Path(tempfile.mkdtemp()))
        calls = []

        def http(method, url, body=b"", headers=None):
            calls.append(url)
            return 200, {}, b"ok"

        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            for url, max_sats in (("http://evil.test/x", 0), ("http://evil.test/x", 500), ("http://api.test@evil.test/x", 500),
                                  ("http://api.test.evil.test/x", 0), ("http://api.test/x#frag", 500), ("//api.test/x", 500)):
                r = s.handle({"method": "xbt402_pay", "params": {"url": url, "max_sats": max_sats}})
                self.assertEqual(r["verdict"], "deny", (url, r))
        self.assertEqual(calls, [])


class StuckPending(unittest.TestCase):
    def test_a_kept_funding_that_can_never_confirm_stays_pending_after_expiry(self):
        """AGP-085 stated limit 2 says such a funding blocks its destination "until the refund answers
        at expiry". The refund answers funding_unknown and the record stays pending: the destination
        stays blocked after expiry too, with no socket method to clear it."""
        rpc = FakeRpc(height=1000, track_outputs=True)
        s = signer(Path(tempfile.mkdtemp()), rpc, open_retry_s=0)
        real = rpc.call

        def call(method, *p):
            if method == "sendrawtransaction":
                raise call.answer
            return real(method, *p)

        call.answer = TimeoutError("timed out")                # the node never got it
        rpc.call = call
        try:
            s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000}})
        except Exception:
            pass
        rec = s.channels.get(API)
        self.assertEqual(rec.state, "pending")
        call.answer = KnotsRpcRefused('{"code":-25,"message":"bad-txns-inputs-missingorspent"}')   # and never will
        rpc.height = rec.expiry + 10
        acts = s.watch_tick()
        self.assertTrue(any(a.get("rule") == "funding_unknown" for a in acts), acts)
        self.assertEqual(s.channels.get(API).state, "pending")
        r = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000}})
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "funding_unconfirmed"), r)
        r = s.handle({"method": "xbt402_refund", "params": {"counterparty": API}})
        self.assertEqual(r["rule"], "funding_unknown", r)


class ApprovalsGrow(unittest.TestCase):
    def test_every_quote_over_the_threshold_leaves_an_approval_on_disk(self):
        """AGP-085 found-not-fixed 7, and one more writer: `quote_payment` (an MCP tool) stores a token too."""
        tmp = Path(tempfile.mkdtemp())
        s = signer(tmp, human_threshold_sats=1_000)
        for _ in range(25):
            self.assertEqual(s.handle({"method": "quote_payment", "params": {"to": API, "amount_sats": 2_000}})["verdict"],
                             "needs_human")
        doc = json.loads((tmp / ".run" / "ledger.json").read_text(encoding="utf-8"))
        self.assertEqual(len(doc["approvals"]), 25)


class PolicyFile(unittest.TestCase):
    def test_w4_a_policy_file_anyone_can_write_is_read_without_complaint(self):
        """B2 has no enrolment: the approver's key is whatever policy.json says, and its mode is not checked."""
        tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        write_policy(tmp, human_pubkey=HUMAN_PUB.hex())
        os.chmod(tmp / "policy.json", 0o666)
        self.assertEqual(Signer(tmp, rpc=FakeRpc(height=1000)).human_pubkey, HUMAN_PUB)

    def test_k1_the_plaintext_flag_is_taken_on_mainnet(self):
        """K1: "production mode refuses it" has no counterpart in B2."""
        from test_mainnet_readiness import Rig

        env = {k: v for k, v in os.environ.items() if k not in ("B2_HOT_KEYFILE", "B2_HOT_PASSPHRASE")}
        rig = Rig(chain="main")
        with mock.patch.dict(os.environ, {**env, "B2_HOT_ALLOW_PLAINTEXT": "1"}, clear=True):
            s = Signer(self._root(rig), rpc=rig.node)
        self.assertEqual((s.chain, s.keystore), ("main", None))
        hot = (s.root / ".run" / "hot.json").read_text(encoding="utf-8")
        self.assertIn(f"{s.hot.secret:064x}", hot, "the mainnet hot key is on disk in the clear")

    @staticmethod
    def _root(rig) -> Path:
        tmp = Path(tempfile.mkdtemp())
        (tmp / "policy.json").write_text((rig.tmp / "policy.json").read_text(encoding="utf-8"), encoding="utf-8")
        return tmp


if __name__ == "__main__":
    unittest.main()
