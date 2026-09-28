"""Attack tests for cryptographic, out-of-band human approval (XBT-054 rework)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentwallet.approval import (
    b2x,
    generate_keypair,
    sign_approval,
    verify_approval,
    write_human_device,
)
from agentwallet.mcp_server import registered_tool_names
from agentwallet.policy import Payment
from agentwallet.signer import Signer


MERCHANT = "bcrt1qmerchant0000000000000000000000000000qq"
OTHER = "bcrt1qother000000000000000000000000000000qq"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class FakeRpc:
    def __init__(self):
        self.sent = []
        self.wallet = "agent"

    def call(self, method, *args):
        if method == "getbalances":
            return {"mine": {"trusted": 50, "untrusted_pending": 0, "immature": 0}}
        if method == "sendtoaddress":
            txid = "ab" * 32
            self.sent.append((args[0], args[1], txid))
            return txid
        if method == "listunspent":
            return []
        if method == "estimatesmartfee":
            return {"feerate": 0.00001}
        if method == "getblockchaininfo":      # AGP-017: the signer learns its chain at start
            return {"chain": "regtest", "blocks": 200, "initialblockdownload": False}
        raise RuntimeError(method)


def make_signer(tmp: Path, pub_hex: str, clock: Clock | None = None) -> Signer:
    policy = {
        "allowlist": [MERCHANT],
        "max_per_tx_sats": 100_000_000,
        "daily_budget_sats": 200_000_000,
        "weekly_budget_sats": 500_000_000,
        "per_counterparty_cap_sats": 100_000_000,
        "velocity_max": 20,
        "velocity_window_s": 3600,
        "human_threshold_sats": 400_000,
        "split_window_s": 600,
        "approval_ttl_s": 120,
        "recovery_address": MERCHANT,
        "human_pubkey": pub_hex,
    }
    (tmp / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    rpc = FakeRpc()
    # AGP-013: the signer refuses a plaintext hot key; its wrapping key lives outside the run dir
    os.environ["B2_HOT_KEYFILE"] = str(Path(tempfile.mkdtemp(prefix="b2-hotkey-")) / "hot.key")
    signer = Signer(tmp, rpc=rpc)
    if clock is not None:
        signer.engine.clock = clock
    signer._rpc_fake = rpc  # type: ignore[attr-defined]
    return signer


class ApprovalCryptoTests(unittest.TestCase):
    def test_round_trip(self):
        priv, pub = generate_keypair()
        sig = sign_approval(priv, "tok", MERCHANT, 100, 1_000_100)
        self.assertTrue(verify_approval(pub, "tok", MERCHANT, 100, 1_000_100, sig))
        self.assertFalse(verify_approval(pub, "tok", MERCHANT, 101, 1_000_100, sig))

    def test_human_device_writes_marked_dir(self):
        tmp = Path(tempfile.mkdtemp()) / "THE_HUMANS_DEVICE"
        info = write_human_device(tmp)
        self.assertTrue((tmp / "THIS_IS_THE_HUMANS_DEVICE.txt").exists())
        self.assertTrue(Path(info["sk"]).is_file())
        self.assertEqual(Path(info["sk"]).stat().st_mode & 0o777, 0o600)


class ApprovalAttackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.priv, self.pub = generate_keypair()
        self.clock = Clock()
        self.signer = make_signer(self.tmp, b2x(self.pub), self.clock)

    def _pending(self, amount=400_000):
        d = self.signer.handle(
            {"method": "pay", "params": {"to": MERCHANT, "amount_sats": amount, "memo": "gate"}}
        )
        self.assertEqual(d["verdict"], "needs_human", d)
        return d

    def _approve(self, token, dest, amount, expiry, sig_hex, **extra):
        params = {
            "token": token,
            "dest": dest,
            "amount_sats": amount,
            "expiry": expiry,
            "signature": sig_hex,
        }
        params.update(extra)
        return self.signer.handle({"method": "approve", "params": params})

    def test_a_agent_cannot_approve_through_mcp(self):
        names = registered_tool_names()
        self.assertNotIn("approve", names)
        self.assertNotIn("recover_vault", names)

    def test_b_socket_approve_without_valid_signature_denies(self):
        pending = self._pending()
        # no signature
        r = self._approve(pending["approval_token"], MERCHANT, 400_000, pending["approval_expires"], "")
        self.assertEqual(r["verdict"], "deny")
        self.assertEqual(r["rule"], "approval_sig")
        # garbage
        r2 = self._approve(
            pending["approval_token"], MERCHANT, 400_000, pending["approval_expires"], "00" * 64
        )
        self.assertEqual(r2["verdict"], "deny")
        self.assertEqual(r2["rule"], "approval_sig")
        # old human=true boolean is ignored and still denies without a sig
        r3 = self.signer.handle(
            {
                "method": "approve",
                "params": {"token": pending["approval_token"], "human": True},
            }
        )
        self.assertEqual(r3["verdict"], "deny")
        self.assertEqual(r3["rule"], "approval_sig")
        self.assertEqual(self.signer._rpc_fake.sent, [])

    def test_c_signature_over_different_amount_or_dest_denies(self):
        pending = self._pending()
        token = pending["approval_token"]
        exp = pending["approval_expires"]
        wrong_amt = sign_approval(self.priv, token, MERCHANT, 399_000, exp)
        r = self._approve(token, MERCHANT, 399_000, exp, b2x(wrong_amt))
        self.assertEqual(r["verdict"], "deny")
        self.assertEqual(r["rule"], "approval_bind")
        wrong_dest = sign_approval(self.priv, token, OTHER, 400_000, exp)
        r2 = self._approve(token, OTHER, 400_000, exp, b2x(wrong_dest))
        self.assertEqual(r2["verdict"], "deny")
        self.assertEqual(r2["rule"], "approval_bind")
        self.assertEqual(self.signer._rpc_fake.sent, [])

    def test_d_replay_used_token_denies(self):
        pending = self._pending()
        token = pending["approval_token"]
        exp = pending["approval_expires"]
        sig = sign_approval(self.priv, token, MERCHANT, 400_000, exp)
        ok = self._approve(token, MERCHANT, 400_000, exp, b2x(sig))
        self.assertEqual(ok["verdict"], "allow")
        self.assertTrue(ok.get("txid"))
        replay = self._approve(token, MERCHANT, 400_000, exp, b2x(sig))
        self.assertEqual(replay["verdict"], "deny")
        self.assertIn(replay["rule"], {"approval", "approval_replay"})
        self.assertEqual(len(self.signer._rpc_fake.sent), 1)

    def test_e_expired_token_denies(self):
        pending = self._pending()
        token = pending["approval_token"]
        exp = pending["approval_expires"]
        self.clock.advance(121)
        sig = sign_approval(self.priv, token, MERCHANT, 400_000, exp)
        r = self._approve(token, MERCHANT, 400_000, exp, b2x(sig))
        self.assertEqual(r["verdict"], "deny")
        self.assertEqual(r["rule"], "approval_expired")
        self.assertEqual(self.signer._rpc_fake.sent, [])

    def test_valid_human_signature_sends(self):
        pending = self._pending()
        token = pending["approval_token"]
        exp = pending["approval_expires"]
        sig = sign_approval(self.priv, token, MERCHANT, 400_000, exp)
        r = self._approve(token, MERCHANT, 400_000, exp, b2x(sig))
        self.assertEqual(r["verdict"], "allow", r)
        self.assertTrue(r.get("approved"))
        self.assertEqual(len(self.signer._rpc_fake.sent), 1)

    def test_cli_refuses_key_under_agent_workspace(self):
        from agentwallet.approve import main as approve_main

        workspace = self.tmp
        bad_key = workspace / "stolen.sk"
        bad_key.write_bytes(self.priv)
        with self.assertRaises(SystemExit) as ctx:
            approve_main(
                [
                    "--key",
                    str(bad_key),
                    "--token",
                    "x",
                    "--dest",
                    MERCHANT,
                    "--amount-sats",
                    "1",
                    "--expiry",
                    "1",
                    "--sock",
                    "/tmp/no.sock",
                    "--agent-root",
                    str(workspace),
                ]
            )
        self.assertIn("refuse", str(ctx.exception).lower() + str(ctx.exception))


class ConsumeStillSingleUse(unittest.TestCase):
    def test_policy_consume_still_one_shot(self):
        from agentwallet.policy import AuditLog, PolicyConfig, PolicyEngine, PolicyStore, Verdict

        tmp = Path(tempfile.mkdtemp())
        clock = Clock()
        cfg = PolicyConfig(
            allowlist=frozenset({MERCHANT}),
            max_per_tx_sats=1_000_000,
            human_threshold_sats=400_000,
            approval_ttl_s=120,
        )
        eng = PolicyEngine(cfg, PolicyStore(tmp / "ledger.json"), AuditLog(tmp / "audit.jsonl"), clock=clock)
        d = eng.evaluate(Payment(dest=MERCHANT, amount_sats=400_000))
        self.assertEqual(d.verdict, Verdict.NEEDS_HUMAN)
        self.assertIsNotNone(eng.consume_approval(d.approval_token))
        self.assertIsNone(eng.consume_approval(d.approval_token))


if __name__ == "__main__":
    unittest.main()
