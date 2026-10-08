"""AGP-017: the B2 patches the AGP-015 runbook needs before any mainnet sat moves.

P1  the payer key and channel are on disk (sealed) before the funding is broadcast; a crash between
    the funding and the open, a refused open or a dead provider leaves a pending channel that is
    retried and, failing that, refunded at expiry
P2  the open is posted only once the funding has the offer's minConf; until then xbt402_pay returns
    "pending" and the watcher finishes the open
P3  no mining outside regtest: refused at start, in the session and in the RPC client
P4  the mainnet network id is block 961640's (and must equal XBT_MAINNET), not block 101's
P5  mainnet addresses use hrp `bc`; another network's address is refused as a sweep destination
P6  a pruned node without txindex is enough (funding, closes, refunds, change)

Every flow runs against a real B1 provider on a fake pruned node (tests/_agp017.py).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet import netparams
from agentwallet.approval import b2x, generate_keypair, sign, sweep_message
from agentwallet.channels import ChannelBook
from agentwallet.keystore import KeyStore
from agentwallet.rpc import KnotsRpc, KnotsRpcError
from agentwallet.signer import Signer
from agentwallet.xbt402 import Xbt402Session

from _agp013 import keyfile_env, write_policy
from _agp017 import MAIN_961640, PrunedChain

from xbt402 import ecc
from xbt402.funding import FundingPolicy
from xbt402.tx import Tx, segwit_address
from xbt402.x402_channel import XBT_MAINNET, XbtChannelProvider

API = "http://api.test"
URL = API + "/agp015/echo"
PAY_TO = 0xB0B


class Killed(BaseException):
    """The signer process dies (not an Exception: nothing in the signer catches it)."""


class Rpc1:
    """B1's provider calls rpc.method(*args); the fake node answers call(method, *args)."""

    def __init__(self, chain):
        self.chain = chain

    def __getattr__(self, m):
        return lambda *a: self.chain.call(m, *a)


def runbook_policy(root: Path, **over):
    return write_policy(root, **{
        "allowlist": [API], "counterparties": {}, "max_per_tx_sats": 1000, "daily_budget_sats": 6000,
        "weekly_budget_sats": 6000, "per_counterparty_cap_sats": 9400, "velocity_max": 20,
        "human_threshold_sats": 1000, "channel_expiry_blocks": 1008, "refund_margin_blocks": 6,
        "hot_balance_cap_sats": 15000, "open_wait_s": 0, "open_retry_s": 0,
        # the runbook's human_threshold (1,000) and max_per_tx (1,000) with the default 600 s split window
        # refuse the 2nd and 3rd 500-sat call to the same origin (split_bypass): G4 needs the window off
        "split_window_s": 0, **over})


class Rig:
    """A signer and a B1 provider (runbook parameters) on one fake pruned node."""

    def __init__(self, chain="regtest", **policy):
        self.tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        runbook_policy(self.tmp, **policy)
        self.node = PrunedChain(chain=chain, height=974_446 if chain == "main" else 1000)
        self.signer = Signer(self.tmp, rpc=self.node)
        self.provider = XbtChannelProvider(
            Rpc1(self.node), PAY_TO, self.node.network(), str(self.tmp / "provider.sqlite"),
            lambda m, p: 500, lambda m, p, b: (200, {"Content-Type": "application/json"}, b'{"ok":true}'),
            close_fee=600, close_margin=144,
            policy=FundingPolicy(min_capacity=10_000, max_capacity=10_000, min_expiry_blocks=1_008, close_margin=144))
        self.posts: list[str] = []          # funded opens; the review C2 preflights go to self.preflights
        self.preflights: list[str] = []
        self.refuse_open = False
        self.kill_on_open = False
        self.provider_down = False

    def http(self, method, url, body=b"", headers=None):
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        if path.endswith("/open") and json.loads(body or b"{}").get("preflight") is True:
            self.preflights.append(path)
        elif path.endswith("/open"):
            self.posts.append(path)
            if self.kill_on_open:
                raise Killed()
            if self.refuse_open:          # the provider changed its mind after the preflight
                self.provider.policy.min_expiry_blocks = 5_000
        if self.provider_down:
            raise ConnectionRefusedError("provider down")
        return self.provider.serve(method, path, headers or {}, body or b"", url)

    def fund_hot(self, sats=12_000):
        txid = os.urandom(32).hex()
        self.node.credit(txid, 0, sats, self.signer.hot.spk.hex())
        return self.signer.handle({"method": "notice_hot_txid", "params": {"txid": txid}})

    def pay(self):
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=self.http):
            return self.signer.handle({"method": "xbt402_pay", "params": {"url": URL, "max_sats": 500}})

    def tick(self):
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=self.http):
            return self.signer.watch_tick()

    def restart(self):
        self.signer = Signer(self.tmp, rpc=self.node)     # same run dir, same wrapping key file
        return self.signer

    def channel(self):
        return self.signer.channels.get(API)


class P1WriteAhead(unittest.TestCase):
    def test_channel_and_sealed_key_are_on_disk_before_the_funding_is_broadcast(self):
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        seen = {}
        send = rig.node.call

        def call(method, *p):
            if method == "sendrawtransaction" and not seen:
                book = ChannelBook(rig.tmp / ".run/channels.json", rig.tmp / ".run/channel_keys.json",
                                   keystore=KeyStore.from_env(pop=False))
                rec = book.get(API)
                seen.update(state=rec.state, txid=rec.funding_txid, has_key=rec.chan in book._secrets,
                            sealed="sealed" in json.loads((rig.tmp / ".run/channel_keys.json").read_text()))
            return send(method, *p)

        rig.node.call = call
        rig.pay()
        self.assertEqual(seen["state"], "pending")
        self.assertTrue(seen["has_key"] and seen["sealed"])
        self.assertEqual(seen["txid"], Tx.parse(bytes.fromhex(rig.node.sent[0])).txid())

    def test_killed_between_funding_and_open_then_restart_then_refund_after_expiry(self):
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        rig.kill_on_open = True
        rig.node.mine(1)                     # (no-op for the funding: it is not sent yet)
        orig = rig.node.call

        def call(method, *p):                # the funding confirms right after it is sent
            r = orig(method, *p)
            if method == "sendrawtransaction":
                rig.node.mine(1)
            return r

        rig.node.call = call
        with self.assertRaises(Killed):
            rig.pay()
        rig.node.call = orig
        self.assertEqual(len(rig.posts), 1, "the process died while posting the open")
        s = rig.restart()
        rec = rig.channel()
        self.assertEqual((rec.state, rec.funding_sats), ("pending", 10_000))
        self.assertEqual(s.hot.balance_sats(), 1_400, "the funding's change survived the crash")
        rig.kill_on_open, rig.provider_down = False, True      # and the provider is gone for good
        acts = rig.tick()
        self.assertEqual(rig.channel().state, "pending")
        self.assertIn("unreachable", acts[0]["open_retry"]["error"])
        rig.node.height = rec.expiry - 1
        self.assertEqual([a for a in rig.tick() if a.get("rule")], [], "no refund before expiry")
        rig.node.height = rec.expiry
        acts = rig.tick()
        self.assertEqual([(a["verdict"], a["rule"], a["sats"]) for a in acts if a.get("rule")],
                         [("allow", "refund", 9_400)])
        self.assertEqual(rig.channel().state, "refunded")
        refund = Tx.parse(bytes.fromhex(rig.node.sent[-1]))
        self.assertEqual((refund.locktime, refund.outputs[0].value, refund.outputs[0].script_pubkey),
                         (rec.expiry, 9_400, s.hot.spk))
        self.assertEqual(s.hot.balance_sats(), 1_400 + 9_400)

    def test_refused_open_stays_pending_and_is_refunded(self):
        rig = Rig(regtest_mine=None)                       # regtest: the signer mines its funding
        rig.fund_hot()
        rig.refuse_open = True
        r = rig.pay()
        self.assertEqual(r["verdict"], "deny")
        self.assertIn("stays pending", r["reason"])
        self.assertIn("bad_expiry", rig.channel().open_error)
        rig.node.height = rig.channel().expiry
        self.assertEqual([a["rule"] for a in rig.tick() if a.get("rule")], ["refund"])

    def test_duplicate_channel_counts_as_opened(self):
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        self.assertEqual(rig.pay()["verdict"], "pending")
        rig.node.mine(1)
        rec = rig.channel()
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=rig.http):
            rig.signer._xbt402.complete_open(API)                       # opens
            rig.signer.channels._records[API].state = "pending"         # as if the reply was lost
            out = rig.signer._xbt402.complete_open(API)
        self.assertEqual((out["state"], rig.channel().state), ("open", "open"))
        self.assertEqual(rig.provider.ledger.channels[rec.chan].params.channel_id, rec.chan)

    def test_failed_broadcast_forgets_the_pending_channel_and_keeps_the_coin(self):
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        rig.node.reject = "min relay fee not met"
        r = rig.pay()
        self.assertEqual(r["verdict"], "deny")
        self.assertIsNone(rig.channel())
        self.assertEqual(rig.signer.hot.balance_sats(), 12_000)
        rig.node.reject = None
        self.assertEqual(rig.pay()["verdict"], "pending")


class P2MinConf(unittest.TestCase):
    def test_open_waits_for_min_conf_then_pays(self):
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        r = rig.pay()
        self.assertEqual((r["verdict"], r["rule"], r["confirmations"], r["min_conf"]),
                         ("pending", "funding_unconfirmed", 0, 1))
        self.assertEqual(rig.posts, [], "no open is posted for an unconfirmed funding")
        self.assertEqual(rig.node.mined_by_signer, 0)
        rig.node.mine(1)
        r = rig.pay()
        self.assertEqual((r["verdict"], r["charged_sats"], r["opened"]["confirmations"]), ("allow", 500, 1))
        self.assertEqual(len(rig.posts), 1)
        self.assertEqual(rig.channel().state, "open")
        self.assertGreater(rig.channel().funding_height, 0)

    def test_the_watcher_finishes_the_open(self):
        rig = Rig(regtest_mine=False)
        rig.fund_hot()
        rig.pay()
        self.assertEqual(rig.tick(), [], "unconfirmed: nothing to do yet")
        rig.node.mine(1)
        acts = rig.tick()
        self.assertEqual(acts[0]["open_retry"]["state"], "open")
        self.assertEqual(rig.pay()["charged_sats"], 500)

    def test_ten_calls_sign_exactly_5000(self):
        """The runbook's G4: 10 x 500 sat, first state topped up to dust (546), final cum 5,000."""
        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        cums = [rig.pay()["cum"] for _ in range(10)]
        self.assertEqual(cums[0], 546)
        self.assertEqual(cums[1:], [1000 + 500 * i for i in range(9)])
        self.assertEqual((rig.channel().used_sats, rig.channel().spent_sats), (5_000, 5_000))

    def test_runbook_budgets_with_the_default_split_window_stop_at_the_second_call(self):
        rig = Rig(regtest_mine=None, split_window_s=600)
        rig.fund_hot()
        self.assertEqual(rig.pay()["charged_sats"], 500)
        self.assertEqual(rig.pay()["rule"], "split_bypass")

    def test_close_fee_above_the_wallet_cap_is_refused_before_funding(self):
        rig = Rig(regtest_mine=False, close_fee_max_sats=500)
        rig.fund_hot()
        r = rig.pay()
        self.assertEqual(r["verdict"], "deny")
        self.assertIn("closeFeeSat 600", r["reason"])
        self.assertEqual(rig.node.sent, [])


class P3NoMiningOffRegtest(unittest.TestCase):
    def test_mainnet_signer_refuses_a_mining_policy(self):
        with self.assertRaises(netparams.ChainError):
            Rig(chain="main", regtest_mine=True)

    def test_mainnet_signer_never_mines(self):
        rig = Rig(chain="main")
        self.assertFalse(rig.signer.mining)
        self.assertIsNone(rig.signer._xbt402.mine)
        with self.assertRaises(netparams.ChainError):
            rig.signer._mine(1)
        rig.fund_hot()
        self.assertEqual(rig.pay()["verdict"], "pending")
        rig.node.mine(1)
        self.assertEqual(rig.pay()["charged_sats"], 500)
        self.assertNotIn("generatetoaddress", rig.node.calls)

    def test_session_refuses_a_mining_hook_off_regtest(self):
        with self.assertRaises(netparams.ChainError):
            Xbt402Session(None, None, None, height=lambda: 0, mine=lambda n: None, chain="main")

    def test_rpc_client_refuses_generate_until_allowed(self):
        rpc = KnotsRpc(Path("/nonexistent"), Path("/dev/null"))
        with self.assertRaises(KnotsRpcError) as cm:
            rpc.call("generatetoaddress", 1, "bc1qx")
        self.assertIn("regtest only", str(cm.exception))


class P4NetworkId(unittest.TestCase):
    def test_mainnet_uses_block_961640(self):
        rig = Rig(chain="main")
        self.assertEqual(rig.signer._xbt402.network(), XBT_MAINNET)
        node = PrunedChain(chain="main", height=974_446)
        node.bhash = lambda h: "00" * 32 if h == 961640 else f"{h:064x}"
        with self.assertRaises(netparams.ChainError):
            netparams.network(node, "main")

    def test_regtest_keeps_block_101(self):
        node = PrunedChain(chain="regtest", height=500)
        self.assertEqual(netparams.network(node, "regtest"), node.network())
        self.assertEqual(node.network(), "bip122:" + f"{101:064x}"[:32])


class P5Hrp(unittest.TestCase):
    def setUp(self):
        os.environ.pop(netparams.ENV_CHAIN, None)

    tearDown = setUp

    def test_mainnet_addresses_are_bc(self):
        rig = Rig(chain="main")
        self.assertTrue(rig.signer.hot.address.startswith("bc1q"))
        self.assertTrue(rig.signer.treasury.address.startswith("bc1q"))
        self.assertEqual(rig.signer.handle({"method": "health"})["hrp"], "bc")

    def test_sweep_to_another_networks_address_is_refused(self):
        priv, pub = generate_keypair()
        rig = Rig(chain="main", human_pubkey=b2x(pub))
        rig.fund_hot(5_800)
        s, exp = rig.signer, 2**40
        spk = bytes.fromhex("0014" + "66" * 20)
        for to, ok in ((segwit_address("bcrt", spk), False), (segwit_address("bc", spk), True)):
            sig = sign(priv, sweep_message(s.hot.address, to, 5_200, exp))
            r = s.handle({"method": "sweep_hot", "params": {"to": to, "amount_sats": 5_200, "expiry": exp,
                                                           "signature": b2x(sig)}})
            self.assertEqual(r["ok"], ok, r)
        tx = Tx.parse(bytes.fromhex(rig.node.sent[-1]))
        self.assertEqual([(o.script_pubkey, o.value) for o in tx.outputs], [(spk, 5_200)], "zero change")
        self.assertEqual((r["fee_sats"], r["change_sats"], r["outputs"]), (600, 0, 1))

    def test_chain_env_must_agree_with_the_node(self):
        os.environ[netparams.ENV_CHAIN] = "main"
        with self.assertRaises(netparams.ChainError):
            netparams.detect_chain(PrunedChain(chain="regtest"))

        class Down:
            def call(self, *a):
                raise ConnectionRefusedError()
        self.assertEqual(netparams.detect_chain(Down()), "main")
        os.environ.pop(netparams.ENV_CHAIN)
        with self.assertRaises(netparams.ChainError):
            netparams.detect_chain(Down())


class P6Pruned(unittest.TestCase):
    def test_hot_notices_a_confirmed_coin_without_txindex(self):
        rig = Rig(regtest_mine=False)
        r = rig.fund_hot(12_000)
        self.assertEqual((r["noticed"], r["hot_sats"]), (1, 12_000))

    def test_provider_close_confirmed_on_a_pruned_node_is_found_and_its_change_noticed(self):
        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        for _ in range(2):
            rig.pay()
        rec = rig.channel()
        rig.node.height = rec.expiry - 144                       # the provider's own close (G5 rollback)
        closed = rig.provider.close_due()
        self.assertEqual(len(closed), 1)
        rig.node.mine(3)                                         # confirmed: out of the mempool
        with self.assertRaises(Exception):
            rig.node.call("getrawtransaction", closed[0], True)  # a pruned node cannot look it up
        rig.node.height = rec.expiry
        acts = rig.tick()
        self.assertEqual([a["rule"] for a in acts if a.get("rule")], ["channel_closed"])
        self.assertEqual((rig.channel().state, rig.channel().closed_txid), ("closed", closed[0]))
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400 + 10_000 - 600 - 1_000)

    def test_signer_code_never_needs_txindex(self):
        rig = Rig(regtest_mine=None)
        rig.fund_hot()
        rig.pay()
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=rig.http):
            r = rig.signer.handle({"method": "close_channel", "params": {"counterparty": API}})
        self.assertEqual(r["verdict"], "allow")
        rig.node.mine(1)
        self.assertEqual(rig.signer.hot.balance_sats(), 1_400 + 10_000 - 600 - 546)


if __name__ == "__main__":
    unittest.main()
