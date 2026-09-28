"""AGP-024 on a real chain: Knots 29.4.2 (BLAKE2b from block 101, no txindex) and electrs 0.11.1 with the
header-v2 patch, on ports 34980-34984. Skipped when either binary is missing (B2_TEST_BITCOIND_DIR,
B2_TEST_ELECTRS).

1. Every RPC the client path makes answers as the node answers (tip, block hashes, gettxout in the
   mempool and confirmed, getrawtransaction, scantxoutset, gettxspendingprevout), with no
   verification failure.
2. A light signer (no node, never mines) funds a channel with a 0x21 transaction, sees it confirm by
   Merkle proof, and at the CLTV expiry its watcher refunds it through Electrum; the refunded coin is
   found again by a reconcile.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from agentwallet.electrum import ElectrumBackend
from agentwallet.rpc import KnotsRpc
from agentwallet.signer import Signer

from _agp013 import keyfile_env, write_policy

BIN = Path(os.environ.get("B2_TEST_BITCOIND_DIR", Path.home() / "lazarus-regtest/b1-xbt402/knots-29.4.2"))
ELECTRS = Path(os.environ.get("B2_TEST_ELECTRS", Path.home() / "xbt-rnd/electrs-agp-024/src/target/release/electrs"))
BASE = int(os.environ.get("B2_TEST_LIVE_PORT_BASE", "34980"))
RPC, P2P, ELEC, MON = BASE, BASE + 1, BASE + 2, BASE + 3


@unittest.skipUnless((BIN / "bitcoind").exists() and ELECTRS.exists(), "needs Knots 29.4.2 and electrs (header-v2)")
class LiveElectrs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="agp024-live-"))
        cls.node_dir = cls.tmp / "node"
        cls.node_dir.mkdir()
        subprocess.run([str(BIN / "bitcoind"), "-regtest", f"-datadir={cls.node_dir}", f"-rpcport={RPC}", f"-port={P2P}",
                        "-bind=127.0.0.1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-listenonion=0",
                        "-discover=0", "-dnsseed=0", "-fixedseeds=0", "-upnp=0", "-natpmp=0", "-fallbackfee=0.0002",
                        "-testactivationheight=blake2b@101", "-blake2b_headline=agp024-live",
                        "-rdtsexpiry=4102444800", "-daemonwait"], check=True, capture_output=True, timeout=60)
        cls.old_port = os.environ.get("B2_RPCPORT")
        os.environ["B2_RPCPORT"] = str(RPC)
        cls.node = KnotsRpc(cls.node_dir, Path("/dev/null"), wallet="w")
        cls.node.allow_generate = True
        cls.node.call("createwallet", "w")
        cls.addr = cls.node.call("getnewaddress", "", "bech32")
        cls.node.call("generatetoaddress", 220, cls.addr)
        cls.log = open(cls.tmp / "electrs.log", "w")
        cls.electrs = subprocess.Popen(
            [str(ELECTRS), "--skip-default-conf-files", "--network", "regtest", "--db-dir", str(cls.tmp / "db"),
             "--daemon-dir", str(cls.node_dir), "--cookie-file", str(cls.node_dir / "regtest" / ".cookie"),
             "--daemon-rpc-addr", f"127.0.0.1:{RPC}", "--daemon-p2p-addr", f"127.0.0.1:{P2P}",
             "--electrum-rpc-addr", f"127.0.0.1:{ELEC}", "--monitoring-addr", f"127.0.0.1:{MON}"],
            stdout=cls.log, stderr=subprocess.STDOUT)
        cls.cp = (101, cls.node.call("getblockhash", 101))
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                b = cls.backend()
                if b.call("getblockcount") == 220:
                    b.close()
                    break
                b.close()
            except Exception:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("electrs did not index the chain: " + (cls.tmp / "electrs.log").read_text()[-800:])

    @classmethod
    def tearDownClass(cls):
        cls.electrs.terminate()
        try:
            cls.electrs.wait(10)
        except subprocess.TimeoutExpired:
            cls.electrs.kill()
        try:
            cls.node.call("stop")
        except Exception:
            pass
        for _ in range(80):
            if not (cls.node_dir / "regtest" / "bitcoind.pid").exists():
                break
            time.sleep(0.25)
        cls.log.close()
        if cls.old_port is None:
            os.environ.pop("B2_RPCPORT", None)
        else:
            os.environ["B2_RPCPORT"] = cls.old_port
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def backend(cls) -> ElectrumBackend:
        return ElectrumBackend([f"tcp://127.0.0.1:{ELEC}"], chain="regtest", checkpoint=cls.cp, timeout=10)

    def settle(self, b, height=None):
        height = height or self.node.call("getblockcount")
        deadline = time.time() + 20
        while b.call("getblockcount") != height and time.time() < deadline:
            b.wait_for_change(0.25)
        self.assertEqual(b.call("getblockcount"), height)

    def mine(self, n=1):
        self.node.call("generatetoaddress", n, self.addr)

    def test_1_every_client_rpc_answers_as_the_node(self):
        b = self.backend()
        self.addCleanup(b.close)
        node = self.node
        self.assertEqual(b.call("getblockhash", 200), node.call("getblockhash", 200))
        addr = node.call("getnewaddress", "", "bech32")
        spk = node.call("getaddressinfo", addr)["scriptPubKey"]
        txid = node.call("sendtoaddress", addr, 0.5)
        n = next(o["n"] for o in node.call("getrawtransaction", txid, True)["vout"] if o["scriptPubKey"]["hex"] == spk)
        for _ in range(40):
            if b.call("gettxout", txid, n, True):
                break
            time.sleep(0.25)
        self.assertEqual(b.call("gettxout", txid, n, True)["confirmations"], 0)
        self.mine(2)
        self.settle(b)
        light, full = b.call("gettxout", txid, n, True), node.call("gettxout", txid, n, True)
        for k in ("confirmations", "bestblock"):
            self.assertEqual(light[k], full[k], k)
        self.assertEqual(light["value"], float(full["value"]))
        v = b.call("getrawtransaction", txid, True)
        self.assertEqual(v["hex"], node.call("getrawtransaction", txid, False, v["blockhash"]))
        self.assertEqual(sorted((u["txid"], u["vout"]) for u in b.call("scantxoutset", "start", [f"raw({spk})"])["unspents"]),
                         sorted((u["txid"], u["vout"]) for u in node.call("scantxoutset", "start", [f"raw({spk})"])["unspents"]))
        raw = node.call("createrawtransaction", [{"txid": txid, "vout": n}], [{addr: 0.4999}])
        spend = node.call("signrawtransactionwithwallet", raw)["hex"]
        sp = b.call("sendrawtransaction", spend)
        time.sleep(1)
        self.assertEqual(b.call("gettxspendingprevout", [{"txid": txid, "vout": n}]),
                         node.call("gettxspendingprevout", [{"txid": txid, "vout": n}]))
        self.mine(1)
        self.settle(b)
        self.assertIsNone(b.call("gettxout", txid, n, True))
        self.assertEqual(b.call("getrawtransaction", sp, True)["confirmations"], 1)
        self.assertEqual(b.flags, [], "no answer from electrs failed verification")

    def test_2_light_signer_funds_and_refunds_a_channel_over_electrum(self):
        root = Path(tempfile.mkdtemp(prefix="agp024-signer-"))
        self.addCleanup(shutil.rmtree, root, True)
        keyfile_env()
        write_policy(root, allowlist=["probe://x"], counterparties={}, per_counterparty_cap_sats=20_000,
                     channel_expiry_blocks=12, refund_margin_blocks=2, hot_balance_cap_sats=0, regtest_mine=False)
        b = self.backend()
        self.addCleanup(b.close)
        signer = Signer(root, rpc=b)
        self.assertEqual((signer.light, signer.mining), (True, False))
        hot = signer.handle({"method": "hot_address", "params": {}})["hot_address"]
        ftx = self.node.call("sendtoaddress", hot, 0.001)
        self.mine(1)
        self.settle(b)
        self.assertEqual(signer.handle({"method": "notice_hot_txid", "params": {"txid": ftx}})["noticed"], 1)
        from xbt402 import ecc
        pay_to = ecc.pubkey(0xB0B).hex()
        op = signer.handle({"method": "open_channel", "params": {"dest": "probe://x", "pay_to": pay_to,
                                                                    "cap_sats": 20_000, "expiry_blocks": 12}})
        self.assertEqual((op["verdict"], op["funding_sighash"]), ("allow", "0x21"), op)
        self.mine(1)
        self.settle(b)
        rec = signer.channels.get("probe://x")
        self.assertEqual(b.call("gettxout", rec.funding_txid, 0, True)["confirmations"], 1, "the 0x21 funding confirmed")
        early = signer.handle({"method": "xbt402_refund", "params": {"counterparty": "probe://x"}})
        self.assertEqual(early["rule"], "refund_early")
        self.mine(rec.expiry - self.node.call("getblockcount"))
        self.settle(b)
        acts = signer.watch_tick()
        [ref] = [a for a in acts if a.get("rule") == "refund"]
        self.mine(1)
        self.settle(b)
        conf = b.call("getrawtransaction", ref["txid"], True)
        self.assertEqual(conf["confirmations"], 1, "Knots accepted the refund at the CLTV expiry")
        rec2 = signer.handle({"method": "hot_reconcile", "params": {"scan": True}})
        self.assertTrue(rec2["ok"])
        self.assertIn(ref["txid"], [u["txid"] for u in signer.hot._utxos])
        self.assertEqual(b.flags, [])
        print(json.dumps({"funding": rec.funding_txid, "refund": ref["txid"], "refund_sats": ref["sats"],
                          "expiry": rec.expiry, "backend": b.status()["servers"][0]["server"]}))


if __name__ == "__main__":
    unittest.main()
