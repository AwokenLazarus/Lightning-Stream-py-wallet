"""AGP-024: the light chain backend (Electrum, BLAKE2b header chain from a pinned checkpoint, SPV).

Headers   the port matches electrs' published v2 vectors stage by stage; the regtest vector chain
          verifies from its first BLAKE2b block; every header rule refuses its violation; the
          most-work branch wins; mainnet retargets follow Knots' pow.cpp.
Backend   over a fake Electrum server on a mined test chain, every RPC the client path makes gives
          the answer the node gives, and each is proven (Merkle proof into our own header).
Servers   a lying server is caught: forged proofs, wrong heights, substituted transactions, another
          chain, a wrong checkpoint; hiding is defeated by one honest server; an invented mempool
          spend never costs the refund.
Signer    with B2_CHAIN_BACKEND=electrum the signer funds, opens, pays, closes, counts a late close's
          change (woken by a subscription, AGP-022) and refunds at expiry, and never mines.
"""

from __future__ import annotations

import io
import json
import os
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from agentwallet import chain as chainbackend
from agentwallet.electrum import ElectrumBackend, ElectrumError, LightBackendError, scripthash
from agentwallet.headers import (
    PRIOR_HEADERS,
    RULES,
    Header,
    HeaderChain,
    HeaderError,
    merkle_branch,
    merkle_root_from_proof,
    parse_header,
    target_to_bits,
    bits_to_target,
    v1_hash,
    v2_stages,
)
from agentwallet.rpc import KnotsRpc
from agentwallet.signer import Signer

from _agp013 import keyfile_env
from _electrum_sim import CHECKPOINT, FakeElectrum, SimChain, T0, coinbase, mine_header, v1_header
from test_close_change import LaggedNode
from test_mainnet_readiness import API, PAY_TO, Rpc1, runbook_policy

from xbt402.funding import FundingPolicy
from xbt402.tx import Tx, TxIn, TxOut
from xbt402.x402_channel import XbtChannelProvider

VECTORS = Path(__file__).parent / "vectors"


def backend(*fakes, sim=None, **kw) -> ElectrumBackend:
    sim = sim or fakes[0].sim
    return ElectrumBackend([f.url for f in fakes], chain="regtest", checkpoint=(CHECKPOINT, sim.bhash(CHECKPOINT)),
                           timeout=5, **kw)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.sim = SimChain(height=200)
        self.fake = FakeElectrum(self.sim)
        self.addCleanup(self.fake.close)

    def light(self, *more, **kw):
        b = backend(self.fake, *more, sim=self.sim, **kw)
        self.addCleanup(b.close)
        return b


# --- headers --------------------------------------------------------------------------------------------------
class HeaderVectors(unittest.TestCase):
    def test_published_v2_vectors_stage_by_stage(self):
        vs = json.loads((VECTORS / "block_header_v2.json").read_text())["headers"]
        self.assertEqual(len(vs), 5)
        for v in vs:
            st = v2_stages(bytes.fromhex(v["serialized"]))
            for k in ("xor_key_hash", "mask", "h1", "h2", "blake2b_1", "blake2b_2", "block_hash"):
                self.assertEqual(st[k].hex(), v[k], f"{v['name']}: {k}")
            self.assertEqual(st["asic_input"].hex(), v["asic_input"], v["name"])
            self.assertEqual(parse_header(bytes.fromhex(v["serialized"])).hash, v["block_hash"])

    def test_the_regtest_vector_chain_verifies_from_its_first_blake2b_block(self):
        doc = json.loads((VECTORS / "blake2b_regtest.json").read_text())
        hs = {h["height"]: h for h in doc["headers"]}
        act = doc["activation_height"]
        c = HeaderChain("regtest", (act, hs[act]["hash"]))
        c.set_checkpoint(bytes.fromhex(hs[act]["header"]), [bytes.fromhex(hs[h]["header"]) for h in range(act - c.prior_needed, act)])
        r = c.connect(act, [bytes.fromhex(hs[h]["header"]) for h in range(act + 1, max(hs) + 1)])
        self.assertEqual((r["adopted"], c.tip_height, c.tip().hash), (True, max(hs), hs[max(hs)]["hash"]))

    def test_merkle_proof_into_a_real_block_and_its_committed_txcount(self):
        blk = json.loads((VECTORS / "blake2b_regtest.json").read_text())["blocks"]["131"]
        raw = bytes.fromhex(blk["raw"])
        hdr = parse_header(raw[:164])
        self.assertEqual((hdr.hash, hdr.txcount, hdr.height), (blk["hash"], 4, 131))
        s, txids = io.BytesIO(raw[165:]), []
        for _ in range(4):
            rest = s.getvalue()[s.tell():]
            tx = Tx.parse(rest)
            s.seek(s.tell() + len(tx.serialize()))
            txids.append(tx.txid())
        for pos, t in enumerate(txids):
            self.assertEqual(merkle_root_from_proof(t, merkle_branch(txids, pos), pos, hdr.txcount), hdr.merkle_root)
        br = merkle_branch(txids, 1)
        with self.assertRaises(HeaderError):            # a proof one level short (a 64-byte inner node as a tx)
            merkle_root_from_proof(t, br[:-1], 1, hdr.txcount)
        with self.assertRaises(HeaderError):            # a position past the committed count
            merkle_root_from_proof(t, br, 5, hdr.txcount)


class HeaderRules(unittest.TestCase):
    def chain(self, n=20):
        prev, raws, self.priors = "ab" * 32, [], []
        for h in range(CHECKPOINT - PRIOR_HEADERS, CHECKPOINT):
            self.priors.append(v1_header(prev, bytes(32), T0 + 60 * h))
            prev = v1_hash(self.priors[-1])
        for h in range(CHECKPOINT, CHECKPOINT + n):
            raw = mine_header(prev, bytes(32), h, 1, T0 + 60 * h)
            raws.append(raw)
            prev = parse_header(raw).hash
        c = HeaderChain("regtest", (CHECKPOINT, parse_header(raws[0]).hash))
        c.set_checkpoint(raws[0], self.priors)
        return c, raws

    def child(self, c, **kw):
        p = c.tip()
        args = {"prev_hash": p.hash, "merkle": bytes(32), "height": p.height + 1, "txcount": 1, "t": p.time + 60}
        args.update(kw)
        return mine_header(**args)

    def test_a_valid_chain_connects(self):
        c, raws = self.chain()
        self.assertTrue(c.connect(CHECKPOINT, raws[1:])["adopted"])
        self.assertEqual(c.tip_height, CHECKPOINT + 19)

    def test_each_rule_refuses_its_violation(self):
        c, raws = self.chain()
        c.connect(CHECKPOINT, raws[1:])
        tip = c.tip_height
        bad_pow = bytearray(self.child(c))
        for n in range(1 << 16):                       # a nonce whose hash misses the target
            bad_pow[76:80] = struct.pack("<I", n)
            if int(parse_header(bytes(bad_pow)).hash, 16) > parse_header(bytes(bad_pow)).target:
                break
        cases = {
            "pow": bytes(bad_pow),
            "link": self.child(c, prev_hash="cd" * 32),
            "height": self.child(c, height=tip + 5),
            "bits": self.child(c, bits=0x1F7FFFFF),     # harder than powLimit but not what regtest gives
            "mtp": self.child(c, t=c.at(tip - 6).time),
            "future": self.child(c, t=int(time.time()) + 3 * 3600),
            "v1": bytes(80),
        }
        for why, raw in cases.items():
            with self.subTest(why), self.assertRaises(HeaderError):
                c.connect(tip, [raw])
        self.assertEqual(c.tip_height, tip, "nothing connected")

    def test_the_checkpoint_is_pinned(self):
        c, raws = self.chain(2)
        other = HeaderChain("regtest", (CHECKPOINT, "00" * 32))
        with self.assertRaises(HeaderError):
            other.set_checkpoint(raws[0], self.priors)

    def test_most_work_wins_and_ties_keep_ours(self):
        c, raws = self.chain(10)
        c.connect(CHECKPOINT, raws[1:])
        fork_at = CHECKPOINT + 5
        base = c.at(fork_at)
        branch, prev = [], base
        for i in range(4):                             # same length as ours above the fork: a tie
            raw = mine_header(prev.hash, b"\x01" * 32, prev.height + 1, 1, prev.time + 61)
            branch.append(raw)
            prev = parse_header(raw)
        self.assertFalse(c.connect(fork_at, branch)["adopted"])
        raw = mine_header(prev.hash, b"\x01" * 32, prev.height + 1, 1, prev.time + 61)
        r = c.connect(fork_at, branch + [raw])
        self.assertEqual((r["adopted"], r["reorg"], c.tip().hash), (True, 4, parse_header(raw).hash))

    def test_persisted_headers_reload_and_a_tampered_file_is_ignored(self):
        c, raws = self.chain(8)
        path = Path(tempfile.mkdtemp()) / "headers-regtest.bin"
        c2 = HeaderChain("regtest", (CHECKPOINT, c.cp_hash), path)
        c2.set_checkpoint(raws[0], self.priors)
        c2.connect(CHECKPOINT, raws[1:])
        self.assertEqual(HeaderChain("regtest", (CHECKPOINT, c.cp_hash), path).tip_height, CHECKPOINT + 7)
        blob = bytearray(path.read_bytes())
        blob[80 * PRIOR_HEADERS + 164 * 3 + 76] ^= 0xFF   # one nonce
        path.write_bytes(bytes(blob))
        self.assertFalse(HeaderChain("regtest", (CHECKPOINT, c.cp_hash), path).ready)

    def test_mainnet_retarget_follows_pow_cpp(self):
        rules = RULES["main"]

        def hdr(height, bits, t):
            return Header(raw=b"", hash="", prev="", merkle_root=b"", time=t, bits=bits, height=height, txcount=1)

        bits = 0x1A0FFFFF
        self.assertEqual(rules.next_bits(hdr(10_000, bits, 0), None), {bits}, "inside a period: unchanged")
        last = 2016 * 5 - 1
        exact = rules.next_bits(hdr(last, bits, 1_209_600 // 2), 0)       # twice as fast: target halves
        self.assertEqual(exact, {target_to_bits(bits_to_target(bits) // 2)})
        self.assertEqual(rules.next_bits(hdr(last, bits, 10), 0),          # clamped at 4x harder
                         {target_to_bits(bits_to_target(bits) // 4)})
        self.assertEqual(rules.next_bits(hdr(last, 0x1D00FFFF, 10 ** 8), 0), {0x1D00FFFF}, "never above powLimit")
        lo, hi = rules.next_bits(hdr(last, bits, 0), None)                 # period start below the checkpoint
        self.assertLess(lo, bits_to_target(bits))
        self.assertGreater(hi, bits_to_target(bits))
        self.assertAlmostEqual(hi / lo, 16, delta=0.01)


# --- the backend against the chain ------------------------------------------------------------------------------
class BackendAnswers(Fixture):
    def test_tip_and_block_hashes_come_from_verified_headers(self):
        b = self.light()
        self.assertEqual(b.call("getblockcount"), self.sim.height)
        self.assertEqual(b.call("getblockhash", 150), self.sim.bhash(150))
        self.assertEqual(b.call("getblockheader", self.sim.bhash(150))["height"], 150)
        with self.assertRaises(ElectrumError):
            b.call("getblockhash", CHECKPOINT - 1)       # below the checkpoint: never read
        info = b.call("getblockchaininfo")
        self.assertEqual((info["chain"], info["blocks"], info["initialblockdownload"]), ("regtest", 200, False))

    def test_gettxout_and_friends_match_the_node(self):
        b = self.light()
        spk = "0014" + "33" * 20
        txid = self.sim.credit("", 1, 5_000, spk)
        self.sim.mine(2)
        node, light = self.sim.call("gettxout", txid, 1, True), b.call("gettxout", txid, 1, True)
        self.assertEqual({k: light[k] for k in ("confirmations", "value")}, {k: node[k] for k in ("confirmations", "value")})
        self.assertEqual(light["scriptPubKey"]["hex"], spk)
        self.assertEqual(light["bestblock"], self.sim.bhash(self.sim.height))
        v = b.call("getrawtransaction", txid, True)
        self.assertEqual((v["blockhash"], v["confirmations"]), (self.sim.bhash(201), 3))
        self.assertEqual(b.call("getrawtransaction", txid, True, self.sim.bhash(201))["txid"], txid)
        with self.assertRaises(ElectrumError):
            b.call("getrawtransaction", txid, True, self.sim.bhash(150))
        scan = b.call("scantxoutset", "start", [f"raw({spk})"])
        self.assertEqual([(u["txid"], u["vout"], u["amount"]) for u in scan["unspents"]], [(txid, 1, 5e-05)])
        # spent: gone from gettxout and the scan, and its spender is found
        spend = Tx(version=2, inputs=[TxIn(bytes.fromhex(txid)[::-1], 1)],
                   outputs=[TxOut(4_000, bytes.fromhex("0014" + "44" * 20))], locktime=0)
        self.assertEqual(b.call("sendrawtransaction", spend.hex()), spend.txid())
        self.assertEqual(b.call("gettxspendingprevout", [{"txid": txid, "vout": 1}])[0]["spendingtxid"], spend.txid())
        self.assertEqual(b.call("gettxout", spend.txid(), 0, True)["confirmations"], 0, "mempool output")
        self.assertIsNone(b.call("gettxout", spend.txid(), 0, False), "not in the UTXO set yet")
        self.sim.mine(1)
        self.assertIsNone(b.call("gettxout", txid, 1, True))
        self.assertEqual(b.call("scantxoutset", "start", [f"raw({spk})"])["unspents"], [])
        self.assertIsNone(b.call("gettxout", "ee" * 32, 0))

    def test_broadcast_goes_to_every_server_and_errors_read_like_the_node(self):
        second = FakeElectrum(self.sim)
        self.addCleanup(second.close)
        b = self.light(second)
        spk = "0014" + "55" * 20
        txid = self.sim.credit("", 0, 3_000, spk)
        spend = Tx(version=2, inputs=[TxIn(bytes.fromhex(txid)[::-1], 0)], outputs=[TxOut(2_000, bytes.fromhex(spk))],
                   locktime=0)
        b.call("sendrawtransaction", spend.hex())
        self.assertIn("blockchain.transaction.broadcast", self.fake.calls)
        self.assertIn("blockchain.transaction.broadcast", second.calls)
        with self.assertRaisesRegex(ElectrumError, "missingorspent|already"):
            b.call("sendrawtransaction", Tx(version=2, inputs=[TxIn(os.urandom(32), 0)],
                                            outputs=[TxOut(1, b"\x51")], locktime=0).hex())

    def test_node_wallet_and_mining_are_refused(self):
        b = self.light()
        for m in ("getbalances", "sendtoaddress", "generatetoaddress", "getblock", "listunspent", "dumpprivkey"):
            with self.subTest(m), self.assertRaises(LightBackendError):
                b.call(m)
        self.assertEqual(b.call("estimatesmartfee", 1)["feerate"], 0.00001)

    def test_a_subscription_wakes_the_waiter(self):
        b = self.light()
        spk = "0014" + "66" * 20
        b.watch([bytes.fromhex(spk)])
        b.wait_for_change(0.01)
        self.assertFalse(b.wait_for_change(0.2), "nothing changed")
        self.sim.credit("", 0, 2_000, spk, confirmed=False)
        self.assertTrue(b.wait_for_change(3), "the payment to a watched script notifies")


# --- lying servers ------------------------------------------------------------------------------------------------
class LyingServers(Fixture):
    def two(self):
        liar = FakeElectrum(self.sim)
        self.addCleanup(liar.close)
        return liar

    def coin(self, sats=5_000):
        spk = "0014" + os.urandom(20).hex()
        return self.sim.credit("", 0, sats, spk), spk

    def test_a_forged_merkle_proof_proves_nothing(self):
        txid, _ = self.coin()
        self.fake.forge_merkle = True
        b = self.light()
        self.assertIsNone(b.call("gettxout", txid, 0, True), "no proof: not a confirmed coin")
        self.assertTrue(any("get_merkle" in f["reason"] for f in b.flags))

    def test_one_honest_server_proves_what_a_liar_will_not(self):
        liar = self.two()
        liar.forge_merkle = True
        txid, _ = self.coin()
        b = ElectrumBackend([liar.url, self.fake.url], chain="regtest",
                            checkpoint=(CHECKPOINT, self.sim.bhash(CHECKPOINT)), timeout=5)
        self.addCleanup(b.close)
        self.assertEqual(b.call("gettxout", txid, 0, True)["confirmations"], 1)
        self.assertTrue(any(f["server"] == liar.url for f in b.flags))

    def test_a_wrong_height_is_not_believed(self):
        txid, _ = self.coin()
        self.fake.claim_height[txid] = 150             # "it confirmed long ago"
        b = self.light()
        self.assertIsNone(b.call("gettxout", txid, 0, True))
        with self.assertRaises(ElectrumError):
            b.call("getrawtransaction", txid, True)

    def test_a_substituted_transaction_is_refused(self):
        txid, _ = self.coin()
        other, _ = self.coin()
        self.fake.substitute[txid] = self.sim.raw[other]
        b = self.light()
        self.assertIsNone(b.call("gettxout", txid, 0, True))
        self.assertTrue(any("not the transaction asked for" in f["reason"] for f in b.flags))

    def test_hiding_a_spend_fails_when_one_server_shows_it(self):
        liar = self.two()
        txid, spk = self.coin()
        spend = Tx(version=2, inputs=[TxIn(bytes.fromhex(txid)[::-1], 0)],
                   outputs=[TxOut(4_000, bytes.fromhex("0014" + "77" * 20))], locktime=0)
        self.sim.call("sendrawtransaction", spend.hex())
        self.sim.mine(1)
        liar.hide.add(spend.txid())
        alone = backend(liar, sim=self.sim)
        self.addCleanup(alone.close)
        self.assertIsNotNone(alone.call("gettxout", txid, 0, True), "one liar alone can hide a spend")
        both = self.light(liar)
        self.assertIsNone(both.call("gettxout", txid, 0, True), "the union of histories shows it")

    def test_an_invented_mempool_spend_never_costs_the_refund(self):
        txid, spk = self.coin()
        fake_spend = Tx(version=2, inputs=[TxIn(bytes.fromhex(txid)[::-1], 0)],
                        outputs=[TxOut(4_000, bytes.fromhex("0014" + "88" * 20))], locktime=0)
        self.fake.extra_raw[fake_spend.txid()] = fake_spend.hex()
        self.fake.extra_history[scripthash(bytes.fromhex(spk))] = [{"tx_hash": fake_spend.txid(), "height": 0}]
        b = self.light()
        self.assertEqual(b.call("gettxspendingprevout", [{"txid": txid, "vout": 0}])[0].get("spendingtxid"),
                         fake_spend.txid(), "reported, as the node reports its mempool")
        self.assertIsNotNone(b.call("gettxout", txid, 0, True), "but the output is still ours to refund")
        self.fake.extra_history.clear()
        self.fake.claim_height[fake_spend.txid()] = 201
        self.fake.extra_history[scripthash(bytes.fromhex(spk))] = [{"tx_hash": fake_spend.txid(), "height": 201}]
        self.assertIsNotNone(b.call("gettxout", txid, 0, True), "a claimed confirmation without a proof is nothing")

    def test_a_server_on_a_weaker_chain_is_ignored_and_reported(self):
        liar = self.two()
        alt = dict(self.sim.hdr)
        prev = alt[150]
        for h in range(151, 170):                      # shorter branch from 150: less work
            raw = mine_header(parse_header(prev).hash, b"\x02" * 32, h, 1, T0 + 60 * h + 1)
            alt[h] = prev = raw
        for h in [h for h in alt if h >= 170]:
            del alt[h]
        liar.headers = alt
        b = self.light(liar)
        self.assertEqual(b.call("getblockcount"), self.sim.height)
        st = {s["url"]: s for s in b.status()["servers"]}
        self.assertFalse(st[liar.url]["on_best_chain"])
        self.assertTrue(st[self.fake.url]["on_best_chain"])

    def test_a_reorg_to_more_work_unconfirms_what_it_orphaned(self):
        txid, _ = self.coin()                          # confirmed at 201
        b = self.light()
        self.assertEqual(b.call("gettxout", txid, 0, True)["confirmations"], 1)
        alt = {h: r for h, r in self.sim.hdr.items() if h <= 200}
        prev = alt[200]
        for h in range(201, 204):                      # a longer branch without the coin's block
            raw = mine_header(parse_header(prev).hash, b"\x03" * 32, h, 1, T0 + 60 * h + 2)
            alt[h] = prev = raw
        self.fake.headers = alt
        self.fake._changed()
        time.sleep(0.2)
        self.assertEqual(b.call("getblockcount"), 203)
        self.assertEqual(b.call("getblockhash", 201), parse_header(alt[201]).hash)
        self.assertIsNone(b.call("gettxout", txid, 0, True), "its block is gone: no longer proven")

    def test_a_server_on_another_checkpoint_is_refused(self):
        b = ElectrumBackend([self.fake.url], chain="regtest", checkpoint=(CHECKPOINT, "00" * 32), timeout=5)
        self.addCleanup(b.close)
        with self.assertRaisesRegex(ElectrumError, "checkpoint"):
            b.call("getblockcount")

    def test_too_few_reachable_servers_is_an_error(self):
        dead = "tcp://127.0.0.1:1"
        b = ElectrumBackend([self.fake.url, dead], chain="regtest", checkpoint=(CHECKPOINT, self.sim.bhash(CHECKPOINT)),
                            timeout=2, min_servers=2)
        self.addCleanup(b.close)
        with self.assertRaisesRegex(ElectrumError, "1 of 2"):
            b.call("getblockcount")
        ok = ElectrumBackend([self.fake.url, dead], chain="regtest", checkpoint=(CHECKPOINT, self.sim.bhash(CHECKPOINT)),
                             timeout=2)
        self.addCleanup(ok.close)
        self.assertEqual(ok.call("getblockcount"), self.sim.height)

    def test_mainnet_needs_two_servers_and_its_checkpoint_by_default(self):
        b = ElectrumBackend(["tcp://127.0.0.1:1", "tcp://127.0.0.1:2"], chain="main")
        self.assertEqual((b.min_servers, b.headers.cp_height), (2, 961_640))
        with self.assertRaises(ElectrumError):
            ElectrumBackend(["tcp://127.0.0.1:1"], chain="regtest")       # regtest: no default checkpoint


# --- selection ---------------------------------------------------------------------------------------------------
class Selection(Fixture):
    def env(self, **kv):
        keys = ("B2_CHAIN_BACKEND", "B2_ELECTRUM_SERVERS", "B2_ELECTRUM_CHECKPOINT", "B2_CHAIN")
        return mock.patch.dict(os.environ, {**{k: "" for k in keys}, **kv})

    def test_rpc_stays_the_default(self):
        tmp = Path(tempfile.mkdtemp())
        with self.env():
            self.assertIsInstance(chainbackend.backend_from_env(tmp, tmp / "c", "agent", tmp), KnotsRpc)

    def test_electrum_and_auto(self):
        tmp = Path(tempfile.mkdtemp())
        cp = f"{CHECKPOINT}:{self.sim.bhash(CHECKPOINT)}"
        with self.env(B2_CHAIN_BACKEND="electrum", B2_ELECTRUM_SERVERS=self.fake.url, B2_ELECTRUM_CHECKPOINT=cp,
                      B2_CHAIN="regtest"):
            b = chainbackend.backend_from_env(tmp, tmp / "c", "agent", tmp)
            self.assertIsInstance(b, ElectrumBackend)
            b.close()
        with self.env(B2_ELECTRUM_SERVERS=self.fake.url, B2_ELECTRUM_CHECKPOINT=cp, B2_CHAIN="regtest"):
            self.assertEqual(chainbackend.backend_mode(), "auto")
            b = chainbackend.backend_from_env(tmp, tmp / "c", "agent", tmp)      # no node here: Electrum
            self.assertIsInstance(b, ElectrumBackend)
            b.close()
            with mock.patch.object(chainbackend, "node_answers", return_value=True):
                self.assertIsInstance(chainbackend.backend_from_env(tmp, tmp / "c", "agent", tmp), KnotsRpc)
        with self.env(B2_CHAIN_BACKEND="electrum", B2_ELECTRUM_SERVERS=self.fake.url):
            with self.assertRaisesRegex(chainbackend.BackendError, "B2_CHAIN"):
                chainbackend.backend_from_env(tmp, tmp / "c", "agent", tmp)


# --- the signer on the light backend ---------------------------------------------------------------------------
class LightRig:
    """The AGP-017 rig with the payer on Electrum: the B1 provider uses the chain as its node (RPC), the
    signer sees it only through a fake Electrum server."""

    def __init__(self, **policy):
        self.tmp = Path(tempfile.mkdtemp())
        keyfile_env()
        runbook_policy(self.tmp, **policy)
        self.node = SimChain(height=1000)
        self.fake = FakeElectrum(self.node)
        self.light = backend(self.fake, sim=self.node)
        self.signer = Signer(self.tmp, rpc=self.light)
        self.provider = XbtChannelProvider(
            Rpc1(self.node), PAY_TO, self.node.network(), str(self.tmp / "provider.sqlite"),
            lambda m, p: 500, lambda m, p, b: (200, {"Content-Type": "application/json"}, b'{"ok":true}'),
            close_fee=600, close_margin=144,
            policy=FundingPolicy(min_capacity=10_000, max_capacity=10_000, min_expiry_blocks=1_008, close_margin=144))

    def close_all(self):
        self.light.close()
        self.fake.close()

    def http(self, method, url, body=b"", headers=None):
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        return self.provider.serve(method, path, headers or {}, body or b"", url)

    def call(self, method, **params):
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=self.http):
            return self.signer.handle({"method": method, "params": params})

    def tick(self):
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=self.http):
            return self.signer.watch_tick()

    def mine(self, n=1):
        """The rig's miner. The watcher wakes on the header notification; here we wait for the tip."""
        self.node.mine(n)
        deadline = time.time() + 5
        while self.light.call("getblockcount") != self.node.height and time.time() < deadline:
            self.light.wait_for_change(0.1)

    def fund_hot(self, sats=12_000):
        txid = self.node.credit("", 0, sats, self.signer.hot.spk.hex())
        return self.call("notice_hot_txid", txid=txid)

    def channel(self):
        return self.signer.channels.get(API)


class SignerOnElectrum(unittest.TestCase):
    def rig(self, **policy):
        r = LightRig(regtest_mine=False, **policy)
        self.addCleanup(r.close_all)
        return r

    def opened(self, pays=2):
        rig = self.rig()
        self.assertEqual(rig.fund_hot()["noticed"], 1)
        r = rig.call("xbt402_pay", url=API + "/agp024/echo", max_sats=500)
        self.assertEqual((r["verdict"], r["rule"]), ("pending", "funding_unconfirmed"), r)
        rig.mine(1)                             # the rig's miner; the light signer never mines
        rig.tick()
        self.assertEqual(rig.channel().state, "open")
        self.assertEqual(rig.channel().funding_height, 1002, "the funding's block, from a Merkle proof")
        for _ in range(pays):
            r = rig.call("xbt402_pay", url=API + "/agp024/echo", max_sats=500)
            self.assertEqual((r["verdict"], r["charged_sats"]), ("allow", 500), r)
        return rig

    def test_light_signer_health_balance_and_refusals(self):
        rig = self.rig()
        h = rig.call("health")
        self.assertEqual((h["mining"], h["chain"], h["chain_backend"]["backend"]), (False, "regtest", "electrum"))
        self.assertEqual(h["chain_backend"]["checkpoint"], [CHECKPOINT, rig.node.bhash(CHECKPOINT)])
        bal = rig.call("balance")
        self.assertEqual((bal["node_wallet"], bal["trusted_sats"]), (None, 0))
        rig.fund_hot()
        self.assertEqual(rig.call("balance")["hot"]["hot_sats"], 12_000)
        r = rig.call("pay", to="bcrt1qxvenxvenxvenxvenxvenxvenxvenxvenztev8a", amount_sats=100)
        self.assertEqual(r["verdict"], "deny")
        self.assertNotIn("generatetoaddress", rig.fake.calls)

    def test_a_light_signer_on_the_wrong_chain_refuses_to_start(self):
        """As the RPC path refuses a node on another chain (AGP-017 P3): servers that answer but cannot
        serve the pinned checkpoint are another chain. Servers that are down only delay the start."""
        rig = self.rig()
        main = ElectrumBackend([rig.fake.url], chain="main", timeout=5, min_servers=1)
        self.addCleanup(main.close)
        with mock.patch.dict(os.environ, {"B2_CHAIN": "main"}):
            with self.assertRaisesRegex(Exception, "B2_CHAIN='main'.*checkpoint"):
                Signer(rig.tmp, rpc=main)
        # the regtest checkpoint pinned for "main" (a copied environment): regtest PoW fails mainnet's powLimit
        mixed = ElectrumBackend([rig.fake.url], chain="main", timeout=5, min_servers=1,
                                checkpoint=(CHECKPOINT, rig.node.bhash(CHECKPOINT)))
        self.addCleanup(mixed.close)
        with mock.patch.dict(os.environ, {"B2_CHAIN": "main"}):
            with self.assertRaisesRegex(Exception, "B2_CHAIN='main'.*powLimit"):
                Signer(rig.tmp, rpc=mixed)
        down = ElectrumBackend(["tcp://127.0.0.1:1"], chain="regtest", timeout=2,
                               checkpoint=(CHECKPOINT, rig.node.bhash(CHECKPOINT)))
        self.addCleanup(down.close)
        with mock.patch.dict(os.environ, {"B2_CHAIN": "regtest"}):
            self.assertTrue(Signer(rig.tmp, rpc=down).light)

    def test_reconcile_at_start_finds_coins_through_electrum(self):
        rig = self.rig()
        rig.node.credit("", 0, 7_000, rig.signer.hot.spk.hex())     # arrives while the signer is "down"
        rec = rig.call("hot_reconcile", scan=True)
        self.assertEqual((rec["ok"], rec["found"], rec["hot_sats"]), (True, 1, 7_000), rec)

    def test_open_pay_and_close_counts_the_change(self):
        rig = self.opened()
        r = rig.call("close_channel", counterparty=API)
        self.assertEqual(r["close_change"], "counted", r)
        rec = rig.channel()
        self.assertEqual(rig.signer.hot.balance_sats(), 12_000 - rec.funding_sats - 600 + rec.funding_sats
                         - rec.close_fee - rec.used_sats)

    def test_a_late_close_is_counted_when_its_subscription_fires(self):
        """AGP-022 over Electrum: the close reaches the servers after close_channel looked; the watcher
        is woken by the funding script's subscription and counts the change."""
        rig = self.opened()
        lag = LaggedNode(rig.node)
        rig.provider.rpc = lag
        r = rig.call("close_channel", counterparty=API)
        self.assertEqual(r["close_change"], "pending", r)
        before = rig.signer.hot.balance_sats()
        rig.light.watch(rig.signer._watch_scripts())
        rig.light.wait_for_change(0.01)
        self.assertEqual(rig.tick(), [])
        lag.deliver()
        self.assertTrue(rig.light.wait_for_change(3), "the close notifies a watched script")
        acts = rig.tick()
        self.assertEqual([(a["close_change"], a["closed_txid"]) for a in acts], [("counted", r["txid"])])
        rec = rig.channel()
        self.assertEqual(rig.signer.hot.balance_sats(), before + rec.funding_sats - rec.close_fee - rec.used_sats)

    def test_a_close_that_confirms_before_we_look_is_found_by_its_proof(self):
        rig = self.opened()
        lag = LaggedNode(rig.node)
        rig.provider.rpc = lag
        r = rig.call("close_channel", counterparty=API)
        lag.deliver()
        rig.mine(2)
        self.assertEqual([a["close_change"] for a in rig.tick()], ["counted"])

    def test_refund_at_expiry_through_electrum(self):
        rig = self.opened(pays=1)
        rec = rig.channel()
        self.assertEqual(rig.call("xbt402_refund", counterparty=API)["rule"], "refund_early")
        rig.mine(rec.expiry - rig.node.height)
        acts = rig.tick()
        [a] = [a for a in acts if a.get("rule") == "refund"]
        self.assertEqual(rig.channel().state, "refunded")
        self.assertIn(a["txid"], rig.node.mempool)
        rig.mine(1)
        self.assertEqual(rig.call("hot_reconcile", scan=True)["ok"], True)

    def test_an_invented_close_does_not_stop_the_refund(self):
        rig = self.opened(pays=1)
        rec = rig.channel()
        fake = Tx(version=2, inputs=[TxIn(bytes.fromhex(rec.funding_txid)[::-1], rec.funding_vout)],
                  outputs=[TxOut(1_000, bytes.fromhex("0014" + "99" * 20))], locktime=0)
        rig.fake.extra_raw[fake.txid()] = fake.hex()
        from xbt402.channel import funding_script
        from xbt402.tx import p2wsh_spk
        sh = scripthash(p2wsh_spk(funding_script(bytes.fromhex(rec.payer_pub), bytes.fromhex(rec.payee_pub),
                                                 rec.expiry)))
        rig.fake.extra_history[sh] = [{"tx_hash": fake.txid(), "height": 0}]
        rig.mine(rec.expiry - rig.node.height)
        acts = rig.tick()
        self.assertEqual([a.get("rule") for a in acts if "rule" in a], ["refund"])
        self.assertEqual(rig.channel().state, "refunded")


if __name__ == "__main__":
    unittest.main()
