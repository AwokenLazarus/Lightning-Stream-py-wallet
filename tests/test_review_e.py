"""AGP-069 review E: light client and consensus edges (the Rust tests of the same names in xbt-rs:
crates/xbt-primitives/tests/header_chain.rs, crates/xbt-electrum/tests/backend.rs,
crates/xbt-signer/tests/review_e.rs).

E3   bad-flags-highbits, bad-version, the median from the first header (the 10 headers below the
     checkpoint), pins, Knots' min-difficulty walk back; testnet4 and signet fail closed.
E1   a lying server (a tip near 2**32, junk headers, slow answers) neither stalls other callers nor
     costs more than a chunk of headers.
E2   a cheap fork is not believed (min chain work, the time floor); mainnet needs TLS.
M1   a coinbase coin in the hot wallet waits for the node's coinbase maturity, and for good when the
     node cannot say.
"""

from __future__ import annotations

import json
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from agentwallet.electrum import ElectrumBackend, ElectrumError, ImplausibleChain, Plausibility
from agentwallet.headers import (
    MAINNET_CHECKPOINT,
    MAINNET_PINS,
    RULES,
    ChainRules,
    HeaderChain,
    HeaderError,
    check_pow,
    mainnet_min_work_above,
    parse_header,
    v1_hash,
    work_of,
)
from agentwallet.hot import HotWallet

from _agp017 import PrunedChain
from _electrum_sim import CHECKPOINT, FakeElectrum, SimChain, T0 as SIM_T0, mine_header

VECTORS = Path(__file__).parent / "vectors"
REGTEST_BITS = 0x207FFFFF
T0 = 1_800_000_000
VERSION = 0x2000_0000


# --- E3: header rules ------------------------------------------------------------------------------------------
def mine_with(prev: str, height: int, t: int, bits: int, salt: int, want_valid: bool, version: int, flags: int) -> bytes:
    rules = RULES["regtest"]
    for nonce in range(1 << 32):
        raw = (struct.pack("<I", version | 0x8000_0000) + bytes.fromhex(prev)[::-1] + bytes([salt]) * 32
               + struct.pack("<III", t, bits, nonce) + bytes(8) + bytes(16) + struct.pack("<I", 0)
               + struct.pack("<H", 1) + bytes([flags, 0]) + bytes(16) + struct.pack("<I", height) + bytes(32))
        try:
            check_pow(parse_header(raw), rules)
            valid = True
        except HeaderError:
            valid = False
        if valid == want_valid:
            return raw
    raise AssertionError("unreachable")


def mine(prev: str, height: int, t: int, bits: int = REGTEST_BITS, salt: int = 0, want_valid: bool = True) -> bytes:
    return mine_with(prev, height, t, bits, salt, want_valid, VERSION, 0)


def v1(prev: str, t: int) -> bytes:
    return struct.pack("<I", VERSION) + bytes.fromhex(prev)[::-1] + b"\x5a" * 32 + struct.pack("<III", t, REGTEST_BITS, 0)


def priors(t: int) -> list[bytes]:
    """The 10 v1 headers below the checkpoint (heights 91..100), times t, t+1, ..."""
    out, prev = [], "03" * 32
    for i in range(10):
        out.append(v1(prev, t + i))
        prev = v1_hash(out[-1])
    return out


def branch(parent: bytes, n: int, t: int, salt: int) -> list[bytes]:
    out, p = [], parse_header(parent)
    for i in range(n):
        raw = mine(p.hash, p.height + 1, t + i, REGTEST_BITS, salt)
        p = parse_header(raw)
        out.append(raw)
    return out


def chain_with(cp: bytes, prior: list[bytes], rules: ChainRules | None = None) -> HeaderChain:
    h = parse_header(cp)
    c = HeaderChain("regtest", (h.height, h.hash), clock=lambda: T0 + 10_000)
    if rules is not None:
        c.rules = rules
    c.set_checkpoint(cp, prior)
    return c


def base() -> tuple[list[bytes], bytes]:
    p = priors(T0 - 100)
    return p, mine(v1_hash(p[-1]), 101, T0)


class HeaderRulesE3(unittest.TestCase):
    def test_e3_flags_highbits_and_version(self):
        """Knots refuses either of the top two flag bits (bad-flags-highbits, validation.cpp:4431) and a
        version below 4 (bad-version, 4757-4762)."""
        p, cp = base()
        c = chain_with(cp, p)
        h = parse_header(cp)
        for flags in (0x40, 0x80, 0xC0):
            with self.assertRaisesRegex(HeaderError, "bad-flags-highbits"):
                c.connect(101, [mine_with(h.hash, 102, T0 + 1, REGTEST_BITS, 1, True, VERSION, flags)])
        for version in (0, 1, 2, 3):
            with self.assertRaisesRegex(HeaderError, "bad-version"):
                c.connect(101, [mine_with(h.hash, 102, T0 + 1, REGTEST_BITS, 1, True, version, 0)])
        ok = mine_with(h.hash, 102, T0 + 1, REGTEST_BITS, 1, True, 4, 0x01)
        self.assertTrue(c.connect(101, [ok])["adopted"])

    def test_e3_median_time_from_the_first_header(self):
        p = priors(T0 + 1_000)
        cp = mine(v1_hash(p[-1]), 101, T0 + 1_010)
        c = chain_with(cp, p)
        h = parse_header(cp)
        with self.assertRaisesRegex(HeaderError, "not above the median"):   # the median of 91..101 is T0+1005
            c.connect(101, [mine(h.hash, 102, T0 + 500, salt=1)])
        self.assertTrue(c.connect(101, [mine(h.hash, 102, T0 + 1_006, salt=1)])["adopted"])
        fresh = HeaderChain("regtest", (101, h.hash), clock=lambda: 0)
        with self.assertRaises(HeaderError, msg="nine instead of ten"):
            fresh.set_checkpoint(cp, p[1:])
        swapped = list(p)
        swapped[3], swapped[4] = swapped[4], swapped[3]
        with self.assertRaises(HeaderError, msg="not hash-linked"):
            fresh.set_checkpoint(cp, swapped)
        with self.assertRaises(HeaderError, msg="another chain's headers"):
            fresh.set_checkpoint(cp, priors(T0))
        fresh.set_checkpoint(cp, p)

    def test_pinned_heights_refuse_any_other_block(self):
        p, cp = base()
        honest = branch(cp, 10, T0 + 1, 1)
        pin = parse_header(honest[4])                     # height 106
        rules = ChainRules("regtest", pow_limit=RULES["regtest"].pow_limit, allow_min_difficulty=True,
                           no_retargeting=True, pins=((106, pin.hash),))
        c = chain_with(cp, p, rules)
        c.connect(101, honest[:2])
        with self.assertRaisesRegex(HeaderError, "checkpoint-mismatch"):
            c.connect(103, branch(honest[1], 20, T0 + 50, 2))
        self.assertTrue(c.connect(103, honest[2:])["adopted"])
        self.assertTrue(c.connect(108, branch(honest[6], 10, T0 + 50, 3))["adopted"])
        self.assertEqual(RULES["main"].pins, MAINNET_PINS)
        self.assertEqual(MAINNET_PINS[0][0], 964_264)

    def test_e3_min_difficulty_walk_back(self):
        harder = 0x207FFFFE
        p = priors(T0 - 100)
        cp = mine(v1_hash(p[-1]), 101, T0, harder)
        c = chain_with(cp, p)
        h = parse_header(cp)
        with self.assertRaisesRegex(HeaderError, "207ffffe"):
            c.connect(101, [mine(h.hash, 102, T0 + 600, REGTEST_BITS, 1)])
        gap = T0 + 1_201
        with self.assertRaises(HeaderError):
            c.connect(101, [mine(h.hash, 102, gap, harder, 1)])
        m1 = mine(h.hash, 102, gap, REGTEST_BITS, 1)
        c.connect(101, [m1])
        m1h = parse_header(m1)
        with self.assertRaises(HeaderError):
            c.connect(102, [mine(m1h.hash, 103, gap + 1, REGTEST_BITS, 2)])
        self.assertTrue(c.connect(102, [mine(m1h.hash, 103, gap + 1, harder, 2)])["adopted"])

    def test_unsupported_test_networks_fail_closed(self):
        for chain in ("testnet4", "test", "signet", "nochain"):
            with self.subTest(chain), self.assertRaises(HeaderError):
                HeaderChain(chain, (150_308, "00" * 32))
            with self.subTest(f"backend {chain}"), self.assertRaises(ElectrumError):
                ElectrumBackend(["ssl://a.example:1"], chain=chain, checkpoint=(150_308, "00" * 32))

    def test_a_branch_validates_as_it_grows(self):
        p, cp = base()
        c = chain_with(cp, p)
        good = branch(cp, 6, T0 + 1, 1)
        b = c.branch(101)
        b.extend(good[:3])
        bad = bytearray(good[3])
        bad[40] ^= 1
        with self.assertRaises(HeaderError):
            b.extend([bytes(bad), good[4]])
        self.assertEqual((len(b), b.tip_height), (3, 104))
        self.assertTrue(c.adopt(b)["adopted"])
        self.assertEqual(c.tip_height, 104)
        stale = c.branch(104)
        b2 = c.branch(103)
        b2.extend(branch(good[1], 3, T0 + 20, 2))
        self.assertTrue(c.adopt(b2)["adopted"])
        stale.extend(good[3:])
        self.assertFalse(c.adopt(stale)["adopted"], "its fork point 104 was replaced")

    def test_mainnet_checkpoint_with_its_real_priors(self):
        v = json.loads((VECTORS / "mainnet_headers_961630.json").read_text())
        self.assertEqual(v["start"], 961_630)
        raws = [bytes.fromhex(h) for h in v["headers"]]
        c = HeaderChain("main", MAINNET_CHECKPOINT)
        self.assertEqual(c.prior_needed, 10)
        with self.assertRaises(HeaderError, msg="nine headers below"):
            c.set_checkpoint(raws[10], raws[1:10])
        c.set_checkpoint(raws[10], raws[:10])
        r = c.connect(961_640, raws[11:])
        self.assertEqual((r["adopted"], r["tip"]), (True, 961_700))
        bad = list(raws[11:])
        b = bytearray(bad[5])
        b[110] |= 0x80
        bad[5] = bytes(b)
        c2 = HeaderChain("main", MAINNET_CHECKPOINT)
        c2.set_checkpoint(raws[10], raws[:10])
        with self.assertRaises(HeaderError):
            c2.connect(961_640, bad)
        self.assertEqual(c2.tip_height, 961_640, "connect is all or nothing")

    def test_mainnet_minimum_work(self):
        self.assertEqual(mainnet_min_work_above(MAINNET_CHECKPOINT), 0x0010_c428_4b55_92c3_c377)
        self.assertEqual(mainnet_min_work_above((964_264, "00" * 32)), 0)
        self.assertIsNone(mainnet_min_work_above((962_000, "00" * 32)), "an older anchor of unknown chainwork")

    def test_persists_and_reloads(self):
        path = Path(tempfile.mkdtemp()) / "headers.bin"
        p, cp = base()
        hx = parse_header(cp).hash
        c = HeaderChain("regtest", (101, hx), path, clock=lambda: T0 + 10_000)
        c.set_checkpoint(cp, p)
        c.connect(101, branch(cp, 5, T0 + 1, 1))
        self.assertEqual(HeaderChain("regtest", (101, hx), path, clock=lambda: T0 + 10_000).tip_height, 106)
        self.assertFalse(HeaderChain("regtest", (101, "00" * 32), path).ready)
        meta = path.with_suffix(".json")
        m = json.loads(meta.read_text())
        del m["prior"]                                    # a store from before the headers below were kept
        meta.write_text(json.dumps(m))
        self.assertFalse(HeaderChain("regtest", (101, hx), path, clock=lambda: T0 + 10_000).ready)


# --- E1, E2: the backend -----------------------------------------------------------------------------------------
def light(chain: SimChain, *fakes, **kw) -> ElectrumBackend:
    return ElectrumBackend([f.url for f in fakes], chain="regtest", checkpoint=(CHECKPOINT, chain.bhash(CHECKPOINT)),
                           timeout=5, **kw)


class BackendE1E2(unittest.TestCase):
    def fake(self, sim):
        f = FakeElectrum(sim)
        self.addCleanup(f.close)
        return f

    def test_mainnet_needs_tls(self):
        for ok in ("tcp://127.0.0.1:50001", "tcp://127.8.9.10:1", "tcp://localhost:1", "tcp://LOCALHOST.:1", "tcp://[::1]:1",
                   "tcp://[::ffff:127.0.0.1]:1", "127.0.0.1:50001:t", "ssl://electrum.example:50002", "electrum.example:50002:s"):
            with self.subTest(ok):
                ElectrumBackend([ok, "ssl://b.example:1"], chain="main").close()
        for bad in ("tcp://electrum.example:50001", "tcp://10.0.0.5:50001", "tcp://192.168.1.2:1", "tcp://[::ffff:10.0.0.1]:1",
                    "tcp://localhost.example.com:1", "tcp://127.0.0.1.nip.io:1", "electrum.example:50001:t", "tcp://0.0.0.0:1"):
            with self.subTest(bad), self.assertRaisesRegex(ElectrumError, "mainnet needs ssl://"):
                ElectrumBackend([bad, "ssl://b.example:1"], chain="main")
        ElectrumBackend(["tcp://10.0.0.5:1"], chain="regtest", checkpoint=(101, "ab" * 32)).close()

    def test_hostile_lying_server_cannot_stall(self):
        """A server claiming a tip near 2**32 and streaming junk headers, then answering slowly, neither
        stalls the other callers nor costs more than a chunk of headers per sync."""
        sim = SimChain(height=300)
        honest, liar = self.fake(sim), self.fake(sim)
        liar.fake_tip = mine_header("44" * 32, b"\x45" * 32, 4_000_000_000, 1, SIM_T0 + 60 * 300)
        liar.junk_above = 300
        b = light(sim, liar, honest)
        self.addCleanup(b.close)
        t = time.monotonic()
        self.assertEqual(b.call("getblockcount"), 300)
        self.assertLess(time.monotonic() - t, 5)
        self.assertTrue(any(f["server"] == liar.url and "beyond the plausible" in f["reason"] for f in b.flags), b.flags)
        asked = liar.calls.count("blockchain.block.headers")
        self.assertLessEqual(asked, 5, f"the first junk chunk ends the fetch: {asked} header requests")
        # the liar claims the real tip but answers header requests slowly: a sync in flight holds no one up
        liar.fake_tip, liar.junk_above, liar.delay_headers_s = None, None, 1.5
        sim.mine(1)
        got = []
        syncing = threading.Thread(target=lambda: got.append(b.sync(force=True)))
        syncing.start()
        time.sleep(0.3)
        t = time.monotonic()
        b.status()
        b.call("getblockhash", 300)
        held = time.monotonic() - t
        self.assertLess(held, 0.7, f"held up {held:.2f}s by the slow server's sync")
        syncing.join(10)
        self.assertEqual(got, [301], "the honest server's block still arrives")

    def test_hostile_cheap_fork_is_not_believed(self):
        """A fresh client whose only server serves the real checkpoint and then a few cheap blocks with a
        fake funding in them believes nothing until the chain is plausible."""
        honest, cheap = SimChain(height=CHECKPOINT), SimChain(height=CHECKPOINT)
        self.assertEqual(honest.bhash(CHECKPOINT), cheap.bhash(CHECKPOINT))
        honest.mine(299)                                   # tip 400
        fake = cheap.credit("", 0, 5_000_000, "0014" + "91" * 20)   # mined: 102
        cheap.mine(19)                                      # tip 121
        good, liar = self.fake(honest), self.fake(cheap)
        per_block = work_of(REGTEST_BITS)

        def rules(*fakes, now):
            b = light(honest, *fakes, clock=lambda: now,
                      plausibility=Plausibility(min_work_above=per_block * 200, floor_spacing_s=60, floor_slack=50))
            self.addCleanup(b.close)
            return b

        now = SIM_T0 + 60 * 400 + 30
        alone = rules(liar, now=now)
        with self.assertRaisesRegex(ImplausibleChain, "below the minimum"):
            alone.call("gettxout", fake, 0, True)
        with self.assertRaises(ImplausibleChain):
            alone.call("getblockcount")
        with self.assertRaises(ImplausibleChain, msg="nothing is answered from it"):
            alone.call("getblockhash", CHECKPOINT)
        self.assertIsInstance(alone.status()["implausible"], str)
        b = rules(liar, good, now=now)
        self.assertEqual(b.call("getblockcount"), 400)
        self.assertIsNone(b.call("gettxout", fake, 0, True))
        self.assertIsNone(b.status()["implausible"])
        late = rules(good, now=SIM_T0 + 60 * 500)
        with self.assertRaisesRegex(ImplausibleChain, "implausibly low"):
            late.call("getblockcount")


# --- M1: the hot wallet's coinbase coins -------------------------------------------------------------------------
DEST = bytes.fromhex("0014" + "aa" * 20)
CB = "cb" * 32


def long_rule(depth: int) -> dict:
    return {"deployments": {"long_coinbase_maturity": {"type": "flagday", "active": True, "height": 150,
                                                       "height_end": 900_000, "coinbase_start_height": 150,
                                                       "maturity": depth}}}


class HotCoinbaseM1(unittest.TestCase):
    def wallet(self, node, d=None):
        d = d or tempfile.mkdtemp()
        return HotWallet(Path(d) / "hot.json", node, "bcrt"), d

    def test_m1_coinbase_waits_for_the_node_maturity(self):
        node = PrunedChain("regtest", 200)
        node.deployments = long_rule(150)
        hot, _ = self.wallet(node)
        node.credit_coinbase(CB, 0, 50_000, hot.spk.hex())
        r = hot.reconcile(scan=True)
        self.assertEqual(hot.balance_sats(), 50_000, r)
        self.assertEqual(hot.status()["hot_coinbase_sats"], 50_000)
        with self.assertRaisesRegex(RuntimeError, "50000 of it immature coinbase"):
            hot.prepare_fund(DEST, 10_000, 500)
        node.mine(100)                                      # past the ordinary 100, short of the node's 150
        with self.assertRaises(RuntimeError):
            hot.prepare_fund(DEST, 10_000, 500)
        with self.assertRaisesRegex(RuntimeError, "immature coinbase"):
            hot.sweep_to(DEST, 10_000, 500)
        self.assertIsNone(hot.rotate()["sweep"], "rotation leaves the coin on the retired key")
        self.assertIsNone(hot.sweep_retired())
        node.mine(49)                                       # the spend relays in block 350 = 200 + 150
        swept = hot.sweep_retired()
        self.assertEqual(swept["inputs"], 1)
        self.assertIn(swept["txid"], node.mempool)

    def test_m1_coinbase_waits_when_the_node_cannot_say(self):
        node = PrunedChain("regtest", 200)
        hot, _ = self.wallet(node)
        node.credit_coinbase(CB, 0, 50_000, hot.spk.hex())
        node.credit("ab" * 32, 0, 20_000, hot.spk.hex(), confirmed=True)
        hot.reconcile(scan=True)
        node.mine(10_000)
        with self.assertRaisesRegex(RuntimeError, "immature coinbase"):
            hot.prepare_fund(DEST, 30_000, 500)
        hot.prepare_fund(DEST, 10_000, 500)                 # an ordinary coin still spends
        node.deployments = {"deployments": {}}              # a node with no long rule: the ordinary depth
        hot.prepare_fund(DEST, 30_000, 500)

    def test_m1_coinbase_flag_from_gettxout_and_the_transaction(self):
        node = PrunedChain("regtest", 200)
        node.deployments = {"deployments": {}}
        hot, _ = self.wallet(node)
        node.credit_coinbase(CB, 0, 50_000, hot.spk.hex())
        hot.notice_utxo(CB, 0, 50_000)                      # learnt without the flag
        node.mine(98)
        hot.reconcile(scan=False)
        with self.assertRaises(RuntimeError, msg="block 299 cannot spend a block-200 coinbase"):
            hot.prepare_fund(DEST, 10_000, 500)
        node.mine(1)
        hot.prepare_fund(DEST, 10_000, 500)                 # block 300 can

        hot2, d2 = self.wallet(node)
        cb2 = "cd" * 32
        node.credit_coinbase(cb2, 1, 40_000, hot2.spk.hex())
        self.assertEqual(hot2.scan_from_txid(cb2, blockhash=node.bhash(node.height)), 1)
        with self.assertRaises(RuntimeError, msg="scanned from the transaction: vin[0] is a coinbase"):
            hot2.prepare_fund(DEST, 10_000, 500)
        hot2, _ = self.wallet(node, d2)                     # the flag survives a restart
        self.assertEqual(hot2.status()["hot_coinbase_sats"], 40_000)
        node.mine(99)
        hot2.prepare_fund(DEST, 10_000, 500)


if __name__ == "__main__":
    unittest.main()
