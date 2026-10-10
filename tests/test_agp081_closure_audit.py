"""AGP-081: closure-audit fixes on the transport and the light client (the Rust tests of the same
names are in xbt-rs: crates/xbt-electrum/tests and crates/xbt402/tests).

E1   one Electrum server can no longer stall or exhaust the client: a line above what the pending
     requests can be answered with drops the server before it is parsed; an invented history is
     bounded, flagged and never cached past the cache bound; a trickled header sync ends at the
     first short answer, and any sync at its deadline.
T2   a URL with a `#` fragment is refused before anything is signed, funded or sent.
T4c  a paid answer without a receipt is refused; what was signed for it stays booked.

The hostile server is tests/e1_attacks.py (which also measures the three E1 attacks).
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agentwallet import electrum
from agentwallet.b1path import ensure_b1
from agentwallet.electrum import ElectrumBackend, ElectrumError, scripthash
from agentwallet.forward import ForwardSession
from agentwallet.signer import Signer

ensure_b1()
from xbt402.channel import ChannelError  # noqa: E402
from xbt402.tx import Tx, TxIn, TxOut  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, network_id  # noqa: E402

from _electrum_sim import CHECKPOINT, FakeElectrum, SimChain  # noqa: E402
from e1_attacks import HostileElectrum, invented_tx  # noqa: E402

SPK = "0014" + "5a" * 20
DEST = "http://127.0.0.1:9"


def light(sim: SimChain, *servers, **kw) -> ElectrumBackend:
    kw.setdefault("timeout", 5)
    return ElectrumBackend([s.url for s in servers], chain="regtest", checkpoint=(CHECKPOINT, sim.bhash(CHECKPOINT)), **kw)


def reasons(b: ElectrumBackend, server) -> list[str]:
    return [f["reason"] for f in b.flags if f["server"] == server.url]


def wait_dropped(conn, within: float = 3.0) -> bool:
    end = time.monotonic() + within
    while conn.connected and time.monotonic() < end:
        time.sleep(0.01)
    return not conn.connected


# --- E1: the light client ----------------------------------------------------------------------------------------
class ElectrumE1(unittest.TestCase):
    def hostile(self, sim) -> HostileElectrum:
        f = HostileElectrum(sim)
        self.addCleanup(f.close)
        return f

    def honest(self, sim) -> FakeElectrum:
        f = FakeElectrum(sim)
        self.addCleanup(f.close)
        return f

    def backend(self, sim, *servers, **kw) -> ElectrumBackend:
        b = light(sim, *servers, **kw)
        self.addCleanup(b.close)
        return b

    def test_an_oversized_line_is_dropped_before_it_is_parsed(self):
        sim = SimChain(height=CHECKPOINT + 5)
        txid = sim.credit("", 0, 50_000, SPK)
        srv = self.hostile(sim)
        b = self.backend(sim, srv)
        self.assertEqual(b.call("getblockcount"), sim.height)
        conn = b.conns[0]
        parsed, loads = [], json.loads

        def recording(s, *a, **kw):
            parsed.append(len(s))
            return loads(s, *a, **kw)

        with mock.patch.object(electrum.json, "loads", recording):
            b.sync(force=True)
            self.assertTrue(parsed, "the reader parses through the patched json.loads")
            with self.subTest("a whole line above what an idle connection may be sent"):
                srv.push(200_000)
                self.assertTrue(wait_dropped(conn), "the server is dropped")
                self.assertLessEqual(max(parsed), electrum.NOTIFY_SLACK, "and the line was never parsed")
                self.assertTrue(any("bytes" in r and "above the" in r for r in reasons(b, srv)), b.flags)
            with self.subTest("a line that never ends is dropped while it is still partial"):
                self.assertEqual(b.sync(force=True), sim.height, "the next call reconnects")
                flags = len(b.flags)
                srv.push(200_000, newline=False)
                self.assertTrue(wait_dropped(conn), "no newline is waited for")
                self.assertGreater(len(b.flags), flags)
            with self.subTest("a dense line inside the byte allowance of the request it answers"):
                srv.raw_answer["blockchain.transaction.get"] = b"[" + b"0," * 100_000 + b"0]\n"
                with self.assertRaises(ElectrumError):
                    b.call("getrawtransaction", txid)
                self.assertTrue(any("JSON values" in r for r in reasons(b, srv)), b.flags)
                self.assertLessEqual(max(parsed), electrum.NOTIFY_SLACK)
                srv.raw_answer.clear()
        with self.subTest("an answer as long as a request can ask for is still taken"):
            sh = scripthash(bytes.fromhex(SPK))
            srv.extra_history[sh] = [{"tx_hash": f"{i:064x}", "height": 0} for i in range(2_000)]
            flags = len(b.flags)
            self.assertEqual(len(b._history(bytes.fromhex(SPK))), 2_001)
            self.assertEqual(len(b.flags), flags)
            self.assertTrue(conn.connected)

    def test_an_invented_history_is_bounded_and_flagged(self):
        sim = SimChain(height=CHECKPOINT + 5)
        txid = sim.credit("", 0, 50_000, SPK)
        sh = scripthash(bytes.fromhex(SPK))
        honest = self.honest(sim)

        with self.subTest("invented entries are flagged; the cache keeps to its bound"):
            liar = self.hostile(sim)
            liar.invent(sh, 300, size=1_000)
            b = self.backend(sim, liar, honest)
            with mock.patch.object(electrum, "TX_CACHE_BYTES", 64 << 10, create=True):
                self.assertEqual(b.call("gettxout", txid, 0, True)["value"], 0.0005)
                cached = sum(len(tx.hex()) // 2 for tx in b._tx.values())
            self.assertIn("get_history lists a transaction that neither pays nor spends the script", reasons(b, liar))
            self.assertEqual(reasons(b, honest), [])
            self.assertLessEqual(cached, 64 << 10, "300 kB of invented transactions were fetched")
            self.assertLessEqual(set(b._conf), set(b._tx), "a confirmation is cached only with its transaction")

        with self.subTest("a real spend and an entry whose prevout nobody serves are not flagged"):
            spend = Tx(version=2, inputs=[TxIn(bytes.fromhex(txid)[::-1], 0)],
                       outputs=[TxOut(40_000, bytes.fromhex("0014" + "77" * 20))], locktime=0)
            sim.call("sendrawtransaction", spend.hex())
            odd = self.hostile(sim)
            unserved = "ee" * 32
            child = Tx(version=2, inputs=[TxIn(bytes.fromhex(unserved)[::-1], 0)],
                       outputs=[TxOut(1_000, bytes.fromhex("0014" + "78" * 20))], locktime=0)
            odd.extra_raw[child.txid()] = child.hex()
            odd.extra_history[sh] = [{"tx_hash": unserved, "height": 0}, {"tx_hash": child.txid(), "height": 0}]
            b = self.backend(sim, odd, honest)
            self.assertEqual(b.call("gettxspendingprevout", [{"txid": txid, "vout": 0}])[0]["spendingtxid"], spend.txid())
            self.assertEqual(b.flags, [])

        with self.subTest("an answer above MAX_HISTORY entries is flagged and not used"):
            long = self.hostile(sim)
            long.extra_history[sh] = [{"tx_hash": f"{i:064x}", "height": 0} for i in range(electrum.MAX_HISTORY + 1)]
            b = self.backend(sim, long, honest)
            self.assertEqual(b.call("gettxspendingprevout", [{"txid": txid, "vout": 0}])[0]["spendingtxid"], spend.txid(),
                             "the honest server's history is still used")
            self.assertTrue(any("get_history" in r and "above" in r for r in reasons(b, long)), b.flags)
            self.assertLessEqual(long.calls.count("blockchain.transaction.get"), 4, "none of its entries is fetched")

        with self.subTest("an invented unspent output is flagged"):
            fake = invented_tx(0, 200)
            liar = self.hostile(sim)
            liar.invented[fake.txid()] = (0, 200)
            liar.extra_unspent[sh] = [{"tx_hash": fake.txid(), "tx_pos": 0, "height": 0, "value": 9}]
            b = self.backend(sim, liar, honest)
            self.assertEqual(b.call("scantxoutset", "start", [f"raw({SPK})"])["unspents"], [])
            self.assertIn("listunspent lists an output that does not pay the script", reasons(b, liar))

        with self.subTest("no answer is not an empty history"):
            mute = self.hostile(sim)
            mute.refuse = {"blockchain.scripthash.get_history", "blockchain.scripthash.listunspent"}
            b = self.backend(sim, mute)
            with self.assertRaisesRegex(ElectrumError, "no server answered"):
                b.call("gettxout", txid, 0, True)
            with self.assertRaisesRegex(ElectrumError, "no server answered"):
                b.call("scantxoutset", "start", [f"raw({SPK})"])

    def test_a_trickled_header_sync_is_cut_off_and_flagged(self):
        start = CHECKPOINT + 20
        with self.subTest("a short answer inside the tip the server claims ends its part of the round"):
            sim = SimChain(height=start)
            slow, honest = self.hostile(sim), self.honest(sim)
            both, alone = self.backend(sim, slow, honest), self.backend(sim, slow)
            self.assertEqual((both.sync(force=True), alone.sync(force=True)), (start, start))
            sim.mine(120)
            slow.headers_per_answer, slow.trickle_above, slow.trickle_delay_s = 1, start, 0.05
            # a server whose tip is on our chain already is not asked for headers: the honest answer
            # is held back so that the trickler is always asked first
            honest.delay_headers_s = 0.5
            asked = slow.calls.count("blockchain.block.headers")
            t = time.monotonic()
            self.assertEqual(both.sync(force=True), start + 120, "the honest server's headers arrive")
            took = time.monotonic() - t
            self.assertLess(took, 3.0, f"the round waited {took:.2f}s for the trickle (120 answers take 6 s)")
            self.assertEqual(slow.calls.count("blockchain.block.headers") - asked, 1)
            self.assertIn(f"headers: withheld headers: served up to {start + 1}, claims tip {start + 120}",
                          reasons(both, slow))
            self.assertEqual(alone.sync(force=True), start + 1, "the header it did serve is kept")
            self.assertEqual(alone.sync(force=True), start + 2)

        with self.subTest("a sync that is still going at its deadline keeps what it proved and is flagged"):
            sim = SimChain(height=start)
            slow = self.honest(sim)
            b = self.backend(sim, slow, sync_deadline=1.0)
            self.assertEqual(b.sync(force=True), start)
            sim.mine(120)
            slow.delay_headers_s = 0.3                  # 15 full answers of 8 headers: 4.5 s
            with mock.patch.object(electrum, "HEADERS_CHUNK", 8):
                t = time.monotonic()
                tip = b.sync(force=True)
                took = time.monotonic() - t
            self.assertLess(took, 2.5, f"a 1 s deadline held the round for {took:.2f}s")
            self.assertTrue(start < tip < start + 120 and (tip - start) % 8 == 0, f"whole chunks are kept: tip {tip}")
            self.assertTrue(any("sync deadline" in r for r in reasons(b, slow)), b.flags)


# --- T2, T4c: the payer ------------------------------------------------------------------------------------------
class PayerTransport(unittest.TestCase):
    """The signer's xbt402_pay against a B1 provider, over an HTTP hook that records every request
    and can change a paid answer on its way back.

    The fixtures of the earlier test modules are imported when a test runs, not when this module is
    loaded: they put B1's tests/security first on sys.path, and unittest's discovery would then find
    B1's test_l7_untrusted_body in place of ours."""

    def setUp(self):
        import test_request_auth
        import xbt402.x402_channel as xc
        from sechelp import FakeNode, make_provider
        from test_unacked_state import Engine, Rpc

        self.assertEqual(test_request_auth.DEST, DEST)
        tmp = Path(tempfile.mkdtemp())
        self.book, _, p = test_request_auth.funded(tmp)
        node = FakeNode()
        prov = make_provider(xc, node)
        self.assertEqual(prov.network, network_id("11" * 32))
        node.add_funding(p, confirmations=6)
        prov.open({"x402Version": 2, "network": prov.network, "channel": {
            "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry,
            "payerPub": p.payer_pub, "redeemScript": p.script.hex()}})
        self.sent: list[tuple[str, str]] = []
        self.tamper = None

        def http(method, url, body=b"", headers=None):
            self.sent.append((method, url))
            path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
            st, h, out = prov.serve(method, path, headers or {}, body or b"", url)
            h = {k.upper(): v for k, v in h.items()}
            if self.tamper and "PAYMENT-SIGNATURE" in {k.upper() for k in headers or {}}:
                return self.tamper(st, h, out)
            return st, h, out

        patch = mock.patch.object(XbtChannelClient, "http", staticmethod(http))
        patch.start()
        self.addCleanup(patch.stop)
        self.signer = Signer.__new__(Signer)
        self.signer.engine = Engine()
        self.signer.config = SimpleNamespace(channel_expiry_blocks=2_000, per_counterparty_cap_sats=50_000)
        self.session = ForwardSession(self.book, hot=None, rpc=Rpc(), height=lambda: 1_000, forward_path=tmp / "forward.json")
        self.signer._xbt402 = self.session
        self.session.set_spend_book(self.signer._book_signed_delta)

    def pay(self, url: str, max_sats: int = 500) -> dict:
        return self.signer._xbt402_pay_locked({"url": url, "method": "GET", "body": "", "max_sats": max_sats})

    def state(self) -> tuple:
        rec = self.book.get(DEST)
        return rec.used_sats, rec.seq, rec.last_sig

    def test_a_target_with_a_fragment_is_refused_by_the_payer(self):
        before = self.state()
        for url in (DEST + "/v1/x#frag", DEST + "/v1/x#", DEST + "/v1/x?a=1#b", DEST + "#/v1/x"):
            for max_sats in (500, 0):
                with self.subTest(url=url, max_sats=max_sats):
                    r = self.pay(url, max_sats)
                    self.assertEqual((r.get("verdict"), r.get("rule")), ("deny", "dest"), r)
        with self.subTest("the session itself, as the forward rail and the stream reach it"):
            with self.assertRaises(ChannelError) as err:
                self.session.pay_once(DEST + "/v1/x#frag", "GET", b"", 500, 2_000, 50_000)
            self.assertEqual(err.exception.code, "bad_request")
            with self.assertRaises(ChannelError) as err:
                self.session._with_auth({"chan": self.book.get(DEST).chan, "seq": 1, "cum": "0"}, "GET",
                                        DEST + "/v1/x#frag", b"")
            self.assertEqual(err.exception.code, "bad_request")
        self.assertEqual(self.sent, [], "nothing was sent, not even the unpaid request")
        self.assertEqual(self.state(), before, "nothing was signed and no seq was spent")
        self.assertEqual(self.signer.engine.commits, [])
        with self.subTest("the same URL without the fragment is paid"):
            self.assertEqual(self.pay(DEST + "/v1/x")["status"], 200)

    def test_a_sellers_chunk_url_with_a_fragment_buys_no_chunk(self):
        from test_m7_final_chunk import ORIGIN, RID, Rig

        rig = Rig()
        sent = []
        doc = {"manifest": rig.c.manifest, "chunkUrl": f"/v1/report/{RID}/chunk/{{i}}#x"}
        seq = rig.book.get(ORIGIN).seq

        def http(method, url, body=b"", headers=None):
            sent.append(url)
            return rig.http(method, url, body, headers)

        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            out = rig.s.stream(ORIGIN, {"payTo": rig.c.manifest["payTo"]}, doc, 1_000_000)
        self.assertFalse(out["stream"]["ok"])
        self.assertIn("fragment", out["stream"]["refused"])
        self.assertEqual(sent, [])
        self.assertEqual(rig.book.get(ORIGIN).seq, seq, "no seq was spent and no hash lock signed")
        self.assertEqual(rig.book.get(ORIGIN).pending_cond, {})

    def test_a_paid_answer_without_a_receipt_is_refused(self):
        def strip(st, h, out):
            h.pop("PAYMENT-RESPONSE", None)
            return st, h, b"forged"

        self.tamper = strip
        r = self.pay(DEST + "/v1/x")
        self.assertEqual((r.get("verdict"), r.get("rule")), ("deny", "bad_receipt"), r)
        self.assertNotIn("forged", json.dumps(r))
        rec = self.book.get(DEST)
        self.assertGreater(rec.used_sats, 0)
        booked = [(rec.used_sats, f"xbt402:{rec.chan}:{rec.used_sats}")]
        self.assertEqual(self.signer.engine.commits, booked, "the state that was signed stays booked")
        self.tamper = None
        again = self.pay(DEST + "/v1/x")
        self.assertEqual((again["status"], again["cum"]), (200, rec.used_sats), "the same state is sent again")
        self.assertEqual(self.signer.engine.commits, booked)


if __name__ == "__main__":
    unittest.main()
