"""AGP-080: the wallet side paths the closure audit (AGP-077) found, one test per hole.

W1  every signing path books the signed amount before the signature leaves: 0xA3 states (the audit's
    failing test, 750a3e8), the stream's hash-locked last chunk, adaptor pre-signatures (routed locks
    and forward lots). A voided lock releases nothing.
W3  a close the chain never saw does not stop the refund watcher; `fund_treasury` needs the human's
    signature and a `recover_treasury` signature binds its destination.
X1  a seller-supplied URL off the origin is refused before any request; a redirect is not followed.
M1  the forward rail reads the coinbase maturity from the node.
S1  the forward rail's sighash is B1's (annex and codeseparator: both or refused).

Same names as xbt-rs crates/xbt-signer/tests/agp080_closure.rs where the Rust signer has the path.
"""

from __future__ import annotations

import copy
import http.server
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.approval import b2x, sign
from agentwallet.channels import ChannelBook
from agentwallet.signer import Signer
from agentwallet.xbt402 import Xbt402Session

from _agp013 import HUMAN_PRIV, HUMAN_PUB, NETWORK, PAY_TO, FakeRpc, fund_channel, keyfile_env, write_policy

from xbt402 import ecc
from xbt402.channel import DERIVATION, ChannelError
from xbt402.x402_channel import FACILITATOR_VERIFY, SCHEME, XbtChannelClient, b64json, unb64json

API = "http://api.test"
HUB = "http://hub.test"
ROUTING = {"hubs": {HUB: {"max_fee_ppm": 5_000, "max_fee_base_msat": 2_000}}, "max_lock_sats": 20_000,
           "daily_budget_sats": 3_000}


def ledger_sum(s: Signer) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


def signer(tmp: Path, rpc: FakeRpc | None = None, **policy) -> Signer:
    keyfile_env()
    write_policy(tmp, **{"per_counterparty_cap_sats": 100_000, "split_window_s": 0, "human_pubkey": HUMAN_PUB.hex(),
                         **policy})
    s = Signer(tmp, rpc=rpc or FakeRpc(height=1000))
    s.hot.notice_utxo("aa" * 32, 0, 300_000)
    return s


def free_port() -> int:
    """A loopback port below the ephemeral range (32768+), bound once to prove it is free."""
    for port in range(21080, 21980):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port in 21080-21979")


class A3Booking(unittest.TestCase):
    def test_w1_a3_states_are_booked_before_the_signature_leaves(self):
        """The audit's test (b2 agp-077 750a3e8), and the order: the ledger holds the state when it is signed."""
        s = signer(Path(tempfile.mkdtemp()), max_per_tx_sats=1_000, daily_budget_sats=2_000, weekly_budget_sats=2_000)
        chan = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 100_000}})["chan"]
        at_sign, real = [], s.channels.sign_state_a3

        def sign_a3(dest, amount):
            at_sign.append((amount, ledger_sum(s)))
            return real(dest, amount)

        s.channels.sign_state_a3 = sign_a3
        signed = 0
        for cum in range(1_000, 20_001, 1_000):
            r = s.handle({"method": "xbt402_sign_state_a3", "params": {"chan": chan, "amount": cum}})
            if "sig" not in r:
                break
            signed = cum
        booked = ledger_sum(s)
        self.assertLessEqual(signed, 2_000, f"0xA3 states signed up to {signed} sat against a daily budget of 2,000")
        self.assertEqual(booked, signed, f"signed {signed} sat, ledger holds {booked}")
        self.assertTrue(at_sign and all(held >= amount for amount, held in at_sign), at_sign)


class SignedAhead(unittest.TestCase):
    """Every path that hands out a signature: the ledger holds the amount at that moment."""

    def test_w1_sign_state_and_the_pay_rail_book_before_they_sign(self):
        s = signer(Path(tempfile.mkdtemp()))
        seen = []
        for name in ("sign_state", "increment"):
            real = getattr(s.channels, name)

            def hooked(dest, amount, real=real, name=name):
                before = ledger_sum(s)
                out = real(dest, amount)
                seen.append((name, s.channels.get(dest).used_sats, before))
                return out

            setattr(s.channels, name, hooked)
        r = s.handle({"method": "pay", "params": {"to": API, "amount_sats": 700, "memo": "a"}})
        self.assertEqual(r["verdict"], "allow", r)
        r = s.handle({"method": "sign_state", "params": {"dest": API, "cum": 1_500}})
        self.assertEqual(r["verdict"], "allow", r)
        self.assertEqual([n for n, _, _ in seen], ["increment", "sign_state"])
        self.assertTrue(all(held >= cum for _, cum, held in seen), seen)

    def test_w1_the_streams_hash_locked_last_chunk_is_booked_before_it_is_signed(self):
        """A whole stream through pay_once: every state that reaches the provider (plain chunk states on
        /x402/verify, the hash-locked last chunk) is in the ledger when its request is made, and the
        folded plain state books nothing more."""
        from test_m7_final_chunk import LAST, ORIGIN, PRICE, RID, Rig

        r = Rig()
        booked = []
        r.s.set_spend_book(lambda dest, delta, chan, cum: booked.append((delta, cum)))
        exposed = []                                   # (what the request's signature is worth, booked then)
        m = copy.deepcopy(r.c.manifest)

        def http(method, url, body=b"", headers=None):
            path = "/" + url.split("/", 3)[3]
            held = sum(d for d, _ in booked)
            pay = unb64json(headers["PAYMENT-SIGNATURE"])["payload"] if "PAYMENT-SIGNATURE" in (headers or {}) else None
            if path == FACILITATOR_VERIFY:
                exposed.append(("plain", int(json.loads(body)["paymentPayload"]["payload"]["cum"]), held))
            elif pay and pay.get("hashlock"):
                exposed.append(("hashlock", int(pay["cum"]) + PRICE, held))
            if path.startswith(f"/v1/report/{RID}/chunk/") and path != LAST:
                return 200, {}, json.dumps(r.c.chunk(int(path.rsplit("/", 1)[1]))).encode()
            return r.http(method, url, body, headers)

        doc = {"manifest": m, "chunkUrl": f"/v1/report/{RID}/chunk/{{i}}"}
        acc = {"payTo": m["payTo"], "network": r.prov.network, "scheme": SCHEME, "amount": str(PRICE), "extra": {}}
        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            out = r.s.stream(ORIGIN, acc, doc, budget=m["n"] * PRICE)
        self.assertTrue(out["stream"]["ok"], out)
        self.assertEqual([k for k, _, _ in exposed], ["plain"] * (m["n"] - 1) + ["hashlock", "plain"])
        self.assertTrue(all(held >= worth for _, worth, held in exposed), exposed)
        used = r.book.get(ORIGIN).used_sats
        self.assertEqual(sum(d for d, _ in booked), used, "the folded state rides on the lock's booking")
        self.assertEqual(r.book.get(ORIGIN).ledger_booked_sats, used)

    def test_w1_a_last_chunk_that_fails_keeps_its_booking(self):
        from test_m7_final_chunk import ORIGIN, PRICE, Rig
        from agentwallet.stream import StreamError

        r = Rig()
        r.drop = True
        booked = []
        r.s.set_spend_book(lambda dest, delta, chan, cum: booked.append(delta))
        with self.assertRaises(StreamError):
            r.buy_last()
        self.assertTrue(r.chan.cond_sig, "the provider holds the signed hash lock")
        self.assertEqual(sum(booked), PRICE, "the lock the provider can still claim stays booked")
        self.assertEqual(r.book.get(ORIGIN).ledger_booked_sats, PRICE)

    def test_w1_a_forward_lots_pre_signature_is_booked_before_it_leaves(self):
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        at_send, real = [], t.m.http

        def http(method, url, body=b"", headers=None):
            if "PAYMENT-SIGNATURE" in (headers or {}):
                at_send.append((int(unb64json(headers["PAYMENT-SIGNATURE"])["payload"]["cum"]), ledger_sum(t.s)))
            return real(method, url, body, headers)

        t.m.withhold = True
        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            r = t.buy()
        self.assertEqual(r["delivered"], False, r)
        self.assertEqual(at_send, [(PRICE, PRICE)], "the pre-signed state was in the ledger when it left")
        # the market closes with the completed state: the recovery books nothing twice
        rec = t.s.handle({"method": "forward_recover", "params": {"txid": t.m.close_with_last_state()}})
        self.assertTrue(rec["recovered"], rec)
        self.assertEqual(ledger_sum(t.s), PRICE)
        self.assertEqual(t.s.channels.get(MARKET).ledger_booked_sats, PRICE)

    def test_w1_a_forward_lot_proven_void_by_the_refund_is_released(self):
        from test_forward_rail import MARKET, PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        t.m.withhold = True
        t.buy()
        self.assertEqual(ledger_sum(t.s), PRICE, "booked while the market can still complete it")
        t.rpc.height = 8000
        r = t.s.handle({"method": "xbt402_refund", "params": {"counterparty": MARKET}})
        self.assertEqual(r["rule"], "refund", r)
        self.assertEqual(ledger_sum(t.s), 0, "our refund spent the funding: the pre-signature is void")


class AdaptorBooking(unittest.TestCase):
    def setUp(self):
        from test_routing import invoice_point

        self.point = invoice_point
        self.rpc = FakeRpc(height=1000)
        self.s = signer(Path(tempfile.mkdtemp()), self.rpc, routing=ROUTING, allowlist=[API, HUB])
        self.p = fund_channel(self.s.channels, self.rpc, HUB)
        self.chan = self.p.channel_id

    def lock(self, cum: int):
        t, T = self.point()
        r = self.s.handle({"method": "xbt402_sign_state_adaptor", "params": {
            "chan": self.chan, "cum": cum, "point": T, "route": {"hub": HUB, "amount": 900, "fee": 2, "lockId": f"L{cum}"}}})
        return t, r

    def void(self):
        return self.s.handle({"method": "xbt402_void_lock", "params": {"chan": self.chan}})

    def test_w1_an_adaptor_pre_signature_is_booked_before_it_leaves_and_a_void_does_not_release_it(self):
        at_sign, real = [], self.s.routing.sign_state_adaptor

        def presign(chan, cum, point, route=None):      # what the route signer hands on: the ledger holds it
            out = real(chan, cum, point, route)
            at_sign.append((cum, ledger_sum(self.s)))
            return out

        self.s.routing.sign_state_adaptor = presign
        out = []
        for cum in range(1_000, 5_001, 1_000):        # five pre-signatures, each voided: the hub may hold all five
            _, r = self.lock(cum)
            out.append(r.get("rule") or r["verdict"])
            self.void()
        self.assertEqual(out[:3], ["allow"] * 3, out)
        self.assertEqual(out[3:], ["route_daily_budget"] * 2, "the routing budget (3,000) stops the fourth")
        self.assertTrue(all(held >= cum for cum, held in at_sign), at_sign)
        self.assertEqual(ledger_sum(self.s), 3_000, "a void released nothing")
        self.assertEqual(self.s.handle({"method": "routing_status"})["spent_24h_sats"], 3_000)
        # a lock at a voided cum rides on its booking: one close can claim only one state
        t, r = self.lock(3_000)
        self.assertEqual(r["verdict"], "allow", r)
        self.assertEqual(ledger_sum(self.s), 3_000)
        secret = (t + int(r["tweak"], 16)) % ecc.N
        self.assertIn("t", self.s.handle({"method": "xbt402_resolve_lock",
                                          "params": {"chan": self.chan, "secret": f"{secret:064x}"}}))
        self.assertEqual(ledger_sum(self.s), 3_000, "the resolve does not book it again")
        self.assertEqual(self.s.handle({"method": "routing_status"})["spent_24h_sats"], 3_000)
        self.assertEqual(self.s.channels.get(HUB).used_sats, 3_000)
        # and a restart books nothing more
        s2 = Signer(self.s.root, rpc=self.rpc)
        self.assertEqual((ledger_sum(s2), s2.routing.recovered_bookings), (3_000, 0))

    def test_w1_a_booked_lock_whose_rows_a_crash_lost_is_booked_at_start(self):
        with mock.patch.object(self.s.routing, "_book", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.s.routing.sign_state_adaptor(self.chan, 1_000, self.point()[1], {"hub": HUB, "amount": 900, "fee": 2})
        lk = self.s.channels.get(HUB).pending_lock
        self.assertEqual((lk["booked"], lk["booked_sats"], ledger_sum(self.s)), (True, 1_000, 0))
        self.s.routing.spend._log.close()
        self.s.engine.store._log.close()
        s2 = Signer(self.s.root, rpc=self.rpc)
        self.assertEqual((ledger_sum(s2), s2.routing.recovered_bookings, s2.routing.spend.since(0)), (3_000 // 3, 1, 1_000))
        self.assertEqual(Signer(self.s.root, rpc=self.rpc).routing.recovered_bookings, 0)

    def test_w1_a_lock_pre_signed_before_the_upgrade_is_booked_when_it_resolves(self):
        t, r = self.lock(1_000)
        with self.s.channels._lock:                    # as a book from before AGP-080 left it: no flag, no rows
            rec = self.s.channels._records[HUB]
            rec.pending_lock.pop("booked", None)
            rec.pending_lock.pop("booked_sats", None)
            rec.ledger_booked_sats = 0
            self.s.channels._persist()
        self.s.engine.store.amend(f"lock:{self.chan}:1000", None)
        self.s.routing.spend.rows.clear()
        self.s.routing.spend._keys.clear()
        self.assertEqual(self.s.routing.pending_sats(), 1_000, "an unbooked pending lock counts against the budget")
        secret = (t + int(r["tweak"], 16)) % ecc.N
        self.s.handle({"method": "xbt402_resolve_lock", "params": {"chan": self.chan, "secret": f"{secret:064x}"}})
        self.assertEqual(ledger_sum(self.s), 1_000)
        self.assertEqual(self.s.handle({"method": "routing_status"})["spent_24h_sats"], 1_000)

    def test_w1_a_plain_state_over_a_booked_lock_books_only_the_rest(self):
        self.lock(1_000)
        r = self.s.handle({"method": "sign_state", "params": {"chan": self.chan, "cum": 1_400}})
        self.assertEqual(r["verdict"], "allow", r)
        self.assertEqual(ledger_sum(self.s), 1_400)


class SellerUrls(unittest.TestCase):
    """X1: the seller names where the open and the chunks are; neither may leave its origin."""

    OFF = ("@evil.example/open", "//evil.example/open", "http://evil.example/open", ".evil.example/open",
           "/open\\@evil.example", "/open\n/x", " /open", ":8080/open", "", "open")

    def test_x1_a_seller_url_off_the_origin_is_refused(self):
        from agentwallet.xbt402 import same_origin_url

        for bad in self.OFF:
            with self.subTest(bad), self.assertRaises(ChannelError) as e:
                same_origin_url(API, bad)
            self.assertEqual(e.exception.code, "seller_url")
        self.assertEqual(same_origin_url(API, "/x402/xbt-channel/open"), API + "/x402/xbt-channel/open")
        self.assertEqual(same_origin_url(API, API + "/open?a=1"), API + "/open?a=1")

    def test_x1_an_open_url_off_the_origin_funds_nothing_and_asks_no_one(self):
        rpc = FakeRpc(height=1000)
        s = signer(Path(tempfile.mkdtemp()), rpc)
        s._xbt402.network = lambda: NETWORK
        asked = []

        def http(method, url, body=b"", headers=None):
            asked.append(url)
            if "evil" in url:
                return 200, {}, b'{"preflight": true}'
            extra = {"derivation": DERIVATION, "closeFeeSat": "600", "closeMarginBlocks": "6", "minConf": "0",
                     "openUrl": "@evil.example/open"}
            acc = {"scheme": SCHEME, "network": NETWORK, "amount": "500", "payTo": ecc.pubkey(PAY_TO).hex(), "extra": extra}
            return 402, {"PAYMENT-REQUIRED": b64json({"x402Version": 2, "accepts": [acc]})}, b"{}"

        with mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
            r = s.handle({"method": "xbt402_pay", "params": {"url": API + "/v1/x", "max_sats": 500}})
        self.assertEqual((r["verdict"], r["rule"]), ("deny", "seller_url"), r)
        self.assertEqual(asked, [API + "/v1/x"], "only the allowlisted origin was asked")
        self.assertEqual((rpc.sent, s.channels.list_public()), ([], []), "nothing was funded")

    def test_x1_a_chunk_url_off_the_origin_is_refused_before_any_chunk_request(self):
        from test_m7_final_chunk import ORIGIN, PRICE, Rig

        r = Rig()
        m = copy.deepcopy(r.c.manifest)
        acc = {"payTo": m["payTo"], "network": r.prov.network, "scheme": SCHEME, "amount": str(PRICE), "extra": {}}
        asked = []

        def http(method, url, body=b"", headers=None):
            asked.append(url)
            return 500, {}, b""

        for bad in ("@evil.example/chunk/{i}", "//evil.example/{i}", "http://evil.example/c/{i}"):
            with self.subTest(bad), mock.patch.object(XbtChannelClient, "http", staticmethod(http)):
                out = r.s.stream(ORIGIN, acc, {"manifest": m, "chunkUrl": bad}, budget=m["n"] * PRICE)
                self.assertFalse(out["stream"]["ok"])
                self.assertTrue(out["stream"]["refused"].startswith("chunkUrl: "), out)
        self.assertEqual(asked, [])
        self.assertEqual(r.book.get(ORIGIN).seq, 0, "no seq was spent on it")

    def test_x1_a_stored_open_url_off_the_origin_is_never_posted(self):
        tmp = Path(tempfile.mkdtemp())
        rpc = FakeRpc(height=1000)
        book = ChannelBook(tmp / "c.json", tmp / "k.json")
        p = fund_channel(book, rpc, API)
        with book._lock:                               # a pending record as a wallet from before AGP-080 wrote it
            rec = book._records[API]
            rec.state, rec.open_url, rec.min_conf = "pending", API + "@evil.example/open", 0
        rpc.utxos[(p.funding_txid, 0)]["confirmations"] = 1
        s = Xbt402Session(book, hot=None, rpc=rpc, height=lambda: 1000)
        asked = []
        with mock.patch.object(XbtChannelClient, "http", staticmethod(lambda *a, **k: asked.append(a) or (200, {}, b"{}"))):
            with self.assertRaises(ChannelError) as e:
                s.complete_open(API)
        self.assertEqual((e.exception.code, asked, book.get(API).state), ("seller_url", [], "pending"))


class _Redirector(http.server.BaseHTTPRequestHandler):
    target = ""

    def do_GET(self):  # noqa: N802 (http.server's name)
        self.send_response(302)
        self.send_header("Location", self.target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_a):
        pass


class _Catcher(http.server.BaseHTTPRequestHandler):
    hits: list = []

    def do_GET(self):  # noqa: N802
        self.hits.append(self.path)
        body = b"off the allowlist"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


class Redirects(unittest.TestCase):
    def serve(self, handler) -> int:
        port = free_port()
        srv = http.server.HTTPServer(("127.0.0.1", port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return port

    def test_x1_a_redirect_is_not_followed(self):
        """Real sockets: an allowlisted origin answers 302 to a host that is not on the allowlist."""
        hits: list = []
        other = self.serve(type("Catcher", (_Catcher,), {"hits": hits}))
        origin = f"http://127.0.0.1:{self.serve(type('Redir', (_Redirector,), {'target': f'http://127.0.0.1:{other}/steal'}))}"
        s = signer(Path(tempfile.mkdtemp()), allowlist=[origin])
        r = s.handle({"method": "xbt402_pay", "params": {"url": origin + "/v1/x", "max_sats": 0}})
        self.assertEqual(hits, [], "the wallet followed a redirect off the allowlist")
        self.assertEqual((r["verdict"], r["status"]), ("allow", 302), r)


class UnprovenClose(unittest.TestCase):
    """W3: 'closed' on the provider's word alone must not stop the refund watcher."""

    def rig(self, *, honest: bool):
        self.rpc = FakeRpc(height=1000, track_outputs=True)
        s = signer(Path(tempfile.mkdtemp()), self.rpc)
        r = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000, "expiry_blocks": 50}})
        self.assertEqual(r["state"], "open", r)
        rec = s.channels.get(API)
        self.closes = 0

        def http(method, url, body=b"", headers=None):
            self.assertEqual(url, API + "/x402/xbt-channel/close")
            self.closes += 1
            if honest:                                 # the close spends the funding on our own node
                self.rpc.utxos.pop((rec.funding_txid, 0))
                self.rpc.spenders[(rec.funding_txid, 0)] = "cc" * 32
                self.rpc.txs["cc" * 32] = {"txid": "cc" * 32, "hex": "", "vout": []}
            return 200, {}, json.dumps({"txid": "cc" * 32, "cum": 0, "unpaidMsat": 0}).encode()

        p = mock.patch.object(XbtChannelClient, "http", staticmethod(http))
        p.start()
        self.addCleanup(p.stop)
        return s, rec

    def test_w3_a_close_the_chain_never_saw_is_refunded_at_expiry(self):
        s, rec = self.rig(honest=False)
        r = s.handle({"method": "close_channel", "params": {"counterparty": API}})
        self.assertEqual(r["verdict"], "allow", r)
        got = s.channels.get(API)
        self.assertEqual((got.state, got.close_unproven), ("closed", True), "the provider said 200 and broadcast nothing")
        self.assertIs(r["close_proven"], False)
        # no second channel to that dest while the first one's coins are still in its funding output
        again = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000}})
        self.assertEqual((again["verdict"], again["rule"]), ("deny", "close_unproven"), again)
        self.assertEqual(s.channels.get(API).chan, rec.chan, "the unproven record was not archived")
        self.assertEqual(s.handle({"method": "watch_tick"})["actions"], [], "before expiry the watcher waits")
        early = s.handle({"method": "xbt402_refund", "params": {"counterparty": API}})
        self.assertEqual(early["rule"], "refund_early", early)
        self.rpc.height = rec.expiry
        acts = s.handle({"method": "watch_tick"})["actions"]
        refund = [a for a in acts if a.get("rule") == "refund"]
        self.assertEqual(len(refund), 1, acts)
        got = s.channels.get(API)
        self.assertEqual((got.state, got.close_unproven, got.closed_txid), ("refunded", False, ""))
        self.assertEqual(got.refund_txid, refund[0]["txid"])
        self.assertTrue(s.hot.holds(refund[0]["txid"], 0) if hasattr(s.hot, "holds") else True)
        # a book the Rust signer reads: the flag is written only while it is set
        raw = json.loads(s.channels.records_path.read_text())
        self.assertNotIn("close_unproven", raw["channels"][API])

    def test_w3_an_honest_close_is_proven_and_nothing_changes(self):
        s, rec = self.rig(honest=True)
        r = s.handle({"method": "close_channel", "params": {"counterparty": API}})
        got = s.channels.get(API)
        self.assertEqual((r["verdict"], got.state, got.close_unproven, got.closed_txid), ("allow", "closed", False, "cc" * 32))
        self.assertIs(r["close_proven"], True)
        self.assertNotIn("close_unproven", json.loads(s.channels.records_path.read_text())["channels"][API])
        self.rpc.height = rec.expiry
        acts = s.handle({"method": "watch_tick"})["actions"]
        self.assertEqual([a for a in acts if a.get("rule") == "refund"], [])
        again = s.handle({"method": "open_channel", "params": {"dest": API, "cap_sats": 50_000, "expiry_blocks": 50}})
        self.assertEqual((again["verdict"], again["state"]), ("allow", "open"), again)
        self.assertNotEqual(again["chan"], rec.chan)

    def test_w3_a_late_close_clears_the_flag(self):
        s, rec = self.rig(honest=False)
        s.handle({"method": "close_channel", "params": {"counterparty": API}})
        self.rpc.utxos.pop((rec.funding_txid, 0))      # the close reaches our node after all, under another txid
        self.rpc.spenders[(rec.funding_txid, 0)] = "dd" * 32
        self.rpc.txs["dd" * 32] = {"txid": "dd" * 32, "hex": "", "vout": []}
        acts = s.handle({"method": "watch_tick"})["actions"]
        self.assertEqual([a.get("close_proven") for a in acts if "close_proven" in a], ["dd" * 32])
        got = s.channels.get(API)
        self.assertEqual((got.state, got.close_unproven, got.closed_txid), ("closed", False, "dd" * 32))

    def test_w3_a_funded_channel_never_replaces_a_live_record(self):
        tmp = Path(tempfile.mkdtemp())
        rpc = FakeRpc()
        book = ChannelBook(tmp / "c.json", tmp / "k.json")
        first = fund_channel(book, rpc, API)
        with self.assertRaises(ChannelError) as e:
            fund_channel(book, rpc, API, secret=0xB0B0)
        self.assertEqual((e.exception.code, book.get(API).chan), ("channel_open", first.channel_id))


class Treasury(unittest.TestCase):
    def setUp(self):
        self.rpc = FakeRpc(height=1000, track_outputs=True)
        self.s = signer(Path(tempfile.mkdtemp()), self.rpc)
        self.exp = int(self.s.engine.clock()) + 600

    def test_w3_fund_treasury_needs_the_humans_signature(self):
        from agentwallet.approval import treasury_fund_message

        r = self.s.handle({"method": "fund_treasury", "params": {"sats": 100_000}})
        self.assertEqual(self.rpc.sent, [], f"hot funds moved with no signature: {r}")
        self.assertFalse(r.get("ok", False), r)
        msg = lambda sats: treasury_fund_message(self.s.hot.address, self.s.treasury.address, sats, self.exp)  # noqa: E731
        other = self.s.handle({"method": "fund_treasury", "params": {
            "sats": 100_000, "expiry": self.exp, "signature": b2x(sign(HUMAN_PRIV, msg(50_000)))}})
        self.assertEqual((other.get("ok", False), self.rpc.sent), (False, []), "the signature is for another amount")
        late = self.s.handle({"method": "fund_treasury", "params": {"sats": 100_000, "expiry": 1, "signature": b2x(
            sign(HUMAN_PRIV, treasury_fund_message(self.s.hot.address, self.s.treasury.address, 100_000, 1)))}})
        self.assertEqual((late.get("ok", False), self.rpc.sent), (False, []), "an expired signature")
        good = self.s.handle({"method": "fund_treasury", "params": {
            "sats": 100_000, "expiry": self.exp, "signature": b2x(sign(HUMAN_PRIV, msg(100_000)))}})
        self.assertEqual((len(self.rpc.sent), good.get("sighash")), (1, "0x21"), good)
        self.assertEqual(self.s.sigaudit.read()[-1]["rule"], "human:treasury_fund_signature")

    def test_w3_a_recover_treasury_signature_binds_the_destination(self):
        from agentwallet.approval import recover_message, treasury_recover_message
        from xbt402.tx import segwit_address

        mine = segwit_address(self.s.hrp, bytes.fromhex("0014" + "11" * 20))
        thief = segwit_address(self.s.hrp, bytes.fromhex("0014" + "22" * 20))
        txid, vout = self.s.hot.fund(self.s.treasury.spk, 50_000)
        self.s.treasury.record_funding(txid, vout, 50_000)
        sent = len(self.rpc.sent)
        addr = self.s.treasury.address
        sig = b2x(sign(HUMAN_PRIV, treasury_recover_message(addr, mine, self.exp)))
        r = self.s.handle({"method": "recover_treasury", "params": {"to": thief, "expiry": self.exp, "signature": sig}})
        self.assertEqual((r["ok"], len(self.rpc.sent)), (False, sent), "a signature for one address paid another")
        old = b2x(sign(HUMAN_PRIV, recover_message(addr, self.exp)))
        r = self.s.handle({"method": "recover_treasury", "params": {"to": thief, "expiry": self.exp, "signature": old}})
        self.assertEqual((r["ok"], len(self.rpc.sent)), (False, sent), "the old message named no destination")
        r = self.s.handle({"method": "recover_treasury", "params": {"to": mine, "expiry": self.exp, "signature": sig}})
        self.assertEqual((r["ok"], r["to"], len(self.rpc.sent)), (True, mine, sent + 1), r)


class ForwardRailEdges(unittest.TestCase):
    def test_s1_the_forward_rails_sighash_is_b1s(self):
        """B2's vendored fwd/tx.py: the same digests as B1 on B1's S1 vectors, and the same refusals."""
        from agentwallet.b1path import ensure_b1
        from agentwallet.fwd import tx as ftx

        rows = json.loads((Path(ensure_b1()) / "tests" / "data" / "unified_sighash_ext.json").read_text())
        self.assertEqual((rows[0][8], len(rows)), ("sighash", 61))
        for n, (raw, idx, ht, st, spent, leaf, annex, pos, want) in enumerate(rows[1:]):
            got = ftx.unified_sighash(ftx.Tx.parse(bytes.fromhex(raw)), [ftx.TxOut(v, bytes.fromhex(s)) for v, s in spent],
                                      idx, st, b"", ht, bytes.fromhex(leaf) if leaf else None,
                                      annex=bytes.fromhex(annex) if annex is not None else None, codesep_pos=pos)
            self.assertEqual(got.hex(), want, f"case {n}")
        raw, idx, ht, st, spent = rows[1][:5]
        tx, prev = ftx.Tx.parse(bytes.fromhex(raw)), [ftx.TxOut(v, bytes.fromhex(s)) for v, s in spent]
        with self.assertRaises(ValueError):
            ftx.unified_sighash(tx, prev, idx, ftx.ST_WITNESS_V0, b"\x51", 0x21, annex=bytes([0x50, 1]))
        with self.assertRaises(ValueError):
            ftx.unified_sighash(tx, prev, idx, ftx.ST_TAPROOT, b"", 0x21, codesep_pos=3)

    def test_m1_the_forward_rail_reads_coinbase_maturity_from_the_node(self):
        from test_forward_rail import PRICE, ForwardRail

        t = ForwardRail("test_lot_delivered_atomically_and_charged_once")
        t.make()
        self.addCleanup(t.doCleanups)
        # the node's rule is longer than the offer's 6480: the escape (6480 + 300) leaves the buyer no grace
        t.rpc.deployments = {"deployments": {"long_coinbase_maturity": {
            "coinbase_start_height": 0, "height": 0, "height_end": 4_000_000, "maturity": 6_700}}}
        r = t.buy(0)
        self.assertEqual((r["verdict"], r["rule"], r["reason"]), ("deny", "forward_offer", "thin_grace"), r)
        # a node that cannot say: refused, nothing signed
        t.rpc.deployments = None
        r = t.buy(1)
        self.assertEqual((r["verdict"], r["rule"], r["reason"]), ("deny", "forward_offer", "maturity_unknown"), r)
        self.assertEqual(t.s.sigaudit.read(), [])
        # the node's rule as the offer states it: bought
        t.rpc.deployments = {"deployments": {"long_coinbase_maturity": {
            "coinbase_start_height": 0, "height": 0, "height_end": 4_000_000, "maturity": 6_480}}}
        r = t.buy(2)
        self.assertEqual((r["verdict"], r["delivered"], r["charged_sats"]), ("allow", True, PRICE), r)
        self.assertEqual(r["deliver_height"], t.m.height + 2 + 6_480)


if __name__ == "__main__":
    unittest.main()
