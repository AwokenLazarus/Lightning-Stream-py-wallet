"""AGP-084: the on-chain `pay` rail is write-ahead.

K1  `pay` books the payment before it asks the node to send (AGP-077 list 1 item 12, B2 side). Only the
    node's own JSON-RPC refusal takes the row back; a call whose fate is unknown (no answer, a dropped
    connection, an answer that is not JSON-RPC) stays booked, and so does a crash between the two.

Same name as xbt-rs crates/xbt-signer/tests/agp080_closure.rs for K1.
"""

from __future__ import annotations

import http.server
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.rpc import KnotsRpc, KnotsRpcError, KnotsRpcRefused
from agentwallet.signer import Signer

from _agp013 import FakeRpc, keyfile_env, write_policy

ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
TXID = "5a" * 32


def ledger_sum(s: Signer) -> int:
    return sum(e.amount_sats for e in s.engine.store.payments())


class PayNode(FakeRpc):
    """A node whose `sendtoaddress` records what the ledger held when it was called, then gives
    `answer` (a txid, or an exception to raise)."""

    def __init__(self):
        super().__init__(height=1000)
        self.signer: Signer | None = None
        self.held: list[int] = []
        self.answer: object = TXID

    def call(self, method, *params):
        if method == "sendtoaddress":
            assert self.signer is not None
            self.held.append(ledger_sum(self.signer))
            if isinstance(self.answer, BaseException):
                raise self.answer
            return self.answer
        if method == "listunspent":
            return []
        return super().call(method, *params)


def signer(tmp: Path, node: FakeRpc, *, restart: bool = False) -> Signer:
    if not restart:                         # a restart keeps the wrapping key and the policy
        keyfile_env()
        write_policy(tmp, allowlist=[ADDR], split_window_s=0)
    s = Signer(tmp, rpc=node)
    if isinstance(node, PayNode):
        node.signer = s
    return s


def pay(s: Signer, sats: int, memo: str) -> dict:
    return s.handle({"method": "pay", "params": {"to": ADDR, "amount_sats": sats, "memo": memo}})


class OnchainPayWriteAhead(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="b2-agp084-"))
        self.node = PayNode()
        self.s = signer(self.tmp, self.node)

    def test_k1_the_onchain_pay_rail_books_before_it_sends(self):
        r = pay(self.s, 400, "m")
        self.assertEqual((r.get("verdict"), r.get("rail"), r.get("txid")), ("allow", "onchain", TXID), r)
        self.assertEqual(self.node.held, [400], "the payment was in the ledger when sendtoaddress was called")
        rows = self.s.engine.store.payments()
        self.assertEqual([(e.amount_sats, e.txid) for e in rows], [(400, TXID)], "booked once, under the txid")
        # the node refuses: the booking is taken back
        self.node.answer = KnotsRpcRefused('{"code":-6,"message":"Insufficient funds"}')
        with self.assertRaises(KnotsRpcRefused):
            pay(self.s, 300, "n")
        self.assertEqual(ledger_sum(self.s), 400, "a payment the node refused is not booked")
        # the node does not answer: the payment may have gone out, so it stays booked
        for i, unknown in enumerate((KnotsRpcError("RPC HTTP 503: work queue depth exceeded"), TimeoutError("timed out"),
                                     ConnectionResetError("reset by peer"), json.JSONDecodeError("bad", "", 0))):
            self.node.answer = unknown
            with self.assertRaises(KnotsRpcError) as cm:
                pay(self.s, 200, "o")
            self.assertNotIsInstance(cm.exception, KnotsRpcRefused)
            self.assertIn("stays in the ledger", str(cm.exception))
            self.assertEqual(ledger_sum(self.s), 600 + 200 * i, f"a payment whose fate is unknown stays booked ({unknown!r})")

    def test_k1_a_payment_whose_fate_is_unknown_is_still_counted_after_a_restart(self):
        self.node.answer = TimeoutError("timed out")
        with self.assertRaises(KnotsRpcError):
            pay(self.s, 700, "x")
        again = signer(self.tmp, PayNode(), restart=True)
        self.assertEqual(ledger_sum(again), 700)
        self.assertTrue(again.engine.store.payments()[0].txid.startswith("onchain:unconfirmed:"))

    def test_k1_a_crash_between_the_booking_and_the_send_leaves_the_payment_booked(self):
        class Crash(BaseException):
            """The process dies inside sendtoaddress: nothing after the call runs."""

        self.node.answer = Crash()
        with self.assertRaises(Crash):
            pay(self.s, 500, "x")
        again = signer(self.tmp, PayNode(), restart=True)
        self.assertEqual(ledger_sum(again), 500, "a signer started after the crash counts the payment")

    def test_k1_a_crash_after_the_send_counts_the_payment_at_least_once(self):
        """The row under the txid is written before the write-ahead row is dropped."""
        real = self.s.engine.store.amend
        seen = []

        def amend(txid, amount):
            seen.append(ledger_sum(self.s))
            return real(txid, amount)

        with mock.patch.object(self.s.engine.store, "amend", side_effect=amend):
            pay(self.s, 400, "m")
        self.assertEqual(seen, [800], "both rows were held when the write-ahead row was dropped")
        self.assertEqual(ledger_sum(self.s), 400)

    def test_k1_the_budget_counts_a_payment_of_unknown_fate(self):
        write_policy(self.tmp, allowlist=[ADDR], split_window_s=0, daily_budget_sats=1_000)
        node = PayNode()
        s = Signer(self.tmp, rpc=node)
        node.signer = s
        node.answer = TimeoutError("timed out")
        with self.assertRaises(KnotsRpcError):
            pay(s, 700, "x")
        node.answer = TXID
        r = pay(s, 700, "y")
        self.assertEqual(r.get("verdict"), "deny", r)
        self.assertEqual(len(node.held), 1, "the second payment never reached the node")


class _Node(http.server.BaseHTTPRequestHandler):
    reply: tuple[int, bytes] = (200, b"{}")

    def do_POST(self):  # noqa: N802 (http.server's name)
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        code, body = type(self).reply
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def free_port() -> int:
    """A loopback port below the ephemeral range (32768+), bound once to prove it is free."""
    for port in range(21980, 22400):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port in 21980-22399")


class RpcRefusal(unittest.TestCase):
    """KnotsRpc tells the node's own refusal (a JSON-RPC error) from every other failure."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="b2-agp084-rpc-"))
        (self.tmp / ".cookie").write_text("u:p", encoding="utf-8")
        self.port = free_port()
        self.srv = http.server.HTTPServer(("127.0.0.1", self.port), _Node)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.rpc = KnotsRpc(self.tmp, self.tmp / "none.conf")

    def call(self, code: int, body: bytes):
        _Node.reply = (code, body)
        with mock.patch.dict("os.environ", {"B2_RPCPORT": str(self.port)}):
            return self.rpc.call("sendtoaddress", ADDR, "0.00000400")

    def test_k1_a_json_rpc_error_is_the_nodes_refusal(self):
        err = json.dumps({"result": None, "error": {"code": -6, "message": "Insufficient funds"}, "id": "b2"}).encode()
        for code in (500, 404, 200):         # bitcoind sends a JSON-RPC error with HTTP 500 (404 for an unknown method)
            with self.assertRaises(KnotsRpcRefused) as cm:
                self.call(code, err)
            self.assertIn("Insufficient funds", str(cm.exception))

    def test_k1_any_other_failure_is_not_a_refusal(self):
        for code, body in ((503, b"Work queue depth exceeded"), (500, b"<html>oops</html>"), (200, b"not json"),
                           (500, b'{"result": null, "error": null}'), (200, b"[1]")):
            with self.assertRaises(KnotsRpcError) as cm:
                self.call(code, body)
            self.assertNotIsInstance(cm.exception, KnotsRpcRefused, (code, body))
        self.srv.shutdown()
        self.srv.server_close()
        with self.assertRaises(KnotsRpcError) as cm:        # nothing listening
            self.call(200, b"")
        self.assertNotIsInstance(cm.exception, KnotsRpcRefused)

    def test_k1_a_result_is_returned(self):
        self.assertEqual(self.call(200, json.dumps({"result": TXID, "error": None}).encode()), TXID)


if __name__ == "__main__":
    unittest.main()
