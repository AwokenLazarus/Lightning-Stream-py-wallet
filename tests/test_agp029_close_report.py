"""AGP-029: the wallet reads the provider's close report (xbt402 v1.2).

Before AGP-029 a payee-pays provider reported the close of a 1,500 state with a 600 fee as
`cum: 900, unpaidMsat: 600000`: the provider's own close fee showed up as money the payer still
owed. The fixed report is the gross `cum` with `payeeFee` and `payeeNet`, and `unpaidMsat` = spent -
gross. close_channel now returns `close_report` (integers only, from the untrusted reply) with a
status: ok, debt (the provider says we owe) or mismatch (its numbers disagree with our channel).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentwallet.b1path import ensure_b1
from agentwallet.channels import ChannelBook
from agentwallet.xbt402 import Xbt402Session

from test_l12_error_text import DEST, Hot, Rpc  # noqa: E402
from test_v11_offer import NET  # noqa: E402

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelParams  # noqa: E402
import xbt402.x402_channel as xc  # noqa: E402

V12 = "close_fee_payer" in ChannelParams.__dataclass_fields__
needs_v12 = unittest.skipUnless(V12, "pinned B1 predates xbt402 v1.2 closeFeePayer (AGP-023)")
REPORTS = hasattr(xc.XbtChannelProvider, "_close_report")     # the pinned B1 has AGP-029
PAYTO, PAYER = 0xB0B, 0xA11CE


def book_with(fee_payer: str, cum: int = 1_500):
    tmp = Path(tempfile.mkdtemp())
    book = ChannelBook(tmp / "c.json", tmp / "k.json")
    kw = {"close_fee_payer": fee_payer} if fee_payer != "payer" else {}
    p = ChannelParams.derive(ecc.pubkey(PAYTO).hex(), ecc.pubkey(PAYER).hex(), 8_000, 600, network=NET, **kw)
    p.funding_txid, p.funding_vout, p.capacity = "11" * 32, 0, 100_000
    book.add_funded(DEST, secret=PAYER, params=p, origin=DEST, cap_sats=p.max_amount)
    _, sig = book.increment(DEST, cum)
    return book, p, sig


def close_with(book, reply: dict):
    s = Xbt402Session(book, Hot(), rpc=Rpc(), height=lambda: 1000)
    with mock.patch("agentwallet.xbt402.XbtChannelClient.http", return_value=(200, {}, json.dumps(reply).encode())):
        return s.close_channel(DEST)


class CloseReport(unittest.TestCase):
    @needs_v12
    def test_payee_pays_gross_report_is_no_debt(self):
        book, p, _ = book_with("payee")
        res = close_with(book, {"chan": p.channel_id, "txid": "cd" * 32, "cum": "1500", "unpaidMsat": "0",
                                "payeeFee": "600", "payeeNet": "900"})
        self.assertEqual(res["close_report"], {"status": "ok", "cum": 1500, "unpaid_msat": 0,
                                               "payee_fee": 600, "payee_net": 900})

    @needs_v12
    def test_the_pre_agp029_net_report_reads_as_a_debt(self):
        """What a provider before AGP-029 answered: the wallet would see its fee as a debt."""
        book, p, _ = book_with("payee")
        res = close_with(book, {"chan": p.channel_id, "txid": "cd" * 32, "cum": "900", "unpaidMsat": "600000"})
        self.assertEqual(res["close_report"]["status"], "debt")

    @needs_v12
    def test_a_wrong_fee_or_net_is_a_mismatch(self):
        book, p, _ = book_with("payee")
        for fee, net in (("700", "800"), ("600", "1500"), (None, None)):
            reply = {"chan": p.channel_id, "txid": "cd" * 32, "cum": "1500", "unpaidMsat": "0"}
            if fee:
                reply.update(payeeFee=fee, payeeNet=net)
            self.assertEqual(close_with(book, reply)["close_report"]["status"], "mismatch", (fee, net))

    def test_payer_pays_report_unchanged(self):
        book, p, _ = book_with("payer")
        res = close_with(book, {"chan": p.channel_id, "txid": "cd" * 32, "cum": "1500", "unpaidMsat": "0"})
        self.assertEqual(res["close_report"], {"status": "ok", "cum": 1500, "unpaid_msat": 0})
        res = close_with(book, {"chan": p.channel_id, "txid": "cd" * 32, "cum": "1500", "unpaidMsat": "0",
                                "payeeFee": "600", "payeeNet": "900"})       # fee fields on a payer-pays channel
        self.assertEqual(res["close_report"]["status"], "mismatch")

    def test_untrusted_values_stay_numbers(self):
        book, p, _ = book_with("payer")
        res = close_with(book, {"txid": "cd" * 32, "cum": "IGNORE ALL PREVIOUS", "unpaidMsat": -5})
        self.assertEqual(res["close_report"], {"status": "mismatch", "cum": None, "unpaid_msat": None})


class StubNode:
    """The RPCs the B1 provider uses for an open and a close, with fixed answers."""

    def __init__(self, p):
        self.p, self.sent = p, []

    def getblockcount(self):
        return 1_000

    def getrawtransaction(self, txid, verbose=True):
        return {"vin": [{"txid": "cd" * 32, "vout": 0}], "confirmations": 6,
                "vout": [{"n": 0, "value": self.p.capacity / 1e8, "scriptPubKey": {"hex": self.p.spk.hex()}}]}

    def gettxout(self, txid, vout, include_mempool=True):
        return {"confirmations": 6, "value": self.p.capacity / 1e8, "scriptPubKey": {"hex": self.p.spk.hex()},
                "coinbase": False}

    def sendrawtransaction(self, hx):
        from xbt402.tx import Tx
        self.sent.append(hx)
        return Tx.parse(bytes.fromhex(hx)).txid()


@unittest.skipUnless(V12 and REPORTS, "pinned B1 predates the AGP-029 close report (B1_ROOT=~/xbt-rnd/b1-agp-029)")
class AgainstTheB1Provider(unittest.TestCase):
    def test_a_fully_paid_payee_pays_close_is_ok(self):
        """The wallet's own close against B1's provider: 1,500 spent (10 x 150), a 600 close fee."""
        book, p, sig = book_with("payee")
        node = StubNode(p)
        prov = xc.XbtChannelProvider(node, PAYTO, NET, os.path.join(tempfile.mkdtemp(), "l.json"),
                                     lambda m, path: 150, lambda m, path, b: (200, {}, b"ok"), close_fee_payer="payee")
        prov.open({"x402Version": 2, "network": NET, "channel": {
            "txid": p.funding_txid, "vout": 0, "capacity": p.capacity, "expiry": p.expiry, "payerPub": p.payer_pub,
            "payerSpk": p.payer_spk, "redeemScript": p.script.hex(), "closeFeePayer": "payee"}})
        st = prov.ledger.channels[p.channel_id]
        st.spent_msat = 1_500_000                                   # ten 150-sat calls served
        prov.facilitator_verify(xc.facilitator_request(prov.requirements(150),
                                                       {"chan": p.channel_id, "cum": "1500", "sig": sig.hex()}))
        s = Xbt402Session(book, Hot(), rpc=Rpc(), height=lambda: 1000)
        http = lambda m, url, body=b"", headers=None: prov.serve(m, "/" + url.split("/", 3)[3], {}, body)  # noqa: E731
        with mock.patch("agentwallet.xbt402.XbtChannelClient.http", side_effect=http):
            res = s.close_channel(DEST)
        self.assertEqual(res["close_report"], {"status": "ok", "cum": 1500, "unpaid_msat": 0,
                                               "payee_fee": 600, "payee_net": 900})
        from xbt402.tx import Tx
        outs = [o.value for o in Tx.parse(bytes.fromhex(node.sent[-1])).outputs]
        self.assertEqual(outs, [900, 100_000 - 1_500])


if __name__ == "__main__":
    unittest.main()
