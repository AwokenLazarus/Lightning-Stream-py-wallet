"""Shared fakes for the AGP-013 tests: a node that records broadcasts, and a funded channel."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from agentwallet.approval import b2x, generate_keypair, rotate_message, sign
from agentwallet.b1path import ensure_b1

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import ChannelParams  # noqa: E402
from xbt402.tx import Tx  # noqa: E402

NETWORK = "bip122:" + "11" * 16
PAY_TO = 0xB0B


class FakeRpc:
    """getblockcount / sendrawtransaction / gettxout / getrawtransaction, enough for the signer.

    AGP-095: it answers as a node does about what is in a block and what is only in its mempool (the
    third audit found the wallet took a mempool spend for a close, and this double could not show
    it). A transaction broadcast here is in the mempool at the height it was sent and in a block
    once the chain is higher (unless its txid is in `unmined`); one a test put into `txs` by hand is
    confirmed when its entry says `confirmations` >= 1, and a spender named in `spenders` with no
    entry at all counts as confirmed. So `gettxout(.., False)` still shows an output only a mempool
    transaction spends, `gettxspendingprevout` names mempool spenders only, and `getblock` (every
    height is the one block here) lists the confirmed transactions for a spender scan."""

    wallet = "agent"

    def __init__(self, height: int = 1000, *, track_outputs: bool = False):
        self.height = height
        self.track_outputs = track_outputs  # AGP-016: broadcast outputs become gettxout / scantxoutset coins
        self.sent: list[str] = []          # raw hex, in broadcast order
        self.utxos: dict[tuple, dict] = {}  # (txid, vout) -> gettxout result
        self.txs: dict[str, dict] = {}      # txid -> getrawtransaction verbose
        self.spenders: dict[tuple, str] = {}
        self.spent: dict[tuple, dict] = {}  # outpoint -> the gettxout answer it had before it was spent
        self.sent_at: dict[str, int] = {}   # txid -> the height it was broadcast at
        self.unmined: set[str] = set()      # broadcast transactions no block ever takes
        self.reject: str | None = None
        self.deployments: dict | None = None  # getdeploymentinfo; None: the node does not answer it

    def in_block(self, txid: str) -> bool:
        t = self.txs.get(txid)
        try:
            if t is not None and int(t.get("confirmations") or 0) >= 1:
                return True
        except (TypeError, ValueError):
            pass
        if txid in self.sent_at:
            return txid not in self.unmined and self.height > self.sent_at[txid]
        return t is None

    def call(self, method, *params):
        if method == "getblockcount":
            return self.height
        if method == "getblockhash":
            return "22" * 32
        if method == "getblock":
            txs = []
            for txid, t in self.txs.items():
                if not t.get("hex") or not self.in_block(txid):
                    continue
                try:
                    tx = Tx.parse(bytes.fromhex(t["hex"]))
                except Exception:
                    continue
                txs.append({"txid": txid, "hex": t["hex"],
                            "vin": [{"txid": i.txid[::-1].hex(), "vout": i.vout} for i in tx.inputs]})
            have = {t["txid"] for t in txs}
            by: dict[str, list] = {}       # a spender a test named without its transaction, once confirmed
            for (t, v), sp in self.spenders.items():
                if sp not in have and self.in_block(sp):
                    by.setdefault(sp, []).append({"txid": t, "vout": v})
            txs += [{"txid": sp, "vin": vin} for sp, vin in by.items()]
            return {"hash": params[0], "height": self.height, "tx": txs}
        if method == "sendrawtransaction":
            if self.reject:         # the node's own JSON-RPC refusal (AGP-085: only that forgets a funding)
                from agentwallet.rpc import KnotsRpcRefused
                raise KnotsRpcRefused(self.reject)
            raw = params[0]
            tx = Tx.parse(bytes.fromhex(raw))
            txid = tx.txid()
            for i in tx.inputs:
                op = (i.txid[::-1].hex(), i.vout)
                was = self.utxos.pop(op, None)
                if was is not None:
                    self.spent[op] = was
                self.spenders[op] = txid
            self.sent_at[txid] = self.height
            if self.track_outputs:
                for n, o in enumerate(tx.outputs):
                    self.utxos[(txid, n)] = {"value": o.value / 1e8, "scriptPubKey": {"hex": o.script_pubkey.hex()}}
            self.sent.append(raw)
            self.txs[txid] = {"txid": txid, "hex": raw, "vout": [
                {"n": n, "value": o.value / 1e8, "scriptPubKey": {"hex": o.script_pubkey.hex()}}
                for n, o in enumerate(tx.outputs)]}
            return txid
        if method == "gettxout":
            op = (params[0], int(params[1]))
            u = self.utxos.get(op)
            if u is None and len(params) > 2 and not params[2] and op in self.spent \
                    and not self.in_block(self.spenders.get(op, "")):
                return self.spent[op]          # without the mempool: its only spender is in no block
            return u
        if method == "getrawtransaction":
            t = self.txs.get(params[0])
            if t is None:
                from agentwallet.rpc import KnotsRpcError
                raise KnotsRpcError("No such mempool or blockchain transaction")
            return t if (len(params) > 1 and params[1]) else t["hex"]
        if method == "gettxspendingprevout":
            return [{"txid": o["txid"], "vout": o["vout"], **({"spendingtxid": self.spenders[(o["txid"], o["vout"])]}
                     if (o["txid"], o["vout"]) in self.spenders
                     and not self.in_block(self.spenders[(o["txid"], o["vout"])]) else {})} for o in params[0]]
        if method == "getblockchaininfo":
            return {"blocks": self.height, "initialblockdownload": False}
        if method == "scantxoutset":
            want = {d[4:-1] for d in params[1] if d.startswith("raw(")}
            return {"success": True, "unspents": [
                {"txid": t, "vout": v, "scriptPubKey": u["scriptPubKey"]["hex"], "amount": u["value"], "height": self.height}
                for (t, v), u in self.utxos.items() if u.get("scriptPubKey", {}).get("hex") in want]}
        if method == "getnewaddress":
            return "bcrt1qmine"
        if method == "generatetoaddress":
            self.height += int(params[0])
            return []
        if method == "getdeploymentinfo":
            if self.deployments is None:
                from agentwallet.rpc import KnotsRpcError
                raise KnotsRpcError("Method not found")
            return self.deployments
        if method == "estimatesmartfee":
            return {"feerate": 0.00001}
        if method == "getbalances":
            return {"mine": {"trusted": 0, "untrusted_pending": 0, "immature": 0}}
        raise AssertionError(f"FakeRpc: unexpected {method}{params}")


def keyfile_env() -> str:
    """Point the signer at a fresh wrapping-key file outside any run dir."""
    path = str(Path(tempfile.mkdtemp(prefix="b2-hotkey-")) / "hot.key")
    os.environ["B2_HOT_KEYFILE"] = path
    os.environ.pop("B2_HOT_PASSPHRASE", None)
    return path


def write_policy(root: Path, **over) -> dict:
    policy = {
        "allowlist": ["http://api.test", "http://market.test"],
        "max_per_tx_sats": 5_000_000, "daily_budget_sats": 20_000_000, "weekly_budget_sats": 50_000_000,
        "per_counterparty_cap_sats": 5_000_000, "velocity_max": 50, "velocity_window_s": 3600,
        "human_threshold_sats": 10_000_000, "split_window_s": 600, "approval_ttl_s": 900,
        "channel_expiry_blocks": 100, "recovery_address": "", "human_pubkey": "",
        "counterparties": {"http://api.test": {"pay_to": ecc.pubkey(PAY_TO).hex()}},
    }
    policy.update(over)
    (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    return policy


def fund_channel(book, rpc: FakeRpc, dest: str, *, secret: int = 0xA11CE, expiry: int = 1100,
                 capacity: int = 100_600, payer_spk: str = "", close_fee: int = 600, origin: str = ""):
    """A channel in `book` whose funding output is unspent on `rpc`. Returns its ChannelParams."""
    p = ChannelParams.derive(ecc.pubkey(PAY_TO).hex(), ecc.pubkey(secret).hex(), expiry, close_fee, payer_spk,
                             network=NETWORK)
    p.funding_txid, p.funding_vout, p.capacity = os.urandom(32).hex(), 0, capacity
    rpc.utxos[(p.funding_txid, 0)] = {"value": capacity / 1e8, "scriptPubKey": {"hex": p.spk.hex()}}
    rpc.txs[p.funding_txid] = {"txid": p.funding_txid, "hex": "", "confirmations": 1, "vout": []}
    book.add_funded(dest, secret=secret, params=p, origin=origin or dest, cap_sats=capacity - close_fee,
                    open_height=rpc.height)
    return p


HUMAN_PRIV, HUMAN_PUB = generate_keypair()


def rotate_hot_key(s) -> dict:
    """AGP-063 W3: the hot-key rotation, signed by the human key (`human_pubkey=b2x(HUMAN_PUB)`)."""
    exp = int(s.engine.clock()) + 600
    sig = sign(HUMAN_PRIV, rotate_message(s.hot.address, exp))
    return s.handle({"method": "rotate_hot_key", "params": {"expiry": exp, "signature": b2x(sig)}})

