"""A fake pruned node for the AGP-017 tests: blocks, confirmations, no txindex.

`getrawtransaction` finds a transaction only in the mempool, or in a block when given that block's
hash (as a pruned Knots node without txindex does). `gettxout` reports confirmations and the tip
hash; `gettxspendingprevout` only sees mempool spends; `getblock` (verbosity 2) lists a block's
transactions with their inputs. `mine(n)` confirms everything in the mempool.
"""

from __future__ import annotations

from agentwallet.b1path import ensure_b1

ensure_b1()
from xbt402.tx import Tx  # noqa: E402
from xbt402.x402_channel import network_id  # noqa: E402

MAIN_961640 = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb"


class RpcError(RuntimeError):
    pass


class PrunedChain:
    wallet = "agent"

    def __init__(self, chain: str = "regtest", height: int = 1000):
        self.chain, self.height = chain, height
        self.mempool: dict[str, dict] = {}         # txid -> verbose tx
        self.blocks: dict[int, list[dict]] = {}    # height -> verbose txs
        self.conf_height: dict[str, int] = {}
        self.utxos: dict[tuple, dict] = {}         # (txid, vout) -> {"value", "spk", "coinbase"}
        self.spent_by: dict[tuple, str] = {}
        self.sent: list[str] = []
        self.calls: list[str] = []
        self.reject: str | None = None
        self.mined_by_signer = 0
        self.coinbase: set[str] = set()
        self.deployments: dict | None = None       # getdeploymentinfo; None: the node does not answer it

    # --- helpers for tests ------------------------------------------------------------------------
    def bhash(self, h: int) -> str:
        if self.chain == "main" and h == 961640:
            return MAIN_961640
        return f"{h:064x}"

    def credit(self, txid: str, vout: int, sats: int, spk: str, *, confirmed: bool = True) -> None:
        """An outside coin (a faucet send) to `spk`."""
        tx = {"txid": txid, "hex": "", "vin": [{"txid": "ee" * 32, "vout": 0}],
              "vout": [{"n": n, "value": 0, "scriptPubKey": {"hex": ""}} for n in range(vout)]
              + [{"n": vout, "value": sats / 1e8, "scriptPubKey": {"hex": spk}}]}
        self.utxos[(txid, vout)] = {"value": sats, "spk": spk}
        if confirmed:
            self.blocks.setdefault(self.height, []).append(tx)
            self.conf_height[txid] = self.height
        else:
            self.mempool[txid] = tx

    def credit_coinbase(self, txid: str, vout: int, sats: int, spk: str) -> None:
        """A coinbase paying `sats` to `spk`, in a block at the current height."""
        tx = {"txid": txid, "hex": "", "vin": [{"coinbase": "03c80000", "sequence": 0xFFFF_FFFF}],
              "vout": [{"n": n, "value": 0, "scriptPubKey": {"hex": ""}} for n in range(vout)]
              + [{"n": vout, "value": sats / 1e8, "scriptPubKey": {"hex": spk}}]}
        self.utxos[(txid, vout)] = {"value": sats, "spk": spk}
        self.blocks.setdefault(self.height, []).append(tx)
        self.conf_height[txid] = self.height
        self.coinbase.add(txid)

    def mine(self, n: int = 1) -> None:
        for _ in range(n):
            self.height += 1
            txs = list(self.mempool.values())
            self.mempool.clear()
            self.blocks[self.height] = txs
            for t in txs:
                self.conf_height[t["txid"]] = self.height

    def network(self) -> str:
        return network_id(self.bhash(961640 if self.chain == "main" else 101))

    # --- RPC ---------------------------------------------------------------------------------------
    def call(self, method, *p):
        self.calls.append(method)
        if method == "getblockchaininfo":
            return {"chain": self.chain, "blocks": self.height, "initialblockdownload": False, "pruned": True}
        if method == "getblockcount":
            return self.height
        if method == "getblockhash":
            if int(p[0]) > self.height:
                raise RpcError("Block height out of range")
            return self.bhash(int(p[0]))
        if method == "getblockheader":
            return {"height": int(p[0], 16) if p[0] != MAIN_961640 else 961640}
        if method == "getblock":
            h = int(p[0], 16)
            return {"height": h, "tx": self.blocks.get(h, [])}
        if method == "sendrawtransaction":
            if self.reject:         # the node's own JSON-RPC refusal (AGP-085: only that forgets a funding)
                from agentwallet.rpc import KnotsRpcRefused
                raise KnotsRpcRefused(self.reject)
            raw = p[0]
            tx = Tx.parse(bytes.fromhex(raw))
            txid = tx.txid()
            if txid in self.mempool or txid in self.conf_height:
                raise RpcError("txn-already-known")
            for i in tx.inputs:
                op = (i.txid[::-1].hex(), i.vout)
                if op not in self.utxos:
                    raise RpcError("bad-txns-inputs-missingorspent")
            for i in tx.inputs:
                op = (i.txid[::-1].hex(), i.vout)
                self.utxos.pop(op)
                self.spent_by[op] = txid
            for n, o in enumerate(tx.outputs):
                self.utxos[(txid, n)] = {"value": o.value, "spk": o.script_pubkey.hex()}
            self.mempool[txid] = {"txid": txid, "hex": raw, "locktime": tx.locktime,
                                  "vin": [{"txid": i.txid[::-1].hex(), "vout": i.vout} for i in tx.inputs],
                                  "vout": [{"n": n, "value": o.value / 1e8, "scriptPubKey": {"hex": o.script_pubkey.hex()}}
                                           for n, o in enumerate(tx.outputs)]}
            self.sent.append(raw)
            return txid
        if method == "gettxout":
            txid, vout, mem = p[0], int(p[1]), (p[2] if len(p) > 2 else True)
            u = self.utxos.get((txid, vout))
            if u is None:
                return None
            if txid in self.mempool:
                if not mem:
                    return None
                confs = 0
            else:
                confs = self.height - self.conf_height.get(txid, self.height) + 1
            return {"bestblock": self.bhash(self.height), "confirmations": confs, "value": u["value"] / 1e8,
                    "scriptPubKey": {"hex": u["spk"]}, "coinbase": txid in self.coinbase}
        if method == "getrawtransaction":
            txid = p[0]
            if txid in self.mempool:
                return self.mempool[txid]
            if len(p) > 2 and p[2]:
                h = int(p[2], 16) if p[2] != MAIN_961640 else 961640
                for t in self.blocks.get(h, []):
                    if t["txid"] == txid:
                        return t
            raise RpcError("No such mempool transaction. Use -txindex or provide a block hash to enable "
                           "blockchain transaction queries.")
        if method == "gettxspendingprevout":
            out = []
            for o in p[0]:
                op = (o["txid"], int(o["vout"]))
                sp = self.spent_by.get(op)
                out.append({**o, **({"spendingtxid": sp} if sp in self.mempool else {})})
            return out
        if method == "scantxoutset":
            want = {d[4:-1] for d in p[1] if d.startswith("raw(")}
            return {"success": True, "unspents": [
                {"txid": t, "vout": v, "scriptPubKey": u["spk"], "amount": u["value"] / 1e8,
                 "coinbase": t in self.coinbase, "height": self.conf_height.get(t)}
                for (t, v), u in self.utxos.items() if u["spk"] in want and t not in self.mempool]}
        if method == "getdeploymentinfo":
            if self.deployments is None:
                raise RpcError("Method not found")
            return self.deployments
        if method == "getnewaddress":
            return "bcrt1qmine"
        if method == "generatetoaddress":
            if self.chain != "regtest":
                raise AssertionError("generatetoaddress off regtest")
            self.mined_by_signer += int(p[0])
            self.mine(int(p[0]))
            return []
        if method == "getbalances":
            return {"mine": {"trusted": 0, "untrusted_pending": 0, "immature": 0}}
        if method == "estimatesmartfee":
            return {"feerate": 0.00001}
        raise AssertionError(f"PrunedChain: unexpected {method}{p}")
