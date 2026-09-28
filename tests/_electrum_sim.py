"""AGP-024 test chain and Electrum server.

`SimChain` is the AGP-017 fake pruned node (`PrunedChain`, so a B1 provider can use it as its node)
with a real chain under it: v2 BLAKE2b headers mined at the regtest target from block 101 (the
checkpoint) on, real transactions (txid = hash of the raw bytes) and real Merkle roots and
transaction counts in the headers.

`FakeElectrum` serves a SimChain over TCP with the Electrum methods electrs serves, notifications
included, plus knobs for a malicious server: hide transactions, forge Merkle proofs, claim wrong
heights, substitute a different transaction, invent a mempool spend, or serve another header chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import socketserver
import struct
import threading

from _agp017 import PrunedChain

from agentwallet.headers import merkle_branch, merkle_root, parse_header
from xbt402.tx import Tx, TxIn, TxOut

REGTEST_BITS = 0x207FFFFF
CHECKPOINT = 101
T0 = 1_780_000_000


def sh_of(spk_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(spk_hex)).digest()[::-1].hex()


def mine_header(prev_hash: str, merkle: bytes, height: int, txcount: int, t: int, bits: int = REGTEST_BITS,
                *, nonce0: int = 0) -> bytes:
    """A v2 header meeting its target (profile 0, no xor key, no time offset)."""
    target = (bits & 0x7FFFFF) << 8 * ((bits >> 24) - 3)
    nonce = nonce0
    while True:
        raw = (struct.pack("<I", 0x2000_0000 | 0x8000_0000) + bytes.fromhex(prev_hash)[::-1] + merkle
               + struct.pack("<IIIII", t, bits, nonce, 0, 0) + bytes(16) + struct.pack("<I", 0)
               + struct.pack("<H", txcount) + bytes([0, 0]) + bytes(16) + struct.pack("<I", height) + bytes(32))
        if int(parse_header(raw).hash, 16) <= target:
            return raw
        nonce += 1


def coinbase(height: int, salt: bytes = b"") -> Tx:
    return Tx(version=2, inputs=[TxIn(bytes(32), 0xFFFF_FFFF, 0xFFFF_FFFF, struct.pack("<I", height) + salt)],
              outputs=[TxOut(312_500_000, bytes.fromhex("0014" + "11" * 20))], locktime=0)


class SimChain(PrunedChain):
    """PrunedChain with mined v2 headers, raw transactions and Merkle roots."""

    def __init__(self, chain: str = "regtest", height: int = 1000, *, salt: bytes = b""):
        super().__init__(chain=chain, height=CHECKPOINT - 1)
        self.salt = salt
        self.raw: dict[str, str] = {}               # txid -> hex, every tx the chain has seen
        self.block_txids: dict[int, list[str]] = {}
        self.hdr: dict[int, bytes] = {}
        self.hash_at: dict[int, str] = {}
        self.listeners: list = []
        self._mine_one(prev="ab" * 32, txs=[])      # block 101: the checkpoint
        self.mine(height - CHECKPOINT)

    # --- the chain -----------------------------------------------------------------------------------
    def bhash(self, h: int) -> str:
        return self.hash_at.get(h) or f"{h:064x}"

    def _mine_one(self, prev: str, txs: list[dict]) -> None:
        self.height += 1
        h = self.height
        cb = coinbase(h, self.salt)
        self.raw[cb.txid()] = cb.hex()
        txids = [cb.txid()] + [t["txid"] for t in txs]
        raw = mine_header(prev, merkle_root(txids), h, len(txids), T0 + 60 * h)
        self.hdr[h], self.hash_at[h] = raw, parse_header(raw).hash
        self.block_txids[h] = txids
        self.blocks[h] = txs
        for t in txs:
            self.conf_height[t["txid"]] = h

    def mine(self, n: int = 1) -> None:
        for _ in range(n):
            txs = list(self.mempool.values())
            self.mempool.clear()
            self._mine_one(self.hash_at[self.height], txs)
        self._notify()

    def _notify(self) -> None:
        for fn in list(self.listeners):
            fn()

    def credit(self, txid: str, vout: int, sats: int, spk: str, *, confirmed: bool = True) -> str:
        """A faucet payment of `sats` to `spk` at output `vout`. Returns its real txid (the argument is ignored)."""
        outs = [TxOut(546, bytes.fromhex("0014" + "22" * 20)) for _ in range(vout)] + [TxOut(sats, bytes.fromhex(spk))]
        tx = Tx(version=2, inputs=[TxIn(os.urandom(32), 0)], outputs=outs, locktime=0)
        raw = tx.hex()
        txid = tx.txid()
        self.raw[txid] = raw
        self.utxos[(txid, vout)] = {"value": sats, "spk": spk}
        self.mempool[txid] = self._verbose(tx)
        if confirmed:
            self.mine(1)
        else:
            self._notify()
        return txid

    @staticmethod
    def _verbose(tx: Tx) -> dict:
        return {"txid": tx.txid(), "hex": tx.hex(), "locktime": tx.locktime,
                "vin": [{"txid": i.txid[::-1].hex(), "vout": i.vout} for i in tx.inputs],
                "vout": [{"n": n, "value": o.value / 1e8, "scriptPubKey": {"hex": o.script_pubkey.hex()}}
                         for n, o in enumerate(tx.outputs)]}

    def call(self, method, *p):
        if method == "sendrawtransaction":
            txid = super().call(method, *p)
            self.raw[txid] = p[0]
            self._notify()
            return txid
        if method in ("getblockheader", "getblock"):
            h = next((k for k, v in self.hash_at.items() if v == p[0]), None)
            if h is None:
                raise AssertionError(f"SimChain: unknown block {p[0]}")
            return {"height": h} if method == "getblockheader" else {"height": h, "tx": self.blocks.get(h, [])}
        return super().call(method, *p)

    # --- what an Electrum server reads -------------------------------------------------------------------
    def all_txs(self):
        """(txid, height or 0) for every confirmed and mempool transaction, coinbases included."""
        for h in sorted(self.block_txids):
            for t in self.block_txids[h]:
                yield t, h
        for t in self.mempool:
            yield t, 0

    def history(self, sh: str) -> list[dict]:
        out = []
        for txid, h in self.all_txs():
            tx = Tx.parse(bytes.fromhex(self.raw[txid]))
            spks = [o.script_pubkey.hex() for o in tx.outputs]
            for i in tx.inputs:
                prev = self.raw.get(i.txid[::-1].hex())
                if prev:
                    spks.append(Tx.parse(bytes.fromhex(prev)).outputs[i.vout].script_pubkey.hex())
            if any(sh_of(s) == sh for s in spks):
                out.append({"tx_hash": txid, "height": h})
        return out

    def listunspent(self, sh: str) -> list[dict]:
        spent_in_mempool = {(i["txid"], i["vout"]) for t in self.mempool.values() for i in t["vin"]}
        return [{"tx_hash": t, "tx_pos": v, "height": 0 if t in self.mempool else self.conf_height.get(t, 0),
                 "value": u["value"]}
                for (t, v), u in self.utxos.items() if sh_of(u["spk"]) == sh and (t, v) not in spent_in_mempool]


class FakeElectrum:
    """An Electrum server over a SimChain (electrs' method set), with knobs for lying."""

    def __init__(self, sim: SimChain):
        self.sim = sim
        self.hide: set[str] = set()              # txids left out of everything
        self.forge_merkle = False
        self.claim_height: dict[str, int] = {}   # txid -> the height get_history claims
        self.substitute: dict[str, str] = {}     # txid -> another tx's hex, served for it
        self.extra_history: dict[str, list] = {}  # scripthash -> extra entries
        self.extra_raw: dict[str, str] = {}      # txid -> hex for invented transactions
        self.headers: dict[int, bytes] | None = None   # another header chain
        self.down = False
        self.calls: list[str] = []
        self._clients: list = []
        self._subs: dict = {}
        sim.listeners.append(self._changed)
        fake = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                fake._clients.append(self)
                self.lock = threading.Lock()
                self.subs: dict[str, str] = {}
                self.tip_sub = False
                try:
                    for line in self.rfile:
                        if fake.down:
                            return
                        req = json.loads(line)
                        try:
                            res = {"id": req["id"], "result": fake.answer(self, req["method"], req.get("params") or [])}
                        except Exception as e:
                            res = {"id": req["id"], "error": {"code": 1, "message": str(e)}}
                        self.send(res)
                finally:
                    if self in fake._clients:
                        fake._clients.remove(self)

            def send(self, msg):
                with self.lock:
                    try:
                        self.wfile.write((json.dumps(msg) + "\n").encode())
                        self.wfile.flush()
                    except OSError:
                        pass

        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = f"tcp://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        for c in list(self._clients):
            try:
                c.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    # --- the chain as this server shows it ----------------------------------------------------------------
    def _hdrs(self) -> dict[int, bytes]:
        return self.headers if self.headers is not None else self.sim.hdr

    def _tip(self) -> int:
        return max(self._hdrs())

    def _status(self, sh: str):
        hist = self._history(sh)
        if not hist:
            return None
        return hashlib.sha256("".join(f"{e['tx_hash']}:{e['height']}:" for e in hist).encode()).hexdigest()

    def _history(self, sh: str) -> list[dict]:
        out = [dict(e) for e in self.sim.history(sh) if e["tx_hash"] not in self.hide]
        for e in out:
            if e["tx_hash"] in self.claim_height:
                e["height"] = self.claim_height[e["tx_hash"]]
        return out + list(self.extra_history.get(sh, []))

    def _changed(self) -> None:
        for c in list(self._clients):
            if c.tip_sub:
                c.send({"jsonrpc": "2.0", "method": "blockchain.headers.subscribe",
                        "params": [{"hex": self._hdrs()[self._tip()].hex(), "height": self._tip()}]})
            for sh, old in list(c.subs.items()):
                new = self._status(sh)
                if new != old:
                    c.subs[sh] = new
                    c.send({"jsonrpc": "2.0", "method": "blockchain.scripthash.subscribe", "params": [sh, new]})

    def answer(self, client, method: str, p: list):
        self.calls.append(method)
        sim = self.sim
        if method == "server.version":
            return ["fake-electrs/0.11.1", "1.8"]
        if method == "blockchain.headers.subscribe":
            client.tip_sub = True
            return {"hex": self._hdrs()[self._tip()].hex(), "height": self._tip()}
        if method == "blockchain.block.header":
            return self._hdrs()[int(p[0])].hex()
        if method == "blockchain.block.headers":
            start, count = int(p[0]), min(int(p[1]), 2016)
            hs = [self._hdrs()[h].hex() for h in range(start, start + count) if h in self._hdrs()]
            return {"count": len(hs), "hex": "".join(hs), "max": 2016}
        if method == "blockchain.transaction.get":
            txid = p[0]
            if txid in self.hide:
                raise ValueError("No such mempool or blockchain transaction")
            if txid in self.substitute:
                return self.substitute[txid]
            raw = sim.raw.get(txid) or self.extra_raw.get(txid)
            if raw is None:
                raise ValueError("No such mempool or blockchain transaction")
            return raw
        if method == "blockchain.transaction.get_merkle":
            txid, height = p[0], int(p[1])
            txids = sim.block_txids.get(height) or []
            if txid not in txids:
                if not self.forge_merkle:
                    raise ValueError(f"tx {txid} not in block at height {height}")
                return {"block_height": height, "merkle": ["00" * 32] * 2, "pos": 1}
            pos = txids.index(txid)
            branch = merkle_branch(txids, pos)
            if self.forge_merkle:
                branch = ["00" * 32] + branch[1:] if branch else ["00" * 32]
            return {"block_height": height, "merkle": branch, "pos": pos}
        if method == "blockchain.scripthash.get_history":
            return self._history(p[0])
        if method == "blockchain.scripthash.listunspent":
            return [u for u in sim.listunspent(p[0]) if u["tx_hash"] not in self.hide]
        if method == "blockchain.scripthash.subscribe":
            client.subs[p[0]] = self._status(p[0])
            return client.subs[p[0]]
        if method == "blockchain.transaction.broadcast":
            return sim.call("sendrawtransaction", p[0])
        if method == "blockchain.estimatefee":
            return 0.00001
        raise ValueError(f"unknown method {method}")
