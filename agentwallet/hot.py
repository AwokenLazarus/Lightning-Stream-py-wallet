"""Signer-owned secp256k1 hot key. Channel fundings are signed ALL|UNIFIED (0x21).

The Knots wallet will not sign 0x21 on regtest ("fork is not scheduled"), so the
signer spends its own P2WPKH coins with the B1 sighash. Coinbases never fund a
channel: the demo first moves mature coinbase → hot with sendtoaddress, then
this module builds the 0x21 funding.

AGP-013 custody:
  * the key is sealed at rest by a `KeyStore` (keystore.py); `hot.json` holds only ciphertext + pub;
  * `rotate()` makes a new key and sweeps the old key's coins into it in one 0x21 transaction; the
    old key stays sealed as "retired" so change and refunds that still pay its address can be swept;
  * `cap_sats` caps the balance: above it `check_channel_funding` refuses new channels and the
    wallet asks for a human sweep (`sweep_to`, gated by an ed25519 signature in the signer);
  * every signature is recorded in the signature audit log (sigaudit.py).

AGP-016: the UTXO set persists in `hot_utxos.json`, sealed like the key (AES-256-GCM under the same
wrapping key, so it is integrity-protected too), rewritten on every change. `reconcile()` (the signer
runs it at start) checks every stored coin against the node with gettxout: a coin the node no longer
has becomes "stale" (kept, rechecked, not spent or counted), a coin whose script or value disagrees is
dropped, and `scantxoutset` over every key, current and retired, adds confirmed coins the file never
heard of (a close's change or a refund that landed while the signer was down).

AGP-069 M1: a coin records whether it is a coinbase output and its block ("coinbase", "height", from
scantxoutset, gettxout's confirmations at its bestblock, or the transaction's vin[0]). A coinbase coin
is spent only once the node's coinbase maturity (getdeploymentinfo, maturity.py) allows; when the node
cannot say (the light backend has no getdeploymentinfo), it waits.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from .b1path import ensure_b1
from .keystore import KeyStore, KeyStoreError, write_private
from .maturity import Maturity
from .rpc import BroadcastUnknown, KnotsRpc, KnotsRpcError, KnotsRpcRefused
from .sigaudit import NullAudit

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.tx import (  # noqa: E402
    SIGHASH_ALL_UNIFIED,
    ST_WITNESS_V0,
    Tx,
    TxIn,
    TxOut,
    p2wpkh_script_code,
    p2wpkh_spk,
    segwit_address,
    unified_sighash,
)

XBT_SATS = 100_000_000
DEFAULT_FEE = 600
SWEEP_FEE_BASE, SWEEP_FEE_PER_INPUT = 200, 100
DUST = 546
AAD = "b2/hot-key"
UTXO_AAD = "b2/hot-utxos"
MAX_STALE = 500
CLOSE_MAX_OUTPUTS = 4        # a close has 1-3 outputs (payee, our change, a hash lock)
CLOSE_SCAN_MAX = 144         # blocks one learn_close_change call reads; the next call goes on from there


def _short(e: BaseException) -> str:
    return (str(e) or type(e).__name__)[:160]


def _coinbase_fields(height: int | None) -> dict:
    return {"coinbase": True, **({"height": int(height)} if isinstance(height, int) else {})}


def _scanned(c: dict) -> dict:
    """The coinbase flag and block of one scantxoutset unspent."""
    return _coinbase_fields(c.get("height")) if c.get("coinbase") else {}


class HotCapError(RuntimeError):
    def __init__(self, balance: int, cap: int):
        super().__init__(f"hot key holds {balance} sats, above its {cap} sat cap: a human must sweep it "
                         f"(agentwallet-approve sweep) before new channels are funded")
        self.balance, self.cap = balance, cap


class _Key:
    __slots__ = ("secret", "pub", "spk", "address", "retired_at")

    def __init__(self, secret: int, hrp: str, retired_at: float = 0.0):
        self.secret = secret
        self.pub = ecc.pubkey(secret)
        self.spk = p2wpkh_spk(self.pub)
        self.address = segwit_address(hrp, self.spk)
        self.retired_at = retired_at


class HotWallet:
    def __init__(self, path: Path, rpc: KnotsRpc, hrp: str = "bcrt", *, keystore: KeyStore | None = None,
                 audit=None, cap_sats: int = 0):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rpc = rpc
        self.hrp = hrp
        self.keystore = keystore
        self.audit = audit or NullAudit()
        self.cap_sats = int(cap_sats or 0)
        self._current, self._retired = self._load_or_create()
        self.utxo_path = self.path.with_name(self.path.stem + "_utxos.json")
        self._utxo_salt = secrets.token_bytes(16)
        self._utxos: list[dict] = []
        self._stale: list[dict] = []
        self.last_reconcile: dict = {}
        self._load_utxos()

    # --- the current key (older callers use these attributes) ------------------------------------
    @property
    def secret(self) -> int:
        return self._current.secret

    @property
    def pub(self) -> bytes:
        return self._current.pub

    @property
    def spk(self) -> bytes:
        return self._current.spk

    @property
    def address(self) -> str:
        return self._current.address

    @property
    def encrypted(self) -> bool:
        return self.keystore is not None

    # --- storage -----------------------------------------------------------------------------------
    def _seal(self, k: _Key) -> dict:
        d = {"pub": k.pub.hex()}
        if k.retired_at:
            d["retired_at"] = k.retired_at
        if self.keystore is None:
            d["secret"] = f"{k.secret:064x}"
        else:
            d["sealed"] = self.keystore.seal(k.secret.to_bytes(32, "big"), AAD)
        return d

    def _unseal(self, d: dict) -> _Key:
        if "sealed" in d:
            if self.keystore is None:
                raise KeyStoreError("hot key is encrypted: set B2_HOT_KEYFILE or B2_HOT_PASSPHRASE")
            secret = int.from_bytes(self.keystore.open(d["sealed"], AAD), "big")
        else:
            secret = int(d["secret"], 16)
        k = _Key(secret, self.hrp, float(d.get("retired_at") or 0.0))
        if d.get("pub") and d["pub"] != k.pub.hex():
            raise KeyStoreError("hot key file: the key does not match its recorded pub")
        return k

    def _persist(self) -> None:
        doc = {"v": 2, "encrypted": self.encrypted, "current": self._seal(self._current),
               "retired": [self._seal(k) for k in self._retired]}
        write_private(self.path, json.dumps(doc, indent=2))

    def _load_or_create(self) -> tuple[_Key, list[_Key]]:
        if not self.path.exists():
            self._current, self._retired = _Key(secrets.randbelow(ecc.N - 1) + 1, self.hrp), []
            self._persist()
            return self._current, self._retired
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if "current" in raw:
            cur, ret = self._unseal(raw["current"]), [self._unseal(d) for d in raw.get("retired") or []]
            plain = any("secret" in d for d in [raw["current"], *(raw.get("retired") or [])])
        else:  # wave-2 format: {"secret", "pub"} in the clear
            cur, ret, plain = self._unseal(raw), [], True
        self._current, self._retired = cur, ret
        if plain and self.keystore is not None:
            self._persist()  # first start with a wrapping key: re-seal the plaintext file
        return cur, ret

    def _load_utxos(self) -> None:
        if not self.utxo_path.exists():
            return
        raw = json.loads(self.utxo_path.read_text(encoding="utf-8"))
        if "sealed" in raw:
            if self.keystore is None:
                raise KeyStoreError("hot UTXO set is encrypted: set B2_HOT_KEYFILE or B2_HOT_PASSPHRASE")
            try:
                doc = json.loads(self.keystore.open(raw["sealed"], UTXO_AAD))
            except KeyStoreError as e:
                raise KeyStoreError(f"{self.utxo_path.name}: {e}. Move it aside to rebuild the set from the node "
                                    "(scantxoutset at the next start)") from e
        else:
            doc = raw
        self._utxos = [self._coin(u) for u in doc.get("utxos") or []]
        self._stale = [self._coin(u) for u in doc.get("stale") or []]
        if self.keystore is not None and "sealed" not in raw:
            self._persist_utxos()  # first start with a wrapping key: re-seal the plaintext set

    @staticmethod
    def _coin(u: dict) -> dict:
        c = {"txid": str(u["txid"]), "vout": int(u["vout"]), "value": int(u["value"]), "spk": str(u.get("spk") or "")}
        if u.get("why"):
            c["why"] = str(u["why"])
        if u.get("coinbase"):
            h = u.get("height")
            c |= _coinbase_fields(h if isinstance(h, int) and not isinstance(h, bool) and 0 <= h < 1 << 32 else None)
        return c

    def _persist_utxos(self) -> None:
        doc = {"v": 1, "utxos": self._utxos, "stale": self._stale[-MAX_STALE:]}
        if self.keystore is not None:
            doc = {"v": 1, "encrypted": True,
                   "sealed": self.keystore.seal(json.dumps(doc).encode(), UTXO_AAD, salt=self._utxo_salt)}
        write_private(self.utxo_path, json.dumps(doc, indent=1))

    def reconcile(self, *, scan: bool = True) -> dict:
        """Check the stored coins against the node; with `scan`, also find coins the file lacks."""
        out = {"ok": False, "kept": 0, "stale": 0, "restored": 0, "dropped": 0, "found": 0, "scanned": False}
        try:
            info = self.rpc.call("getblockchaininfo")
            if info.get("initialblockdownload"):
                out["reason"] = "node is in initial block download: stored coins kept unverified"
                self.last_reconcile = out
                return out
        except Exception as e:
            out["reason"] = f"node unreachable: {str(e)[:160]}; stored coins kept unverified"
            self.last_reconcile = out
            return out
        keep, stale = [], []
        for u, was_stale in [(u, False) for u in self._utxos] + [(u, True) for u in self._stale]:
            try:
                r = self.rpc.call("gettxout", u["txid"], int(u["vout"]), True)
            except Exception as e:
                out["reason"] = f"gettxout failed: {str(e)[:160]}; stored coins kept unverified"
                self.last_reconcile = out
                return out
            if not r:
                stale.append({**u, "why": "not unspent on the node"})
                out["stale"] += 1
                continue
            spk = (r.get("scriptPubKey") or {}).get("hex", "")
            value = int(round(float(r.get("value", 0)) * XBT_SATS))
            if (u.get("spk") and spk and spk != u["spk"]) or value != int(u["value"]) or self._key_for_spk(spk or u["spk"]) is None:
                out["dropped"] += 1   # the node disagrees with the file: the node wins
                continue
            c = {k: v for k, v in u.items() if k not in ("why", "coinbase", "height")} | {"spk": spk or u["spk"]}
            if r.get("coinbase"):
                h = u.get("height") if u.get("coinbase") else None
                c |= _coinbase_fields(h if h is not None else self._txout_height(r))
            keep.append(c)
            out["restored" if was_stale else "kept"] += 1
        if scan:
            try:
                res = self.rpc.call("scantxoutset", "start", [f"raw({k.spk.hex()})" for k in self._keys()])
                have = {(u["txid"], int(u["vout"])) for u in keep}
                for c in (res or {}).get("unspents") or []:
                    op = (c["txid"], int(c["vout"]))
                    if op in have or self._key_for_spk(c.get("scriptPubKey", "")) is None:
                        continue
                    keep.append({"txid": c["txid"], "vout": int(c["vout"]),
                                 "value": int(round(float(c["amount"]) * XBT_SATS)), "spk": c["scriptPubKey"]} | _scanned(c))
                    stale = [x for x in stale if (x["txid"], int(x["vout"])) != op]
                    have.add(op)
                    out["found"] += 1
                out["scanned"] = bool(res and res.get("success", True))
            except Exception as e:
                out["scan_error"] = str(e)[:160]
        self._utxos, self._stale = keep, stale[-MAX_STALE:]
        self._persist_utxos()
        out["ok"] = True
        out["hot_sats"] = self.balance_sats()
        self.last_reconcile = out
        return out

    # --- coins -------------------------------------------------------------------------------------
    def _keys(self) -> list[_Key]:
        return [self._current, *self._retired]

    def _key_for_spk(self, spk_hex: str) -> _Key | None:
        return next((k for k in self._keys() if k.spk.hex() == spk_hex), None)

    def notice_utxo(self, txid: str, vout: int, value_sats: int, spk: str = "", *, extra: dict | None = None) -> None:
        spk = spk or self.spk.hex()
        if not any(u["txid"] == txid and u["vout"] == vout for u in self._utxos):
            self._utxos.append({"txid": txid, "vout": int(vout), "value": int(value_sats), "spk": spk} | (extra or {}))
            self._stale = [u for u in self._stale if (u["txid"], int(u["vout"])) != (txid, int(vout))]
            self._persist_utxos()

    def _txout_height(self, r: dict) -> int | None:
        """A coinbase output's block from a gettxout answer: its confirmations counted back from the
        bestblock they were counted at."""
        try:
            conf = int(r.get("confirmations") or 0)
            if conf <= 0 or not r.get("bestblock"):
                return None
            return int(self.rpc.call("getblockheader", r["bestblock"], True)["height"]) - conf + 1
        except Exception:
            return None

    def _tx_height(self, raw: dict, looked_in: str) -> int | None:
        """The block of a confirmed transaction from its verbose form (height, else its blockhash, else
        the block it was looked up in)."""
        if isinstance(raw.get("height"), int):
            return raw["height"]
        bh = raw.get("blockhash") or looked_in
        if not bh:
            return None
        try:
            return int(self.rpc.call("getblockheader", bh, True)["height"])
        except Exception:
            return None

    def scan_from_txid(self, txid: str, *, unspent_only: bool = False, blockhash: str = "") -> int:
        """Notice this tx's outputs to any hot key. `unspent_only` (AGP-016, for closes found after the
        fact) skips outputs the node says are already spent, so a swept coin is never counted twice.

        AGP-017 P6: without txindex (a pruned node) a confirmed tx is found only with its block hash;
        without one, the UTXO set is scanned for this tx's unspent outputs to our keys."""
        from .netparams import get_tx
        raw = get_tx(self.rpc, txid, blockhash)
        if raw is None:
            return self._scan_utxoset_for(txid)
        vin = raw.get("vin") or []
        cb = _coinbase_fields(self._tx_height(raw, blockhash)) if vin and "coinbase" in vin[0] else {}
        added = 0
        for o in raw.get("vout") or []:
            spk = (o.get("scriptPubKey") or {})
            k = self._key_for_spk(spk.get("hex", "")) or next(
                (k for k in self._keys() if spk.get("address") == k.address), None)
            if k is not None and unspent_only and not self.rpc.call("gettxout", txid, int(o["n"]), True):
                continue
            if k is not None:
                self.notice_utxo(txid, int(o["n"]), int(round(float(o["value"]) * XBT_SATS)), k.spk.hex(), extra=cb)
                added += 1
        return added

    def learn_close_change(self, txid: str, funding: tuple[str, int], scan_from: int = 0,
                           *, limit: int = CLOSE_SCAN_MAX) -> dict:
        """AGP-022: count a channel close's change to a hot key, once. Called at the close and again on
        every watcher tick (and before a balance read) until the answer is final.

        The close may be built and broadcast by the provider on its own node, so it can be missing from
        ours for a while, and it may confirm before our mempool ever sees it. Without txindex it is looked
        up in the mempool, then by its outputs (gettxout, which also sees confirmed coins), then in the
        blocks from `scan_from` on (by the funding outpoint it spends, so a different close is found too).

        Returns {"status", "txid", "scan_from", "added"}. status: "counted" (our change is in the set),
        "none" (the close pays no hot key), "spent" (it did, but that output is already spent: never
        counted), or "pending" (the close is not on this node yet: ask again later)."""
        from .netparams import get_tx
        out = {"status": "pending", "txid": txid or "", "scan_from": int(scan_from or 0), "added": 0}
        if not txid:                                      # the provider's reply had no txid: find the spend
            try:
                r = self.rpc.call("gettxspendingprevout", [{"txid": funding[0], "vout": int(funding[1])}])
                out["txid"] = txid = ((r[0] or {}).get("spendingtxid") if r else None) or ""
            except Exception:
                pass
        raw = get_tx(self.rpc, txid) if txid else None    # the mempool (or a txindex)
        if raw is None and txid:                          # confirmed: its unspent outputs answer gettxout
            for n in range(CLOSE_MAX_OUTPUTS):
                c = self.rpc.call("gettxout", txid, n, True)
                if c and self._key_for_spk((c.get("scriptPubKey") or {}).get("hex", "")) is not None:
                    return {**out, "status": "counted", "added": self._count_close(txid, [(n, c)])}
        if raw is None:                                   # no unspent output of ours: find it in a block
            raw = self._close_in_blocks(out, funding, limit)
            txid = out["txid"]
        if raw is None:
            return out
        mine = []
        for o in raw.get("vout") or []:
            spk = (o.get("scriptPubKey") or {})
            if self._key_for_spk(spk.get("hex", "")) is not None or any(spk.get("address") == k.address for k in self._keys()):
                mine.append(int(o["n"]))
        if not mine:
            return {**out, "status": "none"}
        live = [(n, c) for n in mine if (c := self.rpc.call("gettxout", txid, n, True))]
        if not live:
            return {**out, "status": "spent"}
        return {**out, "status": "counted", "added": self._count_close(txid, live)}

    def _count_close(self, txid: str, coins: list[tuple[int, dict]]) -> int:
        """Add unspent close outputs (gettxout results) that pay a hot key; notice_utxo never adds twice."""
        before = len(self._utxos)
        for n, c in coins:
            k = self._key_for_spk((c.get("scriptPubKey") or {}).get("hex", ""))
            if k is not None:
                self.notice_utxo(txid, n, int(round(float(c["value"]) * XBT_SATS)), k.spk.hex())
        return len(self._utxos) - before

    def _close_in_blocks(self, out: dict, funding: tuple[str, int], limit: int) -> dict | None:
        """The block tx spending `funding`, from out["scan_from"] to the tip. Blocks already read are not
        read again: out["scan_from"] moves past them. Sets out["txid"] if the spend is a different tx."""
        try:
            tip = int(self.rpc.call("getblockcount"))
        except Exception:
            return None
        start = out["scan_from"] or tip
        if start > tip:
            return None
        end = min(tip, start + limit - 1)
        for h in range(start, end + 1):
            try:
                blk = self.rpc.call("getblock", self.rpc.call("getblockhash", h), 2)
            except Exception:
                return None                               # keep scan_from here: retry this block next time
            for tx in blk.get("tx") or []:
                if any(v.get("txid") == funding[0] and int(v.get("vout", -1)) == int(funding[1])
                       for v in tx.get("vin") or []):
                    out["txid"], out["scan_from"] = tx.get("txid") or out["txid"], h
                    return tx
            out["scan_from"] = h + 1
        return None

    def _scan_utxoset_for(self, txid: str) -> int:
        """Unspent outputs of `txid` to any hot key, from scantxoutset (confirmed coins only)."""
        res = self.rpc.call("scantxoutset", "start", [f"raw({k.spk.hex()})" for k in self._keys()])
        added = 0
        for c in (res or {}).get("unspents") or []:
            k = self._key_for_spk(c.get("scriptPubKey", ""))
            if c.get("txid") == txid and k is not None:
                self.notice_utxo(txid, int(c["vout"]), int(round(float(c["amount"]) * XBT_SATS)), k.spk.hex(),
                                 extra=_scanned(c))
                added += 1
        return added

    def _current_utxos(self) -> list[dict]:
        cur = self.spk.hex()
        return [u for u in self._utxos if u.get("spk", cur) == cur]

    def _retired_utxos(self) -> list[dict]:
        cur = self.spk.hex()
        return [u for u in self._utxos if u.get("spk", cur) != cur]

    def balance_sats(self) -> int:
        return sum(int(u["value"]) for u in self._utxos)

    def over_cap(self) -> bool:
        return bool(self.cap_sats) and self.balance_sats() > self.cap_sats

    def check_channel_funding(self) -> None:
        """Called before a new channel is funded. Above the cap, a human sweeps first."""
        if self.over_cap():
            raise HotCapError(self.balance_sats(), self.cap_sats)

    def status(self) -> dict:
        return {
            "hot_address": self.address,
            "hot_spk": self.spk.hex(),
            "hot_sats": self.balance_sats(),
            "hot_utxos": len(self._utxos),
            "hot_coinbase_sats": sum(int(u["value"]) for u in self._utxos if u.get("coinbase")),
            "hot_stale_utxos": len(self._stale),
            "hot_encrypted": self.encrypted,
            "hot_retired_keys": len(self._retired),
            "hot_retired_sats": sum(int(u["value"]) for u in self._retired_utxos()),
            "hot_cap_sats": self.cap_sats,
            "hot_over_cap": self.over_cap(),
        }

    # --- spending ----------------------------------------------------------------------------------
    def spendable(self, coins: list[dict]) -> tuple[list[dict], int]:
        """`coins` less every coinbase coin the node would not relay a spend of yet, and the sats held
        back. The depth is the node's (getdeploymentinfo, Maturity.relay_at); when the node cannot say
        (no deployment info, no tip, no block for the coin), the coin waits."""
        if not any(u.get("coinbase") for u in coins):
            return list(coins), 0
        try:
            rule = Maturity.from_deployments(self.rpc.call("getdeploymentinfo"))
        except Exception:
            rule = None
        try:
            tip = int(self.rpc.call("getblockcount"))
        except Exception:
            tip = None
        ok, held = [], 0
        for u in coins:
            h = u.get("height")
            if not u.get("coinbase") or (rule is not None and tip is not None and isinstance(h, int)
                                         and tip + 1 >= rule.relay_at(h)):
                ok.append(u)
            else:
                held += int(u["value"])
        return ok, held

    def _spend(self, utxos: list[dict], outs: list[TxOut], kind: str, **audit) -> str:
        """Sign every input 0x21 with the key that owns it, broadcast, forget the spent coins."""
        prep = self._prepare(utxos, outs, kind, **audit)
        txid = self.broadcast(prep)
        self.commit(prep)
        return txid

    def _prepare(self, utxos: list[dict], outs: list[TxOut], kind: str, **audit) -> dict:
        """AGP-017 P1: build and 0x21-sign, but do not broadcast. The caller can persist what it needs
        (a channel's payer key) before `broadcast`, then `commit` forgets the spent coins. Every
        signature is logged here, whether or not the transaction is ever broadcast."""
        tx = Tx(version=2, inputs=[TxIn(bytes.fromhex(u["txid"])[::-1], int(u["vout"])) for u in utxos],
                outputs=outs, locktime=0)
        keys = [self._key_for_spk(u.get("spk") or self.spk.hex()) for u in utxos]
        if any(k is None for k in keys):
            raise RuntimeError("hot wallet holds a coin it has no key for")
        prevouts = [TxOut(int(u["value"]), k.spk) for u, k in zip(utxos, keys)]
        sigs = []
        for i, k in enumerate(keys):
            digest = unified_sighash(tx, prevouts, i, ST_WITNESS_V0, p2wpkh_script_code(k.pub), SIGHASH_ALL_UNIFIED)
            sig = ecc.sign(k.secret, digest) + bytes([SIGHASH_ALL_UNIFIED])
            if sig[-1] != SIGHASH_ALL_UNIFIED:
                raise RuntimeError("hot signature is not 0x21")
            tx.inputs[i].witness = [sig, k.pub]
            sigs.append((k, sig))
        txid = tx.txid()
        for k, sig in sigs:
            self.audit.record(kind, sig=sig, txid=txid, key_spk=k.spk.hex(), sighash="0x21",
                              amount_sats=sum(o.value for o in outs), **audit)
        return {"hex": tx.hex(), "txid": txid, "inputs": [(u["txid"], int(u["vout"])) for u in utxos],
                "outputs": [(o.value, o.script_pubkey.hex()) for o in outs]}

    def broadcast(self, prep: dict) -> str:
        """Send a prepared transaction. A failed send whose transaction the node already has (a lost
        RPC answer, a re-send) counts as sent. Otherwise this raises, and nothing is forgotten:

        * KnotsRpcRefused when the node itself refused the send and then answered that it has no such
          output: the transaction is not on the node, and the caller may take back what it wrote ahead;
        * BroadcastUnknown for every other failure (no answer, a reset, a lookup that failed too): the
          node may hold the transaction, so the caller keeps what it wrote ahead (AGP-085)."""
        try:
            return self.rpc.call("sendrawtransaction", prep["hex"])
        except Exception as sent:
            try:
                known = self.rpc.call("gettxout", prep["txid"], 0, True)
            except Exception as e:
                raise BroadcastUnknown(f"{_short(sent)}; then gettxout failed too ({_short(e)}): the node may "
                                       f"hold {prep['txid']}") from sent
            if known:
                return prep["txid"]
            if isinstance(sent, KnotsRpcRefused):
                raise
            raise BroadcastUnknown(f"{_short(sent)}: the node did not refuse {prep['txid']} and may still "
                                   "take it") from sent

    def commit(self, prep: dict) -> None:
        """The prepared transaction is sent: forget its inputs, learn its outputs to our keys."""
        spent = {(t, int(v)) for t, v in prep["inputs"]}
        self._utxos = [u for u in self._utxos if (u["txid"], int(u["vout"])) not in spent]
        self._persist_utxos()
        for n, (value, spk) in enumerate(prep["outputs"]):
            if self._key_for_spk(spk) is not None and value >= DUST:
                self.notice_utxo(prep["txid"], n, value, spk)
        self._persist_utxos()

    def holds(self, txid: str, vout: int) -> bool:
        return any(u["txid"] == txid and int(u["vout"]) == int(vout) for u in self._utxos)

    def fund(self, dest_spk: bytes, sats: int, fee: int = DEFAULT_FEE) -> tuple[str, int]:
        """Build, 0x21-sign and broadcast a 1-in/2-out payment to dest_spk. Returns (txid, vout)."""
        prep = self.prepare_fund(dest_spk, sats, fee)
        txid = self.broadcast(prep)
        self.commit(prep)
        return txid, 0

    def prepare_fund(self, dest_spk: bytes, sats: int, fee: int = DEFAULT_FEE) -> dict:
        """`fund` without the broadcast (AGP-017 P1): output 0 pays dest_spk, output 1 is our change."""
        if sats <= 0:
            raise ValueError("fund amount must be positive")
        need = sats + fee
        ok, held = self.spendable(self._current_utxos())
        utxo = next((u for u in ok if int(u["value"]) >= need), None)
        if utxo is None:
            immature = f", {held} of it immature coinbase" if held else ""
            raise RuntimeError(f"hot wallet has no UTXO ≥ {need} sats (have {self.balance_sats()}{immature})")
        change = int(utxo["value"]) - need
        outs = [TxOut(sats, dest_spk)]
        if change >= DUST:
            outs.append(TxOut(change, self.spk))
        return self._prepare([utxo], outs, "funding", dest_spk=dest_spk.hex())

    def _sweep(self, utxos: list[dict], dest_spk: bytes, kind: str, **audit) -> dict:
        total = sum(int(u["value"]) for u in utxos)
        fee = SWEEP_FEE_BASE + SWEEP_FEE_PER_INPUT * len(utxos)
        if total - fee < DUST:
            raise RuntimeError(f"nothing to sweep ({total} sats)")
        txid = self._spend(utxos, [TxOut(total - fee, dest_spk)], kind, **audit)
        return {"txid": txid, "swept_sats": total - fee, "inputs": len(utxos), "fee_sats": fee}

    def rotate(self) -> dict:
        """New hot key; every coin of the old key(s) sweeps into it. The old key stays sealed as retired."""
        old = self._current
        new = _Key(secrets.randbelow(ecc.N - 1) + 1, self.hrp)
        old.retired_at = round(time.time(), 3)
        self._retired.append(old)
        self._current = new
        self._persist()  # the new key is on disk before any coin moves to it
        out = {"old_address": old.address, "new_address": new.address, "sweep": None}
        coins = self.spendable(self._retired_utxos())[0]
        if coins:
            out["sweep"] = self._sweep(coins, new.spk, "rotation_sweep", old_key=old.spk.hex())
        return out

    def sweep_retired(self) -> dict | None:
        """Sweep coins that reached a retired key (a channel close or refund to an old address)."""
        coins = self.spendable(self._retired_utxos())[0]
        if not coins or sum(int(u["value"]) for u in coins) - SWEEP_FEE_BASE - SWEEP_FEE_PER_INPUT * len(coins) < DUST:
            return None
        return self._sweep(coins, self.spk, "retired_sweep")

    def sweep_to(self, dest_spk: bytes, amount_sats: int, fee: int = DEFAULT_FEE) -> dict:
        """Human-approved sweep of `amount_sats` out of the hot key (the signer checks the signature)."""
        coins, held = self.spendable(list(self._utxos))
        total = sum(int(u["value"]) for u in coins)
        fee = max(fee, SWEEP_FEE_BASE + SWEEP_FEE_PER_INPUT * len(coins))
        if amount_sats < DUST or amount_sats + fee > total:
            immature = f" (and {held} immature coinbase)" if held else ""
            raise RuntimeError(f"cannot sweep {amount_sats} sats from {total}{immature}")
        change = total - amount_sats - fee
        outs = [TxOut(amount_sats, dest_spk)]
        if change >= DUST:
            outs.append(TxOut(change, self.spk))
        else:
            fee += change         # zero change, or change below dust: it goes to the fee, and is reported
        txid = self._spend(coins, outs, "human_sweep", dest_spk=dest_spk.hex())
        return {"txid": txid, "swept_sats": amount_sats, "fee_sats": fee, "change_sats": change if change >= DUST else 0,
                "outputs": len(outs), "hot_sats": self.balance_sats()}


__all__ = ["BroadcastUnknown", "HotWallet", "HotCapError", "KnotsRpcError"]
