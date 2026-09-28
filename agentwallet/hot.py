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
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from .b1path import ensure_b1
from .keystore import KeyStore, KeyStoreError, write_private
from .rpc import KnotsRpc, KnotsRpcError
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
            keep.append({k: v for k, v in u.items() if k != "why"} | {"spk": spk or u["spk"]})
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
                                 "value": int(round(float(c["amount"]) * XBT_SATS)), "spk": c["scriptPubKey"]})
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

    def notice_utxo(self, txid: str, vout: int, value_sats: int, spk: str = "") -> None:
        spk = spk or self.spk.hex()
        if not any(u["txid"] == txid and u["vout"] == vout for u in self._utxos):
            self._utxos.append({"txid": txid, "vout": int(vout), "value": int(value_sats), "spk": spk})
            self._stale = [u for u in self._stale if (u["txid"], int(u["vout"])) != (txid, int(vout))]
            self._persist_utxos()

    def scan_from_txid(self, txid: str, *, unspent_only: bool = False) -> int:
        """Notice this tx's outputs to any hot key. `unspent_only` (AGP-016, for closes found after the
        fact) skips outputs the node says are already spent, so a swept coin is never counted twice."""
        raw = self.rpc.call("getrawtransaction", txid, True)
        added = 0
        for o in raw.get("vout") or []:
            spk = (o.get("scriptPubKey") or {})
            k = self._key_for_spk(spk.get("hex", "")) or next(
                (k for k in self._keys() if spk.get("address") == k.address), None)
            if k is not None and unspent_only and not self.rpc.call("gettxout", txid, int(o["n"]), True):
                continue
            if k is not None:
                self.notice_utxo(txid, int(o["n"]), int(round(float(o["value"]) * XBT_SATS)), k.spk.hex())
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
            "hot_stale_utxos": len(self._stale),
            "hot_encrypted": self.encrypted,
            "hot_retired_keys": len(self._retired),
            "hot_retired_sats": sum(int(u["value"]) for u in self._retired_utxos()),
            "hot_cap_sats": self.cap_sats,
            "hot_over_cap": self.over_cap(),
        }

    # --- spending ----------------------------------------------------------------------------------
    def _spend(self, utxos: list[dict], outs: list[TxOut], kind: str, **audit) -> str:
        """Sign every input 0x21 with the key that owns it, broadcast, forget the spent coins."""
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
        txid = self.rpc.call("sendrawtransaction", tx.hex())
        for k, sig in sigs:
            self.audit.record(kind, sig=sig, txid=txid, key_spk=k.spk.hex(), sighash="0x21",
                              amount_sats=sum(o.value for o in outs), **audit)
        spent = {(u["txid"], int(u["vout"])) for u in utxos}
        self._utxos = [u for u in self._utxos if (u["txid"], int(u["vout"])) not in spent]
        self._persist_utxos()
        return txid

    def fund(self, dest_spk: bytes, sats: int, fee: int = DEFAULT_FEE) -> tuple[str, int]:
        """Build, 0x21-sign and broadcast a 1-in/2-out payment to dest_spk. Returns (txid, vout)."""
        if sats <= 0:
            raise ValueError("fund amount must be positive")
        need = sats + fee
        utxo = next((u for u in self._current_utxos() if int(u["value"]) >= need), None)
        if utxo is None:
            raise RuntimeError(f"hot wallet has no UTXO ≥ {need} sats (have {self.balance_sats()})")
        change = int(utxo["value"]) - need
        outs = [TxOut(sats, dest_spk)]
        if change >= DUST:
            outs.append(TxOut(change, self.spk))
        txid = self._spend([utxo], outs, "funding", dest_spk=dest_spk.hex())
        if change >= DUST:
            self.notice_utxo(txid, 1, change)
        return txid, 0

    def _sweep(self, utxos: list[dict], dest_spk: bytes, kind: str, **audit) -> dict:
        total = sum(int(u["value"]) for u in utxos)
        fee = SWEEP_FEE_BASE + SWEEP_FEE_PER_INPUT * len(utxos)
        if total - fee < DUST:
            raise RuntimeError(f"nothing to sweep ({total} sats)")
        txid = self._spend(utxos, [TxOut(total - fee, dest_spk)], kind, **audit)
        if self._key_for_spk(dest_spk.hex()) is not None:
            self.notice_utxo(txid, 0, total - fee, dest_spk.hex())
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
        coins = self._retired_utxos()
        if coins:
            out["sweep"] = self._sweep(coins, new.spk, "rotation_sweep", old_key=old.spk.hex())
        return out

    def sweep_retired(self) -> dict | None:
        """Sweep coins that reached a retired key (a channel close or refund to an old address)."""
        coins = self._retired_utxos()
        if not coins or sum(int(u["value"]) for u in coins) - SWEEP_FEE_BASE - SWEEP_FEE_PER_INPUT * len(coins) < DUST:
            return None
        return self._sweep(coins, self.spk, "retired_sweep")

    def sweep_to(self, dest_spk: bytes, amount_sats: int, fee: int = DEFAULT_FEE) -> dict:
        """Human-approved sweep of `amount_sats` out of the hot key (the signer checks the signature)."""
        coins = list(self._utxos)
        total = sum(int(u["value"]) for u in coins)
        fee = max(fee, SWEEP_FEE_BASE + SWEEP_FEE_PER_INPUT * len(coins))
        if amount_sats < DUST or amount_sats + fee > total:
            raise RuntimeError(f"cannot sweep {amount_sats} sats from {total}")
        change = total - amount_sats - fee
        outs = [TxOut(amount_sats, dest_spk)]
        if change >= DUST:
            outs.append(TxOut(change, self.spk))
        txid = self._spend(coins, outs, "human_sweep", dest_spk=dest_spk.hex())
        if change >= DUST:
            self.notice_utxo(txid, 1, change)
        return {"txid": txid, "swept_sats": amount_sats, "fee_sats": fee, "hot_sats": self.balance_sats()}


__all__ = ["HotWallet", "HotCapError", "KnotsRpcError"]
