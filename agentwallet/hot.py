"""Signer-owned secp256k1 hot key. Channel fundings are signed ALL|UNIFIED (0x21).

The Knots wallet will not sign 0x21 on regtest ("fork is not scheduled"), so the
signer spends its own P2WPKH coins with the B1 sighash. Coinbases never fund a
channel: the demo first moves mature coinbase → hot with sendtoaddress, then
this module builds the 0x21 funding.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from .b1path import ensure_b1
from .rpc import KnotsRpc, KnotsRpcError

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


class HotWallet:
    def __init__(self, path: Path, rpc: KnotsRpc, hrp: str = "bcrt"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rpc = rpc
        self.hrp = hrp
        self.secret, self.pub = self._load_or_create()
        self.spk = p2wpkh_spk(self.pub)
        self.address = segwit_address(hrp, self.spk)
        self._utxos: list[dict] = []

    def _load_or_create(self) -> tuple[int, bytes]:
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            secret = int(raw["secret"], 16)
        else:
            secret = secrets.randbelow(ecc.N - 1) + 1
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"secret": f"{secret:064x}", "pub": ecc.pubkey(secret).hex()}, indent=2),
                encoding="utf-8",
            )
            os.replace(tmp, self.path)
            os.chmod(self.path, 0o600)
        return secret, ecc.pubkey(secret)

    def notice_utxo(self, txid: str, vout: int, value_sats: int) -> None:
        if not any(u["txid"] == txid and u["vout"] == vout for u in self._utxos):
            self._utxos.append({"txid": txid, "vout": vout, "value": int(value_sats)})

    def scan_from_txid(self, txid: str) -> int:
        raw = self.rpc.call("getrawtransaction", txid, True)
        added = 0
        for o in raw.get("vout") or []:
            spk = (o.get("scriptPubKey") or {})
            if spk.get("hex") == self.spk.hex() or spk.get("address") == self.address:
                self.notice_utxo(txid, int(o["n"]), int(round(float(o["value"]) * XBT_SATS)))
                added += 1
        return added

    def balance_sats(self) -> int:
        return sum(int(u["value"]) for u in self._utxos)

    def status(self) -> dict:
        return {
            "hot_address": self.address,
            "hot_sats": self.balance_sats(),
            "hot_utxos": len(self._utxos),
        }

    def fund(self, dest_spk: bytes, sats: int, fee: int = DEFAULT_FEE) -> tuple[str, int]:
        """Build, 0x21-sign and broadcast a 1-in/2-out payment to dest_spk. Returns (txid, vout)."""
        if sats <= 0:
            raise ValueError("fund amount must be positive")
        need = sats + fee
        utxo = next((u for u in self._utxos if int(u["value"]) >= need), None)
        if utxo is None:
            raise RuntimeError(f"hot wallet has no UTXO ≥ {need} sats (have {self.balance_sats()})")
        change = int(utxo["value"]) - need
        outs = [TxOut(sats, dest_spk)]
        dest_vout = 0
        if change >= 546:
            outs.append(TxOut(change, self.spk))
        tx = Tx(
            version=2,
            inputs=[TxIn(bytes.fromhex(utxo["txid"])[::-1], int(utxo["vout"]))],
            outputs=outs,
            locktime=0,
        )
        prev = TxOut(int(utxo["value"]), self.spk)
        digest = unified_sighash(tx, [prev], 0, ST_WITNESS_V0, p2wpkh_script_code(self.pub), SIGHASH_ALL_UNIFIED)
        sig = ecc.sign(self.secret, digest) + bytes([SIGHASH_ALL_UNIFIED])
        tx.inputs[0].witness = [sig, self.pub]
        if sig[-1] != SIGHASH_ALL_UNIFIED:
            raise RuntimeError("funding signature is not 0x21")
        try:
            txid = self.rpc.call("sendrawtransaction", tx.hex())
        except KnotsRpcError:
            raise
        self._utxos = [u for u in self._utxos if not (u["txid"] == utxo["txid"] and u["vout"] == utxo["vout"])]
        if change >= 546:
            self.notice_utxo(txid, 1, change)
        return txid, dest_vout
