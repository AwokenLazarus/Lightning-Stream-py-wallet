"""Presigned-vault recovery: signed sweep stored on disk, never returned to MCP."""

from __future__ import annotations

import json
from pathlib import Path

from .rpc import KnotsRpc, KnotsRpcError


class PresignedVault:
    def __init__(self, path: Path, rpc: KnotsRpc, recovery_address: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rpc = rpc
        self.recovery_address = recovery_address

    def _state(self) -> dict:
        if not self.path.exists():
            return {"presigned_hex": None, "recovery_address": self.recovery_address, "txid": None}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, state: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def status(self) -> dict:
        st = self._state()
        return {
            "recovery_ready": bool(st.get("presigned_hex")),
            "recovery_address": st.get("recovery_address") or self.recovery_address,
            "broadcast_txid": st.get("txid"),
            # hex is intentionally omitted
        }

    def refresh(self) -> dict:
        """Build and sign a sweep to the recovery address. Hex stays on disk."""
        unspent = self.rpc.call("listunspent", 1, 9999999) or []
        if not unspent:
            st = self._state()
            st["presigned_hex"] = None
            self._save(st)
            return self.status()
        inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in unspent]
        # subtractFeeFromOutputs[0] so the whole pot goes to recovery (no change).
        raw = self.rpc.call(
            "createrawtransaction",
            inputs,
            [{self.recovery_address: sum(u["amount"] for u in unspent)}],
        )
        funded = self.rpc.call(
            "fundrawtransaction",
            raw,
            {"subtractFeeFromOutputs": [0], "change_type": "bech32"},
        )
        signed = self.rpc.call("signrawtransactionwithwallet", funded["hex"])
        if not signed.get("complete"):
            raise KnotsRpcError(f"vault sign incomplete: {signed.get('errors')}")
        st = {
            "presigned_hex": signed["hex"],
            "recovery_address": self.recovery_address,
            "input_count": len(inputs),
            "txid": None,
        }
        self._save(st)
        return self.status()

    def recover(self, *, human: bool) -> dict:
        if not human:
            raise PermissionError("vault recover is human-only")
        st = self._state()
        hex_tx = st.get("presigned_hex")
        if not hex_tx:
            st_status = self.refresh()
            st = self._state()
            hex_tx = st.get("presigned_hex")
            if not hex_tx:
                return {"ok": False, "reason": "no spendable coins to recover", **st_status}
        txid = self.rpc.call("sendrawtransaction", hex_tx)
        st["txid"] = txid
        st["presigned_hex"] = None  # spent
        self._save(st)
        return {"ok": True, "txid": txid, "recovery_address": self.recovery_address}
