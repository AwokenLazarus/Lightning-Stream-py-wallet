"""Treasury P2WSH: 2-of-2 (human, cosigner) or recovery after CSV older(4320).

Matches research note idea #3 / miniscript
`wsh(or_d(multi(2,Human,Cosigner),and_v(v:pk(Recovery),older(4320))))`
as an equivalent witness-v0 script (OP_IF is legal in P2WSH under RDTS).

AGP-016: the demo human, cosigner and recovery secrets in `treasury.json` are sealed like `hot.json`
(AES-256-GCM, the signer's wrapping key from B2_HOT_KEYFILE / B2_HOT_PASSPHRASE). The file keeps only
the three pubkeys, the CSV and the funding outpoint in the clear. A plaintext file from before is
re-sealed on the first start with a wrapping key; a wrong key, a tampered blob or pubkeys that do not
match the sealed secrets are refused.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from .b1path import ensure_b1
from .keystore import KeyStore, KeyStoreError, write_private

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.tx import (  # noqa: E402
    OP_CHECKSIG,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    SIGHASH_ALL_UNIFIED,
    ST_WITNESS_V0,
    Tx,
    TxIn,
    TxOut,
    p2wsh_spk,
    push,
    script_num,
    segwit_address,
    unified_sighash,
)

OP_2 = 0x52
OP_CHECKMULTISIG = 0xAE
OP_CHECKSEQUENCEVERIFY = 0xB2

TREASURY_CSV = 4320
AAD = "b2/treasury-keys"
ROLES = ("human", "cosigner", "recovery")


def treasury_script(
    human_pub: bytes, cosigner_pub: bytes, recovery_pub: bytes, csv: int = TREASURY_CSV
) -> bytes:
    if csv <= 0:
        raise ValueError("csv must be positive")
    return (
        bytes([OP_IF])
        + bytes([OP_2])
        + push(human_pub)
        + push(cosigner_pub)
        + bytes([OP_2, OP_CHECKMULTISIG])
        + bytes([OP_ELSE])
        + script_num(csv)
        + bytes([OP_CHECKSEQUENCEVERIFY, OP_DROP])
        + push(recovery_pub)
        + bytes([OP_CHECKSIG])
        + bytes([OP_ENDIF])
    )


def _new_secret() -> int:
    return secrets.randbelow(ecc.N - 1) + 1


class Treasury:
    def __init__(self, path: Path, csv: int = TREASURY_CSV, hrp: str = "bcrt", *, keystore: KeyStore | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.csv = int(csv)
        self.hrp = hrp
        self.keystore = keystore
        raw = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        secrets_ = self._open_secrets(raw)
        self.human_secret = secrets_.get("human") or _new_secret()
        self.cosigner_secret = secrets_.get("cosigner") or _new_secret()
        self.recovery_secret = secrets_.get("recovery") or _new_secret()
        self.human_pub = ecc.pubkey(self.human_secret)
        self.cosigner_pub = ecc.pubkey(self.cosigner_secret)
        self.recovery_pub = ecc.pubkey(self.recovery_secret)
        for role, pub in (raw.get("pubs") or {}).items():
            if role in ROLES and pub != getattr(self, f"{role}_pub").hex():
                raise KeyStoreError(f"treasury file: the {role} key does not match its recorded pub")
        self.script = treasury_script(self.human_pub, self.cosigner_pub, self.recovery_pub, self.csv)
        self.spk = p2wsh_spk(self.script)
        self.address = segwit_address(hrp, self.spk)
        self.funding_txid = raw.get("funding_txid") or ""
        self.funding_vout = int(raw.get("funding_vout") or 0)
        self.capacity = int(raw.get("capacity") or 0)
        # AGP-085: a funding written ahead of its broadcast, until the node shows or refuses it
        self.pending: dict | None = self._pending_from(raw.get("pending_funding"))
        # fundings the node refused when they were sent again: no coin is known behind them, and the
        # record stays in case one confirms after all (it reached other nodes on its first send)
        self.unsettled: list[dict] = [self._pending_from(p) for p in raw.get("unsettled_fundings") or []]
        # AGP-089: fundings recorded before the current one. A second funding used to overwrite the one
        # recorded outpoint; its coins stayed at the treasury address with no record of where
        self.earlier: list[dict] = [self._outpoint_from(p) for p in raw.get("earlier_fundings") or []]
        self._persist()

    @staticmethod
    def _outpoint_from(p) -> dict:
        try:
            out = {"txid": str(p["txid"]), "vout": int(p["vout"]), "capacity": int(p["capacity"])}
            bytes.fromhex(out["txid"])
        except (KeyError, TypeError, ValueError) as e:
            # never read as "no earlier funding": the record is the only pointer to those coins
            raise KeyStoreError("treasury file: earlier_fundings is malformed") from e
        return out

    def outpoints(self) -> list[dict]:
        """Every funding this treasury recorded: the current one first, then the earlier ones."""
        cur = [{"txid": self.funding_txid, "vout": self.funding_vout, "capacity": self.capacity}] if self.funding_txid else []
        return cur + list(self.earlier)

    @staticmethod
    def _pending_from(p) -> dict | None:
        if p is None:
            return None
        try:
            out = {"txid": str(p["txid"]), "vout": int(p["vout"]), "capacity": int(p["capacity"]), "hex": str(p["hex"])}
            bytes.fromhex(out["txid"]), bytes.fromhex(out["hex"])
        except (KeyError, TypeError, ValueError) as e:
            # never read as "no pending funding": that would let the next funding overwrite the record
            raise KeyStoreError("treasury file: pending_funding is malformed") from e
        return out

    @property
    def encrypted(self) -> bool:
        return self.keystore is not None

    def _open_secrets(self, raw: dict) -> dict[str, int]:
        if "sealed" in raw:
            if self.keystore is None:
                raise KeyStoreError("treasury secrets are encrypted: set B2_HOT_KEYFILE or B2_HOT_PASSPHRASE")
            doc = json.loads(self.keystore.open(raw["sealed"], AAD))
        else:  # AGP-013 and older: the secrets in the clear (re-sealed below when a keystore is set)
            doc = raw
        return {r: int(doc[r], 16) for r in ROLES if doc.get(r)}

    def _persist(self) -> None:
        doc = {
            "v": 2,
            "encrypted": self.encrypted,
            "pubs": {r: getattr(self, f"{r}_pub").hex() for r in ROLES},
            "csv": self.csv,
            "funding_txid": self.funding_txid,
            "funding_vout": self.funding_vout,
            "capacity": self.capacity,
        }
        if self.pending:
            doc["pending_funding"] = self.pending
        if self.unsettled:
            doc["unsettled_fundings"] = self.unsettled
        if self.earlier:
            doc["earlier_fundings"] = self.earlier
        keys = {r: f"{getattr(self, f'{r}_secret'):064x}" for r in ROLES}
        if self.keystore is None:
            doc.update(keys)
        else:
            doc["sealed"] = self.keystore.seal(json.dumps(keys).encode(), AAD)
        write_private(self.path, json.dumps(doc, indent=2))

    def export_human_device(self, device_dir: Path) -> dict[str, str]:
        """Write human + recovery secp keys next to the ed25519 device key. Never under B2_ROOT."""
        device_dir = Path(device_dir)
        device_dir.mkdir(parents=True, exist_ok=True)
        hs = device_dir / "treasury-human.sk"
        rs = device_dir / "treasury-recovery.sk"
        hs.write_text(f"{self.human_secret:064x}\n", encoding="utf-8")
        rs.write_text(f"{self.recovery_secret:064x}\n", encoding="utf-8")
        os.chmod(hs, 0o600)
        os.chmod(rs, 0o600)
        return {
            "human_pub": self.human_pub.hex(),
            "recovery_pub": self.recovery_pub.hex(),
            "address": self.address,
            "csv": str(self.csv),
        }

    def record_pending(self, txid: str, vout: int, capacity: int, hex_tx: str) -> None:
        """AGP-085: write a funding ahead of its broadcast (one at a time)."""
        if self.pending and self.pending["txid"] != txid:
            raise RuntimeError(f"treasury funding {self.pending['txid']} is still pending")
        self.pending = {"txid": txid, "vout": int(vout), "capacity": int(capacity), "hex": hex_tx}
        self._persist()

    def drop_pending(self, txid: str) -> None:
        """The node refused the pending funding on its first send and has no such output: it exists
        nowhere but here."""
        if self.pending and self.pending["txid"] == txid:
            self.pending = None
            self._persist()

    def shelve_pending(self, txid: str) -> None:
        """A kept funding the node refuses to take again and has no output of. It may have left the
        node on its first send, so its outpoint is kept under `unsettled_fundings`, where it no longer
        holds up a new funding."""
        if self.pending and self.pending["txid"] == txid:
            self.unsettled.append(self.pending)
            self.pending = None
            self._persist()

    def record_funding(self, txid: str, vout: int, capacity: int) -> None:
        """Record a funding. AGP-089: the one recorded before it is kept under `earlier_fundings`,
        never overwritten (recover_treasury spends every recorded outpoint)."""
        if self.funding_txid and (self.funding_txid, self.funding_vout) != (txid, int(vout)):
            self.earlier.append({"txid": self.funding_txid, "vout": self.funding_vout, "capacity": self.capacity})
        self.earlier = [e for e in self.earlier if (e["txid"], e["vout"]) != (txid, int(vout))]
        self.funding_txid, self.funding_vout, self.capacity = txid, int(vout), int(capacity)
        if self.pending and self.pending["txid"] == txid:
            self.pending = None
        self.unsettled = [p for p in self.unsettled if p["txid"] != txid]
        self._persist()

    def status(self) -> dict:
        return {
            "treasury_address": self.address,
            "treasury_csv": self.csv,
            "treasury_funded_sats": self.capacity,
            "treasury_outpoint": f"{self.funding_txid}:{self.funding_vout}" if self.funding_txid else "",
            **({"treasury_pending_outpoint": f"{self.pending['txid']}:{self.pending['vout']}",
                "treasury_pending_sats": self.pending["capacity"]} if self.pending else {}),
            **({"treasury_unsettled_outpoints": [f"{p['txid']}:{p['vout']}" for p in self.unsettled]}
               if self.unsettled else {}),
            **({"treasury_earlier_outpoints": [f"{p['txid']}:{p['vout']}" for p in self.earlier],
                "treasury_earlier_sats": sum(p["capacity"] for p in self.earlier)} if self.earlier else {}),
        }

    def recovery_tx(self, dest_spk: bytes, fee: int = 600, outpoint: dict | None = None) -> Tx:
        """CSV recovery of one recorded funding (the current one unless `outpoint` names another, from
        `outpoints()`): valid once that UTXO is older(csv). Signed 0x21."""
        op = outpoint or {"txid": self.funding_txid, "vout": self.funding_vout, "capacity": self.capacity}
        if not op["txid"]:
            raise RuntimeError("treasury is not funded")
        if op["capacity"] <= fee:
            raise RuntimeError(f"this funding holds {op['capacity']} sat, not more than the {fee} sat fee")
        tx = Tx(
            version=2,
            inputs=[TxIn(bytes.fromhex(op["txid"])[::-1], op["vout"], sequence=self.csv)],
            outputs=[TxOut(op["capacity"] - fee, dest_spk)],
            locktime=0,
        )
        prev = TxOut(op["capacity"], self.spk)
        digest = unified_sighash(tx, [prev], 0, ST_WITNESS_V0, self.script, SIGHASH_ALL_UNIFIED)
        sig = ecc.sign(self.recovery_secret, digest) + bytes([SIGHASH_ALL_UNIFIED])
        tx.inputs[0].witness = [sig, b"", self.script]
        return tx
