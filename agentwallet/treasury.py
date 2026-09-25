"""Treasury P2WSH: 2-of-2 (human, cosigner) or recovery after CSV older(4320).

Matches research note idea #3 / miniscript
`wsh(or_d(multi(2,Human,Cosigner),and_v(v:pk(Recovery),older(4320))))`
as an equivalent witness-v0 script (OP_IF is legal in P2WSH under RDTS).
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from .b1path import ensure_b1

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
    def __init__(self, path: Path, csv: int = TREASURY_CSV, hrp: str = "bcrt"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.csv = int(csv)
        self.hrp = hrp
        raw = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        self.human_secret = int(raw["human"], 16) if raw.get("human") else _new_secret()
        self.cosigner_secret = int(raw["cosigner"], 16) if raw.get("cosigner") else _new_secret()
        self.recovery_secret = int(raw["recovery"], 16) if raw.get("recovery") else _new_secret()
        self.human_pub = ecc.pubkey(self.human_secret)
        self.cosigner_pub = ecc.pubkey(self.cosigner_secret)
        self.recovery_pub = ecc.pubkey(self.recovery_secret)
        self.script = treasury_script(self.human_pub, self.cosigner_pub, self.recovery_pub, self.csv)
        self.spk = p2wsh_spk(self.script)
        self.address = segwit_address(hrp, self.spk)
        self.funding_txid = raw.get("funding_txid") or ""
        self.funding_vout = int(raw.get("funding_vout") or 0)
        self.capacity = int(raw.get("capacity") or 0)
        self._persist()

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "human": f"{self.human_secret:064x}",
                    "cosigner": f"{self.cosigner_secret:064x}",
                    "recovery": f"{self.recovery_secret:064x}",
                    "csv": self.csv,
                    "funding_txid": self.funding_txid,
                    "funding_vout": self.funding_vout,
                    "capacity": self.capacity,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

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

    def record_funding(self, txid: str, vout: int, capacity: int) -> None:
        self.funding_txid, self.funding_vout, self.capacity = txid, int(vout), int(capacity)
        self._persist()

    def status(self) -> dict:
        return {
            "treasury_address": self.address,
            "treasury_csv": self.csv,
            "treasury_funded_sats": self.capacity,
            "treasury_outpoint": f"{self.funding_txid}:{self.funding_vout}" if self.funding_txid else "",
        }

    def recovery_tx(self, dest_spk: bytes, fee: int = 600) -> Tx:
        """CSV recovery: valid once the funding UTXO is older(csv). Signed 0x21."""
        if not self.funding_txid or self.capacity <= fee:
            raise RuntimeError("treasury is not funded")
        tx = Tx(
            version=2,
            inputs=[TxIn(bytes.fromhex(self.funding_txid)[::-1], self.funding_vout, sequence=self.csv)],
            outputs=[TxOut(self.capacity - fee, dest_spk)],
            locktime=0,
        )
        prev = TxOut(self.capacity, self.spk)
        digest = unified_sighash(tx, [prev], 0, ST_WITNESS_V0, self.script, SIGHASH_ALL_UNIFIED)
        sig = ecc.sign(self.recovery_secret, digest) + bytes([SIGHASH_ALL_UNIFIED])
        tx.inputs[0].witness = [sig, b"", self.script]
        return tx
