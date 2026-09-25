"""Per-counterparty Spillman channels used as the policy budget.

The signer holds every payer secret. MCP responses list cap / used / expiry only.
A channel increment is serialized so concurrent pays cannot exceed the cap.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

from .b1path import ensure_b1

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import DUST, ChannelError, ChannelParams, Payer  # noqa: E402


class ChannelCapError(RuntimeError):
    def __init__(self, used: int, amount: int, cap: int):
        super().__init__(f"channel used {used} + {amount} exceeds cap {cap}")
        self.used, self.amount, self.cap = used, amount, cap


@dataclass
class ChannelRecord:
    dest: str
    chan: str
    cap_sats: int
    used_sats: int
    expiry: int
    payer_pub: str
    payee_pub: str
    close_fee: int
    payer_spk: str
    payee_spk: str
    funding_txid: str
    funding_vout: int
    funding_sats: int = 0
    seq: int = 0
    origin: str = ""

    def public(self) -> dict:
        return {
            "dest": self.dest,
            "chan": self.chan,
            "cap_sats": self.cap_sats,
            "used_sats": self.used_sats,
            "expiry": self.expiry,
            "residual_sats": max(0, self.cap_sats - self.used_sats),
            "seq": self.seq,
            "origin": self.origin,
        }


class ChannelBook:
    def __init__(self, records_path: Path, keys_path: Path):
        self.records_path = Path(records_path)
        self.keys_path = Path(keys_path)
        self.records_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._records: dict[str, ChannelRecord] = {}
        self._secrets: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        if self.records_path.exists():
            raw = json.loads(self.records_path.read_text(encoding="utf-8"))
            for dest, rec in (raw.get("channels") or {}).items():
                self._records[dest] = ChannelRecord(**rec)
        if self.keys_path.exists():
            raw = json.loads(self.keys_path.read_text(encoding="utf-8"))
            self._secrets = {k: int(v, 16) for k, v in (raw.get("secrets") or {}).items()}

    def _persist(self) -> None:
        tmp = self.records_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {"channels": {d: asdict(r) for d, r in self._records.items()}},
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        os.replace(tmp, self.records_path)
        ktmp = self.keys_path.with_suffix(".tmp")
        ktmp.write_text(
            json.dumps({"secrets": {k: f"{v:064x}" for k, v in self._secrets.items()}}, indent=2),
            encoding="utf-8",
        )
        os.replace(ktmp, self.keys_path)
        os.chmod(self.keys_path, 0o600)

    def list_public(self) -> list[dict]:
        with self._lock:
            return [r.public() for r in self._records.values()]

    def get(self, dest: str) -> ChannelRecord | None:
        with self._lock:
            rec = self._records.get(dest)
            return None if rec is None else ChannelRecord(**asdict(rec))

    def has(self, dest: str) -> bool:
        with self._lock:
            return dest in self._records

    def find_dest(self, counterparty: str) -> str | None:
        """Resolve an origin, dest, or channel id to the book key."""
        from .policy import normalize_dest

        dest = normalize_dest(counterparty)
        with self._lock:
            if dest in self._records:
                return dest
            if counterparty in self._records:
                return counterparty
            for d, r in self._records.items():
                if r.chan == counterparty or r.origin == dest or r.origin == counterparty:
                    return d
        return None

    def _rec_locked(self, key: str) -> ChannelRecord:
        if key in self._records:
            return self._records[key]
        for r in self._records.values():
            if r.chan == key or r.origin == key:
                return r
        raise ChannelError("unknown_channel", key)

    def sign_close(self, dest: str) -> str:
        """Payer signature over tagged_hash('xbt402/close', chan). Keys stay here."""
        from xbt402.x402_channel import close_message

        with self._lock:
            rec = self._rec_locked(dest)
            secret = self._secrets.get(rec.chan)
            if secret is None:
                raise ChannelError("bad_key", "signer has no key for this channel")
            return ecc.sign(secret, close_message(rec.chan)).hex()

    def request_auth(self, chan: str, seq, cum, sig, req: str) -> str:
        """H3 per-request HMAC. The ECDH channel key never leaves the signer."""
        from xbt402.channel import channel_auth_key
        from xbt402.x402_channel import request_auth

        with self._lock:
            rec = self._rec_locked(chan)
            secret = self._secrets.get(rec.chan)
            if secret is None:
                raise ChannelError("bad_key", "signer has no key for this channel")
            key = channel_auth_key(secret, bytes.fromhex(rec.payee_pub))
            return request_auth(key, rec.chan, seq, cum, sig, req)

    def sign_state_a3(self, chan: str, amount: int) -> bytes:
        """H5: 0xA3 fee-input state. Output 0 is payer change; never sign a lower cum."""
        with self._lock:
            rec = self._rec_locked(chan)
            if amount < rec.used_sats:
                raise ChannelError("stale_amount", f"have {rec.used_sats}, got {amount}")
            if amount > rec.cap_sats:
                raise ChannelCapError(rec.used_sats, amount - rec.used_sats, rec.cap_sats)
            payer = self._payer_locked(rec)
            sig = payer.sign_state_a3(amount)
            rec.used_sats = max(rec.used_sats, amount)
            self._persist()
            return sig

    def fresh_seq(self, dest: str) -> ChannelRecord:
        """Spend a seq without changing the signed cum (every paid request needs a new seq)."""
        with self._lock:
            rec = self._rec_locked(dest)
            rec.seq += 1
            self._persist()
            return ChannelRecord(**asdict(rec))

    def new_payer_key(self) -> tuple[int, str]:
        secret = secrets.randbelow(ecc.N - 1) + 1
        return secret, ecc.pubkey(secret).hex()

    def add_funded(
        self,
        dest: str,
        *,
        secret: int,
        params: ChannelParams,
        origin: str = "",
        cap_sats: int | None = None,
    ) -> ChannelRecord:
        rec = ChannelRecord(
            dest=dest,
            chan=params.channel_id,
            cap_sats=int(cap_sats if cap_sats is not None else params.max_amount),
            used_sats=0,
            expiry=params.expiry,
            payer_pub=params.payer_pub,
            payee_pub=params.payee_pub,
            close_fee=params.close_fee,
            payer_spk=params.payer_spk,
            payee_spk=params.payee_spk,
            funding_txid=params.funding_txid,
            funding_vout=params.funding_vout,
            funding_sats=params.capacity,
            seq=0,
            origin=origin,
        )
        with self._lock:
            self._records[dest] = rec
            self._secrets[params.channel_id] = secret
            self._persist()
            return ChannelRecord(**asdict(rec))

    def _payer_locked(self, rec: ChannelRecord) -> Payer:
        secret = self._secrets.get(rec.chan)
        if secret is None:
            raise ChannelError("bad_key", "signer has no key for this channel")
        params = ChannelParams(
            payer_pub=rec.payer_pub,
            payee_pub=rec.payee_pub,
            expiry=rec.expiry,
            payer_spk=rec.payer_spk,
            payee_spk=rec.payee_spk,
            close_fee=rec.close_fee,
            funding_txid=rec.funding_txid,
            funding_vout=rec.funding_vout,
            capacity=rec.funding_sats or rec.cap_sats,
        )
        payer = Payer(params, secret)
        payer.signed = rec.used_sats
        return payer

    def increment(self, dest: str, amount_sats: int) -> tuple[ChannelRecord, bytes]:
        """Atomically raise the signed cumulative amount. Raises ChannelCapError."""
        if amount_sats <= 0:
            raise ValueError("amount must be positive")
        with self._lock:
            rec = self._records.get(dest)
            if rec is None:
                raise ChannelError("unknown_channel", dest)
            if rec.used_sats + amount_sats > rec.cap_sats:
                raise ChannelCapError(rec.used_sats, amount_sats, rec.cap_sats)
            new_used = rec.used_sats + amount_sats
            sign_cum = new_used
            if 0 < sign_cum < DUST:
                if DUST > rec.cap_sats:
                    raise ChannelCapError(rec.used_sats, DUST - rec.used_sats, rec.cap_sats)
                sign_cum = DUST
            payer = self._payer_locked(rec)
            sig = b""
            if sign_cum > payer.signed:
                if sign_cum > payer.params.max_amount:
                    raise ChannelCapError(rec.used_sats, amount_sats, payer.params.max_amount)
                sig = payer.sign_state(sign_cum)
            rec.used_sats = sign_cum
            rec.seq += 1
            self._persist()
            return ChannelRecord(**asdict(rec)), sig

    def sign_state(self, dest: str, cum: int) -> bytes:
        """Policy-checked caller already decided `cum`. Still refuses a cap breach."""
        with self._lock:
            rec = self._records.get(dest)
            if rec is None:
                raise ChannelError("unknown_channel", dest)
            if cum > rec.cap_sats:
                raise ChannelCapError(rec.used_sats, cum - rec.used_sats, rec.cap_sats)
            if cum < rec.used_sats:
                raise ChannelError("stale_amount", f"have {rec.used_sats}, got {cum}")
            payer = self._payer_locked(rec)
            sig = payer.sign_state(cum) if cum > payer.signed else b""
            rec.used_sats = max(rec.used_sats, cum)
            rec.seq += 1
            self._persist()
            return sig
