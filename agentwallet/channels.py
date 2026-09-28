"""Per-counterparty Spillman channels used as the policy budget.

The signer holds every payer secret. MCP responses list cap / used / expiry only.
A channel increment is serialized so concurrent pays cannot exceed the cap.

AGP-013: payer keys are sealed at rest when the book has a KeyStore; every signature goes to the
signature audit log; a channel has a lifecycle (open -> closed | refunded) and the book refuses to
sign a new state on a channel that is not open or is within `expiry_margin` blocks of its CLTV
expiry (the provider needs those blocks to close before the payer's refund becomes valid).

AGP-017 P1: a channel is written to disk, payer key sealed, in state "pending" *before* its funding
is broadcast (`add_pending`), and becomes "open" only once the provider accepts the open
(`mark_open`). A crash, a dead provider or a refused open leaves a pending record that the signer
retries and, failing that, refunds at expiry: the coins can no longer be stranded. A settled record
(closed or refunded) that a new channel replaces is kept under "archived".

`spent_sats` is what the calls actually cost; `used_sats` stays the cumulative amount signed, which
is at least the 546-sat dust floor. The dust top-up of the first state is no longer charged again on
top of the next call (10 calls of 500 sign 5,000, not 5,046).
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .b1path import ensure_b1
from .keystore import KeyStore, write_private
from .sigaudit import NullAudit

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
    # a signed hash lock whose paid response has not arrived: {hash, cipher, manifest}. The claim that
    # pays the provider reveals k, which opens this ciphertext (Xbt402Session.recover_conditional)
    pending_cond: dict = field(default_factory=dict)
    # AGP-013 lifecycle: "open" | "closed" (a close tx spent the funding) | "refunded" (our refund did)
    state: str = "open"
    closed_txid: str = ""
    refund_txid: str = ""
    open_height: int = 0
    # AGP-017
    spent_sats: int = -1        # charges so far; -1 (a record from before AGP-017) means used_sats
    open_url: str = ""          # where a pending channel's open is (re)posted
    network: str = ""
    min_conf: int = 0           # the offer's minConf: the open is posted once the funding has this many
    funding_hex: str = ""       # the signed funding (public once broadcast), re-sent if it went missing
    funding_height: int = 0     # block of the funding once seen confirmed (lookups on a pruned node)
    open_error: str = ""
    # AGP-020: last signed-but-unacknowledged state. sign_state / pay_once re-hand this
    # (same cum, same sig) instead of signing a higher one (M3: one call of slack).
    last_sig: str = ""
    acked_sats: int = 0

    def spent(self) -> int:
        return self.used_sats if self.spent_sats < 0 else self.spent_sats

    def public(self) -> dict:
        return {
            "state": self.state,
            "funding_txid": self.funding_txid or None,
            "spent_sats": self.spent(),
            **({"open_error": self.open_error} if self.open_error and self.state == "pending" else {}),
            "closed_txid": self.closed_txid or None,
            "refund_txid": self.refund_txid or None,
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
    KEYS_AAD = "b2/channel-keys"

    def __init__(self, records_path: Path, keys_path: Path, *, keystore: KeyStore | None = None, audit=None):
        self.records_path = Path(records_path)
        self.keys_path = Path(keys_path)
        self.keystore = keystore
        self.audit = audit or NullAudit()
        # (height_fn, margin): refuse new states once height >= expiry - margin. None: no check.
        self.expiry_guard = None
        self.records_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._records: dict[str, ChannelRecord] = {}
        self._archived: list[dict] = []
        self._secrets: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        if self.records_path.exists():
            raw = json.loads(self.records_path.read_text(encoding="utf-8"))
            for dest, rec in (raw.get("channels") or {}).items():
                self._records[dest] = ChannelRecord(**rec)
            self._archived = list(raw.get("archived") or [])
        if self.keys_path.exists():
            raw = json.loads(self.keys_path.read_text(encoding="utf-8"))
            if "sealed" in raw:
                if self.keystore is None:
                    raise RuntimeError("channel keys are encrypted: set B2_HOT_KEYFILE or B2_HOT_PASSPHRASE")
                raw = json.loads(self.keystore.open(raw["sealed"], self.KEYS_AAD))
            elif self.keystore is not None and raw.get("secrets"):
                self._secrets = {k: int(v, 16) for k, v in (raw.get("secrets") or {}).items()}
                self._persist()  # first start with a wrapping key: re-seal the plaintext file
            self._secrets = {k: int(v, 16) for k, v in (raw.get("secrets") or {}).items()}

    def _persist(self) -> None:
        # keys first: a record on disk never names a channel whose payer key is not on disk (P1)
        doc = json.dumps({"secrets": {k: f"{v:064x}" for k, v in self._secrets.items()}}, indent=2)
        if self.keystore is not None:
            doc = json.dumps({"sealed": self.keystore.seal(doc.encode(), self.KEYS_AAD)}, indent=2)
        write_private(self.keys_path, doc)
        body = {"channels": {d: asdict(r) for d, r in self._records.items()}}
        if self._archived:
            body["archived"] = self._archived
        write_private(self.records_path, json.dumps(body, indent=2, sort_keys=True))

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
            if rec.state == "refunded":
                raise ChannelError("channel_refunded", f"refunded in {rec.refund_txid}")
            sig = ecc.sign(secret, close_message(rec.chan))
            self.audit.record("close_auth", sig=sig, chan=rec.chan, dest=rec.dest, cum=rec.used_sats)
            return sig.hex()

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
            self.audit.record("channel_state_a3", sig=sig, chan=rec.chan, dest=rec.dest, cum=amount, sighash="0xa3")
            rec.used_sats = max(rec.used_sats, amount)
            rec.spent_sats = max(rec.spent(), amount)
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

    def add_pending(self, dest: str, *, secret: int, params: ChannelParams, origin: str = "",
                    cap_sats: int | None = None, open_height: int = 0, open_url: str = "", network: str = "",
                    min_conf: int = 0, funding_hex: str = "") -> ChannelRecord:
        """AGP-017 P1: record a channel and seal its payer key before its funding is broadcast. A
        pending or open channel to the same dest is never replaced; a settled one is archived."""
        with self._lock:
            old = self._records.get(dest)
            if old is not None and old.state in ("open", "pending"):
                raise ChannelError(f"channel_{old.state}", f"{dest} already has a {old.state} channel {old.chan[:16]}")
            if old is not None:
                self._archived.append(asdict(old))
            rec = self._record(dest, params, origin, cap_sats, open_height)
            rec.state, rec.open_url, rec.network, rec.min_conf = "pending", open_url, network, int(min_conf)
            rec.funding_hex, rec.spent_sats = funding_hex, 0
            self._records[dest] = rec
            self._secrets[params.channel_id] = secret
            self._persist()
            return ChannelRecord(**asdict(rec))

    def drop_pending(self, dest: str, chan: str) -> None:
        """The funding of a pending channel was never broadcast: forget the record and its key."""
        with self._lock:
            rec = self._records.get(dest)
            if rec is None or rec.chan != chan or rec.state != "pending":
                return
            del self._records[dest]
            self._secrets.pop(chan, None)
            if self._archived and self._archived[-1].get("dest") == dest:
                self._records[dest] = ChannelRecord(**self._archived.pop())
            self._persist()

    def mark_open(self, key: str) -> ChannelRecord:
        with self._lock:
            rec = self._rec_locked(key)
            if rec.state == "pending":
                rec.state, rec.open_error = "open", ""
                self._persist()
            return ChannelRecord(**asdict(rec))

    def note_pending(self, key: str, *, open_error: str | None = None, funding_height: int | None = None) -> None:
        with self._lock:
            rec = self._rec_locked(key)
            if open_error is not None:
                rec.open_error = open_error[:200]
            if funding_height:
                rec.funding_height = int(funding_height)
            self._persist()

    def _record(self, dest, params: ChannelParams, origin, cap_sats, open_height) -> ChannelRecord:
        return ChannelRecord(
            dest=dest, chan=params.channel_id,
            cap_sats=int(cap_sats if cap_sats is not None else params.max_amount), used_sats=0,
            expiry=params.expiry, payer_pub=params.payer_pub, payee_pub=params.payee_pub,
            close_fee=params.close_fee, payer_spk=params.payer_spk, payee_spk=params.payee_spk,
            funding_txid=params.funding_txid, funding_vout=params.funding_vout, funding_sats=params.capacity,
            seq=0, origin=origin, open_height=int(open_height or 0), spent_sats=0)

    def add_funded(
        self,
        dest: str,
        *,
        secret: int,
        params: ChannelParams,
        origin: str = "",
        cap_sats: int | None = None,
        open_height: int = 0,
    ) -> ChannelRecord:
        rec = self._record(dest, params, origin, cap_sats, open_height)
        with self._lock:
            old = self._records.get(dest)
            if old is not None and old.state == "pending":
                raise ChannelError("channel_pending", f"{dest} has a pending channel {old.chan[:16]}")
            if old is not None and old.state != "open":
                self._archived.append(asdict(old))
            self._records[dest] = rec
            self._secrets[params.channel_id] = secret
            self._persist()
            return ChannelRecord(**asdict(rec))

    def check_usable_locked(self, rec: ChannelRecord) -> None:
        """Only an open channel outside its expiry margin gets new states."""
        if rec.state != "open":
            raise ChannelError(f"channel_{rec.state}", f"channel {rec.chan[:16]} is {rec.state}")
        if self.expiry_guard is not None:
            height_fn, margin = self.expiry_guard
            h = int(height_fn())
            if h >= rec.expiry - int(margin):
                raise ChannelError("channel_expiring",
                                   f"height {h} is within {margin} blocks of expiry {rec.expiry}: close or refund it")

    def _payer_locked(self, rec: ChannelRecord) -> Payer:
        self.check_usable_locked(rec)
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
            spent = rec.spent()
            if spent + amount_sats > rec.cap_sats:
                raise ChannelCapError(spent, amount_sats, rec.cap_sats)
            new_spent = spent + amount_sats
            sign_cum = max(new_spent, rec.used_sats)
            if 0 < sign_cum < DUST:
                if DUST > rec.cap_sats:
                    raise ChannelCapError(spent, DUST - spent, rec.cap_sats)
                sign_cum = DUST
            payer = self._payer_locked(rec)
            sig = b""
            if sign_cum > payer.signed:
                if sign_cum > payer.params.max_amount:
                    raise ChannelCapError(rec.used_sats, amount_sats, payer.params.max_amount)
                sig = payer.sign_state(sign_cum)
                rec.last_sig = sig.hex()
                self.audit.record("channel_state", sig=sig, chan=rec.chan, dest=rec.dest, cum=sign_cum, sighash="0x21")
            rec.used_sats = sign_cum
            rec.spent_sats = new_spent
            rec.seq += 1
            self._persist()
            return ChannelRecord(**asdict(rec)), sig

    def sign_state(self, dest: str, cum: int) -> bytes:
        """Policy-checked caller already decided `cum`. Still refuses a cap breach.
        An already-signed cum hands back the cached signature (AGP-020); a higher
        one is signed only when the last state has been acknowledged."""
        with self._lock:
            rec = self._records.get(dest)
            if rec is None:
                raise ChannelError("unknown_channel", dest)
            if cum > rec.cap_sats:
                raise ChannelCapError(rec.used_sats, cum - rec.used_sats, rec.cap_sats)
            if cum < rec.used_sats:
                raise ChannelError("stale_amount", f"have {rec.used_sats}, got {cum}")
            payer = self._payer_locked(rec)
            sig = b""
            if cum > payer.signed:
                sig = payer.sign_state(cum)
                rec.last_sig = sig.hex()
                self.audit.record("channel_state", sig=sig, chan=rec.chan, dest=rec.dest, cum=cum, sighash="0x21")
            elif rec.last_sig:
                sig = bytes.fromhex(rec.last_sig)
            rec.used_sats = max(rec.used_sats, cum)
            rec.spent_sats = max(rec.spent(), cum)
            rec.seq += 1
            self._persist()
            return sig

    def resend_state(self, dest: str) -> tuple[ChannelRecord, bytes]:
        """Re-hand the last signed-but-unacknowledged state (same cum, same sig, fresh seq)."""
        with self._lock:
            rec = self._records.get(dest)
            if rec is None:
                raise ChannelError("unknown_channel", dest)
            if not rec.last_sig or rec.used_sats <= rec.acked_sats:
                raise ChannelError("no_unacked_state", dest)
            rec.seq += 1
            self._persist()
            return ChannelRecord(**asdict(rec)), bytes.fromhex(rec.last_sig)

    def ack_state(self, dest: str, cum: int | None = None) -> None:
        """The provider recorded this signed cum (a receipt or a PAYMENT-RESPONSE)."""
        with self._lock:
            rec = self._records.get(dest)
            if rec is None:
                return
            rec.acked_sats = rec.used_sats if cum is None else min(int(cum), rec.used_sats)
            self._persist()

    # --- AGP-013 lifecycle: provider close seen on-chain, payer refund after expiry ---------------
    def open_records(self) -> list[ChannelRecord]:
        with self._lock:
            return [ChannelRecord(**asdict(r)) for r in self._records.values() if r.state == "open"]

    def unsettled_records(self) -> list[ChannelRecord]:
        """Open and pending channels: their funding output may still be ours to refund (P1)."""
        with self._lock:
            return [ChannelRecord(**asdict(r)) for r in self._records.values() if r.state in ("open", "pending")]

    def pending_records(self) -> list[ChannelRecord]:
        with self._lock:
            return [ChannelRecord(**asdict(r)) for r in self._records.values() if r.state == "pending"]

    def mark_closed(self, key: str, txid: str = "") -> None:
        with self._lock:
            rec = self._rec_locked(key)
            if rec.state in ("open", "pending"):
                rec.state, rec.closed_txid = "closed", txid or rec.closed_txid
                self._persist()
            elif rec.state == "closed" and txid and not rec.closed_txid:
                rec.closed_txid = txid
                self._persist()

    def refund_tx(self, key: str, dest_spk: bytes, fee: int | None = None):
        """The payer's CLTV refund of the whole funding output to `dest_spk` (B1 `refund_tx`).
        Only for an open channel: a closed or refunded one has no funding output left to spend."""
        with self._lock:
            rec = self._rec_locked(key)
            if rec.state not in ("open", "pending"):     # a pending channel's funding is refundable too (P1)
                raise ChannelError(f"channel_{rec.state}", rec.refund_txid or rec.closed_txid)
            secret = self._secrets.get(rec.chan)
            if secret is None:
                raise ChannelError("bad_key", "signer has no key for this channel")
            params = ChannelParams(
                payer_pub=rec.payer_pub, payee_pub=rec.payee_pub, expiry=rec.expiry, payer_spk=rec.payer_spk,
                payee_spk=rec.payee_spk, close_fee=rec.close_fee, funding_txid=rec.funding_txid,
                funding_vout=rec.funding_vout, capacity=rec.funding_sats or rec.cap_sats)
            tx = params.refund_tx(secret, dest_spk=dest_spk, fee=fee)
            self.audit.record("refund", sig=tx.inputs[0].witness[0], chan=rec.chan, dest=rec.dest, txid=tx.txid(),
                              amount_sats=tx.outputs[0].value, locktime=rec.expiry, sighash="0x21")
            return tx, rec.expiry

    def mark_refunded(self, key: str, txid: str) -> None:
        with self._lock:
            rec = self._rec_locked(key)
            rec.state, rec.refund_txid = "refunded", txid
            self._persist()
