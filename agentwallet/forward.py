"""Forward rail: buy B5 coinbase-forward lots over xbt402, atomically (AGP-013, from b5 AGP-008).

A rail beside `stream`, inside `xbt402_pay`. When a 402's channel offer carries `extra.forward`
(a market's /forward/quote), the session:

  1. checks the forward policy: the market is allowed, the price is within the per-lot max, and the
     rolling 24 h forward spend stays within the forward budget (all on top of the ordinary policy
     the signer already applied to `max_sats`);
  2. checks the lot on the wallet's own node and rebuilds the transfer to its own hot key
     (fwd.buyer.verify_offer), and recomputes the adaptor point S from R.x;
  3. opens the channel from the offer if needed (v1.3, derivation v3);
  4. books the price in the policy ledger (AGP-080: the market can complete the pre-signature from
     here on), pre-signs the next channel state, cum + price, under S (never a plain signature for
     it), writes the pending purchase to disk, and sends it as the x402 payload's `adaptor`;
  5. on 200 checks the transfer's key-path signature and only then counts the price as spent on the
     channel. The booking is released only on proof the pre-signature is void: a close of the
     channel that does not carry it, or our own refund of the funding.

If the answer is lost, `forward_recover(close_txid)` reads the completed state signature from the
market's channel close and extracts s (the market cannot close with that state without it).

Moved from b5 agp-merge 25d3541 `fwd/wallet.py` (`ForwardSession`, `ForwardSigner`). b5 keeps its
own copy for now (see agentwallet/fwd/__init__.py and the AGP-013 result): switching b5 to this
module is `ForwardSigner = agentwallet.signer.Signer` once b5 vendors b2 agp-013.

Policy (policy.json):
  "forward": {"markets": ["http://market:port"], "per_lot_max_sats": 3000000, "daily_budget_sats": 10000000}
No "forward" section, or an empty markets list, means the rail is off.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import sigaudit
from .fwd import adaptor
from .fwd.buyer import check_transfer, lot_from_offer, receipt_digest, transfer_with, verify_offer
from .fwd.escrow import ForwardError
from .maturity import Maturity
from .policy import normalize_dest
from .xbt402 import Xbt402Session, _log, origin_of

from xbt402 import ecc as becc  # noqa: E402  (B1 on sys.path through .xbt402)
from xbt402.channel import ChannelError  # noqa: E402
from .fwd.tx import Tx as FTx

DAY_S = 24 * 3600


@dataclass
class ForwardPolicy:
    markets: frozenset = field(default_factory=frozenset)
    per_lot_max_sats: int = 0
    daily_budget_sats: int = 0

    @classmethod
    def from_dict(cls, raw) -> "ForwardPolicy":
        raw = raw or {}
        return cls(frozenset(normalize_dest(m) for m in raw.get("markets") or [] if normalize_dest(m)),
                   int(raw.get("per_lot_max_sats") or 0), int(raw.get("daily_budget_sats") or 0))

    @property
    def enabled(self) -> bool:
        return bool(self.markets) and self.per_lot_max_sats > 0 and self.daily_budget_sats > 0

    def public(self) -> dict:
        return {"enabled": self.enabled, "markets": sorted(self.markets), "per_lot_max_sats": self.per_lot_max_sats,
                "daily_budget_sats": self.daily_budget_sats}


class ForwardBook:
    """Pending and delivered forward purchases, next to the channel book (fsynced JSON)."""

    def __init__(self, path: Path):
        self.path, self.lock = Path(path), threading.RLock()
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {}
        for k in ("pending", "delivered", "void"):
            self.data.setdefault(k, {})

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def spent_since(self, since: float) -> int:
        """Forward spend in the window: delivered lots, plus pending ones (a pre-signature the market
        may still complete counts until it is void)."""
        with self.lock:
            rows = list(self.data["pending"].values()) + list(self.data["delivered"].values())
        return sum(int(r.get("price") or 0) for r in rows if float(r.get("at") or 0) >= since)


class ForwardSession(Xbt402Session):
    def __init__(self, *a, forward_path: Path, policy: ForwardPolicy | None = None, **kw):
        super().__init__(*a, **kw)
        self.fwd = ForwardBook(forward_path)
        self.fpolicy = policy or ForwardPolicy()

    def _route_offer(self, url, method, body, max_sats, expiry_blocks, cap_sats, acc):
        """xbt402's one unpaid request found an offer; a forward lot comes here, anything else stays plain."""
        if isinstance((acc.get("extra") or {}).get("forward"), dict):
            return self._forward(url, method, body, max_sats, expiry_blocks, cap_sats, acc)
        return None

    def _gettxout(self, txid, vout):
        return self.rpc.call("gettxout", txid, vout, False)

    def check_policy(self, dest: str, price: int, now: float | None = None) -> dict | None:
        """None if the forward policy allows this lot, else a deny."""
        p, now = self.fpolicy, time.time() if now is None else now
        if not p.enabled:
            return {"verdict": "deny", "rule": "forward_disabled", "reason": "the forward rail is off in this policy"}
        if normalize_dest(dest) not in p.markets:
            return {"verdict": "deny", "rule": "forward_market", "reason": f"{dest} is not an allowed forward market"}
        if price > p.per_lot_max_sats:
            return {"verdict": "deny", "rule": "forward_lot_max",
                    "reason": f"lot price {price} > per_lot_max_sats {p.per_lot_max_sats}"}
        spent = self.fwd.spent_since(now - DAY_S)
        if spent + price > p.daily_budget_sats:
            return {"verdict": "deny", "rule": "forward_daily_budget",
                    "reason": f"forward spend {spent} + {price} > daily_budget_sats {p.daily_budget_sats}"}
        return None

    def _forward(self, url, method, body, max_sats, expiry_blocks, cap_sats, acc):
        t0 = time.time()
        offer = acc["extra"]["forward"]
        try:
            price = int(acc["amount"])
        except (KeyError, TypeError, ValueError):
            return {"verdict": "deny", "rule": "forward_offer", "reason": "bad_price"}
        if price > max_sats:
            return {"verdict": "deny", "rule": "max_sats", "reason": f"quoted {price} > max_sats {max_sats}"}
        dest = origin_of(url)
        denied = self.check_policy(dest, price, t0)
        if denied:
            return denied
        with self.fwd.lock:
            if dest in self.fwd.data["pending"]:
                return {"verdict": "deny", "rule": "forward_pending",
                        "reason": "a forward purchase on this channel is unsettled; forward_recover first"}
        try:
            lot = verify_offer(offer, self._gettxout, self.hot.spk, price, maturity=self._maturity(offer))
        except ForwardError as e:     # our own check's code, never provider text (L12)
            return {"verdict": "deny", "rule": "forward_offer", "reason": e.code}
        opened = None
        rec = self.book.get(dest)
        if rec is None or rec.state != "open":
            opened = self.open_from_offer(dest, acc, cap_sats=cap_sats, expiry_blocks=expiry_blocks)
            _log("open", url=url, chan=opened["chan"], cap=opened["cap_sats"])
        # AGP-080 W1: the market completes this pre-signature with s alone, so the price is in the
        # ledger before it exists (it used to be booked on delivery)
        self.book.check_signable(dest, price)
        cum = self.book.get(dest).used_sats + price
        if cum < getattr(self.book.get(dest).params(), "min_amount", 546):
            raise ChannelError("bad_amount", "state below the channel's least state")
        self._book_through(dest, cum)
        with self.book._lock:
            rec = self.book._records[dest]
            payer = self.book._payer_locked(rec)
            if cum != rec.used_sats + price:
                raise ChannelError("xbt402", "the channel moved while a forward lot was being signed")
            z = payer.params.sighash(payer.params.state_tx(cum))
            pre = adaptor.presign(payer.secret, z, lot.S)
            self.book.audit.record("adaptor_presig", sig=pre.R + pre.s1.to_bytes(32, "big"), chan=rec.chan, dest=dest,
                                   cum=cum, price_sats=price, outpoint=offer["outpoint"], sighash="0x21",
                                   rule=f"{sigaudit.current().get('rule', 'ok')}+forward")
            rec.seq += 1
            payload = {"chan": rec.chan, "seq": rec.seq, "cum": str(cum), "adaptor": pre.to_json()}
            pend = {"dest": dest, "chan": rec.chan, "cum": cum, "price": price, "prevCum": rec.used_sats,
                    "presig": pre.to_json(), "stateDigest": z.hex(), "offer": offer, "at": round(t0, 3)}
            with self.fwd.lock:                 # write-ahead: the pre-signature exists from here on
                self.fwd.data["pending"][dest] = pend
                self.fwd.save()
            self.book._persist()
        st, _, raw, receipt = self._paid(method, url, body, acc, payload)
        res = {"status": st, "chan": rec.chan, "outpoint": offer["outpoint"], "price_sats": price,
               "deliver_height": lot.deliver, "opened": opened, "rail": "forward"}
        tx = None
        if st == 200:
            try:
                doc = json.loads(raw)
                tx = check_transfer(lot, doc["transfer"])
                y = adaptor.extract(pre, bytes.fromhex(doc.get("stateSig", "")), lot.S)
                if tx is None and y is not None:        # a bad transfer field, but the state reveals s
                    tx = transfer_with(lot, y)
                fr = doc.get("forwardReceipt") or {}
                res["forward_receipt_ok"] = bool(fr) and fr.get("outpoint") == offer["outpoint"] and \
                    becc.verify(bytes.fromhex(offer["marketPub"]), receipt_digest(fr), bytes.fromhex(fr.get("sig", "")))
            except (ValueError, KeyError, TypeError, AttributeError):
                tx = None
        if tx is None:
            _log("forward_pending", url=url, status=st, chan=rec.chan, cum=cum, outpoint=offer["outpoint"])
            return {**res, "charged_sats": 0, "delivered": False,
                    "note": "not delivered: the market can't take this payment without revealing the transfer; "
                            "if it closes the channel with it, forward_recover(close_txid) builds the transfer"}
        self._delivered(dest, tx)
        _log("forward", url=url, chan=rec.chan, cum=cum, chargedSat=price, txid=tx.txid(),
             ms=round(1000 * (time.time() - t0), 1))
        return {**res, "charged_sats": price, "delivered": True, "cum": cum, "transfer_txid": tx.txid(),
                "transfer_hex": tx.hex(), "receipt": receipt}

    def _maturity(self, offer: dict) -> int:
        """AGP-080 M1: the depth at which the node relays a spend of this lot's coinbase, read from the
        node (getdeploymentinfo), never a constant. A node that cannot say refuses the lot."""
        try:
            height = int(offer["coinbaseHeight"])
        except (KeyError, TypeError, ValueError):
            raise ForwardError("bad_offer") from None
        try:
            rule = Maturity.from_deployments(self.rpc.call("getdeploymentinfo"))
        except Exception:                      # noqa: BLE001  the node's answer, or none: fail closed
            raise ForwardError("maturity_unknown") from None
        return rule.relay_at(height) - height

    def _delivered(self, dest: str, tx, via: str = "http"):
        with self.book._lock, self.fwd.lock:
            p = self.fwd.data["pending"].pop(dest)
            rec = self.book._records.get(dest)
            if rec is not None and rec.chan == p["chan"]:
                rec.used_sats = max(rec.used_sats, p["cum"])
                rec.spent_sats = max(rec.spent(), p["cum"])
                self.book._persist()
            else:       # AGP-095: the lot's channel was replaced; the dest's record is another channel
                self.book.raise_archived_used_locked(p["chan"], p["cum"])
            self.fwd.data["delivered"][p["offer"]["outpoint"]] = {
                "txid": tx.txid(), "hex": tx.hex(), "deliverHeight": p["offer"]["deliverHeight"], "price": p["price"],
                "chan": p["chan"], "cum": p["cum"], "via": via, "dest": dest, "at": p.get("at", time.time())}
            self.fwd.save()
        return p

    def forward_recover(self, close_txid: str, blockhash: str = "") -> dict:
        """Read a channel close; if it carries our completed adaptor state, extract s and finish the
        transfer. If it closes with a lower state, the pending purchase is void: nothing was paid."""
        from .netparams import get_tx
        found = get_tx(self.rpc, close_txid, blockhash) or {}       # AGP-017 P6: no txindex needed
        raw = found.get("hex")
        try:
            confirmed = int(found.get("confirmations") or 0) >= 1
        except (TypeError, ValueError):
            confirmed = False
        if not raw:
            raise RuntimeError("close transaction not found in the mempool (pass its block hash on a pruned node)")
        close = FTx.parse(bytes.fromhex(raw))
        spent = {(i.txid[::-1].hex(), i.vout): i for i in close.inputs}
        with self.fwd.lock:
            pend = dict(self.fwd.data["pending"])
        for dest, p in pend.items():
            # AGP-095 (audit item 9), the rule: **a lot belongs to the channel its pre-signature was
            # made on, and is settled by what happens to that channel's funding.** The lookup was by
            # dest, which is the dest's current channel: once the lot's channel was closed and a
            # plain call opened the next one, the close that paid for the lot was answered "closes no
            # channel with a pending forward purchase", and the transfer it carries was never built.
            rec, live = self.book.record_of_chan(p["chan"])
            inp = spent.get((rec.funding_txid, rec.funding_vout)) if rec else None
            if inp is None:
                continue
            lot, pre = lot_from_offer(p["offer"]), adaptor.PreSig.from_json(p["presig"])
            for item in inp.witness:
                y = adaptor.extract(pre, item, lot.S)
                if y is not None:
                    tx = transfer_with(lot, y)
                    if tx is not None:
                        if live:
                            self.book.mark_closed(dest, close_txid)
                        self._delivered(dest, tx, via=f"close {close_txid}")
                        return {"recovered": True, "dest": dest, "outpoint": p["offer"]["outpoint"], "price": p["price"],
                                "chan": p["chan"], "cum": p["cum"],
                                "transfer_txid": tx.txid(), "transfer_hex": tx.hex(), "via": "channel close witness"}
            # AGP-089: a close that does not carry the pre-signature voids the lot only once it is in a
            # block. While it is only in our node's mempool the market can still get another close
            # mined, the one with the completed pre-signature; voiding now would drop the record that
            # recovers the transfer from it, and release a booking the market can still collect.
            if not confirmed:
                return {"recovered": False, "void": False, "unconfirmed": True, "dest": dest, "chan": p["chan"], "cum": p["cum"],
                        "reason": "this close is not in a block yet: the lot stays pending and booked; ask again "
                                  "once a close has confirmed"}
            if live:
                self.book.mark_closed(dest, close_txid)
            with self.fwd.lock:
                self.fwd.data["pending"].pop(dest, None)
                self.fwd.data["void"][p["offer"]["outpoint"]] = {"close": close_txid, "cum": p["cum"], "lot": p}
                self.fwd.save()
            # AGP-095 (audit item 17): what this close, in a block, pays away from us, as a cumulative
            # amount: every output that is not our change, plus the close fee where the payee's output
            # carries it. A state other than the lot's may have closed the channel (a stream's
            # hash-locked last chunk, a routed lock), and the release of the lot's booking must leave
            # what it was paid.
            paid = sum(int(o.value) for o in close.outputs if o.script_pubkey.hex() != rec.payer_spk)
            if rec.close_fee_payer == "payee":
                paid += int(rec.close_fee)
            return {"recovered": False, "dest": dest, "void": True, "chan": p["chan"], "cum": p["cum"], "paid": paid,
                    "reason": "the close does not carry the adaptor state: the lot was not paid for"}
        return {"recovered": False, "reason": "the transaction closes no channel with a pending forward purchase"}

    def status(self) -> dict:
        with self.fwd.lock:
            pending = {d: {"chan": p["chan"], "cum": p["cum"], "price": p["price"], "outpoint": p["offer"]["outpoint"]}
                       for d, p in self.fwd.data["pending"].items()}
            delivered = {op: {k: v for k, v in d.items() if k != "hex"} for op, d in self.fwd.data["delivered"].items()}
        return {"policy": self.fpolicy.public(), "spent_24h_sats": self.fwd.spent_since(time.time() - DAY_S),
                "pending": pending, "delivered": delivered}
