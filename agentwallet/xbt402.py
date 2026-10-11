"""xbt402_pay inside the signer: B1 wire helpers, B2 keys.

XBT-060's client SDK should call the same socket methods (`fund`, `sign_state`,
`xbt402_pay`, `close_channel`) so the model never sees a payer secret.

Streamed results (`stream: xbt402-merkle-v1`) are bought here: signed Merkle
manifest, verify-then-pay per chunk, hash-locked last chunk. The MCP response
stores the full body and returns a digest + path (no 500-character cut).
The provider's body and receipt are returned verbatim under `untrusted_provider_response`
(labelled untrusted, not key-filtered: XBT-061 L7); only the tool's own fields are sanitized.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

from . import netparams
from .b1path import ensure_b1
from .chain import spend_is_evidence
from .channels import ChannelBook, ChannelCapError, booked_through, fee_payer_kw
from .hot import HotWallet
from .rpc import KnotsRpcRefused
from .sanitize import UNTRUSTED_KEY, untrusted
from .stream import H, StreamError, check_chunk, check_manifest, open_final

ensure_b1()
from xbt402 import ecc  # noqa: E402
from xbt402.channel import DERIVATION, ChannelError, ChannelParams, SIGHASH_ALL_UNIFIED  # noqa: E402
from xbt402.conditional import ConditionalParams, preimage_from_tx  # noqa: E402
from xbt402.x402_channel import (  # noqa: E402
    FACILITATOR_VERIFY,
    SCHEME,
    XbtChannelClient,
    b64json,
    facilitator_request,
    network_id,
    body_hash,
    receipt_message,
    receipt_of,
    request_digest_v2,
    safe_code,
    unb64json,
)

# Inline preview. Streamed results are always stored in full (digest + path).
# 500 was too small for a real analytics JSON; 12k covers the catalog answers.
BODY_CAP = int(os.environ.get("B2_BODY_CAP", "12000"))
PREVIEW_CAP = 2048
# AGP-085: a funding whose broadcast failed without the node refusing it
FUNDING_KEPT = ("the funding may have reached the node, so the channel stays pending: its funding is sent "
                "again by the watcher, and it is opened or refunded at expiry")


def origin_of(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        raise ValueError("xbt402_pay needs an absolute URL")
    return f"{p.scheme}://{p.netloc}"


def same_origin_url(dest: str, value) -> str:
    """AGP-080 X1: where the seller says its open or its chunks are, held to the origin the policy
    allowed. `dest + value` let `@evil.example/open` name another host. Accepted: a path starting with
    exactly one `/`, or an absolute URL on `dest`'s own origin; no backslash, whitespace or control
    character either way. Anything else is refused before a request is made."""
    def refuse():
        return ChannelError("seller_url", "the seller's URL is not on its own origin; refused before any request")
    if not isinstance(value, str) or not value:
        raise refuse()
    if any(c == "\\" or c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise refuse()
    if value.startswith("/") and not value.startswith("//"):
        return dest + value
    try:
        same = "://" in value and origin_of(value) == dest
    except ValueError:
        same = False
    if not same:
        raise refuse()
    return value


def pick_accept(pr: dict, network: str) -> dict:
    for acc in pr.get("accepts") or []:
        # SCHEME is batch-settlement on B1 agp-050+; xbt-channel is the one-release alias.
        if acc.get("scheme") in (SCHEME, "batch-settlement", "xbt-channel") and acc.get("network") == network:
            return acc
    raise RuntimeError("no batch-settlement offer on this network")


def open_expiry_blocks(want: int, min_expiry: int, max_expiry: int, min_conf: int, close_margin: int) -> int:
    """Blocks to expiry for a new channel: what the wallet wants, at least `minExpiryBlocks + minConf +
    closeMarginBlocks`, at most `maxExpiryBlocks - 1`; every term is the offer's (AGP-076; the same
    rule as xbt-rs `xbt402::funding::open_expiry_blocks`).

    The provider checks `left >= minExpiryBlocks` at its tip when the funded open reaches it, not at
    our tip now. In between the funding has to get `minConf` confirmations, and it may wait for the
    first one. So we add `minConf`, plus the time the provider itself allows a transaction to confirm
    on this chain: `closeMarginBlocks`, how long before expiry it broadcasts its close. A funding
    that takes longer would be refused bad_expiry on every retry, with the coins locked until the
    refund. No provider check reads the margin; it is only our allowance. An offer whose window is
    narrower than that gets the top of its window: the open preflight answers before anything is funded."""
    return max(0, min(max(want, min_expiry + min_conf + close_margin), max_expiry - 1))


def refuse_fragment(url) -> None:
    """review T2 (AGP-081): the request digest drops everything from `#`, and a server routes on the
    target as it arrives, so a payment for `/a` would also authenticate `/a#b`. The digest stays as
    published; the payer refuses a URL with a `#` before anything is signed, funded or sent."""
    if "#" in str(url):
        raise ChannelError("bad_request", "the URL has a '#' fragment, which a payment cannot be bound to; "
                                           "refused before any request")


def charged_of(resp, default: int) -> int:
    """`charged` of the channel receipt inside a PAYMENT-RESPONSE SettlementResponse (xbt402 v1.1)."""
    try:
        return int(receipt_of(resp)["charged"])
    except (ChannelError, KeyError, TypeError, ValueError):
        return default


def _log(kind, **kw):
    path = os.environ.get("B2_CALLS_JSONL")
    if not path:
        return
    with open(path, "a") as f:
        f.write(json.dumps({"t": round(time.time(), 3), "kind": kind, **kw}) + "\n")


def _store_body(raw: bytes, name: str) -> dict:
    """Persist a body; return digest + path. Never truncate the stored bytes."""
    digest = hashlib.sha256(raw).hexdigest()
    root = os.environ.get("B2_BODY_DIR")
    if not root:
        return {"body_digest": digest, "bytes": len(raw)}
    os.makedirs(root, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:80] or digest[:16]
    path = os.path.join(root, f"{safe}.bin")
    Path(path).write_bytes(raw)
    return {"body_digest": digest, "saved_to": path, "bytes": len(raw)}


def max_expiry_blocks(channel_expiry_blocks: int) -> int:
    """The longest a channel's coins may be locked, in blocks from now (AGP-063 W3, AGP-089): the
    policy's channel_expiry_blocks, but at least four weeks so a provider's minimum fits. Every path
    that funds a channel holds the expiry to this, whoever named it (a seller's offer too)."""
    return max(int(channel_expiry_blocks), 4032)


# AGP-089: the longest a stream's last chunk may stay hash-locked on the seller's word (four weeks)
MAX_COND_CSV_BLOCKS = 4032


def _count(v, what: str, least: int = 0) -> int:
    """A counterparty's number that must be a whole number of at least `least` (AGP-089, review W1):
    not a bool, a float, a string or a negative that Python would multiply or compare all the same."""
    if type(v) is not int or v < least:
        raise StreamError(f"{what} is not a whole number of at least {least}")
    return v


class CallBudget:
    """What one xbt402_pay may sign (AGP-089, review W1). The rule: a call never raises what its
    channel's ledger holds by more than the max_sats the policy approved for it, whatever the
    seller's numbers are (its receipt's `charged` included: that is a report, never a budget).
    `start` is the ledger when the call began; every state after the call's first is checked here
    before it is signed."""

    def __init__(self, start: int, max_sats: int):
        self.start, self.max_sats = int(start), int(max_sats)

    def fits(self, cum: int) -> bool:
        return int(cum) - self.start <= self.max_sats

    def left(self, signed: int) -> int:
        return self.max_sats - (int(signed) - self.start)


class Xbt402Session:
    """One signer-owned client session: channels keyed by HTTP origin.

    AGP-017: `chain` is the node's chain (netparams). The network id comes from the spec's anchor
    (block 961640 on mainnet, P4); a mining hook is refused on any chain but regtest (P3); a channel
    is recorded before its funding is broadcast and opened only once the funding has the offer's
    minConf (P1, P2)."""

    OPEN_POLL_S = 2.0

    def __init__(self, book: ChannelBook, hot: HotWallet, rpc, height, mine=None, *, chain: str = "regtest",
                 open_wait_s: float = 45, close_fee_max: int = 0, refund_margin: int = 6):
        if mine is not None and not netparams.mining_allowed(chain):
            raise netparams.ChainError(f"a mining hook on {chain!r}: only regtest may mine")
        self.book = book
        self.hot = hot
        self.rpc = rpc
        self.height = height
        self.mine = mine
        self.chain = chain
        self.open_wait_s = float(open_wait_s)
        self.close_fee_max = int(close_fee_max or 0)
        self.refund_margin = int(refund_margin)
        self._net = None
        self._spend_book = None
        self._spend_check = None

    def set_spend_book(self, book) -> None:
        """AGP-063: commit a signed increase before the signature is sent. `book(dest, delta, chan, cum)`."""
        self._spend_book = book

    def set_spend_check(self, check) -> None:
        """AGP-063 W1: the policy's verdict on a signed increase above max_sats (a channel's dust floor).
        `check(dest, max_sats, delta)` returns a deny dict, which stops the call before anything is signed."""
        self._spend_check = check

    def network(self) -> str:
        if self.chain != "regtest":
            if self._net is None:            # a wrong anchor block raises: never pay on a network we can't name
                self._net = netparams.network(self.rpc, self.chain)
            return self._net
        try:
            return netparams.network(self.rpc, self.chain, tip=self.height())
        except Exception:
            return network_id("0" * 64)

    def open_from_offer(self, dest: str, acc: dict, cap_sats: int, expiry_blocks: int) -> dict:
        """Fund a channel for this offer and open it. Returns the channel's public record, or one with
        state "pending" when the funding has not reached the offer's minConf within `open_wait_s`."""
        extra = acc.get("extra") or {}
        if extra.get("derivation") != DERIVATION:  # checked before funding: a mismatch strands the coins
            # no provider text in the wallet's own errors: the model reads them unlabelled (AGP-005 L12)
            raise RuntimeError(f"provider channel binding (extra.derivation) is not {DERIVATION!r}; refused before funding")
        close_fee = int(extra.get("closeFeeSat") or 600)
        if close_fee < 0:
            raise RuntimeError("offer closeFeeSat is negative; refused before funding")
        # the cap holds under payee-pays too: the least state is dust + closeFeeSat (xbt402 v1.2)
        if self.close_fee_max and close_fee > self.close_fee_max:
            raise RuntimeError(f"offer closeFeeSat {close_fee} is above this wallet's cap {self.close_fee_max}; "
                               "refused before funding")
        fee_payer = extra.get("closeFeePayer", "payer")
        if fee_payer not in ("payer", "payee"):
            raise RuntimeError("offer closeFeePayer is neither payer nor payee; refused before funding")
        # payer-pays: we fund our close fee on top of the cap; payee-pays: the payee's output carries it
        payer_fee = close_fee if fee_payer == "payer" else 0
        # min/maxCapacity bound the funding output (B1 check_funding), which is cap + our close fee.
        # AGP-017: comparing the cap alone funded 10,600 for a 10,000-only offer, which the provider refuses.
        min_cap = int(extra.get("minCapacity") or 0)
        max_cap = int(extra.get("maxCapacity") or (cap_sats + payer_fee))
        # AGP-063 W2: the seller's minCapacity must not raise the owner's per-channel cap.
        owner_funded = cap_sats + payer_fee
        if min_cap > owner_funded:
            raise ChannelError("min_capacity",
                               f"offer minCapacity {min_cap} exceeds this wallet's per-channel cap {owner_funded}")
        cap = cap_sats
        if cap + payer_fee > max_cap:
            raise RuntimeError(f"channel capacity {cap + payer_fee} above provider max {max_cap}")
        min_exp = int(extra.get("minExpiryBlocks") or 1)
        max_exp = int(extra.get("maxExpiryBlocks") or 100_000)
        try:
            min_conf = max(0, int(extra.get("minConf", 1)))
        except (TypeError, ValueError):
            min_conf = 1
        try:
            margin = int(extra["closeMarginBlocks"])
        except (KeyError, TypeError, ValueError):
            margin = -1
        if margin < 0:
            raise RuntimeError("offer closeMarginBlocks is missing or not a block count; refused before funding")
        # AGP-089 (review C2): these three are the seller's numbers and they decide how long the owner's
        # coins are locked if the seller then never opens or closes the channel. The owner's bound holds
        # here as on the socket's open_channel; refused before the preflight.
        most = max_expiry_blocks(expiry_blocks)
        floor = max(0, min_exp) + min_conf + margin
        if floor > most:
            raise ChannelError("expiry", f"the offer needs the channel locked for {floor} blocks (minExpiryBlocks + minConf "
                                         f"+ closeMarginBlocks); this wallet locks a channel for at most {most}; "
                                         "refused before funding")
        blocks = open_expiry_blocks(expiry_blocks, min_exp, max_exp, min_conf, margin)
        if not 0 < blocks <= most:
            raise ChannelError("expiry", "offer expiry window is not a block count this wallet accepts")
        check = getattr(self.hot, "check_channel_funding", None)
        if check is not None:  # AGP-013: above the hot-balance cap, a human sweeps before new channels
            check()
        open_height = self.height()
        expiry = open_height + blocks
        secret, payer_pub = self.book.new_payer_key()
        # Change at close returns to the signer's hot key, not the per-channel payer key.
        params = ChannelParams.derive(acc["payTo"], payer_pub, expiry, close_fee, self.hot.spk.hex(),
                                      network=acc["network"], **fee_payer_kw(fee_payer))
        funded = cap + payer_fee
        open_url = same_origin_url(dest, extra.get("openUrl", "/x402/xbt-channel/open"))
        self._preflight(open_url, acc["network"], params, funded, fee_payer)
        prep = self.hot.prepare_fund(params.spk, funded)
        params.funding_txid, params.funding_vout, params.capacity = prep["txid"], 0, funded
        # P1 write-ahead: the payer key is sealed on disk, with everything the refund needs, before
        # the funding exists anywhere but here
        self.book.add_pending(dest, secret=secret, params=params, origin=dest, cap_sats=cap,
                              open_height=open_height, open_url=open_url,
                              network=acc["network"], min_conf=min_conf, funding_hex=prep["hex"])
        try:
            self.hot.broadcast(prep)
        except KnotsRpcRefused:
            # the node's own refusal, and it has no such output: the funding exists nowhere but here
            self.book.drop_pending(dest, params.channel_id)
            raise
        except Exception as e:
            # AGP-085: any other failure may have left the funding on the node. The record and its key
            # stay; the watcher sends the funding again, opens the channel or refunds it at expiry
            self.hot.commit(prep)
            self.book.note_pending(dest, open_error=f"funding broadcast unconfirmed: {type(e).__name__}")
            _log("funding_unconfirmed", dest=dest, chan=params.channel_id, txid=prep["txid"], capacity=funded)
            raise RuntimeError(f"{FUNDING_KEPT}: {e}") from e
        self.hot.commit(prep)
        _log("funding", dest=dest, chan=params.channel_id, txid=prep["txid"], capacity=funded, expiry=expiry,
             min_conf=min_conf)
        return self.complete_open(dest, wait_s=self.open_wait_s)

    def _preflight(self, open_url: str, network: str, params: ChannelParams, funded: int, fee_payer: str) -> None:
        """review C2: the provider says it opens a channel on exactly these terms before the funding
        exists (a refusal after funding locks the coins until expiry). A provider from before the
        preflight answers bad_request (no outpoint) once the terms it checks first have passed."""
        channel = {"capacity": funded, "expiry": params.expiry, "payerPub": params.payer_pub,
                   "payerSpk": params.payer_spk, "redeemScript": params.script.hex(),
                   **({"closeFeePayer": fee_payer} if fee_payer != "payer" else {})}
        body = {"x402Version": 2, "network": network, "preflight": True, "channel": channel}
        try:
            st, _, out = XbtChannelClient.http("POST", open_url, json.dumps(body).encode(),
                                               {"Content-Type": "application/json"})
        except Exception as e:
            raise RuntimeError(f"open preflight failed: provider unreachable ({type(e).__name__}); "
                               "nothing was funded") from None
        try:
            reply = json.loads(out)
        except ValueError:
            reply = None
        if st != 200:
            code = reply.get("error", "") if isinstance(reply, dict) else ""
            code = code if safe_code(code) else ""     # no provider text in the wallet's errors (L12)
            if code == "bad_request":
                return
            raise RuntimeError(f"open refused before funding: HTTP {st}{' ' + code if code else ''}; "
                               "nothing was funded")
        if not isinstance(reply, dict) or reply.get("preflight") is not True:
            raise RuntimeError("the provider did not answer the open preflight; nothing was funded")
        if reply.get("closeFeePayer", "payer") != fee_payer:
            raise RuntimeError("the provider would open the channel with another closeFeePayer; nothing was funded")

    def funding_confirmations(self, rec) -> int | None:
        """Confirmations of a channel's funding output; None when the node does not have it at all."""
        r = self.rpc.call("gettxout", rec.funding_txid, int(rec.funding_vout), True)
        return None if not r else int(r.get("confirmations") or 0)

    def complete_open(self, dest: str, wait_s: float = 0) -> dict:
        """P2: post a pending channel's open once its funding has `min_conf` confirmations (waiting up
        to `wait_s`), and mark it open when the provider accepts it (`duplicate_channel` counts: the
        provider already has it). Otherwise it stays pending, and the watcher retries or refunds it."""
        rec = self.book.get(dest)
        if rec is None or rec.state != "pending":
            return rec.public() if rec else {}
        if rec.open_url:                               # a record from before AGP-080 may hold one off the origin
            same_origin_url(rec.origin or dest, rec.open_url)
        confs = self.funding_confirmations(rec)
        if confs is None and rec.funding_hex:          # never reached the node, or was evicted: send it again
            try:
                self.rpc.call("sendrawtransaction", rec.funding_hex)
                confs = 0
            except Exception:
                pass
        if confs is not None and confs < rec.min_conf and self.mine:
            self.mine(rec.min_conf - confs)            # regtest only (P3)
            confs = self.funding_confirmations(rec)
        deadline = time.time() + max(0.0, wait_s)
        while (confs is None or confs < rec.min_conf) and time.time() < deadline:
            time.sleep(min(self.OPEN_POLL_S, max(0.05, deadline - time.time())))
            confs = self.funding_confirmations(rec)
        if confs is None or confs < rec.min_conf:
            return {**rec.public(), "confirmations": confs or 0, "min_conf": rec.min_conf}
        if confs >= 1 and not rec.funding_height:
            where = netparams.block_of(self.rpc, rec.funding_txid, rec.funding_vout)
            if where:
                self.book.note_pending(dest, funding_height=where[0])
        if self.height() >= rec.expiry - self.refund_margin:
            self.book.note_pending(dest, open_error="too close to expiry to open; refunded at expiry")
            return {**self.book.get(dest).public(), "confirmations": confs, "min_conf": rec.min_conf}
        if not rec.open_url:
            # the signer's own rail has no provider open: the channel is open once the node has its funding
            opened = self.book.mark_open(dest)
            _log("opened", dest=dest, chan=opened.chan, confirmations=confs, duplicate=False)
            return {**opened.public(), "confirmations": confs}
        body = {
            "x402Version": 2,
            "network": rec.network,
            "channel": {
                "txid": rec.funding_txid,
                "vout": rec.funding_vout,
                "capacity": rec.funding_sats,
                "expiry": rec.expiry,
                "payerPub": rec.payer_pub,
                "payerSpk": rec.payer_spk,
                "redeemScript": rec.params().script.hex(),
                **({"closeFeePayer": rec.close_fee_payer} if rec.close_fee_payer != "payer" else {}),
            },
        }
        try:
            st, _, out = XbtChannelClient.http("POST", rec.open_url, json.dumps(body).encode(),
                                               {"Content-Type": "application/json"})
        except Exception as e:
            self.book.note_pending(dest, open_error=f"open unreachable: {type(e).__name__}")
            raise RuntimeError(f"open failed: provider unreachable ({type(e).__name__}); the channel stays "
                               "pending: retried by the watcher, refunded at expiry if never opened")
        code = ""
        if st != 200:
            try:
                code = json.loads(out).get("error", "")
            except (ValueError, AttributeError):
                code = ""
            code = code if safe_code(code) else ""     # no provider text in the wallet's errors (L12)
        if st == 200:
            try:
                echoed = json.loads(out).get("closeFeePayer", "payer")
            except (ValueError, AttributeError):
                echoed = None
            if echoed != rec.close_fee_payer:
                # the provider would refuse every state we sign: never mark it open (refunded at expiry)
                self.book.note_pending(dest, open_error="open refused: provider opened another closeFeePayer")
                raise RuntimeError("open failed: the provider did not take the offer's closeFeePayer; the channel "
                                   "stays pending and is refunded at expiry")
        if st == 200 or code == "duplicate_channel":
            opened = self.book.mark_open(dest)
            _log("opened", dest=dest, chan=opened.chan, confirmations=confs, duplicate=st != 200)
            return {**opened.public(), "confirmations": confs}
        self.book.note_pending(dest, open_error=f"open refused: HTTP {st}{' ' + code if code else ''}")
        raise RuntimeError(f"open failed: HTTP {st}{' ' + code if code else ''}; the channel stays pending: "
                           "retried by the watcher, refunded at expiry if never opened")

    def _with_auth(self, payload: dict, method: str, url: str, body: bytes) -> dict:
        """H3: bind this payload to (method, URL, body): scheme, host, port and target, length-prefixed
        (xbt402 v1.3, AGP-068). The ECDH key stays in the book."""
        refuse_fragment(url)                   # every paid request passes here; the callers refuse it earlier
        pl = dict(payload)
        req = request_digest_v2(method, url, body or b"")
        pl["auth"] = self.book.request_auth(pl["chan"], pl["seq"], pl["cum"], pl.get("sig"), req)
        return pl

    def _paid(self, method, url, body, acc, payload):
        payload = self._with_auth(payload, method, url, body or b"")
        hdr = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc, "payload": payload})}
        st, hdrs, out = XbtChannelClient.http(method, url, body or b"", hdr)
        h = {k.upper(): v for k, v in hdrs.items()}
        return st, h, out, unb64json(h["PAYMENT-RESPONSE"]) if "PAYMENT-RESPONSE" in h else None

    @staticmethod
    def _booked_through(rec) -> int:
        """Sats of this channel already in the policy ledger. -1 means a pre-AGP-063 record."""
        return booked_through(rec)

    def _book_through(self, dest: str, cum: int) -> int:
        """AGP-080: commit what a state worth `cum` adds to the channel's booked high-water mark, before
        that state is signed (a hash lock, a forward lot's pre-signature: states that do not move
        used_sats until they settle). Idempotent on xbt402:{chan}:{cum}. Returns the sats committed."""
        rec = self.book.get(dest)
        if rec is None:
            raise ChannelError("unknown_channel", dest)
        delta = int(cum) - self._booked_through(rec)
        if delta <= 0:
            return 0
        if self._spend_book is None:
            raise ChannelError("xbt402", "signed increase has no ledger booking")
        self._spend_book(dest, delta, rec.chan, int(cum))
        self.book.mark_ledger_booked(dest, int(cum))
        return delta

    def _book_unbooked(self, dest: str) -> int:
        """Commit any signed amount the ledger does not yet hold. Idempotent on xbt402:{chan}:{cum}."""
        rec = self.book.get(dest)
        if rec is None:
            return 0
        delta = rec.used_sats - self._booked_through(rec)
        if delta <= 0:
            return 0
        if self._spend_book is None:
            raise ChannelError("xbt402", "signed increase has no ledger booking")
        self._spend_book(dest, delta, rec.chan, rec.used_sats)
        self.book.mark_ledger_booked(dest, rec.used_sats)
        return delta

    @staticmethod
    def receipt_for_state(rec, resp) -> tuple[dict, int]:
        """The payee's own word that it has the state `rec` was just sent with (AGP-089, review T4): a
        receipt it signed, for this channel and for the seq of this request, with a cum no higher than
        the one signed. `rec` is the record as the request left with it. A receipt for an earlier seq
        is an earlier answer played again: the seller never saw this request. Returns (receipt, cum)."""
        if not isinstance(resp, dict):
            raise ChannelError("bad_receipt", "PAYMENT-RESPONSE is not a settlement response")
        r = receipt_of(resp)
        if str(r.get("chan")) != rec.chan:
            raise ChannelError("bad_receipt", "receipt is for another channel")
        if str(r.get("seq")) != str(rec.seq):
            raise ChannelError("bad_receipt", "receipt is for another request of this channel (its seq is not this call's)")
        try:
            cum = int(r["cum"])
        except (KeyError, TypeError, ValueError):
            raise ChannelError("bad_receipt", "receipt cum is not an integer")
        if cum < 0 or cum > rec.used_sats:
            raise ChannelError("bad_receipt", "receipt cum is above the amount this wallet signed")
        try:
            sig = bytes.fromhex(r.get("sig") or "")
            payee = bytes.fromhex(rec.payee_pub)
        except (TypeError, ValueError):
            raise ChannelError("bad_receipt", "receipt signature is not hex")
        if not ecc.verify(payee, receipt_message(r), sig):
            raise ChannelError("bad_receipt", "receipt not signed by the channel payee key")
        return r, cum

    @staticmethod
    def check_seller_receipt(rec, resp, method: str, url: str, body: bytes, answer: tuple, quote: int) -> int:
        """The seller's receipt: signature, seq, request and answer binding, and a charged that is not
        negative and not above the quote. The number itself is never what the wallet books."""
        r, _ = Xbt402Session.receipt_for_state(rec, resp)
        if str(r.get("req")) != request_digest_v2(method, url, body or b""):
            raise ChannelError("bad_receipt", "receipt is for another request")
        status, answer_body = answer
        if str(r.get("status")) != str(status) or str(r.get("bodyHash")) != body_hash(answer_body or b""):
            raise ChannelError("bad_receipt", "receipt is for another answer (status or body differs)")
        try:
            charged = int(r["charged"])
        except (KeyError, TypeError, ValueError):
            raise ChannelError("bad_receipt", "charged is not an integer")
        if charged < 0:
            raise ChannelError("bad_receipt", "negative charged")
        if charged > quote:
            raise ChannelError("bad_receipt", f"charged {charged} exceeds the quoted price {quote}")
        return charged

    def pay_once(self, url: str, method: str, body: bytes, max_sats: int, expiry_blocks: int, cap_sats: int) -> dict:
        """One call. The provider's body and receipt come back only under UNTRUSTED_KEY (L7)."""
        res = self._pay_once(url, method, body, max_sats, expiry_blocks, cap_sats)
        if "body" in res or "receipt" in res:
            res[UNTRUSTED_KEY] = untrusted(res.pop("body", ""), res.pop("receipt", None))
        return res

    def _pay_once(self, url: str, method: str, body: bytes, max_sats: int, expiry_blocks: int, cap_sats: int) -> dict:
        refuse_fragment(url)
        dest = origin_of(url)
        t0 = time.time()
        st, hdrs, out = XbtChannelClient.http(method, url, body or b"")
        if st != 402:
            preview = out.decode("utf-8", "replace")[:BODY_CAP]
            stored = _store_body(out, f"free-{int(t0)}") if len(out) > BODY_CAP else {}
            _log("call", url=url, status=st, ms=round(1000 * (time.time() - t0), 1), chargedSat=0, chan=None)
            return {
                "status": st,
                "charged_sats": 0,
                "body": preview,
                "note": "no 402 (already free or error)",
                **stored,
            }
        pr = unb64json(hdrs["PAYMENT-REQUIRED"])
        acc = pick_accept(pr, self.network())
        routed = self._route_offer(url, method, body, max_sats, expiry_blocks, cap_sats, acc)
        if routed is not None:  # another rail (forward) took the offer; the 402 above is its only unpaid call
            return routed
        price = int(acc["amount"])
        if price > max_sats:
            return {"verdict": "deny", "rule": "max_sats", "reason": f"quoted {price} > max_sats {max_sats}"}
        if price == 0:
            preview = out.decode("utf-8", "replace")[:BODY_CAP]
            stored = _store_body(out, f"free-{int(t0)}") if len(out) > BODY_CAP else {}
            _log("call", url=url, status=st, ms=round(1000 * (time.time() - t0), 1), chargedSat=0, chan=None)
            return {
                "status": st,
                "charged_sats": 0,
                "body": preview,
                "note": "zero-priced offer; no channel",
                **stored,
            }
        rec = self.book.get(dest)
        opened = None
        if rec is None or rec.state != "open":  # a closed or refunded channel is replaced by a new one
            t1 = time.time()
            if rec is not None and rec.state == "pending":     # funded earlier, not yet open (P1, P2)
                rec_pub = self.complete_open(dest, wait_s=self.open_wait_s)
            else:
                rec_pub = self.open_from_offer(dest, acc, cap_sats=cap_sats, expiry_blocks=expiry_blocks)
            rec = self.book.get(dest)
            if rec.state == "pending":
                return {"verdict": "pending", "rule": "funding_unconfirmed", "chan": rec.chan,
                        "funding_txid": rec.funding_txid, "confirmations": rec_pub.get("confirmations", 0),
                        "min_conf": rec.min_conf, "charged_sats": 0,
                        "reason": "channel funded; its open waits for the funding to confirm. Call again later: "
                                  "the watcher also opens it, and refunds it at expiry if it never opens"}
            opened = {**rec_pub, "funding_txid": rec.funding_txid, "funding_sats": rec.funding_sats}
            _log("open", url=url, chan=rec.chan, txid=rec.funding_txid, capacity=rec.funding_sats,
                 cap=rec.cap_sats, ms=round(1000 * (time.time() - t1), 1))
        rec = self.book.get(dest)
        ledger_before = self._booked_through(rec)
        if rec is not None and rec.last_sig and rec.used_sats > rec.acked_sats:
            rec, sig = self.book.resend_state(dest)   # same (cum, sig); do not sign a higher one (M3)
        else:
            nxt = self.book.next_cum(dest, price)
            if nxt - ledger_before > max_sats and self._spend_check is not None:
                refused = self._spend_check(dest, max_sats, nxt - ledger_before)
                if refused:
                    return refused
            rec, sig = self.book.increment(dest, price)
        # AGP-063 W1: book the signed increase before the signature leaves. Never the seller's charged.
        booked = self._book_unbooked(dest)
        payload = {"chan": rec.chan, "seq": rec.seq, "cum": str(rec.used_sats)}
        if sig:
            payload["sig"] = sig.hex() if isinstance(sig, bytes) else sig
        st2, _, out2, receipt = self._paid(method, url, body, acc, payload)
        # AGP-089 (review T4): the state counts as arrived only on the payee's signature over this
        # request's seq. Any other PAYMENT-RESPONSE (none, one for an earlier request, one someone on
        # the path made up) leaves it unacked, so the next call sends the same state again and signs
        # nothing higher.
        sent = self.book.get(dest)
        try:
            _, acked = self.receipt_for_state(sent, receipt)
        except (ChannelError, ValueError, TypeError, KeyError, AttributeError):
            acked = None
        if acked is not None:
            self.book.ack_state(dest, acked)
        if st2 < 400:
            if not receipt:
                raise ChannelError("bad_receipt", "paid call returned no receipt")
            charged = self.check_seller_receipt(sent, receipt, method, url, body or b"", (st2, out2), price)
        else:
            charged = 0
        _log("call", url=url, status=st2, ms=round(1000 * (time.time() - t0), 1), chargedSat=charged,
             chan=rec.chan, cum=rec.used_sats, opened=bool(opened))
        preview = out2.decode("utf-8", "replace")[:BODY_CAP]
        stored = _store_body(out2, f"{rec.chan[:12]}-{rec.seq}") if len(out2) > BODY_CAP else {}
        res = {
            "status": st2,
            "charged_sats": charged,
            "booked_sats": booked,
            "receipt": receipt,
            "chan": rec.chan,
            "cum": rec.used_sats,
            "opened": opened,
            "body": preview,
            **stored,
        }
        try:
            doc = json.loads(out2)
        except ValueError:
            return res
        if st2 == 200 and isinstance(doc, dict) and doc.get("stream") == "xbt402-merkle-v1":
            res["receipt_scope"] = "manifest call only; chunk payments are in stream.paid_sats"
            res.update(self.stream(dest, acc, doc, CallBudget(ledger_before, max_sats)))
            res["charged_sats"] = charged + res.pop("stream_charged")
            after = self.book.get(dest)
            res["booked_sats"] = self._booked_through(after) - ledger_before
        return res

    def _route_offer(self, url, method, body, max_sats, expiry_blocks, cap_sats, acc):
        """Hook for rails that buy something other than an HTTP response (forward.py). None = plain call."""
        return None

    def stream(self, dest, acc, doc, budget):
        m, t0 = doc["manifest"], time.time()
        out = {"stream_charged": 0}
        try:
            check_manifest(m, acc["payTo"])
            refuse_fragment(doc.get("chunkUrl"))    # the seller's URL for every chunk, the hash-locked last one too
        except (StreamError, ChannelError) as e:
            return {**out, "stream": {"ok": False, "refused": str(e)}}
        if not isinstance(budget, CallBudget):       # a caller with a plain amount left: from where the channel is
            budget = CallBudget(self._signed_through(dest), budget)
        try:
            n, price = _count(m.get("n"), "manifest n", 1), _count(m.get("price"), "manifest price", 0)
        except StreamError as e:
            return {**out, "stream": {"ok": False, "refused": str(e)}}
        # AGP-089: the last state of the stream is signed + n * price, and it must be inside the call's budget
        signed = self._signed_through(dest)
        if not budget.fits(signed + n * price):
            return {
                **out,
                "stream": {
                    "ok": False,
                    "refused": f"result costs {n} x {price} sat more; max_sats leaves {budget.left(signed)}",
                },
                "body": "",
            }
        try:
            chunk_url = same_origin_url(dest, doc.get("chunkUrl"))
        except ChannelError as e:
            return {**out, "stream": {"ok": False, "refused": f"chunkUrl: {e}"}, "body": ""}
        parts, spent = [], 0
        for i in range(m["n"] - 1):
            url = chunk_url.replace("{i}", str(i))
            rec = self.book.fresh_seq(dest)
            t = time.time()
            st, _, raw, receipt = self._paid("GET", url, b"", acc, {"chan": rec.chan, "seq": rec.seq, "cum": str(rec.used_sats)})
            try:
                if st != 200:
                    raise StreamError(f"chunk {i}: HTTP {st}")
                data = check_chunk(m, json.loads(raw))
            except StreamError as e:
                charged = charged_of(receipt, 0)
                _log("refused_chunk", i=i, reason=str(e), refusedSat=charged, chan=rec.chan, url=url)
                return {
                    **out,
                    "stream_charged": spent,
                    "body": "",
                    "stream": {
                        "ok": False,
                        "id": m["id"],
                        "refused_chunk": i,
                        "reason": str(e),
                        "verified_chunks": i,
                        "paid_sats": spent,
                        "unpaid_refused_sats": charged,
                        "note": "the wallet never signed a state paying for the bad chunk; buying stopped",
                    },
                }
            parts.append(data)
            nxt = self.book.next_cum(dest, m["price"])
            if not budget.fits(nxt):        # refused before signing: nothing was paid for this chunk
                return {**out, "stream_charged": spent, "body": "",
                        "stream": {"ok": False, "id": m["id"], "refused_chunk": i, "verified_chunks": i, "paid_sats": spent,
                                   "reason": f"the next state signs {nxt} sat; max_sats does not cover it"}}
            rec, sig = self.book.increment(dest, m["price"])
            self._book_unbooked(dest)
            self._verify_post(dest, acc, {"chan": rec.chan, "cum": str(rec.used_sats), "sig": sig.hex()})
            spent += m["price"]
            _log("chunk", i=i, ms=round(1000 * (time.time() - t), 1), chargedSat=m["price"], chan=rec.chan, cum=rec.used_sats)
        try:
            pt, cond_ms = self._final_chunk(dest, doc, m, budget)
        except (StreamError, ValueError, KeyError) as e:
            _log("refused_chunk", i=m["n"] - 1, reason=str(e), refusedSat=0, chan=self.book.get(dest).chan)
            return {
                **out,
                "stream_charged": spent,
                "body": "",
                "stream": {
                    "ok": False,
                    "id": m["id"],
                    "refused_chunk": m["n"] - 1,
                    "reason": str(e),
                    "verified_chunks": m["n"] - 1,
                    "paid_sats": spent,
                },
            }
        spent += m["price"]
        report = b"".join(parts) + pt
        stored = _store_body(report, m["id"])
        path = stored.get("saved_to")
        if path and path.endswith(".bin"):
            md = path[:-4] + ".md"
            os.replace(path, md)
            stored["saved_to"] = md
            path = md
        _log("stream", id=m["id"], n=m["n"], bytes=len(report), sats=spent, root=m["root"],
             ms=round(1000 * (time.time() - t0), 1), final_ms=cond_ms, chan=self.book.get(dest).chan)
        text = report.decode("utf-8", "replace")
        preview = text[:PREVIEW_CAP]
        more = f"\n… [{len(report)} bytes, sha256 {stored['body_digest']}" + (f", saved to {path}" if path else "") + "]"
        return {
            **out,
            "stream_charged": spent,
            "body": preview + (more if len(text) > PREVIEW_CAP else ""),
            **stored,
            "stream": {
                "ok": True,
                "id": m["id"],
                "chunks": m["n"],
                "bytes": len(report),
                "merkle_root": m["root"],
                "paid_sats": spent,
                "all_chunks_verified": True,
                "last_chunk": "hash-locked, key checked",
                "body_digest": stored["body_digest"],
                **({"saved_to": path} if path else {}),
            },
        }

    def _verify_post(self, dest, acc, payload):
        """Hand the provider a signed state through /x402/verify (x402 v2 VerifyRequest/VerifyResponse)."""
        st, _, out = XbtChannelClient.http(
            "POST",
            dest + FACILITATOR_VERIFY,
            json.dumps(facilitator_request(acc, payload)).encode(),
            {"Content-Type": "application/json"},
        )
        try:
            valid = st == 200 and json.loads(out).get("isValid") is True
        except (ValueError, AttributeError):
            valid = False
        if not valid:
            raise StreamError(f"provider refused our payment state (HTTP {st})")

    def _signed_through(self, dest: str) -> int:
        """The most this channel is signed or booked for."""
        rec = self.book.get(dest)
        if rec is None:
            raise ChannelError("unknown_channel", dest)
        return max(rec.used_sats, self._booked_through(rec))

    def _final_chunk(self, dest, doc, m, budget: "CallBudget | None" = None):
        t = time.time()
        try:
            url = same_origin_url(dest, doc.get("chunkUrl")).replace("{i}", str(m["n"] - 1))
        except ChannelError as e:
            raise StreamError(f"chunkUrl: {e}") from None
        st, hdrs, _ = XbtChannelClient.http("GET", url, b"")
        if st != 402 or "PAYMENT-REQUIRED" not in {k.upper() for k in hdrs}:
            raise StreamError("last chunk is not offered under the manifest's hash lock")
        acc = pick_accept(unb64json({k.upper(): v for k, v in hdrs.items()}["PAYMENT-REQUIRED"]), self.network())
        cond = (acc.get("extra") or {}).get("conditional") or {}
        if cond.get("hash") != m["lock"] or int(cond.get("amount", 0)) != m["price"]:
            raise StreamError("last chunk is not offered under the manifest's hash lock")
        # AGP-005 M7: the ciphertext comes before the signature. Once the hash lock is signed the
        # provider can close with it and claim, and the claim reveals only k: without the ciphertext
        # already in hand, a dropped response leaves the payer paying for nothing.
        try:
            cipher = bytes.fromhex(cond["cipher"])
        except (KeyError, TypeError, ValueError):
            raise StreamError("last chunk offer carries no ciphertext; refused before signing")
        if H(cipher).hex() != m["finalCt"]:
            raise StreamError("last chunk offer's ciphertext does not match the committed finalCt; refused before signing")
        # AGP-080 W1: the hash-locked state pays used_sats + price to a provider that knows k, and it
        # does not move used_sats: book it before it is signed. The plain state that folds it in then
        # books nothing more, and a last chunk that fails keeps the booking (the provider holds the lock).
        try:
            csv = cond.get("csvDelta", 10)   # the seller's number: how long the price stays locked if the key never comes
            if type(csv) is not int or not 0 <= csv <= MAX_COND_CSV_BLOCKS:
                raise StreamError(f"last chunk offer's csvDelta is not a block count up to {MAX_COND_CSV_BLOCKS}; "
                                  "refused before signing")
            locked = self.book.get(dest).used_sats + _count(m.get("price"), "manifest price", 1)
            if budget is not None and not budget.fits(locked):
                raise StreamError("the last chunk's hash-locked state is above what max_sats leaves; refused before signing")
            self.book.check_signable(dest, int(m["price"]))
            self._book_through(dest, locked)
        except ChannelCapError as e:
            raise StreamError(f"last chunk: {e}") from None
        except ChannelError as e:
            raise StreamError(f"last chunk: {e.code}") from None
        with self.book._lock:
            rec = self.book._records[dest]
            payer = self.book._payer_locked(rec)
            cp = ConditionalParams(payer.params, bytes.fromhex(cond["hash"]), m["price"], csv)
            sig = ecc.sign(payer.secret, cp.sighash(cp.state_tx(rec.used_sats))) + bytes([SIGHASH_ALL_UNIFIED])
            self.book.audit.record("conditional_state", sig=sig, chan=rec.chan, dest=dest, cum=rec.used_sats,
                                   hashlock=cond["hash"], cond_sats=m["price"], sighash="0x21")
            rec.seq += 1
            rec.pending_cond = {"hash": cond["hash"], "cipher": cipher.hex(),
                                "manifest": {k: m[k] for k in ("id", "n", "root", "lock", "finalCt", "lastProof")}}
            payload = {"chan": rec.chan, "seq": rec.seq, "cum": str(rec.used_sats), "hashlock": cond["hash"], "sig": sig.hex()}
            self.book._persist()
        st, _, raw, _ = self._paid("GET", url, b"", acc, payload)
        if st != 200:
            raise StreamError(f"conditional purchase of the last chunk failed: HTTP {st}; "
                              "if the provider claims the hash lock, recover_conditional() opens the chunk")
        try:
            k = bytes.fromhex(json.loads(raw)["preimage"])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise StreamError("paid response carries no key; if the provider claims the hash lock, "
                              "recover_conditional() opens the chunk")
        pt = open_final(m, cipher, k)          # the offered ciphertext, never one the response substitutes
        with self.book._lock:
            self.book._records[dest].pending_cond = {}
            self.book._persist()
        rec, sig2 = self.book.increment(dest, m["price"])
        self._book_unbooked(dest)
        self._verify_post(dest, acc, {"chan": rec.chan, "cum": str(rec.used_sats), "sig": sig2.hex()})
        ms = round(1000 * (time.time() - t), 1)
        _log("chunk", i=m["n"] - 1, ms=ms, chargedSat=m["price"], chan=rec.chan, cum=rec.used_sats, hashlock=cond["hash"])
        return pt, ms

    def recover_conditional(self, dest: str, tx) -> bytes:
        """The last chunk of a stream whose hash lock was signed but whose paid response never came,
        from the provider's claim transaction (hex, bytes or Tx), which reveals k on-chain."""
        rec = self.book.get(dest)
        pc = rec.pending_cond if rec else {}
        if not pc:
            raise StreamError("no pending conditional purchase on this channel")
        k = preimage_from_tx(tx, bytes.fromhex(pc["hash"]))
        if not k:
            raise StreamError("this transaction does not reveal the hash lock's key")
        pt = open_final(pc["manifest"], bytes.fromhex(pc["cipher"]), k)
        with self.book._lock:
            self.book._records[dest].pending_cond = {}
            self.book._persist()
        return pt

    def _height_or(self, default: int) -> int:
        try:
            return int(self.height())
        except Exception:
            return default

    @staticmethod
    def _close_hex(reply, txid: str | None, rec) -> str:
        """The close's raw hex, if the provider's (untrusted) reply has it: kept only when it is the
        reported txid and spends this channel's funding output."""
        h = (reply.get("hex") or reply.get("closeHex")) if isinstance(reply, dict) else None
        if not (txid and isinstance(h, str) and len(h) < 20_000):
            return ""
        try:
            from xbt402.tx import Tx
            tx = Tx.parse(bytes.fromhex(h))
        except Exception:
            return ""
        spends = any((i.txid[::-1].hex(), i.vout) == (rec.funding_txid, rec.funding_vout) for i in tx.inputs)
        return h if tx.txid() == txid and spends else ""

    def learn_close_change(self, rec, txid: str, *, scan_from: int = 0, close_hex: str = "") -> dict:
        """AGP-022: one attempt at counting a close's change (HotWallet.learn_close_change). With the
        close's hex, our own node is handed the tx first (it checks it; a copy it has is a no-op)."""
        if close_hex:
            try:
                self.rpc.call("sendrawtransaction", close_hex)
            except Exception:
                pass
        start = scan_from or rec.close_scan_from or rec.funding_height or rec.open_height
        try:
            return self.hot.learn_close_change(txid or rec.closed_txid, (rec.funding_txid, rec.funding_vout), start)
        except Exception as e:
            return {"status": "pending", "txid": txid or rec.closed_txid, "scan_from": start, "added": 0,
                    "error": str(e)[:160]}

    def funding_spent(self, rec, *, scan: bool = False) -> str | None:
        """AGP-080: has our own node seen this channel's funding output spent? The spender's txid; ""
        when the output is gone and the funding is known to this node (seen confirmed, or its
        transaction is still found) but the spender is not named; None when the node still shows it
        unspent, has never seen it, or cannot be asked. None is "not proven", never "closed".
        `scan` also reads the blocks since the channel opened (the close and the refund do; a watcher
        tick does not, so an unproven close costs two calls a tick)."""
        try:
            utxo = self.rpc.call("gettxout", rec.funding_txid, int(rec.funding_vout), True)
        except Exception:
            return None
        if utxo:
            return None
        try:        # AGP-092: on the light backend an empty gettxout is also every server hiding the funding
            evidence, proven = spend_is_evidence(self.rpc, rec.funding_txid, rec.funding_vout, rec.params().spk)
        except Exception:
            return None
        if not evidence:
            return None
        spender = proven or netparams.find_spender(self.rpc, rec.funding_txid, rec.funding_vout, 0)   # the mempool
        if spender:
            return spender
        if rec.funding_height or netparams.get_tx(self.rpc, rec.funding_txid):
            return ""
        if scan:
            return netparams.find_spender(self.rpc, rec.funding_txid, rec.funding_vout,
                                          rec.funding_height or rec.open_height)
        return None

    def close_channel(self, dest: str) -> dict:
        """Cooperative close through the signer: payer signs tagged_hash(xbt402/close, chan)."""
        rec = self.book.get(dest)
        if rec is None:
            dest = self.book.find_dest(dest) or dest
            rec = self.book.get(dest)
        if rec is None:
            raise RuntimeError(f"no channel for {dest}")
        sig = self.book.sign_close(dest)
        origin = rec.origin or dest
        close_url = origin.rstrip("/") + "/x402/xbt-channel/close"
        payload = {"chan": rec.chan, "seq": rec.seq, "cum": str(rec.used_sats)}
        body = {"chan": rec.chan, "sig": sig, "payload": payload}
        h0 = self._height_or(0)               # AGP-022: no block before this one can hold the close
        st, _, out = XbtChannelClient.http(
            "POST", close_url, json.dumps(body).encode(), {"Content-Type": "application/json"}
        )
        if st != 200:
            raise RuntimeError(f"close failed: HTTP {st}")
        try:
            reply = json.loads(out)
        except ValueError:
            reply = None
        # the provider's reply is untrusted data: only a txid-shaped txid becomes the wallet's own field
        txid = reply.get("txid") if isinstance(reply, dict) else None
        doc = {"txid": txid if isinstance(txid, str) and len(txid) == 64 and all(c in "0123456789abcdef" for c in txid) else None}
        report = self.close_report(reply, rec)
        close_hex = self._close_hex(reply, doc.get("txid"), rec)
        if self.mine and doc.get("txid"):     # regtest only (P3)
            try:
                self.mine(1)
            except Exception:
                pass
        # AGP-022: the provider broadcast the close on its node; ours may get it seconds later (P2P), or
        # only in a block. Learn the change now if we can, then mark the channel closed with the answer:
        # a "pending" change is retried by the watcher (and before a balance read) until it is final.
        change = self.learn_close_change(rec, doc.get("txid") or "", scan_from=h0, close_hex=close_hex)
        # AGP-080 W3: the provider's 200 is its word. Closed for good only once our own node shows the
        # funding output spent; until then the watcher keeps the record and refunds it at expiry.
        spent = self.funding_spent(rec, scan=True)
        self.book.mark_closed(dest, spent or doc.get("txid") or "", change=change,
                              close_hex=close_hex, unproven=spent is None)
        _log("close", dest=dest, chan=rec.chan, txid=doc.get("txid"), cum=rec.used_sats,
             change_spk=rec.payer_spk, hot_spk=self.hot.spk.hex(), close_change=change["status"],
             close_report=report["status"], unpaid_msat=report["unpaid_msat"])
        return {
            "verdict": "allow",
            "rail": "xbt402",
            "dest": dest,
            **doc,
            "chan": rec.chan,
            "cum": rec.used_sats,
            "change_spk": rec.payer_spk,
            "hot_spk": self.hot.spk.hex(),
            "change_to_hot": rec.payer_spk == self.hot.spk.hex(),
            "close_change": change["status"],
            "close_proven": spent is not None,
            "close_report": report,
            UNTRUSTED_KEY: untrusted(out.decode("utf-8", "replace")[:BODY_CAP]),
        }

    @staticmethod
    def close_report(reply, rec) -> dict:
        """The provider's (untrusted) close amounts, as integers only, checked against our own state.
        xbt402 v1.2 (AGP-029): `cum` is the gross state we paid, `unpaidMsat` = spent - cum, and a
        payee-pays channel adds `payeeFee` (the provider's own close fee) and `payeeNet`. status:
        "ok" when the report matches what we signed and owes nothing; "debt" when the provider says
        we still owe (`unpaid_msat` > 0); "mismatch" when its numbers disagree with our channel. The
        close fee of a payee-pays channel is the provider's and is never a debt of ours."""
        def num(k):
            v = reply.get(k) if isinstance(reply, dict) else None
            if isinstance(v, bool) or not isinstance(v, (str, int)):
                return None
            try:
                n = int(v)
            except ValueError:
                return None
            return n if 0 <= n < 1 << 63 else None
        cum, unpaid, fee, net = num("cum"), num("unpaidMsat"), num("payeeFee"), num("payeeNet")
        payee_pays = rec.close_fee_payer == "payee"
        fee_ok = (fee == rec.close_fee and net == (cum or 0) - rec.close_fee) if payee_pays else (fee is None and net is None)
        if unpaid:
            status = "debt"
        elif cum != rec.used_sats or unpaid is None or not fee_ok:
            status = "mismatch"
        else:
            status = "ok"
        out = {"status": status, "cum": cum, "unpaid_msat": unpaid}
        if payee_pays:
            out.update(payee_fee=fee, payee_net=net)
        return out
