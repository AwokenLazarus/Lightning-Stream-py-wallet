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

from .b1path import ensure_b1
from .channels import ChannelBook
from .hot import HotWallet
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
    receipt_of,
    request_digest,
    unb64json,
)

# Inline preview. Streamed results are always stored in full (digest + path).
# 500 was too small for a real analytics JSON; 12k covers the catalog answers.
BODY_CAP = int(os.environ.get("B2_BODY_CAP", "12000"))
PREVIEW_CAP = 2048


def origin_of(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        raise ValueError("xbt402_pay needs an absolute URL")
    return f"{p.scheme}://{p.netloc}"


def request_target(url: str) -> str:
    """Path + query as the provider sees it (B1 request_digest / ASGI raw_path)."""
    parts = url.split("/", 3)
    return "/" + parts[3] if len(parts) > 3 else "/"


def pick_accept(pr: dict, network: str) -> dict:
    for acc in pr.get("accepts") or []:
        if acc.get("scheme") == SCHEME and acc.get("network") == network:
            return acc
    raise RuntimeError("no xbt-channel offer on this network")


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


class Xbt402Session:
    """One signer-owned client session: channels keyed by HTTP origin."""

    def __init__(self, book: ChannelBook, hot: HotWallet, rpc, height, mine=None):
        self.book = book
        self.hot = hot
        self.rpc = rpc
        self.height = height
        self.mine = mine

    def network(self) -> str:
        h = self.height()
        tip = h if h >= 101 else 101
        try:
            return network_id(self.rpc.call("getblockhash", min(tip, 101)))
        except Exception:
            return network_id("0" * 64)

    def open_from_offer(self, dest: str, acc: dict, cap_sats: int, expiry_blocks: int) -> dict:
        extra = acc.get("extra") or {}
        if extra.get("derivation") != DERIVATION:  # checked before funding: a mismatch strands the coins
            # no provider text in the wallet's own errors: the model reads them unlabelled (AGP-005 L12)
            raise RuntimeError(f"provider payee-key derivation is not {DERIVATION!r}; refused before funding")
        close_fee = int(extra.get("closeFeeSat") or 600)
        min_cap = int(extra.get("minCapacity") or 0)
        max_cap = int(extra.get("maxCapacity") or cap_sats)
        cap = max(cap_sats, min_cap)
        if cap > max_cap:
            raise RuntimeError(f"channel cap {cap} above provider max {max_cap}")
        min_exp = int(extra.get("minExpiryBlocks") or 1)
        max_exp = int(extra.get("maxExpiryBlocks") or 100_000)
        blocks = min(max(expiry_blocks, min_exp + 6), max_exp - 1)
        check = getattr(self.hot, "check_channel_funding", None)
        if check is not None:  # AGP-013: above the hot-balance cap, a human sweeps before new channels
            check()
        open_height = self.height()
        expiry = open_height + blocks
        secret, payer_pub = self.book.new_payer_key()
        # Change at close returns to the signer's hot key, not the per-channel payer key.
        params = ChannelParams.derive(acc["payTo"], payer_pub, expiry, close_fee, self.hot.spk.hex(),
                                      network=acc["network"])
        funded = cap + close_fee
        txid, vout = self.hot.fund(params.spk, funded)
        params.funding_txid, params.funding_vout, params.capacity = txid, vout, funded
        if self.mine:
            self.mine(1)
        origin = dest
        open_url = origin + extra.get("openUrl", "/x402/xbt-channel/open")
        body = {
            "x402Version": 2,
            "network": acc["network"],
            "channel": {
                "txid": txid,
                "vout": vout,
                "capacity": funded,
                "expiry": expiry,
                "payerPub": params.payer_pub,
                "payerSpk": params.payer_spk,
                "redeemScript": params.script.hex(),
            },
        }
        st, _, out = XbtChannelClient.http("POST", open_url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        if st != 200:
            raise RuntimeError(f"open failed: HTTP {st}")
        rec = self.book.add_funded(dest, secret=secret, params=params, origin=origin, cap_sats=cap,
                                   open_height=open_height)
        return rec.public()

    def _with_auth(self, payload: dict, method: str, url: str, body: bytes) -> dict:
        """H3: bind this payload to (method, path, body). The ECDH key stays in the book."""
        pl = dict(payload)
        req = request_digest(method, request_target(url), body or b"")
        pl["auth"] = self.book.request_auth(pl["chan"], pl["seq"], pl["cum"], pl.get("sig"), req)
        return pl

    def _paid(self, method, url, body, acc, payload):
        payload = self._with_auth(payload, method, url, body or b"")
        hdr = {"PAYMENT-SIGNATURE": b64json({"x402Version": 2, "accepted": acc, "payload": payload})}
        st, hdrs, out = XbtChannelClient.http(method, url, body or b"", hdr)
        h = {k.upper(): v for k, v in hdrs.items()}
        return st, h, out, unb64json(h["PAYMENT-RESPONSE"]) if "PAYMENT-RESPONSE" in h else None

    def pay_once(self, url: str, method: str, body: bytes, max_sats: int, expiry_blocks: int, cap_sats: int) -> dict:
        """One call. The provider's body and receipt come back only under UNTRUSTED_KEY (L7)."""
        res = self._pay_once(url, method, body, max_sats, expiry_blocks, cap_sats)
        if "body" in res or "receipt" in res:
            res[UNTRUSTED_KEY] = untrusted(res.pop("body", ""), res.pop("receipt", None))
        return res

    def _pay_once(self, url: str, method: str, body: bytes, max_sats: int, expiry_blocks: int, cap_sats: int) -> dict:
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
            rec_pub = self.open_from_offer(dest, acc, cap_sats=cap_sats, expiry_blocks=expiry_blocks)
            rec = self.book.get(dest)
            opened = {**rec_pub, "funding_txid": rec.funding_txid, "funding_sats": rec.funding_sats}
            _log("open", url=url, chan=rec.chan, txid=rec.funding_txid, capacity=rec.funding_sats,
                 cap=rec.cap_sats, ms=round(1000 * (time.time() - t1), 1))
        rec, sig = self.book.increment(dest, price)
        payload = {"chan": rec.chan, "seq": rec.seq, "cum": str(rec.used_sats)}
        if sig:
            payload["sig"] = sig.hex()
        st2, _, out2, receipt = self._paid(method, url, body, acc, payload)
        charged = charged_of(receipt, price) if st2 < 400 else 0
        _log("call", url=url, status=st2, ms=round(1000 * (time.time() - t0), 1), chargedSat=charged,
             chan=rec.chan, cum=rec.used_sats, opened=bool(opened))
        preview = out2.decode("utf-8", "replace")[:BODY_CAP]
        stored = _store_body(out2, f"{rec.chan[:12]}-{rec.seq}") if len(out2) > BODY_CAP else {}
        res = {
            "status": st2,
            "charged_sats": charged,
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
            res.update(self.stream(dest, acc, doc, max_sats - charged))
            res["charged_sats"] = charged + res.pop("stream_charged")
        return res

    def _route_offer(self, url, method, body, max_sats, expiry_blocks, cap_sats, acc):
        """Hook for rails that buy something other than an HTTP response (forward.py). None = plain call."""
        return None

    def stream(self, dest, acc, doc, budget):
        m, t0 = doc["manifest"], time.time()
        out = {"stream_charged": 0}
        try:
            check_manifest(m, acc["payTo"])
        except StreamError as e:
            return {**out, "stream": {"ok": False, "refused": str(e)}}
        if m["n"] * m["price"] > budget:
            return {
                **out,
                "stream": {
                    "ok": False,
                    "refused": f"result costs {m['n']} x {m['price']} sat more; max_sats leaves {budget}",
                },
                "body": "",
            }
        parts, spent = [], 0
        for i in range(m["n"] - 1):
            url = dest + doc["chunkUrl"].replace("{i}", str(i))
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
            rec, sig = self.book.increment(dest, m["price"])
            self._verify_post(dest, acc, {"chan": rec.chan, "cum": str(rec.used_sats), "sig": sig.hex()})
            spent += m["price"]
            _log("chunk", i=i, ms=round(1000 * (time.time() - t), 1), chargedSat=m["price"], chan=rec.chan, cum=rec.used_sats)
        try:
            pt, cond_ms = self._final_chunk(dest, doc, m)
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

    def _final_chunk(self, dest, doc, m):
        t = time.time()
        url = dest + doc["chunkUrl"].replace("{i}", str(m["n"] - 1))
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
        with self.book._lock:
            rec = self.book._records[dest]
            payer = self.book._payer_locked(rec)
            cp = ConditionalParams(payer.params, bytes.fromhex(cond["hash"]), m["price"], int(cond.get("csvDelta", 10)))
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
        self.book.mark_closed(dest, doc.get("txid") or "")
        if self.mine and doc.get("txid"):
            try:
                self.mine(1)
            except Exception:
                pass
        if doc.get("txid"):
            try:
                self.hot.scan_from_txid(doc["txid"])
            except Exception:
                pass
        _log("close", dest=dest, chan=rec.chan, txid=doc.get("txid"), cum=rec.used_sats,
             change_spk=rec.payer_spk, hot_spk=self.hot.spk.hex())
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
            UNTRUSTED_KEY: untrusted(out.decode("utf-8", "replace")[:BODY_CAP]),
        }
