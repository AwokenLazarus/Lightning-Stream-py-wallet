"""Signer process: owns Knots RPC + policy. MCP talks only to this socket.

Human approval is cryptographic: the signer holds only an ed25519 public key.
`approve` and `recover_vault` require a signature by that key. There is no
`human=` boolean. Those methods are not MCP tools.

AGP-013: the hot key and channel keys are sealed at rest (keystore.py; wrapping key from
B2_HOT_KEYFILE / B2_HOT_PASSPHRASE in the signer's environment only), every signature is logged to
`.run/signatures.jsonl` (sigaudit.py), `xbt402_refund` and an expiry watcher refund channels the
provider never closed, `rotate_hot_key` moves the hot key, `sweep_hot` (human-signed) empties it
below its balance cap, and xbt402_pay has a forward rail (forward.py).

AGP-017 (mainnet readiness): the signer learns its chain from the node at start (netparams). On any
chain but regtest it never mines (and refuses to start if the policy asks it to), addresses use that
chain's hrp (`bc` on mainnet), and the xbt402 network id is the spec's anchor block. A channel is
recorded, payer key sealed, before its funding is broadcast; its open is posted once the funding has
the offer's minConf; the watcher retries pending opens and refunds whatever never opened. Nothing
needs txindex (a pruned node works).

AGP-016: the signature log's head is anchored with a witness process (anchor.py, B2_ANCHOR_SOCK) at
start, periodically, and after every close, refund, sweep, rotation and treasury recovery; the signer
refuses to start when its log no longer matches the latest anchor. The hot UTXO set is sealed on disk
and reconciled against the node at start. The treasury secrets are sealed like the hot key.
"""

from __future__ import annotations

import json
import math
import os
import socket
import threading
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

from . import anchor as anchoring, chain as chainbackend, netparams, sigaudit
from .approval import rotate_message, verify, verify_approval, x2b
from .channels import ChannelBook, ChannelCapError
from .forward import ForwardPolicy, ForwardSession
from .hot import HotCapError, HotWallet
from .keystore import KeyStore, KeyStoreError
from .policy import Payment, PolicyConfig, PolicyEngine, PolicyStore, AuditLog, Verdict, normalize_dest
from .rpc import KnotsRpc, KnotsRpcError

from xbt402.channel import ChannelError  # noqa: E402  (B1 on sys.path through .channels)
from .sanitize import sanitize
from .treasury import Treasury, TREASURY_CSV
from .vault import PresignedVault
from .xbt402 import Xbt402Session, origin_of

XBT_SATS = 100_000_000

# Shared with xbt-signer. Agents see these texts on quote_payment / pay.
ERR_NOT_DECIMAL = "amount_xbt is not a decimal number"
ERR_NOT_FINITE = "amount_xbt must be a finite number"
ERR_NEGATIVE = "amount_xbt must not be negative"
ERR_PRECISION = "amount_xbt has more than 8 decimal places"

_NON_FINITE = frozenset({
    "nan", "+nan", "-nan",
    "inf", "+inf", "-inf",
    "infinity", "+infinity", "-infinity",
})


def sats_from_xbt(amount_xbt) -> int:
    """Exact XBT → sats. At most 8 decimal places; refuse negatives, NaN and inf.

    Floats go through ``Decimal(repr(x))`` so 0.00001 / 1e-05 become 1000 sats
    instead of ``int("1e-05")``. Extra precision is refused, never truncated.
    """
    if isinstance(amount_xbt, bool):
        raise ValueError(ERR_NOT_DECIMAL)
    if isinstance(amount_xbt, float):
        if math.isnan(amount_xbt) or math.isinf(amount_xbt):
            raise ValueError(ERR_NOT_FINITE)
        text = repr(amount_xbt)
    elif isinstance(amount_xbt, int):
        text = str(amount_xbt)
    elif isinstance(amount_xbt, str):
        text = amount_xbt.strip()
    elif isinstance(amount_xbt, Decimal):
        if not amount_xbt.is_finite():
            raise ValueError(ERR_NOT_FINITE)
        text = format(amount_xbt, "f")
    else:
        raise ValueError(ERR_NOT_DECIMAL)

    if text.lower() in _NON_FINITE:
        raise ValueError(ERR_NOT_FINITE)
    try:
        d = Decimal(text)
    except InvalidOperation as e:
        raise ValueError(ERR_NOT_DECIMAL) from e
    if not d.is_finite():
        raise ValueError(ERR_NOT_FINITE)
    if d < 0:
        raise ValueError(ERR_NEGATIVE)
    sats = d * Decimal(XBT_SATS)
    if sats != sats.to_integral_value():
        raise ValueError(ERR_PRECISION)
    as_int = int(sats)
    if as_int.bit_length() > 63:
        raise ValueError(ERR_NOT_DECIMAL)
    return as_int


def _deny(rule: str, reason: str) -> dict:
    return {"verdict": "deny", "rule": rule, "reason": reason}


class Signer:
    def __init__(self, root: Path, *, rpc: KnotsRpc | None = None):
        self.root = Path(root)
        run = self.root / ".run"
        run.mkdir(parents=True, exist_ok=True)
        cfg_path = self.root / "policy.json"
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        self.config = PolicyConfig.from_dict(raw)
        self.engine = PolicyEngine(
            self.config,
            PolicyStore(run / "ledger.json"),
            AuditLog(run / "audit.jsonl"),
        )
        datadir = Path(os.environ.get("B2_DATADIR", self.root / ".regtest"))
        conf = Path(os.environ.get("B2_CONF", self.root / "bitcoin-b2.conf"))
        wallet = os.environ.get("B2_WALLET", "agent")
        # AGP-024: the RPC backend is KnotsRpc as before; B2_CHAIN_BACKEND=electrum (or auto without a node)
        # reads the chain from Electrum servers, verified against our own BLAKE2b header chain
        self.rpc = rpc if rpc is not None else chainbackend.backend_from_env(datadir, conf, wallet, run)
        self.light = chainbackend.is_light(self.rpc)
        # AGP-017 P3/P5: the chain decides the hrp and whether this process may ever mine
        self.chain = netparams.detect_chain(self.rpc)
        if self.light:
            self._check_light_chain()
        if self.config.regtest_mine and not netparams.mining_allowed(self.chain):
            raise netparams.ChainError(f"policy regtest_mine is set but the node is on {self.chain!r}: "
                                       "refusing to start (only regtest may mine)")
        # a light client has no node to mine with (AGP-024): its regtest blocks come from the rig
        self.mining = netparams.mining_allowed(self.chain) and self.config.regtest_mine is not False and not self.light
        if hasattr(self.rpc, "allow_generate"):
            self.rpc.allow_generate = self.mining
        self.hrp = netparams.hrp(self.chain)
        recovery = raw.get("recovery_address") or os.environ.get("B2_RECOVERY", "")
        self.vault = PresignedVault(run / "vault.json", self.rpc, recovery)
        self.sock_path = Path(os.environ.get("B2_SIGNER_SOCK", run / "signer.sock"))
        pub_hex = (raw.get("human_pubkey") or "").strip()
        self.human_pubkey = x2b(pub_hex) if pub_hex else b""
        self._spend_lock = threading.RLock()
        self.keystore = KeyStore.from_env(run)
        if self.keystore is None and not KeyStore.plaintext_allowed():
            raise KeyStoreError("the signer's hot key must be encrypted at rest: set B2_HOT_KEYFILE (a 32-byte key "
                                "file outside the run dir) or B2_HOT_PASSPHRASE (B2_HOT_ALLOW_PLAINTEXT=1 for tests)")
        self.sigaudit = sigaudit.SigAudit(run / "signatures.jsonl")
        self.anchor = anchoring.Anchorer(self.sigaudit, anchoring.client_from_env(), self.config.anchor_interval_s)
        self._check_anchor_at_start()
        self.hot = HotWallet(run / "hot.json", self.rpc, hrp=self.hrp, keystore=self.keystore, audit=self.sigaudit,
                             cap_sats=self.config.hot_balance_cap_sats)
        self.hot.reconcile(scan=os.environ.get("B2_HOT_SCAN", "1") != "0")
        self.treasury = Treasury(run / "treasury.json", csv=int(getattr(self.config, "treasury_csv", TREASURY_CSV) or TREASURY_CSV),
                                 hrp=self.hrp, keystore=self.keystore)
        self.channels = ChannelBook(run / "channels.json", run / "channel_keys.json", keystore=self.keystore,
                                    audit=self.sigaudit)
        self.channels.expiry_guard = (self._height, self.config.refund_margin_blocks)
        self._xbt402 = ForwardSession(self.channels, self.hot, self.rpc, height=self._height,
                                      mine=self._mine if self.mining else None, chain=self.chain,
                                      open_wait_s=self.config.open_wait_s, close_fee_max=self.config.close_fee_max_sats,
                                      refund_margin=self.config.refund_margin_blocks,
                                      forward_path=run / "forward.json",
                                      policy=ForwardPolicy.from_dict(self.config.forward))
        # AGP-063 W1: the signed increase is committed before the signature is sent.
        self._xbt402.set_spend_book(self._book_signed_delta)
        self._xbt402.set_spend_check(lambda dest, asked, delta: self._floor_check(dest, asked, delta, human=False))
        from .routing import RoutePolicy, RouteSigner
        self.routing = RouteSigner(self.channels, RoutePolicy.from_dict(self.config.routing),
                                   state_path=run / "routing.json", engine=self.engine)
        self._open_tried: dict[str, float] = {}
        self._watch_stop = threading.Event()
        self.watch_interval = float(os.environ.get("B2_WATCH_INTERVAL", "10"))

    def _check_light_chain(self) -> None:
        """AGP-024: servers that answer but are not on this chain's checkpoint are the wrong chain: refuse
        to start, as the RPC path refuses a node on another chain. Servers that are down only delay us."""
        from .electrum import CheckpointMismatch
        try:
            self.rpc.sync()
        except CheckpointMismatch as e:
            raise netparams.ChainError(f"{netparams.ENV_CHAIN}={self.chain!r}: {e}") from e
        except Exception:
            pass

    def _check_anchor_at_start(self) -> None:
        """Fail closed if the signature log no longer holds the witness's latest anchor."""
        if not self.anchor.enabled:
            if self.config.anchor_required:
                raise sigaudit.SigAuditError(f"policy anchor_required: set {anchoring.ENV_SOCK} to the anchor witness socket")
            return
        try:
            chk = self.anchor.check()
        except anchoring.AnchorError as e:
            if self.config.anchor_required:
                raise sigaudit.SigAuditError(f"policy anchor_required: {e}") from e
            self.anchor.last_error = str(e)[:300]
            return
        if not chk["ok"]:
            raise sigaudit.SigAuditError(f"signature log fails its anchor check ({chk['reason']}): refusing to start. "
                                         f"Keep the log and the witness store as evidence and ask a human.")
        self.anchor.anchor("signer_start")

    def _anchor(self, reason: str) -> None:
        """Anchor after a close, refund or sweep. Never fails the operation that triggered it."""
        if self.anchor.enabled:
            self.anchor.anchor(reason)

    def handle(self, req: dict) -> dict:
        method = req.get("method")
        # every signature made while handling this request is logged under its method (sigaudit)
        with sigaudit.context(method=str(method or ""), rule=f"method:{method}"):
            return self._handle(method, req.get("params") or {})

    def _handle(self, method, params: dict) -> dict:
        # A boolean "human" in the request is never a capability. Ignore it.
        if method == "balance":
            # AGP-024: a light client has no node wallet; its coins are the hot key's (and channels')
            bals = {} if self.light else self.rpc.call("getbalances")
            mine = bals.get("mine") or {}
            return sanitize(
                {
                    "trusted_sats": int(round(float(mine.get("trusted", 0)) * XBT_SATS)),
                    "untrusted_pending_sats": int(round(float(mine.get("untrusted_pending", 0)) * XBT_SATS)),
                    "immature_sats": int(round(float(mine.get("immature", 0)) * XBT_SATS)),
                    **({"node_wallet": None, "chain_backend": "electrum"} if self.light else {}),
                    "vault": self.vault.status(),
                    "hot": self._hot_status(),
                    "treasury": self.treasury.status(),
                    "channels": self.channels.list_public(),
                }
            )
        if method == "quote_payment":
            pay = self._payment(params)
            d = self.engine.quote(pay)
            out = d.as_dict()
            try:
                fee = self.rpc.call("estimatesmartfee", 1)
                out["fee_estimate"] = fee
            except KnotsRpcError:
                out["fee_estimate"] = None
            return sanitize(out)
        if method == "pay":
            with self._spend_lock:
                return sanitize(self._pay_locked(params, human=False))
        if method == "approve":
            return sanitize(self._approve_signed(params))
        if method == "history":
            limit = int(params.get("limit") or 50)
            return sanitize({"events": self.engine.audit.read(limit=limit)})
        if method == "recover_vault":
            return sanitize(self._recover_signed(params))
        if method == "health":
            out = {"ok": True, "wallet": self.rpc.wallet, "chain": self.chain, "hrp": self.hrp, "mining": self.mining}
            if self.light:
                out["chain_backend"] = self.rpc.status()
            return out
        if method == "chain_backend":
            if not self.light:
                return {"backend": "rpc"}
            try:
                self.rpc.sync()
            except Exception as e:
                return sanitize({**self.rpc.status(), "sync_error": str(e)[:200]})
            return sanitize(self.rpc.status())
        if method == "channels":
            return sanitize({"channels": self.channels.list_public(), "height": self._height_safe()})
        if method == "hot_address":
            return sanitize(self._hot_status())
        if method == "notice_hot_txid":
            n = self.hot.scan_from_txid(params.get("txid") or "")
            return sanitize({**self.hot.status(), "noticed": n})
        if method == "fund":
            # AGP-063 W3: the Rust signer funds only a channel for a key it issued, paying the seller's
            # verified terms. B2 issues no client channel keys, so nothing on this socket is fundable.
            if not params.get("origin") or not params.get("params"):
                return _deny("fund_unbound", "fund needs the channel (origin, params) a key was issued for, never a bare address")
            return _deny("bad_key", "this signer issued no channel key for that origin")
        if method == "open_channel":
            with self._spend_lock:
                return sanitize(self._open_channel_checked(params))
        if method == "sign_state":
            with self._spend_lock:
                return sanitize(self._sign_state_locked(params))
        if method == "xbt402_pay":
            with self._spend_lock:
                return sanitize(self._xbt402_pay_locked(params))
        if method == "xbt402_request_auth":
            return sanitize(self._xbt402_request_auth(params))
        if method == "xbt402_sign_state_a3":
            with self._spend_lock:
                return sanitize(self._xbt402_sign_state_a3(params))
        # --- AGP-021: routed (adaptor-locked) states through a hub ------------------------------------
        if method == "xbt402_sign_state_adaptor":
            with self._spend_lock:
                return sanitize(self._xbt402_sign_state_adaptor(params))
        if method == "xbt402_resolve_lock":
            with self._spend_lock:
                try:
                    return sanitize({"t": self.routing.resolve_lock(params.get("chan") or "", params.get("secret") or "")})
                except ChannelError as e:
                    return _deny(e.code, str(e))
        if method == "xbt402_void_lock":
            with self._spend_lock:
                try:
                    return sanitize({"voided": bool(self.routing.void_lock(params.get("chan") or ""))})
                except ChannelError as e:
                    return _deny(e.code, str(e))
        if method == "xbt402_adopt_lock":
            with self._spend_lock:
                try:
                    self.routing.adopt_lock(params.get("chan") or "", int(params.get("cum") or 0))
                    return {"adopted": True}
                except ChannelError as e:
                    return _deny(e.code, str(e))
        if method == "xbt402_recover_lock":
            with self._spend_lock:
                return sanitize(self._xbt402_recover_lock(params))
        if method == "routing_status":
            return sanitize(self.routing.status())
        if method == "close_channel":
            with self._spend_lock:
                return sanitize(self._close_channel_locked(params))
        if method == "fund_treasury":
            with self._spend_lock:
                return sanitize(self._fund_treasury_locked(params))
        if method == "recover_treasury":
            return sanitize(self._recover_treasury_locked(params))
        # --- AGP-013 ---------------------------------------------------------------------------------
        if method in ("xbt402_refund", "refund_channel"):  # refund_channel: b5 AGP-008's name
            with self._spend_lock:
                key = params.get("counterparty") or params.get("dest") or params.get("chan") or ""
                return sanitize(self._refund_locked(key))
        if method == "watch_tick":
            return sanitize({"actions": self.watch_tick()})
        if method == "forward_recover":
            with self._spend_lock:
                res = self._xbt402.forward_recover(params.get("txid") or "", params.get("blockhash") or "")
                if res.get("recovered"):     # booked when it was pre-signed (AGP-080); a no-op unless that was lost
                    self._book_forward(res["dest"], res["chan"], int(res["cum"]), int(res["price"]),
                                       f"forward {res['outpoint']} (recovered)")
                elif res.get("void"):        # the close does not carry the pre-signature: proven void
                    self._release_forward(res["chan"], int(res["cum"]))
                return sanitize(res)
        if method == "forward_status":
            return sanitize(self._xbt402.status())
        if method == "forward_pending":
            return sanitize({"pending": self._xbt402.status()["pending"]})
        if method == "forward_transfers":
            with self._xbt402.fwd.lock:
                return sanitize({"delivered": json.loads(json.dumps(self._xbt402.fwd.data["delivered"]))})
        if method == "rotate_hot_key":
            with self._spend_lock:
                denied = self._human_signed(rotate_message(self.hot.address, self._int(params.get("expiry"))), params)
                if denied:
                    return denied
                sigaudit.set_rule("human:rotate_signature")
                out = self.hot.rotate()
                self.engine.audit.append({"type": "hot_rotation", "ts": self.engine.clock(),
                                          "old_address": out["old_address"], "new_address": out["new_address"],
                                          "sweep_txid": (out.get("sweep") or {}).get("txid")})
                if out.get("sweep"):
                    self._mine_safe()
                self._anchor("rotation")
                return sanitize({**out, **self.hot.status()})
        if method == "sweep_hot":
            with self._spend_lock:
                return sanitize(self._sweep_hot_signed(params))
        if method == "signatures":
            try:
                chk = self.anchor.check()
            except anchoring.AnchorError as e:
                chk = {**sigaudit.check_chain(self.sigaudit.path), "anchor_error": str(e)[:200]}
            return sanitize({"signatures": self.sigaudit.read(int(params.get("limit") or 50)),
                             "chain_ok": chk["ok"], "chain": chk, "anchor": self.anchor.status()})
        # --- AGP-016 (signer-side, not MCP tools) ------------------------------------------------------
        if method == "anchor_now":
            return sanitize({"result": self.anchor.anchor(str(params.get("reason") or "operator")),
                             "anchor": self.anchor.status()})
        if method == "anchor_status":
            return sanitize(self.anchor.status())
        if method == "hot_reconcile":
            if params.get("last"):  # the reconcile the signer ran at start (or the latest one)
                return sanitize({**self.hot.last_reconcile, **self.hot.status()})
            with self._spend_lock:
                rec = self.hot.reconcile(scan=bool(params.get("scan", True)))
                return sanitize({**rec, **self._hot_status()})
        raise ValueError(f"unknown method {method}")

    def _height(self) -> int:
        return int(self.rpc.call("getblockcount"))

    def _height_safe(self) -> int:
        try:
            return self._height()
        except Exception:
            return 0

    def _mine(self, n: int = 1) -> None:
        """Regtest demos only (P3): refused unless the chain was regtest at start and still is."""
        if not self.mining:
            raise netparams.ChainError(f"mining is off on {self.chain!r}")
        if (self.rpc.call("getblockchaininfo") or {}).get("chain", "regtest") != "regtest":
            raise netparams.ChainError("the node is no longer regtest: refusing to mine")
        addr = self.rpc.call("getnewaddress", "mine", "bech32")
        self.rpc.call("generatetoaddress", int(n), addr)

    def _mine_safe(self) -> None:
        if not self.mining:
            return
        try:
            self._mine(1)
        except Exception:
            pass

    # --- AGP-013: payer refund, expiry watcher, human sweep ------------------------------------------
    def _refund_locked(self, key: str, *, auto: bool = False) -> dict:
        """Broadcast the payer's CLTV refund of a channel the provider did not close. The refund always
        pays the signer's current hot key: nothing the caller passes can redirect it."""
        if not self.config.refund_enabled:
            return _deny("refund_disabled", "refunds are off in this policy")
        dest = self.channels.find_dest(key) if key else None
        rec = self.channels.get(dest) if dest else None
        if rec is None:
            return _deny("unknown_channel", f"no channel for {key}")
        base = {"dest": dest, "chan": rec.chan, "expiry": rec.expiry}
        if rec.state == "refunded":  # idempotent: report the refund already made, never a second one
            return {"verdict": "allow", "rule": "already_refunded", "already": True, **base,
                    "txid": rec.refund_txid, "sats": rec.funding_sats - rec.close_fee}
        if rec.state == "closed" and rec.close_unproven:
            # AGP-080 W3: closed on the provider's word. Our node decides: spent means closed; still
            # unspent at expiry means it never closed, and the refund below takes it
            if not self._prove_close(dest):
                if self._height() < rec.expiry:
                    return {**_deny("refund_early", "the provider reported a close this node has not seen; the "
                                                    f"refund is valid from the block after {rec.expiry}"), **base}
                self.channels.reopen_unproven(dest)
            rec = self.channels.get(dest)
        if rec.state == "closed":
            self._notice_close_change(dest)
            return {**_deny("channel_closed", "the channel was closed; there is nothing to refund"), **base,
                    "closed_txid": rec.closed_txid or None}
        h = self._height()
        if h < rec.expiry:
            return {**_deny("refund_early", f"height {h}: the refund is valid from the block after {rec.expiry}"),
                    **base, "height": h}
        try:
            utxo = self.rpc.call("gettxout", rec.funding_txid, rec.funding_vout, True)
        except KnotsRpcError as e:
            return _deny("refund_rpc", str(e)[:200])
        if not utxo:
            # P6: no txindex. The spend is found in the mempool or by scanning blocks from the funding's
            # block; the funding counts as known once seen confirmed (funding_height) or in the mempool.
            start = rec.funding_height or rec.open_height
            spender = netparams.find_spender(self.rpc, rec.funding_txid, rec.funding_vout, start)
            known = bool(spender or rec.funding_height or netparams.get_tx(self.rpc, rec.funding_txid))
            if known:
                # AGP-022: the change first, then the state: a reader that sees "closed" sees the change
                change = self._xbt402.learn_close_change(rec, spender or "", scan_from=start)
                self.channels.mark_closed(dest, spender or "", change=change)
                spender = spender or change.get("txid") or None
                return {**_deny("channel_closed", "the funding output is already spent (the provider closed)"),
                        **base, "closed_txid": spender}
            return {**_deny("funding_unknown", "the funding output is not on this node"), **base}
        sigaudit.set_rule("watcher:auto_refund" if auto else "policy:refund_enabled")
        tx, _ = self.channels.refund_tx(dest, self.hot.spk, fee=rec.close_fee)
        try:
            txid = self.rpc.call("sendrawtransaction", tx.hex())
        except KnotsRpcError as e:
            return {**_deny("refund_rejected", str(e)[:200]), **base}
        self.channels.mark_refunded(dest, txid)
        sats = tx.outputs[0].value
        self.hot.notice_utxo(txid, 0, sats)
        with self._xbt402.fwd.lock:  # a forward pre-signature on this channel can never be completed now
            pend = self._xbt402.fwd.data["pending"].pop(dest, None)
            if pend:
                self._xbt402.fwd.data["void"][pend["offer"]["outpoint"]] = {"refund": txid, "cum": pend["cum"]}
                self._xbt402.fwd.save()
        if pend:
            self._release_forward(pend["chan"], int(pend["cum"]))
        self.engine.audit.append({"type": "refund", "dest": dest, "chan": rec.chan, "txid": txid, "sats": sats,
                                  "auto": auto, "ts": self.engine.clock()})
        self._anchor("refund")
        return {"verdict": "allow", "rule": "refund", **base, "txid": txid, "sats": sats,
                "to": self.hot.address, "auto": auto}

    def _prove_close(self, dest: str, *, scan: bool = True) -> bool:
        """AGP-080 W3: True once our own node shows the funding output of an unproven close spent (the
        record then names the real spender and its change is learned as usual)."""
        rec = self.channels.get(dest)
        if rec is None or rec.state != "closed" or not rec.close_unproven:
            return rec is not None and rec.state == "closed"
        spender = self._xbt402.funding_spent(rec, scan=scan)
        if spender is None:
            return False
        self.channels.prove_close(dest, spender)
        self._notice_close_change(dest)
        return True

    def _release_forward(self, chan: str, cum: int) -> None:
        """AGP-080 W1: a forward lot's pre-signature was booked when it was made; it is released only
        here, on proof it is void (the channel's funding was spent by a transaction that does not carry
        it: our refund, or a close with a lower state)."""
        self.engine.store.amend(f"xbt402:{chan}:{cum}", None)

    def _notice_close_change(self, dest: str) -> str:
        """AGP-016/022: a close pays our change to the hot key. If the provider built it (or its tx had not
        reached our node when we closed), learn the still-unspent change now. Once the answer is final
        (counted, spent, none) nothing is looked up again, so a coin is never counted twice."""
        rec = self.channels.get(dest)
        if rec is None or rec.state != "closed":
            return ""
        if rec.close_change not in ("", "pending"):
            return rec.close_change
        change = self._xbt402.learn_close_change(rec, rec.closed_txid, close_hex=rec.close_hex)
        self.channels.note_close_change(dest, change)
        return change["status"]

    def _settle_close_changes(self) -> list[dict]:
        """Retry every closed channel whose change is still pending (AGP-022). The caller holds _spend_lock."""
        out = []
        for rec in self.channels.pending_close_records():
            st = self._notice_close_change(rec.dest)
            if st != "pending":
                out.append({"dest": rec.dest, "chan": rec.chan, "close_change": st,
                            "closed_txid": (self.channels.get(rec.dest) or rec).closed_txid})
        return out

    def _hot_status(self) -> dict:
        """hot.status() once pending close changes had their chance (AGP-022: a read after a close sees
        its change, or is told which closes are still pending)."""
        if self.channels.pending_close_records():
            with self._spend_lock:
                self._settle_close_changes()
        pend = [r.closed_txid or r.chan for r in self.channels.pending_close_records()]
        return {**self.hot.status(), "hot_pending_close_change": pend}


    def watch_tick(self) -> list[dict]:
        """One watcher pass: refund every open channel at or past its CLTV expiry, and sweep coins that
        reached a retired hot key. Channels within the margin already get no new states."""
        actions = []
        try:
            h = self._height()
        except Exception:
            return actions
        for rec in self.channels.pending_records():       # P1/P2: finish opens a crash or a wait left behind
            if h >= rec.expiry - self.config.refund_margin_blocks:
                continue
            if time.time() - self._open_tried.get(rec.dest, 0.0) < self.config.open_retry_s:
                continue
            self._open_tried[rec.dest] = time.time()
            with self._spend_lock, sigaudit.context(method="watcher", rule="watcher:open_retry"):
                try:
                    r = self._xbt402.complete_open(rec.dest, wait_s=0)
                    act = {"state": r.get("state"), "confirmations": r.get("confirmations")}
                except Exception as e:
                    act = {"state": "pending", "error": str(e)[:160]}
            if act["state"] == "open" or act.get("error"):
                actions.append({"dest": rec.dest, "chan": rec.chan, "height": h, "open_retry": act})
        for rec in self.channels.unproven_close_records():   # AGP-080 W3: closed on the provider's word
            with self._spend_lock, sigaudit.context(method="watcher"):
                if self._prove_close(rec.dest, scan=h >= rec.expiry):
                    now = self.channels.get(rec.dest)
                    actions.append({"dest": rec.dest, "chan": rec.chan, "close_proven": now.closed_txid,
                                    "close_change": now.close_change or "pending", "closed_txid": now.closed_txid,
                                    "height": h})
                elif h >= rec.expiry:
                    self.channels.reopen_unproven(rec.dest)   # never closed: the refund loop below takes it
        for rec in self.channels.unsettled_records():
            if h >= rec.expiry:
                with self._spend_lock, sigaudit.context(method="watcher"):
                    r = self._refund_locked(rec.dest, auto=True)
                actions.append({"dest": rec.dest, "chan": rec.chan, "height": h, **{k: r.get(k) for k in
                                ("verdict", "rule", "txid", "sats", "reason")}})
        if self.channels.pending_close_records():          # AGP-022: a close's change not yet counted
            with self._spend_lock, sigaudit.context(method="watcher"):
                for a in self._settle_close_changes():
                    actions.append({**a, "height": h})
        with self._spend_lock, sigaudit.context(method="watcher", rule="watcher:retired_sweep"):
            try:
                sw = self.hot.sweep_retired()
            except Exception as e:
                sw = {"error": str(e)[:200]}
        if sw:
            actions.append({"retired_sweep": sw})
            if "txid" in sw:
                self._anchor("retired_sweep")
        if self.anchor.due():
            r = self.anchor.anchor("periodic")
            if not r.get("ok") or not r.get("unchanged"):
                actions.append({"anchor": {k: r.get(k) for k in ("ok", "n", "seq", "alert", "reason")}})
        return actions

    def _watch_scripts(self) -> list[bytes]:
        """AGP-024: what a light backend subscribes to: every hot key (a close's change, a refund) and the
        funding script of every channel not yet settled (its spend is the close or the refund)."""
        from xbt402.channel import funding_script
        from xbt402.tx import p2wsh_spk
        spks = [k.spk for k in self.hot._keys()]
        for rec in self.channels.pending_records() + self.channels.unsettled_records() \
                + self.channels.pending_close_records():
            try:
                spks.append(p2wsh_spk(funding_script(bytes.fromhex(rec.payer_pub), bytes.fromhex(rec.payee_pub),
                                                     rec.expiry)))
            except (TypeError, ValueError):
                pass
        return spks

    def _watch_wait(self) -> bool:
        """Sleep until the next watcher tick; True when the signer is stopping. On a light backend the
        tick comes early when a subscribed script or the tip changes (AGP-022's pending change is
        retried as soon as the close reaches any server)."""
        if not self.light:
            return self._watch_stop.wait(self.watch_interval)
        try:
            self.rpc.watch(self._watch_scripts())
            self.rpc.wait_for_change(self.watch_interval)
        except Exception as e:
            print(f"watcher: subscriptions unavailable ({str(e)[:120]})", flush=True)
            return self._watch_stop.wait(self.watch_interval)
        return self._watch_stop.is_set()

    def _watch_loop(self) -> None:
        while not self._watch_wait():
            try:
                for a in self.watch_tick():
                    print(f"watcher: {json.dumps(a, sort_keys=True)}", flush=True)
            except Exception as e:  # the watcher must outlive a bad tick
                print(f"watcher error: {e}", flush=True)

    def _sweep_hot_signed(self, params: dict) -> dict:
        from xbt402.tx import address_to_spk
        from .approval import sweep_message

        to = (params.get("to") or params.get("address") or "").strip()
        try:
            amount = int(params.get("amount_sats") or 0)
            expiry = int(params.get("expiry") or 0)
            signature = x2b(params.get("signature") or "")
        except (TypeError, ValueError):
            return {"ok": False, "reason": "bad amount, expiry or signature"}
        if not self.human_pubkey or not signature or not verify(
                self.human_pubkey, sweep_message(self.hot.address, to, amount, expiry), signature):
            return {"ok": False, "reason": "sweep_hot requires a valid human signature"}
        if expiry < self.engine.clock():
            return {"ok": False, "reason": "sweep signature expired"}
        sigaudit.set_rule("human:sweep_signature")
        self._settle_close_changes()      # AGP-022: a pending close change is counted before the sweep
        try:
            out = self.hot.sweep_to(address_to_spk(to, self.hrp), amount)   # P5: this chain's hrp only
        except (RuntimeError, ValueError, KnotsRpcError) as e:
            return {"ok": False, "reason": str(e)[:200]}
        self.engine.audit.append({"type": "hot_sweep", "to": to, "sats": amount, "txid": out["txid"],
                                  "ts": self.engine.clock()})
        self._anchor("human_sweep")
        self._mine_safe()
        return {"ok": True, "to": to, **out, **self.hot.status()}

    def _uses_channel(self, dest: str) -> bool:
        dest = normalize_dest(dest)
        if self.channels.has(dest):
            return True
        if self.config.pay_to_for(dest):
            return True
        if dest.startswith(("http://", "https://")):
            return True
        return False

    def _pay_locked(self, params: dict, *, human: bool) -> dict:
        pay = self._payment(params)
        d = self.engine.evaluate(pay, human=human)
        if d.verdict is not Verdict.ALLOW:
            return d.as_dict()
        sigaudit.set_rule("human:approval_signature" if human else f"policy:{d.rule}")
        dest = pay.normalized(self.engine.clock()).dest
        if self._uses_channel(dest):
            return self._channel_pay(pay, dest, d, human=human)
        if self.light:
            return _deny("light_backend", "on-chain pay spends the node wallet, and a light client has none: "
                                          "pay through a channel")
        txid = self._send(pay)
        self.engine.commit(pay, txid=txid)
        try:
            self.vault.refresh()
        except KnotsRpcError:
            pass
        return {**d.as_dict(), "txid": txid, "rail": "onchain"}

    @staticmethod
    def _int(v) -> int:
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    def _human_signed(self, message: bytes, params: dict) -> dict | None:
        """None when `params["signature"]` is the human key's over `message` and `params["expiry"]` has
        not passed; else the deny (the Rust signer's rules and codes)."""
        if not self.human_pubkey:
            return _deny("human_key", "no human key is enrolled: run the setup first")
        try:
            sig = x2b(params.get("signature") or "")
        except ValueError:
            sig = b""
        if not sig or not verify(self.human_pubkey, message, sig):
            return _deny("human_sig", "missing or invalid human signature")
        if self._int(params.get("expiry")) < self.engine.clock():
            return _deny("expired", "the signature has expired")
        return None

    def _booked_increase(self, dest: str, cum: int, memo: str, sign):
        """Raise `dest`'s signed amount to `cum`: the increase over what the ledger already holds for
        the channel is evaluated and committed before `sign` runs (AGP-063 W1/K1); the row is taken
        out again when `sign` raises. Returns (result, None) or (None, deny)."""
        rec = self.channels.get(dest)
        origin = (rec.origin or dest) if rec is not None else dest
        booked = Xbt402Session._booked_through(rec)
        txid = f"xbt402:{rec.chan if rec else ''}:{cum}"
        if rec is not None and cum < rec.used_sats:
            return None, _deny("amount", f"never sign a lower cumulative amount: have {rec.used_sats}, got {cum}")
        increase = cum - booked
        added = False
        if increase > 0:
            pay = Payment(dest=origin, amount_sats=increase, memo=memo)
            d = self.engine.evaluate(pay, human=False)
            if d.verdict is not Verdict.ALLOW:
                return None, d.as_dict()
            sigaudit.set_rule(f"policy:{d.rule}")
            added = self.engine.commit_once(pay, txid)
        else:
            sigaudit.set_rule("policy:no_increase")
        try:
            out = sign()
        except Exception:
            if added:
                self.engine.store.amend(txid, None)
            raise
        if increase > 0 and rec is not None:
            self.channels.mark_ledger_booked(dest, cum)
        return out, None

    def _sign_state_locked(self, params: dict) -> dict:
        key = params.get("dest") or params.get("to") or params.get("chan") or ""
        dest = self.channels.find_dest(key) or normalize_dest(key)
        cum = self._int(params.get("cum") or params.get("amount"))
        sig, denied = self._booked_increase(dest, cum, "", lambda: self.channels.sign_state(dest, cum))
        if denied:
            return denied
        rec = self.channels.get(dest)
        return {"verdict": "allow", "chan": rec.chan if rec else "", "cum": cum, "sig": sig.hex() if sig else ""}

    def _floor_check(self, dest: str, asked: int, delta: int, *, human: bool) -> dict | None:
        """AGP-063 W1: a channel's dust floor signs more than the amount the policy approved, so the
        budgets are checked again on the whole increase. A human-threshold verdict is a refusal here."""
        d = self.engine.evaluate_booking(Payment(dest=dest, amount_sats=asked, memo="dust floor"), delta, human=human)
        if d.verdict is Verdict.ALLOW:
            return None
        if d.approval_token:
            self.engine.store.pop_approval(d.approval_token)
        return _deny(d.rule, f"the channel's dust floor signs {delta} sat: {d.reason}")

    def _channel_pay(self, pay: Payment, dest: str, d, *, human: bool = False) -> dict:
        rec = self.channels.get(dest)
        if rec is None or rec.state != "open":
            opened = self._open_channel_locked({"dest": dest})
            if opened.get("verdict") == "deny":
                return opened
        rec = self.channels.get(dest)
        try:
            cum = self.channels.next_cum(dest, pay.amount_sats)
        except ChannelCapError as e:
            return _deny("channel_cap", str(e))
        except (ChannelError, ValueError) as e:
            return _deny(getattr(e, "code", "bad_amount"), str(e))
        # AGP-063 W1/K1: book what this call signs (the dust floor on a first state), before it signs
        booked = Xbt402Session._booked_through(rec)
        if cum - booked > pay.amount_sats:
            refused = self._floor_check(pay.dest, pay.amount_sats, cum - booked, human=human)
            if refused:
                return refused
        txid = f"xbt402:{rec.chan}:{cum}"
        added = cum > booked and self.engine.commit_once(
            Payment(dest=pay.dest, amount_sats=cum - booked, memo=pay.memo, ts=pay.ts), txid)
        try:
            rec, _sig = self.channels.increment(dest, pay.amount_sats)
        except (ChannelCapError, ChannelError) as e:
            if added:
                self.engine.store.amend(txid, None)
            return _deny("channel_cap" if isinstance(e, ChannelCapError) else e.code, str(e))
        if cum > booked:
            self.channels.mark_ledger_booked(dest, rec.used_sats)
        return {
            **d.as_dict(),
            "rail": "channel",
            "booked_sats": max(0, cum - booked),
            "chan": rec.chan,
            "cum": rec.used_sats,
            "seq": rec.seq,
            "cap_sats": rec.cap_sats,
            "used_sats": rec.used_sats,
        }

    def _max_expiry_blocks(self) -> int:
        return max(self.config.channel_expiry_blocks, 4032)

    def _open_channel_checked(self, params: dict) -> dict:
        """AGP-063 W3: a caller on the agent socket opens a channel only to an allowlisted dest, to the
        policy's payTo, within the owner's cap, expiry and close-fee bounds."""
        dest = normalize_dest(params.get("dest") or params.get("to") or "")
        if dest and dest not in self.engine.allowlist:
            return _deny("allowlist", f"destination not on allowlist: {dest}")
        given = str(params.get("pay_to") or "").strip().lower()
        if given and given != (self.config.pay_to_for(dest) or "").strip().lower():
            return _deny("pay_to", "payTo comes from the policy's counterparties, never from the caller")
        cfg = self.config
        cap = self._int(params.get("cap_sats"))
        if cap < 0 or cap > cfg.per_counterparty_cap_sats:
            return _deny("channel_cap", f"cap_sats {cap} is above per_counterparty_cap_sats {cfg.per_counterparty_cap_sats}")
        blocks = self._int(params.get("expiry_blocks"))
        if blocks and (blocks <= cfg.refund_margin_blocks or blocks > self._max_expiry_blocks()):
            return _deny("expiry", f"expiry_blocks {blocks} outside ({cfg.refund_margin_blocks}, {self._max_expiry_blocks()}]")
        close_fee = self._int(params.get("close_fee"))
        if close_fee < 0 or (cfg.close_fee_max_sats > 0 and close_fee > cfg.close_fee_max_sats):
            return _deny("close_fee", f"close_fee {close_fee} is above close_fee_max_sats {cfg.close_fee_max_sats}")
        return self._open_channel_locked(params)

    def _open_channel_locked(self, params: dict) -> dict:
        dest = normalize_dest(params.get("dest") or params.get("to") or "")
        if not dest:
            return _deny("dest", "destination required")
        existing = self.channels.get(dest)
        if existing is not None and existing.state == "open":
            return {"verdict": "allow", "already": True, **existing.public()}
        if existing is not None and existing.close_unproven and not self._prove_close(dest):
            return _deny("close_unproven", f"the last channel to {dest} was reported closed, but this node has not "
                                           "seen its funding spent: a new one opens once it has, or after the refund")
        pay_to = (self.config.pay_to_for(dest) or "").strip()
        if not pay_to:
            return _deny("pay_to", f"no payTo pubkey registered for {dest}")
        cap = int(params.get("cap_sats") or self.config.per_counterparty_cap_sats)
        expiry_blocks = int(params.get("expiry_blocks") or self.config.channel_expiry_blocks)
        close_fee = int(params.get("close_fee") or 600)
        from xbt402.channel import ChannelParams

        try:
            self.hot.check_channel_funding()
        except HotCapError as e:
            return {**_deny("hot_balance_cap", str(e)), "action": "human_sweep",
                    "hot_sats": e.balance, "cap_sats": e.cap}
        secret, payer_pub = self.channels.new_payer_key()
        open_height = self._height()
        expiry = open_height + expiry_blocks
        p = ChannelParams.derive(pay_to, payer_pub, expiry, close_fee, self.hot.spk.hex(),
                                 network=self._xbt402.network())
        funded = cap + close_fee
        prep = self.hot.prepare_fund(p.spk, funded)
        p.funding_txid, p.funding_vout, p.capacity = prep["txid"], 0, funded
        # P1 write-ahead: this rail has no provider open, so the channel is open once the funding is sent
        self.channels.add_pending(dest, secret=secret, params=p, cap_sats=cap, open_height=open_height,
                                  funding_hex=prep["hex"])
        try:
            self.hot.broadcast(prep)
        except Exception:
            self.channels.drop_pending(dest, p.channel_id)
            raise
        self.hot.commit(prep)
        rec = self.channels.mark_open(dest)
        self._mine_safe()
        return {"verdict": "allow", "rail": "channel", **rec.public(), "funding_sighash": "0x21"}

    def _xbt402_pay_locked(self, params: dict) -> dict:
        url = params.get("url") or ""
        method = (params.get("method") or "GET").upper()
        body = params.get("body") or ""
        if isinstance(body, str):
            raw = body.encode()
        else:
            raw = bytes(body)
        try:
            max_sats = int(params["max_sats"]) if params.get("max_sats") is not None else 0
        except (TypeError, ValueError):
            return _deny("amount", "max_sats must be an integer")
        try:
            dest = origin_of(url)
        except ValueError as e:
            return _deny("dest", str(e))
        if max_sats < 0:
            return _deny("amount", "max_sats must be >= 0")
        if max_sats == 0:
            # Free-only: allowlisted dest, no channel open/update. A >0 price is refused in pay_once.
            if dest not in self.engine.allowlist:
                return _deny("allowlist", f"destination not on allowlist: {dest}")
            try:
                result = self._xbt402.pay_once(
                    url,
                    method,
                    raw,
                    max_sats=0,
                    expiry_blocks=self.config.channel_expiry_blocks,
                    cap_sats=self.config.per_counterparty_cap_sats,
                )
            except Exception as e:
                return _deny("xbt402", str(e))
            if result.get("verdict") == "deny":
                return result
            return {"verdict": "allow", "rule": "free", **result, "rail": "xbt402"}
        # AGP-063 W1: on an open channel the most this call can book (price <= max_sats) is known
        # before the 402, so the budgets are held to that
        bound = max_sats
        rec = self._xbt402.book.get(dest)
        if rec is not None and rec.state == "open":
            try:
                bound = self._xbt402.book.next_cum(dest, max_sats) - Xbt402Session._booked_through(rec)
            except (ChannelError, ValueError):
                pass
            if bound <= 0:
                bound = max_sats
        pay = Payment(dest=dest, amount_sats=max_sats, memo=f"xbt402 {method} {url}")
        d = self.engine.evaluate_booking(pay, bound, human=False)
        if d.verdict is not Verdict.ALLOW:
            return d.as_dict()
        sigaudit.set_rule(f"policy:{d.rule}")
        if rec is not None and rec.close_unproven:
            self._prove_close(dest)      # AGP-080: an honest close our node has seen by now; else add_pending refuses
        try:
            result = self._xbt402.pay_once(
                url,
                method,
                raw,
                max_sats=max_sats,
                expiry_blocks=self.config.channel_expiry_blocks,
                cap_sats=self.config.per_counterparty_cap_sats,
            )
        except ChannelCapError as e:
            return _deny("channel_cap", str(e))
        except HotCapError as e:
            return {**_deny("hot_balance_cap", str(e)), "action": "human_sweep", "hot_sats": e.balance, "cap_sats": e.cap}
        except ChannelError as e:
            return _deny(e.code, str(e))
        except Exception as e:
            return _deny("xbt402", str(e))
        if result.get("verdict") in ("deny", "pending"):
            return result
        # The signed delta was committed inside the session, before the signature left (AGP-063). A forward
        # lot is booked once delivered (its pre-signature pays nothing until the transfer is out).
        if result.get("rail") == "forward" and result.get("delivered"):
            self._book_forward(dest, result["chan"], int(result["cum"]), int(result["charged_sats"]),
                               f"forward {result['outpoint']}")
        return {**d.as_dict(), **result, "rail": "xbt402"}

    def _book_forward(self, dest: str, chan: str, cum: int, price: int, memo: str) -> None:
        """A delivered forward lot, under the signed state's id (xbt402:{chan}:{cum}) so neither a
        recovery nor the next call's catch-up books it twice."""
        if price > 0:
            self.engine.commit_once(Payment(dest=dest, amount_sats=price, memo=memo), txid=f"xbt402:{chan}:{cum}")
        if self.channels.get(dest) is not None:
            self.channels.mark_ledger_booked(dest, cum)

    def _book_signed_delta(self, dest: str, delta: int, chan: str, cum: int) -> None:
        if delta <= 0:
            raise ChannelError("amount", "signed delta must be positive")
        self.engine.commit_once(Payment(dest=dest, amount_sats=delta, memo="xbt402 signed delta"),
                                txid=f"xbt402:{chan}:{cum}")

    def _xbt402_request_auth(self, params: dict) -> dict:
        chan = params.get("chan") or ""
        try:
            auth = self.channels.request_auth(
                chan, params.get("seq"), params.get("cum"), params.get("sig") or "", params.get("req") or ""
            )
        except Exception as e:
            return _deny("xbt402_request_auth", str(e))
        return {"auth": auth}

    def _xbt402_sign_state_a3(self, params: dict) -> dict:
        chan = params.get("chan") or ""
        dest = self.channels.find_dest(chan) or chan
        amount = self._int(params.get("amount"))
        # AGP-080 W1: evaluated and committed before the state is signed, as every other state
        # (this path evaluated each step against a ledger it never wrote to)
        try:
            sig, denied = self._booked_increase(dest, amount, "xbt402 0xA3 state",
                                                lambda: self.channels.sign_state_a3(dest, amount))
        except Exception as e:
            return _deny("xbt402_sign_state_a3", str(e))
        if denied:
            return denied
        return {"sig": sig.hex() if isinstance(sig, bytes) else sig}

    def _xbt402_sign_state_adaptor(self, params: dict) -> dict:
        """AGP-021: pre-sign a routed lock under the routing policy and the ordinary policy engine."""
        try:
            chan, cum, point = params.get("chan") or "", int(params.get("cum") or 0), params.get("point") or ""
            route = params.get("route") if isinstance(params.get("route"), dict) else {}
            sigaudit.set_rule("policy:routing")
            out = self.routing.sign_state_adaptor(chan, cum, point, route)
        except ChannelCapError as e:
            return _deny("channel_cap", str(e))
        except ChannelError as e:
            return _deny(e.code, str(e))
        except (TypeError, ValueError) as e:
            return _deny("bad_request", str(e)[:200])
        return {"verdict": "allow", **out}

    def _xbt402_recover_lock(self, params: dict) -> dict:
        """After a restart: t + r from the hub's ch1 close (by txid; blockhash on a pruned node)."""
        from .netparams import get_tx
        from xbt402.tx import Tx
        raw = (get_tx(self.rpc, params.get("txid") or "", params.get("blockhash") or "") or {}).get("hex")
        if not raw:
            return _deny("unknown_tx", "close transaction not found")
        try:
            return {"t": self.routing.recover_lock(params.get("chan") or "", Tx.parse(bytes.fromhex(raw)))}
        except ChannelError as e:
            return _deny(e.code, str(e))

    def _close_channel_locked(self, params: dict) -> dict:
        raw = params.get("counterparty") or params.get("dest") or params.get("to") or ""
        dest = self.channels.find_dest(raw) or normalize_dest(raw)
        if not dest:
            return _deny("dest", "counterparty required")
        if not self.channels.has(dest) and self.channels.find_dest(raw) is None:
            return _deny("unknown_channel", f"no channel for {raw}")
        dest = self.channels.find_dest(raw) or dest
        try:
            return self._xbt402.close_channel(dest)
        except Exception as e:
            return _deny("close_channel", str(e))
        finally:
            self._anchor("close")

    def _fund_treasury_locked(self, params: dict) -> dict:
        """AGP-080 W3: hot funds go to the CSV treasury only on the human's signature over the hot
        address, the treasury address, the amount and an expiry (any socket caller could move any
        amount there, where only the treasury's keys or a 4320-block wait get it back)."""
        from .approval import treasury_fund_message

        sats = self._int(params.get("sats") or params.get("amount_sats"))
        if sats <= 0:
            return {"ok": False, "reason": "fund_treasury needs a positive amount"}
        refused = self._human_signed(
            treasury_fund_message(self.hot.address, self.treasury.address, sats, self._int(params.get("expiry"))), params)
        if refused:
            return {"ok": False, "reason": f"fund_treasury requires a valid human signature: {refused['reason']}",
                    "rule": refused["rule"]}
        sigaudit.set_rule("human:treasury_fund_signature")
        txid, vout = self.hot.fund(self.treasury.spk, sats)
        self.treasury.record_funding(txid, vout, sats)
        self._mine_safe()
        return {**self.treasury.status(), "txid": txid, "vout": vout, "sighash": "0x21"}

    def _recover_treasury_locked(self, params: dict) -> dict:
        from xbt402.tx import address_to_spk

        dest = params.get("to") or params.get("address") or self.vault.recovery_address
        try:
            expiry = int(params.get("expiry") or 0)
        except (TypeError, ValueError):
            expiry = 0
        sig_hex = params.get("signature") or ""
        try:
            signature = x2b(sig_hex) if sig_hex else b""
        except ValueError:
            return {"ok": False, "reason": "signature is not valid hex"}
        from .approval import treasury_recover_message

        now = self.engine.clock()
        # AGP-080 W3: the signature names the destination it pays
        if not self.human_pubkey or not signature or not verify(
            self.human_pubkey, treasury_recover_message(self.treasury.address, dest, expiry), signature
        ):
            return {"ok": False, "reason": "recover_treasury requires a valid human signature over "
                                           "(treasury address, destination, expiry)"}
        if expiry < now:
            return {"ok": False, "reason": "recover signature expired"}
        try:
            dest_spk = address_to_spk(dest, self.hrp)
        except ValueError as e:
            return {"ok": False, "reason": str(e)}
        tx = self.treasury.recovery_tx(dest_spk)
        self.sigaudit.record("treasury_recovery", sig=tx.inputs[0].witness[0], dest=dest, txid=tx.txid(),
                             rule="human:recover_signature", sighash="0x21")
        try:
            txid = self.rpc.call("sendrawtransaction", tx.hex())
        except KnotsRpcError as e:
            return {"ok": False, "reason": str(e), "need_csv": self.treasury.csv}
        finally:
            self._anchor("treasury_recovery")
        return {"ok": True, "txid": txid, "csv": self.treasury.csv, "to": dest}

    def _approve_signed(self, params: dict) -> dict:
        token = params.get("token") or ""
        dest = (params.get("dest") or params.get("to") or "").strip()
        if dest.lower().startswith(("bc1", "bcrt1", "tb1")):
            dest = dest.lower()
        if "amount_sats" in params and params["amount_sats"] is not None:
            amount = int(params["amount_sats"])
        else:
            amount = sats_from_xbt(params.get("amount_xbt") or 0)
        try:
            expiry = int(params.get("expiry") or 0)
        except (TypeError, ValueError):
            expiry = 0
        sig_hex = params.get("signature") or params.get("sig") or ""
        try:
            signature = x2b(sig_hex) if sig_hex else b""
        except ValueError:
            return _deny("approval_sig", "signature is not valid hex")

        if not self.human_pubkey:
            return _deny("approval_sig", "signer has no human public key configured")
        if not signature or not verify_approval(self.human_pubkey, token, dest, amount, expiry, signature):
            self.engine.audit.append(
                {
                    "type": "decision",
                    "verdict": "deny",
                    "rule": "approval_sig",
                    "reason": "missing or invalid human signature",
                    "dest": dest,
                    "amount_sats": amount,
                    "ts": self.engine.clock(),
                }
            )
            return _deny("approval_sig", "missing or invalid human signature over (token, dest, amount, expiry)")

        payload = self.engine.store.get_approval(token)
        if not payload:
            self.engine.audit.append({"type": "approval_miss", "token": token, "ts": self.engine.clock()})
            return _deny("approval", "unknown or already-used approval token")
        if payload.get("used"):
            return _deny("approval_replay", "approval token already used")

        now = self.engine.clock()
        stored_exp = int(payload.get("expires") or 0)
        if stored_exp < now or expiry < now:
            self.engine.store.pop_approval(token)
            self.engine.audit.append({"type": "approval_expired", "token": token, "ts": now})
            return _deny("approval_expired", "approval token expired")

        stored_dest = payload.get("dest") or ""
        stored_amt = int(payload.get("amount_sats") or 0)
        if dest != stored_dest or amount != stored_amt or expiry != stored_exp:
            self.engine.audit.append(
                {
                    "type": "decision",
                    "verdict": "deny",
                    "rule": "approval_bind",
                    "reason": "signature fields do not match pending approval",
                    "dest": dest,
                    "amount_sats": amount,
                    "ts": now,
                }
            )
            return _deny("approval_bind", "signature fields do not match the pending approval")

        pay = self.engine.consume_approval(token)
        if pay is None:
            return _deny("approval", "unknown or expired approval token")
        settled = self._pay_locked({"to": pay.dest, "amount_sats": pay.amount_sats, "memo": pay.memo}, human=True)
        if settled.get("verdict") == "allow":
            settled["approved"] = True
        return settled

    def _recover_signed(self, params: dict) -> dict:
        from .approval import recover_message

        try:
            expiry = int(params.get("expiry") or 0)
        except (TypeError, ValueError):
            expiry = 0
        sig_hex = params.get("signature") or ""
        try:
            signature = x2b(sig_hex) if sig_hex else b""
        except ValueError:
            return {"ok": False, "reason": "signature is not valid hex"}
        addr = self.vault.recovery_address
        now = self.engine.clock()
        if not self.human_pubkey or not signature or not verify(self.human_pubkey, recover_message(addr, expiry), signature):
            return {"ok": False, "reason": "recover_vault requires a valid human signature"}
        if expiry < now:
            return {"ok": False, "reason": "recover signature expired"}
        return self.vault.recover(human=True)

    def _payment(self, params: dict) -> Payment:
        if "amount_sats" in params and params["amount_sats"] is not None:
            amount = int(params["amount_sats"])
        else:
            amount = sats_from_xbt(params.get("amount_xbt") or 0)
        return Payment(dest=params.get("to") or params.get("dest") or "", amount_sats=amount, memo=params.get("memo") or "")

    def _send(self, pay: Payment) -> str:
        xbt = f"{pay.amount_sats / XBT_SATS:.8f}"
        return self.rpc.call("sendtoaddress", pay.dest, xbt, pay.memo, "", False)

    def serve(self) -> None:
        if self.sock_path.exists():
            self.sock_path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.sock_path))
        sock.listen(8)
        os.chmod(self.sock_path, 0o600)
        print(f"signer listening on {self.sock_path}", flush=True)
        if self.watch_interval > 0:
            threading.Thread(target=self._watch_loop, name="expiry-watcher", daemon=True).start()

        def client(conn: socket.socket):
            buf = b""
            try:
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if not line.strip():
                            continue
                        req = json.loads(line.decode())
                        try:
                            result = self.handle(req)
                            resp = {"id": req.get("id"), "result": result}
                        except Exception as e:
                            resp = {"id": req.get("id"), "error": {"message": str(e)}}
                        conn.sendall((json.dumps(resp) + "\n").encode())
            finally:
                conn.close()

        while True:
            conn, _ = sock.accept()
            threading.Thread(target=client, args=(conn,), daemon=True).start()


class SignerClient:
    def __init__(self, sock_path: Path):
        self.sock_path = Path(sock_path)

    def call(self, op: str, **params):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(float(os.environ.get("B2_SIGNER_TIMEOUT", "60")))
        sock.connect(str(self.sock_path))
        req = {"id": 1, "method": op, "params": params}
        sock.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        sock.close()
        resp = json.loads(buf.decode())
        if resp.get("error"):
            raise RuntimeError(resp["error"]["message"])
        return resp.get("result")


def main() -> None:
    root = Path(os.environ.get("B2_ROOT", Path(__file__).resolve().parent.parent))
    Signer(root).serve()


if __name__ == "__main__":
    main()
