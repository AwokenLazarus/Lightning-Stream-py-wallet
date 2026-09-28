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
import os
import socket
import threading
import time
from pathlib import Path

from . import anchor as anchoring, netparams, sigaudit
from .approval import verify, verify_approval, x2b
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


def sats_from_xbt(amount_xbt) -> int:
    # Decimal-safe: work in integer millisats via string
    s = str(amount_xbt).strip()
    if s.startswith("-"):
        return -1
    if "." in s:
        whole, frac = s.split(".", 1)
        frac = (frac + "00000000")[:8]
        return int(whole or "0") * XBT_SATS + int(frac)
    return int(s) * XBT_SATS


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
        self.rpc = rpc if rpc is not None else KnotsRpc(datadir, conf, wallet=wallet)
        # AGP-017 P3/P5: the chain decides the hrp and whether this process may ever mine
        self.chain = netparams.detect_chain(self.rpc)
        if self.config.regtest_mine and not netparams.mining_allowed(self.chain):
            raise netparams.ChainError(f"policy regtest_mine is set but the node is on {self.chain!r}: "
                                       "refusing to start (only regtest may mine)")
        self.mining = netparams.mining_allowed(self.chain) and self.config.regtest_mine is not False
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
        from .routing import RoutePolicy, RouteSigner
        self.routing = RouteSigner(self.channels, RoutePolicy.from_dict(self.config.routing),
                                   state_path=run / "routing.json", engine=self.engine)
        self._open_tried: dict[str, float] = {}
        self._watch_stop = threading.Event()
        self.watch_interval = float(os.environ.get("B2_WATCH_INTERVAL", "10"))

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
            bals = self.rpc.call("getbalances")
            mine = bals.get("mine") or {}
            return sanitize(
                {
                    "trusted_sats": int(round(float(mine.get("trusted", 0)) * XBT_SATS)),
                    "untrusted_pending_sats": int(round(float(mine.get("untrusted_pending", 0)) * XBT_SATS)),
                    "immature_sats": int(round(float(mine.get("immature", 0)) * XBT_SATS)),
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
            return {"ok": True, "wallet": self.rpc.wallet, "chain": self.chain, "hrp": self.hrp, "mining": self.mining}
        if method == "channels":
            return sanitize({"channels": self.channels.list_public(), "height": self._height_safe()})
        if method == "hot_address":
            return sanitize(self._hot_status())
        if method == "notice_hot_txid":
            n = self.hot.scan_from_txid(params.get("txid") or "")
            return sanitize({**self.hot.status(), "noticed": n})
        if method == "fund":
            # B1 / XBT-060 wallet hook: 0x21 funding from the signer hot key.
            from xbt402.tx import address_to_spk

            sats = int(params.get("sats") or params.get("amount_sats") or 0)
            addr = params.get("address") or params.get("to") or ""
            txid, vout = self.hot.fund(address_to_spk(addr, self.hrp), sats)
            return sanitize({"txid": txid, "vout": vout, "sats": sats, "sighash": "0x21"})
        if method == "open_channel":
            with self._spend_lock:
                return sanitize(self._open_channel_locked(params))
        if method == "sign_state":
            dest = normalize_dest(params.get("dest") or params.get("to") or "")
            cum = int(params.get("cum") or 0)
            pay = Payment(dest=dest, amount_sats=max(0, cum - (self.channels.get(dest).used_sats if self.channels.get(dest) else 0)))
            d = self.engine.evaluate(pay, human=False)
            if d.verdict is not Verdict.ALLOW:
                return sanitize(d.as_dict())
            sigaudit.set_rule(f"policy:{d.rule}")
            sig = self.channels.sign_state(dest, cum)
            self.engine.commit(pay, txid=(self.channels.get(dest) or type("R", (), {"chan": ""})).chan)
            return sanitize({"verdict": "allow", "chan": self.channels.get(dest).chan, "cum": cum, "sig": sig.hex() if sig else ""})
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
                if res.get("recovered"):     # the policy ledger learns the spend it could not see live
                    self.engine.commit(Payment(dest=res["dest"], amount_sats=res["price"],
                                               memo=f"forward {res['outpoint']} (recovered)"), txid=res["transfer_txid"])
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
                sigaudit.set_rule("operator:rotate_hot_key")
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
        self.engine.audit.append({"type": "refund", "dest": dest, "chan": rec.chan, "txid": txid, "sats": sats,
                                  "auto": auto, "ts": self.engine.clock()})
        self._anchor("refund")
        return {"verdict": "allow", "rule": "refund", **base, "txid": txid, "sats": sats,
                "to": self.hot.address, "auto": auto}

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

    def _watch_loop(self) -> None:
        while not self._watch_stop.wait(self.watch_interval):
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
            return self._channel_pay(pay, dest, d)
        txid = self._send(pay)
        self.engine.commit(pay, txid=txid)
        try:
            self.vault.refresh()
        except KnotsRpcError:
            pass
        return {**d.as_dict(), "txid": txid, "rail": "onchain"}

    def _channel_pay(self, pay: Payment, dest: str, d) -> dict:
        rec = self.channels.get(dest)
        if rec is None or rec.state != "open":
            opened = self._open_channel_locked({"dest": dest})
            if opened.get("verdict") == "deny":
                return opened
        try:
            rec, _sig = self.channels.increment(dest, pay.amount_sats)
        except ChannelCapError as e:
            return _deny("channel_cap", str(e))
        except ChannelError as e:
            return _deny(e.code, str(e))
        self.engine.commit(pay, txid=rec.chan)
        return {
            **d.as_dict(),
            "rail": "channel",
            "chan": rec.chan,
            "cum": rec.used_sats,
            "seq": rec.seq,
            "cap_sats": rec.cap_sats,
            "used_sats": rec.used_sats,
        }

    def _open_channel_locked(self, params: dict) -> dict:
        dest = normalize_dest(params.get("dest") or params.get("to") or "")
        if not dest:
            return _deny("dest", "destination required")
        existing = self.channels.get(dest)
        if existing is not None and existing.state == "open":
            return {"verdict": "allow", "already": True, **existing.public()}
        pay_to = (params.get("pay_to") or self.config.pay_to_for(dest) or "").strip()
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
        pay = Payment(dest=dest, amount_sats=max_sats, memo=f"xbt402 {method} {url}")
        d = self.engine.evaluate(pay, human=False)
        if d.verdict is not Verdict.ALLOW:
            return d.as_dict()
        sigaudit.set_rule(f"policy:{d.rule}")
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
        charged = int(result.get("charged_sats") or 0)
        if charged:
            self.engine.commit(Payment(dest=dest, amount_sats=charged, memo=pay.memo), txid=result.get("chan") or "")
        return {**d.as_dict(), **result, "rail": "xbt402"}

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
        amount = int(params.get("amount") or 0)
        rec = self.channels.get(dest)
        origin = rec.origin or dest if rec else dest
        pay = Payment(dest=origin, amount_sats=max(0, amount - (rec.used_sats if rec else 0)))
        if pay.amount_sats:
            d = self.engine.evaluate(pay, human=False)
            if d.verdict is not Verdict.ALLOW:
                return d.as_dict()
            sigaudit.set_rule(f"policy:{d.rule}")
        else:
            sigaudit.set_rule("policy:no_increase")
        try:
            sig = self.channels.sign_state_a3(dest, amount)
        except Exception as e:
            return _deny("xbt402_sign_state_a3", str(e))
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
        sats = int(params.get("sats") or params.get("amount_sats") or 0)
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
        from .approval import recover_message

        now = self.engine.clock()
        if not self.human_pubkey or not signature or not verify(
            self.human_pubkey, recover_message(self.treasury.address, expiry), signature
        ):
            return {"ok": False, "reason": "recover_treasury requires a valid human signature"}
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
