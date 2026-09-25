"""Signer process: owns Knots RPC + policy. MCP talks only to this socket.

Human approval is cryptographic: the signer holds only an ed25519 public key.
`approve` and `recover_vault` require a signature by that key. There is no
`human=` boolean. Those methods are not MCP tools.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

from .approval import verify, verify_approval, x2b
from .channels import ChannelBook, ChannelCapError
from .hot import HotWallet
from .policy import Payment, PolicyConfig, PolicyEngine, PolicyStore, AuditLog, Verdict, normalize_dest
from .rpc import KnotsRpc, KnotsRpcError
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
        recovery = raw.get("recovery_address") or os.environ.get("B2_RECOVERY", "")
        self.vault = PresignedVault(run / "vault.json", self.rpc, recovery)
        self.sock_path = Path(os.environ.get("B2_SIGNER_SOCK", run / "signer.sock"))
        pub_hex = (raw.get("human_pubkey") or "").strip()
        self.human_pubkey = x2b(pub_hex) if pub_hex else b""
        self._spend_lock = threading.Lock()
        self.hot = HotWallet(run / "hot.json", self.rpc)
        self.treasury = Treasury(run / "treasury.json", csv=int(getattr(self.config, "treasury_csv", TREASURY_CSV) or TREASURY_CSV))
        self.channels = ChannelBook(run / "channels.json", run / "channel_keys.json")
        self._xbt402 = Xbt402Session(self.channels, self.hot, self.rpc, height=self._height, mine=self._mine)

    def handle(self, req: dict) -> dict:
        method = req.get("method")
        params = req.get("params") or {}
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
                    "hot": self.hot.status(),
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
            return {"ok": True, "wallet": self.rpc.wallet}
        if method == "channels":
            return sanitize({"channels": self.channels.list_public(), "height": self._height_safe()})
        if method == "hot_address":
            return sanitize(self.hot.status())
        if method == "notice_hot_txid":
            n = self.hot.scan_from_txid(params.get("txid") or "")
            return sanitize({**self.hot.status(), "noticed": n})
        if method == "fund":
            # B1 / XBT-060 wallet hook: 0x21 funding from the signer hot key.
            from xbt402.tx import address_to_spk

            sats = int(params.get("sats") or params.get("amount_sats") or 0)
            addr = params.get("address") or params.get("to") or ""
            txid, vout = self.hot.fund(address_to_spk(addr), sats)
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
        if method == "close_channel":
            with self._spend_lock:
                return sanitize(self._close_channel_locked(params))
        if method == "fund_treasury":
            with self._spend_lock:
                return sanitize(self._fund_treasury_locked(params))
        if method == "recover_treasury":
            return sanitize(self._recover_treasury_locked(params))
        raise ValueError(f"unknown method {method}")

    def _height(self) -> int:
        return int(self.rpc.call("getblockcount"))

    def _height_safe(self) -> int:
        try:
            return self._height()
        except Exception:
            return 0

    def _mine(self, n: int = 1) -> None:
        addr = self.rpc.call("getnewaddress", "mine", "bech32")
        self.rpc.call("generatetoaddress", int(n), addr)

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
        if not self.channels.has(dest):
            opened = self._open_channel_locked({"dest": dest})
            if opened.get("verdict") == "deny":
                return opened
        try:
            rec, _sig = self.channels.increment(dest, pay.amount_sats)
        except ChannelCapError as e:
            return _deny("channel_cap", str(e))
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
        if self.channels.has(dest):
            return {"verdict": "allow", "already": True, **self.channels.get(dest).public()}
        pay_to = (params.get("pay_to") or self.config.pay_to_for(dest) or "").strip()
        if not pay_to:
            return _deny("pay_to", f"no payTo pubkey registered for {dest}")
        cap = int(params.get("cap_sats") or self.config.per_counterparty_cap_sats)
        expiry_blocks = int(params.get("expiry_blocks") or self.config.channel_expiry_blocks)
        close_fee = int(params.get("close_fee") or 600)
        from xbt402.channel import ChannelParams

        secret, payer_pub = self.channels.new_payer_key()
        expiry = self._height() + expiry_blocks
        p = ChannelParams.derive(pay_to, payer_pub, expiry, close_fee, self.hot.spk.hex(),
                                 network=self._xbt402.network())
        funded = cap + close_fee
        txid, vout = self.hot.fund(p.spk, funded)
        p.funding_txid, p.funding_vout, p.capacity = txid, vout, funded
        try:
            self._mine(1)
        except Exception:
            pass
        rec = self.channels.add_funded(dest, secret=secret, params=p, cap_sats=cap)
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
        except Exception as e:
            return _deny("xbt402", str(e))
        if result.get("verdict") == "deny":
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
        try:
            sig = self.channels.sign_state_a3(dest, amount)
        except Exception as e:
            return _deny("xbt402_sign_state_a3", str(e))
        return {"sig": sig.hex() if isinstance(sig, bytes) else sig}

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

    def _fund_treasury_locked(self, params: dict) -> dict:
        sats = int(params.get("sats") or params.get("amount_sats") or 0)
        txid, vout = self.hot.fund(self.treasury.spk, sats)
        self.treasury.record_funding(txid, vout, sats)
        try:
            self._mine(1)
        except Exception:
            pass
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
        tx = self.treasury.recovery_tx(address_to_spk(dest))
        try:
            txid = self.rpc.call("sendrawtransaction", tx.hex())
        except KnotsRpcError as e:
            return {"ok": False, "reason": str(e), "need_csv": self.treasury.csv}
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
        sock.settimeout(60)
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
