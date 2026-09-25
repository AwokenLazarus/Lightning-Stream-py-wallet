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
from .policy import Payment, PolicyConfig, PolicyEngine, PolicyStore, AuditLog, Verdict
from .rpc import KnotsRpc, KnotsRpcError
from .sanitize import sanitize
from .vault import PresignedVault

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
            pay = self._payment(params)
            d = self.engine.evaluate(pay, human=False)
            if d.verdict is Verdict.ALLOW:
                txid = self._send(pay)
                self.engine.commit(pay, txid=txid)
                try:
                    self.vault.refresh()
                except KnotsRpcError:
                    pass
                return sanitize({**d.as_dict(), "txid": txid})
            return sanitize(d.as_dict())
        if method == "approve":
            return sanitize(self._approve_signed(params))
        if method == "history":
            limit = int(params.get("limit") or 50)
            return sanitize({"events": self.engine.audit.read(limit=limit)})
        if method == "recover_vault":
            return sanitize(self._recover_signed(params))
        if method == "health":
            return {"ok": True, "wallet": self.rpc.wallet}
        raise ValueError(f"unknown method {method}")

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
        d = self.engine.evaluate(pay, human=True)
        if d.verdict is not Verdict.ALLOW:
            return d.as_dict()
        txid = self._send(pay)
        self.engine.commit(pay, txid=txid)
        try:
            self.vault.refresh()
        except KnotsRpcError:
            pass
        return {**d.as_dict(), "txid": txid, "approved": True}

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

    def call(self, method: str, **params):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect(str(self.sock_path))
        req = {"id": 1, "method": method, "params": params}
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
