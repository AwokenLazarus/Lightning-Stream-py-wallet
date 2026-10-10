"""Knots JSON-RPC over cookie auth. Never dumps keys."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


class KnotsRpcError(RuntimeError):
    pass


class KnotsRpcRefused(KnotsRpcError):
    """The node answered the call with a JSON-RPC error: it did not do what was asked. Every other
    failure is a plain KnotsRpcError: the call may or may not have run (AGP-084: `pay` keeps its
    booking then). The Rust signer's `rpc_refused`."""


class KnotsRpc:
    def __init__(self, datadir: Path, conf: Path, wallet: str = "agent"):
        self.datadir = Path(datadir)
        self.conf = Path(conf)
        self.wallet = wallet
        self._url = None
        self._auth = None
        # AGP-017 P3: block-generating RPCs only when the signer has confirmed the node is regtest
        self.allow_generate = False

    def _cookie(self) -> tuple[str, str]:
        # Knots writes the cookie under <datadir>/regtest/.cookie
        candidates = [
            self.datadir / "regtest" / ".cookie",
            self.datadir / ".cookie",
        ]
        for c in candidates:
            if c.exists():
                user, pw = c.read_text(encoding="utf-8").strip().split(":", 1)
                return user, pw
        raise KnotsRpcError(f"RPC cookie not found under {self.datadir}")

    def _endpoint(self) -> str:
        port = os.environ.get("B2_RPCPORT", "19443")
        return f"http://127.0.0.1:{port}/wallet/{self.wallet}"

    def call(self, method: str, *params):
        forbidden = {
            "dumpprivkey",
            "dumpwallet",
            "dumpmasterprivkey",
            "listdescriptors",
            "getdescriptorinfo",
            "importdescriptors",
            "importprivkey",
            "sethdseed",
            "backupwallet",
        }
        if method.lower() in forbidden:
            raise KnotsRpcError(f"signer refuses RPC method {method}")
        if method.lower() in {"generatetoaddress", "generatetodescriptor", "generateblock", "generate"} \
                and not self.allow_generate:
            raise KnotsRpcError(f"signer refuses {method}: mining is for regtest only")
        user, pw = self._cookie()
        payload = json.dumps({"jsonrpc": "1.0", "id": "b2", "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(
            self._endpoint(),
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # Basic auth from cookie
        import base64

        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            # a JSON-RPC error comes back with HTTP 500 (404 for an unknown method) and a body
            raw = e.read() if e.fp else b""
            refusal = _rpc_error(raw)
            if refusal is not None:
                raise KnotsRpcRefused(refusal) from e
            raise KnotsRpcError(f"RPC HTTP {e.code}: {raw.decode(errors='replace')[:400] or e}") from e
        except OSError as e:                # no connection, a reset, a timeout: the call may have run
            raise KnotsRpcError(f"RPC transport: {e}") from e
        refusal = _rpc_error(raw)
        if refusal is not None:
            raise KnotsRpcRefused(refusal)
        try:
            body = json.loads(raw.decode())
            return body.get("result")
        except (ValueError, AttributeError) as e:
            raise KnotsRpcError(f"RPC answer is not JSON-RPC: {raw[:200]!r}") from e


def _rpc_error(raw: bytes) -> str | None:
    """The node's JSON-RPC error in `raw`, or None when `raw` is not a JSON-RPC answer carrying one."""
    try:
        body = json.loads(raw.decode())
    except ValueError:
        return None
    err = body.get("error") if isinstance(body, dict) else None
    return str(err) if err else None
