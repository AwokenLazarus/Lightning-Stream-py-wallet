"""Knots JSON-RPC over cookie auth. Never dumps keys."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


class KnotsRpcError(RuntimeError):
    pass


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
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode() if e.fp else str(e)
            raise KnotsRpcError(f"RPC HTTP {e.code}: {raw[:400]}") from e
        if body.get("error"):
            raise KnotsRpcError(str(body["error"]))
        return body.get("result")
