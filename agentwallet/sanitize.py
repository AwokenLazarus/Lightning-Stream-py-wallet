"""Strip and refuse key material so MCP responses never leak secrets."""

from __future__ import annotations

import re
from typing import Any

_KEY_NAMES = re.compile(
    r"(priv|wif|seed|xprv|xpub|descriptor|cookie|rpcpassword|passphrase|mnemonic|secret)",
    re.I,
)
# WIF / extended keys only. 64-hex is a txid and must stay in MCP responses.
_WIF = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
_XPRV = re.compile(r"\b[xt]prv[1-9A-HJ-NP-Za-km-z]{20,}\b")


class KeyMaterialError(ValueError):
    pass


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if _KEY_NAMES.search(str(k)):
                continue
            out[k] = sanitize(v)
        return out
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        if _XPRV.search(value) or _WIF.search(value):
            return "[redacted]"
        return value
    return value


def assert_no_key_material(value: Any) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if _KEY_NAMES.search(str(k)):
                raise KeyMaterialError(f"forbidden field: {k}")
            assert_no_key_material(v)
        return
    if isinstance(value, list):
        for v in value:
            assert_no_key_material(v)
        return
    if isinstance(value, str):
        if _XPRV.search(value) or _WIF.search(value) or value.startswith(("xprv", "tprv")):
            raise KeyMaterialError("key-shaped string in response")
