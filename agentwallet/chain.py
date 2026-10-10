"""ChainBackend: where the signer reads the chain from (AGP-024).

A backend is any object with `call(method, *params)` answering these node RPCs, which are every chain
call B2's client path makes. The RPC backend is KnotsRpc itself, unchanged. The light backend
(electrum.py) answers each one from Electrum servers and verifies it:

| RPC (caller) | Electrum | verified by |
|---|---|---|
| getblockchaininfo (netparams.detect_chain, hot.reconcile) | blockchain.headers.subscribe, blockchain.block.header(s) | our BLAKE2b header chain from the checkpoint |
| getblockcount, getblockhash, getblockheader (height, network id, expiry) | same | same |
| gettxout (funding confirmations, refund, close change, reconcile) | transaction.get, scripthash.get_history, transaction.get_merkle | txid hash, Merkle proof into our header, union of histories for spends |
| gettxspendingprevout (close detection) | scripthash.get_history + transaction.get | spend parsed from the tx itself |
| getrawtransaction (close, lock recovery, change) | transaction.get + get_history + get_merkle | txid hash, Merkle proof |
| sendrawtransaction (funding, refund, sweeps) | transaction.broadcast (every server) | txid of what we sent |
| scantxoutset raw(spk) (hot-key coins) | scripthash.listunspent (every server) | each coin's tx and proof; confirmed-spent excluded |
| estimatesmartfee (quote_payment) | blockchain.estimatefee | not verifiable: reported as unverified |

Not available on the light backend, and refused with LightBackendError (a KnotsRpcError): the Knots
wallet (getbalances, sendtoaddress, listunspent, fundrawtransaction, signrawtransactionwithwallet:
`balance`'s node-wallet fields, on-chain `pay`, the presigned vault), mining, and getblock (the block
scans that stand in for txindex are not needed: spends come from script histories).

Selection (`backend_from_env`), environment:
  B2_CHAIN_BACKEND      rpc (default without Electrum servers) | electrum | auto (default with them):
                        auto uses the local node when it answers, else Electrum
  B2_ELECTRUM_SERVERS   comma-separated tcp://host:port or ssl://host:port
  B2_ELECTRUM_CHECKPOINT <height>:<hash>; mainnet defaults to 961640 (the first BLAKE2b block)
  B2_ELECTRUM_MIN_SERVERS servers that must answer (default 2 on mainnet, 1 elsewhere)
  B2_ELECTRUM_TIMEOUT   seconds per request (default 15)
  B2_ELECTRUM_SYNC_DEADLINE seconds one server has for its part of a header sync (default 4 timeouts)
  B2_CHAIN              the chain (required for electrum: a light client does not ask a node)
"""

from __future__ import annotations

import os
from pathlib import Path

from .rpc import KnotsRpc

ENV_BACKEND = "B2_CHAIN_BACKEND"
ENV_SERVERS = "B2_ELECTRUM_SERVERS"
ENV_CHECKPOINT = "B2_ELECTRUM_CHECKPOINT"
ENV_MIN_SERVERS = "B2_ELECTRUM_MIN_SERVERS"
ENV_TIMEOUT = "B2_ELECTRUM_TIMEOUT"
ENV_SYNC_DEADLINE = "B2_ELECTRUM_SYNC_DEADLINE"
BACKENDS = ("rpc", "electrum", "auto")


class BackendError(RuntimeError):
    pass


def backend_mode() -> str:
    mode = os.environ.get(ENV_BACKEND, "").strip().lower()
    if not mode:
        mode = "auto" if os.environ.get(ENV_SERVERS, "").strip() else "rpc"
    if mode not in BACKENDS:
        raise BackendError(f"{ENV_BACKEND}={mode!r}: use one of {', '.join(BACKENDS)}")
    return mode


def node_answers(rpc) -> bool:
    try:
        return isinstance(rpc.call("getblockchaininfo"), dict)
    except Exception:
        return False


def electrum_from_env(run_dir: Path):
    from .electrum import ElectrumBackend, checkpoint_from_env, servers_from_env
    from .netparams import ENV_CHAIN

    chain = os.environ.get(ENV_CHAIN, "").strip()
    if not chain:
        raise BackendError(f"the Electrum backend needs {ENV_CHAIN} (a light client has no node to ask)")
    servers = servers_from_env(os.environ.get(ENV_SERVERS))
    if not servers:
        raise BackendError(f"the Electrum backend needs {ENV_SERVERS}")
    ms = os.environ.get(ENV_MIN_SERVERS, "").strip()
    deadline = os.environ.get(ENV_SYNC_DEADLINE, "").strip()
    return ElectrumBackend(servers, chain=chain, checkpoint=checkpoint_from_env(os.environ.get(ENV_CHECKPOINT)),
                           store_path=Path(run_dir) / f"headers-{chain}.bin",
                           timeout=float(os.environ.get(ENV_TIMEOUT, "15")), min_servers=int(ms) if ms else None,
                           sync_deadline=float(deadline) if deadline else None)


def backend_from_env(datadir: Path, conf: Path, wallet: str, run_dir: Path):
    """KnotsRpc (rpc; auto with a node that answers) or ElectrumBackend (electrum; auto without one)."""
    mode = backend_mode()
    rpc = KnotsRpc(datadir, conf, wallet=wallet)
    if mode == "rpc" or (mode == "auto" and node_answers(rpc)):
        return rpc
    return electrum_from_env(run_dir)


def is_light(backend) -> bool:
    return bool(getattr(backend, "light", False))
