"""Which chain the signer is on, and what follows from it (AGP-017 P3, P4, P5, P6).

The signer asks its node (`getblockchaininfo.chain`) once at start. From that:
  * the bech32 hrp of the hot key, the treasury and every sweep destination (P5): `bc` on mainnet;
  * the xbt402 network id (P4): on mainnet `network_id(getblockhash(961640))`, the spec's anchor, and
    it must equal B1's XBT_MAINNET; on regtest the spec's own rule, the block where the rig switches
    to BLAKE2b (101);
  * whether the signer may mine (P3): only on regtest.

B2_CHAIN, when set, must agree with the node; it is also what the signer uses when the node cannot be
reached at start. With neither, the signer refuses to start rather than guess.

Pruned nodes (P6) have no txindex: `get_tx` looks a transaction up in the mempool, then in a known
block, and `find_spender` scans blocks for the spend of an outpoint.
"""

from __future__ import annotations

import os

from .b1path import ensure_b1

ensure_b1()
from xbt402.x402_channel import XBT_MAINNET, network_id  # noqa: E402

ENV_CHAIN = "B2_CHAIN"
MAINNET_ANCHOR = 961_640
REGTEST_ANCHOR = 101
HRP = {"main": "bc", "test": "tb", "testnet4": "tb", "signet": "tb", "regtest": "bcrt"}
SPENDER_SCAN_MAX = 4_032        # blocks find_spender reads before giving up (4 weeks on mainnet)


class ChainError(RuntimeError):
    pass


def detect_chain(rpc) -> str:
    """The node's chain, checked against B2_CHAIN. Raises ChainError when neither can say."""
    want = os.environ.get(ENV_CHAIN, "").strip() or None
    try:
        info = rpc.call("getblockchaininfo") or {}
    except Exception as e:
        if want:
            return _known(want)
        raise ChainError(f"cannot reach the node to learn its chain ({str(e)[:120]}); set {ENV_CHAIN}") from e
    got = info.get("chain") or want or "regtest"   # test doubles without a chain field are regtest rigs
    if want and got != want:
        raise ChainError(f"the node is on {got!r} but {ENV_CHAIN}={want!r}")
    return _known(got)


def _known(chain: str) -> str:
    if chain not in HRP:
        raise ChainError(f"unknown chain {chain!r}")
    return chain


def hrp(chain: str) -> str:
    return HRP[chain]


def mining_allowed(chain: str) -> bool:
    return chain == "regtest"


def network(rpc, chain: str, tip: int | None = None) -> str:
    """The xbt402 network id for this chain, from the node (P4). `tip`: the height, if known."""
    if chain == "main":
        net = network_id(rpc.call("getblockhash", MAINNET_ANCHOR))
        if net != XBT_MAINNET:
            raise ChainError(f"block {MAINNET_ANCHOR} gives {net}, not the spec's {XBT_MAINNET}")
        return net
    tip = int(rpc.call("getblockcount") if tip is None else tip)
    if tip < REGTEST_ANCHOR:
        raise ChainError(f"the chain has no block {REGTEST_ANCHOR} yet (tip {tip})")
    return network_id(rpc.call("getblockhash", REGTEST_ANCHOR))


def get_tx(rpc, txid: str, blockhash: str = "") -> dict | None:
    """Verbose transaction without txindex: the mempool (or txindex, if the node has one), then the
    block it is known to be in. None when neither has it."""
    try:
        return rpc.call("getrawtransaction", txid, True)
    except Exception:
        pass
    if blockhash:
        try:
            return rpc.call("getrawtransaction", txid, True, blockhash)
        except Exception:
            pass
    return None


def block_of(rpc, txid: str, vout: int) -> tuple[int, str] | None:
    """(height, blockhash) of a confirmed, still unspent output, from gettxout alone."""
    try:
        r = rpc.call("gettxout", txid, int(vout), False)
    except Exception:
        return None
    confs = int((r or {}).get("confirmations") or 0)
    if confs < 1:
        return None
    try:
        tip = int(rpc.call("getblockheader", r["bestblock"])["height"])
    except Exception:
        tip = int(rpc.call("getblockcount"))
    height = tip - confs + 1
    return height, rpc.call("getblockhash", height)


def mempool_spender(rpc, txid: str, vout: int) -> str | None:
    """The mempool transaction spending (txid, vout): gettxspendingprevout, which a node answers for
    mempool spends only. None: none there, or a node without the call."""
    try:
        r = rpc.call("gettxspendingprevout", [{"txid": txid, "vout": int(vout)}])
        return ((r[0] or {}).get("spendingtxid") if r else None) or None
    except Exception:
        return None


def block_spender(rpc, txid: str, vout: int, from_height: int = 0, *, limit: int = SPENDER_SCAN_MAX) -> str | None:
    """The transaction that spent (txid, vout) in a block, from `from_height` on (at most `limit`
    blocks, newest last). Works on a pruned node for blocks it still has; None if not found."""
    if from_height <= 0:
        return None
    try:
        tip = int(rpc.call("getblockcount"))
    except Exception:
        return None
    for h in range(max(from_height, tip - limit + 1), tip + 1):
        try:
            blk = rpc.call("getblock", rpc.call("getblockhash", h), 2)
        except Exception:
            continue
        for tx in blk.get("tx") or []:
            for vin in tx.get("vin") or []:
                if vin.get("txid") == txid and int(vin.get("vout", -1)) == int(vout):
                    return tx.get("txid")
    return None


def spent_in_mempool_only(rpc, txid: str, vout: int) -> bool:
    """AGP-095: (txid, vout) is spent, by this node's view, only by a transaction that is in no block:
    the output is still in the confirmed UTXO set, or a mempool transaction is named as its spender.
    Such a spend may never be mined. A node that cannot be asked answers False (the caller's other
    checks decide)."""
    try:
        if rpc.call("gettxout", txid, int(vout), False):
            return True
    except Exception:
        pass
    return mempool_spender(rpc, txid, vout) is not None


def find_spender(rpc, txid: str, vout: int, from_height: int = 0, *, limit: int = SPENDER_SCAN_MAX) -> str | None:
    """The txid spending (txid, vout): the mempool first (gettxspendingprevout), then the blocks from
    `from_height` on (at most `limit` of them, newest last). Works on a pruned node for blocks it
    still has; None if not found. A caller that must know the spend is in a block asks
    `block_spender`."""
    return mempool_spender(rpc, txid, vout) or block_spender(rpc, txid, vout, from_height, limit=limit)
