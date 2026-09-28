# B2 chain backend: RPC or Electrum (AGP-024)

Mike's decision (xbt-compute, 2026-09-28, `~/notes/projects/xbt-compute/Decisions/Mike/2026-09-28-chain-access-and-hub-mode.md`):
clients run no node. The B2 signer therefore reads the chain through a **ChainBackend**:

- **RPC** (`KnotsRpc`, the default, unchanged): a Knots node, pruned is enough. Merchants and hubs stay here.
- **Electrum** (`ElectrumBackend`, `agentwallet/electrum.py`): Electrum servers, checked against the
  wallet's own BLAKE2b header chain from a pinned post-fork checkpoint, with a Merkle proof for every
  transaction the wallet acts on and several servers cross-checked.

A backend is anything with `call(method, *params)` that answers the node RPCs B2's client path makes, so
the signer, the hot wallet, the xbt402 session, the refund watcher and AGP-022's close-change retry run
unchanged on either.

## Selection

| Variable | Meaning |
|---|---|
| `B2_CHAIN_BACKEND` | `rpc` (the default without servers), `electrum`, or `auto` (the default with servers): the local node when it answers, else Electrum |
| `B2_ELECTRUM_SERVERS` | comma-separated `tcp://host:port` or `ssl://host:port` (certificates are verified) |
| `B2_ELECTRUM_CHECKPOINT` | `<height>:<hash>`. Mainnet defaults to `961640:0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb`, the first BLAKE2b block. Other chains must set it (regtest: block 101 of the rig) |
| `B2_ELECTRUM_MIN_SERVERS` | servers that must answer (default 2 on mainnet, 1 elsewhere). Configure at least one more than this, so one server down does not stop the wallet |
| `B2_ELECTRUM_TIMEOUT` | seconds per request (default 15) |
| `B2_CHAIN` | required with Electrum: a light client does not ask a node which chain it is on |

The verified headers persist in `.run/headers-<chain>.bin` and are verified again at load.

## The interface: every chain call of the client path

| RPC (callers) | Electrum methods | Verified by |
|---|---|---|
| `getblockchaininfo` (`netparams.detect_chain`, `hot.reconcile`) | `blockchain.headers.subscribe`, `blockchain.block.header(s)` | our header chain |
| `getblockcount`, `getblockhash`, `getblockheader` (heights, expiry, the network id from block 961640 / 101) | same | our header chain |
| `gettxout` (funding confirmations, `complete_open`, refund, close change, reconcile, forward rail) | `blockchain.transaction.get`, `blockchain.scripthash.get_history`, `blockchain.transaction.get_merkle` | txid = hash of the raw tx; Merkle proof into our header; spends from the union of every server's history |
| `gettxspendingprevout` (close detection, AGP-022) | `get_history` + `transaction.get` | the spend is parsed from the spending tx itself |
| `getrawtransaction` (close, lock recovery, change, `notice_hot_txid`) | `transaction.get` + `get_history` + `get_merkle` | txid, Merkle proof |
| `sendrawtransaction` (funding, refund, sweeps, rotation) | `blockchain.transaction.broadcast` to every server | the txid returned is the one we sent |
| `scantxoutset raw(spk)` (hot-key coins at start, `hot_reconcile`) | `blockchain.scripthash.listunspent` on every server | each coin's tx and its proof; confirmed spends removed |
| `estimatesmartfee` (`quote_payment`) | `blockchain.estimatefee` | not verifiable: marked `source: electrum (unverified)` |
| (watcher wake-up) | `blockchain.scripthash.subscribe`, `blockchain.headers.subscribe` | notifications only wake the watcher; what it then reads is verified as above |

Not available on Electrum, refused with `LightBackendError` (a `KnotsRpcError`): the Knots wallet
(`getbalances`, `sendtoaddress`, `listunspent`, `fundrawtransaction`, `signrawtransactionwithwallet`), so
`balance` reports `node_wallet: null`, an on-chain `pay` is denied (`light_backend`: pay through a
channel) and the presigned vault is unavailable; mining (a light signer never mines, whatever the
policy says); and `getblock`, which the pruned-node block scans used. Those scans are not needed:
spends are found from script histories.

## Header chain (`agentwallet/headers.py`)

From the pinned checkpoint on, a header is accepted only if:

- it is a v2 header (164 bytes, bit 31 of the version set) whose committed height is its height;
- it links to its parent;
- its BLAKE2b hash (electrs' `headerv2.rs`, checked against its published vectors stage by stage)
  meets the target of its nBits, and that target is within powLimit;
- its nBits follow Knots' `pow.cpp`: unchanged inside a 2016-block period; at a boundary exactly
  `CalculateNextWorkRequired` when the period's first header is in the chain (every period after the
  first), else within `PermittedDifficultyTransition`'s 4x bounds (the period 961632-963647, whose first
  header is below the checkpoint). Regtest allows the parent's nBits or powLimit;
- its time is above the median of the previous 11 and at most 2 h in the future.

The checkpoint header itself must hash to the pinned hash and meet the chain's powLimit (so a regtest
checkpoint pinned for mainnet by a copied environment is refused). Of two branches the one with more
work wins (a tie keeps ours); nothing below the checkpoint is ever read. A light signer whose servers
answer but cannot serve the checkpoint refuses to start (the wrong chain); servers that are down only
delay it, as an unreachable node does on the RPC path.

A transaction counts as confirmed only with a Merkle proof into one of our headers. A v2 header commits
its transaction count, so the proof's depth must be `ceil(log2(txcount))` and its position below the
count: an inner node cannot pass as a 64-byte transaction (CVE-2017-12842).

## What a malicious server can and cannot do

Cannot:
- make the wallet accept a chain with less work, a header without its PoW, or any history below the
  checkpoint;
- invent a confirmation, a confirmed coin, a confirmed spend or a confirmed close (no proof);
- substitute a different transaction for a txid;
- talk the wallet out of a refund: a spend seen only in a mempool never makes `gettxout` report the
  funding spent, so the watcher still refunds at expiry (if the spend was real the refund fails at
  broadcast, harmlessly, and the close is counted once it confirms);
- hide anything that another configured server shows: histories and unspent lists are the union over
  every server.

Can (and how it is bounded):
- **Hide a transaction** from us until another server or a block shows it. A hidden close delays
  counting its change: AGP-022's retry keeps asking on every watcher tick (woken by the funding and
  hot-key subscriptions), and `hot_reconcile` finds the coin later. At expiry the refund is attempted and
  fails at broadcast; nothing is lost. A hidden funding confirmation delays the open: `xbt402_pay`
  answers `pending`, and a channel that never opens before `expiry - refund_margin_blocks` is refunded
  at expiry (AGP-017 P2).
- **Withhold new blocks** (a stale tip). The wallet's height lags, which only makes it later to refund
  (a refund needs height >= expiry). `chain_backend` reports `tip_age_s`, and `tip_stale` when the
  mainnet tip is over 3 h old.
- **Report mempool facts that are false**: an invented unconfirmed coin or spend can make a broadcast
  fail or a pending change look counted until reconcile; it moves no coins.
- **Lie about fee estimates** (reported as unverified; B2's fundings use its own fixed fees).
- **Stall or disconnect** (a timeout drops the connection; the next request reconnects).
- **Learn which scripts we watch** (privacy): every hot key and every unsettled channel's funding script.

## Operation notes

- Server requirements: electrs 0.11.1 with `~/Bitcoin/patches/electrs-0.11.1-header-v2.patch`
  (protocol 1.8, 164-byte headers) and, for Knots 29.4.2 (the `difficulty` field was renamed
  `difficulty_blake2b`), `docs/electrs-0.11.1-knots-29.4.2-rpc.patch` (raw `getblockchaininfo` and
  `getblock` reads; without it `get_merkle` fails with "failed to get block txids"). The Lazarus hub's
  electrs has the equivalent fix in its `bitcoincore-rpc-json`.
- Tests run only against local electrs on regtest, never `electrum.lazarus-xbt.xyz`.
- Status: signer method `chain_backend` (also in `health`): checkpoint, tip, tip age, each server's
  tip, whether it is on our best chain and its errors, the scripts watched, and the last verification
  failures.

## Tests

- `tests/test_electrum_backend.py` (no binaries needed): the published v2 vectors, the regtest vector
  chain and a 4-transaction block's Merkle proofs; every header rule; most-work reorgs; mainnet retarget
  arithmetic; every RPC over a fake Electrum server on a mined test chain; lying servers (forged proofs,
  wrong heights, substituted txs, hidden spends, invented mempool spends, a weaker chain, a
  more-work reorg, a wrong checkpoint, too few servers); backend selection; and the signer on Electrum
  with a real B1 provider: open, pay, close, a late close counted when its subscription fires (AGP-022),
  a close confirmed before we look, refund at expiry, an invented close that does not stop the refund,
  the wrong chain refused at start.
- `tests/test_electrum_live.py` (Knots 29.4.2 + electrs; skipped without them): every client RPC answers
  as the node does, and a light signer's 0x21 funding and CLTV refund go through Electrum.
