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
| `B2_ELECTRUM_SERVERS` | comma-separated `tcp://host:port` or `ssl://host:port` (certificates are verified). Mainnet needs `ssl://`; `tcp://` only to a loopback host (AGP-069) |
| `B2_ELECTRUM_CHECKPOINT` | `<height>:<hash>`. Mainnet defaults to `961640:0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb`, the first BLAKE2b block. Other chains must set it (regtest: block 101 of the rig) |
| `B2_ELECTRUM_MIN_SERVERS` | servers that must answer (default 2 on mainnet, 1 elsewhere). Configure at least one more than this, so one server down does not stop the wallet |
| `B2_ELECTRUM_TIMEOUT` | seconds per request (default 15) |
| `B2_ELECTRUM_SYNC_DEADLINE` | seconds one server has for its part of a header sync (default 4 timeouts); what it proved by then is kept (AGP-081) |
| `B2_ELECTRUM_CALL_DEADLINE` | seconds every request of one call has together, after its header sync (default 4 timeouts) (AGP-092) |
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
  header is below the checkpoint). Regtest follows the min-difficulty walk-back (`pow.cpp:42-56`);
- the top two bits of its flags are clear (`bad-flags-highbits`) and its version without bit 31 is at
  least 4 (`bad-version`);
- at a pinned height it is the pinned block (mainnet: 964264, Knots' assumevalid block);
- its time is above the median of the previous 11, from the first header above the checkpoint on, and
  at most 2 h in the future.

The checkpoint header itself must hash to the pinned hash and meet the chain's powLimit (so a regtest
checkpoint pinned for mainnet by a copied environment is refused). The 10 v1 headers below it are
fetched once, each hash-linked to the one above, for the median and the walk-back only (AGP-069); a
store from an older release lacks them and is resynced. Testnet3, testnet4 and signet have no header
rules here and are refused.

On mainnet nothing is answered (`ImplausibleChain`, status `implausible`) until the chain reaches every
pinned block, carries Knots' nMinimumChainWork less the checkpoint's chainwork, and trails one block
per 600 s since the newest pin by at most 2016 blocks (`Plausibility`). Of two branches the one with more
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
- talk the wallet out of a refund (AGP-092 for the second and third):
  - a spend seen only in a mempool never makes `gettxout` report the funding spent, so the watcher
    still refunds at expiry (if the spend was real the refund fails at broadcast, harmlessly, and
    the close is counted once it confirms);
  - a channel is booked closed only on a confirmed spend of its funding with a Merkle proof into
    our header chain (`ElectrumBackend.proven_spend`, asked through `chain.spend_is_evidence` by the
    refund and by `funding_spent`). An empty `gettxout` is not that evidence: it is also what every
    server hiding the funding looks like. Without the proof the channel stays as it is, the refund
    answers `funding_unknown`, and the next watcher tick asks again;
  - a server that does not answer never reads as "not there". A lookup says so (no such
    transaction, no such output, not in a block, no such coin) only when every server it asked
    answered; if one did not, the call fails and the caller keeps what it had;
- hide anything that another configured server shows: histories and unspent lists are the union over
  every server that answers;
- get a short cheap fork believed on mainnet: it is below the pins or the minimum work (AGP-069);
- stall other callers: no lock is held across a network read, servers sync in parallel, and once a
  chain is held a caller that finds a sync running answers from it. Each chunk of headers is checked
  as it arrives, and on mainnet nothing above ours + (time since our tip / 150 s) + 2016 is fetched;
- hold one call for longer than its deadline (AGP-092): every request a call makes ends at
  `call_deadline` (4 request timeouts unless set), counted from the end of its header sync, and a
  call forces one header sync at most. A server is asked only for the transactions it listed
  itself, in parallel with the other servers. The first it does not supply, or that neither pays
  the script nor can spend an output that does, ends its list and flags it; a transaction listed
  twice counts once. Connecting costs one request timeout for TCP, TLS, `server.version` and the
  subscriptions together;
- hold a sync round open by trickling headers (AGP-081): an answer with fewer headers than asked
  for, below the tip the server itself claims, ends that server's part of the round ("withheld
  headers"), and so does `sync_deadline` ("sync deadline"). The headers it proved are kept, and it
  is flagged;
- exhaust memory with one line (AGP-081): every request has an answer cap from its method and
  params (`electrum.answer_cap`: headers 4096 + 328 bytes per header asked for, a transaction
  2,001,024, a history or unspent list 1,604,096 bytes and 60,016 JSON values, a Merkle proof 8192
  and 128, anything else 16 KiB and 64). A line, whole or still arriving, above 16 KiB plus the caps
  of the requests pending on that connection (8 MiB at most), or with more commas and opening
  brackets than their value caps plus 64, closes the connection before it is parsed, and the server
  is flagged. Transactions above 1 MB are therefore not fetched;
- grow the wallet's memory with invented histories (AGP-081): a history or unspent list of more
  than 10,000 entries is not used, an entry that neither pays the script nor spends an output of
  the same history that pays it is flagged (as is an unspent output that does not pay it), and the
  cache of verified transactions holds 32 MiB of raw bytes, the oldest leaving first with their
  cached confirmations. With no usable history answer from any server the call fails; it does not
  report an empty history.

Can (and how it is bounded):
- **Make calls fail or slow, never answer wrongly** (AGP-092). By not answering, a server turns
  every "not there" into an error for as long as it is configured (the wallet does not guess). By
  listing transactions that pay the script, which cannot be told from unconfirmed payments, and
  supplying them slowly, it holds each call that reads that script up to `call_deadline`. Both are
  flagged in `status()["verification_failures"]`; the cure is to remove the server.
- **Hide a transaction on every configured server at once.** `gettxout` then reads it as absent:
  the wallet's coins on that key go stale until a server shows them again (`hot_reconcile`), and
  nothing is booked as a close (see above). "No such transaction" and "not in that block" are read
  from the server's words (`electrum.NOT_THERE`); an error worded otherwise counts as no answer.
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
- **Be slow or disconnect** (a timeout drops the connection; the next request reconnects). A step
  that asks every server waits for the slowest, up to the timeout per request, and the whole call
  ends at `call_deadline` after its header sync, which has `sync_deadline` (AGP-092; before it a
  history of N entries was N requests to every server with no bound on the call).
- **Build a fork above the newest pin**, where blocks are cheap (difficulty `1a00f0b5`): the
  minimum work and the height floor only raise the bar. Releases should bump the pins.
- **Learn which scripts we watch** (privacy): every hot key and every unsettled channel's funding script.

## Operation notes

- Server requirements: electrs 0.11.1 with `~/Bitcoin/patches/electrs-0.11.1-header-v2.patch`
  (protocol 1.8, 164-byte headers) and, for Knots 29.4.2 (the `difficulty` field was renamed
  `difficulty_blake2b`), `docs/electrs-0.11.1-knots-29.4.2-rpc.patch` (raw `getblockchaininfo` and
  `getblock` reads; without it `get_merkle` fails with "failed to get block txids"). The Lazarus hub's
  electrs has the equivalent fix in its `bitcoincore-rpc-json`.
- Tests run only against local electrs on regtest, never `electrum.lazarus-xbt.xyz`.
- The hot wallet spends a coinbase coin only at the depth the node's `getdeploymentinfo` reports
  (`long_coinbase_maturity`). Electrum has no such call, so a light hot wallet holds coinbase coins
  (AGP-069).
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
- `tests/test_review_e.py` (AGP-069, the same names as xbt-rs): the Knots header rules, the real
  mainnet headers 961630-961700, TLS on mainnet, a lying server that cannot stall, a cheap fork not
  believed, the tip cap, and coinbase maturity in the hot wallet.
- `tests/test_electrum_live.py` (Knots 29.4.2 + electrs; skipped without them): every client RPC answers
  as the node does, and a light signer's 0x21 funding and CLTV refund go through Electrum.
