# B2 · Agent wallet MCP + policy engine

Local-only prototype (no remote). Keys stay in a Knots signer process; the MCP
server only talks to that signer after the policy engine decides. MCP tools are
exactly `balance`, `quote_payment`, `pay`, `history`, `channels`, `xbt402_pay`,
`close_channel`, `xbt402_refund`, `forward_status`, `forward_recover` (AGP-013).
Over-threshold pays need a human ed25519 signature via `agentwallet-approve`
(private key on `~/xbt-rnd/b2-human-device/`, never under this workspace).
Allowlisted counterparties spend through Spillman channels (cap = policy budget);
fundings are 0x21. The treasury has a CSV `older(4320)` recovery path;
`fund_treasury` and `recover_treasury` need the human's signature, over the amount and over the
destination (AGP-080).

```
verify: cd ~/xbt-rnd/b2 && bash demo.sh && python3 ~/xbt-rnd/tools/miners_left.py 30300-30399
```

Uses an **isolated** Knots 29.4.2 on `127.0.0.1:30300` (datadir `~/xbt-rnd/xbt-062/run/`).
It does not generate blocks on the shared rig (`:18443`) and does not start miners.

AGP-013: the hot key and channel keys are encrypted at rest (set `B2_HOT_KEYFILE` or
`B2_HOT_PASSPHRASE` for the signer), the hot key rotates (`rotate_hot_key`) and has a balance cap
with a human sweep (`agentwallet-approve --sweep`), every signature is in `.run/signatures.jsonl`
(hash-chained), channels the provider never closes are refunded at expiry (`xbt402_refund` + a
watcher), and `xbt402_pay` buys B5 forward lots atomically (`agentwallet/forward.py`). Socket API:
`docs/B2_SIGNER_API.md`.

AGP-016: the signature log's head is anchored with a witness process (`python -m agentwallet.anchor
serve --store DIR --sock PATH`, run as its own Unix user; the signer finds it through
`B2_ANCHOR_SOCK`), the hot UTXO set is sealed on disk and reconciled against the node at start, and
`treasury.json`'s secrets are sealed like the hot key.

AGP-017 (mainnet readiness, `agentwallet/netparams.py`): the signer learns its chain from the node
(`B2_CHAIN`, if set, must agree). Off regtest it never mines (a policy `regtest_mine: true` there
refuses to start; the RPC client refuses `generate*`), addresses use that chain's hrp (`bc1…` on
mainnet), and the xbt402 network id is block 961640's. A channel is recorded, payer key sealed,
*before* its funding is broadcast (state `pending`), and its open is posted once the funding has the
offer's `minConf`: `xbt402_pay` returns `verdict: pending` until then, the watcher finishes the open,
and a channel that never opens is refunded at expiry. Nothing needs txindex (pruned nodes work).
Offers are bounded by `close_fee_max_sats`; `minCapacity`/`maxCapacity` bound the funding output
(cap + closeFeeSat). Ten 500-sat calls now sign exactly 5,000 (the first state's dust top-up is no
longer charged twice). Policy: `regtest_mine`, `open_wait_s`, `open_retry_s`, `close_fee_max_sats`;
`B2_SIGNER_TIMEOUT` sets the socket client's timeout.

AGP-074 (review C2, the AGP-067 follow-up): `open_from_offer` posts `/open` with `"preflight": true`
and no outpoint before it funds, and funds only when the provider answers `preflight: true` on the
same terms (including `closeFeePayer`). A refusal names nothing funded and records no channel. A
provider from before the preflight answers `bad_request` (no `vout`), and only after its own terms
checks, so on that answer the wallet funds and opens as before.

AGP-021 (hub routing, `agentwallet/routing.py`): B2 signs adaptor-locked channel states for xbt402
hub routing (B1 agp-021 `xbt402/hub.py`, `RoutePayer`): `xbt402_sign_state_adaptor(chan, cum, point,
route)` pre-signs the next state under T1 = T + r*G (T the provider's invoice point, r fresh) after the
routing policy (`"routing": {"hubs": {origin: {max_fee_ppm, max_fee_base_msat}}, "max_lock_sats",
"daily_budget_sats"}`: allowed hub, that hub's fee caps with a 1-sat carry allowance, max lock, 24 h
routed budget counting pending locks) and the policy engine allow it. One pending lock per channel; a
plain state below it is refused, one at or above it dominates it. The lock (cum, pre-signature, r, T)
is on disk before the pre-signature leaves; `xbt402_resolve_lock` takes t + r (hub) or t (the
provider's signed receipt); `xbt402_recover_lock` reads t + r off the hub's ch1 close after a restart;
`xbt402_void_lock` gives a lock up and `xbt402_adopt_lock` accepts only the cum of a lock this wallet
gave up (the hub completed it later from chain). A lock is booked in the policy ledger and the routed
budget when it is pre-signed, and a void releases nothing (AGP-080): the hub may still hold the
pre-signature, so a later lock or state on that channel up to the voided amount rides on the booking. `RouteSigner` is the same over an in-process
ChannelBook with B1's signer API, for `RoutePayer(signer=...)`. Uses B1's `xbt402.adaptor` when the
pinned B1 has it (libsecp256k1 secret multiplications), else `fwd/adaptor.py`.

AGP-084 (on-chain `pay` is write-ahead; key wiping): an on-chain `pay` is in the policy ledger before
the node is asked to send, under `onchain:unconfirmed:<token>`, and moves to a row under the txid when
the node answers. Only the node's own JSON-RPC error (`KnotsRpcRefused`, the Rust signer's
`rpc_refused`: insufficient funds, a bad address) takes the row back. A timeout, a dropped connection,
an HTTP error with no JSON-RPC error in it, an answer that is not a txid, or a crash leaves the payment
counted against the budgets, because the node may have sent it; the error names the row. Such a row is
not cleared by itself: it ages out of the budget windows like any payment.

AGP-085 (what is written ahead is taken back only on the node's own refusal): a channel funding, a
treasury funding and an approved payment each leave a record before the node is asked to send. That
record is undone only when the node itself answered with a JSON-RPC error (`KnotsRpcRefused`) and, for
a transaction, then answered that it has no such output. A timeout, a reset, a non-JSON answer or a
lookup that failed too is "unknown" (`BroadcastUnknown`): the node may hold the transaction.
- **Channel funding** (`xbt402_pay`, `open_channel`, `pay` to a registered `pay_to`): on "unknown" the
  pending record and its sealed payer key stay, the spent hot coin is set aside, and the watcher sends
  the funding again, opens the channel or refunds it at expiry. Before, any failure forgot the key. An
  `open_channel` to a dest with a kept funding finishes that open; it never funds a second channel.
- **`fund_treasury`** writes `pending_funding` (outpoint, amount, the signed transaction) into
  `treasury.json` before the broadcast. The start and every watcher tick settle it: recorded when the
  node shows the output, sent again when it does not. While it is unsettled a new `fund_treasury` is
  refused (`treasury_funding_pending`). If the node refuses it when it is sent again, it moves to
  `unsettled_fundings` (shown as `treasury_unsettled_outpoints`), stops holding up new fundings, and is
  recorded if it confirms after all.
- **`approve`** marks its token used on disk while the payment runs. The token is free again (until
  its expiry) when the node refused the payment or the policy denied it; it is removed when the
  payment is made; after a crash or a payment of unknown fate it stays used and is never valid again
  (`approval_replay`): the human signs a new approval after checking the chain.

Limits: on the light (Electrum) backend nothing is "the node's own refusal", because the servers are
not ours: a funding they refuse stays pending until it is opened or an operator removes it, and its
dest takes no new channel meanwhile. A kept channel funding that can never confirm (its coin was spent
elsewhere) is answered `funding_unknown` at its expiry and stays on record. A crash between holding an
approval and the payment costs the token with no payment made. The treasury records one funding
outpoint: a second funding replaces the first in the file, as before.

**Keys in memory are not wiped, and Python cannot guarantee that they could be.** The hot key, the
payer keys and the treasury keys are Python `int`s for as long as the signer runs, the wrapping key
and the passphrase are `bytes`, and decrypted key files pass through `bytes`, `str` and `json`. All of
these are immutable: they cannot be overwritten, copies are made freely (every `to_bytes`, every
big-number step of a signature), and the memory is freed, not zeroed, when the garbage collector gets
to it. libsecp256k1 (coincurve) and OpenSSL (cryptography) keep their own copies. Zeroing the few
`bytearray`s that could be introduced would cover a short-lived copy of a secret whose `int` stays in
the same process, so B2 does not pretend to. What protects a B2 key is the sealed file at rest, the
0600 modes and the process boundary (the MCP side never holds a key). A deployment that needs keys
wiped from memory should run the Rust signer (xbt-rs `crates/xbt-signer`), which wipes its hot key,
payer keys and decrypted plaintext, with the limits stated in its README.

AGP-024 (light client, `agentwallet/chain.py`, `electrum.py`, `headers.py`; `docs/B2_CHAIN_BACKEND.md`):
the signer reads the chain through a backend. RPC (`KnotsRpc`) is the default and unchanged;
`B2_CHAIN_BACKEND=electrum` (or `auto` with `B2_ELECTRUM_SERVERS` and no local node) uses Electrum servers
instead: the wallet keeps its own BLAKE2b header chain from a pinned checkpoint (961640 on mainnet,
`B2_ELECTRUM_CHECKPOINT` elsewhere), checking PoW and Knots' retarget rules, needs a Merkle proof for every
transaction it acts on, takes the union of several servers' answers (`B2_ELECTRUM_MIN_SERVERS`, 2 on
mainnet), broadcasts to all of them, and wakes its watcher on script and header subscriptions. A light
signer never mines and has no node wallet (`balance.node_wallet: null`; on-chain `pay` is denied).
`chain_backend` (and `health`) report the checkpoint, tip, servers and verification failures. Servers need
electrs with the header-v2 patch and `docs/electrs-0.11.1-knots-29.4.2-rpc.patch`.
