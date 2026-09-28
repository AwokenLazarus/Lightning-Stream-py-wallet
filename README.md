# B2 · Agent wallet MCP + policy engine

Local-only prototype (no remote). Keys stay in a Knots signer process; the MCP
server only talks to that signer after the policy engine decides. MCP tools are
exactly `balance`, `quote_payment`, `pay`, `history`, `channels`, `xbt402_pay`,
`close_channel`, `xbt402_refund`, `forward_status`, `forward_recover` (AGP-013).
Over-threshold pays need a human ed25519 signature via `agentwallet-approve`
(private key on `~/xbt-rnd/b2-human-device/`, never under this workspace).
Allowlisted counterparties spend through Spillman channels (cap = policy budget);
fundings are 0x21. The treasury has a CSV `older(4320)` recovery path.

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
gave up (the hub completed it later from chain). `RouteSigner` is the same over an in-process
ChannelBook with B1's signer API, for `RoutePayer(signer=...)`. Uses B1's `xbt402.adaptor` when the
pinned B1 has it (libsecp256k1 secret multiplications), else `fwd/adaptor.py`.
