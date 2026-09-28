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
