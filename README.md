# B2 · Agent wallet MCP + policy engine

Local-only prototype (no remote). Keys stay in a Knots signer process; the MCP
server only talks to that signer after the policy engine decides. MCP tools are
exactly `balance`, `quote_payment`, `pay`, `history`. Over-threshold pays need a
human ed25519 signature via `agentwallet-approve` (private key on
`~/xbt-rnd/b2-human-device/`, never under this workspace).

```
verify: bash ~/xbt-rnd/b2/demo.sh && python3 ~/lazarus-regtest/killminer.py | grep -q 'killed nothing'
```

Uses an **isolated** Knots on `127.0.0.1:19443` (binary from `~/lazarus-regtest`).
It does not generate blocks on the shared rig (`:18443`) and does not start miners.
