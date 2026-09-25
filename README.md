# B2 · Agent wallet MCP + policy engine

Local-only prototype (no remote). Keys stay in a Knots signer process; the MCP
server only talks to that signer after the policy engine decides. MCP tools are
exactly `balance`, `quote_payment`, `pay`, `history`, `channels`, `xbt402_pay`.
Over-threshold pays need a human ed25519 signature via `agentwallet-approve`
(private key on `~/xbt-rnd/b2-human-device/`, never under this workspace).
Allowlisted counterparties spend through Spillman channels (cap = policy budget);
fundings are 0x21. The treasury has a CSV `older(4320)` recovery path.

```
verify: cd ~/xbt-rnd/b2 && bash demo.sh && python3 ~/xbt-rnd/tools/miners_left.py 30300-30399
```

Uses an **isolated** Knots 29.4.2 on `127.0.0.1:30300` (datadir `~/xbt-rnd/xbt-062/run/`).
It does not generate blocks on the shared rig (`:18443`) and does not start miners.
