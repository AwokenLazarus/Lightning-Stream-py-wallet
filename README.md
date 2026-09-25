# B2 · Agent wallet MCP + policy engine

Local-only prototype (no remote). Keys stay in a Knots signer process; the MCP
server only talks to that signer after the policy engine decides.

```
verify: bash ~/xbt-rnd/b2/demo.sh && python3 ~/lazarus-regtest/killminer.py | grep -q 'killed nothing'
```

Uses an **isolated** Knots on `127.0.0.1:19443` (binary from `~/lazarus-regtest`).
It does not generate blocks on the shared rig (`:18443`) and does not start miners.
