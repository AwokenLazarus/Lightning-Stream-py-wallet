# B2 Agent wallet MCP + policy engine

Prototype for [[Tasks/XBT-054]] / P-003 Track B2. Code: `~/xbt-rnd/b2/` (local git, no remote).

## Problem
An AI agent that can move XBT will drain a wallet the first time a prompt is jailbroken. The public Lazarus MCP is read-only by design. Agents still need a way to hold and pay — without the model ever seeing keys.

## Mechanism
Three process boundaries:

1. **Policy library** (`agentwallet/policy.py`) — pure functions. Rules: allowlist, max-per-tx, daily/weekly budget, per-counterparty cap, velocity, human threshold, split-bypass (same dest in a short window). Verdicts: `allow` / `deny` / `needs_human`. Append-only JSONL audit.
2. **Signer process** (`agentwallet/signer.py`) — Unix socket, mode 600. Owns the Knots cookie and wallet. Re-runs policy before every `sendtoaddress`. Holds a **presigned vault** sweep to a recovery address; hex never leaves disk. `approve` and `recover_vault` require `human=true`.
3. **MCP server** (`agentwallet/mcp_server.py`) — Python MCP SDK (`FastMCP` / `MCPServer`), stdio. Tools: `balance`, `quote_payment`, `pay`, `approve`, `history`. No RPC. Responses pass `sanitize()` (drops priv/wif/xprv/cookie fields).

Isolated Knots (binary from `~/lazarus-regtest`) on `127.0.0.1:19443`. Funding via `generatetoaddress` — no miners.

## Why it's new
Prior art checked: public Lazarus MCP (read-only, L0 only); an exchange's money tools (pair allowlist + confirm + JSONL, but exchange API, no on-chain keys); Coinbase x402 / L402 (payments, not a custody policy engine); Bitkey/Lazarus Key (human wallet, not agent MCP). Combining a policy engine, a key-isolated signer, human-gated MCP `approve` tokens, split-bypass detection, and a presigned recovery vault as the agent-native wallet for XBT is not something the public pool MCP or the unbuilt-services list shipped.

## Trust and attack analysis
- Prompt injection → agent calls `pay` to an attacker: **allowlist deny**.
- Split a large payment into many small ones: **split_bypass deny** (window sum vs max-per-tx and human threshold).
- Agent calls `approve` itself: refused unless `human=true` (that flag is for the demo/human client, not the model).
- MCP process compromised: no cookie, no descriptors, sanitize strips key-shaped fields. Signer still re-checks policy.
- Signer compromised: same as any hot wallet (see unattended-signer note). Mitigation: small hot balance + presigned sweep to recovery.
- Residual: a human who blindly approves tokens; stolen Unix socket (mode 600, same user).

## Consensus class
None. Policy + process isolation. Works on today's Knots.

## Prototype status
Runnable in `~/xbt-rnd/b2/`. Unit tests for every rule + bypass. `demo.sh` funds an isolated regtest wallet and runs five MCP calls (allow, deny, needs-human, approve).

## Kill criteria
Kill if a production deployment would still need the model to hold a seed, or if policy can be skipped by talking to Knots directly (then the signer host is the real product, not the MCP).
