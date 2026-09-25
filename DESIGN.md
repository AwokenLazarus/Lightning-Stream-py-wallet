# B2 Agent wallet MCP + policy engine

Prototype for [[Tasks/XBT-054]] / P-003 Track B2. Code: `~/xbt-rnd/b2/` (local git, no remote).

## Problem
An AI agent that can move XBT will drain a wallet the first time a prompt is jailbroken. The public Lazarus MCP is read-only by design. Agents still need a way to hold and pay — without the model ever seeing keys, and without the model being able to approve its own over-threshold payments.

## Mechanism
Three process boundaries plus an out-of-band human device:

1. **Policy library** (`agentwallet/policy.py`) — pure functions. Rules: allowlist, max-per-tx, daily/weekly budget, per-counterparty cap, velocity, human threshold, split-bypass (same dest in a short window). Verdicts: `allow` / `deny` / `needs_human`. Append-only JSONL audit. Tokens expire in 15 minutes (`approval_ttl_s=900`) and are single-use.
2. **Signer process** (`agentwallet/signer.py`) — Unix socket, mode 600. Owns the Knots cookie and wallet. Re-runs policy before every `sendtoaddress`. Holds a **presigned vault** sweep to a recovery address; hex never leaves disk. Holds only the **human ed25519 public key**. `approve` requires a signature by that key over `(token, dest, amount_sats, expiry)`. A `human=` boolean in the request is ignored and is not a capability. `recover_vault` likewise requires a human signature.
3. **MCP server** (`agentwallet/mcp_server.py`) — Python MCP SDK (`MCPServer` / `FastMCP`), stdio. Tools (exactly): `balance`, `quote_payment`, `pay`, `history`, `channels`, `xbt402_pay`. **No `approve`. No `recover_vault`.** No RPC. Responses pass `sanitize()` (drops priv/wif/xprv/cookie/secret fields).
4. **Human device CLI** (`agentwallet-approve` / `python -m agentwallet.approve`) — runs with the human private key. The key is stored outside the agent workspace (demo: `~/xbt-rnd/b2-human-device/`, marked `THIS_IS_THE_HUMANS_DEVICE.txt`, mode 0700/0600). The CLI refuses a key path under `B2_ROOT`.

4. **Channel-as-budget** (`agentwallet/channels.py`, `hot.py`, `treasury.py`) — each allowlisted counterparty gets a B1 Spillman channel. Cap = `per_counterparty_cap_sats`, expiry = `channel_expiry_blocks`. The signer holds payer keys (mode 600 `channel_keys.json`). `pay` to a channel dest is an off-chain increment under a spend lock so concurrent calls cannot exceed the cap. Fundings are signed ALL|UNIFIED (`0x21`) from a signer-owned hot key (the Knots wallet will not sign 0x21 on regtest). Treasury is P2WSH `IF 2-of-2 human/cosigner ELSE older(4320) recovery`. Socket API for XBT-060: `docs/B2_SIGNER_API.md`.
5. **Claude session** — project-local `claude-session/.mcp.json` + `claude-session.sh` (`claude -p --strict-mcp-config`). Never edits the global Claude config.

Isolated Knots **29.4.2** on `127.0.0.1:30300` / p2p `30301` / x402 `30310`, datadir `~/xbt-rnd/xbt-062/run/`. Funding via `generatetoaddress` — no miners. RDTS + `blake2b@101`.

## Why it's new
Prior art checked: public Lazarus MCP (read-only, L0 only); an exchange's money tools (pair allowlist + confirm + JSONL, but exchange API, no on-chain keys); Coinbase x402 / L402 (payments, not a custody policy engine); Bitkey/Lazarus Key (human wallet, not agent MCP). Combining a policy engine, a key-isolated signer, **cryptographic out-of-band human approval** (ed25519 over the pending payment), split-bypass detection, and a presigned recovery vault as the agent-native wallet for XBT is not something the public pool MCP or the unbuilt-services list shipped.

The first prototype (`2218092`) used `approve(human: bool)` as an MCP tool. That was rejected: the model chooses `human`. This revision removes the tool and binds approval to a key the agent host's agent-readable paths never hold.

## Trust and attack analysis
- Prompt injection → agent calls `pay` to an attacker: **allowlist deny**.
- Split a large payment into many small ones: **split_bypass deny** (window sum vs max-per-tx and human threshold).
- Agent calls `approve` itself: **impossible** — the MCP tool list is exactly `{balance, quote_payment, pay, history, channels, xbt402_pay}`.
- Concurrent `pay` against one channel: **channel_cap** — increment is locked; used + amount never exceeds cap.
- Channel increment to a stranger: **allowlist deny** (same engine as on-chain pay).
- Treasury alone: recovery needs `older(4320)` plus a human ed25519 signature; not an MCP tool.
- Socket client sends `approve` without a valid signature: **deny / approval_sig**. `human=true` does nothing.
- Signature over a different dest or amount: **deny / approval_bind**.
- Replay of a used token: **deny**.
- Expired token (TTL 15 min): **deny / approval_expired**.
- MCP process compromised: no cookie, no descriptors, no human private key, sanitize strips key-shaped fields. Signer still re-checks policy and still requires the human signature for gated pays.
- Signer compromised: same as any hot wallet. Mitigation: small hot balance + presigned sweep to recovery (sweep itself also needs a human signature).
- **Human private key never touches the agent host's agent-readable paths.** Demo key lives in `~/xbt-rnd/b2-human-device/` (sibling of the workspace, not under `~/xbt-rnd/b2/`). Production: hardware key / phone / Bitkey — the signer sees only the public key.
- Residual: a human who blindly signs tokens; a stolen Unix socket (mode 600, same user) can still `pay` under-threshold amounts; a stolen human device key can approve gated pays.

## Consensus class
None. Policy + process isolation + ed25519. Works on today's Knots.

## Prototype status
Runnable in `~/xbt-rnd/b2/`. Unit tests for every policy rule + bypass + approval attacks + MCP tool list. `demo.sh` funds an isolated regtest wallet, runs the agent path (allow / deny / needs_human / no approve tool), then completes the gated pay with `agentwallet-approve`.

## Kill criteria
Kill if a production deployment would still need the model to hold a seed, or if policy can be skipped by talking to Knots directly (then the signer host is the real product, not the MCP), or if a "human" capability is ever again a parameter the model can set.
