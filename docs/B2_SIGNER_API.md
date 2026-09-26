# B2 signer socket API (agreed with XBT-060)

Newline-delimited JSON on a mode-600 Unix socket (`B2_SIGNER_SOCK`).
Request: `{"id":1,"method":"...","params":{...}}`.
The MCP process is a client of this socket. **Payer secrets never leave the signer.**

This is the wallet hook XBT-060 / the B1 SDK should use (`fund(address, sats)` → B2, 0x21).

| Method | Params | Result |
|---|---|---|
| `fund` | `address`, `sats` | `{txid, vout, sighash: "0x21"}` — spends signer hot coins |
| `sign_state` | `dest`, `cum` | policy-checked `{sig, chan, cum}` |
| `open_channel` | `dest`, `pay_to?`, `cap_sats?`, `expiry_blocks?` | opens a Spillman channel; cap defaults to `per_counterparty_cap_sats` |
| `channels` | — | `{channels:[{dest,chan,cap_sats,used_sats,expiry,residual_sats}]}` |
| `xbt402_pay` | `url`, `method`, `body`, `max_sats` | policy-checked 402 payment; streamed results: digest + stored path; provider body + receipt verbatim under `untrusted_provider_response` (untrusted data, not key-filtered) |
| `notice_hot_txid` | `txid` | register a send-to-hot UTXO |
| `fund_treasury` | `sats` | 0x21 fund of the CSV-4320 treasury |
| `recover_treasury` | `signature`, `expiry`, `to` | human-signed CSV recovery (not an MCP tool) |
| `close_channel` | `counterparty` | cooperative close through the signer (payer close sig); marks the channel `closed`. MCP tool. |
| `xbt402_refund` (alias `refund_channel`) | `counterparty` (origin, dest or chan id) | AGP-013. The payer's CLTV refund (B1 `refund_tx`) of an open channel at or past its expiry, always to the current hot key. `deny/refund_early` before expiry, `deny/channel_closed` if a close spent the funding, `already: true` + the first txid if refunded. MCP tool. |
| `watch_tick` | — | AGP-013. One pass of the expiry watcher (also runs every `B2_WATCH_INTERVAL` s, default 10, inside `serve`): refund channels at expiry, sweep coins that reached a retired hot key |
| `forward_status` | — | AGP-013 forward rail: policy limits, 24 h forward spend, pending and delivered lots (no transfer hex). MCP tool. |
| `forward_recover` | `txid` | rebuild a forward transfer from a market's channel close (adaptor extraction), or void the purchase. MCP tool. |
| `forward_pending` / `forward_transfers` | — | b5 AGP-008 names: pending purchases / delivered transfers with hex |
| `rotate_hot_key` | — | AGP-013. New hot key; the old key's coins sweep into it (one 0x21 tx); the old key stays sealed as retired. Not an MCP tool |
| `sweep_hot` | `to`, `amount_sats`, `expiry`, `signature` | AGP-013. Human-signed (ed25519 over `sweep_message(hot_address, to, amount, expiry)`, `agentwallet-approve --sweep`) sweep out of the hot key, for the balance cap. Not an MCP tool |
| `signatures` | `limit?` | AGP-013. Tail of the signature audit log + `chain_ok` |

Existing methods (`balance`, `quote_payment`, `pay`, `history`, `approve`, `recover_vault`) are unchanged. `pay` to a dest with a channel (or a registered `pay_to`) is an off-chain increment.

MCP tools are exactly: `balance`, `quote_payment`, `pay`, `history`, `channels`, `xbt402_pay`, `close_channel`, and since AGP-013 `xbt402_refund`, `forward_status`, `forward_recover`.

## AGP-013 custody

- **Hot key encrypted at rest.** `hot.json` and `channel_keys.json` hold AES-256-GCM ciphertext only. The wrapping key comes from the signer's environment: `B2_HOT_KEYFILE` (32 bytes, created 0600 if missing, refused inside the run dir) or `B2_HOT_PASSPHRASE` (scrypt N=2^15; removed from `os.environ` once read). Without either the signer does not start (`B2_HOT_ALLOW_PLAINTEXT=1` for old demos only). A plaintext file from an older run is re-sealed on first start.
- **Rotation.** `rotate_hot_key`; later coins to a retired address (a close's change) are swept by the watcher.
- **Balance cap.** Policy `hot_balance_cap_sats` (0 = off). Above it, opening a channel returns `deny/hot_balance_cap` with `action: human_sweep`.
- **Signature audit log.** `.run/signatures.jsonl`: one line per signature (`kind` funding / channel_state / channel_state_a3 / conditional_state / adaptor_presig / close_auth / refund / rotation_sweep / retired_sweep / human_sweep / treasury_recovery; `chan`, `dest`, amount, `sig_sha256`, signer `method`, policy `rule`), hash-chained (`prev`), O_APPEND + fsync. `sigaudit.verify_chain(path)`.
- **Channel lifecycle.** `open` → `closed` | `refunded`. No new state is signed on a channel that is not open or is within `refund_margin_blocks` (default 6) of its expiry; a closed or refunded channel is replaced by a new one on the next payment.
- **Forward rail.** Policy `"forward": {"markets": [...], "per_lot_max_sats": N, "daily_budget_sats": N}` (absent = rail off); see `agentwallet/forward.py`.
