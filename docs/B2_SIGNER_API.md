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
| `xbt402_pay` | `url`, `method`, `body`, `max_sats` | policy-checked 402 payment; streamed results: digest + stored path |
| `notice_hot_txid` | `txid` | register a send-to-hot UTXO |
| `fund_treasury` | `sats` | 0x21 fund of the CSV-4320 treasury |
| `recover_treasury` | `signature`, `expiry`, `to` | human-signed CSV recovery (not an MCP tool) |
| `close_channel` | `counterparty` | cooperative close through the signer (payer close sig). MCP tool. |

Existing methods (`balance`, `quote_payment`, `pay`, `history`, `approve`, `recover_vault`) are unchanged. `pay` to a dest with a channel (or a registered `pay_to`) is an off-chain increment.

MCP tools stay exactly: `balance`, `quote_payment`, `pay`, `history`, `channels`, `xbt402_pay`, `close_channel`.
