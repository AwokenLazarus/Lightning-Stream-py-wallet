# Agent wallet

Python reference for the Lightning Stream agent wallet: keys stay in a signer process, and the MCP
server spends only after the policy engine allows it. Channels use the `xbt402` reference (the
sibling `b1` tree) and settle as x402 v2 `batch-settlement` on XBT.

**Direction (2026-10-11).** Lightning Stream is being rebuilt on Lightning: it adds stream tickets
to ordinary XBT Lightning channels (in design, not built; see the Rust repository). The on-chain
channel this wallet pays over is frozen: kept and tested, off the main path, with no new work.
The hub was retired the same day and removed from the Rust workspace and from the channel
reference. This wallet still carries the routed signing that paid through a hub
(`agentwallet/routing.py`, the `routing` section of `policy.json`, the signer's lock methods);
there is no hub left for it to pay, and the Rust signer no longer has it. It is kept here only
until this reference is brought in line or retired.

**Status: reference, test networks only.** It has had an internal review, and it carries the fixes that followed an external review of the Rust tree and four follow-up audits of our own; some findings end as stated limits and two items are open (`docs/LIMITS.md`). None of this is an independent audit. Do not
use it with mainnet funds. The Rust wallet is [Lightning Stream](https://github.com/AwokenLazarus/Lightning-Stream).

MCP tools: `balance`, `quote_payment`, `pay`, `history`, `channels`, `xbt402_pay`, `close_channel`,
`xbt402_refund`, `forward_status`, `forward_recover`. Over-threshold payments need a human ed25519
signature (`agentwallet-approve`). The hot key is encrypted at rest, signatures are appended to a
hash-chained log, and channels a provider never closes are refunded at expiry.

The signer socket is described in `docs/B2_SIGNER_API.md`. The chain backend (headers, proof of
work, what the light client checks) is in `docs/B2_CHAIN_BACKEND.md`.

## Checks

Python 3.12, plus the `b1` tree on `PYTHONPATH`.

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
PYTHONPATH=".:/path/to/b1" .venv/bin/python -m unittest discover -s tests
```

Regtest needs `XBT_BIN` pointing at a Bitcoin Knots 29.4.2 build and a throwaway datadir. Nothing
here starts a miner on a shared node.

## Credits

The agent's tools are spoken in the Model Context Protocol (Anthropic; now the Agentic AI
Foundation). Giving an app a wallet connection it may spend from within limits is Nostr Wallet
Connect's idea (NIP-47); here the limits are an owner-signed policy. The channels are Jeremy
Spilman's one-way channels, by way of the `xbt402` reference. The header and proof-of-work
rules follow Bitcoin Knots (maintained by Luke Dashjr, whose BLAKE2b proof of work this is), and
the light backend talks to electrs by Roman Zeyde. The references, and the prior art of the
design that replaced the on-chain channel, are in the Rust repository's
[`docs/REFERENCES.md`](https://github.com/AwokenLazarus/Lightning-Stream/blob/main/docs/REFERENCES.md).
Code and data from others, with their licences: `NOTICE`.

## Licence

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE`.
