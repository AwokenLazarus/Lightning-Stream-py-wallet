# Agent wallet

Python reference for the Lightning Stream agent wallet: keys stay in a signer process, and the MCP
server spends only after the policy engine allows it. Channels use the `xbt402` reference (the
sibling `b1` tree) and settle as x402 v2 `batch-settlement` on XBT.

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

## Licence

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE`.
