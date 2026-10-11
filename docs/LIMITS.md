# Limits

This is the Python reference for the agent wallet and its light chain backend. The limits of the
design, and what no review has covered, are stated once, in `docs/LIMITS.md` of the Rust workspace
(Lightning Stream). Every sentence there about the agent wallet, the light client and the
Lightning rail holds here too, unless this file says otherwise. Read that file first.

Status: reference, test networks only. Nobody outside the project has reviewed the fixes that
followed the external review of October 2026.

A limit marked *(test)* is pinned by a test named `test_limit_...` under `tests/`: it passes while
the limit holds and fails when someone lifts it.

## What differs or is added in the Python wallet

### Paying and channels

- After a lost answer the wallet pays the next call with one new state on the seller's unsigned
  word that it holds the last one; whoever can answer in the seller's place can make each call the
  agent makes sign and book one call's price with nothing served, inside `max_sats`, the budgets
  and the channel cap.
- The wallet funds a channel on a seller's offer only if it lasts at least 144 blocks, or the
  owner's `channel_expiry_blocks` when that is lower; a seller that agrees and then never opens
  costs one funding and one refund fee per channel lifetime, outside every budget.
- The seller's close fee is held to `close_fee_max_sats` (2,000); an owner who sets that to 0
  accepts any close fee the seller names.
- A channel counts as closed only when the wallet's own node shows its funding spent in a block:
  after a close, no new channel to that seller opens until then, and while a close sits unmined in
  the node's mempool the wallet does not send its refund (it does on the first check after that
  close has left the mempool). A channel recorded as closed from the mempool by an older version
  stays so.
- If the wallet's node fails two calls in the watcher tick that sees a close in the mempool, that
  close is taken for one in a block: if it is then never mined, the channel is not refunded by the
  wallet. *(test)*
- A refund that loses to the seller's close is not noticed: the record stays `refunded` and the
  hot balance is wrong until the next `hot_reconcile` or restart. *(test)*
- A kept funding frees its destination at expiry only when the node shows, in a block, another
  transaction that spent one of its inputs, and never on the light backend.
- Stream chunks, the last chunk and forward lots are paid without a signed receipt; each is bound
  by a Merkle proof, a hash lock or a transfer signature instead.
- Used as a library, `RouteSigner` keeps a new channel's key in memory until it is attached: an
  embedder that funds the channel and is then refused, or stops, has no key for that funding. The
  wallet's own signer does not open channels this way.

### Approvals and keys

- A human-signed operation (sweep, treasury funding, hot-key rotation) runs once as long as
  `human_sigs.json` is neither deleted nor restored from before the signature was used; a missing
  file is read as an empty one. The signature is used up when its operation starts; a use while
  the host clock is far ahead makes every shorter signature expire until an operator resets the
  file.
- `recover_treasury` and `recover_vault` signatures stay repeatable until they expire; they pay
  only the address signed.
- An approval nobody signs for is never removed, and `quote_payment` writes one per call, so an
  agent can slow the signer.
- The Python wallet has no mode that refuses plaintext keys, does not check the mode of the file
  holding the policy and the approver's key, and cannot wipe keys from memory.

### Watcher

- One channel's error does not end the watcher's tick for the other channels. An error in the
  forward-refund, treasury or close-change step does end that tick: the steps after it wait for a
  tick without the error.

### Forward rail (off by default)

- A lot is void at one confirmation of the spend that does not carry it. A lot the market
  completed only by closing the channel is recovered only when someone calls `forward_recover`
  with that close (on a node without `txindex` the tool finds it only while it is unconfirmed);
  until then it stays booked and the market is refused new lots. A refunded channel's lot is found
  void only if the refund is in the last 4,032 blocks when the watcher next runs.
- A void lot's ledger row can be left too high by the lot's price, when the wallet's own refund is
  shown to `forward_recover` after a hot-key rotation *(test)*, or by one chunk's price, when a
  hash-locked output timed out.
- See "Open items": do not turn the forward rail on.

### Light backend

- One scan's deadline covers every hot key, current and retired: a light wallet whose hot key was
  rotated about a dozen times can fail its coin scan beside a server a third of a timeout late. No
  coin is lost; the reconcile reports a scan error. *(test)*
- When the honest server misses a scan's one history request, coins that only a lying server
  lists as unspent are listed, and the scan still says every server answered; such a coin fails at
  broadcast. *(test)*
- Over TLS a request is written by one deadline, kept by a timer that hangs up on the socket: each
  TLS write starts one timer thread, and a write that ends in the same instant as its deadline can
  still be hung up on, after which the next request reconnects.
- Servers are asked in turn for a watched script, so a wake-up can be late by one polling interval
  (10 seconds).

## Open items

Not fixed. Each is marked in the code with the text in brackets, on a test that asserts the right
behaviour and is expected to fail; searching this tree for `open: AGP-102` finds exactly these.

- **A streamed result cannot be bought on a postpay channel that is one call behind**
  (`open: AGP-102 list 1 item 13`; one test here, two in the Rust workspace). After one lost answer
  the seller is owed one call for the life of the channel; a stream bought then ends at its first
  chunk, and the wallet has paid for the manifest and got no data. Nothing is signed past the
  call's `max_sats` or a budget. Do not rely on buying streams on a postpay channel.
- **Forward rail: a lot recovered after its channel was replaced** (`open: AGP-102 list 1 item 5`;
  three tests). After such a recovery the next channel to that market signs states that are not
  booked and not checked against the policy, up to the recovered lot's total, and the daily and
  weekly budgets do not fill; and a recovery from a close that is then never mined ends that
  channel's refund watch. It needs the rail turned on, an allowed market and the agent's own
  calls. Do not turn the forward rail on.

## Not reviewed by anyone

The project's fourth audit did not re-read the vault, the anchoring code, the routed-lock code or
the approval code (the fix round it audited had not changed them), and no audit ran this wallet
against a real node or a real network: every "in a block" result is on a test double. The light backend was run against a simulator and, in one
script, a regtest Electrum server.
