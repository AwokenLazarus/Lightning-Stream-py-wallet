"""BLAKE2b block headers, proof of work and a header chain from a pinned checkpoint (AGP-024).

The light backend (electrum.py) trusts no server for the chain. It keeps its own header chain, which
starts at a pinned post-fork checkpoint (block 961640 on mainnet; the rig's first BLAKE2b block on
regtest) and accepts a header only when:
  * it is a v2 header (164 bytes, bit 31 of the version set) whose committed height is its height;
  * it links to its parent by hash;
  * the top two bits of its flags are clear (Knots bad-flags-highbits) and its version without bit 31
    is at least 4 (Knots bad-version);
  * at a pinned height (mainnet: Knots' assumevalid block 964264) its hash is the pinned one (Knots
    checkpoint-mismatch);
  * its BLAKE2b block hash meets the target its nBits encode, and that target is within powLimit;
  * its nBits follow Knots' GetNextWorkRequired (pow.cpp): unchanged inside a 2016-block period and,
    at a period boundary, exactly CalculateNextWorkRequired when the period's first header is in the
    chain, else within PermittedDifficultyTransition's 4x bounds; on a min-difficulty chain (regtest)
    powLimit after a 20-minute gap, else the walk back to the last block that was not min-difficulty;
  * its time is above the median of the 11 before it (the 10 headers below the checkpoint are fetched,
    hash-linked back from it, so this holds from the first header) and at most 2 h in the future.
Of competing branches the one with the most work wins (first seen wins a tie). Testnet3, testnet4
(BIP94) and signet have no rules here: rules_for refuses them, so a light client there fails closed.

The header format and the staged hash port electrs' `headerv2.rs` (the header-v2 patch in
~/Bitcoin/patches), checked against its published vectors in tests/vectors/.

`merkle_root_from_proof` checks an Electrum `get_merkle` proof. A v2 header commits the block's
transaction count, so the proof's depth and position must fit it (no CVE-2017-12842 64-byte
inner-node forgeries).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

V2_FLAG = 0x8000_0000
V1_SIZE, V2_SIZE = 80, 164
FLAG_USE_TIME_OFFSET = 0x04
MEDIAN_SPAN = 11
MAX_FUTURE_S = 2 * 60 * 60
FLAGS_RESERVED = 0xC0          # Knots bad-flags-highbits: reserved for a future hard fork
MIN_VERSION = 4                # Knots bad-version (BIP34/66/65 are active far below 961640)
PRIOR_HEADERS = MEDIAN_SPAN - 1

# mainnet's trust anchor: the first BLAKE2b block, also the xbt402 network anchor
MAINNET_CHECKPOINT = (961_640, "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb")
# chainwork from genesis at MAINNET_CHECKPOINT (Knots getblockheader, 2026-10-08)
MAINNET_CHECKPOINT_CHAINWORK = 0x13e002762b0a1ae991b033e89
# Knots mainnet nMinimumChainWork (src/kernel/chainparams.cpp:149, v29.4.2.knots20260508): exactly the
# chainwork of block 964264, Knots' defaultAssumeValid
MAINNET_MIN_CHAIN_WORK = 0x13e00277374c9f9eeadc70200
# hashes every mainnet chain must have at these heights: Knots defaultAssumeValid
# (src/kernel/chainparams.cpp:150); moved forward with each release
MAINNET_PINS = ((964_264, "0000000000000078ed1e20cac1acf78df6d1060c78059fb6331e17141c881fc8"),)


def mainnet_min_work_above(cp: tuple[int, str]) -> int | None:
    """The work a mainnet chain must show above the checkpoint `cp`: nMinimumChainWork minus the
    chainwork at `cp`. 0 for an anchor at or above the last pin; None for an older anchor whose
    chainwork this release does not know."""
    if (int(cp[0]), cp[1].lower()) == MAINNET_CHECKPOINT:
        return max(0, MAINNET_MIN_CHAIN_WORK - MAINNET_CHECKPOINT_CHAINWORK)
    return 0 if int(cp[0]) >= max(h for h, _ in MAINNET_PINS) else None


class HeaderError(ValueError):
    pass


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b))


def _tagged(tag: str, payload: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + payload)


def _blake2b256(b: bytes) -> bytes:
    # digest_size is part of BLAKE2b's parameter block: this is not a truncated BLAKE2b-512
    return hashlib.blake2b(b, digest_size=32).digest()


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


# --- compact targets (arith_uint256 SetCompact / GetCompact) ------------------------------------------
def bits_to_target(bits: int) -> int:
    """SetCompact; raises on a negative or overflowing encoding (DeriveTarget refuses both)."""
    size, word = bits >> 24, bits & 0x007F_FFFF
    target = word >> 8 * (3 - size) if size <= 3 else word << 8 * (size - 3)
    if word and bits & 0x0080_0000:
        raise HeaderError(f"nBits {bits:08x} is negative")
    if word and (size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32)):
        raise HeaderError(f"nBits {bits:08x} overflows")
    return target


def target_to_bits(target: int) -> int:
    size = (target.bit_length() + 7) // 8
    compact = target << 8 * (3 - size) if size <= 3 else target >> 8 * (size - 3)
    if compact & 0x0080_0000:
        compact >>= 8
        size += 1
    return compact | size << 24


def work_of(bits: int) -> int:
    """GetBlockProof: 2**256 / (target + 1)."""
    return (1 << 256) // (bits_to_target(bits) + 1)


# --- chain parameters -----------------------------------------------------------------------------------
@dataclass(frozen=True)
class ChainRules:
    name: str
    pow_limit: int
    interval: int = 2016
    timespan: int = 14 * 24 * 60 * 60
    spacing: int = 10 * 60
    allow_min_difficulty: bool = False
    no_retargeting: bool = False
    pins: tuple = ()                     # (height, display hex hash) every accepted chain has

    def next_bits_with(self, parent: "Header", child_time: int, ancestor) -> set[int] | tuple[int, int]:
        """Knots GetNextWorkRequired for the child of `parent` with time `child_time`. `ancestor(h)` is
        our header at height h when we hold it. Where the min-difficulty walk back runs past what we
        hold, the earliest header held stands in for Knots' genesis stop."""
        pl_bits = target_to_bits(self.pow_limit)
        boundary = (parent.height + 1) % self.interval == 0
        if not boundary and self.allow_min_difficulty:
            if child_time > parent.time + 2 * self.spacing:
                return {pl_bits}
            p = parent
            while p.height % self.interval and p.bits == pl_bits:
                a = ancestor(p.height - 1) if p.height else None
                if a is None:
                    break
                p = a
            return {p.bits}
        if self.no_retargeting:
            return {parent.bits}
        first = ancestor(parent.height + 1 - self.interval) if boundary and parent.height + 1 >= self.interval else None
        return self.next_bits(parent, first.time if first else None)

    def next_bits(self, parent: "Header", first_time: int | None) -> set[int] | tuple[int, int]:
        """The nBits a child of `parent` may carry: a set of exact values, or (min, max) targets as a
        range when the period's first header is below the checkpoint (only the bounds are known). On a
        min-difficulty chain this is only the loose bound {parent, powLimit}; next_bits_with is exact."""
        pl_bits = target_to_bits(self.pow_limit)
        if self.allow_min_difficulty or self.no_retargeting:
            return {parent.bits, pl_bits}          # regtest: GetNextWorkRequired gives either
        if (parent.height + 1) % self.interval:
            return {parent.bits}
        if first_time is not None:
            span = min(max(parent.time - first_time, self.timespan // 4), self.timespan * 4)
            t = bits_to_target(parent.bits) * span // self.timespan
            return {target_to_bits(min(t, self.pow_limit))}
        # PermittedDifficultyTransition: the 4x bounds, each rounded through the compact form
        lo = bits_to_target(target_to_bits(min(bits_to_target(parent.bits) * (self.timespan // 4) // self.timespan,
                                               self.pow_limit)))
        hi = bits_to_target(target_to_bits(min(bits_to_target(parent.bits) * (self.timespan * 4) // self.timespan,
                                               self.pow_limit)))
        return (lo, hi)


RULES = {
    "main": ChainRules("main", pow_limit=0x00000000FFFF << 208, pins=MAINNET_PINS),
    "regtest": ChainRules("regtest", pow_limit=0x7FFFFF << 232, allow_min_difficulty=True, no_retargeting=True),
}


def rules_for(chain: str) -> ChainRules:
    if chain not in RULES:
        raise HeaderError(f"the light backend knows the header rules of {sorted(RULES)}, not {chain!r}")
    return RULES[chain]


# --- headers -----------------------------------------------------------------------------------------------
@dataclass
class Header:
    raw: bytes
    hash: str            # display hex
    prev: str            # display hex
    merkle_root: bytes   # internal byte order
    time: int
    bits: int
    height: int          # committed (v2)
    txcount: int         # committed (v2)
    version: int = V2_FLAG | MIN_VERSION   # as on the wire
    flags: int = 0       # the v2 flags byte (0 on a v1 header)

    @property
    def target(self) -> int:
        return bits_to_target(self.bits)


def header_size(b: bytes) -> int:
    if len(b) < 4:
        raise HeaderError("need 4 bytes to read the version field")
    return V2_SIZE if _u32(b, 0) & V2_FLAG else V1_SIZE


def v2_stages(b: bytes) -> dict:
    """The staged BLAKE2b computation of CBlockHeader::GetHash() for a v2 header (headerv2.rs)."""
    if len(b) != V2_SIZE:
        raise HeaderError(f"a v2 header is {V2_SIZE} bytes, got {len(b)}")
    version = _u32(b, 0)
    if not version & V2_FLAG:
        raise HeaderError("not a v2 header: bit 31 of the version field is clear")
    prev_internal, merkle = b[4:36], b[36:68]
    time_on_wire, bits, nonce, nonce2, nonce3 = (_u32(b, o) for o in (68, 72, 76, 80, 84))
    extranonce, time_offset = b[88:104], _u32(b, 104)
    txcount, flags, clear_bits = int.from_bytes(b[108:110], "little"), b[110], b[111]
    xor_key, height, mm_rhs = b[112:128], _u32(b, 128), b[132:164]

    xor_key_hash = _tagged("Bitcoin block hash PoW XOR key", xor_key)
    mask = bytearray(32)
    if any(xor_key):
        mask = bytearray(_tagged("Bitcoin block hash PoW XOR mask", xor_key))
        clear = clear_bits // 8
        for i in range(clear):
            mask[i] = 0
        mask[clear] &= 0xFF >> (clear_bits % 8)
    prev_sane = prev_internal[::-1]
    prev_hidden = bytearray(_tagged("Bitcoin prevblock header, hashed", prev_sane))
    h1p = (version.to_bytes(4, "little") + prev_sane + height.to_bytes(4, "little") + merkle
           + time_on_wire.to_bytes(4, "little") + b"\0" + bits.to_bytes(4, "little") + txcount.to_bytes(4, "little")
           + bytes([flags, clear_bits]) + xor_key_hash)
    h1 = _tagged("Bitcoin block header 1", h1p)
    h2 = _tagged("Merge-mining hook", h1 + bytes(32) + mm_rhs)
    blake2b_1 = _blake2b256(bytes(4) + h2 + extranonce)
    le = lambda n: n.to_bytes(4, "little")  # noqa: E731
    profile = flags & 3
    if profile == 0:
        prev_hidden[:6] = bytes(6)
        asic = bytes(prev_hidden) + le(nonce) + le(nonce2) + le(time_offset) + le(nonce3) + blake2b_1
    elif profile == 1:
        asic = le(nonce) + le(nonce2) + le(nonce3) + le(time_offset) + blake2b_1 + h2
    else:
        asic = (bytes(32) if profile == 3 else b"") + bytes(48) + h2 + le(nonce) + le(nonce2) + le(time_offset) \
            + le(nonce3) + blake2b_1
    blake2b_2 = _blake2b256(asic)
    block_hash = bytes(x ^ y for x, y in zip(blake2b_2, mask))
    return {"xor_key_hash": xor_key_hash, "mask": bytes(mask), "h1": h1, "h2": h2, "blake2b_1": blake2b_1,
            "asic_input": asic, "blake2b_2": blake2b_2, "block_hash": block_hash}


def parse_header(b: bytes) -> Header:
    """A v2 header. Its hash is `block_hash` read big-endian, as Knots prints it."""
    st = v2_stages(b)
    flags = b[110]
    time_on_wire, offset = _u32(b, 68), _u32(b, 104)
    t = (time_on_wire + offset) & 0xFFFF_FFFF if flags & FLAG_USE_TIME_OFFSET else time_on_wire
    return Header(raw=bytes(b), hash=st["block_hash"].hex(), prev=b[4:36][::-1].hex(), merkle_root=b[36:68],
                  time=t, bits=_u32(b, 72), height=_u32(b, 128), txcount=int.from_bytes(b[108:110], "little"),
                  version=_u32(b, 0), flags=flags)


def parse_prior(b: bytes, height: int) -> Header:
    """A header below a checkpoint, at `height`: v2 (committing `height`) or v1 (80 bytes, SHA-256d).
    Only its link and time matter: it is trusted because it hashes to the parent the header above names."""
    if header_size(b) == V2_SIZE:
        h = parse_header(b)
        if h.height != height:
            raise HeaderError(f"header {height} commits height {h.height}")
        return h
    if len(b) != V1_SIZE:
        raise HeaderError(f"a v1 header is {V1_SIZE} bytes, got {len(b)}")
    return Header(raw=bytes(b), hash=v1_hash(b), prev=b[4:36][::-1].hex(), merkle_root=b[36:68], time=_u32(b, 68),
                  bits=_u32(b, 72), height=height, txcount=0, version=_u32(b, 0), flags=0)


def v1_hash(b: bytes) -> str:
    return dsha256(b[:V1_SIZE])[::-1].hex()


def split_headers(blob: bytes) -> list[bytes]:
    """A run of headers of either size, walked by each one's version field."""
    out, i = [], 0
    while i < len(blob):
        n = header_size(blob[i:i + 4])
        if len(blob) - i < n:
            raise HeaderError(f"trailing {len(blob) - i} bytes, need {n} for the next header")
        out.append(blob[i:i + n])
        i += n
    return out


def check_pow(h: Header, rules: ChainRules) -> None:
    target = h.target
    if target <= 0 or target > rules.pow_limit:
        raise HeaderError(f"block {h.height}: nBits {h.bits:08x} outside powLimit")
    if int(h.hash, 16) > target:
        raise HeaderError(f"block {h.height}: hash {h.hash} does not meet its target {h.bits:08x}")


# --- merkle proofs -------------------------------------------------------------------------------------------
def merkle_depth(txcount: int) -> int:
    return max(0, (txcount - 1).bit_length())


def merkle_root_from_proof(txid: str, branch: list[str], pos: int, txcount: int | None = None) -> bytes:
    """The root (internal byte order) an Electrum merkle branch proves for `txid` at `pos`. With the
    header's committed `txcount`, a branch of the wrong depth or a position past the end is refused."""
    if pos < 0:
        raise HeaderError("negative merkle position")
    if txcount is not None:
        if txcount < 1 or pos >= txcount:
            raise HeaderError(f"merkle position {pos} is outside the block's {txcount} transactions")
        if len(branch) != merkle_depth(txcount):
            raise HeaderError(f"merkle branch of {len(branch)} for a block of {txcount} transactions")
    h = bytes.fromhex(txid)[::-1]
    idx = pos
    for sib_hex in branch:
        sib = bytes.fromhex(sib_hex)[::-1]
        h = dsha256(sib + h) if idx & 1 else dsha256(h + sib)
        idx >>= 1
    if idx:
        raise HeaderError("merkle position does not fit the branch")
    return h


def merkle_branch(txids: list[str], pos: int) -> list[str]:
    """Electrum-style branch for txids[pos] (tests and fakes build proofs with it)."""
    level = [bytes.fromhex(t)[::-1] for t in txids]
    branch, idx = [], pos
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(level[idx ^ 1][::-1].hex())
        level = [dsha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        idx >>= 1
    return branch


def merkle_root(txids: list[str]) -> bytes:
    level = [bytes.fromhex(t)[::-1] for t in txids]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [dsha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


# --- the header chain ------------------------------------------------------------------------------------------
class HeaderChain:
    """Headers from a pinned checkpoint to the most-work tip seen, each one verified. Persisted (raw
    headers, re-verified on load) so a restart does not download them again."""

    def __init__(self, chain: str, checkpoint: tuple[int, str], path: Path | None = None, *, clock=time.time):
        self.rules = rules_for(chain)
        self.chain = chain
        self.cp_height, self.cp_hash = int(checkpoint[0]), checkpoint[1].lower()
        self.path = Path(path) if path else None
        self.clock = clock
        self.lock = threading.RLock()
        self.prior: list[Header] = []        # the prior_needed headers below the checkpoint, oldest first
        self.headers: list[Header] = []      # headers[i] is at cp_height + i
        self.work: list[int] = []            # cumulative work above the checkpoint
        self._load()

    @property
    def prior_needed(self) -> int:
        """How many headers below the checkpoint set_checkpoint needs."""
        return min(PRIOR_HEADERS, self.cp_height)

    # --- queries -------------------------------------------------------------------------------------
    @property
    def ready(self) -> bool:
        return bool(self.headers)

    @property
    def tip_height(self) -> int:
        with self.lock:
            if not self.headers:
                raise HeaderError("no verified headers yet (checkpoint not fetched)")
            return self.cp_height + len(self.headers) - 1

    def tip(self) -> Header:
        with self.lock:
            return self.headers[-1]

    def at(self, height: int) -> Header | None:
        with self.lock:
            i = int(height) - self.cp_height
            return self.headers[i] if 0 <= i < len(self.headers) else None

    def height_of(self, block_hash: str) -> int | None:
        with self.lock:
            for i in range(len(self.headers) - 1, -1, -1):
                if self.headers[i].hash == block_hash:
                    return self.cp_height + i
        return None

    def total_work(self) -> int:
        with self.lock:
            return self.work[-1] if self.work else 0

    def implausible(self, min_work_above: int, floor: tuple[int, int] | None = None) -> str | None:
        """Why this chain is not believable yet, or None: it must reach every pinned height above the
        checkpoint, carry `min_work_above` the checkpoint, and with floor = (spacing_s, slack) its tip
        may not trail the newest pinned block it holds (or the checkpoint) by more than `slack` blocks
        at one block per spacing_s since that block's time."""
        with self.lock:
            if not self.headers:
                return "no verified headers yet"
            tip_h = self.headers[-1].height
            for h, _ in self.rules.pins:
                if h > self.cp_height and tip_h < h:
                    return f"tip {tip_h} is below the pinned block {h}"
            work = self.total_work()
            if work < min_work_above:
                return f"work above the checkpoint {work:#x} is below the minimum {min_work_above:#x}"
            if floor is None:
                return None
            spacing, slack = floor
            held = [b for b in (self.at(h) for h, _ in self.rules.pins) if b is not None]
            base = max(held, key=lambda b: b.height) if held else self.headers[0]
            expected = base.height + max(0, int(self.clock()) - base.time) // max(1, spacing)
            if tip_h + slack < expected:
                return (f"tip {tip_h} is implausibly low: block {expected} expected by now at one per {spacing} s "
                        f"from block {base.height}")
            return None

    # --- building --------------------------------------------------------------------------------------
    def set_checkpoint(self, raw: bytes, prior: list[bytes]) -> None:
        """The checkpoint header, whose hash must be the pinned one, and the prior_needed headers below
        it (oldest first), each hash-linked to the one above it."""
        h = parse_header(raw)
        if h.hash != self.cp_hash:
            raise HeaderError(f"checkpoint {self.cp_height} hashes to {h.hash}, not the pinned {self.cp_hash}")
        if h.height != self.cp_height:
            raise HeaderError(f"checkpoint commits height {h.height}, not {self.cp_height}")
        check_pow(h, self.rules)             # a pinned hash from another chain fails this chain's powLimit
        want = self.prior_needed
        if len(prior) != want:
            raise HeaderError(f"the checkpoint needs the {want} headers below it, got {len(prior)}")
        below, child = [], h.prev
        for i in range(want - 1, -1, -1):
            height = self.cp_height - (want - i)
            p = parse_prior(prior[i], height)
            if p.hash != child:
                raise HeaderError(f"header {height} is not the parent of header {height + 1}")
            child = p.prev
            below.append(p)
        below.reverse()
        with self.lock:
            if not self.headers:
                self.prior, self.headers, self.work = below, [h], [0]
                self._save()

    def branch(self, fork_height: int) -> "Branch":
        """A branch to grow on our header at fork_height, validated without holding the chain."""
        with self.lock:
            i0 = int(fork_height) - self.cp_height
            if not 0 <= i0 < len(self.headers):
                raise HeaderError(f"no header of ours at {fork_height} to build on")
            back = max(self.rules.interval, MEDIAN_SPAN)   # a retarget's first header, the walk, the median
            start = max(0, i0 + 1 - back)
            known = self.prior[max(0, len(self.prior) - (back - (i0 + 1))):] if start == 0 else []
            known = known + self.headers[start:i0 + 1]
            return Branch(self.rules, self.clock, known, (int(fork_height), self.headers[i0].hash), self.work[i0])

    def adopt(self, b: "Branch") -> dict:
        """Apply a branch: it replaces ours above its fork point only if it has more work and the fork
        point is still ours (if another branch moved our chain under it, the next sync redoes it)."""
        with self.lock:
            base = self.at(b.base[0])
            if not len(b) or base is None or base.hash != b.base[1] or b.work <= self.total_work():
                return {"adopted": False, "tip": self.tip_height, "reorg": 0}
            i0 = b.base[0] - self.cp_height
            reorg = len(self.headers) - 1 - i0
            new = b.known[b.base_len:]
            cum, works = self.work[i0], []
            for h in new:
                cum += work_of(h.bits)
                works.append(cum)
            self.headers = self.headers[:i0 + 1] + new
            self.work = self.work[:i0 + 1] + works
            self._save()
            return {"adopted": True, "tip": self.tip_height, "reorg": reorg}

    def connect(self, fork_height: int, raws: list[bytes]) -> dict:
        """Headers fork_height+1.. that build on our header at fork_height, all or nothing. The branch
        replaces ours above fork_height only if it has more work. Returns {"adopted", "tip", "reorg"}."""
        b = self.branch(fork_height)
        b.extend(raws)
        return self.adopt(b)

    # --- persistence ----------------------------------------------------------------------------------------
    def _meta_path(self) -> Path | None:
        return self.path.with_suffix(".json") if self.path else None

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(b"".join(h.raw for h in self.prior + self.headers))
        os.replace(tmp, self.path)
        self._meta_path().write_text(json.dumps({"chain": self.chain, "checkpoint": [self.cp_height, self.cp_hash],
                                                 "prior": len(self.prior), "tip": self.cp_height + len(self.headers) - 1}))

    def _load(self) -> None:
        """A store without the headers below the checkpoint (older releases) is ignored: refetched."""
        if not self.path or not self.path.exists() or not self._meta_path().exists():
            return
        try:
            meta = json.loads(self._meta_path().read_text())
            if meta.get("chain") != self.chain or meta.get("checkpoint") != [self.cp_height, self.cp_hash] \
                    or meta.get("prior") != self.prior_needed:
                return                       # another chain or checkpoint, or an older store: start over
            n = self.prior_needed
            raws = split_headers(self.path.read_bytes())
            if len(raws) <= n:
                return
            self.set_checkpoint(raws[n], raws[:n])
            self.connect(self.cp_height, raws[n + 1:])
        except (HeaderError, ValueError, OSError):
            self.prior, self.headers, self.work = [], [], []  # a file that no longer verifies is ignored, then rewritten


class Branch:
    """Headers validated on top of one of ours without holding the chain: made by HeaderChain.branch,
    grown by extend as each chunk arrives, applied by HeaderChain.adopt."""

    def __init__(self, rules: ChainRules, clock, known: list[Header], base: tuple[int, str], work: int):
        self.rules, self.clock = rules, clock
        self.known = list(known)             # ours up to the fork point (as far back as the rules look), then new
        self.base_len = len(self.known)
        self.base = base                     # (height, hash) of the fork point
        self.work = work                     # work above the checkpoint at the branch tip

    def __len__(self) -> int:
        return len(self.known) - self.base_len

    @property
    def fork_height(self) -> int:
        return self.base[0]

    @property
    def tip_height(self) -> int:
        return self.base[0] + len(self)

    def at(self, height: int) -> Header | None:
        if not self.known:
            return None
        i = height - self.known[0].height
        return self.known[i] if 0 <= i < len(self.known) and self.known[i].height == height else None

    def extend(self, raws: list[bytes]) -> None:
        """Validate `raws` in order on top of the branch. The first invalid header stops it: those
        before it stay (they carry real work), it and the rest are dropped, and its reason is raised."""
        for raw in raws:
            if header_size(raw) != V2_SIZE:
                raise HeaderError(f"block {self.tip_height + 1} is a v1 header above the BLAKE2b checkpoint")
            h = parse_header(raw)
            self._validate(h)
            self.work += work_of(h.bits)
            self.known.append(h)

    def _validate(self, h: Header) -> None:
        parent = self.known[-1]
        n = parent.height + 1
        if h.prev != parent.hash:
            raise HeaderError(f"block {n} does not link to {parent.hash}")
        if h.height != n:
            raise HeaderError(f"block {n} commits height {h.height}")
        if h.flags & FLAGS_RESERVED:
            raise HeaderError(f"block {n}: bad-flags-highbits (flags {h.flags:02x})")
        if h.version & ~V2_FLAG & 0xFFFF_FFFF < MIN_VERSION:
            raise HeaderError(f"block {n}: bad-version ({h.version:08x})")
        for ph, pin in self.rules.pins:
            if ph == h.height and h.hash != pin:
                raise HeaderError(f"block {n}: checkpoint-mismatch, {pin} is pinned")
        check_pow(h, self.rules)
        allowed = self.rules.next_bits_with(parent, h.time, self.at)
        if isinstance(allowed, set):
            if h.bits not in allowed:
                raise HeaderError(f"block {n}: nBits {h.bits:08x}, expected {sorted(f'{b:08x}' for b in allowed)}")
        else:
            lo, hi = allowed
            if not lo <= h.target <= hi:
                raise HeaderError(f"block {n}: nBits {h.bits:08x} outside the permitted retarget")
        # GetMedianTimePast: the 11 before it, fewer only near genesis
        times = sorted(x.time for x in self.known[-MEDIAN_SPAN:])
        mtp = times[len(times) // 2]
        if h.time <= mtp:
            raise HeaderError(f"block {n}: time {h.time} not above the median {mtp}")
        if h.time > self.clock() + MAX_FUTURE_S:
            raise HeaderError(f"block {n}: time {h.time} is more than 2 h in the future")
