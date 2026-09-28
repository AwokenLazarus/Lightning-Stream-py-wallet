"""BLAKE2b block headers, proof of work and a header chain from a pinned checkpoint (AGP-024).

The light backend (electrum.py) trusts no server for the chain. It keeps its own header chain, which
starts at a pinned post-fork checkpoint (block 961640 on mainnet; the rig's first BLAKE2b block on
regtest) and accepts a header only when:
  * it is a v2 header (164 bytes, bit 31 of the version set) whose committed height is its height;
  * it links to its parent by hash;
  * its BLAKE2b block hash meets the target its nBits encode, and that target is within powLimit;
  * its nBits follow Knots' rules (pow.cpp): unchanged inside a 2016-block period and, at a period
    boundary, exactly CalculateNextWorkRequired when the period's first header is in the chain, else
    within PermittedDifficultyTransition's 4x bounds; regtest (fPowNoRetargeting,
    fPowAllowMinDifficultyBlocks) allows the parent's nBits or powLimit;
  * its time is above the median of the 11 before it, and at most 2 h in the future.
Of competing branches the one with the most work wins. Nothing below the checkpoint is ever read.

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

MAINNET_CHECKPOINT = (961_640, "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb")


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
    allow_min_difficulty: bool = False
    no_retargeting: bool = False

    def next_bits(self, parent: "Header", first_time: int | None) -> set[int] | tuple[int, int]:
        """The nBits a child of `parent` may carry: a set of exact values, or (min, max) targets as a
        range when the period's first header is below the checkpoint (only the bounds are known)."""
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
    "main": ChainRules("main", pow_limit=0x00000000FFFF << 208),
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
                  time=t, bits=_u32(b, 72), height=_u32(b, 128), txcount=int.from_bytes(b[108:110], "little"))


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
        self.headers: list[Header] = []      # headers[i] is at cp_height + i
        self.work: list[int] = []            # cumulative work above the checkpoint
        self._load()

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

    # --- building --------------------------------------------------------------------------------------
    def set_checkpoint(self, raw: bytes) -> None:
        """The checkpoint header itself: its hash must be the pinned one."""
        h = parse_header(raw)
        if h.hash != self.cp_hash:
            raise HeaderError(f"checkpoint {self.cp_height} hashes to {h.hash}, not the pinned {self.cp_hash}")
        if h.height != self.cp_height:
            raise HeaderError(f"checkpoint commits height {h.height}, not {self.cp_height}")
        check_pow(h, self.rules)             # a pinned hash from another chain fails this chain's powLimit
        with self.lock:
            if not self.headers:
                self.headers, self.work = [h], [0]
                self._save()

    def _validate(self, parent: Header, h: Header, ancestors: list[Header]) -> None:
        """h as the child of parent. `ancestors` ends with parent (oldest first, may start mid-chain)."""
        if h.prev != parent.hash:
            raise HeaderError(f"block {parent.height + 1} does not link to {parent.hash}")
        if h.height != parent.height + 1:
            raise HeaderError(f"block {parent.height + 1} commits height {h.height}")
        check_pow(h, self.rules)
        first_time = None
        if not (self.rules.allow_min_difficulty or self.rules.no_retargeting) and (h.height % self.rules.interval) == 0:
            first = h.height - self.rules.interval
            fh = self._ancestor(first, ancestors)
            first_time = fh.time if fh else None
        allowed = self.rules.next_bits(parent, first_time)
        if isinstance(allowed, set):
            if h.bits not in allowed:
                raise HeaderError(f"block {h.height}: nBits {h.bits:08x}, expected {sorted(f'{b:08x}' for b in allowed)}")
        else:
            lo, hi = allowed
            if not lo <= h.target <= hi:
                raise HeaderError(f"block {h.height}: nBits {h.bits:08x} outside the permitted retarget")
        prior = ancestors[-MEDIAN_SPAN:]
        if len(prior) == MEDIAN_SPAN:
            mtp = sorted(x.time for x in prior)[MEDIAN_SPAN // 2]
            if h.time <= mtp:
                raise HeaderError(f"block {h.height}: time {h.time} not above the median {mtp}")
        if h.time > self.clock() + MAX_FUTURE_S:
            raise HeaderError(f"block {h.height}: time {h.time} is more than 2 h in the future")

    def _ancestor(self, height: int, ancestors: list[Header]) -> Header | None:
        for a in reversed(ancestors):
            if a.height == height:
                return a
        return self.at(height) if height >= self.cp_height else None

    def connect(self, fork_height: int, raws: list[bytes]) -> dict:
        """Headers fork_height+1.. that build on our header at fork_height. The branch replaces ours
        above fork_height only if it has more work. Returns {"adopted", "tip", "reorg"}."""
        with self.lock:
            base = self.at(fork_height)
            if base is None:
                raise HeaderError(f"no header of ours at {fork_height} to build on")
            i0 = fork_height - self.cp_height
            ancestors = self.headers[max(0, i0 + 1 - self.rules.interval):i0 + 1]
            branch, work = [], self.work[i0]
            parent = base
            for raw in raws:
                if header_size(raw) != V2_SIZE:
                    raise HeaderError(f"block {parent.height + 1} is a v1 header above the BLAKE2b checkpoint")
                h = parse_header(raw)
                self._validate(parent, h, ancestors + branch)
                branch.append(h)
                work += work_of(h.bits)
                parent = h
            if not branch:
                return {"adopted": False, "tip": self.tip_height, "reorg": 0}
            if work <= self.work[-1]:          # equal or less work: keep ours (first seen wins a tie)
                return {"adopted": False, "tip": self.tip_height, "reorg": 0}
            reorg = len(self.headers) - 1 - i0
            cum, works = self.work[i0], []
            for h in branch:
                cum += work_of(h.bits)
                works.append(cum)
            self.headers = self.headers[:i0 + 1] + branch
            self.work = self.work[:i0 + 1] + works
            self._save()
            return {"adopted": True, "tip": self.tip_height, "reorg": reorg}

    # --- persistence ----------------------------------------------------------------------------------------
    def _meta_path(self) -> Path | None:
        return self.path.with_suffix(".json") if self.path else None

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(b"".join(h.raw for h in self.headers))
        os.replace(tmp, self.path)
        self._meta_path().write_text(json.dumps({"chain": self.chain, "checkpoint": [self.cp_height, self.cp_hash],
                                                 "tip": self.cp_height + len(self.headers) - 1}))

    def _load(self) -> None:
        if not self.path or not self.path.exists() or not self._meta_path().exists():
            return
        try:
            meta = json.loads(self._meta_path().read_text())
            if meta.get("chain") != self.chain or meta.get("checkpoint") != [self.cp_height, self.cp_hash]:
                return                       # another chain or checkpoint: start over
            raws = split_headers(self.path.read_bytes())
            if not raws:
                return
            self.set_checkpoint(raws[0])
            self.connect(self.cp_height, raws[1:])
        except (HeaderError, ValueError, OSError):
            self.headers, self.work = [], []  # a file that no longer verifies is ignored, then rewritten
