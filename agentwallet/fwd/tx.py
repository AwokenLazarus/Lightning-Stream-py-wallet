"""Transaction (de)serialization, scripts, bech32 and the XBT unified signature hash.

b5 agp-merge 25d3541 fwd/tx.py, verbatim (B2 AGP-013 forward rail). The escrow and buyer code are
written against this Tx, so the rail keeps it rather than B1's xbt402.tx."""
import hashlib
import io
import struct
from dataclasses import dataclass, field
from typing import List, Optional

SIGHASH_ALL = 0x01
UNIFIED_FLAG = 0x20
SIGHASH_ALL_UNIFIED = 0x21

# UnifiedSighash script-type domain separator (Knots hf-sighash-opt-in).
ST_BARE, ST_WITNESS_V0, ST_TAPROOT, ST_TAPSCRIPT = 0, 1, 2, 3

OP_0, OP_1, OP_DROP, OP_IF, OP_ELSE, OP_ENDIF = 0x00, 0x51, 0x75, 0x63, 0x67, 0x68
OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKLOCKTIMEVERIFY = 0xAC, 0xAD, 0xB1


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b))


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def varbytes(b: bytes) -> bytes:
    return varint(len(b)) + b


def read_varint(s: io.BytesIO) -> int:
    n = s.read(1)[0]
    if n < 0xFD:
        return n
    return struct.unpack({0xFD: "<H", 0xFE: "<I", 0xFF: "<Q"}[n], s.read({0xFD: 2, 0xFE: 4, 0xFF: 8}[n]))[0]


@dataclass
class TxIn:
    txid: bytes            # internal byte order (as serialized)
    vout: int
    sequence: int = 0xFFFFFFFD
    script_sig: bytes = b""
    witness: List[bytes] = field(default_factory=list)

    def outpoint(self) -> bytes:
        return self.txid + struct.pack("<I", self.vout)


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return struct.pack("<q", self.value) + varbytes(self.script_pubkey)


@dataclass
class Tx:
    version: int = 2
    inputs: List[TxIn] = field(default_factory=list)
    outputs: List[TxOut] = field(default_factory=list)
    locktime: int = 0

    def serialize(self, with_witness: bool = True) -> bytes:
        seg = with_witness and any(i.witness for i in self.inputs)
        out = struct.pack("<i", self.version)
        if seg:
            out += b"\x00\x01"
        out += varint(len(self.inputs))
        for i in self.inputs:
            out += i.outpoint() + varbytes(i.script_sig) + struct.pack("<I", i.sequence)
        out += varint(len(self.outputs))
        for o in self.outputs:
            out += o.serialize()
        if seg:
            for i in self.inputs:
                out += varint(len(i.witness)) + b"".join(varbytes(w) for w in i.witness)
        return out + struct.pack("<I", self.locktime)

    def txid(self) -> str:
        return dsha256(self.serialize(False))[::-1].hex()

    def hex(self) -> str:
        return self.serialize().hex()

    def vsize(self) -> int:
        base = len(self.serialize(False))
        total = len(self.serialize(True))
        return (base * 3 + total + 3) // 4

    @classmethod
    def parse(cls, raw: bytes) -> "Tx":
        s = io.BytesIO(raw)
        version = struct.unpack("<i", s.read(4))[0]
        n_in = read_varint(s)
        seg = False
        if n_in == 0:
            flag = s.read(1)[0]
            if flag != 0:
                seg = True
                n_in = read_varint(s)
        ins = []
        for _ in range(n_in):
            txid = s.read(32)
            vout = struct.unpack("<I", s.read(4))[0]
            ss = s.read(read_varint(s))
            seq = struct.unpack("<I", s.read(4))[0]
            ins.append(TxIn(txid, vout, seq, ss))
        outs = []
        for _ in range(read_varint(s)):
            v = struct.unpack("<q", s.read(8))[0]
            outs.append(TxOut(v, s.read(read_varint(s))))
        if seg:
            for i in ins:
                i.witness = [s.read(read_varint(s)) for _ in range(read_varint(s))]
        locktime = struct.unpack("<I", s.read(4))[0]
        return cls(version, ins, outs, locktime)


def push(data: bytes) -> bytes:
    if len(data) < 0x4C:
        return bytes([len(data)]) + data
    if len(data) <= 0xFF:
        return b"\x4c" + bytes([len(data)]) + data
    raise ValueError("push too large for this library (RDTS caps pushes anyway)")


def script_num(n: int) -> bytes:
    """Minimal CScriptNum push for a non-negative integer."""
    if n == 0:
        return bytes([OP_0])
    if 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    b = bytearray()
    while n:
        b.append(n & 0xFF)
        n >>= 8
    if b[-1] & 0x80:
        b.append(0)
    return push(bytes(b))


def p2wsh_spk(witness_script: bytes) -> bytes:
    return b"\x00\x20" + sha256(witness_script)


def p2wpkh_spk(pub: bytes) -> bytes:
    h = hashlib.new("ripemd160", sha256(pub)).digest()
    return b"\x00\x14" + h


# --- bech32 (BIP173, witness v0 only) -------------------------------------------------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frm, to, pad=True):
    acc, bits, ret, maxv = 0, 0, [], (1 << to) - 1
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    elif not pad and (bits >= frm or ((acc << (to - bits)) & maxv)):
        raise ValueError("bad padding")
    return ret


def segwit_address(hrp: str, spk: bytes) -> str:
    if spk[0] != 0:
        raise ValueError("only witness v0")
    data = [0] + _convertbits(spk[2:], 8, 5)
    chk = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 1
    return hrp + "1" + "".join(_CHARSET[d] for d in data + [(chk >> 5 * (5 - i)) & 31 for i in range(6)])


def address_to_spk(addr: str) -> bytes:
    addr = addr.lower()
    hrp, _, rest = addr.rpartition("1")
    data = [_CHARSET.index(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("bad bech32 checksum")
    ver, prog = data[0], bytes(_convertbits(data[1:-6], 5, 8, False))
    if ver != 0:
        raise ValueError("only witness v0")
    return b"\x00" + bytes([len(prog)]) + prog


# --- XBT unified signature hash ------------------------------------------------------------
def unified_sighash(tx: Tx, prevouts: List[TxOut], index: int, script_type: int,
                    script_code: bytes, hash_type: int, leaf_hash: Optional[bytes] = None) -> bytes:
    """Port of Knots hf-sighash-opt-in `UnifiedSighash` (see bitkey-xbt xbt_unified.rs).

    Commits to every input's amount and scriptPubKey (like BIP341) for every script type.
    SHA-256d Bitcoin verifies a different message, so these signatures never replay there.
    """
    if len(prevouts) != len(tx.inputs) or index >= len(tx.inputs):
        raise ValueError("prevouts/inputs mismatch")
    if not hash_type & UNIFIED_FLAG:
        raise ValueError("hash type lacks the 0x20 opt-in bit")
    is_tr = script_type in (ST_TAPROOT, ST_TAPSCRIPT)
    out_type = hash_type & 0x1F
    acp = bool(hash_type & 0x80)
    if is_tr and ((hash_type & ~(0x1F | 0x80 | UNIFIED_FLAG)) or not 1 <= out_type <= 3):
        raise ValueError("undefined taproot hash type")
    m = bytearray(b"\x00")
    m.append(hash_type & 0xFF)
    m += struct.pack("<i", tx.version) + struct.pack("<I", tx.locktime) + b"\x00"
    if not acp:
        m += sha256(b"".join(i.outpoint() for i in tx.inputs))
        m += sha256(b"".join(struct.pack("<q", p.value) for p in prevouts))
        m += sha256(b"".join(varbytes(p.script_pubkey) for p in prevouts))
        m += sha256(b"".join(struct.pack("<I", i.sequence) for i in tx.inputs))
    if out_type not in (2, 3):
        m += sha256(b"".join(o.serialize() for o in tx.outputs))
    m.append(script_type)
    if acp:
        i = tx.inputs[index]
        m += i.outpoint() + struct.pack("<q", prevouts[index].value)
        m += varbytes(prevouts[index].script_pubkey) + struct.pack("<I", i.sequence)
    else:
        m += struct.pack("<I", index)
    m += varbytes(script_code) if not is_tr else b"\x00"
    if out_type == 3:
        if index >= len(tx.outputs):
            raise ValueError("SIGHASH_SINGLE without output")
        m += sha256(tx.outputs[index].serialize())
    if script_type == ST_TAPSCRIPT:
        if leaf_hash is None:
            raise ValueError("tapscript needs leaf hash")
        m += leaf_hash + b"\x00" + b"\xff\xff\xff\xff"
    return tagged_hash("UnifiedSighash", bytes(m))


def bip143_sighash(tx: Tx, index: int, script_code: bytes, value: int, hash_type: int = SIGHASH_ALL) -> bytes:
    """Legacy segwit v0 message (BIP143, SIGHASH_ALL only): what SHA-256d Bitcoin verifies.
    Used only in tests, to build the replayable counterpart of a unified signature."""
    if hash_type != SIGHASH_ALL:
        raise ValueError("only SIGHASH_ALL")
    i = tx.inputs[index]
    m = struct.pack("<i", tx.version)
    m += dsha256(b"".join(x.outpoint() for x in tx.inputs))
    m += dsha256(b"".join(struct.pack("<I", x.sequence) for x in tx.inputs))
    m += i.outpoint() + varbytes(script_code) + struct.pack("<q", value) + struct.pack("<I", i.sequence)
    m += dsha256(b"".join(o.serialize() for o in tx.outputs))
    m += struct.pack("<I", tx.locktime) + struct.pack("<I", hash_type)
    return dsha256(m)


def p2wpkh_script_code(pub: bytes) -> bytes:
    return b"\x76\xa9\x14" + hashlib.new("ripemd160", sha256(pub)).digest() + b"\x88\xac"
