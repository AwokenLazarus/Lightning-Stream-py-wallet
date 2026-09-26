"""The buyer's view of a B5 P2TR escrow (AGP-013 forward rail).

b5 agp-merge 25d3541 fwd/escrow.py, the P2TR path only, on the pure-Python key aggregation in this
package: the buyer rebuilds the escrow output, the deterministic transfer and its BIP341 digest from
public data, and finalizes the transfer with the 64-byte key-path signature it bought.

  internal key = MuSig2(miner, market); one leaf: <escape_csv> OP_CSV OP_DROP <miner_x> OP_CHECKSIG
"""
from dataclasses import dataclass

from . import musig2, schnorr
from .tx import OP_CHECKSIG, OP_DROP, Tx, TxIn, TxOut, push, script_num

OP_CHECKSEQUENCEVERIFY = 0xB2
MATURITY_419 = 6480          # Knots #419 coinbase maturity
CSV_MAX = 0xFFFF
SALE_VSIZE_P2TR = 99         # 1-in/1-out key-path sale, measured on regtest (b5)
DUST = 546


class ForwardError(ValueError):
    """An offer the wallet refuses. `code` is ours; no provider text reaches the model (AGP-005 L12)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass
class Escrow:
    miner_pub: bytes      # 33-byte compressed
    market_pub: bytes     # 33-byte compressed
    escape_csv: int       # blocks after the coinbase confirms

    def __post_init__(self):
        if not 0 < self.escape_csv <= CSV_MAX:
            raise ForwardError("bad_escrow", "escape_csv must fit a BIP68 block lock")
        lock = script_num(self.escape_csv) + bytes([OP_CHECKSEQUENCEVERIFY])
        self.agg = musig2.key_agg(sorted([self.miner_pub, self.market_pub]))
        self.leaf = lock + bytes([OP_DROP]) + push(self.miner_pub[1:]) + bytes([OP_CHECKSIG])
        self.leaf_hash = schnorr.leaf_hash(self.leaf)
        self.out = musig2.taproot_tweak(self.agg, self.leaf_hash)
        self.spk = b"\x51\x20" + self.out.xonly()

    def grace(self, maturity: int) -> int:
        """Blocks between maturity and the miner's escape: the buyer's window to mine the transfer."""
        return self.escape_csv - maturity

    def transfer(self, txid: str, vout: int, value: int, coinbase_height: int, maturity: int,
                 dest_spk: bytes, fee_rate: int, locktime: int = 0) -> Tx:
        if maturity <= 0 or coinbase_height <= 0:
            raise ForwardError("bad_offer", "bad coinbase height or maturity")
        fee = fee_rate * SALE_VSIZE_P2TR
        if value - fee < DUST:
            raise ForwardError("bad_offer", "output too small to transfer")
        return Tx(2, [TxIn(bytes.fromhex(txid)[::-1], vout, 0xFFFFFFFD)], [TxOut(value - fee, dest_spk)], locktime)

    def prevout(self, value: int) -> TxOut:
        return TxOut(value, self.spk)

    def tr_digest(self, tx: Tx, value: int) -> bytes:
        return musig2.bip341_sighash(tx, [self.prevout(value)], 0, musig2.SIGHASH_DEFAULT, None)

    def finalize_sale(self, tx: Tx, sig64: bytes) -> Tx:
        tx.inputs[0].witness = [sig64]
        return tx
