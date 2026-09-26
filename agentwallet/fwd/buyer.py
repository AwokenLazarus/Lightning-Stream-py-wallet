"""Buyer-side checks for a B5 forward lot (AGP-013; from b5 agp-merge 25d3541 fwd/settle.py).

Everything the wallet checks before it pre-signs a channel state for a lot, and the two ways it gets
the finished transfer: the market's HTTP answer (`check_transfer`) or s extracted from a completed
adaptor signature (`transfer_with`). Pure Python on public data; no market code.
"""
import json
from dataclasses import dataclass
from typing import Callable, Optional

from . import adaptor, schnorr
from .escrow import MATURITY_419, Escrow, ForwardError
from .tx import Tx, tagged_hash

MIN_BUYER_GRACE = 144          # blocks between delivery and the seller's escape


def outpoint(key: str):
    try:
        txid, vout = key.split(":")
        vout = int(vout)
    except (AttributeError, ValueError):
        raise ForwardError("bad_outpoint")
    if len(txid) != 64:
        raise ForwardError("bad_outpoint")
    return txid.lower(), vout


def receipt_digest(r: dict) -> bytes:
    body = {k: r[k] for k in ("outpoint", "transferTxid", "price", "deliverHeight", "chan", "cum", "marketPub")}
    return tagged_hash("b5/forward-receipt", json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


@dataclass
class Lot:
    esc: Escrow
    txid: str
    vout: int
    value: int
    height: int
    deliver: int
    tx: Tx             # the unsigned transfer, rebuilt by the buyer (pays the buyer's own spk)
    msg: bytes         # its BIP341 key-path digest
    rx: bytes          # R.x of the final MuSig2 signature, fixed by the quote's nonces
    S: tuple           # adaptor point = s*G of the final signature


def _escrow(fwd: dict) -> Escrow:
    try:
        return Escrow(bytes.fromhex(fwd["minerPub"]), bytes.fromhex(fwd["marketPub"]), int(fwd["escapeCsv"]))
    except (KeyError, TypeError, ValueError) as e:
        if isinstance(e, ForwardError):
            raise
        raise ForwardError("bad_offer")


def verify_offer(fwd: dict, gettxout: Callable, buyer_spk: bytes, price: int,
                 maturity: int = MATURITY_419, min_grace: int = MIN_BUYER_GRACE) -> Lot:
    """The outpoint is an unspent coinbase on the wallet's own node, its script is MuSig2(miner,
    market) + an escape at least `min_grace` blocks after delivery, the transfer is the deterministic
    one paying *our* spk, and the adaptor point is the one the transfer signature must hit."""
    if not isinstance(fwd, dict) or fwd.get("kind") != "p2tr":
        raise ForwardError("unsupported_escrow")
    txid, vout = outpoint(fwd.get("outpoint"))
    esc = _escrow(fwd)
    utxo = gettxout(txid, vout)
    if not utxo:
        raise ForwardError("unknown_outpoint")
    if not utxo.get("coinbase"):
        raise ForwardError("not_coinbase")
    if utxo["scriptPubKey"]["hex"] != esc.spk.hex():
        raise ForwardError("wrong_script")
    value = round(float(utxo["value"]) * 1e8)
    try:
        if value != int(fwd["value"]):
            raise ForwardError("wrong_value")
        height, fee_rate = int(fwd["coinbaseHeight"]), int(fwd["feeRate"])
        rx, point = bytes.fromhex(fwd["nonceRx"]), fwd["adaptorPoint"]
        offered = fwd["transfer"]
    except (KeyError, TypeError, ValueError) as e:
        if isinstance(e, ForwardError):
            raise
        raise ForwardError("bad_offer")
    if esc.grace(maturity) < min_grace:
        raise ForwardError("thin_grace")
    tx = esc.transfer(txid, vout, value, height, maturity, buyer_spk, fee_rate)
    if tx.serialize(with_witness=False).hex() != offered:
        raise ForwardError("wrong_transfer")
    if not 0 < price < value:
        raise ForwardError("bad_price")
    msg = esc.tr_digest(tx, value)
    try:
        S = adaptor.sig_point(rx, esc.out.xonly(), msg)
    except ValueError:
        raise ForwardError("wrong_adaptor_point")
    if adaptor.enc(S).hex() != point:
        raise ForwardError("wrong_adaptor_point")
    return Lot(esc, txid, vout, value, height, height + maturity, tx, msg, rx, S)


def lot_from_offer(f: dict) -> Lot:
    """Rebuild a Lot from an offer the wallet already verified (a pending purchase on disk)."""
    esc = _escrow(f)
    tx = Tx.parse(bytes.fromhex(f["transfer"]))
    txid, vout = outpoint(f["outpoint"])
    msg = esc.tr_digest(tx, int(f["value"]))
    return Lot(esc, txid, vout, int(f["value"]), int(f["coinbaseHeight"]), int(f["deliverHeight"]), tx, msg,
               bytes.fromhex(f["nonceRx"]), adaptor.dec(bytes.fromhex(f["adaptorPoint"])))


def transfer_with(lot: Lot, y: int) -> Optional[Tx]:
    """The finished transfer once the buyer knows s (= y), or None if y is wrong."""
    sig = adaptor.complete_schnorr(lot.rx, y)
    if not schnorr.verify(lot.esc.out.xonly(), lot.msg, sig):
        return None
    return lot.esc.finalize_sale(Tx.parse(lot.tx.serialize()), sig)


def check_transfer(lot: Lot, raw_hex: str) -> Optional[Tx]:
    """A transfer the market handed over: the right bytes and a valid key-path signature."""
    try:
        tx = Tx.parse(bytes.fromhex(raw_hex))
        wit = tx.inputs[0].witness
    except (ValueError, IndexError, TypeError, AttributeError):
        return None
    if tx.serialize(with_witness=False) != lot.tx.serialize(with_witness=False) or len(wit) != 1:
        return None
    return tx if len(wit[0]) == 64 and schnorr.verify(lot.esc.out.xonly(), lot.msg, wit[0]) else None
