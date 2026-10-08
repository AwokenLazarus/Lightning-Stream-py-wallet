"""Coinbase maturity as the node enforces it (AGP-069 M1; the Rust `xbt402::maturity`): read from
`getdeploymentinfo`, never hard-coded."""

from __future__ import annotations

from dataclasses import dataclass

ORDINARY_MATURITY = 100        # COINBASE_MATURITY: the depth when the node reports no long rule


@dataclass(frozen=True)
class LongMaturity:
    """The node's long coinbase maturity rule (Knots long_coinbase_maturity, a flag-day deployment)."""
    coinbase_start: int        # coinbase_start_height: coinbases from here are covered
    enforce: int               # height: spends in blocks from here are held to it by consensus...
    end: int                   # ...until height_end (inclusive)
    depth: int                 # maturity


@dataclass(frozen=True)
class Maturity:
    long: LongMaturity | None = None

    @classmethod
    def from_deployments(cls, info: dict) -> "Maturity":
        """From getdeploymentinfo (deployments.long_coinbase_maturity). A node that lists no such
        deployment has only the ordinary depth; a listed one with a missing field is an error."""
        d = (info or {}).get("deployments") if isinstance(info, dict) else None
        if not isinstance(d, dict):
            raise ValueError("getdeploymentinfo has no deployments")
        lcm = d.get("long_coinbase_maturity")
        if lcm is None:
            return cls(None)
        try:
            vals = [lcm[k] for k in ("coinbase_start_height", "height", "height_end", "maturity")]
        except (KeyError, TypeError) as e:
            raise ValueError("long_coinbase_maturity: a field is missing") from e
        if not all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << 32 for v in vals):
            raise ValueError("long_coinbase_maturity: a field is out of range")
        return cls(LongMaturity(*vals))

    def relay_at(self, height: int) -> int:
        """The first height at which a spend of the coinbase at `height` relays. Knots' mempool holds every
        coinbase spend to the long depth whatever its height (policy start height 0)."""
        return height + (max(self.long.depth, ORDINARY_MATURITY) if self.long else ORDINARY_MATURITY)

    def consensus_at(self, height: int) -> int:
        """The first height at which a block may include a spend of the coinbase at `height`."""
        ordinary = height + ORDINARY_MATURITY
        lm = self.long
        if lm is None or height < lm.coinbase_start:
            return ordinary
        # a spend at s needs the long depth while enforce <= s <= end, the ordinary one otherwise
        return ordinary if ordinary < lm.enforce or ordinary > lm.end else min(height + lm.depth, lm.end + 1)


__all__ = ["ORDINARY_MATURITY", "LongMaturity", "Maturity"]
