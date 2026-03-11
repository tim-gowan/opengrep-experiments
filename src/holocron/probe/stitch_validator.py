"""Validate stitching between forward and backward findings."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from holocron.core.types import Match
from holocron.stitching.matcher import can_stitch_with_index


def validate_stitching(
    forward_findings: Dict[str, Any],
    backward_findings: Dict[str, Any],
    index: Dict[str, Any],
) -> Tuple[bool, List[Match]]:
    """Attempt to stitch findings and report success."""

    matches: List[Match] = []
    forward_results = forward_findings.get("results", [])
    backward_results = backward_findings.get("results", [])

    for src_idx, src in enumerate(forward_results, start=1):
        for snk_idx, snk in enumerate(backward_results, start=1):
            match = can_stitch_with_index(src, snk, index)
            if match:
                match.source_idx = src_idx
                match.sink_idx = snk_idx
                matches.append(match)

    return (len(matches) > 0, matches)


def check_insufficient_metadata(matches: List[Match]) -> bool:
    """Return True when stitching failed due to lack of matches."""

    return len(matches) == 0


__all__ = ["validate_stitching", "check_insufficient_metadata"]

