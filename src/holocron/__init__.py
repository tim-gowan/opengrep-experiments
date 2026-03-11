"""
Holocron - OpenGrep Finding Stitcher

Tooling to stitch OpenGrep taint findings across file boundaries
using class indexing and semantic matching.
"""

__version__ = "0.0.1"

from holocron.core.indexer import build_index_with_ast
from holocron.stitching.stitcher import stitch_findings_with_index

__all__ = [
    "build_index_with_ast",
    "stitch_findings_with_index",
]

