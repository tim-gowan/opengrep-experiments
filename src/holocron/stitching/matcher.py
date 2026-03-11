"""Core matching logic for stitching findings."""

from typing import Dict, Optional, Any
from holocron.core.types import Confidence, Match
from holocron.utils.parsers import extract_metavars
from holocron.stitching import strategies


def can_stitch_with_index(
    src_finding: Dict,
    snk_finding: Dict,
    index: Dict[str, Any]
) -> Optional[Match]:
    """
    Check if source and sink findings can be stitched together using the index.
    
    This function tries multiple matching strategies in order of confidence,
    returning the first successful match.
    
    Confidence Levels:
    ------------------
    HIGH: Direct match with full resolution
        - Direct function/class name matches
        - Attribute resolution confirmed (obj.attr → Class)
        - Inheritance relationships verified
        - All required information available
    
    MEDIUM: Match with inference or partial resolution
        - Method name matches but attribute resolution not confirmed
        - Line number inference required
        - Constructor chain inference (missing nested call capture)
        - Some uncertainty in the match
    
    LOW: Weak inference (not currently used)
        - Requires significant assumptions
        - Missing critical information
        - High risk of false positive
    
    Args:
        src_finding: Source finding dictionary from JSON
        snk_finding: Sink finding dictionary from JSON
        index: Class index dictionary
    
    Returns:
        Match object if stitchable, None otherwise
    """
    src_metavars = extract_metavars(src_finding)
    snk_metavars = extract_metavars(snk_finding)
    
    # Try strategies in order of confidence (HIGH to MEDIUM)
    # Strategy 0: Call graph propagation (PRIMARY - try first)
    match = strategies.strategy_call_graph_propagation(
        src_finding, snk_finding, src_metavars, snk_metavars, index
    )
    if match:
        return _create_match(match, src_finding, snk_finding)
    
    # Strategy 1: Direct function match (HIGH)
    match = strategies.strategy_direct_function_match(
        src_finding, snk_finding, src_metavars, snk_metavars
    )
    if match:
        return _create_match(match, src_finding, snk_finding)
    
    # Strategy 2: Attribute resolution (HIGH or MEDIUM)
    match = strategies.strategy_attribute_resolution(
        src_finding, snk_finding, src_metavars, snk_metavars, index
    )
    if match:
        return _create_match(match, src_finding, snk_finding)
    
    # Strategy 3: Inheritance resolution (HIGH/MEDIUM/LOW)
    match = strategies.strategy_inheritance_resolution(
        src_finding, snk_finding, src_metavars, snk_metavars, index
    )
    if match:
        return _create_match(match, src_finding, snk_finding)
    
    # Strategy 4: Class name match (HIGH)
    match = strategies.strategy_class_name_match(
        src_finding, snk_finding, src_metavars, snk_metavars
    )
    if match:
        return _create_match(match, src_finding, snk_finding)
    
    # Strategy 5: Constructor chain (MEDIUM) - now with index
    match = strategies.strategy_constructor_chain(
        src_finding, snk_finding, src_metavars, snk_metavars, index
    )
    if match:
        return _create_match(match, src_finding, snk_finding)
    
    return None


def _create_match(
    match_dict: Dict,
    src_finding: Dict,
    snk_finding: Dict
) -> Match:
    """Create a Match object from match dictionary and findings."""
    return Match(
        strategy=match_dict['strategy'],
        source=match_dict['source'],
        sink=match_dict['sink'],
        confidence=match_dict['confidence'],
        source_idx=0,  # Will be set by caller
        sink_idx=0,  # Will be set by caller
        source_path=src_finding['path'],
        source_line=src_finding['start']['line'],
        sink_path=snk_finding['path'],
        sink_line=snk_finding['start']['line'],
        resolution=match_dict.get('resolution'),
        note=match_dict.get('note')
    )

