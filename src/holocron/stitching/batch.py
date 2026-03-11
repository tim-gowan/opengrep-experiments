"""Batch stitching with parallel processing support."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Tuple
from holocron.core.indexer import load_index
from holocron.stitching.matcher import can_stitch_with_index
from holocron.core.types import Match, Confidence
from holocron.utils.discovery import discover_findings


def _stitch_pair(src_finding: Dict[str, Any], snk_finding: Dict[str, Any], 
                 index: Dict[str, Any], src_idx: int, snk_idx: int) -> Optional[Match]:
    """
    Stitch a single source-sink pair.
    
    Args:
        src_finding: Source finding dictionary
        snk_finding: Sink finding dictionary
        index: Class index dictionary
        src_idx: Source finding index (for tracking)
        snk_idx: Sink finding index (for tracking)
        
    Returns:
        Match object if stitchable, None otherwise
    """
    match = can_stitch_with_index(src_finding, snk_finding, index)
    if match:
        match.source_idx = src_idx
        match.sink_idx = snk_idx
        return match
    return None


def _extract_taint_source_origin(src_finding: Dict[str, Any]) -> Optional[str]:
    """
    Extract the original taint source from a finding's dataflow trace.
    
    This is a generic method that works with any finding structure.
    Returns a canonical identifier for the taint source (e.g., "sys.argv[1]").
    
    Args:
        src_finding: Source finding dictionary
        
    Returns:
        String identifier for the taint source, or None if not found
    """
    # Try to extract from dataflow_trace first (most accurate)
    trace = src_finding.get('dataflow_trace', {})
    taint_source = trace.get('taint_source')
    
    if taint_source:
        # Extract content from taint_source location
        # Structure: ["CliLoc", [{"path":..., "start": {"line":...}, ...}, "content"]]
        if isinstance(taint_source, list) and len(taint_source) >= 2:
            loc_data = taint_source[1]
            if isinstance(loc_data, list) and len(loc_data) >= 2:
                content = loc_data[1] if isinstance(loc_data[1], str) else None
                if content:
                    return content
    
    # Fallback: try to extract from metavars
    metavars = src_finding.get('extra', {}).get('metavars', {})
    
    # Check for common source patterns in metavars
    if '$INDEX' in metavars:
        index_val = metavars['$INDEX'].get('abstract_content', '')
        # Check if there's a propagated value that shows the original source
        if '$INPUT' in metavars:
            input_val = metavars['$INPUT']
            propagated = input_val.get('propagated_value', {})
            if propagated:
                source_content = propagated.get('svalue_abstract_content', '')
                if source_content:
                    return source_content
            # Fallback: construct from context
            input_content = input_val.get('abstract_content', '')
            if 'sys.argv' in str(input_val) or index_val:
                return f"sys.argv[{index_val}]" if index_val else "sys.argv"
    
    # Last resort: use the finding's code line if it contains a source pattern
    lines = src_finding.get('lines', '')
    if 'sys.argv' in lines:
        # Try to extract sys.argv[N] pattern
        import re
        match = re.search(r'sys\.argv\[(\d+)\]', lines)
        if match:
            return f"sys.argv[{match.group(1)}]"
    
    return None


def _get_flow_key(match: Match, src_finding: Dict[str, Any]) -> Tuple[str, str, int, int]:
    """
    Generate a canonical flow key for deduplication.
    
    Groups matches by actual taint flow: (source origin, sink path, sink line).
    This is generic and works for any codebase.
    
    Args:
        match: Match object
        src_finding: Source finding dictionary (for extracting origin)
        
    Returns:
        Tuple of (source_origin, sink_path, sink_line) for grouping
    """
    source_origin = _extract_taint_source_origin(src_finding)
    # Use sink location as the identifier (path + line)
    return (source_origin or match.source, match.sink_path, match.sink_line)


def _deduplicate_matches(matches: List[Match], sources: List[Dict[str, Any]]) -> List[Match]:
    """
    Deduplicate matches by grouping by actual taint flow.
    
    Generic deduplication that:
    1. Groups matches by (source origin + sink location)
    2. Keeps the best match per group (highest confidence, most specific strategy)
    3. Works for any codebase structure
    
    Args:
        matches: List of all matches
        sources: List of source findings (for extracting origins)
        
    Returns:
        Deduplicated list of matches (one per unique flow)
    """
    if not matches:
        return []
    
    # Group matches by flow key
    flow_groups: Dict[Tuple[str, str, int], List[Match]] = {}
    match_to_src = {i+1: src for i, src in enumerate(sources)}
    
    for match in matches:
        src_finding = match_to_src.get(match.source_idx)
        if not src_finding:
            continue
        
        flow_key = _get_flow_key(match, src_finding)
        if flow_key not in flow_groups:
            flow_groups[flow_key] = []
        flow_groups[flow_key].append(match)
    
    # For each group, keep the best match
    deduplicated = []
    confidence_order = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
    strategy_priority = {
        'Direct function match': 4,
        'Call graph propagation (same method)': 3,
        'Call graph propagation': 2,
        'Inheritance resolution': 1,
        'Attribute resolution': 1,
        'Class name match': 1
    }
    
    for flow_key, group_matches in flow_groups.items():
        if len(group_matches) == 1:
            deduplicated.append(group_matches[0])
        else:
            # Select best match: highest confidence, then most specific strategy,
            # then earliest source line (closer to actual source)
            best_match = max(
                group_matches,
                key=lambda m: (
                    confidence_order.get(m.confidence, 0),
                    strategy_priority.get(m.strategy, 0),
                    -m.source_line  # Negative for earlier lines (higher priority)
                )
            )
            deduplicated.append(best_match)
    
    return deduplicated


def stitch_batch(
    findings_dir: str = 'outputs/findings',
    index_file: str = 'outputs/indices/class_index.json',
    parallel: bool = True,
    max_workers: Optional[int] = None
) -> List[Match]:
    """
    Stitch source and sink findings in batch, with optional parallel processing.
    
    Auto-discovers all findings from a single directory and classifies them as
    source/sink based on metadata.
    
    Args:
        findings_dir: Directory containing all finding JSON files
        index_file: Path to class index JSON file
        parallel: Whether to use parallel processing (default: True)
        max_workers: Maximum number of worker threads (None = auto-detect)
        
    Returns:
        List of Match objects representing all stitched findings
        
    Time Complexity:
        Sequential: O(S × T) where S = sources, T = sinks
        Parallel: O(S × T / W) where W = workers (with overhead)
    """
    # Load class index
    index = load_index(index_file)
    
    # Discover and classify all findings from single directory
    sources, sinks, _ = discover_findings(findings_dir)
    
    if not sources or not sinks:
        return []
    
    matches = []
    
    if parallel:
        # Parallel processing using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all pairs for processing
            future_to_pair = {}
            for i, src_finding in enumerate(sources, 1):
                for j, snk_finding in enumerate(sinks, 1):
                    future = executor.submit(
                        _stitch_pair, src_finding, snk_finding, index, i, j
                    )
                    future_to_pair[future] = (i, j)
            
            # Collect results as they complete
            for future in as_completed(future_to_pair):
                match = future.result()
                if match:
                    matches.append(match)
    else:
        # Sequential processing
        for i, src_finding in enumerate(sources, 1):
            for j, snk_finding in enumerate(sinks, 1):
                match = _stitch_pair(src_finding, snk_finding, index, i, j)
                if match:
                    matches.append(match)
    
    # Deduplicate matches by actual taint flow
    # This ensures we return one match per unique flow (source origin + sink)
    return _deduplicate_matches(matches, sources)

