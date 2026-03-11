"""Main stitching orchestration."""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from holocron.core.indexer import load_index
from holocron.stitching.matcher import can_stitch_with_index
from holocron.core.types import Match, Confidence


def stitch_findings_with_index(
    source_file: str,
    sink_file: str,
    index_file: str = 'outputs/indices/class_index.json'
) -> List[Match]:
    """
    Stitch source and sink findings using the class index.
    
    This is the main entry point for stitching findings from forward pass
    (source rules) and backward pass (sink rules) into complete taint flows.
    
    Args:
        source_file: Path to source findings JSON file
        sink_file: Path to sink findings JSON file
        index_file: Path to class index JSON file
    
    Returns:
        List of Match objects representing stitched findings
    """
    # Load data
    with open(source_file, 'r') as f:
        source_data = json.load(f)
    
    with open(sink_file, 'r') as f:
        sink_data = json.load(f)
    
    index = load_index(index_file)
    
    matches = []
    for i, src_finding in enumerate(source_data['results'], 1):
        for j, snk_finding in enumerate(sink_data['results'], 1):
            match = can_stitch_with_index(src_finding, snk_finding, index)
            if match:
                match.source_idx = i
                match.sink_idx = j
                matches.append(match)
    
    return matches


def _get_code_line(file_path: str, line_num: int) -> str:
    """Get actual code line from file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if 1 <= line_num <= len(lines):
                return lines[line_num - 1].rstrip()
    except Exception:
        pass
    return "<code not available>"


def _is_deterministic_strategy(strategy: str, confidence: str) -> bool:
    """Determine if strategy is deterministic (vs heuristic)."""
    deterministic_strategies = [
        'Direct function match',
        'Call graph propagation (same method)'
    ]
    
    if strategy in deterministic_strategies and confidence == 'HIGH':
        return True
    
    # Call graph with verified path is deterministic
    if strategy == 'Call graph propagation' and confidence == 'HIGH':
        return True
    
    return False


def _format_location(loc: Any) -> str:
    """Format a location from dataflow_trace into readable string."""
    if isinstance(loc, list) and len(loc) >= 2:
        loc_type = loc[0] if isinstance(loc[0], str) else "Unknown"
        loc_data = loc[1] if len(loc) > 1 else None
        
        if isinstance(loc_data, list) and len(loc_data) > 0:
            loc_info = loc_data[0] if isinstance(loc_data[0], dict) else {}
            path = loc_info.get('path', '?')
            start = loc_info.get('start', {})
            line = start.get('line', '?')
            col = start.get('col', '?')
            return f"{path}:{line}:{col}"
        elif isinstance(loc_data, str):
            return loc_data
    
    return "Unknown location"


def _extract_taint_steps(trace: Dict) -> List[Dict]:
    """
    Extract taint steps from dataflow_trace.
    
    Returns list of steps with location and content.
    """
    steps = []
    
    # Extract taint source
    taint_source = trace.get('taint_source')
    if taint_source:
        source_loc = _format_location(taint_source)
        # Extract content from location
        if isinstance(taint_source, list) and len(taint_source) >= 2:
            loc_data = taint_source[1]
            if isinstance(loc_data, list) and len(loc_data) >= 2:
                content = loc_data[1] if isinstance(loc_data[1], str) else "?"
            else:
                content = str(loc_data) if isinstance(loc_data, str) else "?"
        else:
            content = "?"
        steps.append({'type': 'source', 'location': source_loc, 'content': content})
    
    # Extract intermediate variables
    intermediate_vars = trace.get('intermediate_vars', [])
    for ivar in intermediate_vars:
        if isinstance(ivar, dict):
            loc_info = ivar.get('location', {})
            path = loc_info.get('path', '?')
            start = loc_info.get('start', {})
            line = start.get('line', '?')
            col = start.get('col', '?')
            location = f"{path}:{line}:{col}"
            content = ivar.get('content', '?')
            steps.append({'type': 'intermediate', 'location': location, 'content': content})
    
    # Extract taint sink (where forward pass stops)
    taint_sink = trace.get('taint_sink')
    if taint_sink:
        sink_loc = _format_location(taint_sink)
        # Extract content from location
        if isinstance(taint_sink, list) and len(taint_sink) >= 2:
            loc_data = taint_sink[1]
            if isinstance(loc_data, list) and len(loc_data) >= 2:
                content = loc_data[1] if isinstance(loc_data[1], str) else "?"
            else:
                content = str(loc_data) if isinstance(loc_data, str) else "?"
        else:
            content = "?"
        steps.append({'type': 'sink_boundary', 'location': sink_loc, 'content': content})
    
    return steps


def _format_forward_pass(finding: Dict) -> Optional[str]:
    """
    Format forward pass (source rule) taint flow from finding's dataflow_trace.
    
    Shows: taint_source → intermediate_vars → taint_sink (where source rule stops)
    """
    trace = finding.get('dataflow_trace')
    if not trace:
        return None
    
    steps = _extract_taint_steps(trace)
    if not steps:
        return None
    
    lines = []
    lines.append("   Forward Pass (Source Rule):")
    
    for i, step in enumerate(steps):
        step_type = step['type']
        location = step['location']
        content = step['content']
        
        if step_type == 'source':
            lines.append(f"      Source: {content} ({location})")
        elif step_type == 'intermediate':
            lines.append(f"      → Intermediate: {content} ({location})")
        elif step_type == 'sink_boundary':
            lines.append(f"      → Sink Boundary: {content} ({location})")
    
    return '\n'.join(lines)


def _format_backward_pass(finding: Dict) -> Optional[str]:
    """
    Format backward pass (sink rule) taint flow from finding's dataflow_trace.
    
    Shows: taint_source (where sink rule starts) → taint_sink (the actual sink)
    """
    trace = finding.get('dataflow_trace')
    if not trace:
        return None
    
    steps = _extract_taint_steps(trace)
    if not steps:
        return None
    
    lines = []
    lines.append("   Backward Pass (Sink Rule):")
    
    # For sink findings, the trace shows where taint came from within the file
    # taint_source is the boundary where sink rule starts (often the method/function start)
    # taint_sink is the actual sink location
    
    source_step = next((s for s in steps if s['type'] == 'source'), None)
    sink_step = next((s for s in steps if s['type'] == 'sink_boundary'), None)
    
    if source_step:
        # Extract method/class context from source if available
        content = source_step['content']
        # Try to extract class/method from content if it's code
        if 'def ' in content or 'class ' in content:
            # This is the method/function boundary
            lines.append(f"      Source Boundary: {content[:100]}... ({source_step['location']})")
        else:
            lines.append(f"      Source Boundary: {content} ({source_step['location']})")
    
    # Show intermediate vars
    for step in steps:
        if step['type'] == 'intermediate':
            lines.append(f"      → Intermediate: {step['content']} ({step['location']})")
    
    if sink_step:
        lines.append(f"      → Sink: {sink_step['content']} ({sink_step['location']})")
    
    return '\n'.join(lines)


def _analyze_flow_intersection(
    src_finding: Dict,
    snk_finding: Dict,
    match: Match
) -> Optional[str]:
    """
    Analyze where forward and backward passes intersect.
    
    Returns formatted string describing the intersection point.
    """
    src_trace = src_finding.get('dataflow_trace', {})
    snk_trace = snk_finding.get('dataflow_trace', {})
    
    if not src_trace or not snk_trace:
        return None
    
    # Get forward pass sink boundary (where source rule stops)
    src_sink = src_trace.get('taint_sink')
    src_sink_loc = _format_location(src_sink) if src_sink else "Unknown"
    
    # Get backward pass source boundary (where sink rule starts)
    snk_source = snk_trace.get('taint_source')
    snk_source_loc = _format_location(snk_source) if snk_source else "Unknown"
    
    # Extract content for intersection analysis
    src_sink_content = "?"
    if src_sink and isinstance(src_sink, list) and len(src_sink) >= 2:
        loc_data = src_sink[1]
        if isinstance(loc_data, list) and len(loc_data) >= 2:
            src_sink_content = loc_data[1] if isinstance(loc_data[1], str) else "?"
    
    snk_source_content = "?"
    if snk_source and isinstance(snk_source, list) and len(snk_source) >= 2:
        loc_data = snk_source[1]
        if isinstance(loc_data, list) and len(loc_data) >= 2:
            snk_source_content = loc_data[1] if isinstance(loc_data[1], str) else "?"
        elif isinstance(loc_data, str):
            snk_source_content = loc_data[:100]  # Truncate long code blocks
    
    lines = []
    lines.append("   Intersection Analysis:")
    lines.append(f"      Forward pass stops at: {src_sink_content[:80]}... ({src_sink_loc})")
    lines.append(f"      Backward pass starts at: {snk_source_content[:80]}... ({snk_source_loc})")
    
    # Try to identify intersection point from match resolution
    if match.resolution:
        lines.append(f"      Stitched at: {match.resolution}")
    
    return '\n'.join(lines)


def print_stitching_results(matches: List[Match], source_findings: Optional[List[Dict]] = None, sink_findings: Optional[List[Dict]] = None) -> None:
    """
    Print stitching results in a verbose, traceable format.
    
    Args:
        matches: List of Match objects
        source_findings: Optional list of source findings (for code extraction)
        sink_findings: Optional list of sink findings (for code extraction)
    """
    print("=" * 80)
    print("STITCHED TAINT FLOWS")
    print("=" * 80)
    print(f"\nFound {len(matches)} stitched match(es) between source and sink findings.\n")
    
    # Group matches by unique flow paths (source->sink pairs)
    # Flow IDs are assigned in discovery order (algorithmic, deterministic)
    unique_flows = {}
    for i, match in enumerate(matches, 1):
        flow_key = (
            match.source_path,
            match.source_line,
            match.sink_path,
            match.sink_line
        )
        
        if flow_key not in unique_flows:
            unique_flows[flow_key] = {
                'matches': [],
                'flow_id': len(unique_flows) + 1  # Discovery order: first unique flow = 1, second = 2, etc.
            }
        unique_flows[flow_key]['matches'].append((i, match))
    
    # Print each unique flow with full details (in discovery order)
    for flow_key, flow_data in unique_flows.items():
        source_path, source_line, sink_path, sink_line = flow_key
        flow_id = flow_data['flow_id']
        matches_in_flow = flow_data['matches']
        
        print("=" * 80)
        print(f"FLOW #{flow_id}: {source_path}:{source_line} → {sink_path}:{sink_line}")
        print("=" * 80)
        
        # Get code lines
        source_code = _get_code_line(source_path, source_line)
        sink_code = _get_code_line(sink_path, sink_line)
        
        print(f"\n📍 SOURCE:")
        print(f"   File: {source_path}")
        print(f"   Line: {source_line}")
        print(f"   Code: {source_code}")
        
        print(f"\n📍 SINK:")
        print(f"   File: {sink_path}")
        print(f"   Line: {sink_line}")
        print(f"   Code: {sink_code}")
        
        # Show all matches for this flow
        print(f"\n🔗 MATCHING STRATEGIES ({len(matches_in_flow)} match(es)):")
        
        for match_num, match in matches_in_flow:
            is_deterministic = _is_deterministic_strategy(match.strategy, match.confidence)
            path_type = "DETERMINISTIC" if is_deterministic else "HEURISTIC"
            
            print(f"\n   Match #{match_num}: {match.strategy}")
            print(f"   └─ Path Type: {path_type}")
            print(f"   └─ Confidence: {match.confidence}")
            print(f"      {Confidence.explain(match.confidence)}")
            
            if match.resolution:
                print(f"   └─ Resolution Path: {match.resolution}")
            
            # Show source details
            if source_findings and match.source_idx <= len(source_findings):
                src_finding = source_findings[match.source_idx - 1]
                src_code = src_finding.get('lines', source_code)
                print(f"   └─ Source Finding #{match.source_idx}: {match.source}")
                print(f"      Code: {src_code}")
                # Show metavars if available
                metavars = src_finding.get('extra', {}).get('metavars', {})
                if metavars:
                    metavar_strs = []
                    for k, v in metavars.items():
                        if k.startswith('$'):
                            content = v.get('abstract_content', '?') if isinstance(v, dict) else str(v)
                            metavar_strs.append(f'{k}={content}')
                    if metavar_strs:
                        print(f"      Metavars: {', '.join(metavar_strs)}")
                
                # Show forward pass
                forward_pass = _format_forward_pass(src_finding)
                if forward_pass:
                    print(f"\n   📍 {forward_pass}")
            
            # Show sink details
            if sink_findings and match.sink_idx <= len(sink_findings):
                snk_finding = sink_findings[match.sink_idx - 1]
                snk_code = snk_finding.get('lines', sink_code)
                print(f"   └─ Sink Finding #{match.sink_idx}: {match.sink}")
                print(f"      Code: {snk_code}")
                # Show metavars if available
                metavars = snk_finding.get('extra', {}).get('metavars', {})
                if metavars:
                    metavar_strs = []
                    for k, v in metavars.items():
                        if k.startswith('$'):
                            content = v.get('abstract_content', '?') if isinstance(v, dict) else str(v)
                            metavar_strs.append(f'{k}={content}')
                    if metavar_strs:
                        print(f"      Metavars: {', '.join(metavar_strs)}")
                
                # Show backward pass
                backward_pass = _format_backward_pass(snk_finding)
                if backward_pass:
                    print(f"\n   📍 {backward_pass}")
            
            # Show intersection analysis
            if source_findings and sink_findings and \
               match.source_idx <= len(source_findings) and \
               match.sink_idx <= len(sink_findings):
                src_finding = source_findings[match.source_idx - 1]
                snk_finding = sink_findings[match.sink_idx - 1]
                intersection = _analyze_flow_intersection(src_finding, snk_finding, match)
                if intersection:
                    print(f"\n   🔗 {intersection}")
            
            # Show assumptions/notes
            if match.note:
                print(f"   └─ Assumptions/Notes: {match.note}")
            
            # Show what makes it deterministic or heuristic
            if is_deterministic:
                print(f"   └─ Why Deterministic: Direct match verified in index")
            else:
                print(f"   └─ Why Heuristic: Requires inference or assumptions")
                if 'inferred' in match.strategy.lower() or 'inference' in (match.note or '').lower():
                    print(f"      • Method/class inferred from line number or context")
                if match.confidence == 'MEDIUM':
                    print(f"      • Some uncertainty in resolution path")
                if match.confidence == 'LOW':
                    print(f"      • Significant assumptions required")
                    # Add specific reasons for LOW confidence
                    if match.note:
                        note_lower = match.note.lower()
                        if 'method overridden' in note_lower and 'no call graph path' in note_lower:
                            print(f"      • Method is overridden in subclass but no call graph path confirms this match")
                            print(f"      • May be matching to wrong method - actual flow may differ")
                        elif 'method overridden' in note_lower:
                            print(f"      • Method is overridden - runtime behavior uncertain")
                        if 'deep inheritance' in note_lower:
                            print(f"      • Deep inheritance chain increases uncertainty")
                        if 'inferred from line number' in note_lower:
                            print(f"      • Sink method inferred rather than explicitly matched")
        
        print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    deterministic_count = sum(
        1 for flow_data in unique_flows.values()
        for _, match in flow_data['matches']
        if _is_deterministic_strategy(match.strategy, match.confidence)
    )
    heuristic_count = len(matches) - deterministic_count
    
    print(f"\nTotal Unique Flows: {len(unique_flows)}")
    print(f"Total Matches: {len(matches)}")
    print(f"  └─ Deterministic: {deterministic_count}")
    print(f"  └─ Heuristic: {heuristic_count}")
    print(f"\nConfidence Distribution:")
    confidence_counts = {}
    for flow_data in unique_flows.values():
        for _, match in flow_data['matches']:
            confidence_counts[match.confidence] = confidence_counts.get(match.confidence, 0) + 1
    for conf, count in sorted(confidence_counts.items(), key=lambda x: ['HIGH', 'MEDIUM', 'LOW'].index(x[0])):
        print(f"  └─ {conf}: {count}")
    
    # Print unique flows with source-sink pairs
    print(f"\n{'=' * 80}")
    print("UNIQUE FLOWS (Source → Sink Pairs)")
    print(f"{'=' * 80}\n")
    
    for flow_key, flow_data in sorted(unique_flows.items(), key=lambda x: x[1]['flow_id']):
        source_path, source_line, sink_path, sink_line = flow_key
        flow_id = flow_data['flow_id']
        
        # Get code lines
        source_code = _get_code_line(source_path, source_line)
        sink_code = _get_code_line(sink_path, sink_line)
        
        print(f"Flow #{flow_id}:")
        print(f"  📍 SOURCE:")
        print(f"     File: {source_path}")
        print(f"     Line: {source_line}")
        print(f"     Code: {source_code}")
        print(f"  📍 SINK:")
        print(f"     File: {sink_path}")
        print(f"     Line: {sink_line}")
        print(f"     Code: {sink_code}")
        print()
    
    print(f"✅ Stitching complete: {len(unique_flows)} unique flow(s) identified")

