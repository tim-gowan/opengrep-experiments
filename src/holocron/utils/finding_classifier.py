"""Finding classification utilities for identifying source, sink, and intermediary findings."""

from typing import Dict, Any


def classify_finding_type(finding: Dict[str, Any]) -> str:
    """
    Classify a finding as source, sink, intermediary, or unknown.
    
    Uses a three-tier fallback strategy:
    1. Priority 1: Explicit metadata (finding['metadata']['finding_type'])
    2. Priority 2: Pattern match on check_id
    3. Priority 3: Pattern match on message content
    
    Args:
        finding: Finding dictionary from JSON output
        
    Returns:
        'source', 'sink', 'intermediary', or 'unknown'
    """
    # Priority 1: Explicit metadata (most reliable)
    metadata = finding.get('metadata', {})
    if isinstance(metadata, dict) and 'finding_type' in metadata:
        finding_type = metadata['finding_type']
        if finding_type in ['source', 'sink', 'intermediary']:
            return finding_type
    
    # Priority 2: Pattern match on check_id
    check_id = finding.get('check_id', '').lower()
    if 'sink' in check_id:
        return 'sink'
    elif any(keyword in check_id for keyword in ['source', 'input', 'parent']):
        return 'source'
    
    # Priority 3: Pattern match on message content (last resort)
    message = finding.get('message', '').lower()
    if 'sink' in message and 'source' not in message:
        return 'sink'
    elif any(keyword in message for keyword in ['source', 'input', 'flows to']):
        return 'source'
    
    return 'unknown'

