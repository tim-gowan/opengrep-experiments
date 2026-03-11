"""Utility functions for parsing metavariables and findings."""

from typing import Dict, Any, Optional


def get_content(mv: Any) -> str:
    """
    Extract abstract_content from metavar (handles dict format).
    
    Metavariables from Opengrep/Semgrep can be either:
    - Simple strings
    - Dictionaries with location and abstract_content
    
    Args:
        mv: Metavariable value (string or dict)
    
    Returns:
        Extracted content string
    """
    if isinstance(mv, dict):
        return mv.get('abstract_content', '')
    return mv if mv else ''


def extract_metavars(finding: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract metavariables from a finding.
    
    Args:
        finding: Finding dictionary from JSON output
    
    Returns:
        Dictionary of metavariable names to values
    """
    metavars = finding.get('extra', {}).get('metavars', {})
    return {
        'obj': get_content(metavars.get('$OBJ', '')),
        'class': get_content(metavars.get('$CLASS', '')),
        'method': get_content(metavars.get('$METHOD', '')),
        'func': get_content(metavars.get('$FUNC', '')),
        'input': get_content(metavars.get('$INPUT', '')),
    }

