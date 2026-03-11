"""Auto-discovery utilities for finding source and sink findings in directories."""

import json
from pathlib import Path
from typing import Dict, List, Tuple, Any
from holocron.utils.finding_classifier import classify_finding_type


def discover_findings(base_dir: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Discover and classify findings from all JSON files in a directory.
    
    Recursively searches for all *.json files, loads them, extracts findings
    from the 'results' array, and classifies each finding.
    
    Args:
        base_dir: Base directory to search for JSON files
        
    Returns:
        Tuple of (sources, sinks, intermediaries) - each is a list of finding dictionaries
    """
    sources = []
    sinks = []
    intermediaries = []
    
    base_path = Path(base_dir)
    if not base_path.exists():
        return sources, sinks, intermediaries
    
    # Recursively find all JSON files
    json_files = list(base_path.rglob('*.json'))
    
    for file_path in json_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract findings from 'results' array
            findings = data.get('results', [])
            
            # Classify each finding
            for finding in findings:
                finding_type = classify_finding_type(finding)
                
                if finding_type == 'source':
                    sources.append(finding)
                elif finding_type == 'sink':
                    sinks.append(finding)
                elif finding_type == 'intermediary':
                    intermediaries.append(finding)
                # 'unknown' findings are skipped
                    
        except (json.JSONDecodeError, IOError) as e:
            # Skip invalid JSON files or files that can't be read
            continue
    
    return sources, sinks, intermediaries


def load_findings_from_files(file_paths: List[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Load and classify findings from explicit file paths.
    
    Args:
        file_paths: List of JSON file paths to load
        
    Returns:
        Tuple of (sources, sinks, intermediaries) - each is a list of finding dictionaries
    """
    sources = []
    sinks = []
    intermediaries = []
    
    for file_path in file_paths:
        try:
            path = Path(file_path)
            if not path.exists():
                continue
                
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = data.get('results', [])
            
            for finding in findings:
                finding_type = classify_finding_type(finding)
                
                if finding_type == 'source':
                    sources.append(finding)
                elif finding_type == 'sink':
                    sinks.append(finding)
                elif finding_type == 'intermediary':
                    intermediaries.append(finding)
                    
        except (json.JSONDecodeError, IOError):
            continue
    
    return sources, sinks, intermediaries

