"""Individual stitching strategies with confidence scoring."""

from typing import Dict, Optional, Any, List, Tuple
from dataclasses import dataclass
from holocron.core.types import Confidence
from holocron.core.resolver import resolve_attribute_with_index, resolve_inheritance_with_index
from holocron.utils.parsers import extract_metavars, get_content


@dataclass
class StrategyConfig:
    """Configuration for matching strategies.
    
    All tunable parameters in one place for easy adjustment.
    """
    line_tolerance: int = 5  # Lines within which to consider method match
    max_path_hops: int = 3  # Maximum call path hops for HIGH confidence
    require_exact_match: bool = False  # Require exact line match
    allow_heuristics: bool = True  # Allow heuristic-based resolution
    
    def validate(self) -> bool:
        """Validate configuration values."""
        return self.line_tolerance > 0 and self.max_path_hops > 0


# Global default configuration
_DEFAULT_CONFIG = StrategyConfig()


def strategy_call_graph_propagation(
    src_finding: Dict,
    snk_finding: Dict,
    src_metavars: Dict[str, str],
    snk_metavars: Dict[str, str],
    index: Dict[str, Any],
    config: StrategyConfig = _DEFAULT_CONFIG
) -> Optional[Dict]:
    """
    Strategy 0: Call graph-based taint propagation (PRIMARY).
    
    Core principle: Match Opengrep metavars to indexed fields, then verify
    call path exists in method_calls.
    
    Confidence:
    - HIGH: Direct match to indexed fields, 1-hop call path verified
    - MEDIUM: Requires resolution, 2-3 hop call path verified
    - LOW: Many hops or unverified path
    
    Returns:
        Match dictionary or None
    """
    # Extract repo_id from index if available
    repo_info = index.get('repository', {})
    repo_id = repo_info.get('id') if isinstance(repo_info, dict) else None
    
    # Step 1: Extract source method identifier from metavars
    src_method_id = _extract_indexed_method_id(src_finding, src_metavars, index, config, repo_id)
    if not src_method_id:
        return None
    
    # Step 2: Extract sink method identifier from metavars
    snk_method_id = _extract_indexed_method_id(snk_finding, snk_metavars, index, config, repo_id)
    if not snk_method_id:
        return None
    
    # Step 3: Verify both exist in index
    if not _method_exists_in_index(src_method_id, index):
        return None
    if not _method_exists_in_index(snk_method_id, index):
        return None
    
    # Step 4: Check if call path exists in method_calls
    # Special case: If source and sink are the same method, it's a direct match
    if src_method_id == snk_method_id:
        return {
            'strategy': 'Call graph propagation (same method)',
            'source': src_method_id,
            'sink': snk_method_id,
            'confidence': Confidence.HIGH,
            'resolution': f"Same method: {src_method_id}",
            'path': [src_method_id],
            'hops': 0
        }
    
    call_path = _find_call_path_in_index(src_method_id, snk_method_id, index)
    
    if call_path:
        hops = len(call_path) - 1
        confidence = _determine_confidence_from_path(hops, call_path, src_metavars, snk_metavars, index, config)
        
        return {
            'strategy': 'Call graph propagation',
            'source': src_method_id,
            'sink': snk_method_id,
            'confidence': confidence,
            'resolution': ' → '.join(call_path),
            'path': call_path,
            'hops': hops
        }
    
    return None


def _is_method_overridden(child_class: str, method_name: str, parent_class: str, index: Dict[str, Any]) -> bool:
    """
    Check if a method is overridden in a child class.
    
    Args:
        child_class: Child class name
        method_name: Method name to check
        parent_class: Parent class name
        index: Class index
    
    Returns:
        True if method is overridden in child class, False otherwise
    """
    if child_class not in index.get('classes', {}):
        return False
    
    # Check if child class has the method
    child_methods = index['classes'][child_class].get('methods', {})
    return method_name in child_methods


def _parse_method_id(method_id: str) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Parse method ID to extract repo_id, class_name/function_name, and method_name.
    
    Handles formats:
    - "ClassName.method" -> (None, "ClassName", "method")
    - "function" -> (None, "function", None)
    - "repo-id:ClassName.method" -> ("repo-id", "ClassName", "method")
    - "repo-id:function" -> ("repo-id", "function", None)
    
    Args:
        method_id: Method identifier string
        
    Returns:
        Tuple of (repo_id, class_or_function_name, method_name)
    """
    if ':' in method_id:
        repo_part, rest = method_id.split(':', 1)
        if '.' in rest:
            class_name, method_name = rest.split('.', 1)
            return (repo_part, class_name, method_name)
        else:
            return (repo_part, rest, None)
    else:
        if '.' in method_id:
            class_name, method_name = method_id.split('.', 1)
            return (None, class_name, method_name)
        else:
            return (None, method_id, None)


def _infer_method_for_class(
    finding: Dict,
    class_name: str,
    index: Dict[str, Any],
    config: StrategyConfig
) -> Optional[str]:
    """
    Infer method name for a class from finding context.
    
    Tries multiple strategies:
    1. Line number inference
    2. Constructor call detection from dataflow_trace
    3. Constructor call detection from method_calls
    4. Fallback to __init__ if class exists
    """
    # Strategy 1: Line number inference
    method = _infer_method_from_line(finding, class_name, index, config)
    if method:
        return method
    
    # Strategy 2: Constructor call from dataflow_trace
    finding_line = _extract_line_from_trace(finding)
    if finding_line:
        method = _find_constructor_call_at_line(class_name, finding_line, index, config)
        if method:
            return method
    
    # Strategy 3: Fallback - assume __init__ if class exists
    if class_name in index.get('classes', {}):
        class_info = index['classes'][class_name]
        if '__init__' in class_info.get('methods', {}):
            return '__init__'
    
    return None


def _extract_line_from_trace(finding: Dict) -> Optional[int]:
    """Extract line number from dataflow_trace taint_sink, fallback to finding line."""
    finding_line = finding.get('start', {}).get('line')
    
    trace = finding.get('dataflow_trace', {})
    taint_sink = trace.get('taint_sink')
    
    if not taint_sink or not isinstance(taint_sink, list) or len(taint_sink) < 2:
        return finding_line
    
    sink_data = taint_sink[1]
    if not isinstance(sink_data, list) or len(sink_data) == 0:
        return finding_line
    
    sink_loc = sink_data[0] if isinstance(sink_data[0], dict) else {}
    sink_line = sink_loc.get('start', {}).get('line')
    
    return sink_line if sink_line else finding_line


def _find_constructor_call_at_line(
    class_name: str,
    line: int,
    index: Dict[str, Any],
    config: StrategyConfig
) -> Optional[str]:
    """Find if there's a constructor call for class_name at the given line."""
    for call_info in index.get('method_calls', []):
        call = call_info.get('call', {})
        call_line = call_info.get('line')
        
        if (call.get('type') == 'function_call' and
            call.get('function') == class_name and
            call_line and abs(call_line - line) <= config.line_tolerance):
            return '__init__'
    
    return None


def _build_method_id_if_exists(
    class_name: str,
    method: str,
    index: Dict[str, Any],
    repo_id: Optional[str]
) -> Optional[str]:
    """Build method ID if it exists in index, checking both flat and repo-scoped structures."""
    # Check flat structure first (backward compatible)
    if class_name in index.get('classes', {}):
        methods = index['classes'][class_name].get('methods', {})
        if method in methods:
            return _build_method_id(class_name, method, repo_id)
    
    # Check repo-scoped structure
    if repo_id and repo_id in index.get('repositories', {}):
        repo_index = index['repositories'][repo_id]
        if class_name in repo_index.get('classes', {}):
            methods = repo_index['classes'][class_name].get('methods', {})
            if method in methods:
                return _build_method_id(class_name, method, repo_id)
    
    return None


def _build_method_id(class_name: str, method: str, repo_id: Optional[str]) -> str:
    """Build a method identifier string."""
    method_id = f"{class_name}.{method}"
    return f"{repo_id}:{method_id}" if repo_id else method_id


def _resolve_obj_to_class_for_method(
    obj: str,
    finding: Dict,
    index: Dict[str, Any],
    config: StrategyConfig
) -> Optional[str]:
    """
    Resolve object to class for method call resolution.
    
    Handles nested paths like "manager.processor" and simple objects.
    """
    if '.' in obj:
        return _resolve_nested_path_to_class(obj, index)
    else:
        return _resolve_obj_to_indexed_class(obj, finding, index, config)


def _resolve_nested_path_to_class(obj: str, index: Dict[str, Any]) -> Optional[str]:
    """Resolve nested attribute path (e.g., 'manager.processor') to class."""
    parts = obj.split('.')
    attr_name = parts[-1]  # e.g., "processor" from "manager.processor"
    
    # Search through all classes to find which one has this attribute
    for class_name, class_info in index.get('classes', {}).items():
        attrs = class_info.get('attributes', {})
        if attr_name not in attrs:
            continue
        
        # Check if attribute type is a class
        attr_info = attrs[attr_name]
        for attr in attr_info:
            attr_type = attr.get('type')
            if not attr_type:
                continue
            
            # Direct class type
            if attr_type in index.get('classes', {}):
                return attr_type
            
            # Constructor call string (e.g., "BenchmarkTest00001(data)")
            if isinstance(attr_type, str) and '(' in attr_type:
                class_part = attr_type.split('(')[0].strip()
                if class_part in index.get('classes', {}):
                    return class_part
    
    # Fallback: try the existing attribute resolution function
    return resolve_attribute_with_index(obj, index)


def _infer_class_from_finding(finding: Dict, index: Dict[str, Any]) -> Optional[str]:
    """
    Infer class name from finding's file path and dataflow trace.
    
    For backward findings, the class name can often be inferred from:
    1. File path (e.g., BenchmarkTest00005.py -> BenchmarkTest00005)
    2. Dataflow trace taint_source showing class definition
    """
    # Try file path first
    file_path = finding.get('path', '')
    if file_path:
        # Extract filename without extension
        import os
        filename = os.path.basename(file_path)
        class_name = os.path.splitext(filename)[0]
        # Check if this class exists in index
        if class_name in index.get('classes', {}):
            return class_name
    
    # Try dataflow trace
    trace = finding.get('dataflow_trace', {})
    taint_source = trace.get('taint_source')
    if taint_source and isinstance(taint_source, list) and len(taint_source) > 1:
        source_data = taint_source[1]
        if isinstance(source_data, list) and len(source_data) > 0:
            source_str = source_data[-1] if isinstance(source_data[-1], str) else ""
            # Look for "class ClassName:" pattern
            import re
            match = re.search(r'class\s+(\w+):', source_str)
            if match:
                class_name = match.group(1)
                if class_name in index.get('classes', {}):
                    return class_name
    
    return None


def _extract_indexed_method_id(
    finding: Dict,
    metavars: Dict[str, str],
    index: Dict[str, Any],
    config: StrategyConfig = _DEFAULT_CONFIG,
    repo_id: Optional[str] = None
) -> Optional[str]:
    """
    Extract method identifier that matches index structure.
    
    Returns: "ClassName.method", "repo-id:ClassName.method", "function", or None
    
    Matches:
    - index['classes'][className]['methods'][methodName]
    - index['functions'][functionName]
    - index['repositories'][repoId]['classes'][className]['methods'][methodName] (if repo_id provided)
    
    Args:
        finding: Finding dictionary
        metavars: Extracted metavariables
        index: Class index dictionary
        config: Strategy configuration
        repo_id: Optional repository identifier for repo-scoped method IDs
    """
    # Case 1: Function (not a method)
    func = metavars.get('func')
    if func:
        # Check flat structure first (backward compatible)
        if func in index.get('functions', {}):
            return f"{repo_id}:{func}" if repo_id else func
        # Check repo-scoped structure
        if repo_id and repo_id in index.get('repositories', {}):
            repo_index = index['repositories'][repo_id]
            if func in repo_index.get('functions', {}):
                return f"{repo_id}:{func}"
    
    # Case 2: Class method - check if we have both class and method
    class_name = metavars.get('class')
    method = metavars.get('method')
    
    if class_name:
        # If method not in metavars, try to infer
        if not method:
            method = _infer_method_for_class(finding, class_name, index, config)
            # If inference failed, we can't proceed without a method
            if not method:
                return None
        
        # Return method ID if it exists in index
        method_id = _build_method_id_if_exists(class_name, method, index, repo_id)
        if method_id:
            return method_id
    
    # Case 3: Object method call - resolve to class
    obj = metavars.get('obj')
    method = metavars.get('method')
    
    if not (obj and method):
        # Case 4: Fallback - infer from file path and dataflow_trace for backward findings
        # Backward findings often lack metavariables but have class info in trace
        class_name = _infer_class_from_finding(finding, index)
        if class_name:
            # For backward findings, check taint_source to find where taint originates
            trace = finding.get('dataflow_trace', {})
            taint_source = trace.get('taint_source')
            if taint_source and isinstance(taint_source, list) and len(taint_source) > 1:
                source_data = taint_source[1]
                if isinstance(source_data, list) and len(source_data) > 0:
                    source_str = source_data[-1] if isinstance(source_data[-1], str) else ""
                    # Check if taint_source shows __init__ constructor pattern
                    if "__init__" in source_str or "def __init__" in source_str:
                        method_id = _build_method_id_if_exists(class_name, '__init__', index, repo_id)
                        if method_id:
                            return method_id
                    # Try to extract method from source string pattern
                    import re
                    method_match = re.search(r'def\s+(\w+)\s*\(', source_str)
                    if method_match:
                        method_name = method_match.group(1)
                        method_id = _build_method_id_if_exists(class_name, method_name, index, repo_id)
                        if method_id:
                            return method_id
            # Fallback: Try to infer method from finding line number
            # For backward findings, the sink is at the finding line, but we need the source method
            # Try line-based inference first (this will find the method containing the sink)
            inferred_method = _infer_method_for_class(finding, class_name, index, config)
            if inferred_method:
                # For backward findings, if the inferred method is not __init__, check if taint
                # originates from a parameter in that method (not from __init__)
                # The backward finding's taint_source should show where the parameter comes from
                method_id = _build_method_id_if_exists(class_name, inferred_method, index, repo_id)
                if method_id:
                    return method_id
            # Last resort: if class exists, try __init__ (common for constructor parameters)
            if class_name in index.get('classes', {}):
                class_info = index['classes'][class_name]
                if '__init__' in class_info.get('methods', {}):
                    method_id = _build_method_id_if_exists(class_name, '__init__', index, repo_id)
                    if method_id:
                        return method_id
        return None
    
    # Special case: If method is actually a class name (nested class constructor)
    if method in index.get('classes', {}):
        return _build_method_id(method, '__init__', repo_id)
    
    # Resolve obj to class
    resolved_class = _resolve_obj_to_class_for_method(obj, finding, index, config)
    if resolved_class:
        return _build_method_id(resolved_class, method, repo_id)
    
    return None


def _infer_method_from_line(
    finding: Dict,
    class_name: str,
    index: Dict[str, Any],
    config: StrategyConfig = _DEFAULT_CONFIG
) -> Optional[str]:
    """
    Infer method name from line number and class.
    
    Confidence: MEDIUM (inference-based)
    
    Since the index only stores method start lines, we check:
    1. Exact match
    2. Line is within tolerance of method start (tolerance for method body)
    
    Uses closest match algorithm to prevent false matches when multiple
    methods are nearby.
    
    Args:
        finding: Finding dictionary
        class_name: Class name to search in
        index: Class index
        config: Strategy configuration (uses line_tolerance)
    
    Returns:
        Method name if found, None otherwise
    """
    if class_name not in index.get('classes', {}):
        return None
    
    line = finding.get('start', {}).get('line')
    if not line:
        return None
    
    # Find method at this line or nearby
    methods = index['classes'][class_name].get('methods', {})
    
    # First try exact match
    for method_name, method_info in methods.items():
        if method_info.get('line') == line:
            return method_name
    
    # Then try tolerance match (within config.line_tolerance of method start)
    # This handles cases where the sink is inside the method body
    # IMPORTANT: Find the CLOSEST match, not the first match
    best_match = None
    min_distance = float('inf')
    for method_name, method_info in methods.items():
        method_start = method_info.get('line')
        if method_start:
            distance = abs(line - method_start)
            if distance <= config.line_tolerance and distance < min_distance:
                min_distance = distance
                best_match = method_name
    
    return best_match


def _resolve_obj_to_indexed_class(
    obj: str,
    finding: Dict,
    index: Dict[str, Any],
    config: StrategyConfig = _DEFAULT_CONFIG
) -> Optional[str]:
    """
    Resolve object name to class using index.
    
    Confidence: MEDIUM (heuristic-based)
    
    Uses multiple strategies and scores matches to return the best one.
    
    Strategies (in order of preference):
    1. Direct class name match
    2. Capitalized version
    3. Variable assignment from method_calls (constructor calls nearby)
    4. Method-based inference (obj.method() → find class with method)
    5. Substring match in class names
    
    Args:
        obj: Object/variable name to resolve
        finding: Finding dictionary (for line number and metavars)
        index: Class index
        config: Strategy configuration
    
    Returns:
        Best matching class name or None
    """
    if not config.allow_heuristics:
        # Only try direct matches if heuristics disabled
        if obj in index.get('classes', {}):
            return obj
        capitalized = obj.capitalize()
        if capitalized in index.get('classes', {}):
            return capitalized
        return None
    
    # Score potential matches using multiple strategies
    matches: List[Tuple[str, float]] = []
    
    matches.extend(_score_direct_class_match(obj, index))
    matches.extend(_score_capitalized_match(obj, index))
    matches.extend(_score_constructor_call_match(obj, finding, index, config))
    matches.extend(_score_method_based_match(obj, finding, index))
    matches.extend(_score_substring_match(obj, index))
    
    # Return highest scoring match
    if matches:
        return max(matches, key=lambda x: x[1])[0]
    
    return None


def _score_direct_class_match(obj: str, index: Dict[str, Any]) -> List[Tuple[str, float]]:
    """Strategy 1: Direct class name match (highest score)."""
    if obj in index.get('classes', {}):
        return [(obj, 1.0)]
    return []


def _score_capitalized_match(obj: str, index: Dict[str, Any]) -> List[Tuple[str, float]]:
    """Strategy 2: Capitalized version (high score)."""
    capitalized = obj.capitalize()
    if capitalized in index.get('classes', {}):
        return [(capitalized, 0.9)]
    return []


def _score_constructor_call_match(
    obj: str,
    finding: Dict,
    index: Dict[str, Any],
    config: StrategyConfig
) -> List[Tuple[str, float]]:
    """Strategy 3: Variable assignment from method_calls (medium-high score)."""
    matches = []
    finding_line = finding.get('start', {}).get('line')
    if not finding_line:
        return matches
    
    for call_info in index.get('method_calls', []):
        call = call_info.get('call', {})
        call_line = call_info.get('line')
        
        if not (call.get('type') == 'function_call' and
                call_line and 0 <= (finding_line - call_line) <= config.line_tolerance):
            continue
        
        func_name = call.get('function')
        if not func_name or func_name not in index.get('classes', {}):
            continue
        
        # Score based on proximity and name similarity
        distance = finding_line - call_line
        proximity_score = 1.0 - (distance / config.line_tolerance)
        name_score = 0.5 if obj.lower() in func_name.lower() else 0.3
        score = 0.7 * proximity_score + name_score
        matches.append((func_name, score))
    
    return matches


def _score_method_based_match(
    obj: str,
    finding: Dict,
    index: Dict[str, Any]
) -> List[Tuple[str, float]]:
    """Strategy 4: Method-based inference (medium score)."""
    matches = []
    metavars = finding.get('extra', {}).get('metavars', {})
    method_var = metavars.get('$METHOD')
    
    if not method_var:
        return matches
    
    method_name = get_content(method_var)
    if not method_name:
        return matches
    
    for class_name, class_info in index.get('classes', {}).items():
        methods = class_info.get('methods', {})
        if method_name not in methods:
            continue
        
        # Score based on name similarity and whether method is actually called
        name_score = 0.8 if obj.lower() in class_name.lower() else 0.5
        
        # Bonus if method is actually called in method_calls
        if _is_method_called_in_index(class_name, method_name, index):
            name_score += 0.1
        
        matches.append((class_name, name_score))
    
    return matches


def _is_method_called_in_index(class_name: str, method_name: str, index: Dict[str, Any]) -> bool:
    """Check if a method is actually called in method_calls."""
    for call_info in index.get('method_calls', []):
        if (call_info.get('caller_class') == class_name and
            call_info.get('call', {}).get('method') == method_name):
            return True
    return False


def _score_substring_match(obj: str, index: Dict[str, Any]) -> List[Tuple[str, float]]:
    """Strategy 5: Substring match (low score)."""
    matches = []
    obj_lower = obj.lower()
    
    for class_name in index.get('classes', {}):
        class_lower = class_name.lower()
        if obj_lower in class_lower or class_lower.startswith(obj_lower):
            matches.append((class_name, 0.3))
    
    return matches


def _method_exists_in_index(method_id: str, index: Dict[str, Any]) -> bool:
    """
    Check if method identifier exists in index.
    
    Supports both repo-scoped and flat structure (backward compatible).
    Handles formats:
    - "ClassName.method" (flat structure)
    - "repo-id:ClassName.method" (repo-scoped)
    - "function" (flat structure)
    - "repo-id:function" (repo-scoped)
    """
    repo_id, class_or_func, method_name = _parse_method_id(method_id)
    
    if method_name:
        # Class method
        if repo_id:
            # Check repo-scoped structure
            if repo_id in index.get('repositories', {}):
                repo_index = index['repositories'][repo_id]
                if class_or_func in repo_index.get('classes', {}):
                    methods = repo_index['classes'][class_or_func].get('methods', {})
                    if method_name in methods:
                        return True
        # Check flat structure (backward compatible)
        if class_or_func in index.get('classes', {}):
            methods = index['classes'][class_or_func].get('methods', {})
            if method_name in methods:
                return True
    else:
        # Function
        if repo_id:
            # Check repo-scoped structure
            if repo_id in index.get('repositories', {}):
                repo_index = index['repositories'][repo_id]
                if class_or_func in repo_index.get('functions', {}):
                    return True
        # Check flat structure (backward compatible)
        if class_or_func in index.get('functions', {}):
            return True
    
    return False


def _find_call_path_in_index(
    src_method_id: str,
    snk_method_id: str,
    index: Dict[str, Any]
) -> Optional[List[str]]:
    """
    Find call path from source to sink using method_calls.
    
    Supports both repo-scoped and flat method IDs.
    Handles cross-repo paths when repo prefixes differ.
    
    Returns: [src_method_id, intermediate1, ..., snk_method_id] or None
    """
    if src_method_id == snk_method_id:
        return [src_method_id]
    
    # Parse method IDs to extract repo info
    src_repo, _, _ = _parse_method_id(src_method_id)
    snk_repo, _, _ = _parse_method_id(snk_method_id)
    
    # Build call graph from method_calls
    call_graph = _build_call_graph(index)
    
    # BFS to find path
    queue = [(src_method_id, [src_method_id])]
    visited = {src_method_id}
    
    while queue:
        current, path = queue.pop(0)
        
        for neighbor in call_graph.get(current, []):
            if neighbor == snk_method_id:
                return path + [neighbor]
            
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))
    
    return None


def _build_call_graph(index: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Build call graph from index method_calls and cross_repo_calls.
    
    Returns a dictionary mapping caller method IDs to lists of callee method IDs.
    """
    call_graph = {}
    
    # Add method calls from index
    for call_info in index.get('method_calls', []):
        caller_id = _build_caller_id(call_info)
        if not caller_id:
            continue
        
        if caller_id not in call_graph:
            call_graph[caller_id] = []
        
        callee_id = _resolve_callee_from_call(
            call_info.get('call', {}),
            call_info.get('caller_class', ''),
            index,
            call_info.get('caller_repo')
        )
        if callee_id:
            call_graph[caller_id].append(callee_id)
    
    # Add cross-repo calls
    for cross_call in index.get('cross_repo_calls', []):
        caller = cross_call.get('caller')
        callee = cross_call.get('callee')
        if caller and callee:
            if caller not in call_graph:
                call_graph[caller] = []
            call_graph[caller].append(callee)
    
    return call_graph


def _build_caller_id(call_info: Dict[str, Any]) -> Optional[str]:
    """Build caller method ID from call info."""
    caller_class = call_info.get('caller_class')
    caller_method = call_info.get('caller_method')
    caller_repo = call_info.get('caller_repo')
    
    if not caller_class or not caller_method:
        return None
    
    caller_id = f"{caller_class}.{caller_method}"
    return f"{caller_repo}:{caller_id}" if caller_repo else caller_id


def _resolve_callee_from_call(
    call: Dict,
    caller_class: str,
    index: Dict[str, Any],
    caller_repo: Optional[str] = None
) -> Optional[str]:
    """
    Resolve a call to a method identifier.
    
    Handles:
    - function_call: "BenchmarkTest00001" → "BenchmarkTest00001.__init__" or "repo-id:BenchmarkTest00001.__init__"
    - method_call: "self.process" → "ClassName.process" or "repo-id:ClassName.process"
    - nested_method_call: "self.processor.execute" → "BenchmarkTest00001.execute" or "repo-id:BenchmarkTest00001.execute"
    
    Args:
        call: Call information dictionary
        caller_class: Class name of caller
        index: Class index dictionary
        caller_repo: Optional repository identifier of caller
    """
    call_type = call.get('type')
    
    if call_type == 'function_call':
        # Constructor call
        func_name = call.get('function')
        # Check flat structure first (backward compatible)
        if func_name in index.get('classes', {}):
            result = f"{func_name}.__init__"
            return f"{caller_repo}:{result}" if caller_repo else result
        # Check repo-scoped structure
        if caller_repo and caller_repo in index.get('repositories', {}):
            repo_index = index['repositories'][caller_repo]
            if func_name in repo_index.get('classes', {}):
                return f"{caller_repo}:{func_name}.__init__"
    
    elif call_type == 'method_call':
        obj = call.get('object')
        method = call.get('method')
        
        if not obj or not method:
            return None
        
        if obj == 'self':
            # self.method() in caller_class
            result = f"{caller_class}.{method}"
            return f"{caller_repo}:{result}" if caller_repo else result
        else:
            # obj.method() - need to resolve obj type
            # This is an ASSUMPTION - confidence decremented
            resolved_class = _resolve_variable_to_class(obj, caller_class, index)
            if resolved_class:
                result = f"{resolved_class}.{method}"
                return f"{caller_repo}:{result}" if caller_repo else result
    
    elif call_type == 'nested_method_call':
        # self.processor.execute
        path = call.get('path', '').replace('self.', '')
        method = call.get('method')
        
        # Resolve path to class using attribute resolution
        resolved_class = resolve_attribute_with_index(path, index)
        if resolved_class:
            result = f"{resolved_class}.{method}"
            return f"{caller_repo}:{result}" if caller_repo else result
    
    return None


def _resolve_variable_to_class(
    var_name: str,
    caller_class: str,
    index: Dict[str, Any]
) -> Optional[str]:
    """Resolve variable name to class (heuristic)."""
    # Check if it's a class name
    if var_name in index.get('classes', {}):
        return var_name
    
    # Heuristic: capitalized version
    capitalized = var_name.capitalize()
    if capitalized in index.get('classes', {}):
        return capitalized
    
    return None


def _determine_confidence_from_path(
    hops: int,
    path: List[str],
    src_metavars: Dict[str, str],
    snk_metavars: Dict[str, str],
    index: Dict[str, Any],
    config: StrategyConfig = _DEFAULT_CONFIG
) -> str:
    """
    Determine confidence based on path quality.
    
    Rules:
    - 0 hops (same method): HIGH
    - 1 hop: HIGH (direct call)
    - 2-config.max_path_hops hops: MEDIUM (requires some resolution)
    - >config.max_path_hops hops: LOW (many assumptions)
    - If any hop requires variable resolution: decrement
    
    Args:
        hops: Number of hops in call path
        path: Call path list
        src_metavars: Source metavariables
        snk_metavars: Sink metavariables
        index: Class index
        config: Strategy configuration
    
    Returns:
        Confidence level string
    """
    if hops == 0:
        return Confidence.HIGH
    
    if hops == 1:
        return Confidence.HIGH
    
    if hops <= config.max_path_hops:
        # Check if path requires resolution
        requires_resolution = _path_requires_resolution(path, index)
        if requires_resolution:
            return Confidence.MEDIUM
        return Confidence.MEDIUM
    
    return Confidence.LOW


def _path_requires_resolution(path: List[str], index: Dict[str, Any]) -> bool:
    """Check if path requires variable/attribute resolution."""
    # If any method in path requires inference, confidence is lower
    # This is a simplified check - could be enhanced
    return False  # Placeholder


def strategy_direct_function_match(
    src_finding: Dict,
    snk_finding: Dict,
    src_metavars: Dict[str, str],
    snk_metavars: Dict[str, str]
) -> Optional[Dict]:
    """
    Strategy 1: Direct function name match.
    
    Confidence: HIGH
    - Direct function name match (src_func == snk_func)
    - Or class name matches function name (src_class == snk_func)
    - No resolution needed, exact match
    
    Returns:
        Match dictionary or None
    """
    src_func = src_metavars['func']
    src_class = src_metavars['class']
    snk_func = snk_metavars['func']
    
    if (src_func and snk_func and src_func == snk_func) or \
       (src_class and snk_func and src_class == snk_func):
        return {
            'strategy': 'Direct function match',
            'source': f"{src_func or src_class}",
            'sink': f"{snk_func}",
            'confidence': Confidence.HIGH
        }
    return None


def strategy_attribute_resolution(
    src_finding: Dict,
    snk_finding: Dict,
    src_metavars: Dict[str, str],
    snk_metavars: Dict[str, str],
    index: Dict[str, Any]
) -> Optional[Dict]:
    """
    Strategy 2: Method name match with attribute resolution.
    
    Confidence: HIGH (if resolution successful)
    - Resolves obj.attr → Class using index
    - Confirms resolved class matches sink class
    - Method names match
    
    Confidence: MEDIUM (if no resolution but method matches)
    - Method name matches but attribute resolution failed
    - Some uncertainty in the match
    
    Returns:
        Match dictionary or None
    """
    src_obj = src_metavars['obj']
    src_method = src_metavars['method']
    snk_class = snk_metavars['class']
    snk_method = snk_metavars['method']
    
    if not src_method:
        return None
    
    src_path = f"{src_obj}.{src_method}" if src_obj else src_method
    
    # Try attribute resolution if we have obj.method
    if src_obj and '.' in src_obj:
        resolved_class = resolve_attribute_with_index(src_obj, index)
        if resolved_class:
            # HIGH confidence: Full resolution successful
            if resolved_class == snk_class:
                if snk_method and src_method == snk_method:
                    return {
                        'strategy': 'Attribute resolution + method match',
                        'source': f"{src_obj}.{src_method}",
                        'sink': f"{snk_class}.{snk_method}",
                        'confidence': Confidence.HIGH,
                        'resolution': f"{src_obj} → {resolved_class}"
                    }
                # Also check by line number if method not in sink metavars
                # Removed hard-coded method name check - use generic inference instead
                snk_line = snk_finding['start']['line']
                if snk_method and src_method == snk_method:
                    return {
                        'strategy': 'Attribute resolution + method match',
                        'source': f"{src_obj}.{src_method}",
                        'sink': f"{snk_class}.{snk_method}",
                        'confidence': Confidence.HIGH,
                        'resolution': f"{src_obj} → {resolved_class}"
                    }
    
    # MEDIUM confidence: Method name matches but no resolution
    if snk_method and snk_method in src_path:
        return {
            'strategy': 'Method name substring',
            'source': src_path,
            'sink': f"{snk_class}.{snk_method}",
            'confidence': Confidence.MEDIUM,
            'note': 'Method name matches but attribute resolution not confirmed'
        }
    
    # MEDIUM confidence: Line number inference (generic)
    # Removed hard-coded method name check - use generic method matching instead
    snk_line = snk_finding['start']['line']
    if snk_method and src_method == snk_method:
        return {
            'strategy': 'Method name + line number inference',
            'source': src_path,
            'sink': f"{snk_class}.{snk_method} (inferred from line {snk_line})",
            'confidence': Confidence.MEDIUM,
            'note': 'Inference based on method name and line number'
        }
    
    return None


def strategy_inheritance_resolution(
    src_finding: Dict,
    snk_finding: Dict,
    src_metavars: Dict[str, str],
    snk_metavars: Dict[str, str],
    index: Dict[str, Any],
    config: StrategyConfig = _DEFAULT_CONFIG
) -> Optional[Dict]:
    """
    Strategy 3: Inheritance resolution.
    
    Confidence: HIGH (if method not overridden)
    - Resolves inheritance chain using index
    - Confirms sink class is parent of source class
    - Verified relationship
    - Method is NOT overridden in child class
    
    Confidence: MEDIUM (if method overridden or complex inheritance)
    - Inheritance relationship verified
    - But method may be overridden (requires runtime resolution)
    - Complex inheritance chains (known Opengrep limitation)
    
    Confidence: LOW (if many assumptions required)
    - Deep inheritance chains
    - Multiple overrides
    
    Returns:
        Match dictionary or None
    """
    src_method = src_metavars.get('method')
    src_obj = src_metavars.get('obj')
    src_class = src_metavars.get('class')
    snk_class = snk_metavars.get('class')
    snk_method = snk_metavars.get('method')
    snk_line = snk_finding.get('start', {}).get('line')
    
    # Try to extract child class from source
    child_class = None
    if src_class:
        child_class = src_class
    elif src_method and src_method in index.get('classes', {}):
        # Special case: method is actually a class name (nested class constructor)
        # e.g., manager.BenchmarkTest00002_Subclass -> BenchmarkTest00002_Subclass
        child_class = src_method
    elif src_obj:
        # Try to resolve obj to class
        child_class = _resolve_obj_to_indexed_class(src_obj, src_finding, index, config)
    
    if not child_class or not snk_class:
        return None
    
    # Check if child class inherits from sink class
    parents = resolve_inheritance_with_index(child_class, index)
    if snk_class not in parents:
        return None
    
    # Infer sink method if not provided
    if not snk_method and snk_line:
        snk_method = _infer_method_from_line(snk_finding, snk_class, index, config)
    
    # Check if method is overridden in child class
    # This is important: if Extended.process() overrides base class,
    # we shouldn't match to base class process() sink unless we can verify the path
    method_overridden = False
    if snk_method:
        method_overridden = _is_method_overridden(child_class, snk_method, snk_class, index)
    
    # If method is overridden, we need to verify there's a call graph path
    # If no path exists, the overridden method may not actually call the parent method
    # (e.g., process() is overridden and calls execute() instead, so we shouldn't match to process())
    if method_overridden and snk_method:
        # Try to find a call path from child class constructor to sink method
        # Extract repo_id if available
        repo_info = index.get('repository', {})
        repo_id = repo_info.get('id') if isinstance(repo_info, dict) else None
        
        # Try __init__ -> sink method path
        child_init_id = f"{repo_id}:{child_class}.__init__" if repo_id else f"{child_class}.__init__"
        snk_method_id = f"{repo_id}:{snk_class}.{snk_method}" if repo_id else f"{snk_class}.{snk_method}"
        call_graph_path = _find_call_path_in_index(child_init_id, snk_method_id, index)
        
        if call_graph_path is None:
            # Method is overridden but no call graph path found
            # This means the overridden method likely doesn't call the parent method
            # (e.g., BenchmarkTest00002_Subclass.process() doesn't call BenchmarkTest00001.process())
            # Reject the match to avoid FP
            return None
    
    # Determine confidence based on complexity
    confidence = Confidence.HIGH
    assumptions = []
    
    if method_overridden:
        # Method is overridden but call graph path exists - MEDIUM confidence
        # (We already returned None if no path exists above)
        confidence = Confidence.MEDIUM
        assumptions.append(f"Method {snk_method} is overridden in {child_class}")
    
    # Check inheritance depth (deeper = lower confidence)
    inheritance_depth = len(parents)
    if inheritance_depth > 2:
        if confidence == Confidence.HIGH:
            confidence = Confidence.MEDIUM
        elif confidence == Confidence.MEDIUM:
            confidence = Confidence.LOW
        assumptions.append(f"Deep inheritance chain ({inheritance_depth} levels)")
    
    # If we had to infer the sink method, decrement confidence
    if not snk_metavars.get('method') and snk_method:
        if confidence == Confidence.HIGH:
            confidence = Confidence.MEDIUM
        elif confidence == Confidence.MEDIUM:
            confidence = Confidence.LOW
        assumptions.append("Sink method inferred from line number")
    
    # Build resolution description
    resolution_parts = [f"{child_class} inherits from {snk_class}"]
    if snk_method:
        resolution_parts.append(f"sink method: {snk_method}")
    
    # Add confidence indicator to resolution if method is overridden
    if method_overridden and confidence == Confidence.MEDIUM:
        resolution_parts.append("(method overridden - MEDIUM confidence)")
    
    return {
        'strategy': 'Inheritance resolution',
        'source': f"{src_obj or child_class}.{src_method or '?'}",
        'sink': f"{snk_class}.{snk_method or '?'}",
        'confidence': confidence,
        'resolution': '; '.join(resolution_parts),
        'note': '; '.join(assumptions) if assumptions else None
    }


def strategy_class_name_match(
    src_finding: Dict,
    snk_finding: Dict,
    src_metavars: Dict[str, str],
    snk_metavars: Dict[str, str]
) -> Optional[Dict]:
    """
    Strategy 4: Class name match.
    
    Confidence: HIGH
    - Direct class name match
    - No resolution needed
    
    Returns:
        Match dictionary or None
    """
    src_class = src_metavars['class']
    snk_class = snk_metavars['class']
    
    if src_class and snk_class and src_class == snk_class:
        return {
            'strategy': 'Class name match',
            'source': src_class,
            'sink': snk_class,
            'confidence': Confidence.HIGH
        }
    return None


def strategy_constructor_chain(
    src_finding: Dict,
    snk_finding: Dict,
    src_metavars: Dict[str, str],
    snk_metavars: Dict[str, str],
    index: Dict[str, Any]
) -> Optional[Dict]:
    """
    Strategy 5: Constructor chain inference using class index.
    
    Confidence: MEDIUM (decremented due to inference)
    - Infers constructor relationship from method_calls in index
    - Assumes source class constructor creates sink class instance
    - Some uncertainty if nested call not captured in index
    
    Returns:
        Match dictionary or None
    """
    src_class = src_metavars['class']
    snk_class = snk_metavars['class']
    snk_line = snk_finding['start']['line']
    
    if not src_class or not snk_class:
        return None
    
    # Check if source class __init__ calls sink class constructor
    for call_info in index.get('method_calls', []):
        if (call_info.get('caller_class') == src_class and
            call_info.get('caller_method') == '__init__' and
            call_info.get('call', {}).get('type') == 'function_call' and
            call_info.get('call', {}).get('function') == snk_class):
            # Verify sink is __init__ method
            if snk_class in index.get('classes', {}):
                init_method = index['classes'][snk_class].get('methods', {}).get('__init__')
                if init_method and init_method.get('line') == snk_line:
                    return {
                        'strategy': 'Constructor chain inference',
                        'source': f"{src_class}.__init__",
                        'sink': f"{snk_class}.__init__ (line {snk_line})",
                        'confidence': Confidence.MEDIUM,
                        'resolution': f"{src_class}.__init__ creates {snk_class} instance",
                        'note': 'Inferred from method_calls in class index'
                    }
    
    return None

