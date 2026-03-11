"""CWE-specific source and sink pattern helpers."""

from __future__ import annotations

from typing import Dict, List, Sequence, Any

DEFAULT_SOURCES: Dict[str, List[Any]] = {
    "CWE-89": [
        "request.args.get(..., default=None)",
        "request.form.get(..., default=None)",
        "sys.argv[$INDEX]",
        "input(...)",
    ],
    "CWE-78": [
        "sys.argv[$INDEX]",
        "input(...)",
        "request.args.get(..., default=None)",
        "request.form.get(..., default=None)",
    ]
}

DEFAULT_SINKS: Dict[str, List[str]] = {
    "CWE-89": [
        "cursor.execute($INPUT)",
        "cursor.executemany($INPUT)",
        "cursor.executescript($INPUT)",
        "connection.execute($INPUT)",
    ],
    "CWE-78": [
        "subprocess.run($CMD, ...)",
        "subprocess.Popen($CMD, ...)",
        "os.system($CMD)",
        "os.popen($CMD, ...)",
    ]
}


def _flask_route_pattern() -> Dict[str, Any]:
    return {
        "patterns": [
            {
                "pattern-inside": """@$APP.route(...)
def $FUNC(..., $ROUTEVAR, ...):
    ..."""
            },
            {"pattern": "$ROUTEVAR"},
        ]
    }


def _flask_request_pattern() -> Dict[str, Any]:
    return {
        "patterns": [
            {
                "pattern-either": [
                    {"pattern": "flask.request.form.get(...)"},
                    {"pattern": "flask.request.form[...]"},
                    {"pattern": "flask.request.args.get(...)"},
                    {"pattern": "flask.request.args[...]"},
                    {"pattern": "flask.request.values.get(...)"},
                    {"pattern": "flask.request.values[...]"},
                    {"pattern": "flask.request.cookies.get(...)"},
                    {"pattern": "flask.request.cookies[...]"},
                    {"pattern": "flask.request.headers.get(...)"},
                    {"pattern": "flask.request.headers[...]"},
                    {"pattern": "flask.request.data"},
                    {"pattern": "flask.request.json"},
                    {"pattern": "flask.request.get_json()"},
                ]
            }
        ]
    }


def get_cwe_source_patterns(cwe: str, index: Dict[str, Any]) -> List[Any]:
    """Return default source patterns for a given CWE."""

    patterns = list(DEFAULT_SOURCES.get(cwe, []))
    imports = index.get("imports", {})
    flask_imports = imports.get("flask", [])
    if flask_imports:
        patterns.append(_flask_request_pattern())
        patterns.append(_flask_route_pattern())
    return patterns


def get_cwe_sink_patterns(cwe: str, user_sinks: Sequence[str]) -> List[str]:
    """Merge default and user-provided sink patterns.
    
    Uses appropriate metavariable based on CWE:
    - CWE-78 (command injection): $CMD
    - Others: $INPUT
    
    Deduplicates by function name to avoid duplicate patterns.
    """

    # Determine metavariable based on CWE
    metavariable = "$CMD" if cwe == "CWE-78" else "$INPUT"
    
    # Start with defaults
    patterns = list(DEFAULT_SINKS.get(cwe, []))
    
    # Track function names we've already seen (from defaults)
    seen_functions = set()
    for pattern in patterns:
        # Extract function name (e.g., "subprocess.run" from "subprocess.run($CMD, ...)")
        func_name = pattern.split("(")[0].strip()
        seen_functions.add(func_name)
    
    # Add user-provided sinks, avoiding duplicates
    for sink in user_sinks:
        sink = sink.strip()
        if not sink:
            continue
        
        # Extract function name
        if "(" in sink:
            func_name = sink.split("(")[0].strip()
            # Normalize metavariable if needed
            if "$INPUT" in sink and metavariable == "$CMD":
                sink = sink.replace("$INPUT", "$CMD")
            elif "$CMD" in sink and metavariable == "$INPUT":
                sink = sink.replace("$CMD", "$INPUT")
        else:
            func_name = sink
            sink = f"{sink}({metavariable}, ...)"
        
        # Only add if we haven't seen this function name
        if func_name not in seen_functions:
            patterns.append(sink)
            seen_functions.add(func_name)
    
    return patterns


__all__ = ["get_cwe_sink_patterns", "get_cwe_source_patterns"]

