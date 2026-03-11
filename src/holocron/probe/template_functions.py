"""Utility functions for inserting dynamic content into rule templates."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union

from .template_config import EntityRelationship, InferenceType


PatternEntry = Union[str, Dict[str, Any]]


def _as_pattern_entries(patterns: Sequence[PatternEntry]) -> List[Dict[str, Any]]:
    """Normalize plain strings into Opengrep pattern dictionaries."""

    entries: List[Dict[str, Any]] = []
    for pattern in patterns:
        if isinstance(pattern, dict):
            entries.append(pattern)
        else:
            entries.append({"pattern": pattern})
    return entries


def insert_source_patterns(
    cwe: str, source_types: Sequence[PatternEntry]
) -> List[Dict[str, Any]]:
    """Return pattern-sources entries for forward rules."""

    if not source_types:
        source_types = ["sys.argv[$INDEX]"]
    return _as_pattern_entries(source_types)


def insert_sink_patterns(
    sinks: Sequence[str],
    focus_metavariable: str = "$INPUT",
) -> List[Dict[str, Any]]:
    """Return pattern-sinks entries with focus metavariable.
    
    When multiple sinks are provided, uses pattern-either to group them,
    as Opengrep requires pattern-either for multiple alternatives.
    """

    if not sinks:
        sinks = ["cursor.executescript($SQL)"]
    
    # Remove duplicates while preserving order
    unique_sinks = []
    seen = set()
    for sink in sinks:
        if sink not in seen:
            unique_sinks.append(sink)
            seen.add(sink)
    
    if len(unique_sinks) == 1:
        # Single pattern - no need for pattern-either
        sink_entry = {
            "patterns": [{"pattern": unique_sinks[0]}],
            "focus-metavariable": focus_metavariable,
        }
    else:
        # Multiple patterns - use pattern-either
        # Structure matches example: pattern-either first, then focus-metavariable at same level
        sink_entry = {
            "patterns": [
                {
                    "pattern-either": [{"pattern": sink} for sink in unique_sinks]
                },
            ],
            "focus-metavariable": focus_metavariable,
        }
    return [sink_entry]


def insert_propagators(
    relationship: EntityRelationship,
    inference_type: InferenceType,
) -> List[Dict[str, Any]]:
    """Return propagators tuned for relationship and inference type."""

    base = [
        {
            "pattern": "$SELF.$FIELD = $VALUE",
            "from": "$VALUE",
            "to": "$SELF",
            "by-side-effect": True,
        },
        {"pattern": "$OBJ.$FIELD", "from": "$OBJ", "to": "$RETURN"},
        {"pattern": "$CLASS($INPUT)", "from": "$INPUT", "to": "$RETURN"},
        {"pattern": "$OBJ.$METHOD($INPUT)", "from": "$INPUT", "to": "$RETURN"},
        {
            "pattern": "$OBJ.$ATTR.$METHOD($INPUT)",
            "from": "$INPUT",
            "to": "$RETURN",
        },
    ]

    if relationship == EntityRelationship.INHERITANCE:
        base.append(
            {
                "patterns": [
                    {"pattern": "$CHILD($INPUT)"},
                    {"pattern": "$PARENT.__init__($INPUT)"},
                ],
                "from": "$INPUT",
                "to": "$RETURN",
            }
        )
    elif relationship == EntityRelationship.FUNCTION_CALL:
        base.append({"pattern": "$FUNC(..., $ARG, ...)", "from": "$ARG", "to": "$RETURN"})

    if inference_type == InferenceType.BRIDGE_PASS:
        base.append({"pattern": "$OBJ.$METHOD($INPUT)", "from": "$OBJ", "to": "$INPUT"})

    return base


def insert_boundary_patterns(
    class_name: Optional[str] = None,
    method_name: Optional[str] = None,
    is_forward: bool = True,
    method_params: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Return boundary pattern definitions for forward/backward passes."""

    class_token = class_name or "$CLASS"
    method_token = method_name or "$METHOD"
    method_params = method_params or []

    if is_forward:
        # For forward pass: use pattern-inside to establish class context and bind $CLASS
        # This ensures $CLASS metavariable is available for stitching
        if class_name:
            pattern_inside = f"""class {class_token}:
    ...
    {class_token}($INPUT)
    ..."""
            return [
                {
                    "patterns": [
                        {"pattern-inside": pattern_inside},
                        {"pattern": "$CLASS($INPUT)"},
                    ],
                    "focus-metavariable": "$INPUT",
                },
                {
                    "patterns": [{"pattern": f"$OBJ.{method_token}($INPUT)"}],
                    "focus-metavariable": "$INPUT",
                },
            ]
        # Fallback: use generic pattern if no class name provided
        return [
            {
                "patterns": [{"pattern": "$CLASS($INPUT)"}],
                "focus-metavariable": "$INPUT",
            },
            {
                "patterns": [{"pattern": f"$OBJ.{method_token}($INPUT)"}],
                "focus-metavariable": "$INPUT",
            },
        ]

    # For "backward" pass: use generic patterns matching the example rule structure
    # This matches ANY class/method/function with $INPUT parameter, not just specific ones
    # This ensures we don't regress from the SQLi case and matches the example rule
    # The example rule (python-sink-command-injection.yml) uses these generic patterns:
    return [
        {"pattern": "class $CLASS:\n    def __init__(..., $INPUT,...):\n        ..."},
        {"pattern": "class $CLASS:\n    def $METHOD(..., $INPUT, ...):\n        ..."},
        {"pattern": "class $CLASS:\n    $INPUT\n    ..."},
        {"pattern": "def $FUNC($INPUT, ...):\n    ..."},
        {"pattern": "$INPUT"},
    ]


def insert_metadata(
    cwe: str,
    finding_type: str,
    version: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return metadata block for rule template."""

    metadata: Dict[str, Any] = {
        "finding_type": finding_type,
        "cwe": [cwe],
        "version": version,
        "description": f"Probe-generated {finding_type} rule for {cwe}.",
    }
    if extra:
        metadata.update(extra)
    return metadata


__all__ = [
    "insert_boundary_patterns",
    "insert_metadata",
    "insert_propagators",
    "insert_sink_patterns",
    "insert_source_patterns",
]

