"""Generate forward, backward, and bridge rules from templates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from .inheritance_analyzer import identify_bridge_points
from .template_config import (
    EntityRelationship,
    InferenceType,
    TemplateConfig,
    default_backward_config,
    default_forward_config,
)
from .template_functions import (
    insert_boundary_patterns,
    insert_metadata,
    insert_propagators,
    insert_sink_patterns,
    insert_source_patterns,
)
from .template_loader import render_template


@dataclass
class GeneratedRule:
    """Container for rendered rule content."""

    rule_id: str
    template_name: str
    pass_type: str
    content: str
    metadata: Dict[str, Any]


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sanitize_identifier(value: str) -> str:
    return value.lower().replace(".", "-").replace(" ", "-")


def _collect_sink_targets(index: Dict[str, Any], sinks: Sequence[str]) -> List[Dict[str, Any]]:
    """Return method call entries matching the provided sink list."""

    sink_set: Set[str] = {
        sink.strip().split("(")[0] for sink in sinks if sink.strip()
    }
    if not sink_set:
        return []

    targets = []
    for call_entry in index.get("method_calls", []):
        call = call_entry.get("call", {})
        full_name = call.get("full")
        if full_name and full_name in sink_set:
            targets.append(call_entry)
    return targets


def _prepare_context(
    config: TemplateConfig,
    rule_id: str,
    pattern_sources: List[Dict[str, Any]],
    pattern_sources_key: str,
    propagators: List[Dict[str, Any]],
    boundary_section_key: str,
    boundary_patterns: List[Dict[str, Any]],
    sink_patterns: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Assemble template context dictionary."""

    context: Dict[str, Any] = {
        "RULE_ID": rule_id,
        "MESSAGE": config.message,
        "SEVERITY": config.severity,
        "LANGUAGES": config.languages,
        "MODE": config.mode,
        "OPTIONS": config.options,
        pattern_sources_key: pattern_sources,
        "PATTERN_PROPAGATORS": propagators,
        boundary_section_key: boundary_patterns,
        "METADATA": config.build_metadata(),
    }
    if sink_patterns is not None:
        context["SINK_PATTERNS"] = sink_patterns
    return context


def generate_forward_rules(
    cwe: str,
    sinks: Sequence[str],
    index: Dict[str, Any],
    source_patterns: Optional[Sequence[str]] = None,
) -> List[GeneratedRule]:
    """Generate forward-pass rules for classes that eventually reach sinks."""

    sink_targets = _collect_sink_targets(index, sinks)
    # Get classes that directly contain sinks
    sink_classes = {
        target.get("caller_class") for target in sink_targets if target.get("caller_class")
    }
    
    # Also get classes that call the sink-containing classes (caller classes)
    # This captures flows like: BenchmarkTest00004 -> BenchmarkTest00003 (which has sink)
    caller_classes = set()
    for call_entry in index.get("method_calls", []):
        callee = call_entry.get("callee", {})
        callee_class = callee.get("class")
        if callee_class and callee_class in sink_classes:
            caller_class = call_entry.get("caller_class")
            if caller_class:
                caller_classes.add(caller_class)
    
    # Combine both sets
    target_classes = sorted(sink_classes | caller_classes)
    if not target_classes:
        return []

    config = default_forward_config(
        cwe=cwe,
        rule_id_prefix=f"python-{_sanitize_identifier(cwe)}",
        message=f"Taint reaches boundary before {cwe} sink",
    )

    pattern_sources = insert_source_patterns(cwe, list(source_patterns or []))
    propagators = insert_propagators(EntityRelationship.METHOD_CALL, InferenceType.FORWARD_PASS)
    metadata = insert_metadata(cwe, "source", version=_timestamp())

    rules: List[GeneratedRule] = []

    for class_name in target_classes:
        boundary_patterns = insert_boundary_patterns(class_name=class_name, is_forward=True)
        rule_id = config.create_rule_id(f"{_sanitize_identifier(class_name)}-forward")
        context = _prepare_context(
            config=config,
            rule_id=rule_id,
            pattern_sources=pattern_sources,
            pattern_sources_key="PATTERN_SOURCES",
            propagators=propagators,
            boundary_section_key="BOUNDARY_SINKS",
            boundary_patterns=boundary_patterns,
        )
        context["METADATA"] = metadata
        rendered = render_template("base_forward", context)
        rules.append(
            GeneratedRule(
                rule_id=rule_id,
                template_name="base_forward",
                pass_type="forwards",
                content=rendered,
                metadata=metadata,
            )
        )

    return rules


def generate_backward_rules(
    cwe: str,
    sinks: Sequence[str],
    index: Dict[str, Any],
) -> List[GeneratedRule]:
    """Generate backward-pass rules that start at sink definitions.
    
    Creates a single generic rule matching the example structure (python-sink-command-injection.yml),
    rather than class-specific rules. This ensures no regressions and matches the example granularity.
    """

    sink_targets = _collect_sink_targets(index, sinks)
    if not sink_targets:
        return []

    config = default_backward_config(
        cwe=cwe,
        rule_id_prefix=f"python-{_sanitize_identifier(cwe)}",
        message=f"Taint from {cwe} sink back to boundary",
    )

    propagators = insert_propagators(EntityRelationship.METHOD_CALL, InferenceType.BACKWARD_PASS)
    
    # Determine correct focus metavariable based on CWE
    # CWE-78 (command injection) uses $CMD, others use $INPUT
    focus_metavariable = "$CMD" if cwe == "CWE-78" else "$INPUT"
    sink_pattern_block = insert_sink_patterns(sinks, focus_metavariable=focus_metavariable)
    metadata = insert_metadata(cwe, "sink", version=_timestamp())

    # Generate a single generic backward rule (like the example)
    # This matches ANY class/method/function, not specific ones
    rule_id = config.create_rule_id("sink-taint-backward")
    
    # Use generic boundary patterns (matches example rule structure)
    boundary_sources = insert_boundary_patterns(
        class_name=None,  # Generic, not class-specific
        method_name=None,  # Generic, not method-specific
        is_forward=False,
        method_params=None,
    )
    
    context = _prepare_context(
        config=config,
        rule_id=rule_id,
        pattern_sources=boundary_sources,
        pattern_sources_key="BOUNDARY_SOURCES",
        propagators=propagators,
        boundary_section_key="SINK_PATTERNS",
        boundary_patterns=sink_pattern_block,
    )
    context["METADATA"] = metadata
    rendered = render_template("base_backward", context)
    
    return [
        GeneratedRule(
            rule_id=rule_id,
            template_name="base_backward",
            pass_type="backwards",
            content=rendered,
            metadata=metadata,
        )
    ]


def generate_bridge_rules(
    cwe: str,
    index: Dict[str, Any],
    inheritance_map: Optional[Dict[str, List[str]]] = None,
) -> List[GeneratedRule]:
    """Generate inheritance bridge rules to continue flows."""

    bridge_points = identify_bridge_points(index, inheritance_map)
    if not bridge_points:
        return []

    config = TemplateConfig(
        cwe=cwe,
        finding_type="source",
        rule_id_prefix=f"python-{_sanitize_identifier(cwe)}-bridge",
        message="Bridge inheritance boundary for taint flow",
        severity="INFO",
    )
    propagators = insert_propagators(EntityRelationship.INHERITANCE, InferenceType.BRIDGE_PASS)
    metadata = insert_metadata(cwe, "source", version=_timestamp(), extra={"bridge": True})

    generated: List[GeneratedRule] = []
    for point in bridge_points:
        child_class = point["child_class"]
        parent_class = point["parent_class"]
        rule_id = config.create_rule_id(
            f"{_sanitize_identifier(parent_class)}-to-{_sanitize_identifier(child_class)}"
        )

        source_patterns = insert_boundary_patterns(
            class_name=child_class,
            is_forward=True,
        )
        sink_patterns = insert_boundary_patterns(
            class_name=parent_class,
            method_name=None,
            is_forward=False,
        )

        context = {
            "RULE_ID": rule_id,
            "MESSAGE": config.message,
            "SEVERITY": config.severity,
            "LANGUAGES": config.languages,
            "MODE": config.mode,
            "OPTIONS": config.options,
            "BRIDGE_SOURCES": source_patterns,
            "BRIDGE_SINKS": sink_patterns,
            "PATTERN_PROPAGATORS": propagators,
            "METADATA": metadata,
            "PARENT_CLASS": parent_class,
            "CHILD_CLASS": child_class,
        }

        rendered = render_template("inheritance_bridge", context)
        generated.append(
            GeneratedRule(
                rule_id=rule_id,
                template_name="inheritance_bridge",
                pass_type="forwards",
                content=rendered,
                metadata=metadata,
            )
        )

    return generated


def write_rules_to_file(
    rules: Sequence[GeneratedRule],
    pass_type: str,
    cwe: str,
    timestamp: Optional[str] = None,
) -> Optional[Path]:
    """Write generated rule contents to disk."""

    if not rules:
        return None

    timestamp = timestamp or _timestamp()
    output_dir = Path("rules") / "generated" / pass_type
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"python-{_sanitize_identifier(cwe)}-{pass_type}-{timestamp}.yml"

    # Parse each rule's YAML content and extract rule items
    import yaml
    all_rules = []
    comments = ""
    
    for rule in rules:
        try:
            # Parse the YAML content
            parsed = yaml.safe_load(rule.content)
            if parsed and "rules" in parsed:
                all_rules.extend(parsed["rules"])
        except Exception:
            # Fallback: try regex extraction
            import re
            match = re.search(r'^\s*-\s+id:', rule.content, re.MULTILINE)
            if match:
                # Extract from this match to end of rule block
                rule_text = rule.content[match.start():]
                # Try to parse just this rule
                try:
                    parsed = yaml.safe_load(f"rules:\n{rule_text}")
                    if parsed and "rules" in parsed:
                        all_rules.extend(parsed["rules"])
                except Exception:
                    pass
    
    # Get comments from first rule
    if rules:
        first_rule = rules[0].content
        comment_lines = [line for line in first_rule.split("\n") if line.strip().startswith("#")]
        comments = "\n".join(comment_lines) + "\n" if comment_lines else ""
    
    # Write combined rules
    if all_rules:
        combined = {"rules": all_rules}
        yaml_content = yaml.dump(combined, sort_keys=False, default_flow_style=False, allow_unicode=True)
        new_content = f"{comments}{yaml_content}"
    else:
        # Fallback: concatenate as-is
        snippets = "\n".join(rule.content.strip("\n") for rule in rules)
        new_content = f"{snippets}\n"

    output_path.write_text(new_content, encoding="utf-8")
    return output_path


__all__ = [
    "GeneratedRule",
    "generate_forward_rules",
    "generate_backward_rules",
    "generate_bridge_rules",
    "write_rules_to_file",
]

