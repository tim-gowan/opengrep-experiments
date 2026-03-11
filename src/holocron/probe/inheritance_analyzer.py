"""Helpers for analyzing inheritance structures from the class index."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


def analyze_inheritance_structures(index: Dict[str, Any]) -> Dict[str, List[str]]:
    """Return mapping of child class -> list[parent classes]."""

    inheritance_section = index.get("inheritance", {})
    classes_section = index.get("classes", {})

    mapping: Dict[str, List[str]] = {}
    for class_name, info in inheritance_section.items():
        parents = info.get("parents") or classes_section.get(class_name, {}).get(
            "parent_classes", []
        )
        mapping[class_name] = list(parents or [])
    return mapping


def extract_class_hierarchy(
    index: Dict[str, Any],
    class_name: str,
    include_self: bool = True,
) -> List[str]:
    """Return hierarchy chain for a class (child -> ancestors)."""

    inheritance_map = analyze_inheritance_structures(index)

    def _walk(name: str, seen: Set[str]) -> List[str]:
        if name in seen:
            return []
        seen.add(name)
        parents = inheritance_map.get(name, [])
        chain: List[str] = []
        for parent in parents:
            chain.append(parent)
            chain.extend(_walk(parent, seen))
        return chain

    chain = _walk(class_name, set())
    if include_self:
        return [class_name, *chain]
    return chain


def _class_file_info(
    classes_section: Dict[str, Any],
    class_name: str,
) -> Dict[str, Optional[Any]]:
    """Extract file metadata for a class safely."""

    info = classes_section.get(class_name, {})
    return {
        "file": info.get("file_relative") or info.get("file"),
        "line": info.get("line"),
        "methods": info.get("methods", {}),
    }


def identify_bridge_points(
    index: Dict[str, Any],
    inheritance_map: Optional[Dict[str, List[str]]] = None,
) -> List[Dict[str, Any]]:
    """Identify inheritance relationships that need bridging rules."""

    inheritance_map = inheritance_map or analyze_inheritance_structures(index)
    classes_section = index.get("classes", {})
    inheritance_section = index.get("inheritance", {})

    bridge_points: List[Dict[str, Any]] = []

    for child_class, parents in inheritance_map.items():
        if not parents:
            continue

        child_meta = inheritance_section.get(child_class, {})
        child_file_info = _class_file_info(classes_section, child_class)
        nested_in = child_meta.get("nested_in") or classes_section.get(child_class, {}).get(
            "nested_in"
        )

        for parent_class in parents:
            parent_file_info = _class_file_info(classes_section, parent_class)
            bridge_points.append(
                {
                    "relationship": "inheritance",
                    "child_class": child_class,
                    "parent_class": parent_class,
                    "child_file": child_file_info["file"],
                    "parent_file": parent_file_info["file"],
                    "child_line": child_file_info["line"],
                    "parent_line": parent_file_info["line"],
                    "nested_in": nested_in,
                    "needs_bridge": True,
                }
            )

    return bridge_points


__all__ = [
    "analyze_inheritance_structures",
    "identify_bridge_points",
    "extract_class_hierarchy",
]

