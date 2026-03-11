"""Template loading and rendering helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml
from yaml.representer import SafeRepresenter


class MultilineDumper(yaml.SafeDumper):
    """Custom YAML dumper that uses pipe syntax for multi-line strings."""

    def represent_str(self, data):
        """Represent strings, using pipe syntax for multi-line strings."""
        if "\n" in data:
            return self.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        return SafeRepresenter.represent_str(self, data)


MultilineDumper.add_representer(str, MultilineDumper.represent_str)

TEMPLATE_DIR = Path(__file__).resolve().parents[3] / "rules" / "templates"
BLOCK_KEYS = {
    "OPTIONS",
    "PATTERN_SOURCES",
    "PATTERN_PROPAGATORS",
    "BOUNDARY_SINKS",
    "BOUNDARY_SOURCES",
    "SINK_PATTERNS",
    "BRIDGE_SOURCES",
    "BRIDGE_SINKS",
    "METADATA",
}


def _format_block(value: Any, indent: int = 6) -> str:
    """Render dictionaries/lists as readable YAML using PyYAML."""

    if value is None:
        return " " * indent + "null"
    elif isinstance(value, str):
        return " " * indent + value
    else:
        # Use PyYAML with custom dumper for multi-line strings
        yaml_str = yaml.dump(
            value,
            Dumper=MultilineDumper,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=1000,  # Don't wrap long lines
        )
        # Indent all lines
        lines = yaml_str.splitlines()
        indented = "\n".join(" " * indent + line if line.strip() else line for line in lines)
        return indented.rstrip()




def load_base_template(template_name: str) -> str:
    """Return template contents as a string."""

    template_path = TEMPLATE_DIR / f"{template_name}.yml.template"
    if not template_path.exists():
        raise FileNotFoundError(f"Template '{template_name}' not found at {template_path}")
    return template_path.read_text(encoding="utf-8")


def render_template(template_name: str, context: Dict[str, Any]) -> str:
    """Load template and render with provided context."""

    template = load_base_template(template_name)
    prepared_context: Dict[str, Any] = {}

    for key, value in context.items():
        if key in BLOCK_KEYS:
            prepared_context[key] = _format_block(value)
        else:
            prepared_context[key] = value

    return template.format(**prepared_context)


__all__ = ["load_base_template", "render_template"]

