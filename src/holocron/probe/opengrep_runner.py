"""Adapters for running Opengrep and validating findings."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

OPENGREP_BIN = os.environ.get("ENDOR_SCAN_OPENGREP_PATH", "opengrep")


def run_opengrep(
    rules_file: str,
    source_dir: str,
    output_file: str,
) -> Dict[str, Any]:
    """Execute Opengrep with provided rule file and return parsed findings."""

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        OPENGREP_BIN,
        "--config",
        rules_file,
        "--json",
        "--output",
        str(output_path),
        source_dir,
    ]

    subprocess.run(cmd, check=True)
    return json.loads(output_path.read_text(encoding="utf-8"))


def validate_findings(
    findings: Dict[str, Any],
    expected_metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    """Basic validation to ensure findings contain expected metadata."""

    results = findings.get("results", [])
    if not results:
        return False

    expected_metadata = expected_metadata or {}
    expected_type = expected_metadata.get("finding_type")

    for result in results:
        metadata = result.get("metadata", {})
        if expected_type and metadata.get("finding_type") != expected_type:
            return False
        if not result.get("path") or not result.get("start"):
            return False

    return True


__all__ = ["run_opengrep", "validate_findings"]

