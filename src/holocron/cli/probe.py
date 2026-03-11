"""CLI entry point for the holocron probe command."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from holocron.core.indexer import load_index
from holocron.probe.cwe_patterns import get_cwe_sink_patterns, get_cwe_source_patterns
from holocron.probe.inheritance_analyzer import analyze_inheritance_structures
from holocron.probe.opengrep_runner import run_opengrep, validate_findings
from holocron.probe.rule_generator import (
    generate_backward_rules,
    generate_bridge_rules,
    generate_forward_rules,
    write_rules_to_file,
)
from holocron.probe.stitch_validator import check_insufficient_metadata, validate_stitching


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def main(args) -> None:
    cwe = args.cwe
    if not cwe:
        raise ValueError("--cwe is required")

    sink_inputs = _split_csv(args.sinks or "")
    if not sink_inputs:
        raise ValueError("--sinks must include at least one sink signature")

    timestamp = _timestamp()
    print("Loading class index...")
    index = load_index(args.index)
    source_patterns = get_cwe_source_patterns(cwe, index)
    sink_patterns = get_cwe_sink_patterns(cwe, sink_inputs)
    inheritance_map = analyze_inheritance_structures(index)

    print("Generating forward rules...")
    forward_rules = generate_forward_rules(
        cwe=cwe,
        sinks=sink_patterns,
        index=index,
        source_patterns=source_patterns,
    )

    print("Generating backward rules...")
    backward_rules = generate_backward_rules(
        cwe=cwe,
        sinks=sink_patterns,
        index=index,
    )

    rules_dir = Path(args.rules_dir or "rules/generated")
    rules_dir.mkdir(parents=True, exist_ok=True)

    forward_rules_path = write_rules_to_file(forward_rules, "forwards", cwe, timestamp)
    backward_rules_path = write_rules_to_file(backward_rules, "backwards", cwe, timestamp)

    output_dir = Path(args.output_dir or "outputs/findings")
    output_dir.mkdir(parents=True, exist_ok=True)

    forward_findings = {}
    backward_findings = {}

    if forward_rules_path:
        forward_output = output_dir / f"probe-{cwe}-forward-{timestamp}.json"
        print(f"Running opengrep for forward rules ({forward_rules_path})...")
        forward_findings = run_opengrep(
            str(forward_rules_path),
            args.source_dir,
            str(forward_output),
        )
        print(
            f"Forward findings: {len(forward_findings.get('results', []))} "
            f"(valid={validate_findings(forward_findings, {'finding_type': 'source'})})"
        )

    if backward_rules_path:
        backward_output = output_dir / f"probe-{cwe}-backward-{timestamp}.json"
        print(f"Running opengrep for backward rules ({backward_rules_path})...")
        backward_findings = run_opengrep(
            str(backward_rules_path),
            args.source_dir,
            str(backward_output),
        )
        print(
            f"Backward findings: {len(backward_findings.get('results', []))} "
            f"(valid={validate_findings(backward_findings, {'finding_type': 'sink'})})"
        )

    success, matches = validate_stitching(forward_findings, backward_findings, index)
    print(f"Initial stitching success: {success}, matches={len(matches)}")

    retries = args.max_retries or 0
    bridge_applied = False

    while not success and retries > 0:
        print("No stitched flows detected; attempting inheritance bridge...")
        bridge_rules = generate_bridge_rules(cwe=cwe, index=index, inheritance_map=inheritance_map)
        if not bridge_rules:
            print("No bridge rules generated; stopping retries.")
            break

        forward_rules_path = write_rules_to_file(
            bridge_rules,
            "forwards",
            cwe,
            _timestamp(),
        )

        forward_output = output_dir / f"probe-{cwe}-forward-{timestamp}-bridge.json"
        forward_findings = run_opengrep(
            str(forward_rules_path),
            args.source_dir,
            str(forward_output),
        )
        success, matches = validate_stitching(forward_findings, backward_findings, index)
        bridge_applied = True
        retries -= 1
        print(f"Bridge attempt success: {success}, matches={len(matches)}, retries left={retries}")

        if success:
            break

    if not success and check_insufficient_metadata(matches):
        print("Stitching failed: insufficient metadata after retries.")
    else:
        print(f"Stitching complete. Matches found: {len(matches)}")

    if bridge_applied and not success:
        print("Bridge rules were applied but stitching still failed. Additional modeling may be required.")

