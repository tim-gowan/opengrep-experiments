"""Unified CLI entry point for Holocron."""

import argparse
from holocron.cli import index, probe, stitch_findings


def main():
    """Main entry point for holocron command."""
    parser = argparse.ArgumentParser(
        prog='holocron',
        description='Holocron - Neuro-Symbolic Taint Analysis Platform',
        epilog='Use "holocron <command> --help" for command-specific help.'
    )
    
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        required=True
    )
    
    # index subcommand
    index_parser = subparsers.add_parser(
        'index',
        help='Build class index from Python files',
        description='Build a comprehensive class index from Python source files using AST analysis.'
    )
    index_parser.add_argument(
        '--source-dir',
        default='src/benchmark',
        help='Source directory containing Python files (default: src/benchmark)'
    )
    index_parser.add_argument(
        '--output',
        default='outputs/indices/class_index.json',
        help='Output file path for the index JSON (default: outputs/indices/class_index.json)'
    )
    index_parser.add_argument(
        '--repo-id',
        default=None,
        help='Repository identifier for cross-repo tracking'
    )
    index_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print detailed tree view of indexed structure (Repo > File > [Class > method | function])'
    )
    index_parser.set_defaults(func=index.main)
    
    # stitch subcommand
    stitch_parser = subparsers.add_parser(
        'stitch',
        help='Stitch source and sink findings together',
        description='Stitch findings from forward pass (source rules) and backward pass (sink rules) into complete taint flows. Auto-discovers all findings from a single directory.'
    )
    stitch_parser.add_argument(
        '--findings-dir',
        default='outputs/findings',
        help='Directory containing all finding JSON files (default: outputs/findings). Findings are auto-classified as source/sink based on metadata.'
    )
    stitch_parser.add_argument(
        '--index',
        default='outputs/indices/class_index.json',
        help='Class index JSON file (default: outputs/indices/class_index.json)'
    )
    stitch_parser.add_argument(
        '--output',
        help='Output file for stitched results (JSON)'
    )
    stitch_parser.add_argument(
        '--parallel',
        action='store_true',
        default=True,
        help='Use parallel processing (default: True)'
    )
    stitch_parser.add_argument(
        '--no-parallel',
        dest='parallel',
        action='store_false',
        help='Disable parallel processing'
    )
    stitch_parser.add_argument(
        '--max-workers',
        type=int,
        help='Maximum number of worker threads for parallel processing (default: auto-detect)'
    )
    stitch_parser.set_defaults(func=stitch_findings.main)
    
    # probe subcommand
    probe_parser = subparsers.add_parser(
        'probe',
        help='Generate rules, run opengrep, and validate stitching',
        description='Analyze the index, generate CWE-scoped rules, execute opengrep, and validate stitching with retries.'
    )
    probe_parser.add_argument(
        '--cwe',
        required=True,
        help='CWE identifier (e.g., CWE-89)'
    )
    probe_parser.add_argument(
        '--sinks',
        required=True,
        help='Comma-separated sink signatures (e.g., cursor.execute,cursor.executescript)'
    )
    probe_parser.add_argument(
        '--source-dir',
        default='src/benchmark',
        help='Source directory to scan with opengrep (default: src/benchmark)'
    )
    probe_parser.add_argument(
        '--index',
        default='outputs/indices/class_index.json',
        help='Class index JSON file (default: outputs/indices/class_index.json)'
    )
    probe_parser.add_argument(
        '--rules-dir',
        default='rules/generated',
        help='Directory to store generated rules (default: rules/generated)'
    )
    probe_parser.add_argument(
        '--output-dir',
        default='outputs/findings',
        help='Directory for opengrep findings output (default: outputs/findings)'
    )
    probe_parser.add_argument(
        '--max-retries',
        type=int,
        default=1,
        help='Maximum retries for stitching with bridge rules (default: 1)'
    )
    probe_parser.set_defaults(func=probe.main)
    
    # Parse arguments and call appropriate function
    args = parser.parse_args()
    args.func(args)

