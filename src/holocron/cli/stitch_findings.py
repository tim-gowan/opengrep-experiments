"""CLI entry point for stitching findings."""

import json
from pathlib import Path
from holocron.stitching.batch import stitch_batch
from holocron.stitching.stitcher import print_stitching_results


def main(args):
    """Main entry point for holocron stitch command.
    
    Args:
        args: Parsed argparse arguments
    """
    matches = stitch_batch(
        findings_dir=args.findings_dir,
        index_file=args.index,
        parallel=args.parallel,
        max_workers=getattr(args, 'max_workers', None)
    )
    
    # Load findings for verbose output
    source_findings = []
    sink_findings = []
    try:
        source_file = Path(args.findings_dir) / 'output-source.json'
        sink_file = Path(args.findings_dir) / 'output-sink.json'
        
        if source_file.exists():
            with open(source_file, 'r') as f:
                source_data = json.load(f)
                source_findings = source_data.get('results', [])
        
        if sink_file.exists():
            with open(sink_file, 'r') as f:
                sink_data = json.load(f)
                sink_findings = sink_data.get('results', [])
    except Exception:
        pass  # If we can't load findings, just proceed without them
    
    print_stitching_results(matches, source_findings, sink_findings)
    
    if args.output:
        # Save results
        output_data = [match.to_dict() for match in matches]
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n✅ Results saved to {args.output}")

