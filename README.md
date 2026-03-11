# OpenGrep Experiments

Experimental tooling to work around OpenGrep's file-scoped taint analysis limitation by stitching findings at intersection boundaries.

## How It Works

OpenGrep (forked from Semgrep OSS) performs taint analysis within a single file. This tooling extends that by:

1. **Indexing** your Python codebase to build a call graph
2. **Running OpenGrep** with forward (source→boundary) and backward (boundary→sink) rules
3. **Stitching** findings where they meet at class/method boundaries

```
Forward Pass:  sys.argv → Class2 → [Class1 boundary] ← STOPS
Backward Pass: [Class1 boundary] → Class1.method → sink ← STARTS
                        ↑
                   Intersection
```

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd opengrep-experiments

# Install with Poetry
poetry install

# Activate virtual environment
poetry shell
```

## Usage

### Build Class Index

Build a call graph index from Python source files:

```bash
holocron index --source-dir src/benchmark
holocron index --source-dir /path/to/your/code --output outputs/indices/class_index.json
```

### Stitch Findings

Connect source and sink findings into complete taint flows:

```bash
holocron stitch --findings-dir outputs/findings --index outputs/indices/class_index.json
```

### Generate Rules and Probe

Generate rules, run OpenGrep, and validate stitching:

```bash
holocron probe --cwe CWE-89 --sinks "cursor.execute,cursor.executescript" --source-dir src/benchmark
```

## Project Structure

```
src/holocron/
├── core/           # Indexer, resolver, types
├── stitching/      # 6 matching strategies
├── probe/          # Rule generation, OpenGrep runner
├── utils/          # Parsers, discovery
└── cli/            # Command-line interface

rules/
├── sources/        # Forward pass rules
├── sinks/          # Backward pass rules
└── templates/      # Jinja2 rule templates

tools/
└── semantic-cluster-analysis.py  # SARIF hotspot analysis utility
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - System design and components
- [INDEX_SCHEMA.md](INDEX_SCHEMA.md) - Class index JSON structure
- [AGENTS.md](AGENTS.md) - Development guidance and commands

## Stitching Strategies

The system uses 6 matching strategies to connect findings:

| # | Strategy | Description |
|---|----------|-------------|
| 0 | Call Graph Propagation | Verify call path in method_calls index |
| 1 | Direct Function Match | Exact function name match |
| 2 | Attribute Resolution | Resolve `obj.attr` to class |
| 3 | Inheritance Resolution | Match via inheritance chain |
| 4 | Class Name Match | Direct class name match |
| 5 | Constructor Chain | Infer from constructor calls |

Each match includes a confidence level (HIGH, MEDIUM, LOW).

## License

See [LICENSE](LICENSE)
