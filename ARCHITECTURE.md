# Architecture

This document describes the actual implemented architecture for stitching OpenGrep findings across file boundaries.

## Overview

OpenGrep (forked from Semgrep OSS) has a limitation: taint analysis is file-scoped. This tooling works around that limitation by:

1. **Indexing** Python source code to build a call graph
2. **Running OpenGrep** with forward (source) and backward (sink) rules
3. **Stitching** findings at intersection boundaries using semantic matching

## System Flow

```
Source Code
    │
    ├──────────────────────────────────┐
    │                                  │
    ▼                                  ▼
┌──────────────┐              ┌──────────────┐
│   Indexer    │              │   OpenGrep   │
│  (AST-based) │              │   (Rules)    │
└──────┬───────┘              └──────┬───────┘
       │                             │
       ▼                             ▼
┌──────────────┐              ┌──────────────┐
│ Class Index  │              │   Findings   │
│   (JSON)     │              │   (JSON)     │
└──────┬───────┘              └──────┬───────┘
       │                             │
       │                             ├─→ Classification
       │                             │   (Source/Sink)
       │                             │
       └───────────┬─────────────────┘
                   │
                   ▼
            ┌──────────────┐
            │   Stitching  │
            │  (Strategies)│
            └──────┬───────┘
                   │
                   ▼
            ┌──────────────┐
            │   Matches    │
            │  (Deduplicated)│
            └──────────────┘
```

## Components

### 1. Indexer (`src/holocron/core/indexer.py`)

AST-based Python indexer that builds a comprehensive class index:

- **Classes**: Name, methods, attributes, inheritance
- **Functions**: Standalone function definitions
- **Method Calls**: Caller → callee relationships with line numbers
- **Inheritance**: Parent-child class relationships

Output: `class_index.json`

### 2. Stitching Strategies (`src/holocron/stitching/strategies.py`)

Six matching strategies to connect source and sink findings:

| Strategy | Description | Confidence |
|----------|-------------|------------|
| 0. Call Graph Propagation | Verify call path exists in method_calls | HIGH/MEDIUM |
| 1. Direct Function Match | Exact function name match | HIGH |
| 2. Attribute Resolution | Resolve `obj.attr` to class | HIGH/MEDIUM |
| 3. Inheritance Resolution | Match via inheritance chain | HIGH/MEDIUM |
| 4. Class Name Match | Direct class name match | HIGH |
| 5. Constructor Chain | Infer from constructor calls | MEDIUM |

### 3. Rule Generation (`src/holocron/probe/rule_generator.py`)

Template-based generation of OpenGrep rules:

- **Forward rules**: Trace from source to callee boundary
- **Backward rules**: Trace from callee boundary to sink
- **Bridge rules**: Handle inheritance boundaries

### 4. CLI (`src/holocron/cli/main.py`)

Commands:
- `holocron index` - Build class index from Python files
- `holocron stitch` - Stitch source and sink findings
- `holocron probe` - Generate rules, run OpenGrep, validate stitching

## The Intersection Boundary Concept

The core insight that makes stitching work:

```
Forward Pass (Source Rule):
  sys.argv[1] → Class2.__init__ → Class1.__init__ → [BOUNDARY] ← STOPS

Backward Pass (Sink Rule):
  [BOUNDARY] → Class1.process → subprocess.run ← STARTS

Intersection:
  Both passes meet at the Class1 boundary
  Stitching matches metavariables: $CLASS, $METHOD, $OBJ
```

## Index Schema

The class index JSON structure is documented in [INDEX_SCHEMA.md](INDEX_SCHEMA.md).

Key fields:
- `classes` - Class definitions with methods and attributes
- `method_calls` - Call graph (PRIMARY for stitching)
- `inheritance` - Inheritance relationships
- `functions` - Standalone functions

## Project Structure

```
src/holocron/
├── core/
│   ├── indexer.py      # AST-based Python indexer
│   ├── resolver.py     # Attribute/inheritance resolution
│   └── types.py        # Match, Confidence types
├── stitching/
│   ├── strategies.py   # 6 matching strategies
│   ├── matcher.py      # Strategy orchestration
│   ├── batch.py        # Deduplication + parallel processing
│   └── stitcher.py     # Entry point
├── probe/
│   ├── rule_generator.py    # Forward/backward/bridge rules
│   ├── template_loader.py   # Jinja2 rendering
│   ├── template_functions.py
│   └── opengrep_runner.py   # OpenGrep execution
├── utils/
│   ├── parsers.py      # Metavariable extraction
│   ├── discovery.py    # Finding auto-discovery
│   └── finding_classifier.py
└── cli/
    ├── main.py         # CLI entry point
    ├── index.py        # index command
    ├── stitch_findings.py  # stitch command
    └── probe.py        # probe command
```
