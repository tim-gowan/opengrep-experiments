# Stitching Strategies Architecture

## Overview

The stitching system connects source findings (forward pass) with sink findings (backward pass) to create complete taint flows. It uses a multi-strategy approach where strategies are tried in order of confidence, returning the first successful match.

## Architecture

### Core Components

1. **`matcher.py`** - Orchestrates strategy execution
   - Extracts metavariables from findings
   - Tries strategies in confidence order (HIGH → MEDIUM)
   - Converts match dictionaries to `Match` objects

2. **`strategies.py`** - Individual matching strategies
   - Each strategy is a function that returns a match dictionary or `None`
   - Strategies use the class index to resolve method/class relationships
   - Confidence levels assigned based on resolution quality

3. **`batch.py`** - Batch processing and deduplication
   - Processes all source-sink pairs
   - Deduplicates by actual taint flow (source origin + sink location)
   - Keeps best match per unique flow

4. **`stitcher.py`** - Output formatting
   - Formats matches for verbose display
   - Shows forward/backward pass traces
   - Explains confidence levels and assumptions

## Strategy Execution Order

Strategies are tried in this order (first match wins):

1. **Call Graph Propagation** (PRIMARY) - HIGH/MEDIUM
2. **Direct Function Match** - HIGH
3. **Attribute Resolution** - HIGH/MEDIUM
4. **Inheritance Resolution** - HIGH/MEDIUM/LOW
5. **Class Name Match** - HIGH
6. **Constructor Chain** - MEDIUM

## Strategy Details

### Strategy 0: Call Graph Propagation (PRIMARY)

**Purpose**: Match metavariables to indexed methods, verify call path exists.

**Process**:
1. Extract source method ID from metavars (`$CLASS`, `$METHOD`, `$OBJ`, `$FUNC`)
2. Extract sink method ID from metavars
3. Verify both methods exist in index
4. Find call path in `method_calls` using BFS
5. Assign confidence based on path length and resolution quality

**Confidence**:
- **HIGH**: Same method, or 1-hop path with direct resolution
- **MEDIUM**: 2-3 hop path, or requires some resolution
- **LOW**: >3 hops or unverified path

**Key Functions**:
- `_extract_indexed_method_id()` - Resolves metavars to method IDs
- `_find_call_path_in_index()` - BFS path finding in call graph
- `_build_call_graph()` - Builds graph from `method_calls`
- `_resolve_callee_from_call()` - Resolves call types to method IDs

**Resolution Types**:
- `function_call` → `ClassName.__init__`
- `method_call` → `ClassName.method` (self.method or obj.method)
- `nested_method_call` → `ClassName.method` (self.attr.method)

### Strategy 1: Direct Function Match

**Purpose**: Match when function names are identical.

**Process**:
- Compares `$FUNC` from source and sink
- Or `$CLASS` from source matches `$FUNC` from sink

**Confidence**: HIGH (exact match, no resolution needed)

### Strategy 2: Attribute Resolution

**Purpose**: Resolve `obj.method` to class using index attributes.

**Process**:
1. Extract `$OBJ` and `$METHOD` from source
2. Resolve `obj` to class using `resolve_attribute_with_index()`
3. Match resolved class to sink `$CLASS`
4. Match method names

**Confidence**:
- **HIGH**: Full resolution successful, class and method match
- **MEDIUM**: Method name matches but resolution uncertain

**Key Functions**:
- `resolve_attribute_with_index()` - Resolves attribute paths to classes
- `_resolve_obj_to_class_for_method()` - Handles nested paths

### Strategy 3: Inheritance Resolution

**Purpose**: Match when source class inherits from sink class.

**Process**:
1. Extract child class from source (`$CLASS` or `$METHOD` if nested class)
2. Verify child inherits from sink class using index
3. Infer sink method if not provided (from line number)
4. Check if method is overridden in child
5. If overridden, verify call graph path exists (reject if not)

**Confidence**:
- **HIGH**: Method not overridden, inheritance verified
- **MEDIUM**: Method overridden but call graph path exists
- **LOW**: Deep inheritance (>2 levels) or method inferred

**Key Functions**:
- `resolve_inheritance_with_index()` - Gets inheritance chain
- `_is_method_overridden()` - Checks if method overridden in child
- `_find_call_path_in_index()` - Verifies path for overridden methods

**Rejection Logic**: If method is overridden and no call graph path exists, reject match (prevents FPs where overridden method doesn't call parent).

### Strategy 4: Class Name Match

**Purpose**: Direct class name match when both have `$CLASS`.

**Process**:
- Compares `$CLASS` from source and sink

**Confidence**: HIGH (exact match)

### Strategy 5: Constructor Chain

**Purpose**: Infer constructor relationships when explicit calls missing.

**Process**:
1. Extract class names from metavars
2. Check if source class constructor calls sink class constructor
3. Verify via `method_calls` or line proximity

**Confidence**: MEDIUM (requires inference)

## Method ID Extraction

The `_extract_indexed_method_id()` function resolves Opengrep metavariables to method identifiers that match the index structure.

**Supported Patterns**:
1. **Function**: `$FUNC` → `"function_name"` or `"repo-id:function_name"`
2. **Class Method**: `$CLASS` + `$METHOD` → `"ClassName.method"` or `"repo-id:ClassName.method"`
3. **Object Method**: `$OBJ` + `$METHOD` → Resolve obj to class, then `"ClassName.method"`

**Inference Logic**:
- If `$METHOD` missing, infer from line number
- If constructor call, infer `__init__` from `method_calls` or class structure
- Handle nested paths like `manager.processor` → resolve to class type

**Method ID Format**:
- Flat: `"ClassName.method"`
- Repo-scoped: `"repo-id:ClassName.method"`

## Call Graph Building

The call graph is built from `index['method_calls']` which contains:
- `caller_class`, `caller_method` - Who is calling
- `call` - Call information (type, function/method name, path)
- `callee` - Resolved callee (if `callee_resolved: true`)

**Call Types**:
- `function_call`: `ClassName()` → `ClassName.__init__`
- `method_call`: `self.method()` or `obj.method()` → `ClassName.method`
- `nested_method_call`: `self.attr.method()` → Resolve attr to class, then `ClassName.method`

**Path Finding**: Uses BFS to find shortest path from source method to sink method.

## Confidence Assignment

Confidence is determined by:
1. **Resolution Quality**: Direct match (HIGH) vs inference (MEDIUM/LOW)
2. **Path Length**: 0-1 hops (HIGH), 2-3 hops (MEDIUM), >3 hops (LOW)
3. **Override Status**: Method overridden (MEDIUM) vs not overridden (HIGH)
4. **Inference Required**: Method inferred from line (MEDIUM) vs explicit (HIGH)

## Match Dictionary Structure

Each strategy returns a dictionary with these fields:

**Required Fields**:
- `strategy`: Strategy name (e.g., "Call graph propagation")
- `source`: Source identifier (method ID, class name, etc.)
- `sink`: Sink identifier (method ID, class name, etc.)
- `confidence`: Confidence level (`Confidence.HIGH`, `MEDIUM`, or `LOW`)

**Optional Fields**:
- `resolution`: Human-readable explanation of the match path
- `note`: Additional assumptions or limitations
- `path`: List of method IDs in call path (for call graph strategy)
- `hops`: Number of hops in path (for call graph strategy)

## Extending Strategies

### Adding a New Strategy

1. **Create Strategy Function**:
```python
def strategy_your_strategy(
    src_finding: Dict,
    snk_finding: Dict,
    src_metavars: Dict[str, str],
    snk_metavars: Dict[str, str],
    index: Dict[str, Any],
    config: StrategyConfig = _DEFAULT_CONFIG
) -> Optional[Dict]:
    """
    Strategy N: Your strategy description.
    
    Confidence: HIGH/MEDIUM/LOW
    - When HIGH confidence
    - When MEDIUM confidence
    - When LOW confidence
    
    Returns:
        Match dictionary or None
    """
    # Extract required metavars
    # Perform matching logic
    # Return match dict or None
```

2. **Add to Matcher**:
   - Add strategy call in `can_stitch_with_index()` in `matcher.py`
   - Place in appropriate confidence order

3. **Required Match Dictionary Fields**:
   - `strategy`: Unique strategy name
   - `source`: Source identifier string
   - `sink`: Sink identifier string
   - `confidence`: One of `Confidence.HIGH`, `MEDIUM`, `LOW`
   - `resolution`: Optional explanation string
   - `note`: Optional assumptions/limitations string

### Modeling Untested Hops

When adding support for new call patterns:

1. **Identify Call Pattern**:
   - What does the call look like in code?
   - What metavariables does Opengrep extract?
   - What information is in the index?

2. **Add Resolution Logic**:
   - Extend `_extract_indexed_method_id()` for new metavar patterns
   - Extend `_resolve_callee_from_call()` for new call types
   - Add to `_build_call_graph()` if new index structure needed

3. **Update Index Structure** (if needed):
   - Ensure `build_index.py` captures the new pattern
   - Add to `method_calls` with appropriate structure

4. **Test Confidence Assignment**:
   - Direct resolution → HIGH
   - Requires inference → MEDIUM
   - Many assumptions → LOW

### Example: Adding Support for Property Calls

If you need to handle `obj.property` → `ClassName.property`:

1. **Extend `_extract_indexed_method_id()`**:
   - Add case for `$OBJ` with no `$METHOD` but property access
   - Resolve obj to class, check if property exists in index

2. **Update `_resolve_callee_from_call()`**:
   - Add `property_access` call type
   - Resolve to class and property name

3. **Update Index**:
   - Ensure properties are tracked in class attributes
   - Add property access to `method_calls` if needed

## Configuration

`StrategyConfig` controls strategy behavior:
- `line_tolerance`: Lines within which to consider method match (default: 5)
- `max_path_hops`: Maximum hops for HIGH confidence (default: 3)
- `require_exact_match`: Require exact line match (default: False)
- `allow_heuristics`: Allow heuristic-based resolution (default: True)

## Deduplication

Matches are deduplicated by actual taint flow:
- **Flow Key**: `(source_origin, sink_path, sink_line)`
- **Source Origin**: Extracted from `dataflow_trace.taint_source` or metavars
- **Best Match**: Highest confidence, most specific strategy

This ensures one match per unique taint flow, not per finding pair.

## Key Design Principles

1. **Fail Fast**: Return `None` if match impossible, don't guess
2. **Confidence Reflects Certainty**: HIGH = verified, MEDIUM = inferred, LOW = assumed
3. **Index as Source of Truth**: All resolution uses index, not heuristics
4. **Reject Overridden Methods**: If no call graph path, reject to avoid FPs
5. **Generic and Extensible**: Strategies work for any codebase structure

