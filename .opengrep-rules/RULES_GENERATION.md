# Rule Generation Requirements

## Metavariable Requirements

Rules MUST capture the following metavariables at the intersection boundary (callee boundary):

| Metavar | Required For | Capture Location |
|---------|--------------|------------------|
| `$CLASS` | Class method identification | Class definition context |
| `$METHOD` | Method identification | Method definition or call site |
| `$OBJ` | Object method calls | Object reference in method calls |
| `$FUNC` | Standalone function identification | Function definition or call site |
| `$INPUT` | Input parameter tracking | Parameter or argument position |

**Metavariable structure is identical for source and sink rules.**

---

## Source Rule Requirements

### Required Configuration
- `mode: taint`
- `options.taint_intrafile: true`
- `options.taint_focus_on: source` (reports at source location)
- `metadata.finding_type: source`

### Required Pattern-Sinks
MUST capture metavars at the **callee boundary** where taint propagation stops:

```yaml
pattern-sinks:
  - patterns:
      - pattern: $CLASS($INPUT)
      - focus-metavariable: $INPUT
  - patterns:
      - pattern: $OBJ.$METHOD($INPUT)
      - focus-metavariable: $INPUT
```

**Minimum metavar combinations:**
- `$CLASS` + `$METHOD` (via pattern-sinks)
- `$OBJ` + `$METHOD` (via pattern-sinks)
- `$FUNC` (standalone function)

### Pattern-Propagators
MUST include propagators for:
- Field assignments: `$SELF.$FIELD = $VALUE`
- Attribute access: `$OBJ.$FIELD`
- Method calls: `$OBJ.$METHOD(...)`
- Constructor calls: `$CLASS(...)`
- Nested attribute access: `$OBJ.$ATTR.$METHOD(...)`

**Reference:** `rules/sources/python-source-sys.yml`

---

## Sink Rule Requirements

### Required Configuration
- `mode: taint`
- `options.taint_intrafile: true`
- `metadata.finding_type: sink`

### Required Pattern-Sources
MUST capture metavars at the **callee boundary** where backward pass starts:

```yaml
pattern-sources:
  - pattern: |
      class $CLASS:
        def __init__(..., $INPUT, ...):
          ...
  - pattern: |
      class $CLASS:
        def $METHOD(..., $INPUT, ...):
          ...
  - pattern: |
      class $CLASS:
        $INPUT
        ...
  - pattern: |
      def $FUNC($INPUT, ...):
        ...
  - pattern: $INPUT
```

**Minimum metavar combinations:**
- `$CLASS` + `$METHOD` (via pattern-sources)
- `$CLASS` (via pattern-inside)
- `$FUNC` (standalone function)

### Pattern-Propagators
MUST include propagators for:
- Function calls: `$FUNC(..., $ARG, ...)`
- Method calls: `$OBJ.$METHOD(..., $ARG, ...)`
- Constructor calls: `$CLASS(..., $ARG, ...)`
- Nested attribute access: `$OBJ.$ATTR.$METHOD(..., $ARG, ...)`

### Pattern-Sinks
MUST capture the actual sink location with `focus-metavariable`:

```yaml
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: subprocess.run($CMD, ...)
          - pattern: subprocess.Popen($CMD, ...)
          - pattern: os.system($CMD)
      - focus-metavariable: $CMD
```

**Reference:** `rules/sinks/python-sink-command-injection.yml`

---

## Intersection Boundary Requirements

### Forward Pass (Source Rule)
- MUST stop at callee boundary (method/function call site)
- MUST capture `$CLASS` + `$METHOD` OR `$OBJ` + `$METHOD` OR `$FUNC` at boundary
- Format: `"ClassName.method"` or `"function"`

### Backward Pass (Sink Rule)
- MUST start at callee boundary (method/function definition)
- MUST capture `$CLASS` + `$METHOD` OR `$CLASS` OR `$FUNC` at boundary
- Format: `"ClassName.method"` or `"function"`

### Matching Requirements
- Both passes MUST provide method/function identifiers at the same boundary
- Identifiers MUST be matchable via:
  - Exact match: `"Class1.process" == "Class1.process"`
  - Substring match: `"testclass0002.class0001.method"` contains `"class0001.method"`
  - Call path: Verified through class index

---

## Universal Constraints

1. **Metavar Consistency**: Source and sink rules MUST use identical metavar names (`$CLASS`, `$METHOD`, `$OBJ`, `$FUNC`)
2. **Boundary Capture**: Both rules MUST capture metavars at the callee boundary (where classes/methods intersect)
3. **Minimum Metavars**: At least one method/function identifier MUST be extractable from metavars
4. **Location Information**: All findings MUST include `path`, `start.line`, `start.col` (provided by Opengrep)

---

## Rule Structure Template

### Source Rule Template
```yaml
rules:
  - id: <rule-id>
    mode: taint
    options:
      taint_intrafile: true
      taint_focus_on: source
    pattern-sources:
      - pattern: <source-pattern>
    pattern-propagators:
      - pattern: <propagator-patterns>
    pattern-sinks:
      - patterns:
          - pattern: $CLASS($INPUT)
          - focus-metavariable: $INPUT
      - patterns:
          - pattern: $OBJ.$METHOD($INPUT)
          - focus-metavariable: $INPUT
    metadata:
      finding_type: source
```

### Sink Rule Template
```yaml
rules:
  - id: <rule-id>
    mode: taint
    options:
      taint_intrafile: true
    pattern-sources:
      - pattern: |
          class $CLASS:
            def $METHOD(..., $INPUT, ...):
              ...
      - pattern: |
          def $FUNC($INPUT, ...):
            ...
    pattern-propagators:
      - pattern: <propagator-patterns>
    pattern-sinks:
      - patterns:
          - pattern: <sink-pattern>
          - focus-metavariable: <input-var>
    metadata:
      finding_type: sink
```

Taint Rules for Modeling Python Classes, Methods, and Functions in OpenGrep

Based on your index structure, here are the taint rules you can use to properly model Python files across classes, methods, and functions, along with their limitations.
Core Configuration Requirements

For cross-function/cross-method taint analysis in Python, you must enable the taint_intrafile option

Your rules should follow this structure:
```yaml
rules:  
  - id: your-rule-id  
    mode: taint  
    languages: [python]  
    options:  
      taint_intrafile: true  # REQUIRED for cross-method tracking
```
Pattern-Propagators for Python Object-Oriented Code

To model taint flow across your benchmark classes, you need these propagators:
1. Field Assignment Propagation (self.field = value)

```yaml
pattern-propagators:  
  - pattern: $SELF.$FIELD = $VALUE  
    from: $VALUE  
    to: $SELF  
    by-side-effect: true
```
This handles cases like self.data = data in __init__ methods.
2. Attribute Access Propagation (obj.field)

```yaml
pattern-propagators:  
  - pattern: $OBJ.$FIELD  
    from: $OBJ  
    to: $RETURN
```
This propagates taint when accessing self.data or self.processor.execute().
3. Method Call Propagation

```yaml
pattern-propagators:  
  - pattern: $OBJ.$METHOD(...)  
    from: $OBJ  
    to: $RETURN
```
4. Constructor Call Propagation

```yaml
pattern-propagators:  
  - pattern: $CLASS($INPUT)  
    from: $INPUT  
    to: $RETURN
```
This handles cases like BenchmarkTest00001(data) creating instances.
5. Nested Attribute/Method Access

```yaml
pattern-propagators:  
  - pattern: $OBJ.$ATTR.$METHOD(...)  
    from: $OBJ  
    to: $RETURN
```
For patterns like self.processor.execute(data).
How __init__ Boundaries Are Handled

OpenGrep tracks taint across __init__ constructors and methods using a specialized system:

    Constructor Detection: The engine detects __init__ methods automatically

    Instance Variable Tracking: When taint is assigned to self.field in __init__, it's stored in domain-local storage keyed by class name

    Cross-Method Propagation: When non-constructor methods run, they inherit the taint state from the constructor's instance variables

Example from your index: In BenchmarkTest00001.__init__, when data is assigned to self.data (line 5), that taint will automatically be available in the process() method when it accesses self.data.
Complete Example Rules
Source Rule (Forward Analysis)

```yaml
rules:  
  - id: python-taint-source  
    mode: taint  
    languages: [python]  
    severity: WARNING  
    message: Tainted data from source  
    metadata:  
      finding_type: source  
    options:  
      taint_intrafile: true  
      taint_focus_on: source  
      
    pattern-sources:  
      - pattern: source(...)  
      - pattern: request.$W.get(...)  
      - pattern: sys.argv[$N]  
      
    pattern-propagators:  
      - pattern: $SELF.$FIELD = $VALUE  
        from: $VALUE  
        to: $SELF  
        by-side-effect: true  
      - pattern: $CLASS($INPUT)  
        from: $INPUT  
        to: $RETURN  
      - pattern: $OBJ.$METHOD($INPUT)  
        from: $INPUT  
        to: $RETURN  
      - pattern: $OBJ.$FIELD  
        from: $OBJ  
        to: $RETURN  
      
    pattern-sinks:  
      - pattern: $SINK  
        focus-metavariable: $SINK
```
Sink Rule (Backward Analysis)

```yaml
rules:  
  - id: python-taint-sink  
    mode: taint  
    languages: [python]  
    severity: ERROR  
    message: Tainted data reaches dangerous sink  
    metadata:  
      finding_type: sink  
    options:  
      taint_intrafile: true  
      
    pattern-sources:  
      - pattern: $SOURCE  
        focus-metavariable: $SOURCE  
      
    pattern-sinks:  
      - pattern: subprocess.Popen($CMD, ...)  
      - pattern: os.system($CMD)  
      - pattern: cursor.executescript($SQL)
```
Critical Limitations
1. Subclass Inheritance NOT Supported (MAJOR LIMITATION)

This is explicitly documented as a TODO limitation in OpenGrep's codebase

What this means for your index:

    BenchmarkTest00002_Subclass inherits from BenchmarkTest00001
    If BenchmarkTest00001.__init__ sets self.name = source(), taint will NOT propagate to BenchmarkTest00002_Subclass methods
    This is a false negative - the taint exists but won't be detected

Workaround: You must explicitly model each class's taint sources separately, not rely on inherited field taint.
2. Call Graph Topological Ordering

The engine analyzes functions in topological order (callees before callers)

This means:

    Functions calling each other must be in the same file
    Cyclic dependencies have arbitrary ordering (mutual recursion not fully supported)
    Cross-file taint tracking is NOT supported

3. Field Normalization

The taint engine normalizes self.x.y to x.y internally, stripping the self base: 

This means your patterns should match the actual syntax ($SELF.$FIELD), but internally the engine handles the normalization.
4. Higher-Order Functions Not Supported

Callbacks and higher-order functions (like flatMap, lambdas passed as arguments) are not yet supported
5. Performance Considerations

The taint fixpoint computation has a timeout (default 200ms). For complex files with many methods, you may need to increase this
Metavariable Capture at Boundaries

Based on your requirements table, here's how to capture metavariables:
At Callee Boundaries (Pattern-Sinks for Source Rules)
```yaml
pattern-sinks:  
  - patterns:  
      - pattern-inside: |  
          class $CLASS:  
            ...  
            def $METHOD($SELF, $INPUT, ...):  
              ...  
      - pattern: $SINK($INPUT)  
    focus-metavariable: $SINK
```
At Callee Boundaries (Pattern-Sources for Sink Rules)

pattern-sources:  
```yaml
  - patterns:  
      - pattern-inside: |  
          def $FUNC($INPUT, ...):  
            ...  
      - pattern: $SOURCE  
    focus-metavariable: $SOURCE
```
For Object Method Calls
```yaml
pattern-propagators:  
  - patterns:  
      - pattern: $OBJ.$METHOD($INPUT)  
      - metavariable-pattern:  
          metavariable: $OBJ  
          pattern: $SELF.$FIELD  
    from: $INPUT  
    to: $OBJ
```