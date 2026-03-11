# Index Schema Specification

This document defines the required JSON structure that the tree-sitter indexer **MUST** produce for compatibility with downstream components (stitching strategies, resolver functions).

## Critical Constraint

The tree-sitter indexer implementation must produce a JSON structure that is **compatible** with the AST-based indexer's output. Downstream components (stitching strategies with 62 index accesses, resolver with 17 index accesses) depend on this exact structure.

## Root Schema

```json
{
  "classes": {},
  "functions": {},
  "imports": {},
  "attributes": {},
  "inheritance": {},
  "method_calls": [],
  "repository": {},
  "repositories": {},
  "cross_repo_calls": [],
  "files": {},
  "object_initializations": []
}
```

## Field Specifications

### `classes` (Required)

**Type:** `Dict[str, ClassInfo]`

**Purpose:** Maps class names to class definitions with methods, attributes, and metadata.

**Structure:**
```json
{
  "ClassName": {
    "methods": {
      "method_name": {
        "file": "path/to/file.py",
        "file_relative": "path/to/file.py",
        "line": 42,
        "params": ["param1", "param2"],
        "params_full": [
          {
            "name": "param1",
            "position": 0,
            "annotation": "str",
            "default": null,
            "kind": "POSITIONAL_OR_KEYWORD",
            "usage_context": {
              "assigned_to_fields": [],
              "passed_to_calls": [],
              "returned": false
            }
          }
        ],
        "is_init": false,
        "decorators": ["@property"],
        "returns": "str"
      }
    },
    "attributes": {
      "attr_name": [
        {
          "type": "ResolvedType",
          "file": "path/to/file.py",
          "line": 20,
          "value_code": "SomeClass()"
        }
      ]
    },
    "parent_classes": ["ParentClass"],
    "file": "path/to/file.py",
    "file_relative": "path/to/file.py",
    "line": 10,
    "nested_in": null,
    "decorators": []
  }
}
```

**Key Requirements:**
- `methods` must include all methods, including `__init__`
- `attributes` tracks `self.attr = value` assignments
- `parent_classes` lists direct parent classes (inheritance chain in separate field)
- `file_relative` should be relative to repository root

**Used By:**
- Stitching strategies: Method lookup, attribute resolution
- Resolver: Attribute type resolution, class hierarchy traversal

### `functions` (Required)

**Type:** `Dict[str, FunctionInfo]`

**Purpose:** Maps standalone function names to function definitions.

**Structure:**
```json
{
  "function_name": {
    "file": "path/to/file.py",
    "file_relative": "path/to/file.py",
    "line": 5,
    "params": ["arg1", "arg2"],
    "params_full": [
      {
        "name": "arg1",
        "position": 0,
        "annotation": null,
        "default": null,
        "kind": "POSITIONAL_OR_KEYWORD"
      }
    ],
    "decorators": [],
    "returns": null
  }
}
```

**Used By:**
- Stitching strategies: Direct function matching (Strategy 1)

### `method_calls` (Required - PRIMARY)

**Type:** `List[CallEntry]`

**Purpose:** Call graph tracking - records all method/function calls with caller context.

**Structure:**
```json
[
  {
    "caller_class": "CallerClass",
    "caller_method": "caller_method",
    "call": {
      "type": "method_call",
      "object": "obj_name",
      "method": "method_name",
      "full": "obj_name.method_name"
    },
    "arguments": [
      {
        "position": 0,
        "value": "arg_value_code",
        "source": "parameter"
      }
    ],
    "file": "path/to/file.py",
    "file_relative": "path/to/file.py",
    "line": 25,
    "callee": {
      "file": "path/to/callee.py",
      "file_relative": "path/to/callee.py",
      "class": "CalleeClass",
      "method": "method_name",
      "resolved": true
    },
    "callee_resolved": true,
    "caller_repo": "repo-id"
  }
]
```

**Call Types:**
- `"function_call"`: `function_name(...)`
- `"method_call"`: `obj.method(...)`
- `"nested_method_call"`: `obj.attr.method(...)`

**Key Requirements:**
- Must track caller context (class, method, file, line)
- Must include call information (type, object, method)
- Should resolve callee when possible (`callee_resolved: true`)
- Arguments should track position and source (parameter vs. literal)

**Used By:**
- Stitching strategies: **PRIMARY strategy** (Strategy 0) - call graph propagation
- Resolver: Call path resolution

### `inheritance` (Required)

**Type:** `Dict[str, InheritanceInfo]`

**Purpose:** Maps class names to inheritance relationships.

**Structure:**
```json
{
  "ChildClass": {
    "parents": ["ParentClass", "MixinClass"],
    "file": "path/to/file.py",
    "file_relative": "path/to/file.py",
    "line": 10,
    "nested_in": null,
    "decorators": []
  }
}
```

**Key Requirements:**
- `parents` lists direct parent classes
- Resolver functions traverse this to build full inheritance chains

**Used By:**
- Stitching strategies: Inheritance resolution (Strategy 3)
- Resolver: Inheritance chain traversal

### `files` (Required)

**Type:** `Dict[str, FileInfo]`

**Purpose:** Per-file exports and metadata.

**Structure:**
```json
{
  "path/to/file.py": {
    "relative_path": "path/to/file.py",
    "exports": ["ClassName", "function_name"]
  }
}
```

**Key Requirements:**
- `relative_path` should be relative to repository root
- `exports` lists all classes and functions exported from the file

**Used By:**
- Resolver: Import-to-file resolution
- Cross-repository call tracking

### `imports` (Optional but Recommended)

**Type:** `Dict[str, List[ImportInfo]]`

**Purpose:** Tracks import statements for cross-file resolution.

**Structure:**
```json
{
  "module_name": [
    {
      "name": "ImportedName",
      "asname": "Alias",
      "file": "path/to/importer.py",
      "from_module": "module.path",
      "line": 5
    }
  ]
}
```

**Used By:**
- Resolver: Import resolution

### `repositories` (Optional - Cross-Repo Support)

**Type:** `Dict[str, RepoIndex]`

**Purpose:** Repository-scoped indices for cross-repository analysis.

**Structure:**
```json
{
  "repo-id": {
    "classes": {},
    "functions": {},
    "imports": {},
    "inheritance": {},
    "method_calls": []
  }
}
```

**Used By:**
- Stitching strategies: Cross-repository method matching

### `repository` (Optional)

**Type:** `Dict[str, Any] | null`

**Purpose:** Current repository metadata.

**Structure:**
```json
{
  "id": "repo-id",
  "url": "https://github.com/org/repo",
  "root_path": "/path/to/repo/root"
}
```

**Used By:**
- Stitching strategies: Repository ID extraction

### `cross_repo_calls` (Optional)

**Type:** `List[CrossRepoCall]`

**Purpose:** Cross-repository call tracking.

**Structure:**
```json
[
  {
    "caller": "repo-id:CallerClass.method",
    "callee": "other-repo-id:CalleeClass.method",
    "via": "import",
    "file": "path/to/file.py",
    "line": 25
  }
]
```

### `attributes` (Legacy - May be Deprecated)

**Type:** `Dict[str, Any]`

**Note:** Currently used by resolver but may be redundant with `classes[].attributes`.

### `object_initializations` (Optional)

**Type:** `List[ObjectInit]`

**Purpose:** Tracks object constructor calls.

**Structure:**
```json
[
  {
    "variable": "var_name",
    "scope": {
      "class": "ClassName",
      "method": "method_name"
    },
    "constructor": {
      "class": "ConstructedClass",
      "arguments": [
        {
          "position": 0,
          "value": "arg_value",
          "source": "parameter"
        }
      ]
    },
    "file": "path/to/file.py",
    "file_relative": "path/to/file.py",
    "line": 15
  }
]
```

## Compatibility Requirements

### Backward Compatibility

The index structure supports both:
1. **Flat structure**: `index['classes'][className]`
2. **Repo-scoped structure**: `index['repositories'][repoId]['classes'][className]`

Downstream code checks both structures for backward compatibility.

### Required vs. Optional Fields

**Required for Stitching:**
- `classes` (with `methods` subfield)
- `method_calls` (PRIMARY dependency)
- `inheritance`
- `functions`

**Required for Resolver:**
- `classes` (with `attributes` subfield)
- `inheritance`
- `files`

**Optional but Recommended:**
- `imports` (improves resolution accuracy)
- `repositories` (enables cross-repo analysis)
- `object_initializations` (improves constructor chain inference)

## Validation Checklist

Before migrating to tree-sitter, ensure the indexer produces:

- [ ] `classes` dictionary with methods, attributes, parent_classes
- [ ] `method_calls` array with caller context and call information
- [ ] `inheritance` dictionary with parent relationships
- [ ] `functions` dictionary for standalone functions
- [ ] `files` dictionary with exports
- [ ] All file paths use forward slashes and are relative to repo root
- [ ] Method calls include resolved callee information when possible
- [ ] Attributes track type information from assignments

## Testing Compatibility

To verify tree-sitter indexer compatibility:

1. Run stitching strategies on tree-sitter index
2. Verify all 6 strategies can access required fields
3. Test resolver functions with tree-sitter index
4. Compare output with AST-based indexer on same codebase

## Migration Notes

When implementing tree-sitter indexer:

1. **Start with schema**: Define data structures matching this schema
2. **Incremental implementation**: Build one field at a time (classes → methods → method_calls)
3. **Test compatibility**: Run downstream components after each field
4. **Preserve structure**: Don't change field names or nesting
5. **Document differences**: Note any tree-sitter-specific enhancements

