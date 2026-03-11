This is a sandbox environment from which we are to attempt to stitch together complete data flows from tain analysis through a set of rules. This project is leveraging the Opengrep engine with existing limitations on Inter-file analyis that we are looking to work around since the fork from Semgrep OSS. The most recent version has supplied a Intra-file mode as to avoid modeling each function call or class boundaries (with known limitations on nested classes).

DO NOT MAKE ASSUMPTIONS AROUND CONFIGURATION OR SYNTAX OF THE RULES AND TOOL AS THIS IS THE OPENGREP ENGINE FORKED FROM SEMGREP OSS LAST YEAR.


## Parameters: 
1. The rules are to trace taint from a known Source, Sink entity through mapping of AST boundaries of each file. 

2. The file-scoped results must have semantic matches to stitch together across the fields in the JSON output. 

3.The INTERSECTION of two or more finding output attributes MUST include ALL True Positive findings. False Positive flows are acceptable so long as the Intersection has complete recall.
In Essence: When a finding traces or provides a value like "testclass0002.class0001.test_method_0002" Then the backwards pass must also provide that same method somehow at the highest possible degree of substrings matching.

### Intersection Boundary Concept
**Forward Pass (Source Rule):** Traces from `sys.argv` → Class2 (caller) → **Class1 (callee boundary)** ← STOPS HERE  
**Backward Pass (Sink Rule):** Traces from **Class1 (callee boundary)** ← Class1.method ← sink ← STARTS HERE  
**Intersection:** Both passes meet at the Class1 boundary where Class2 calls into Class1

## AppSec Modeling Guidance
- Treat framework-provided request objects (Flask, FastAPI, Django, etc.) as default sources. Flask `request.args/form/json/...` MUST be modeled explicitly rather than inferred.
- Likewise, obvious sinks (database execution, subprocess invocation, template rendering) MUST be enumerated as inputs to the rule generator. Do not rely on heuristics.
- When a framework decorator or router is present (e.g., `@app.route`), capture it via `pattern-inside` so that route variables are bound to metavariables available to stitching.
- Templates should include audit metadata (type and implication) and be decomposed into atomic propagation relationships so every hop is reviewable.
- Likewise the same principle for: Reflection, Dynamic Programming, Pathfinding complexity of branching control flows. Treat these as an atomic program analysis unit. 
- IMPORTANT: Rules that are generated that is modeling these class of patterns are marked accordingly.

## Commands Cheatsheet:
** Running a re-index**
cd G:\GitHub\BenchmarkPythonA && .\venv\Scripts\Activate.ps1 && holocron build-index 

** Running a stitch:**
cd G:\GitHub\BenchmarkPythonA && .\venv\Scripts\Activate.ps1 && holocron stitch --findings-dir outputs/findings --index outputs/indices/class_index.json --output outputs/stitched.json 2>&1 | Select-Object -Last 40

