How Sanitizers Work
1. Simple Sanitizers

The simplest form matches function calls that sanitize data:

pattern-sanitizers:  
  - pattern: shlex.quote($X)

This marks any data passed through shlex.quote() as sanitized. Rule.ml:264-288
2. By-Side-Effect Sanitizers

For functions that sanitize arguments by modifying them (not through return values):

pattern-sanitizers:  
  - pattern: validate_command($X)  
    by-side-effect: true  
    exact: true

Parse_rule.ml:374-376

This is useful for validation functions that modify their arguments in-place, as shown in the test example: taint_sanitizer_var.py:1-6
3. Contextual Sanitizers

Sanitizers can match patterns within specific contexts:

pattern-sanitizers:  
  - patterns:  
      - pattern: $X  
      - pattern-inside: |  
          if is_safe($X):  
            ...

This sanitizes $X only when it appears inside an is_safe() check, similar to the example in the codebase: taint_wo_side_effects1.yaml:12-36
4. Not-Conflicting Sanitizers

To prevent sanitizers from conflicting with sources/sinks at the exact same location:

pattern-sanitizers:  
  - pattern: $F(...)  
    not-conflicting: true

This assumes any function call sanitizes data, but won't override explicit sources/sinks. Rule.ml:274-287
How Sanitizers Are Processed

During taint analysis, sanitizers are checked at each instruction: Dataflow_tainting.ml:1867-1872

The engine filters out conflicting sanitizers (when not-conflicting: true) to avoid false negatives: Match_taint_spec.ml:254-274
Complete Example

Here's a practical example for your command injection rule:

rules:  
  - id: python-parent-class-command-injection-sink  
    message: "Command injection vulnerability in class '$CLASS'"  
    severity: ERROR  
    languages:  
      - python  
    mode: taint  
    options:  
      taint_intrafile: true  
    pattern-sources:  
      - pattern: |  
          class $CLASS:  
            def __init__(self, $INPUT):  
              ...  
    pattern-sanitizers:  
      - pattern: shlex.quote($X)  
      - pattern: shlex.split($X)  
      - pattern: validate_shell_command($X)  
        by-side-effect: true  
    pattern-sinks:  
      - patterns:  
          - pattern-either:  
              - pattern: subprocess.run($CMD, shell=True, ...)  
              - pattern: os.system($CMD)  
          - focus-metavariable: $CMD

This will detect tainted data flowing from class constructors to shell command sinks, but not report findings where the data passes through shlex.quote() or similar sanitization functions.
Notes

    Sanitizers use exact: false by default, meaning they match subexpressions Parse_rule.ml:370-372
    The by-side-effect option is false by default, suitable for most sanitization functions that return sanitized values Parse_rule.ml:374-376
    Sanitizers completely remove taint from data, unlike propagators which transform it Rule.ml:252-263
