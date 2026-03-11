Core Matching Options
Option	Default	Description
constant_propagation	true	Enable constant value propagation during matching
symbolic_propagation	false	Enable symbolic value propagation (requires constant_propagation)
ac_matching	true	Associative-commutative matching for operators
commutative_boolop	false	Treat && and || as commutative
symmetric_eq	false	Treat == as symmetric (a==b matches b==a)
vardef_assign	true	Match assignments with variable definitions
flddef_assign	false	Match assignments with field definitions
attr_expr	true	Match expression patterns with attributes
unify_ids_strictly	true	Strict identifier unification
arrow_is_function	true	Treat arrow functions like regular functions
let_is_var	true	Treat let/const as equivalent to var (JS)
go_deeper_expr	true	Implicitly match nested expressions
go_deeper_stmt	true	Implicitly match nested statements
implicit_deep_exprstmt	true	Implicit deep ellipsis in expression statements
implicit_return	true	Treat last expression as return (Ruby/Julia)
decorators_order_matters	false	Match decorators in order
Taint Analysis Options
Option	Default	Description
taint_focus_on	Sink	Where to focus taint matches (Source or Sink)
taint_unify_mvars	false	Unify metavariables between sources and sinks
taint_assume_safe_functions	false	Assume functions don't propagate taint
taint_assume_safe_indexes	false	Assume array indexing is safe
taint_assume_safe_comparisons	false	Assume comparisons are safe
taint_assume_safe_booleans	false	Assume boolean operations are safe
taint_assume_safe_numbers	false	Assume numeric operations are safe
taint_only_propagate_through_assignments	false	Only propagate taint via assignments
taint_intrafile	false	Enable intra-file interprocedural taint analysis
taint_fixpoint_timeout	(optional)	Override default taint fixpoint timeout
Generic Engine Options
Option	Default	Description
generic_caseless	false	Case-insensitive matching (aliengrep only)
generic_ellipsis_max_span	10	Max newlines an ellipsis can match (spacegrep)
generic_comment_style	(optional)	Comment style for preprocessing
Performance & Limits
Option	Default	Description
max_match_per_file	(optional)	Limit matches reported per file
timeout	(optional)	Rule-specific timeout override
dynamic_timeout	(optional)	Scale timeout with file size
dynamic_timeout_unit_kb	(optional)	Unit for dynamic timeout calculation
dynamic_timeout_max_multiplier	(optional)	Max multiplier for dynamic timeout