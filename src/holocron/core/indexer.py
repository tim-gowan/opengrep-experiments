"""Class index building using AST analysis."""

import ast
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any
from holocron.core.types import ClassIndex


def _unparse_ast(node: ast.AST) -> Optional[str]:
    """Safely unparse AST node, with fallback for Python < 3.9."""
    if hasattr(ast, 'unparse'):
        try:
            return ast.unparse(node)
        except Exception:
            pass
    # Fallback: return string representation
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return f"{_unparse_ast(node.value) or '?'}.{node.attr}"
    return None


class IndexerBase(ABC):
    """Abstract base class for index builders.
    
    Allows alternate tool implementations to override indexing logic
    while maintaining a consistent interface.
    """
    
    @abstractmethod
    def build_index(self, file_path: str, repo_id: Optional[str] = None, repo_url: Optional[str] = None, repo_root: Optional[str] = None) -> Dict[str, Any]:
        """
        Build index for a single file.
        
        Args:
            file_path: Path to Python file
            repo_id: Optional repository identifier
            repo_url: Optional repository URL
            repo_root: Optional repository root path for relative path calculation
            
        Returns:
            Class index dictionary
        """
        pass
    
    def build_index_for_directory(
        self, 
        source_dir: str, 
        repo_id: Optional[str] = None,
        repo_url: Optional[str] = None,
        output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build index for all Python files in a directory.
        
        Args:
            source_dir: Source directory path
            repo_id: Optional repository identifier
            repo_url: Optional repository URL
            output_file: Optional output file path
            
        Returns:
            Merged class index dictionary
        """
        raise NotImplementedError("Subclasses must implement build_index_for_directory")
    
    def get_repo_id(self, file_path: str) -> Optional[str]:
        """
        Extract repository identifier from file path.
        
        Override this method for custom repository detection logic.
        
        Args:
            file_path: Path to file
            
        Returns:
            Repository identifier or None
        """
        return None


def _find_repo_root(file_path: str) -> Optional[str]:
    """Find repository root by looking for .git directory."""
    path = Path(file_path).resolve()
    if path.is_file():
        path = path.parent
    
    # Walk up the directory tree looking for .git
    while path != path.parent:
        git_dir = path / '.git'
        if git_dir.exists():
            return str(path)
        path = path.parent
    
    return None


def _calculate_relative_path(file_path: str, repo_root: Optional[str]) -> Optional[str]:
    """Calculate relative path from repository root."""
    if not repo_root:
        return None
    
    try:
        file_abs = os.path.abspath(file_path)
        repo_abs = os.path.abspath(repo_root)
        relative = os.path.relpath(file_abs, repo_abs)
        # Normalize to forward slashes for consistency
        return relative.replace('\\', '/')
    except (ValueError, OSError):
        return None


class EnhancedClassIndexBuilder(IndexerBase, ast.NodeVisitor):
    """
    Enhanced AST visitor using ast module features more effectively.
    Builds comprehensive index of classes, methods, functions, attributes, and relationships.
    """
    
    def __init__(self, file_path: str, repo_id: Optional[str] = None, repo_url: Optional[str] = None, repo_root: Optional[str] = None):
        self.file_path = file_path
        self.repo_id = repo_id
        self.repo_url = repo_url
        
        # Auto-detect repo_root if not provided
        if not repo_root:
            repo_root = _find_repo_root(file_path)
        self.repo_root = repo_root
        
        # Calculate relative path
        self.file_relative = _calculate_relative_path(file_path, repo_root)
        
        self.index = {
            'classes': {},  # class_name -> {methods, attributes, parent, file, decorators}
            'functions': {},  # func_name -> {file, line, params, decorators}
            'imports': {},  # module -> {imported_items}
            'attributes': {},  # class_name.attr_name -> resolved_type
            'inheritance': {},  # class_name -> [parent_classes]
            'method_calls': [],  # Track method calls for call graph
            'repository': {
                'id': repo_id,
                'url': repo_url,
                'root_path': repo_root
            } if repo_id or repo_url or repo_root else None,
            'repositories': {},
            'cross_repo_calls': [],
            'files': {}  # NEW: per-file exports and metadata
        }
        self.current_class = None
        self.current_class_stack = []
        self.current_method = None
        
        # Initialize file entry for exports tracking
        if self.file_relative:
            self.index['files'][self.file_relative] = {
                'relative_path': self.file_relative,
                'exports': []
            }
        
    def visit_Import(self, node):
        """Track import statements using ast."""
        for alias in node.names:
            module = alias.asname if alias.asname else alias.name
            if module not in self.index['imports']:
                self.index['imports'][module] = []
            self.index['imports'][module].append({
                'name': alias.name,
                'asname': alias.asname,
                'file': self.file_path,
                'line': node.lineno
            })
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Track from ... import statements using ast."""
        module = node.module if node.module else ''
        for alias in node.names:
            imported_name = alias.asname if alias.asname else alias.name
            if module not in self.index['imports']:
                self.index['imports'][module] = []
            self.index['imports'][module].append({
                'name': alias.name,
                'asname': alias.asname,
                'file': self.file_path,
                'from_module': module,
                'line': node.lineno
            })
        self.generic_visit(node)
    
    def visit_ClassDef(self, node):
        """Track class definitions, inheritance, decorators, and methods using ast."""
        class_name = node.name
        
        # Extract parent classes (handles both Name and Attribute bases)
        parent_classes = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                parent_classes.append(base.id)
            elif isinstance(base, ast.Attribute):
                # Handle cases like module.Class
                parent_classes.append(self._get_full_name(base))
        
        # Extract decorators
        decorators = [self._get_decorator_name(d) for d in node.decorator_list]
        
        # Track inheritance
        self.index['inheritance'][class_name] = {
            'parents': parent_classes,
            'file': self.file_path,
            'file_relative': self.file_relative,
            'line': node.lineno,
            'nested_in': self.current_class,
            'decorators': decorators
        }
        
        # Initialize class entry
        self.index['classes'][class_name] = {
            'methods': {},
            'attributes': {},
            'parent_classes': parent_classes,
            'file': self.file_path,
            'file_relative': self.file_relative,
            'line': node.lineno,
            'nested_in': self.current_class,
            'decorators': decorators
        }
        
        # Track export
        if self.file_relative and class_name not in self.index['files'][self.file_relative]['exports']:
            self.index['files'][self.file_relative]['exports'].append(class_name)
        
        # Push current class onto stack
        self.current_class_stack.append(self.current_class)
        self.current_class = class_name
        
        # Visit class body
        self.generic_visit(node)
        
        # Pop class from stack
        self.current_class = self.current_class_stack.pop()
    
    def visit_FunctionDef(self, node):
        """Track function and method definitions using ast."""
        func_name = node.name
        
        # Extract decorators
        decorators = [self._get_decorator_name(d) for d in node.decorator_list]
        
        # Extract parameters with enhanced information
        params = []
        args_list = node.args.args
        defaults_list = node.args.defaults
        kw_defaults = node.args.kw_defaults if hasattr(node.args, 'kw_defaults') else []
        
        # Calculate offset for defaults (positional args without defaults come first)
        num_args = len(args_list)
        num_defaults = len(defaults_list)
        default_offset = num_args - num_defaults
        
        for position, arg in enumerate(args_list):
            param_info = {
                'name': arg.arg,
                'position': position,
                'annotation': _unparse_ast(arg.annotation) if arg.annotation else None,
                'default': None,
                'kind': self._get_param_kind(arg)
            }
            
            # Map default values to parameters
            if position >= default_offset:
                default_idx = position - default_offset
                if default_idx < len(defaults_list):
                    default_node = defaults_list[default_idx]
                    param_info['default'] = _unparse_ast(default_node)
            
            # Initialize usage context for tracking
            param_info['usage_context'] = {
                'assigned_to_fields': [],
                'passed_to_calls': [],
                'returned': False
            }
            
            params.append(param_info)
        
        if self.current_class:
            # It's a method
            if self.current_class not in self.index['classes']:
                self.index['classes'][self.current_class] = {
                    'methods': {},
                    'attributes': {},
                    'parent_classes': [],
                    'file': self.file_path,
                    'line': node.lineno
                }
            
            old_method = self.current_method
            self.current_method = func_name
            
            self.index['classes'][self.current_class]['methods'][func_name] = {
                'file': self.file_path,
                'file_relative': self.file_relative,
                'line': node.lineno,
                'params': [p['name'] for p in params if p['name'] != 'self'],
                'params_full': params,
                'is_init': func_name == '__init__',
                'decorators': decorators,
                'returns': _unparse_ast(node.returns) if node.returns else None
            }
            
            # Visit method body
            self.generic_visit(node)
            
            self.current_method = old_method
        else:
            # It's a standalone function
            self.index['functions'][func_name] = {
                'file': self.file_path,
                'file_relative': self.file_relative,
                'line': node.lineno,
                'params': [p['name'] for p in params],
                'params_full': params,
                'decorators': decorators,
                'returns': _unparse_ast(node.returns) if node.returns else None
            }
            
            # Track export
            if self.file_relative and func_name not in self.index['files'][self.file_relative]['exports']:
                self.index['files'][self.file_relative]['exports'].append(func_name)
            
            self.generic_visit(node)
    
    def visit_Return(self, node):
        """Track return statements to identify which parameters are returned."""
        if node.value and self.current_method:
            # Track what's being returned
            if isinstance(node.value, ast.Name):
                # Returning a variable (could be a parameter)
                var_name = node.value.id
                # Check if it's a parameter
                if self.current_class and self.current_class in self.index['classes']:
                    method_info = self.index['classes'][self.current_class]['methods'].get(self.current_method)
                    if method_info:
                        for param in method_info.get('params_full', []):
                            if param['name'] == var_name:
                                param['usage_context']['returned'] = True
            elif isinstance(node.value, ast.Attribute):
                # Returning an attribute
                attr_name = self._get_full_name(node.value)
                # Could track this for field returns
                pass
        
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        """Track attribute assignments and object initializations."""
        if self.current_class and self.current_method:
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    # self.attr = value
                    if isinstance(target.value, ast.Name) and target.value.id == 'self':
                        attr_name = target.attr
                        
                        # Resolve the value type using ast
                        value_type = self._resolve_value_type_ast(node.value)
                        
                        if attr_name not in self.index['classes'][self.current_class]['attributes']:
                            self.index['classes'][self.current_class]['attributes'][attr_name] = []
                        
                        self.index['classes'][self.current_class]['attributes'][attr_name].append({
                            'type': value_type,
                            'file': self.file_path,
                            'line': node.lineno,
                            'value_code': _unparse_ast(node.value)
                        })
                        
                        # Track if value is a parameter (for usage context)
                        if isinstance(node.value, ast.Name):
                            param_name = node.value.id
                            method_info = self.index['classes'][self.current_class]['methods'].get(self.current_method)
                            if method_info:
                                for param in method_info.get('params_full', []):
                                    if param['name'] == param_name:
                                        if attr_name not in param['usage_context']['assigned_to_fields']:
                                            param['usage_context']['assigned_to_fields'].append(f"self.{attr_name}")
                
                # Track object initializations (all variable assignments)
                elif isinstance(target, ast.Name):
                    var_name = target.id
                    # Check if value is a constructor call
                    if isinstance(node.value, ast.Call):
                        constructor_info = self._extract_call_info(node.value)
                        if constructor_info and constructor_info.get('type') == 'function_call':
                            class_name = constructor_info.get('function')
                            if class_name:
                                # Extract constructor arguments
                                constructor_args = []
                                for pos, arg in enumerate(node.value.args):
                                    arg_info = {
                                        'position': pos,
                                        'value': _unparse_ast(arg) if arg else None,
                                        'source': 'argument'
                                    }
                                    # Check if argument is a parameter
                                    if isinstance(arg, ast.Name):
                                        arg_info['source'] = 'parameter'
                                    constructor_args.append(arg_info)
                                
                                # Store object initialization
                                if 'object_initializations' not in self.index:
                                    self.index['object_initializations'] = []
                                
                                self.index['object_initializations'].append({
                                    'variable': var_name,
                                    'scope': {
                                        'class': self.current_class,
                                        'method': self.current_method
                                    },
                                    'constructor': {
                                        'class': class_name,
                                        'arguments': constructor_args
                                    },
                                    'file': self.file_path,
                                    'file_relative': self.file_relative,
                                    'line': node.lineno
                                })
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Track method calls for call graph analysis."""
        if self.current_method:
            # Track calls made within methods
            call_info = self._extract_call_info(node)
            if call_info:
                # Extract argument positions
                arguments = []
                for pos, arg in enumerate(node.args):
                    arg_info = {
                        'position': pos,
                        'value': _unparse_ast(arg) if arg else None
                    }
                    # Check if argument is a parameter
                    if isinstance(arg, ast.Name):
                        param_name = arg.id
                        if self.current_class and self.current_class in self.index['classes']:
                            method_info = self.index['classes'][self.current_class]['methods'].get(self.current_method)
                            if method_info:
                                for param in method_info.get('params_full', []):
                                    if param['name'] == param_name:
                                        # Track parameter usage in call
                                        call_target = call_info.get('full') or call_info.get('function') or call_info.get('method', 'unknown')
                                        param['usage_context']['passed_to_calls'].append({
                                            'target': call_target,
                                            'position': pos,
                                            'line': node.lineno
                                        })
                    arguments.append(arg_info)
                
                call_entry = {
                    'caller_class': self.current_class,
                    'caller_method': self.current_method,
                    'call': call_info,
                    'arguments': arguments,  # NEW: track argument positions
                    'file': self.file_path,
                    'file_relative': self.file_relative,
                    'line': node.lineno,
                    'callee_resolved': False  # Will be resolved in post-processing
                }
                if self.repo_id:
                    call_entry['caller_repo'] = self.repo_id
                self.index['method_calls'].append(call_entry)
                
                # Detect potential cross-repo calls
                # This is a simple heuristic - can be enhanced
                callee_repo = self._detect_callee_repo(call_info)
                if callee_repo and callee_repo != self.repo_id:
                    caller_method_id = f"{self.current_class}.{self.current_method}"
                    callee_method_id = self._extract_callee_method_id(call_info)
                    if callee_method_id:
                        cross_call = _track_cross_repo_call(
                            self.repo_id,
                            callee_repo,
                            caller_method_id,
                            callee_method_id,
                            self.file_path,
                            node.lineno
                        )
                        self.index['cross_repo_calls'].append(cross_call)
        self.generic_visit(node)
    
    def _detect_callee_repo(self, call_info: Dict) -> Optional[str]:
        """
        Detect repository identifier for callee.
        
        Simple heuristic: check if call references an imported module
        that might be from another repo. Override for custom logic.
        
        Args:
            call_info: Call information dictionary
            
        Returns:
            Repository identifier or None
        """
        # TODO: Implement more sophisticated cross-repo detection
        # For now, return None (no cross-repo detection)
        return None
    
    def _extract_callee_method_id(self, call_info: Dict) -> Optional[str]:
        """
        Extract method identifier from call info.
        
        Args:
            call_info: Call information dictionary
            
        Returns:
            Method identifier string or None
        """
        call_type = call_info.get('type')
        if call_type == 'function_call':
            func_name = call_info.get('function')
            return f"{func_name}.__init__" if func_name else None
        elif call_type == 'method_call':
            obj = call_info.get('object')
            method = call_info.get('method')
            if obj and method:
                return f"{obj}.{method}"
        elif call_type == 'nested_method_call':
            path = call_info.get('path', '')
            method = call_info.get('method')
            if path and method:
                return f"{path}.{method}"
        return None
    
    def _get_decorator_name(self, node: ast.AST) -> str:
        """Extract decorator name from ast node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_full_name(node)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id
            elif isinstance(node.func, ast.Attribute):
                return self._get_full_name(node.func)
        return _unparse_ast(node) or '<unknown>'
    
    def _get_full_name(self, node: ast.Attribute) -> str:
        """Get full name of an Attribute node (e.g., 'module.Class')."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return '.'.join(reversed(parts))
    
    def _get_param_kind(self, arg: ast.arg) -> str:
        """Get parameter kind as string."""
        if isinstance(arg, ast.arg):
            # Python 3.8+ has arg.kind
            if hasattr(arg, 'kind'):
                kind_map = {
                    ast.POSITIONAL_ONLY: 'POSITIONAL_ONLY',
                    ast.POSITIONAL_OR_KEYWORD: 'POSITIONAL_OR_KEYWORD',
                    ast.VAR_POSITIONAL: 'VAR_POSITIONAL',
                    ast.KEYWORD_ONLY: 'KEYWORD_ONLY',
                    ast.VAR_KEYWORD: 'VAR_KEYWORD'
                }
                return kind_map.get(arg.kind, 'POSITIONAL_OR_KEYWORD')
        return 'POSITIONAL_OR_KEYWORD'
    
    def _resolve_value_type_ast(self, node: ast.AST) -> Optional[str]:
        """Resolve the type of a value node using ast analysis."""
        if isinstance(node, ast.Call):
            # Function/constructor call
            if isinstance(node.func, ast.Name):
                return node.func.id
            elif isinstance(node.func, ast.Attribute):
                # obj.method() or module.Class()
                return self._get_full_name(node.func)
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_full_name(node)
        elif isinstance(node, ast.Constant):
            return type(node.value).__name__
        return None
    
    def _extract_call_info(self, node: ast.Call) -> Optional[Dict]:
        """Extract information about a method call."""
        if isinstance(node.func, ast.Attribute):
            # obj.method() or self.method()
            if isinstance(node.func.value, ast.Name):
                obj_name = node.func.value.id
                method_name = node.func.attr
                return {
                    'type': 'method_call',
                    'object': obj_name,
                    'method': method_name,
                    'full': f"{obj_name}.{method_name}"
                }
            elif isinstance(node.func.value, ast.Attribute):
                # obj.attr.method()
                return {
                    'type': 'nested_method_call',
                    'path': self._get_full_name(node.func.value),
                    'method': node.func.attr,
                    'full': f"{self._get_full_name(node.func.value)}.{node.func.attr}"
                }
        elif isinstance(node.func, ast.Name):
            # function()
            return {
                'type': 'function_call',
                'function': node.func.id
            }
        return None
    
    def get_index(self) -> Dict[str, Any]:
        """Return the built index."""
        return self.index
    
    def build_index(self, file_path: str, repo_id: Optional[str] = None, repo_url: Optional[str] = None, repo_root: Optional[str] = None) -> Dict[str, Any]:
        """
        Build index for a single Python file using AST.
        
        Args:
            file_path: Path to Python file
            repo_id: Optional repository identifier
            repo_url: Optional repository URL
            repo_root: Optional repository root path for relative path calculation
            
        Returns:
            Class index dictionary
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            builder = EnhancedClassIndexBuilder(file_path, repo_id, repo_url, repo_root)
            builder.visit(tree)
            return builder.get_index()
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}")
            return _empty_index()
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return _empty_index()
    
    def build_index_for_directory(
        self, 
        source_dir: str, 
        repo_id: Optional[str] = None,
        repo_url: Optional[str] = None,
        output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build index for all Python files in a directory.
        
        Args:
            source_dir: Source directory path
            repo_id: Optional repository identifier
            repo_url: Optional repository URL
            output_file: Optional output file path
            
        Returns:
            Merged class index dictionary
        """
        src_path = Path(source_dir)
        python_files = list(src_path.glob('**/*.py'))  # Recursive search
        
        # Find repo root if not provided
        repo_root = _find_repo_root(source_dir)
        
        indices = []
        for py_file in python_files:
            if py_file.name == '__init__.py':
                continue
            idx = self.build_index(str(py_file), repo_id, repo_url, repo_root)
            indices.append(idx)
        
        # Merge indices with batched operations
        merged_index = _empty_index()
        
        # Collect all updates first
        all_classes = {}
        all_functions = {}
        all_imports = {}
        all_inheritance = {}
        all_method_calls = []
        all_files = {}
        all_object_inits = []
        repo_structure = None
        
        for idx in indices:
            all_classes.update(idx.get('classes', {}))
            all_functions.update(idx.get('functions', {}))
            all_imports.update(idx.get('imports', {}))
            all_inheritance.update(idx.get('inheritance', {}))
            all_method_calls.extend(idx.get('method_calls', []))
            all_files.update(idx.get('files', {}))
            all_object_inits.extend(idx.get('object_initializations', []))
            
            # Get repository structure from first index that has it
            if not repo_structure and idx.get('repository'):
                repo_structure = idx['repository']
        
        # Apply all updates at once
        merged_index['classes'] = all_classes
        merged_index['functions'] = all_functions
        merged_index['imports'] = all_imports
        merged_index['inheritance'] = all_inheritance
        merged_index['method_calls'] = all_method_calls
        merged_index['files'] = all_files
        merged_index['object_initializations'] = all_object_inits
        merged_index['repository'] = repo_structure
        
        # Post-process: Resolve callees in call graph
        from holocron.core.resolver import resolve_callee_from_call
        for call_entry in merged_index['method_calls']:
            call_info = call_entry.get('call', {})
            caller_file = call_entry.get('file', '')
            resolved_callee = resolve_callee_from_call(call_info, caller_file, merged_index)
            if resolved_callee:
                call_entry['callee'] = resolved_callee
                call_entry['callee_resolved'] = True
        
        if repo_id:
            merged_index['repositories'][repo_id] = {
                'classes': all_classes,
                'functions': all_functions,
                'imports': all_imports,
                'inheritance': all_inheritance,
                'method_calls': all_method_calls
            }
        
        # Save index if output_file provided
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(merged_index, f, indent=2)
        
        return merged_index


def build_index_with_ast(file_path: str, repo_id: Optional[str] = None, repo_url: Optional[str] = None, repo_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Build index for a single Python file using ast module.
    
    Convenience function that uses the default AST-based indexer.
    
    Args:
        file_path: Path to Python file
        repo_id: Optional repository identifier
        repo_url: Optional repository URL
        repo_root: Optional repository root path
    
    Returns:
        Class index dictionary
    """
    builder = EnhancedClassIndexBuilder(file_path, repo_id, repo_url, repo_root)
    return builder.build_index(file_path, repo_id, repo_url, repo_root)


def _empty_index() -> Dict[str, Any]:
    """Return an empty index structure."""
    return {
        'classes': {},
        'functions': {},
        'imports': {},
        'attributes': {},
        'inheritance': {},
        'method_calls': [],
        'repository': None,
        'repositories': {},
        'cross_repo_calls': [],
        'files': {},  # NEW: per-file exports and metadata
        'object_initializations': []  # NEW: object initialization tracking
    }


def load_index(index_file: str = 'outputs/indices/class_index.json') -> Dict[str, Any]:
    """
    Load the class index from JSON file.
    
    Ensures backward compatibility with old index files that don't have
    repository, repositories, or cross_repo_calls fields.
    
    Args:
        index_file: Path to index JSON file
    
    Returns:
        Class index dictionary with all required fields
    """
    try:
        with open(index_file, 'r') as f:
            index = json.load(f)
        
        # Ensure backward compatibility - add missing fields if not present
        if 'repository' not in index:
            index['repository'] = None
        if 'repositories' not in index:
            index['repositories'] = {}
        if 'cross_repo_calls' not in index:
            index['cross_repo_calls'] = []
        if 'files' not in index:
            index['files'] = {}
        if 'object_initializations' not in index:
            index['object_initializations'] = []
        
        return index
    except FileNotFoundError:
        return _empty_index()


def build_index_for_directory(
    source_dir: str, 
    output_file: str = 'outputs/indices/class_index.json',
    repo_id: Optional[str] = None,
    repo_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build index for all Python files in a directory.
    
    Convenience function that uses the default AST-based indexer.
    
    Args:
        source_dir: Source directory path
        output_file: Output file path
        repo_id: Optional repository identifier
        repo_url: Optional repository URL
    
    Returns:
        Merged class index dictionary
    """
    builder = EnhancedClassIndexBuilder("", repo_id, repo_url)
    return builder.build_index_for_directory(source_dir, repo_id, repo_url, output_file)


# Cross-repo index loading and tracking
_cross_repo_cache: Dict[str, Dict[str, Any]] = {}


def load_cross_repo_index(repo_id: str, base_path: str = 'outputs/indices/repos') -> Optional[Dict[str, Any]]:
    """
    Lazy load a repository index from file.
    
    Caches loaded indices in memory for efficiency.
    
    Args:
        repo_id: Repository identifier
        base_path: Base path for repository indices
        
    Returns:
        Repository index dictionary or None if not found
    """
    if repo_id in _cross_repo_cache:
        return _cross_repo_cache[repo_id]
    
    index_file = Path(base_path) / repo_id / 'class_index.json'
    if not index_file.exists():
        return None
    
    try:
        with open(index_file, 'r') as f:
            index = json.load(f)
        _cross_repo_cache[repo_id] = index
        return index
    except Exception as e:
        print(f"Error loading cross-repo index for {repo_id}: {e}")
        return None


def _track_cross_repo_call(
    caller_repo: Optional[str],
    callee_repo: Optional[str],
    caller_method_id: str,
    callee_method_id: str,
    file_path: str,
    line: int,
    via: str = 'import'
) -> Dict[str, Any]:
    """
    Track a cross-repository call.
    
    Args:
        caller_repo: Repository ID of caller
        callee_repo: Repository ID of callee
        caller_method_id: Method identifier of caller
        callee_method_id: Method identifier of callee
        file_path: File path where call occurs
        line: Line number of call
        via: How the call is made ('import', 'dependency', etc.)
        
    Returns:
        Cross-repo call entry dictionary
    """
    return {
        'caller': f"{caller_repo}:{caller_method_id}" if caller_repo else caller_method_id,
        'callee': f"{callee_repo}:{callee_method_id}" if callee_repo else callee_method_id,
        'via': via,
        'file': file_path,
        'line': line
    }

