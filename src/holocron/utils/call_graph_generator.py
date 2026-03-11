#!/usr/bin/env python3
"""
Language-Agnostic Call Graph Generator.

Supports multiple languages through tree-sitter parsers:
- Python, JavaScript, Java, C, C++, Go, Rust, and more
- Extensible plugin architecture for additional languages
- Falls back to Python AST when tree-sitter unavailable
"""

import argparse
import sys
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
from abc import ABC, abstractmethod


# Try to import tree-sitter (optional)
TREE_SITTER_AVAILABLE = False
try:
    from tree_sitter import Language, Parser, Query, QueryCursor  # type: ignore
    TREE_SITTER_AVAILABLE = True
except ImportError:
    Language = None  # type: ignore
    Parser = None  # type: ignore
    Query = None  # type: ignore
    QueryCursor = None  # type: ignore


class CallGraphExtractor(ABC):
    """Abstract base class for language-specific call graph extractors."""
    
    @abstractmethod
    def extract_calls(self, file_path: Path, source_code: str) -> Dict[str, List[str]]:
        """
        Extract call relationships from source code.
        
        Returns:
            Dictionary mapping caller identifiers to lists of callee identifiers
        """
        pass
    
    @abstractmethod
    def get_language_name(self) -> str:
        """Return the language name this extractor supports."""
        pass
    
    @abstractmethod
    def get_file_extensions(self) -> List[str]:
        """Return list of file extensions this extractor supports."""
        pass


class PythonASTExtractor(CallGraphExtractor):
    """Python call graph extractor using AST (fallback when tree-sitter unavailable)."""
    
    def __init__(self):
        import ast
        self.ast = ast
    
    def get_language_name(self) -> str:
        return "Python"
    
    def get_file_extensions(self) -> List[str]:
        return ['.py']
    
    def extract_calls(self, file_path: Path, source_code: str) -> Dict[str, List[str]]:
        """Extract calls using Python AST."""
        calls = defaultdict(list)
        functions = set()
        classes = set()
        current_function = None
        current_class = None
        class_stack = []
        
        ast_module = self.ast
        
        class Visitor(ast_module.NodeVisitor):
            def __init__(self, calls_dict, functions_set, classes_set):
                self.calls = calls_dict
                self.functions = functions_set
                self.classes = classes_set
                self.current_function = None
                self.current_class = None
                self.class_stack = []
                self.ast = ast_module
            
            def visit_FunctionDef(self, node):
                old_func = self.current_function
                old_class = self.current_class
                
                if self.current_class:
                    func_name = f"{self.current_class}.{node.name}"
                else:
                    func_name = node.name
                
                self.functions.add(func_name)
                self.current_function = func_name
                self.generic_visit(node)
                self.current_function = old_func
                self.current_class = old_class
            
            def visit_ClassDef(self, node):
                old_class = self.current_class
                self.classes.add(node.name)
                self.class_stack.append(node.name)
                self.current_class = node.name
                self.generic_visit(node)
                self.class_stack.pop()
                if self.class_stack:
                    self.current_class = self.class_stack[-1]
                else:
                    self.current_class = old_class
            
            def visit_Call(self, node):
                if not self.current_function:
                    self.generic_visit(node)
                    return
                
                callee = self._extract_callee(node)
                if callee and callee != self.current_function:
                    self.calls[self.current_function].append(callee)
                self.generic_visit(node)
            
            def _extract_callee(self, node):
                if isinstance(node.func, self.ast.Name):
                    return node.func.id
                elif isinstance(node.func, self.ast.Attribute):
                    attr = node.func.attr
                    if isinstance(node.func.value, self.ast.Name):
                        obj = node.func.value.id
                        if obj == 'self' and self.current_class:
                            return f"{self.current_class}.{attr}"
                        return f"{obj}.{attr}"
                return None
        
        try:
            tree = self.ast.parse(source_code, filename=str(file_path))
            visitor = Visitor(calls, functions, classes)
            visitor.visit(tree)
            return dict(calls)
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}", file=sys.stderr)
            return {}


class TreeSitterExtractor(CallGraphExtractor):
    """Language-agnostic extractor using tree-sitter."""
    
    def __init__(self, language_name: str, language_lib: Any):
        if not TREE_SITTER_AVAILABLE or Parser is None or Language is None:
            raise ImportError("tree-sitter is not installed")
        self.language_name = language_name
        # Create Language object from language library
        self.language = Language(language_lib.language())
        self.parser = Parser(self.language)
        self.query = self._build_query()
    
    def _build_query(self) -> Optional[Any]:
        """Build tree-sitter query for function calls (language-specific)."""
        if Query is None:
            return None
            
        # Common query patterns for different languages
        queries = {
            'python': """
                (function_definition
                  name: (identifier) @function.def)
                (class_definition
                  name: (identifier) @class.def)
                (call
                  function: (identifier) @function.call)
                (call
                  function: (attribute) @method.call)
            """,
            'javascript': """
                (function_declaration
                  name: (identifier) @function.def)
                (class_declaration
                  name: (identifier) @class.def)
                (call_expression
                  function: (identifier) @function.call)
                (call_expression
                  function: (member_expression) @method.call)
            """,
            'java': """
                (method_declaration
                  name: (identifier) @function.def)
                (class_declaration
                  name: (identifier) @class.def)
                (method_invocation
                  name: (identifier) @method.call)
            """,
            'c': """
                (function_definition
                  declarator: (function_declarator
                    declarator: (identifier) @function.def))
                (call_expression
                  function: (identifier) @function.call)
            """,
            'cpp': """
                (function_definition
                  declarator: (function_declarator
                    declarator: (identifier) @function.def))
                (class_specifier
                  name: (type_identifier) @class.def)
                (call_expression
                  function: (identifier) @function.call)
            """,
        }
        
        query_str = queries.get(self.language_name.lower())
        if query_str:
            try:
                return Query(self.language, query_str)
            except Exception:
                return None
        return None
    
    def get_language_name(self) -> str:
        return self.language_name
    
    def get_file_extensions(self) -> List[str]:
        """Map language to file extensions."""
        ext_map = {
            'python': ['.py'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx'],
            'java': ['.java'],
            'c': ['.c', '.h'],
            'cpp': ['.cpp', '.cc', '.cxx', '.hpp', '.hxx'],
            'go': ['.go'],
            'rust': ['.rs'],
        }
        return ext_map.get(self.language_name.lower(), [])
    
    def extract_calls(self, file_path: Path, source_code: str) -> Dict[str, List[str]]:
        """Extract calls using tree-sitter queries."""
        calls = defaultdict(list)
        functions: Dict[Any, str] = {}  # node -> function_name
        classes: Dict[Any, str] = {}  # node -> class_name
        function_nodes: Dict[str, Any] = {}  # function_name -> node
        
        try:
            tree = self.parser.parse(bytes(source_code, 'utf8'))
            root_node = tree.root_node
            
            # Use query if available for more accurate extraction
            if self.query and QueryCursor is not None:
                query_cursor = QueryCursor(self.query)
                captures = query_cursor.captures(root_node)
                
                # Process captures
                for node, capture_name in captures:
                    if capture_name == 'function.def':
                        func_name = self._get_node_text(node)
                        functions[node] = func_name
                        function_nodes[func_name] = node
                    elif capture_name == 'class.def':
                        class_name = self._get_node_text(node)
                        classes[node] = class_name
                    elif capture_name in ['function.call', 'method.call']:
                        callee_name = self._get_node_text(node)
                        # Find the containing function
                        containing_func = self._find_containing_function(node, functions)
                        if containing_func:
                            calls[containing_func].append(callee_name)
            else:
                # Fallback to manual traversal
                self._traverse_tree(root_node, functions, classes, calls)
            
            return dict(calls)
            
        except Exception as e:
            print(f"Error parsing {file_path} with tree-sitter: {e}", file=sys.stderr)
            return {}
    
    def _get_node_text(self, node) -> str:
        """Extract text from a node."""
        if hasattr(node, 'text'):
            return node.text.decode('utf8')
        return ''
    
    def _find_containing_function(self, node: Any, functions: Dict[Any, str]) -> Optional[str]:
        """Find the function that contains this node."""
        current = node.parent
        while current:
            if current in functions:
                return functions[current]
            current = current.parent
        return None
    
    def _traverse_tree(self, node: Any, functions: Dict[Any, str], classes: Dict[Any, str], 
                       calls: Dict[str, List[str]], current_func: Optional[str] = None, 
                       current_class: Optional[str] = None) -> None:
        """Fallback tree traversal when queries aren't available."""
        # Track function definitions
        if node.type in ['function_definition', 'function_declaration', 'method_declaration']:
            name_node = node.child_by_field_name('name')
            if not name_node:
                # Try to find identifier child
                for child in node.children:
                    if child.type in ['identifier', 'type_identifier']:
                        name_node = child
                        break
            
            if name_node:
                func_name = self._get_node_text(name_node)
                if current_class:
                    func_name = f"{current_class}.{func_name}"
                functions[node] = func_name
                current_func = func_name
        
        # Track class definitions
        if node.type in ['class_definition', 'class_declaration']:
            name_node = node.child_by_field_name('name')
            if not name_node:
                for child in node.children:
                    if child.type in ['identifier', 'type_identifier']:
                        name_node = child
                        break
            
            if name_node:
                class_name = self._get_node_text(name_node)
                classes[node] = class_name
                current_class = class_name
        
        # Track calls
        if node.type in ['call', 'call_expression', 'method_invocation']:
            if current_func:
                callee = self._extract_callee_name(node)
                if callee:
                    calls[current_func].append(callee)
        
        # Recursively traverse children
        for child in node.children:
            self._traverse_tree(child, functions, classes, calls, current_func, current_class)
    
    def _extract_callee_name(self, node: Any) -> Optional[str]:
        """Extract callee name from call node."""
        func_node = node.child_by_field_name('function')
        if not func_node:
            # Try to find function in children
            for child in node.children:
                if child.type in ['identifier', 'attribute', 'member_expression']:
                    func_node = child
                    break
        
        if func_node:
            return self._get_node_text(func_node)
        return None


class CallGraphGenerator:
    """Language-agnostic call graph generator."""
    
    def __init__(self):
        self.all_calls: Dict[str, List[str]] = defaultdict(list)
        self.all_functions: Set[str] = set()
        self.all_classes: Set[str] = set()
        self.file_mapping: Dict[str, str] = {}
        self.extractors: Dict[str, CallGraphExtractor] = {}
        self._initialize_extractors()
    
    def _initialize_extractors(self):
        """Initialize available extractors."""
        # Tree-sitter extractors (preferred when available)
        if TREE_SITTER_AVAILABLE and Parser is not None and Language is not None:
            # Python via tree-sitter
            try:
                import tree_sitter_python as tspython  # type: ignore
                extractor = TreeSitterExtractor('python', tspython)
                for ext in extractor.get_file_extensions():
                    self.extractors[ext] = extractor
            except ImportError:
                pass
            
            # Add more tree-sitter languages as needed
            # Example for JavaScript:
            # try:
            #     import tree_sitter_javascript as tsjs
            #     extractor = TreeSitterExtractor('javascript', tsjs)
            #     for ext in extractor.get_file_extensions():
            #         self.extractors[ext] = extractor
            # except ImportError:
            #     pass
        
        # Python AST (fallback when tree-sitter unavailable)
        if '.py' not in self.extractors:
            try:
                py_extractor = PythonASTExtractor()
                for ext in py_extractor.get_file_extensions():
                    self.extractors[ext] = py_extractor
            except:
                pass
    
    def _get_extractor(self, file_path: Path) -> Optional[CallGraphExtractor]:
        """Get appropriate extractor for file extension."""
        ext = file_path.suffix.lower()
        return self.extractors.get(ext)
    
    def analyze_file(self, file_path: Path) -> None:
        """Analyze a single file."""
        extractor = self._get_extractor(file_path)
        if not extractor:
            print(f"No extractor available for {file_path.suffix} files", file=sys.stderr)
            return
        
        try:
            source = file_path.read_text(encoding='utf8')
            calls = extractor.extract_calls(file_path, source)
            
            # Merge results
            for caller, callees in calls.items():
                self.all_functions.add(caller)
                self.file_mapping[caller] = str(file_path)
                for callee in callees:
                    if callee not in self.all_calls[caller]:
                        self.all_calls[caller].append(callee)
                        self.all_functions.add(callee)
                        
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}", file=sys.stderr)
    
    def analyze_path(self, path: Path) -> None:
        """Analyze a path (file or directory)."""
        if path.is_file():
            self.analyze_file(path)
        elif path.is_dir():
            # Find files with supported extensions
            for ext in self.extractors.keys():
                for file_path in path.rglob(f'*{ext}'):
                    self.analyze_file(file_path)
        else:
            print(f"Path does not exist: {path}", file=sys.stderr)
    
    def generate_dot(self, output_file: Optional[Path] = None) -> str:
        """Generate DOT format call graph."""
        lines = ['digraph G {']
        
        # Add all nodes
        all_nodes = self.all_functions | self.all_classes
        for node in sorted(all_nodes):
            lines.append(f'  "{node}";')
        
        lines.append('')
        
        # Add edges
        for caller in sorted(self.all_calls.keys()):
            for callee in sorted(self.all_calls[caller]):
                lines.append(f'  "{caller}" -> "{callee}";')
        
        lines.append('}')
        
        dot_content = '\n'.join(lines)
        
        if output_file:
            output_file.write_text(dot_content, encoding='utf8')
            print(f"Call graph written to {output_file}")
        else:
            print(dot_content)
        
        return dot_content
    
    def generate_json(self, output_file: Optional[Path] = None) -> str:
        """Generate JSON format call graph."""
        graph = {
            'nodes': sorted(list(self.all_functions | self.all_classes)),
            'edges': [
                {'from': caller, 'to': callee}
                for caller in sorted(self.all_calls.keys())
                for callee in sorted(self.all_calls[caller])
            ],
            'functions': sorted(list(self.all_functions)),
            'classes': sorted(list(self.all_classes)),
            'file_mapping': self.file_mapping
        }
        
        json_content = json.dumps(graph, indent=2)
        
        if output_file:
            output_file.write_text(json_content, encoding='utf8')
            print(f"Call graph written to {output_file}")
        else:
            print(json_content)
        
        return json_content


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Language-agnostic call graph generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single Python file
  python call_graph_generator.py src/benchmark/BenchmarkTest00001.py
  
  # Multiple files (different languages)
  python call_graph_generator.py file1.py file2.js file3.java
  
  # Directory
  python call_graph_generator.py src/
  
  # Output to file
  python call_graph_generator.py src/ -o call_graph.dot
  
  # JSON format
  python call_graph_generator.py src/ -f json -o call_graph.json
        """
    )
    
    parser.add_argument(
        'inputs',
        nargs='*',
        type=Path,
        help='File(s) or directory path(s) to analyze'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file path (default: stdout)'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['dot', 'json'],
        default='dot',
        help='Output format: dot (Graphviz) or json (default: dot)'
    )
    
    parser.add_argument(
        '--list-languages',
        action='store_true',
        help='List supported languages and exit'
    )
    
    args = parser.parse_args()
    
    generator = CallGraphGenerator()
    
    if args.list_languages:
        print("Supported languages:")
        seen = set()
        for ext, extractor in generator.extractors.items():
            lang = extractor.get_language_name()
            if lang not in seen:
                print(f"  - {lang}: {', '.join(extractor.get_file_extensions())}")
                seen.add(lang)
        return
    
    if not args.inputs:
        parser.error("At least one input file or directory is required (use --list-languages to see supported languages)")
    
    # Process all inputs
    for input_path in args.inputs:
        generator.analyze_path(input_path)
    
    # Generate output
    if args.format == 'dot':
        generator.generate_dot(args.output)
    else:
        generator.generate_json(args.output)


if __name__ == '__main__':
    main()
