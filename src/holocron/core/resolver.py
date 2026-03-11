"""Resolution functions for attributes and inheritance."""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple


def is_version_compatible(
    src_version: Optional[str],
    snk_version: Optional[str],
    method_signature: Optional[Dict] = None
) -> bool:
    """
    Check if versions are compatible for stitching.
    
    TODO: Implement fuzzy hashing mechanism for version compatibility.
    For now, returns True if versions match exactly or both are None.
    
    Args:
        src_version: Source version string (e.g., "v1.2.3")
        snk_version: Sink version string (e.g., "v1.2.3")
        method_signature: Optional method signature dictionary for signature-based matching
        
    Returns:
        True if versions are compatible, False otherwise
    """
    if src_version is None or snk_version is None:
        return True  # No version info, assume compatible
    
    # Exact match
    if src_version == snk_version:
        return True
    
    # TODO: Implement fuzzy matching:
    # - Semantic versioning compatibility (same major version)
    # - Signature hash comparison
    # - Method signature compatibility checking
    
    return False


def resolve_attribute_with_index(obj_path: str, index: Dict[str, Any]) -> Optional[str]:
    """
    Resolve an attribute path like 'testclass0002.class0001' to a class name.
    
    Uses the class index to resolve object.attribute paths to their actual
    class types by looking up attribute assignments in the AST.
    
    Args:
        obj_path: Object path like 'testclass0002.class0001'
        index: Class index dictionary
    
    Returns:
        Resolved class name or None if not found
    
    Example:
        >>> resolve_attribute_with_index('testclass0002.class0001', index)
        'TestClass0001'
    """
    parts = obj_path.split('.')
    
    if len(parts) == 1:
        # Just an object name - check if it's a class
        if parts[0] in index['classes']:
            return parts[0]
        return None
    
    # Multi-part path: obj.attr
    obj_name = parts[0]
    attr_name = parts[1]
    
    # Find class that has this attribute
    for class_name, class_info in index['classes'].items():
        if attr_name in class_info.get('attributes', {}):
            attr_info = class_info['attributes'][attr_name]
            for attr in attr_info:
                attr_type = attr.get('type')
                if attr_type and attr_type in index['classes']:
                    return attr_type
                # Also check if it's a constructor call
                if attr_type and '(' in str(attr_type):
                    class_part = str(attr_type).split('(')[0]
                    if class_part in index['classes']:
                        return class_part
    
    return None


def resolve_inheritance_with_index(class_name: str, index: Dict[str, Any]) -> List[str]:
    """
    Resolve inheritance chain using the index.
    
    Returns all parent classes (including transitive parents) for a given class.
    
    Args:
        class_name: Name of the class
        index: Class index dictionary
    
    Returns:
        List of parent class names (empty if none found)
    
    Example:
        >>> resolve_inheritance_with_index('sub_class_0002', index)
        ['TestClass0001']
    """
    if class_name not in index['inheritance']:
        return []
    
    parents = []
    to_process = [class_name]
    processed = set()
    
    while to_process:
        current = to_process.pop(0)
        if current in processed:
            continue
        processed.add(current)
        
        if current in index['inheritance']:
            for parent in index['inheritance'][current].get('parents', []):
                if parent not in parents:
                    parents.append(parent)
                    to_process.append(parent)
    
    return parents


def resolve_import_to_file(
    imported_name: str,
    from_module: Optional[str],
    importer_file: str,
    index: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Resolve an import to its source file using the export index.
    
    Args:
        imported_name: Name of the imported item (class or function)
        from_module: Module path from 'from X import Y' (None for 'import X')
        importer_file: File path where the import occurs
        index: Class index dictionary with exports
    
    Returns:
        Dictionary with resolved information:
        {
            'source_file': 'path/to/file.py',
            'source_file_relative': 'path/to/file.py',
            'exported_name': 'ClassName',
            'resolved': True
        }
        or None if not found
    """
    files = index.get('files', {})
    
    # Search through all files for the exported name
    for file_path, file_info in files.items():
        exports = file_info.get('exports', [])
        if imported_name in exports:
            return {
                'source_file': file_info.get('file'),  # Absolute path if available
                'source_file_relative': file_path,
                'exported_name': imported_name,
                'resolved': True
            }
    
    # If not found in exports, try to resolve using module path
    if from_module:
        # Try to find file matching module path
        module_parts = from_module.split('.')
        # Look for files with matching module structure
        for file_path, file_info in files.items():
            file_parts = file_path.replace('/', '.').replace('\\', '.').split('.')
            # Check if module parts match file path
            if len(module_parts) <= len(file_parts):
                if file_parts[-len(module_parts):] == module_parts:
                    return {
                        'source_file': file_info.get('file'),
                        'source_file_relative': file_path,
                        'exported_name': imported_name,
                        'resolved': True
                    }
    
    return None


def resolve_all_imports(index: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Resolve all imports in the index to their source files.
    
    This is a post-processing step that uses the export index to resolve
    imports that were tracked during indexing.
    
    Args:
        index: Class index dictionary
    
    Returns:
        Dictionary mapping import keys to resolved information:
        {
            'module_name': {
                'imports': {
                    'ImportedName': {
                        'source_file': '...',
                        'source_file_relative': '...',
                        'exported_name': '...',
                        'resolved': True
                    }
                }
            }
        }
    """
    resolved_imports = {}
    imports = index.get('imports', {})
    files = index.get('files', {})
    
    for module_key, import_list in imports.items():
        if module_key not in resolved_imports:
            resolved_imports[module_key] = {'imports': {}}
        
        for imp in import_list:
            imported_name = imp.get('asname') or imp.get('name')
            from_module = imp.get('from_module')
            importer_file = imp.get('file')
            
            if imported_name:
                resolved = resolve_import_to_file(
                    imported_name,
                    from_module,
                    importer_file,
                    index
                )
                
                if resolved:
                    resolved_imports[module_key]['imports'][imported_name] = resolved
                else:
                    # Mark as unresolved
                    resolved_imports[module_key]['imports'][imported_name] = {
                        'resolved': False,
                        'from_module': from_module,
                        'importer_file': importer_file
                    }
    
    return resolved_imports


def resolve_callee_from_call(
    call: Dict[str, Any],
    caller_file: str,
    index: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Resolve a callee from a call using import resolution.
    
    Args:
        call: Call information dictionary from method_calls
        caller_file: File where the call occurs
        index: Class index dictionary
    
    Returns:
        Resolved callee information:
        {
            'repo': 'repo_id',
            'file': 'source_file',
            'file_relative': 'source_file_relative',
            'class': 'ClassName',
            'method': 'method_name',
            'resolved': True
        }
        or None if not resolved
    """
    call_type = call.get('type')
    resolved_imports = resolve_all_imports(index)
    
    if call_type == 'function_call':
        func_name = call.get('function')
        if func_name:
            # Try to find in exports
            files = index.get('files', {})
            for file_path, file_info in files.items():
                exports = file_info.get('exports', [])
                if func_name in exports:
                    # Check if it's a class (constructor call)
                    if func_name in index.get('classes', {}):
                        return {
                            'file': file_info.get('file'),
                            'file_relative': file_path,
                            'class': func_name,
                            'method': '__init__',
                            'resolved': True
                        }
                    # Or a function
                    elif func_name in index.get('functions', {}):
                        return {
                            'file': file_info.get('file'),
                            'file_relative': file_path,
                            'function': func_name,
                            'resolved': True
                        }
    
    elif call_type == 'method_call':
        obj_name = call.get('object')
        method_name = call.get('method')
        
        # Try to resolve object to class
        if obj_name and method_name:
            # Check if obj is 'self' or a parameter
            # For now, try to find method in current file's classes
            # This is a simplified resolution
            classes = index.get('classes', {})
            for class_name, class_info in classes.items():
                methods = class_info.get('methods', {})
                if method_name in methods:
                    method_info = methods[method_name]
                    # Check if it's in the same file as caller
                    if method_info.get('file') == caller_file:
                        return {
                            'file': method_info.get('file'),
                            'file_relative': method_info.get('file_relative'),
                            'class': class_name,
                            'method': method_name,
                            'resolved': True
                        }
    
    elif call_type == 'nested_method_call':
        path = call.get('path', '')
        method_name = call.get('method')
        
        # Try to resolve nested path (e.g., 'self.processor')
        if path and method_name:
            # Extract attribute name from path
            parts = path.split('.')
            if len(parts) >= 2:
                attr_name = parts[-1]
                # Find class with this attribute
                for class_name, class_info in index.get('classes', {}).items():
                    attrs = class_info.get('attributes', {})
                    if attr_name in attrs:
                        attr_info = attrs[attr_name]
                        for attr in attr_info:
                            attr_type = attr.get('type')
                            if attr_type and attr_type in index.get('classes', {}):
                                # Found the class, now find the method
                                target_class = index['classes'][attr_type]
                                methods = target_class.get('methods', {})
                                if method_name in methods:
                                    method_info = methods[method_name]
                                    return {
                                        'file': method_info.get('file'),
                                        'file_relative': method_info.get('file_relative'),
                                        'class': attr_type,
                                        'method': method_name,
                                        'resolved': True
                                    }
    
    return None

