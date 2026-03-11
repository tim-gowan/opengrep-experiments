"""CLI entry point for building class index."""

from collections import defaultdict
from holocron.core.indexer import EnhancedClassIndexBuilder, build_index_for_directory


def print_tree_view(index: dict):
    """Print a tree view of the index structure: Repo > File > [Class > method | function].
    
    Args:
        index: Merged index dictionary
    """
    repo_info = index.get('repository')
    if isinstance(repo_info, dict):
        repo_id = repo_info.get('id')
        repo_url = repo_info.get('url')
    else:
        # Backward compatibility: repository might be just a string (repo_id)
        repo_id = repo_info if repo_info else None
        repo_url = None
    
    # Organize by file
    files_data = defaultdict(lambda: {'classes': [], 'functions': []})
    
    # Collect classes by file
    for class_name, class_info in index.get('classes', {}).items():
        file_path = class_info.get('file_relative') or class_info.get('file', 'unknown')
        files_data[file_path]['classes'].append((class_name, class_info))
    
    # Collect functions by file
    for func_name, func_info in index.get('functions', {}).items():
        file_path = func_info.get('file_relative') or func_info.get('file', 'unknown')
        files_data[file_path]['functions'].append((func_name, func_info))
    
    # Print tree structure
    print("\n" + "=" * 80)
    print("INDEX TREE VIEW")
    print("=" * 80)
    
    # Print repository header
    if repo_id:
        repo_display = f"Repository: {repo_id}"
        if repo_url:
            repo_display += f" ({repo_url})"
        print(f"\n{repo_display}")
    else:
        print("\nRepository: (not specified)")
    
    # Print files and their contents
    for file_path in sorted(files_data.keys()):
        file_data = files_data[file_path]
        print(f"\n  📄 File: {file_path}")
        
        # Print classes and their methods
        for class_name, class_info in sorted(file_data['classes'], key=lambda x: x[0]):
            methods = class_info.get('methods', {})
            print(f"    📦 Class: {class_name}")
            for method_name in sorted(methods.keys()):
                method_info = methods[method_name]
                params = method_info.get('params', [])
                params_str = ', '.join(params) if params else ''
                if params_str:
                    print(f"      └─ method: {method_name}({params_str})")
                else:
                    print(f"      └─ method: {method_name}()")
        
        # Print standalone functions
        for func_name, func_info in sorted(file_data['functions'], key=lambda x: x[0]):
            params = func_info.get('params', [])
            params_str = ', '.join(params) if params else ''
            if params_str:
                print(f"    🔧 function: {func_name}({params_str})")
            else:
                print(f"    🔧 function: {func_name}()")
    
    print("\n" + "=" * 80)


def main(args):
    """Main entry point for holocron index command.
    
    Args:
        args: Parsed argparse arguments
    """
    print("=" * 80)
    print("Building Class Index using AST Module")
    print("=" * 80)
    print(f"\nSource directory: {args.source_dir}")
    print(f"Output file: {args.output}")
    repo_id = getattr(args, 'repo_id', None)
    if repo_id:
        print(f"Repository ID: {repo_id}")
    print()
    
    # Use IndexerBase interface
    indexer = EnhancedClassIndexBuilder("", repo_id)
    merged_index = indexer.build_index_for_directory(args.source_dir, repo_id, None, args.output)
    
    print(f"\n✅ Index saved to {args.output}")
    print(f"\n📊 Index Summary:")
    print(f"  Classes: {len(merged_index['classes'])}")
    for class_name in merged_index['classes']:
        methods = len(merged_index['classes'][class_name].get('methods', {}))
        attrs = len(merged_index['classes'][class_name].get('attributes', {}))
        print(f"    - {class_name}: {methods} methods, {attrs} attributes")
    print(f"  Functions: {len(merged_index['functions'])}")
    print(f"  Inheritance relationships: {len(merged_index['inheritance'])}")
    print(f"  Method calls tracked: {len(merged_index['method_calls'])}")
    if repo_id:
        print(f"  Repository: {repo_id}")
    if merged_index.get('cross_repo_calls'):
        print(f"  Cross-repo calls: {len(merged_index['cross_repo_calls'])}")
    
    # Print tree view if verbose flag is set
    if getattr(args, 'verbose', False):
        print_tree_view(merged_index)

