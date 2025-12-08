import ast
import argparse
import os
import sys
import pathlib
import logging
import json

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)


def find_python_files(directory):
    """
    Recursively find all python files in a given directory.
    Args:
        directory (str): The path to the directory.
    Returns:
        list: A list of file paths.
    """
    python_files = []
    for root, _, files in os.walk(directory):
        for script in files:
            if script.endswith(".py"):
                python_files.append(os.path.join(root, script))
    return python_files


def get_called_methods_or_functions(node):
    """
    Returns a set of functions or methods that this function or method calls.
    """
    calls = set()
    for sub_node in ast.walk(node):
        if isinstance(sub_node, ast.Call):
            if isinstance(sub_node.func, ast.Name):  # Function call
                calls.add(sub_node.func.id)
            elif isinstance(sub_node.func, ast.Attribute):  # Method call
                calls.add(sub_node.func.attr)
    return calls


def find_function_and_method_calls(filepath):
    """
    Find all function and method calls in a given file.
    Returns a dictionary like this:
    {
        'func_name_1': {'func_a', 'func_b', 'func_c'},
        'ClassName.method_name': {'func_d', 'func_e'}
    }
    """
    function_calls = {}
    ast_tree = None
    with open(filepath, 'r') as py_file:
        try:
            ast_tree = ast.parse(py_file.read())
        except SyntaxError as e:
            logger.error(f'Error parsing file {filepath}: {e}')
            return function_calls

    for ast_node in ast.walk(ast_tree):
        if isinstance(ast_node, ast.FunctionDef):  # Standalone function
            function_calls[ast_node.name] = get_called_methods_or_functions(ast_node)
        elif isinstance(ast_node, ast.ClassDef):  # Class with methods
            for class_node in ast_node.body:
                if isinstance(class_node, ast.FunctionDef):  # Method in class
                    method_name = f"{ast_node.name}.{class_node.name}"
                    function_calls[method_name] = get_called_methods_or_functions(class_node)

    return function_calls


def find_dependent_functions_and_methods(function_name, calls):
    """
    Find all functions and methods that directly or indirectly call the given function_name.
    """
    dependent_items = set()
    visited_items = set()

    def helper(item_name):
        if item_name in visited_items:
            return
        visited_items.add(item_name)
        for caller, callee_set in calls.items():
            if item_name in callee_set:
                dependent_items.add(caller)
                helper(caller)

    helper(function_name)
    return dependent_items


def find_tests_using_fixture(fixture_name, python_files):
    """
    Find all test files that use the given pytest fixture.
    """
    affected_test_files = set()
    for py_file in python_files:
        with open(py_file, 'r') as f:
            try:
                tree = ast.parse(f.read())
            except SyntaxError as e:
                logger.error(f'Error parsing file {py_file}: {e}')
                continue

            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and node.name.startswith('test'):
                    for arg in node.args.args:
                        if arg.arg == fixture_name:
                            affected_test_files.add(py_file)
                            break
    return affected_test_files


if __name__ == '__main__':
    description = """Given a function name and directory containing python files,
find all functions that directly or indirectly call the given function or use the given fixture."""
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument('--function_name',
                        type=str,
                        required=True, help='The name of the function or fixture to check dependencies for.')
    parser.add_argument('--directory',
                        type=str,
                        required=True,
                        help='The path to the directory containing python files.')
    parser.add_argument('--trace', action='store_true', help='Enable trace logging.')

    args = parser.parse_args()
    if args.trace:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.debug('Function Name:', args.function_name)
    logger.debug('Directory:', args.directory)

    # find all python files
    python_files = find_python_files(args.directory)
    logger.debug(f'Scanning {len(python_files)} python files in {args.directory}')

    # Update to handle both functions and methods
    function_calls = {}
    function_calls_per_file = {}
    for py_file in python_files:
        file_function_calls = find_function_and_method_calls(py_file)
        for func_name, called_items in file_function_calls.items():
            if func_name in function_calls:
                function_calls[func_name].update(called_items)
            else:
                function_calls[func_name] = called_items.copy()
        function_calls_per_file[py_file] = file_function_calls.keys()

    dependent_items = find_dependent_functions_and_methods(args.function_name, function_calls)

    affected_files = set()
    for item in dependent_items:
        for file_path, function_items in function_calls_per_file.items():
            if item in function_items:
                affected_files.add(file_path)
                break

    affected_test_files = set()
    for file_path in affected_files:
        p = pathlib.Path(file_path)
        if p.name.startswith('test'):
            affected_test_files.add(file_path)

    # Check if the function_name is a fixture
    fixture_test_files = find_tests_using_fixture(args.function_name, python_files)
    affected_test_files.update(fixture_test_files)

    # Check if the function_name is a test function
    if args.function_name.startswith('test'):
        for file_path, function_items in function_calls_per_file.items():
            if args.function_name in function_items:
                affected_test_files.add(file_path)

    impacted_files = {
        'total_scanned': len(python_files),
        'number_of_impacted_tests': len(affected_test_files),
        'tests': list(affected_test_files)
    }
    print(json.dumps(impacted_files, indent=4))
