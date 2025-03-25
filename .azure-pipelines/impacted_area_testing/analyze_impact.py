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
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))
    return python_files


def get_called_functions(node):
    """
    Returns a set of functions that this function calls
    """
    function_calls = set()
    for sub_node in ast.walk(node):
        if isinstance(sub_node, ast.Call):
            if isinstance(sub_node.func, ast.Name):
                called_function = sub_node.func.id
                function_calls.add(called_function)
            elif isinstance(sub_node.func, ast.Attribute) and isinstance(sub_node.func.value, ast.Name):
                called_function = sub_node.func.attr
                function_calls.add(called_function)
    return function_calls


def find_function_calls(filepath):
    """
    Find all function calls in a given file. The
    function scans the file and looks for ast.FunctionDef
    and ast.Call nodes. If ast.FunctionDef is found it visits
    that node and looks for all the function this function calls.
    It returns a dictionary like this -
    {
        'func_name_1': ('func_a', 'func_b', 'func_c')
        'func_name_2': ('func_d', 'func_e')
    }
    """
    function_calls = {}
    tree = None
    with open(filepath, 'r') as file:
        try:
            tree = ast.parse(file.read())
        except SyntaxError as e:
            logger.error(f'Error parsing file {filepath}: {e}')
            return function_calls

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            # logger.debug(f'Analyzing function {node.name}')
            called_functions = get_called_functions(node)
            function_calls[node.name] = called_functions

    # logger.debug(f'{filepath} function calls: {function_calls}')
    return function_calls


def find_dependent_functions(function_name, function_calls):
    """
    Find all functions that directly or indirectly call the
    given function_name

    To do that we need to traverse function_calls.
    1. For each function in function_calls check if
       the called functions is the function_name.
    2. If it is the add it to dependent functions list/set
    3. Add the visited function to a visited set to avoid revisiting.
    """
    dependent_functions = set()
    visited_functions = set()

    def find_dependent_functions_helper(func_name):
        if func_name in visited_functions:
            return
        visited_functions.add(func_name)
        for f, calls in function_calls.items():
            if func_name in calls:
                dependent_functions.add(f)
                find_dependent_functions_helper(f)

    find_dependent_functions_helper(function_name)
    return dependent_functions


def find_tests_using_fixture(fixture_name, python_files):
    """
    Find all test files that use the given pytest fixture.
    """
    affected_test_files = set()
    for py_file in python_files:
        with open(py_file, 'r') as file:
            try:
                tree = ast.parse(file.read())
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

    # CAVEAT
    # this holds the function name and all the functions it calls
    # note - if there is a function name that has the same name
    # let's say across multiple files
    # then merge the calls just to get a broader set (though it is not accurate)
    function_calls = {}
    function_calls_per_file = {}
    for py_file in python_files:
        f_calls = find_function_calls(py_file)
        for func_name, called_functions in f_calls.items():
            if func_name in function_calls:
                function_calls[func_name].update(called_functions)
            else:
                function_calls[func_name] = called_functions.copy()
        function_calls_per_file[py_file] = f_calls.keys()

    dependent_functions = find_dependent_functions(args.function_name, function_calls)
    # print(f'Functions that depend on {args.function_name}: {dependent_functions}')

    affected_files = set()
    for func in dependent_functions:
        for file, functions in function_calls_per_file.items():
            if func in functions:
                affected_files.add(file)
                break

    affected_test_files = set()
    for file in affected_files:
        p = pathlib.Path(file)
        if p.name.startswith('test'):
            affected_test_files.add(file)

    # if the function_name is a fixture.
    fixture_test_files = find_tests_using_fixture(args.function_name, python_files)
    affected_test_files.update(fixture_test_files)

    # if the function_name is a test function
    if args.function_name.startswith('test'):
        for file, functions in function_calls_per_file.items():
            if args.function_name in functions:
                affected_test_files.add(file)

    impacted_files = {
        'total_scanned': len(python_files),
        'number_of_impacted_tests': len(affected_test_files),
        'tests': list(affected_test_files)
    }
    print(json.dumps(impacted_files, indent=4))
