import ast
import argparse
import os
import sys
import pathlib
import logging
import json

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stderr)  # Use stderr to avoid contaminating JSON output
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


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


def is_pytest_fixture(node):
    """
    Check if a function node is a pytest fixture.
    Returns True if the function has @pytest.fixture decorator.
    """
    if not isinstance(node, ast.FunctionDef):
        return False

    for decorator in node.decorator_list:
        # Handle @pytest.fixture or @pytest.fixture(...)
        if isinstance(decorator, ast.Name) and decorator.id == 'fixture':
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr == 'fixture':
            return True
        if isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name) and decorator.func.id == 'fixture':
                return True
            if isinstance(decorator.func, ast.Attribute) and decorator.func.attr == 'fixture':
                return True
    return False


def get_fixture_dependencies(node):
    """
    Get the list of fixtures that this fixture depends on.
    Returns a set of fixture names used as parameters.
    """
    if not isinstance(node, ast.FunctionDef):
        return set()

    dependencies = set()
    for arg in node.args.args:
        # Skip 'self', 'cls', 'request' which are special parameters
        if arg.arg not in ['self', 'cls', 'request']:
            dependencies.add(arg.arg)

    return dependencies


def build_fixture_dependency_graph(python_files):
    """
    Build a dependency graph of all fixtures.
    Returns a dictionary: {fixture_name: set of fixtures it depends on}
    """
    fixture_graph = {}

    for py_file in python_files:
        try:
            with open(py_file, 'r') as f:
                tree = ast.parse(f.read())

            for node in tree.body:
                if is_pytest_fixture(node):
                    fixture_name = node.name
                    dependencies = get_fixture_dependencies(node)

                    if fixture_name in fixture_graph:
                        fixture_graph[fixture_name].update(dependencies)
                    else:
                        fixture_graph[fixture_name] = dependencies.copy()

        except (SyntaxError, FileNotFoundError) as e:
            logger.debug(f'Error parsing file {py_file}: {e}')
            continue

    return fixture_graph


def find_dependent_fixtures(fixture_name, fixture_graph):
    """
    Find all fixtures that directly or indirectly depend on the given fixture.
    Uses recursive tracing to find the complete dependency chain.

    Args:
        fixture_name: The name of the fixture that was changed
        fixture_graph: Dictionary mapping fixture names to their dependencies

    Returns:
        Set of fixture names that depend on the given fixture
    """
    dependent_fixtures = set()
    visited = set()

    def helper(current_fixture):
        if current_fixture in visited:
            return
        visited.add(current_fixture)

        # Find all fixtures that depend on current_fixture
        for fixture, dependencies in fixture_graph.items():
            if current_fixture in dependencies:
                dependent_fixtures.add(fixture)
                helper(fixture)  # Recursively find fixtures depending on this one

    helper(fixture_name)
    return dependent_fixtures


def find_tests_using_fixture(fixture_name, python_files, fixture_graph=None):
    """
    Find all test files that use the given pytest fixture, including indirect usage
    through fixture dependency chains.

    Args:
        fixture_name: The name of the fixture to search for
        python_files: List of Python files to search
        fixture_graph: Optional fixture dependency graph. If provided, will also
                      find tests using fixtures that depend on fixture_name.

    Returns:
        Set of test file paths that use the fixture directly or indirectly
    """
    # Find all fixtures that depend on the changed fixture
    fixtures_to_check = {fixture_name}
    if fixture_graph:
        dependent_fixtures = find_dependent_fixtures(fixture_name, fixture_graph)
        fixtures_to_check.update(dependent_fixtures)
        logger.debug(f'Fixture {fixture_name} has {len(dependent_fixtures)} dependent fixtures: {dependent_fixtures}')

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
                        # Check if test uses any of the fixtures in our chain
                        if arg.arg in fixtures_to_check:
                            affected_test_files.add(py_file)
                            logger.debug(f'Test {node.name} in {py_file} uses fixture {arg.arg}')
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

    logger.debug(f'Function Name: {args.function_name}')
    logger.debug(f'Directory: {args.directory}')

    # find all python files
    python_files = find_python_files(args.directory)
    logger.debug(f'Scanning {len(python_files)} python files in {args.directory}')

    # Build fixture dependency graph
    logger.debug('Building fixture dependency graph...')
    fixture_graph = build_fixture_dependency_graph(python_files)
    logger.debug(f'Found {len(fixture_graph)} fixtures in dependency graph')

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

    # Check if the function_name is a fixture (with fixture dependency graph)
    fixture_test_files = find_tests_using_fixture(args.function_name, python_files, fixture_graph)
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
