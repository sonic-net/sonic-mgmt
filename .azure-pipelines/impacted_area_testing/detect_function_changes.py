"""
AST-based impacted test detector used by CI.

High-level flow:
1. Read changed files from git diff (`target_branch...feature_branch`).
2. Map changed lines to Python functions using AST line ranges.
3. For each changed function, ask `analyze_impact.py` to find dependent tests.
4. Independently detect non-function changes (imports, dynamic imports, globals).
5. Escalate to full-suite execution for high-impact conditions
    (infrastructure files, autouse fixture changes, risky import patterns, conftest changes).
6. Apply static module dependency expansion from `test_dependencies.json`.
7. Emit compact JSON to stdout for pipeline consumption.
"""

import argparse
import subprocess
import os
import ast
import logging
import json
import sys
from dependency_resolver import apply_module_dependencies

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def map_lines_to_functions(file_path):
    """
    Build a line-to-function lookup for a Python file.

    The mapping includes decorator lines so decorator-only edits (for example
    changing `@pytest.fixture(autouse=True)`) are still attributed to the
    underlying function.

    Args:
        file_path: Python file path in the workspace.

    Returns:
        Dict[int, str]: `line_number -> function_name`.
        Returns an empty dict if the file cannot be parsed.
    """
    line_to_function = {}
    try:
        with open(file_path, 'r') as file:
            tree = ast.parse(file.read(), filename=file_path)
    except SyntaxError as e:
        logger.error(f"Error parsing file {file_path}: {e}")
        return line_to_function

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start_line = node.lineno
            if node.decorator_list:
                start_line = min(dec.lineno for dec in node.decorator_list)

            end_line = getattr(node, 'end_lineno', node.lineno)
            for i in range(start_line, end_line + 1):
                line_to_function[i] = node.name

    return line_to_function


def get_changed_new_lines(file_path, target_branch, feature_branch):
    """
    Parse unified git diff and return changed line numbers on the "new" side.

    This function tracks hunk positions (`@@ -old,+new @@`) and advances old/new
    cursors line-by-line to compute exact line numbers in the feature branch
    version. That precision avoids the common pitfall of guessing changed ranges.

    Why this matters:
    - Function attribution depends on exact new-file line numbers.
    - Decorator-only and small edits are easy to miss with coarse heuristics.

    Args:
        file_path: File path to diff.
        target_branch: Base branch ref (for example `origin/master`).
        feature_branch: Head ref/sha being analyzed.

    Returns:
        Tuple[Set[int], str]:
            - set of changed line numbers in the new file
            - raw diff text (used by higher-level non-function scanners)
    """
    try:
        diff_output = subprocess.check_output(
            ["git", "diff", f"{target_branch}...{feature_branch}", "--", file_path],
            universal_newlines=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running git diff for {file_path}: {e}")
        return set(), ""

    changed_new_lines = set()
    old_line = None
    new_line = None

    for line in diff_output.splitlines():
        if line.startswith("@@"):
            try:
                parts = line.split(" ")
                old_range = parts[1]  # -<start>,<count>
                new_range = parts[2]  # +<start>,<count>
                old_line = int(old_range[1:].split(",")[0])
                new_line = int(new_range[1:].split(",")[0])
            except (IndexError, ValueError):
                old_line = None
                new_line = None
            continue

        if old_line is None or new_line is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            changed_new_lines.add(new_line)
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            old_line += 1
        else:
            old_line += 1
            new_line += 1

    return changed_new_lines, diff_output


def get_changed_functions(file_path, target_branch, feature_branch):
    """
    Determine which functions were touched in a file between two revisions.

    Strategy:
    - Compute exact changed new-file lines from git diff.
    - Map those lines to function definitions from AST.

    Args:
        file_path: Python file being analyzed.
        target_branch: Base branch ref.
        feature_branch: Head ref/sha.

    Returns:
        List[str]: Unique function names with at least one changed line.
    """
    # Map line numbers to functions
    line_to_function = map_lines_to_functions(file_path)
    changed_functions = set()
    changed_new_lines, _ = get_changed_new_lines(file_path, target_branch, feature_branch)

    for line_number in changed_new_lines:
        function_name = line_to_function.get(line_number)
        if function_name:
            changed_functions.add(function_name)

    return list(changed_functions)


def get_changed_non_function_parts(file_path, target_branch, feature_branch):
    """
    Detect top-level/non-call-graph-sensitive changes in a Python file.

    The call-graph analyzer is excellent for function-body changes, but some
    changes impact runtime behavior without explicit call edges. This function
    captures those classes of changes from diff text:
    - import statements (`import`, `from ... import ...`)
    - dynamic import patterns (`importlib`, `__import__`, module spec loading)
    - global assignments

    Args:
        file_path: Python file being analyzed.
        target_branch: Base branch ref.
        feature_branch: Head ref/sha.

    Returns:
        Dict[str, List[str]] with keys:
        - `imports`
        - `globals`
        - `dynamic_imports`
    """
    changed_new_lines, diff_output = get_changed_new_lines(file_path, target_branch, feature_branch)
    if diff_output == "" and not changed_new_lines:
        return {"imports": [], "globals": [], "dynamic_imports": []}

    changed_imports = set()
    changed_globals = set()
    changed_dynamic_imports = set()

    for line in diff_output.splitlines():
        if (line.startswith("+") and not line.startswith("+++")) or (line.startswith("-") and not line.startswith("---")):  # noqa: E501
            stripped_line = line[1:].strip()
            if stripped_line.startswith("import ") or stripped_line.startswith("from "):
                changed_imports.add(stripped_line)
            if (
                "importlib.import_module(" in stripped_line
                or "__import__(" in stripped_line
                or "importlib.util.spec_from_file_location(" in stripped_line
            ):
                changed_dynamic_imports.add(stripped_line)
            elif "=" in stripped_line and not stripped_line.startswith("def ") and not stripped_line.startswith("class "):  # noqa: E501
                # Detect global variable assignments
                changed_globals.add(stripped_line.split("=")[0].strip())

    return {
        "imports": list(changed_imports),
        "globals": list(changed_globals),
        "dynamic_imports": list(changed_dynamic_imports)
    }


def invoke_analyze_impact(function_name, directory, trace=False):
    """
    Execute `analyze_impact.py` for one changed function and parse JSON output.

    This keeps function-level dependency logic isolated in `analyze_impact.py`
    while this script focuses on diff interpretation and CI decisions.

    Args:
        function_name: Changed function to analyze.
        directory: Root directory to scan (typically `tests`).
        trace: Enable verbose analyzer logging.

    Returns:
        Dict/None: Parsed analyzer response, or `None` on subprocess failure.
    """
    script_path = os.path.join(os.path.dirname(__file__), "analyze_impact.py")
    command = ["python", script_path, "--function_name", function_name, "--directory", directory]
    if trace:
        command.append("--trace")

    try:
        output = subprocess.check_output(command, universal_newlines=True)
        logger.info(f"Output for function {function_name}:\n{output}")
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running analyze_impact.py for {function_name}: {e}")
        return None


def is_infrastructure_file(file_path):
    """
    Decide whether a changed file should force full-suite execution.

    Infrastructure files can alter broad test execution semantics, so they are
    treated as global-impact changes and bypass fine-grained call-graph routing.

    Note: tests/common is NOT included here because AST-based analysis
    can precisely detect which tests depend on changed common code.
    """
    # Directories that are considered infrastructure
    infrastructure_dirs = [
        "ansible/",
        "tests/scripts/"
    ]

    # Critical shell scripts that affect test execution
    infrastructure_scripts = [
        "tests/run_tests.sh",
        "setup-container.sh"
    ]

    # Exclude changes to impacted_area_testing itself (would cause infinite recursion)
    if file_path.startswith(".azure-pipelines/impacted_area_testing/"):
        return False

    # Check if file is in an infrastructure directory
    for infra_dir in infrastructure_dirs:
        if file_path.startswith(infra_dir):
            return True

    # Check if file is a critical infrastructure script
    if file_path in infrastructure_scripts:
        return True

    return False


def has_autouse_fixture(file_path, function_name):
    """
    Check if the named function is a pytest fixture with `autouse=True`.

    Autouse fixtures can implicitly affect many or all tests, so any detected
    change is treated as high impact and can trigger full-suite selection.

    Args:
        file_path: Python file containing the candidate function.
        function_name: Function name identified from changed lines.

    Returns:
        bool: True if the function is an autouse fixture, else False.
    """
    try:
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read())

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
                # Check if it has @pytest.fixture decorator
                for decorator in node.decorator_list:
                    # Handle @pytest.fixture(autouse=True)
                    if isinstance(decorator, ast.Call):
                        if (hasattr(decorator.func, 'attr') and decorator.func.attr == 'fixture') or \
                           (hasattr(decorator.func, 'id') and decorator.func.id == 'fixture'):
                            # Check for autouse=True in keywords
                            for keyword in decorator.keywords:
                                if keyword.arg != 'autouse':
                                    continue

                                is_true_autouse = (
                                    isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                                ) or (
                                    hasattr(ast, 'NameConstant')
                                    and isinstance(keyword.value, ast.NameConstant)
                                    and keyword.value.value is True
                                )

                                if is_true_autouse:
                                    return True
    except (SyntaxError, FileNotFoundError) as e:
        logger.error(f"Error checking autouse fixture in {file_path}: {e}")

    return False


def collect_all_tests(directory):
    """
    Collect all discoverable test files under the target directory.

    This is used by conservative fallback paths (global-impact changes) where
    precision is intentionally traded for safety.

    Args:
        directory: Root test directory to walk.

    Returns:
        List[str]: Paths to `test_*.py` files, excluding helper-only folders.
    """
    all_tests = []
    tests_path = directory

    for root, dirs, files in os.walk(tests_path):
        # Skip common and scripts directories as they're not test suites
        if 'common' in root or 'scripts' in root:
            continue

        for file in files:
            if file.startswith("test_") and file.endswith(".py"):
                # Get relative path from current directory
                full_path = os.path.join(root, file)
                all_tests.append(full_path)

    return all_tests


def is_conftest_file(file_path):
    """
    Check whether the changed file is a pytest `conftest.py`.

    `conftest.py` can alter fixture behavior for large test scopes, therefore
    it is treated as high-impact in the main decision flow.
    """
    return os.path.basename(file_path) == "conftest.py"


def validate_python_syntax(file_path):
    """
    Validate that a Python source file can be parsed.

    This guard is used as a CI safety check. If a modified Python file has
    invalid syntax, impact analysis is unreliable and we fall back to running
    the full test suite.

    Args:
        file_path: Path to a Python source file.

    Returns:
        Tuple[bool, str]:
            - True/False indicating parse success
            - Empty string on success, or parse error message on failure
    """
    try:
        with open(file_path, 'r') as f:
            ast.parse(f.read(), filename=file_path)
        return True, ""
    except (SyntaxError, FileNotFoundError) as e:
        return False, str(e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect changed functions and invoke analyze_impact.py.")
    parser.add_argument("--modified_files", type=str, nargs="+", required=True, help="List of modified files.")
    parser.add_argument("--feature_branch", type=str, required=True, help="Feature branch name.")
    parser.add_argument("--target_branch", type=str, required=True, help="Target branch name.")
    parser.add_argument("--directory", type=str, required=True, help="Directory to analyze.")
    parser.add_argument("--trace", action="store_true", help="Enable trace logging.")
    parser.add_argument("--no-log", action="store_true", help="Disable logging.")
    parser.add_argument("--dependency_file", type=str,
                        default=os.path.join(os.path.dirname(__file__), "test_dependencies.json"),
                        help="Path to test_dependencies.json file.")

    args = parser.parse_args()

    if args.no_log:
        logger.disabled = True
    elif args.trace:
        logger.setLevel(logging.DEBUG)

    logger.info(f"Modified files: {args.modified_files}")
    logger.info(f"Feature branch: {args.feature_branch}")
    logger.info(f"Target branch: {args.target_branch}")

    # Safety guard: if any modified Python file has syntax errors,
    # skip fine-grained analysis and run full suite.
    syntax_errors = []
    for file_path in args.modified_files:
        if not file_path.endswith('.py'):
            continue

        is_valid, error_msg = validate_python_syntax(file_path)
        if not is_valid:
            syntax_errors.append((file_path, error_msg))

    if syntax_errors:
        logger.error("Syntax error detected in modified Python file(s). Falling back to full test suite.")
        for file_path, error_msg in syntax_errors:
            logger.error(f"  - {file_path}: {error_msg}")
        all_tests = collect_all_tests(args.directory)
        consolidated_results = {"tests": all_tests, "others": []}
        logger.info(f"Collected {len(all_tests)} tests from full test suite")
        print(json.dumps(consolidated_results, separators=(',', ':')))
        sys.exit(0)

    # Check if any infrastructure files were modified
    has_infrastructure_changes = any(is_infrastructure_file(f) for f in args.modified_files)

    if has_infrastructure_changes:
        logger.info("Infrastructure files detected. Running full test suite.")
        # Collect all tests
        all_tests = collect_all_tests(args.directory)
        consolidated_results = {"tests": all_tests, "others": []}
        logger.info(f"Collected {len(all_tests)} tests from full test suite")

        # Skip individual file analysis and dependency resolution for infrastructure changes
        # Print compressed JSON (single line)
        print(json.dumps(consolidated_results, separators=(',', ':')))
        sys.exit(0)

    consolidated_results = {"tests": [], "others": []}

    for file_path in args.modified_files:
        if not file_path.endswith(".py"):
            logger.debug(f"Skipping non-Python file: {file_path}")
            continue

        logger.info(f"Analyzing file: {file_path}")
        changed_functions = get_changed_functions(file_path, args.target_branch, args.feature_branch)

        if not changed_functions:
            logger.info(f"No changed functions detected in {file_path}.")
        else:
            for function_name in changed_functions:
                # Check if this is an autouse fixture - if so, run all tests
                if has_autouse_fixture(file_path, function_name):
                    logger.info(f"Detected autouse fixture '{function_name}' in {file_path}. Running full test suite.")
                    all_tests = collect_all_tests(args.directory)
                    consolidated_results = {"tests": all_tests, "others": []}
                    logger.info(f"Collected {len(all_tests)} tests from full test suite")
                    # Print compressed JSON to avoid Azure Pipelines truncation bug
                    print(json.dumps(consolidated_results, separators=(',', ':')))
                    sys.exit(0)

                logger.info(f"Invoking analyze_impact.py for function: {function_name}")
                result = invoke_analyze_impact(function_name, args.directory, args.trace)
                if result and result.get('tests'):
                    for test in result['tests']:
                        if test.startswith("tests"):
                            consolidated_results["tests"].append(test)
                        else:
                            consolidated_results["others"].append(test)

        # Detect changes to imports and global variables
        changed_non_function_parts = get_changed_non_function_parts(file_path, args.target_branch, args.feature_branch)
        if (
            changed_non_function_parts["imports"]
            or changed_non_function_parts["globals"]
            or changed_non_function_parts["dynamic_imports"]
        ):
            logger.info(f"File {file_path} has changes in non-function parts.")
            should_run_full_suite = (
                is_conftest_file(file_path)
                or bool(changed_non_function_parts["dynamic_imports"])
                or bool(changed_non_function_parts["imports"] and not file_path.startswith("tests"))
            )

            if should_run_full_suite:
                logger.info(
                    f"Detected high-impact import/dynamic-import/conftest change in {file_path}. "
                    "Running full test suite."
                )
                all_tests = collect_all_tests(args.directory)
                consolidated_results = {"tests": all_tests, "others": []}
                print(json.dumps(consolidated_results, separators=(',', ':')))
                sys.exit(0)

            if file_path.startswith("tests"):
                consolidated_results["tests"].append(file_path)
            else:
                consolidated_results["others"].append(file_path)

            if changed_non_function_parts["imports"]:
                logger.info(f"Changed imports in {file_path}: {changed_non_function_parts['imports']}")
            if changed_non_function_parts["dynamic_imports"]:
                logger.info(f"Changed dynamic imports in {file_path}: {changed_non_function_parts['dynamic_imports']}")
            if changed_non_function_parts["globals"]:
                logger.info(f"Changed global variables in {file_path}: {changed_non_function_parts['globals']}")

    # Remove duplicates from the consolidated results
    consolidated_results["tests"] = list(set(consolidated_results["tests"]))
    consolidated_results["others"] = list(set(consolidated_results["others"]))

    # Apply module dependencies to expand the test list
    if consolidated_results["tests"]:
        logger.info(f"Applying module dependencies from {args.dependency_file}")
        original_count = len(consolidated_results["tests"])
        consolidated_results["tests"] = apply_module_dependencies(
            consolidated_results["tests"],
            args.dependency_file
        )
        logger.info(f"Test count after dependencies: {len(consolidated_results['tests'])} (was {original_count})")

    # Print compressed JSON (single line)
    print(json.dumps(consolidated_results, separators=(',', ':')))
