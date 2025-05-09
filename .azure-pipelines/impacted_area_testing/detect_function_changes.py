import argparse
import subprocess
import os
import ast
import logging
import json

logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def map_lines_to_functions(file_path):
    """
    Map each line number in a Python file to the function it belongs to.
    """
    line_to_function = {}
    try:
        with open(file_path, 'r') as file:
            tree = ast.parse(file.read(), filename=file_path)
    except SyntaxError as e:
        logger.error(f"Error parsing file {file_path}: {e}")
        return line_to_function

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for i in range(node.lineno, getattr(node, 'end_lineno', node.lineno + 1)):
                line_to_function[i] = node.name

    return line_to_function


def get_changed_functions(file_path, target_branch, feature_branch):
    """
    Get the list of functions that have changed in a Python file between two branches.
    """
    try:
        # Get the diff of the file between the two branches
        diff_output = subprocess.check_output(
            ["git", "diff", f"{target_branch}...{feature_branch}", "--", file_path],
            universal_newlines=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running git diff for {file_path}: {e}")
        return []

    # Map line numbers to functions
    line_to_function = map_lines_to_functions(file_path)
    changed_functions = set()

    # Parse the diff output to find changed lines
    for line in diff_output.splitlines():
        if line.startswith("@@"):  # Diff hunk header
            # Extract the line range from the hunk header
            parts = line.split(" ")
            if len(parts) > 2:
                line_info = parts[2]  # Example: "+12,5"
                if line_info.startswith("+"):
                    start_line = int(line_info[1:].split(",")[0])
                    for i in range(start_line, start_line + 5):  # Assume 5 lines in the hunk
                        if i in line_to_function:
                            changed_functions.add(line_to_function[i])
        elif line.startswith("+") or line.startswith("-"):  # Detect changes
            # Use the line number to find the function it belongs to
            # This is handled by the hunk header logic above
            continue

    return list(changed_functions)


def invoke_analyze_impact(function_name, directory, trace=False):
    """
    Invoke the analyze_impact.py script for a given function name.
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect changed functions and invoke analyze_impact.py.")
    parser.add_argument("--modified_files", type=str, nargs="+", required=True, help="List of modified files.")
    parser.add_argument("--feature_branch", type=str, required=True, help="Feature branch name.")
    parser.add_argument("--target_branch", type=str, required=True, help="Target branch name.")
    parser.add_argument("--directory", type=str, required=True, help="Directory to analyze.")
    parser.add_argument("--trace", action="store_true", help="Enable trace logging.")

    args = parser.parse_args()

    if args.trace:
        logger.setLevel(logging.DEBUG)

    logger.info(f"Modified files: {args.modified_files}")
    logger.info(f"Feature branch: {args.feature_branch}")
    logger.info(f"Target branch: {args.target_branch}")

    for file_path in args.modified_files:
        if not file_path.endswith(".py"):
            logger.debug(f"Skipping non-Python file: {file_path}")
            continue

        logger.info(f"Analyzing file: {file_path}")
        changed_functions = get_changed_functions(file_path, args.target_branch, args.feature_branch)

        if not changed_functions:
            logger.info(f"No changed functions detected in {file_path}.")
            continue

        for function_name in changed_functions:
            logger.info(f"Invoking analyze_impact.py for function: {function_name}")
            result = invoke_analyze_impact(function_name, args.directory, args.trace)
            if result:
                logger.info(f"Impact analysis result for {function_name}:\n{json.dumps(result, indent=4)}")
