#!/usr/bin/env python3
"""
Coverage checker script for individual modules.
This script checks coverage for each module individually and enforces minimum thresholds.
"""

import argparse
import os
import re
import subprocess
import sys
from typing import List, Tuple


def run_command(cmd: List[str]) -> Tuple[str, int]:
    """Run a command and return output and exit code."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout.strip(), result.returncode
    except (subprocess.SubprocessError, OSError) as e:
        return f"Error running command: {e}", 1


def get_coverage_for_module(module_path: str) -> float:
    """Get coverage percentage for a specific module."""
    cmd = ["python3", "-m", "coverage", "report", f"--include={module_path}"]
    output, returncode = run_command(cmd)

    if returncode != 0:
        print(f"Warning: Could not get coverage for {module_path}")
        return 0.0

    # Parse coverage output to extract percentage
    lines = output.strip().split("\n")
    for line in lines:
        if module_path in line and "%" in line:
            # Extract percentage from line like: "routing/bgp/bgp_route_control.py    100    0   100%"
            match = re.search(r"(\d+)%", line)
            if match:
                return float(match.group(1))

    return 0.0


def get_all_modules() -> List[str]:
    """Get list of all Python modules recursively, excluding utility scripts and tests."""
    modules = []
    excluded_files = {"check_coverage.py", "setup.py", "conftest.py"}
    excluded_dirs = {"unit_tests", ".pytest_cache", "htmlcov", "__pycache__"}

    for root, dirs, files in os.walk("."):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in excluded_dirs]

        for file in files:
            if (
                file.endswith(".py")
                and not file.startswith("_")
                and not file.startswith("test_")
                and file != "__init__.py"
                and file not in excluded_files
            ):
                # Get relative path from current directory
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, ".")
                modules.append(relative_path)
    return modules


def check_coverage(modules: List[str], min_coverage: float) -> bool:
    """Check coverage for all modules and return True if all meet minimum threshold.

    Args:
        modules: List of module names to check
        min_coverage: Minimum coverage percentage required
    """
    if not os.path.exists(".coverage"):
        print("Error: No .coverage file found. Run tests with coverage first.")
        return False

    all_passed = True
    results: List[Tuple[str, float, bool]] = []

    for module_path in modules:
        coverage_pct = get_coverage_for_module(module_path)
        passed = coverage_pct >= min_coverage
        results.append((module_path, coverage_pct, passed))

        if not passed:
            all_passed = False

    # Print results
    print(f"Coverage Report (minimum: {min_coverage}%)")
    print("=" * 50)

    for module_path, coverage_pct, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{module_path:<35} {coverage_pct:>6.1f}% {status}")

    print("=" * 50)

    if all_passed:
        print("🎉 All modules meet minimum coverage requirements!")
        return True

    failed_modules = [module_path for module_path, _, passed in results if not passed]
    print(f"💥 {len(failed_modules)} module(s) failed coverage requirements:")
    for module_path in failed_modules:
        print(f"   - {module_path}")
    return False


def main() -> int:
    """Main function to parse arguments and run coverage checks."""
    parser = argparse.ArgumentParser(description="Check coverage for individual modules")
    parser.add_argument(
        "--min-coverage", type=float, default=80.0, help="Minimum coverage percentage required (default: 80)"
    )
    parser.add_argument("--modules", nargs="*", help="Specific modules to check (default: all)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.modules:
        modules = args.modules
    else:
        modules = get_all_modules()

    if not modules:
        print("No modules found to check coverage for.")
        return 0

    success = check_coverage(modules, args.min_coverage)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
