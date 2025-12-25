#!/usr/bin/env python3
"""
Module Dependency Resolver for Test Impact Analysis

This module provides functionality to resolve test module dependencies
that cannot be detected through AST and call stack analysis alone.
"""

import json
import os
import sys
from typing import Dict, List, Set
from collections import deque


class DependencyResolver:
    """Resolves module-level test dependencies from a JSON configuration file."""

    def __init__(self, dependency_file: str):
        """
        Initialize the DependencyResolver.

        Args:
            dependency_file: Path to the test_dependencies.json file
        """
        self.dependency_file = dependency_file
        self.module_dependencies: Dict[str, List[str]] = {}
        self.load_dependencies()

    def load_dependencies(self):
        """Load dependencies from the JSON configuration file."""
        if not os.path.exists(self.dependency_file):
            print(f"Warning: Dependency file '{self.dependency_file}' not found. "
                  f"No additional dependencies will be added.", file=sys.stderr)
            return

        try:
            with open(self.dependency_file, 'r') as f:
                data = json.load(f)
                self.module_dependencies = data.get('module_dependencies', {})

            # Validate and normalize paths
            self._validate_dependencies()

            print(f"Loaded {len(self.module_dependencies)} module dependency rules from {self.dependency_file}",
                  file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in dependency file '{self.dependency_file}': {e}", file=sys.stderr)
            self.module_dependencies = {}
        except Exception as e:
            print(f"Error loading dependency file '{self.dependency_file}': {e}", file=sys.stderr)
            self.module_dependencies = {}

    def _validate_dependencies(self):
        """Validate dependency definitions and detect circular dependencies."""
        # Check for circular dependencies
        cycles = self._detect_cycles()
        if cycles:
            print(f"Warning: Circular dependencies detected: {cycles}", file=sys.stderr)
            print("Circular dependencies will be resolved but may cause excessive test execution.",
                  file=sys.stderr)

        # Normalize paths (ensure consistent format)
        normalized = {}
        for source, targets in self.module_dependencies.items():
            normalized_source = source.strip()
            normalized_targets = [t.strip() for t in targets if t.strip()]
            if normalized_targets:
                normalized[normalized_source] = normalized_targets

        self.module_dependencies = normalized

    def _detect_cycles(self) -> List[List[str]]:
        """
        Detect circular dependencies using DFS.

        Returns:
            List of cycles found (each cycle is a list of module paths)
        """
        cycles = []
        visited = set()
        rec_stack = set()
        path = []

        def dfs(module: str) -> bool:
            """DFS helper to detect cycles."""
            visited.add(module)
            rec_stack.add(module)
            path.append(module)

            for dependent in self.module_dependencies.get(module, []):
                if dependent not in visited:
                    if dfs(dependent):
                        return True
                elif dependent in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(dependent)
                    cycles.append(path[cycle_start:] + [dependent])
                    return True

            path.pop()
            rec_stack.remove(module)
            return False

        for module in self.module_dependencies.keys():
            if module not in visited:
                dfs(module)

        return cycles

    def resolve_dependencies(self, impacted_modules: List[str]) -> Set[str]:
        """
        Resolve transitive dependencies for the given impacted modules.

        Args:
            impacted_modules: List of module paths that were directly impacted by code changes

        Returns:
            Set of all modules including transitive dependencies
        """
        if not self.module_dependencies:
            # No dependencies defined, return input as-is
            return set(impacted_modules)

        all_modules = set(impacted_modules)
        queue = deque(impacted_modules)
        visited = set()

        # BFS to resolve transitive dependencies
        while queue:
            current = queue.popleft()

            if current in visited:
                continue

            visited.add(current)

            # Find all modules that depend on the current module
            dependents = self._find_dependents(current)

            for dependent in dependents:
                if dependent not in all_modules:
                    all_modules.add(dependent)
                    queue.append(dependent)

        added_count = len(all_modules) - len(impacted_modules)
        if added_count > 0:
            print(f"Module dependencies: Added {added_count} additional test modules", file=sys.stderr)
            added_modules = sorted(all_modules - set(impacted_modules))
            for module in added_modules:
                print(f"  + {module}", file=sys.stderr)

        return all_modules

    def _find_dependents(self, module: str) -> List[str]:
        """
        Find all modules that directly depend on the given module.

        Args:
            module: Module path to find dependents for

        Returns:
            List of dependent module paths
        """
        dependents = []

        # Check exact match
        if module in self.module_dependencies:
            dependents.extend(self.module_dependencies[module])

        # Check prefix matches (e.g., "tests/bgp" matches "tests/bgp/test_bgp_fact.py")
        for source, targets in self.module_dependencies.items():
            if module.startswith(source + '/') or module.startswith(source + '.'):
                dependents.extend(targets)

        return dependents


def apply_module_dependencies(impacted_tests: List[str], dependency_file: str) -> List[str]:
    """
    Apply module dependencies to the list of impacted tests.

    Args:
        impacted_tests: List of test file paths that were directly impacted
        dependency_file: Path to test_dependencies.json file

    Returns:
        Extended list of test file paths including dependencies
    """
    resolver = DependencyResolver(dependency_file)
    extended_tests = resolver.resolve_dependencies(impacted_tests)
    return sorted(extended_tests)


if __name__ == '__main__':
    # Standalone testing/demo mode
    # This is only used when running the script directly for testing purposes
    # The actual pipeline integration happens through apply_module_dependencies()

    if len(sys.argv) < 3:
        print("Usage: python dependency_resolver.py <dependency_file> <test_file1> [test_file2] ...",
              file=sys.stderr)
        print("\nExample:", file=sys.stderr)
        print("  python dependency_resolver.py test_dependencies.json tests/bgp/test_bgp_session.py",
              file=sys.stderr)
        sys.exit(1)

    dep_file = sys.argv[1]
    test_files = sys.argv[2:]

    print(f"Input test files: {test_files}", file=sys.stderr)
    print(file=sys.stderr)

    result = apply_module_dependencies(test_files, dep_file)

    print(file=sys.stderr)
    print(f"Final test files ({len(result)}):", file=sys.stderr)
    for test_file in result:
        print(f"  {test_file}", file=sys.stderr)
