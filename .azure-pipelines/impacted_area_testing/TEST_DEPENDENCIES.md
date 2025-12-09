# Test Module Dependencies

This document describes how to define module-level test dependencies for the impact area testing system.

## Overview

The impact area testing system uses AST and call stack analysis to automatically detect which tests are affected by code changes. However, some test dependencies cannot be detected through static analysis alone. This is where the `test_dependencies.json` file comes in - it allows you to manually define additional dependencies between test modules.

## When to Use Module Dependencies

Use module dependencies when:

1. **Domain Logic Dependencies**: Tests in one module logically depend on functionality tested in another module, even if there's no direct code reference
   - Example: ACL tests may affect forwarding behavior tests
   - Example: BGP route changes may impact FIB lookup tests

2. **Integration Dependencies**: Tests that should run together due to integration relationships
   - Example: When VLAN tests change, also run L2 forwarding tests
   - Example: When interface configuration tests change, also run link state tests

3. **Prerequisite Testing**: Some tests validate prerequisites for other tests
   - Example: Basic connectivity tests before running advanced feature tests

## File Structure

The `test_dependencies.json` file contains a single object with a `module_dependencies` key:

```json
{
  "module_dependencies": {
    "source_module_path": ["dependent_module_path1", "dependent_module_path2"],
    "another_source": ["dependent_module"]
  }
}
```

### Structure Explanation

- **`module_dependencies`**: An object mapping source modules to their dependent modules
  - **Key** (source module): A module or test file path that, when changed, should trigger additional tests
  - **Value** (dependent modules): An array of module or test file paths that should also be tested

## Path Formats

You can specify dependencies at different granularity levels:

1. **Test File Level**: `"tests/bgp/test_bgp_fact.py"` (exact file match)
2. **Module Directory Level**: `"tests/acl"` (matches all files under tests/acl/)
3. **Submodule Level**: `"tests/platform/mellanox"` (matches all files under tests/platform/mellanox/)

### How Matching Works

The system uses **flexible prefix matching** for dependency keys:

- **Exact Match**: If a key exactly matches an impacted file, the dependency applies
  - Key: `"tests/bgp/test_bgp_fact.py"` matches file: `tests/bgp/test_bgp_fact.py`

- **Prefix Match**: If an impacted file starts with a key followed by `/` or `.`, the dependency applies
  - Key: `"tests/bgp"` matches files: `tests/bgp/test_bgp_session.py`, `tests/bgp/test_bgp_fact.py`, etc.
  - Key: `"tests/platform/mellanox"` matches files: `tests/platform/mellanox/test_thermal.py`, etc.

This means you can use **directory-level keys** to apply dependencies to any file within that directory, making configuration more maintainable.

**Important**: Dependency values (targets) are added to the test list as-is. If you specify a directory in the value list, that exact directory path will be added (and will later match any tests in that directory during categorization).

## Examples

### Example 1: Specific File to Specific File

When `test_bgp_fact.py` changes, also run a specific FIB test:

```json
{
  "module_dependencies": {
    "tests/bgp/test_bgp_fact.py": ["tests/fib/test_fib.py"]
  }
}
```

**How it works**: Only when `tests/bgp/test_bgp_fact.py` is impacted, `tests/fib/test_fib.py` is added.

### Example 2: Directory to Directory (Most Common)

When **any** BGP test changes, run **all** FIB tests:

```json
{
  "module_dependencies": {
    "tests/bgp": ["tests/fib"]
  }
}
```

**How it works**:
- If `tests/bgp/test_bgp_session.py` is impacted → adds `tests/fib` to the test list
- If `tests/bgp/test_bgp_fact.py` is impacted → adds `tests/fib` to the test list
- The `tests/fib` directory will match all FIB tests during test categorization

### Example 3: Directory to Multiple Specific Files

When **any** ACL test changes, run specific forwarding and SAI tests:

```json
{
  "module_dependencies": {
    "tests/acl": [
      "tests/forwarding/test_forward.py",
      "tests/sai/test_acl_sai.py"
    ]
  }
}
```

**How it works**: Any file in `tests/acl/` triggers both specific test files to be added.

### Example 4: Multiple Dependencies with Mixed Granularity

When BGP tests change, run both a directory of FIB tests and a specific route test:

```json
{
  "module_dependencies": {
    "tests/bgp": [
      "tests/fib",
      "tests/route/test_static_route.py"
    ]
  }
}
```

**How it works**: Any BGP test triggers all FIB tests (via directory) plus one specific route test.

### Example 5: Transitive Dependencies

The system automatically resolves transitive dependencies:

```json
{
  "module_dependencies": {
    "tests/bgp": ["tests/fib"],
    "tests/fib": ["tests/forwarding"]
  }
}
```

**How it works**: If `tests/bgp/test_bgp_fact.py` changes:
1. Prefix match: `tests/bgp/test_bgp_fact.py` starts with `tests/bgp/` → adds `tests/fib`
2. Transitive: `tests/fib` is now in the list → adds `tests/forwarding`
3. Final result: All three module directories are in the test list

### Example 6: Complex Real-World Scenario

```json
{
  "module_dependencies": {
    "tests/acl": [
      "tests/forwarding/test_forward.py",
      "tests/sai/test_acl_sai.py"
    ],
    "tests/vlan": [
      "tests/forwarding/test_l2_forward.py"
    ],
    "tests/bgp": [
      "tests/fib/test_fib.py",
      "tests/route/test_static_route.py"
    ],
    "tests/platform/mellanox": [
      "tests/platform/test_platform_info.py"
    ]
  }
}
```

## Important Notes

### Circular Dependencies

The system detects circular dependencies and warns you, but still processes them without infinite loops:

```json
{
  "module_dependencies": {
    "tests/module_a": ["tests/module_b"],
    "tests/module_b": ["tests/module_a"]
  }
}
```

**Warning**: Circular dependencies can cause both modules to always run together. Consider if this is intentional.

### Path Validation

- The system normalizes paths (removes extra whitespace)
- If the dependency file doesn't exist, the pipeline continues without errors
- Invalid JSON will generate warnings but won't fail the pipeline

## Testing Your Changes

To test your dependency configuration locally:

```bash
cd .azure-pipelines/impacted_area_testing
python dependency_resolver.py test_dependencies.json tests/bgp/test_bgp_fact.py
```

This will show you which additional tests would be triggered.

### Example Test Session

```bash
$ python dependency_resolver.py test_dependencies.json tests/bgp/test_bgp_session.py
Input test files: ['tests/bgp/test_bgp_session.py']

Loaded 1 module dependency rules from test_dependencies.json
Module dependencies: Added 1 additional test modules
  + tests/fib

Final test files (2):
  tests/bgp/test_bgp_session.py
  tests/fib
```

This shows that:
1. The input was `tests/bgp/test_bgp_session.py`
2. It matched the dependency key `tests/bgp` (via prefix matching)
3. Added `tests/fib` to the output

## Integration with Impact Area Testing

The dependency resolution is automatically integrated into the Azure Pipelines impact area testing workflow:

1. AST and call stack analysis detects directly impacted tests
2. Dependency resolver adds additional tests based on `test_dependencies.json`
3. Combined test list is categorized by topology
4. Tests are executed in the appropriate pipeline jobs
