# Impacted Area Testing

## TL;DR

**Problem:** PR testing originally ran ~570 tests for every change, costing $35/PR and $23,000/month.

**Evolution:**
1. **Phase 1 (Original):** Run all tests → Expensive, slow
2. **Phase 2 (Previous):** Run all tests in changed directory (e.g., all `tests/bgp/` for any change there) → Better, but still wasteful
3. **Phase 3 (Current):** **AST-based analysis** - Only run tests that actually call the changed functions → Precise, fast, cost-effective

**Current Approach:** Uses Abstract Syntax Tree (AST) parsing + call stack tracing + fixture dependency graphs to find exactly which tests are impacted by your code changes.

**To test locally:** `cd .azure-pipelines/impacted_area_testing && ./test_locally.sh`

---

## Overview

This directory contains the implementation of **AST-based Impact Analysis** for sonic-mgmt PR testing. The system uses Abstract Syntax Tree analysis, call stack tracing, and fixture dependency graphs to determine precisely which tests are affected by code changes, significantly reducing PR test execution time and resource costs.

## Evolution of PR Testing in sonic-mgmt

### Phase 1: Full Test Suite (Original Approach)
In the original PR testing process, a **fixed set of ~570 test scripts** was executed for every PR, regardless of the scope of changes.

**Problems:**
- **Time:** Excessive runtime requiring maximum execution time limits
- **Cost:** Required 20 instances for t0 and 25 instances for t1 topologies
- **Expense:** $35 per PR, approximately **$23,000 per month**
- **Inflexibility:** New tests had to be added manually; couldn't adapt to change scope
- **Waste:** Even a single-line change triggered the full test suite

### Phase 2: Directory-Based Impacted Area Testing (Previous Approach)
To address the cost and time issues, **directory-based impacted area testing** was introduced.

**How it worked:**
- Changes in `tests/bgp/` → Run all tests in `tests/bgp/`
- Changes in `tests/common/` → Run all tests (shared component)
- Changes in infrastructure files → Run all tests

**Code Structure:**
```
sonic-mgmt
     | - .azure-pipelines
     | - ansible
     | - docs
     | - tests
           | - common      ---------- shared
           | - arp         -----|
           | - ecmp             | --- features
           | - vlan             |
           | - ......      -----|
```

**Classification:**
- **Shared/Infrastructure:** `.azure-pipelines`, `ansible`, `docs`, `tests/common/` → Full test suite
- **Feature-specific:** `tests/bgp/`, `tests/acl/`, etc. → Tests in that directory only

**Improvements:**
- Reduced test scope for feature-specific changes
- Automatic test collection based on directory
- Dynamic instance allocation based on test count
- Significant cost savings compared to Phase 1

**Limitations:**
- Still ran many unnecessary tests (entire directory for any change)
- No granular analysis of which specific tests were actually affected
- Couldn't distinguish between changing a utility function vs a test function

### Phase 3: AST-Based Impact Analysis (Current Implementation)
The current design uses **Abstract Syntax Tree (AST) analysis** with call stack and dependency graph tracing for precise test selection.

**How it works:
**Key improvements:**
- **Function-level analysis:** Detects which specific functions changed
- **Call stack tracing:** Recursively finds all callers of changed functions
- **Fixture dependency graph:** Traces pytest fixture dependencies (direct and indirect)
- **Autouse fixture detection:** Changes to autouse fixtures trigger full suite
- **Infrastructure file detection:** Ansible, scripts still trigger full suite appropriately
- **Module dependencies:** Manual dependency definitions via configuration

**Results:**
- **Precision:** Only runs tests actually affected by the code change
- **Speed:** Reduced test execution time
- **Cost:** Significant resource and cost savings
- **Accuracy:** Fewer false negatives compared to directory-based approach

## Current Design: AST-Based Impact Analysis

### How It Works

Instead of analyzing at the directory level, the new approach analyzes code changes at the **function level**:

1. **Detect Changed Functions**: For each modified Python file, parse the git diff to identify which specific functions were changed
2. **Call Stack Analysis**: Use AST parsing to build a call graph and determine which test functions depend on the changed functions
3. **Fixture Dependency Analysis**: Detect pytest fixture usage to find tests that indirectly depend on changed code through fixtures
4. **Module Dependency Resolution**: Apply manually-defined module dependencies for logical relationships that cannot be detected through code analysis

### Key Components

- **`detect_function_changes.py`**:
  - Parses git diffs to identify changed functions in modified files
  - Detects changes to imports and global variables
  - Invokes impact analysis for each changed function
  - Applies module dependencies to expand the test list

- **`analyze_impact.py`**:
  - Builds a call graph using AST analysis
  - Traces which test functions call the changed functions (direct or indirect)
  - Tracks fixture dependencies to find tests using affected fixtures
  - Returns a list of impacted test files

- **`categorize_test_scripts_by_topology.py`**:
  - Groups impacted test files by topology type (t0, t1, t2, etc.)
  - Ensures tests are distributed to the correct PR checker jobs

- **`dependency_resolver.py`**:
  - Loads manually-defined module dependencies from `test_dependencies.json`
  - Resolves transitive dependencies automatically
  - Detects and handles circular dependencies
  - See `TEST_DEPENDENCIES.md` for usage documentation

### Infrastructure File Handling

The system has two different strategies for handling changes:

#### 1. Full Test Suite Execution (Infrastructure Changes)

When certain infrastructure files are modified, **the full test suite is executed** because the impact cannot be reliably determined through code analysis:

**Infrastructure Directories:**
- `ansible/` - Ansible playbooks and roles used in test execution
- `tests/scripts/` - Common test scripts and shell utilities

**Critical Infrastructure Scripts:**
- `tests/run_tests.sh` - Main test execution script
- `setup-container.sh` - Test environment setup

**Behavior:** If **any** infrastructure file changes → Run **all tests** (full suite)

#### 2. AST-Based Impact Analysis (Code Changes)

For all other changes, including Python code under `tests/`, the system uses AST and call stack analysis to determine precise impact:

**Handled by AST Analysis:**
- `tests/conftest.py` - Root-level pytest fixtures and configuration
  - Fixture changes: AST detects which tests use the fixture, including indirect dependencies through fixture chains
  - **Fixture dependency tracing:** If Fixture A depends on Fixture B, changing Fixture B finds all tests using Fixture A
  - Hook changes: AST traces function calls to find affected tests
  - **Special case - Autouse fixtures:** If a fixture has `autouse=True`, changing it triggers the full test suite
    - 12 autouse fixtures identified: `enhance_inventory`, `reset_critical_services_list`, `tag_test_report`, etc.
    - These fixtures run automatically for all tests, so changes affect all tests
  - Example: Changing `duthosts` fixture → Runs only the 301 tests that use `duthosts`
  - Example: Changing `enhance_inventory` (autouse) → Runs all 574 tests
  - Example: Fixture chain `base → middle → top`, changing `base` → Runs tests using `base`, `middle`, and `top`
- `tests/common/` - Shared utilities, helpers, and fixtures
  - AST analysis traces which tests call changed functions
  - Fixture dependency tracking identifies tests using changed fixtures
  - Only runs tests that actually depend on the changed code
- `tests/<feature>/` - Feature-specific test files
  - Analyzes function calls and dependencies
  - Applies module dependencies from `test_dependencies.json`

**Behavior:** If **only** Python code changes → Run AST-based impact analysis → Run only impacted tests (unless autouse fixture detected)

**Note:** Changes to `.azure-pipelines/impacted_area_testing/` itself (the impact analysis code) do **not** trigger the full test suite, allowing you to iterate on the analysis logic without running all tests.

### Advantages Over Original Design

1. **Higher Precision**: Only runs tests that are actually affected by code changes, not all tests in a directory
   - Example: Changing one helper function only runs tests that use that function, not all tests in the folder

2. **Fixture Awareness**: Automatically detects when tests are affected through pytest fixture dependencies
   - Tests using a changed fixture are automatically included

3. **Cross-Feature Impact Detection**: Can detect when changes in shared code affect specific features
   - Example: Changing a common utility function correctly identifies all dependent tests across features

4. **Manual Override Support**: Allows defining logical dependencies that cannot be detected through code analysis
   - Example: ACL changes affecting forwarding behavior can be manually specified in `test_dependencies.json`

5. **Infrastructure Safety**: Automatically runs full test suite when infrastructure files change
   - Prevents subtle breakages from ansible playbook or test framework changes

6. **Better Accuracy**: Reduces false negatives (missing impacted tests) and false positives (running unnecessary tests)

7. **Scalable**: As the codebase grows, only analyzes changed files rather than entire directories

### Comparison Example

**Original Design:**
- Change one line in `tests/bgp/utils.py`
- Result: Run ALL tests in `tests/bgp/` directory (~50 tests)

**New AST-Based Design:**
- Change one line in `tests/bgp/utils.py` in function `validate_route()`
- AST analysis finds only 3 test files actually call `validate_route()`
- Result: Run only those 3 tests
- Savings: 94% reduction in test execution

### System Architecture

#### Process Flow

```
PR Created
    ↓
Get changed files (git diff)
    ↓
Check file types → Infrastructure files? → YES → Run full test suite (574 tests)
    ↓ NO
Extract changed functions (AST parsing)
    ↓
Is autouse fixture? → YES → Run full test suite
    ↓ NO
Build fixture dependency graph
    ↓
Trace call stacks & fixture dependencies
    ↓
Find impacted test files
    ↓
Apply module dependencies (test_dependencies.json)
    ↓
Categorize by topology (t0, t1, t2, etc.)
    ↓
Calculate instance allocation
    ↓
Distribute tests to PR checkers
    ↓
Execute tests in parallel
```

#### Files in This Directory

| File | Purpose |
|------|---------|
| **test_locally.sh** | Main testing script - simulates full CI pipeline locally |
| **detect_function_changes.py** | Detects changed functions and triggers appropriate analysis |
| **analyze_impact.py** | AST-based analysis: traces function calls, fixture dependencies |
| **dependency_resolver.py** | Resolves module dependencies from test_dependencies.json |
| **categorize_test_scripts_by_topology.py** | Groups tests by topology type (t0, t1, t2, etc.) |
| **calculate_instance_number.py** | Calculates parallel instances needed for test execution |
| **get_test_scripts.py** | Retrieves test scripts based on impact analysis |
| **get-impacted-area.yml** | Azure Pipeline template for impact detection |
| **test_dependencies.json** | Configuration file for module dependencies |
| **README.md** | This file - complete documentation |
| **TEST_DEPENDENCIES.md** | Guide for defining module dependencies |

**For testing:** Use `test_locally.sh` - it validates all features (autouse fixtures, fixture chains, function tracing, infrastructure detection, module dependencies).

### Configuration

Module dependencies can be defined in `.azure-pipelines/impacted_area_testing/test_dependencies.json`:

```json
{
  "module_dependencies": {
    "tests/bgp": ["tests/fib"],
    "tests/acl": ["tests/forwarding"]
  }
}
```

See `TEST_DEPENDENCIES.md` for complete documentation on defining dependencies.

## Local Testing

The `test_locally.sh` script simulates the complete CI pipeline behavior locally, allowing you to verify what tests will run **before** creating a PR.

### What It Validates

This script tests **all** impact analysis features:
- **Autouse fixture detection** - Changes to autouse fixtures trigger full test suite
- **Fixture dependency tracing** - Changes to base fixtures find tests using dependent fixtures
- **Function call chain tracing** - Changes to utility functions find indirect callers
- **Infrastructure detection** - Changes to ansible/scripts trigger full test suite
- **Module dependencies** - Applies transitive dependencies from `test_dependencies.json`
- **Topology categorization** - Groups tests by t0, t1, t2, dualtor, etc.

**No separate test files needed** - this one script validates everything!

### Quick Start

```bash
# Test your current changes against master
cd .azure-pipelines/impacted_area_testing
./test_locally.sh
```

### Usage

```bash
./test_locally.sh [options]

Options:
  --target-branch <branch>    Target branch to compare against (default: origin/master)
  --source-branch <branch>    Source branch or commit to test (default: HEAD)
  --patch <file>              Apply a patch file before testing
  --trace                     Enable detailed trace logging
  --help                      Show help message
```

### Examples

**Test current uncommitted changes:**
```bash
./test_locally.sh
```

**Test a specific feature branch:**
```bash
./test_locally.sh --source-branch feat/my-feature
```

**Test with a patch file:**
```bash
# Generate a patch from your changes
git diff > my-changes.patch

# Test what would happen if that patch was applied
./test_locally.sh --patch my-changes.patch
```

**Compare two specific commits:**
```bash
./test_locally.sh --target-branch abc123 --source-branch def456
```

**Debug with detailed trace logging:**
```bash
./test_locally.sh --trace
```

**Reproduce a CI failure:**
```bash
# If CI failed on PR #12345, you can test the same comparison locally
git fetch origin pull/12345/head:pr-12345
./test_locally.sh --source-branch pr-12345 --target-branch origin/master
```

### Output

The script provides:

1. **Changed Files**: List of all files modified
2. **Impact Analysis Results**: JSON output showing impacted tests
3. **Categorized Test Scripts**: Tests organized by topology (t0, t1, t2, etc.)
4. **Pipeline Variables**: Exact values that would be set in CI (`PR_CHECKERS`, `TEST_SCRIPTS`)
5. **Summary Statistics**: Count of tests per topology

### Testing Different Scenarios

The `test_locally.sh` script validates **all** impact analysis features:

#### Test Autouse Fixture Detection
```bash
# Make a change to an autouse fixture in tests/conftest.py
# For example, modify the enhance_inventory fixture
./test_locally.sh

# Expected: Should run full test suite (574 tests) because autouse fixtures affect all tests
```

#### Test Fixture Dependency Tracing
```bash
# Modify a base fixture that other fixtures depend on
# For example, change 'duthost' in tests/conftest.py which has 505+ dependent fixtures
./test_locally.sh --trace

# Expected: Should find all tests using dependent fixtures
# Trace output will show: "Fixture duthost has 505 dependent fixtures"
```

#### Test Infrastructure Changes
```bash
# Modify an ansible playbook or shell script
# For example, edit ansible/testbed-cli.sh
./test_locally.sh

# Expected: Should run full test suite (574 tests)
# Output will show: "Infrastructure files detected - running full test suite"
```

#### Test Targeted Impact Analysis
```bash
# Modify a specific test file or helper function
# For example, change tests/bgp/test_bgp_fact.py
./test_locally.sh

# Expected: Should run only affected tests (not full suite)
# Will show fewer tests and specific topology checkers
```

#### Test Module Dependencies
```bash
# Add a dependency in test_dependencies.json, then modify the dependent module
./test_locally.sh

# Expected: Should include additional tests based on defined dependencies
```

#### Test Function Call Chain Tracing
```bash
# Modify a common utility function in tests/common/helpers/
./test_locally.sh --trace

# Expected: Will trace which tests call the function (directly or indirectly)
# Trace output shows the call chain resolution
```

### Troubleshooting

**"Error: Not in a git repository"**
- Make sure you're running the script from within the sonic-mgmt repository

**"Error: Target branch not found"**
- Fetch the latest branches: `git fetch --all`
- Check branch name: `git branch -a`

**"Error: Invalid JSON output"**
- Run with `--trace` flag to see detailed error messages
- Check for syntax errors in Python files

**Module dependencies not being applied**
- Verify `test_dependencies.json` is valid JSON
- Check file paths match exactly (case-sensitive)
- See `TEST_DEPENDENCIES.md` for configuration help

**Want to see detailed fixture dependency resolution?**
- Use `--trace` flag to see fixture graph building and dependency chain resolution
- Output will show: "Building fixture dependency graph...", "Found X fixtures", "Fixture Y has Z dependent fixtures"

### Integration with CI

The local test script simulates exactly what happens in the CI pipeline:

1. Gets changed files using `git diff`
2. Runs `detect_function_changes.py` for AST-based analysis
3. Applies module dependencies from `test_dependencies.json`
4. Categorizes tests by topology using `categorize_test_scripts_by_topology.py`
5. Outputs the same `PR_CHECKERS` and `TEST_SCRIPTS` variables used in CI

This allows you to verify locally what tests will run before creating a PR.

## Known Limitations

### What the AST Analysis Handles

**Indirect function call chains** - Fully supported with recursive tracing
- Example: Test → Function A → Function B → Function C (changing C finds the test)

**Autouse fixtures** - Fully supported with special detection
- Fixtures marked with `autouse=True` trigger full test suite when changed
- 12 autouse fixtures in `tests/conftest.py` are automatically detected

**Direct and indirect fixture usage** - Fully supported with dependency tracing
- Tests that directly use a fixture as a parameter are correctly identified
- Tests that use fixtures which depend on the changed fixture are also identified
- Example: Test uses Fixture A, Fixture A uses Fixture B → Changing Fixture B finds the test

**Infrastructure changes** - Fully supported
- Ansible playbooks, shell scripts, and test framework changes trigger full suite

### What the AST Analysis Does NOT Handle

**Fixture-to-fixture dependency chains** - Fully implemented
- Example: Test uses Fixture A, Fixture A uses Fixture B → Changing Fixture B correctly finds the test
- The system builds a complete fixture dependency graph and recursively resolves all dependent fixtures
- Works for arbitrary depth: Fixture A → Fixture B → Fixture C → Test

**Runtime-only dependencies** - Cannot be statically analyzed
- Example: Dynamic imports, configuration-driven behavior, plugin systems
- **Mitigation:** Infrastructure file detection catches most of these cases
- **Workaround:** Define in `test_dependencies.json` or mark as infrastructure

**Cross-repository dependencies** - Not analyzed
- Changes in external repositories won't trigger dependent tests
- **Mitigation:** This is expected behavior for PR testing

For detailed analysis of indirect dependencies and autouse fixtures, see `INDIRECT_DEPENDENCIES_ANALYSIS.md`.

## Safeguard: Baseline Testing

Since impacted area based PR testing only runs affected tests, we rely on **Baseline Testing** to ensure comprehensive coverage and catch any issues not detected by targeted testing.

**Baseline Testing Process:**
- Runs **all test scripts** in the test plan daily
- 5 rounds of execution per day for overall system stability
- Automatically creates ADO work items when issues are detected
- Sends email alerts to notify relevant teams
- Provides confidence that PR testing optimizations don't introduce blind spots

This combination of targeted PR testing + comprehensive baseline testing provides both **speed** (fast PR feedback) and **safety** (full daily coverage).

---

## Appendix: Historical Implementation Details

### Phase 2 Implementation: Directory-Based Testing

The following sections describe how the Phase 2 directory-based impacted area testing worked. This information is preserved for historical context but is no longer the primary approach.

#### Topology Distribution

In Phase 2, multiple PR checkers were classified by topology type. The system had to distribute test scripts to the appropriate checkers:

**Two approaches were evaluated:**

1. **Using `--topology` parameter:**
   - Used pytest's `--topology` parameter to match against `pytest.mark.topology` markers
   - **Problem:** Triggered pytest's collection process for each script, causing unnecessary time consumption

2. **Pre-collection analysis (chosen approach):**
   - Performed a global scan of all test scripts before execution
   - Extracted `pytest.mark.topology` marker values from each script
   - Distributed scripts to corresponding PR checkers based on topology type
   - **Benefit:** Eliminated unnecessary processes by executing only on-demand scripts

#### Dynamic Instance Allocation

Phase 2 introduced dynamic instance allocation based on estimated test execution time:

**Process:**
1. Query historical data from Kusto table (execution times, dates, results)
2. Calculate average running time of latest 5 executions for each test script
3. Use default value (1800s per script) if no historical data available
4. Distribute scripts evenly across instances to balance workload
5. Target ~1.5 hours execution per instance (leaving time for testbed prep/cleanup)
6. Keep total runtime within 2 hour maximum

**Result:** Efficient resource usage by allocating instances dynamically based on actual test count and estimated runtime.

This dynamic allocation approach continues to be used in the current AST-based implementation.
