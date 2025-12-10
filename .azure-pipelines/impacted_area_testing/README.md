## Background
In current PR testing process, a fixed set of test scripts is executed regardless of the change scope.
This approach lacks flexibility. On the one hand, if changes are only related to a few lines of codebase,
we may don't need to run the whole scope. On the other hand, if there are new added test scripts,
we need to add them manually.

With approximately 570 test scripts running, the process has become excessively large and the runtime increased significantly.
Due to the maximum execution time limit, more instances are needed to run the tests in parallel.
For example, to meet this requirement, we need 20 instances for t0 and 25 instances for t1.
The cost per PR has reached $35, and we will use $23,000 per month to run PR testing, which is considerably high.

To address these issues, we propose a new PR testing model called 'Impacted Area-Based PR Testing.

## Preparation
We can organize the codebase in this way:
```
sonic-mgmgt
     | - .azure-pipelines
     | - ansible
     | - docs
     | - ......
     | - tests
           |
           | - common      ---------- shared
           | - arp         -----|
           | - ecmp             | --- features
           | - vlan             |
           | - ......      -----|
```
Under sonic-mgmt, there are several top-level folders such as `.azure-pipelines`, `ansible`, `docs`, `tests`, and more.
Except for the `tests` folder, we classify all other folders as part of the shared section of the repo.

Within the `tests` folder, there are multiple second-level directories.
Among them, the common folder is also considered part of the shared section.
Other folders, such as `arp`, `ecmp`, and similar directories, are classified as feature-specific parts.

Scripts in the common folder fall under the shared section and can be utilized across different folders.
In contrast, scripts in other folders belong to the features section, representing specific functionalities such as arp, ecmp, and vlan,
and are intended for use within their respective folders.
This hierarchy helps us more effectively identify the impacted areas for the new PR testing process.

However, the previous code had numerous cross-feature dependencies.
To achieve our goal, we carried out some preparatory work by eliminating these cross-feature dependencies.


## Design
### Impcated Area
To take advantage of such code structure, we introduce a new term called `impacted area`, which represents the scope of PR testing.
The `impacted area` can be defined by specific features, so that we can narrow down the scope into folders.

This term can be elaborated as follows:
- If the changes are confined to a specific feature folder, we can narrow the scope of testing to only include files within that folder.
As files in other feature folders remain unaffected and do not require testing.
- If the changes affect the common components, we cannot narrow the testing scope and must run all test scripts to ensure comprehensive coverage, as they are commonly used by other features.

We can determine the impcated area using command `git diff`.

### Distribute scripts to PR checkers
In our new PR test, we will have multiple PR checkers classified by topology type.
To distribute all required scripts for each PR checker, which means,
these scripts should not only within the scope that we changed, but also meet the requirement of topology.

We can suggest two approaches to achieve this:
- One approach is by using the `--topology` parameter supported by pytest.
It compares against the topology marked with `pytest.mark.topology` in script,
and if the mark matches, the script is deemed necessary.
However, this method triggers pytest's collection process for each script,
leading to unnecessary time consumption, which is not expected.

- Another approach is to collect and analyze all scripts before execution.
Each script includes the `pytest.mark.topology` marker to indicate the applicable topology it can run on.
We will perform a global scan of all test scripts in the impacted area to identify this marker and extract its value,
which represents the topology type compatible with the script.
After determining the valid topology for each script, we can distribute the script to corresponding PR checkers.
This method eliminates unnecessary processes by executing only the on-demand scripts, resulting in reduced running time.

### Implement dynamic instances
Since the scope of PR testing is dynamic and determined by the impacted area,
the number of instances required also needs to be dynamic to ensure cost efficiency.
To achieve this, we must accurately estimate the total execution time in advance,
allowing us to allocate the appropriate number of instances.
This estimation can be achieved by analyzing historical data,
which provides insights into execution times for similar scenarios.

We now have a Kusto table that logs details about the execution of test cases,
including the running time, date, results, and more.
To determine the preset running time for each test script,
we will calculate the average running time of the latest five run times.
If no relevant records are found in Kusto, a default value(1800s per script) will be used for the preset running time.
This approach allows us to estimate the total execution time for our scripts accurately.

Using this information, we will evenly distribute the scripts across instances,
ensuring that the workload is balanced of each instance.
Ideally, each instance will run its assigned scripts in approximately 1.5 hours,
leaving additional time for tasks such as testbed preparation and clean-up and keeping the total runtime within 2 hours.

## Advantages
Impacted area based PR testing runs test scripts on demand, reducing the overall scale of the PR test and saving execution time.
And instances will be allocated as needed, resulting in more cost-efficient resource usage.
Additionally, the PR testing will be more flexible as we can collect test scripts automatically rather than hard code.

## NEW DESIGN: AST-Based Impact Analysis

The original design described above used a directory-based approach to determine impacted areas - if a file in a feature folder changed, all tests in that folder would run. While this was an improvement over running all tests, it still resulted in running many unnecessary tests.

The new design introduces **AST (Abstract Syntax Tree) based impact analysis** for more precise test selection.

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

### Advantages Over Original Design

1. **Higher Precision**: Only runs tests that are actually affected by code changes, not all tests in a directory
   - Example: Changing one helper function only runs tests that use that function, not all tests in the folder

2. **Fixture Awareness**: Automatically detects when tests are affected through pytest fixture dependencies
   - Tests using a changed fixture are automatically included

3. **Cross-Feature Impact Detection**: Can detect when changes in shared code affect specific features
   - Example: Changing a common utility function correctly identifies all dependent tests across features

4. **Manual Override Support**: Allows defining logical dependencies that cannot be detected through code analysis
   - Example: ACL changes affecting forwarding behavior can be manually specified in `test_dependencies.json`

5. **Better Accuracy**: Reduces false negatives (missing impacted tests) and false positives (running unnecessary tests)

6. **Scalable**: As the codebase grows, only analyzes changed files rather than entire directories

### Comparison Example

**Original Design:**
- Change one line in `tests/bgp/utils.py`
- Result: Run ALL tests in `tests/bgp/` directory (~50 tests)

**New AST-Based Design:**
- Change one line in `tests/bgp/utils.py` in function `validate_route()`
- AST analysis finds only 3 test files actually call `validate_route()`
- Result: Run only those 3 tests
- Savings: 94% reduction in test execution

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

To test the impact analysis locally before pushing to CI, use the provided test script:

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

### Example Output

```
========================================
Impacted Area Testing - Local Test
========================================

Configuration:
  Target Branch: origin/master
  Source Branch: HEAD
  Trace Logging: disabled

Getting changed files...
Changed files:
  - tests/bgp/test_bgp_fact.py

Running impact analysis...

========================================
Impact Analysis Results
========================================

Raw Impact Analysis Output:
{
  "tests": [
    "tests/bgp/test_bgp_fact.py",
    "tests/fib/test_fib.py"
  ],
  "others": []
}

Impacted Test Files (2):
  - tests/bgp/test_bgp_fact.py
  - tests/fib/test_fib.py

Categorizing tests by topology...

Categorized Test Scripts:
{
  "t0_checker": ["tests/bgp/test_bgp_fact.py"],
  "t1_checker": ["tests/bgp/test_bgp_fact.py", "tests/fib/test_fib.py"]
}

========================================
Final Pipeline Variables
========================================

PR_CHECKERS:
["t0_checker", "t1_checker"]

TEST_SCRIPTS:
{
  "t0_checker": ["tests/bgp/test_bgp_fact.py"],
  "t1_checker": ["tests/bgp/test_bgp_fact.py", "tests/fib/test_fib.py"]
}

========================================
Summary
========================================

Changed Files: 1
Impacted Test Files: 2
Topology Checkers: 2

  - t0_checker: 1 tests
  - t1_checker: 2 tests

✓ Local testing complete!
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

### Integration with CI

The local test script simulates exactly what happens in the CI pipeline:

1. Gets changed files using `git diff`
2. Runs `detect_function_changes.py` for AST-based analysis
3. Applies module dependencies from `test_dependencies.json`
4. Categorizes tests by topology using `categorize_test_scripts_by_topology.py`
5. Outputs the same `PR_CHECKERS` and `TEST_SCRIPTS` variables used in CI

This allows you to verify locally what tests will run before creating a PR.

## Safeguard
As impacted area based PR testing would not cover all test scripts, we need a safeguard to run all test scripts daily to prevent any unforeseen issues.
Fortunately, we have Baseline testing to do so.
Baseline testing involves running all test scripts in the test plan daily to ensure the overall stability of the system and identify potential issues.
We conduct five rounds of baseline testing each day, and if any issues are detected, an ADO is automatically created, and email alerts are sent to notify the relevant teams.
