# Impacted Area Algorithm: Empirical Case Matrix

This report uses **patch-based case simulation** (`test_locally.sh --patch`) so each case runs with only the case patch and avoids branch-drift contamination.

## 1) Run Context

- Target branch: `origin/master`
- Mode: `patch-based`
- Cases executed: `15`
- Full raw outputs: `impact_case_results.json`

## 2) Summary Table

| Case | Changed file | Impacted tests | Impacted others | `test_locally.sh` |
|---|---|---:|---:|---|
| `docs_only_change` | `README.md` | 0 | 0 | `ok` (`0`) |
| `non_python_general_change` | `pyproject.toml` | 0 | 0 | `ok` (`0`) |
| `direct_test_function_change` | `tests/acl/test_acl.py` | 1 | 0 | `ok` (`0`) |
| `common_function_change` | `tests/common/helpers/assertions.py` | 1 | 0 | `ok` (`0`) |
| `syntax_error_in_changed_py` | `tests/acl/test_acl.py` | 598 | 0 | `ok` (`0`) |
| `import_change_in_test_file` | `tests/acl/test_acl.py` | 1 | 0 | `ok` (`0`) |
| `import_change_in_non_test_file` | `tests/common/helpers/assertions.py` | 1 | 0 | `ok` (`0`) |
| `dynamic_import_change_non_test` | `tests/common/helpers/assertions.py` | 598 | 0 | `ok` (`0`) |
| `global_variable_change_non_test` | `tests/common/helpers/assertions.py` | 1 | 0 | `ok` (`0`) |
| `fixture_non_autouse_change` | `tests/restapi/conftest.py` | 598 | 0 | `ok` (`0`) |
| `autouse_fixture_change` | `tests/restapi/conftest.py` | 598 | 0 | `ok` (`0`) |
| `conftest_non_function_change` | `tests/restapi/conftest.py` | 598 | 0 | `ok` (`0`) |
| `infrastructure_ansible_change` | `ansible/basic_check.yml` | 598 | 0 | `ok` (`0`) |
| `infrastructure_script_change` | `tests/run_tests.sh` | 598 | 0 | `ok` (`0`) |
| `impacted_area_internal_change` | `.azure-pipelines/impacted_area_testing/constant.py` | 0 | 1 | `ok` (`0`) |

## 3) Case Details (Change + JSON Output)

### `docs_only_change`

- Change: Append one HTML comment in README.md
- Changed file: `README.md`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "README.md"
  ],
  "tests_count": 0,
  "others_count": 0,
  "sample_tests": [],
  "sample_others": []
}
```

### `non_python_general_change`

- Change: Append one harmless TOML comment
- Changed file: `pyproject.toml`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "pyproject.toml"
  ],
  "tests_count": 0,
  "others_count": 0,
  "sample_tests": [],
  "sample_others": []
}
```

### `direct_test_function_change`

- Change: Add one unused module-level marker near logger
- Changed file: `tests/acl/test_acl.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/acl/test_acl.py"
  ],
  "tests_count": 1,
  "others_count": 0,
  "sample_tests": [
    "tests/acl/test_acl.py"
  ],
  "sample_others": []
}
```

### `common_function_change`

- Change: Add one unused module-level variable
- Changed file: `tests/common/helpers/assertions.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/common/helpers/assertions.py"
  ],
  "tests_count": 1,
  "others_count": 0,
  "sample_tests": [
    "tests/common/helpers/assertions.py"
  ],
  "sample_others": []
}
```

### `syntax_error_in_changed_py`

- Change: Inject one invalid Python line
- Changed file: `tests/acl/test_acl.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/acl/test_acl.py"
  ],
  "tests_count": 598,
  "others_count": 0,
  "sample_tests": [
    "tests/test_procdockerstatsd.py",
    "tests/test_posttest.py",
    "tests/test_features.py",
    "tests/test_interfaces.py",
    "tests/test_nbr_health.py"
  ],
  "sample_others": []
}
```

### `import_change_in_test_file`

- Change: Add one extra import in test file
- Changed file: `tests/acl/test_acl.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/acl/test_acl.py"
  ],
  "tests_count": 1,
  "others_count": 0,
  "sample_tests": [
    "tests/acl/test_acl.py"
  ],
  "sample_others": []
}
```

### `import_change_in_non_test_file`

- Change: Add one extra import in common helper
- Changed file: `tests/common/helpers/assertions.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/common/helpers/assertions.py"
  ],
  "tests_count": 1,
  "others_count": 0,
  "sample_tests": [
    "tests/common/helpers/assertions.py"
  ],
  "sample_others": []
}
```

### `dynamic_import_change_non_test`

- Change: Add importlib dynamic import line
- Changed file: `tests/common/helpers/assertions.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/common/helpers/assertions.py"
  ],
  "tests_count": 598,
  "others_count": 0,
  "sample_tests": [
    "tests/test_procdockerstatsd.py",
    "tests/test_posttest.py",
    "tests/test_features.py",
    "tests/test_interfaces.py",
    "tests/test_nbr_health.py"
  ],
  "sample_others": []
}
```

### `global_variable_change_non_test`

- Change: Add one global variable assignment
- Changed file: `tests/common/helpers/assertions.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/common/helpers/assertions.py"
  ],
  "tests_count": 1,
  "others_count": 0,
  "sample_tests": [
    "tests/common/helpers/assertions.py"
  ],
  "sample_others": []
}
```

### `fixture_non_autouse_change`

- Change: Add one unused local variable in non-autouse fixture
- Changed file: `tests/restapi/conftest.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/restapi/conftest.py"
  ],
  "tests_count": 598,
  "others_count": 0,
  "sample_tests": [
    "tests/test_procdockerstatsd.py",
    "tests/test_posttest.py",
    "tests/test_features.py",
    "tests/test_interfaces.py",
    "tests/test_nbr_health.py"
  ],
  "sample_others": []
}
```

### `autouse_fixture_change`

- Change: Add one unused local variable in autouse fixture
- Changed file: `tests/restapi/conftest.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/restapi/conftest.py"
  ],
  "tests_count": 598,
  "others_count": 0,
  "sample_tests": [
    "tests/test_procdockerstatsd.py",
    "tests/test_posttest.py",
    "tests/test_features.py",
    "tests/test_interfaces.py",
    "tests/test_nbr_health.py"
  ],
  "sample_others": []
}
```

### `conftest_non_function_change`

- Change: Add one import at module top in conftest.py
- Changed file: `tests/restapi/conftest.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/restapi/conftest.py"
  ],
  "tests_count": 598,
  "others_count": 0,
  "sample_tests": [
    "tests/test_procdockerstatsd.py",
    "tests/test_posttest.py",
    "tests/test_features.py",
    "tests/test_interfaces.py",
    "tests/test_nbr_health.py"
  ],
  "sample_others": []
}
```

### `infrastructure_ansible_change`

- Change: Add one harmless YAML comment
- Changed file: `ansible/basic_check.yml`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "ansible/basic_check.yml"
  ],
  "tests_count": 598,
  "others_count": 0,
  "sample_tests": [
    "tests/test_procdockerstatsd.py",
    "tests/test_posttest.py",
    "tests/test_features.py",
    "tests/test_interfaces.py",
    "tests/test_nbr_health.py"
  ],
  "sample_others": []
}
```

### `infrastructure_script_change`

- Change: Add one harmless shell comment
- Changed file: `tests/run_tests.sh`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    "tests/run_tests.sh"
  ],
  "tests_count": 598,
  "others_count": 0,
  "sample_tests": [
    "tests/test_procdockerstatsd.py",
    "tests/test_posttest.py",
    "tests/test_features.py",
    "tests/test_interfaces.py",
    "tests/test_nbr_health.py"
  ],
  "sample_others": []
}
```

### `impacted_area_internal_change`

- Change: Add one unused variable in impacted_area_testing internals
- Changed file: `.azure-pipelines/impacted_area_testing/constant.py`
- `test_locally.sh`: `ok` (exit `0`)

```json
{
  "changed_files_vs_target": [
    ".azure-pipelines/impacted_area_testing/constant.py"
  ],
  "tests_count": 0,
  "others_count": 1,
  "sample_tests": [],
  "sample_others": [
    ".azure-pipelines/impacted_area_testing/constant.py"
  ]
}
```

---

### Notes

- Full per-case raw records are in `impact_case_results.json`.
- This markdown intentionally keeps compact JSON summaries for readability.
