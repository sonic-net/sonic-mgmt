# Impacted Area Algorithm: Behavior by PR Change Type

This document explains how the **AST-based impacted area algorithm** behaves for common PR change patterns.

## 1) Decision Flow (Simple)

1. Pipeline collects changed files from `merge-base..HEAD`.
2. If AST path is selected, `detect_function_changes.py` analyzes modified files.
3. The analyzer uses function-level AST + call graph (`analyze_impact.py`) for precise test selection.
4. For high-risk/global-impact changes, it intentionally falls back to **run full test suite**.
5. Final selected tests are expanded by `test_dependencies.json` (module dependency rules).

## 2) Behavior Matrix (Change Type → Result)

| PR change type | How code detects it | Current behavior |
|---|---|---|
| Only docs / markdown / text changes | Non-`.py` files are skipped by analyzer | **No tests selected by AST analyzer** (empty impacted list) |
| Non-Python file in general | File extension check (`.py`) | Skipped in function-level analysis |
| Direct edit in a test file function (`tests/**/test_*.py`) | Changed lines mapped to function; call graph lookup | Select impacted test files returned by call graph logic |
| Edit in shared Python helper used by tests (for example under `tests/common`) | Changed function → dependent callers/tests via `analyze_impact.py` | Select tests that depend on changed function(s) |
| Python syntax error in changed file | Upfront parse validation on all changed `.py` files | **Run full test suite** (safe fallback; no silent misses) |
| Change to normal import statement (`import ...` / `from ... import ...`) in a **test** file | Diff scanner classifies as non-function import change | Changed test file is added to impacted tests |
| Change to normal import statement in a **non-test Python** file | Diff scanner classifies as import change | **Run full test suite** (conservative global-impact fallback) |
| Change to dynamic import usage (`importlib.import_module`, `__import__`, `spec_from_file_location`) | Diff scanner classifies as dynamic import change | **Run full test suite** |
| Change to global variable assignment at module level | Diff scanner detects non-function global assignment | File added as impacted artifact (`tests/*` goes to tests, others to non-test bucket) |
| Change to fixture function (`@pytest.fixture`) | Function change detected and analyzed via call graph + fixture usage graph in `analyze_impact.py` | Select tests using that fixture (directly/indirectly where resolvable) |
| Change to **autouse** fixture (`@pytest.fixture(autouse=True)`) | Changed line maps to function (including decorator lines), then autouse check | **Run full test suite** |
| Change in `conftest.py` non-function area (imports/globals/etc.) | `conftest.py` special check in non-function handling | **Run full test suite** |
| Infrastructure changes (`ansible/**`, `tests/scripts/**`, `tests/run_tests.sh`, `setup-container.sh`) | Infrastructure path matcher | **Run full test suite** immediately |
| Changes inside `.azure-pipelines/impacted_area_testing/**` | Explicitly excluded from infrastructure-trigger rule | No automatic full-suite trigger from this rule alone |
| PR has pre-defined impact area parameters | Pipeline parameter shortcut (`IMPACT_AREA_INFO`) | Skip analysis and use provided impacted set |

---

### Notes for Reviewers

- The algorithm is intentionally **precision-first** for function changes and **safety-first** for high-risk import/fixture/infrastructure changes.
- Full-suite fallback is expected for change types that can alter runtime behavior beyond explicit call edges.
