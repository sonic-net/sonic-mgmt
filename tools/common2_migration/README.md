# common2 migration dashboard

This workflow scans the legacy helpers under tests/common and produces a contributor-facing migration dashboard for moving them into tests/common2.

## What the workflow does

The workflow performs three related tasks:

1. It analyzes source modules under tests/common and identifies candidate modules that could be migrated into tests/common2.
2. It estimates the effort and risk for each candidate module and for each public symbol (function/class/fixture) inside it.
3. It publishes a Markdown report plus machine-readable JSON/YAML artifacts, and can also upsert the results into a GitHub Project as draft issues/cards.

The main entry point is [tools/common2_migration/migration_dashboard.py](migration_dashboard.py), and the project upsert logic is in [tools/common2_migration/upsert_migration_project.py](upsert_migration_project.py).

## Why this effort exists

The underlying motivation is quality and maintainability. Over time, tests/common has accumulated code that is useful, but often harder to reason about because it mixes test infrastructure, utilities, fixtures, and helper logic in a way that makes reuse and long-term maintenance harder.

The migration effort is meant to improve the codebase in several ways:

- reduce duplication and similar code paths under tests/common
- consolidate fixtures that are currently scattered across tests, conftest modules, utilities, and plugins
- add or improve type annotations
- add or improve docstrings and inline documentation
- improve naming consistency for test helpers and utility methods
- refactor overly complex functions and helpers
- remove unused arguments and variables
- standardize string formatting and imports
- ensure utility functions have unit tests
- and generally improve readability, maintainability, and testability

The dashboard is designed to make those quality gaps visible and to help contributors pick work that is small, focused, and easy to review.

## How the score is calculated

The score is a rough heuristic for migration effort and risk. It is not a formal quality metric and should be treated as a prioritization aid, not a definitive truth.

### Module score

The module-level score is computed as:

score = volume + blast + coupling + quality_gap

Where:

- volume = LOC / 40 + (functions + classes) * 1.5
  - LOC is the number of non-comment, non-blank lines in the module.
  - functions + classes means the number of public top-level functions and classes discovered in the module.
  - The 40 and 1.5 are weighting constants: they convert raw size and symbol count into a smaller, comparable effort signal.
- blast = direct_impacted_tests * 1.2
  - This reflects how many test files import or depend on this module directly.
  - More impacted tests usually means more regression risk and more validation work.
- coupling = direct_common_deps * 2.0 + transitive_common_deps * 0.3
  - Direct dependencies are weighted more heavily than transitive ones.
  - If a module depends on several other common helpers, migrating it cleanly may require migrating those helpers too.
- quality_gap = (1 - typed_ratio) * 6.0 + (1 - documented_ratio) * 3.0
  - Missing type hints and missing docstrings increase the score.
  - This intentionally penalizes modules that are not yet aligned with common2 quality standards.
- unit_gap = 0.0 if common2 unit tests exist else 4.0
  - If the module already has common2 unit tests, that reduces the effort estimate.
  - If it does not, the score increases because the migration likely needs new tests.

### Symbol score

The per-function/class/fixture score is computed as:

score = volume + blast + quality_gap

Where:

- volume = LOC / 25 + 1.0
- blast = direct_impacted_tests * 1.2
- quality_gap = (1 - typed_ratio) * 3.0 + (0 if docstring else 1.5)

These constants are deliberately simple and hand-tuned. They are meant to make the ordering useful for contributor selection, not to be mathematically exact.

## What the report includes

Each generated module report includes:

- a proposed target path under tests/common2
- the target domain/category
- effort score and tier
- direct and transitive test impact
- direct and transitive common dependencies
- sub-tasks for individual functions/classes/fixtures
- a link to the generated dashboard report (for the GitHub Project card body)

## Quality checks during migration

When a contributor ports code into tests/common2, the common2 pipeline already enforces several quality gates:

- pre-commit checks for the touched files
- Black formatting
- mypy type checking
- pylint checks
- unit tests with coverage enforcement for common2

These checks are wired in under [.azure-pipelines/common2](../../.azure-pipelines/common2) and are intended to ensure that migrated code is not only moved, but also improved and kept maintainable.

## How to use the dashboard

1. Pick a low-rank, low-tier module to start with.
2. Read the dependency and impact sections to understand the blast radius.
3. Pick one small function/class/fixture sub-task if the module is large.
4. Port the code into tests/common2.
5. Validate it with the relevant tests and let the common2 pipeline enforce the quality gates.

## Notes

- Lower rank/tier/score means easier and lower-risk work.
- The report is meant to guide migration work, not to replace code review.
- The YAML artifact is the primary machine-readable artifact; the Markdown report is the human-readable summary.
