# Failure-Validated xfail Integration Test Plan

## Overview

This test suite validates the Failure-Validated xfail feature end-to-end using
real pytest test functions. All tests are self-contained and do not require a
DUT or any external infrastructure (except a mock HTTP server for AI agent
tests, and an optional real AI agent for the real AI tests).

The tests are split into two categories:

1. **Mock tests** (`test_fvxfail_mock.py`): Use a mock AI server for
   deterministic, reproducible results. These cover all feature paths.
2. **Real AI tests** (`test_fvxfail_real_ai.py`): Hit the real AI agent
   service to validate the end-to-end flow with a live LLM backend.

Each category has a corresponding **wrapper test** that runs the test file
as a subprocess, parses the pytest short test summary, and asserts that each
test produced the expected outcome (xfail, failed, or passed).

## Test Infrastructure

### Directory Structure

```
integration_test/
    FAILURE_VALIDATED_XFAIL_TEST_PLAN.md          # This file
    conftest.py               # Patches SIGNATURES_DIR, installs mark conditions YAML
    test_fvxfail_mock.py      # Mock integration test cases (TC1-TC22)
    test_fvxfail_mock_wrapper.py    # Wrapper that validates mock test outcomes
    test_fvxfail_real_ai.py         # Real AI integration test cases (TC23-TC24)
    test_fvxfail_real_ai_wrapper.py # Wrapper that validates real AI test outcomes
    tests_mark_conditions_fvxfail_integration.yaml  # Mark conditions for all integration tests
    mocked_failures/          # Stored failure messages replayed by test functions
        high_similarity_failure.txt
        custom_high_th_failure.txt
        custom_low_th_failure.txt
        middle_range_failure.txt
        multi_issue_interface_down.txt
        multi_issue_close_scores.txt
        setup_teardown_failure.txt
    signatures/               # Per-test signature YAML files
        known_issue_signatures_mgmt_990099001.yaml  # TC1 (high similarity)
        known_issue_signatures_mgmt_990099002.yaml  # TC2 (low similarity)
        known_issue_signatures_mgmt_990099003.yaml  # TC13-18, TC23 (AI agent, middle range)
        known_issue_signatures_mgmt_990099004.yaml  # TC10 (missing mandatory field)
        known_issue_signatures_mgmt_990099005.yaml  # TC5 (custom high threshold)
        known_issue_signatures_mgmt_990099006.yaml  # TC6 (custom low threshold)
        known_issue_signatures_mgmt_990099007.yaml  # TC7 (custom weights)
        known_issue_signatures_mgmt_990099008.yaml  # TC8a-8b (setup/teardown)
        known_issue_signatures_mgmt_990099010.yaml  # TC11-12 (multi-issue, good match)
        known_issue_signatures_mgmt_990099011.yaml  # TC11-12 (multi-issue, bad match)
        known_issue_signatures_mgmt_990099012.yaml  # TC19-21, TC24 (multi-issue AI, candidate 1)
        known_issue_signatures_mgmt_990099013.yaml  # TC19-21, TC24 (multi-issue AI, candidate 2)
```

### conftest.py

The conftest performs two setup actions at import time (before collection):

1. **Patches `SIGNATURES_DIR`** in `failure_signature.py` to point to the
   test's own `signatures/` directory, so integration test signature files
   are used instead of the real `known_issue_signatures/` directory.
2. **Copies the mark conditions file**
   (`tests_mark_conditions_fvxfail_integration.yaml`) to the real plugin
   directory so the `conditional_mark` plugin's `load_conditions()` picks
   it up during `pytest_collection`. An `atexit` handler removes the
   copied file when the session ends.

### tests_mark_conditions_fvxfail_integration.yaml

Contains xfail mark conditions entries for all integration test cases. Each
entry maps a test node ID to an xfail condition with one or more issue URLs.
Tests that should not have FV-xfail involvement (TC3, TC22) have no entry in
this file.

### mocked_failures/

Contains `.txt` files with stored failure messages. Test functions load these
via `_load(name)` and pass them to `pytest.fail()` to replay a known failure
pattern. This ensures deterministic similarity scores against the signature
YAML files.

### Mock AI Server

A mock AI HTTP server is implemented directly in `test_fvxfail_mock.py` using
a `mock_ai` fixture:

1. Starts a threaded `HTTPServer` on `127.0.0.1` with a random available port.
2. Handles `POST /api/v1/compare-failures` requests.
3. Returns configurable responses per request (indexed sequentially):
   - Fixed JSON with configurable `is_same_issue`, `reasoning`,
     `processing_time_ms`.
   - Configurable delay (for timeout tests).
   - Configurable HTTP status code (for error tests).
   - Configurable response body (for malformed response tests).
   - Per-request response sequence (for multi-issue tests where each
     call returns a different result).
4. Patches `XFAIL_AI_AGENT_URL` to `http://127.0.0.1:<port>/api/v1`.
5. Shuts down the server after the test.

### Wrapper Tests

Each wrapper (`test_fvxfail_mock_wrapper.py`, `test_fvxfail_real_ai_wrapper.py`)
contains a single test function that:

1. Builds a pytest command for the corresponding test file, reusing relevant
   arguments from the parent process (e.g. `--inventory`, `--host-pattern`)
   while filtering out allure, log-level, and test-file arguments.
2. Runs the command as a subprocess with a 600-second timeout.
3. Parses the short test summary from combined stdout+stderr to extract
   per-test outcomes (`xfail`, `failed`, `passed`) and detail strings.
4. Compares each test's actual outcome against an `EXPECTED` dictionary.
5. For xfail outcomes, also checks that specific keywords appear in the
   detail string (e.g. `"high threshold"`, `"AI agent decision: same_issue"`).
6. Reports all mismatches as a single `pytest.fail()` with detailed diagnostics.

### How Each Test Works

Each test is a real pytest test function. The function itself does one of:

- `pytest.fail(loaded_message)` -- to replay a known failure message from
  `mocked_failures/`.
- `raise SomeException(...)` -- to produce a specific exception type.
- `pass` -- to test the passing path or edge cases.
- Uses a fixture that raises in setup or teardown.

The mark conditions YAML maps each test to issue URL(s). The signatures
directory contains pre-crafted YAML files with known signatures, thresholds,
and weights. The conftest patches module constants so the integration tests
are self-contained.

---

## Test Cases -- Mock Tests (test_fvxfail_mock.py)

### Core Decision Logic

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 1 | `test_same_failure_high_similarity` | Score >= high threshold | **xfail** (detail contains "high threshold", "same issue") |
| 2 | `test_different_failure_low_similarity` | Score <= low threshold | **failed** |
| 3 | `test_no_signature_file_no_fvxfail` | No mark conditions entry | **failed** (normal failure, no FV-xfail involvement) |
| 4 | `test_passed_no_interference` | Test passes despite having signatures | **passed** |

#### Details

1. **test_same_failure_high_similarity**: Test calls `pytest.fail()` with a
   message loaded from `high_similarity_failure.txt`, which closely matches
   the stored signature for issue 990099001. The signature sets
   `xfail_similarity_high_th: "0.55"` and `xfail_similarity_low_th: "0.30"`
   to guarantee the high path is hit. Expected: xfail with "high threshold"
   and "same issue" in detail.

2. **test_different_failure_low_similarity**: Test raises
   `KeyError("completely unrelated error about missing configuration key foobar_xyz")`.
   Message and trace are entirely different from the signature for issue
   990099002. Score is well below the low threshold. Expected: failed.

3. **test_no_signature_file_no_fvxfail**: Test calls `pytest.fail()` with an
   arbitrary message. This test has **no entry** in the mark conditions YAML,
   so the conditional_mark plugin does not process it at all. It is a normal
   test failure with no FV-xfail involvement. Expected: failed.

4. **test_passed_no_interference**: Test has a mark conditions entry (issue
   990099001) with a signature file, so `_dynamic_xfail_info` is set during
   collection. However, the test function passes. The `pytest_runtest_makereport`
   hook only processes failures, so it does not interfere. No XPASS because
   the xfail mark was never added. Expected: passed.

### Threshold and Weight Overrides

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 5 | `test_custom_high_threshold` | Per-signature `xfail_similarity_high_th: "0.50"` | **xfail** (detail contains "high threshold", "same issue") |
| 6 | `test_custom_low_threshold` | Per-signature `xfail_similarity_low_th: "0.85"` | **failed** |
| 7 | `test_custom_weights` | Per-signature `w_type: "0.50"` | **xfail** (detail contains "high threshold", "same issue") |

#### Details

5. **test_custom_high_threshold**: Signature for issue 990099005 has
   `xfail_similarity_high_th: "0.50"`. Test fails with a message loaded from
   `custom_high_th_failure.txt` (BGP session timeout), which has moderate
   similarity to the stored signature. Without the lowered threshold this
   would be middle range; with it, the score exceeds the high threshold.
   Expected: xfail.

6. **test_custom_low_threshold**: Signature for issue 990099006 has
   `xfail_similarity_low_th: "0.85"` and `xfail_similarity_high_th: "0.95"`.
   Test fails with a message loaded from `custom_low_th_failure.txt` (LLDP
   neighbor on a different interface/host). The similarity score falls below
   the raised low threshold. Expected: failed.

7. **test_custom_weights**: Signature for issue 990099007 has
   `w_type: "0.50"`, `w_message: "0.30"`, `w_trace: "0.20"` and
   `xfail_similarity_high_th: "0.45"`. Test raises
   `KeyError("a_totally_different_key_error_message")`. The message content
   doesn't match, but the exception type (`KeyError`) matches exactly. The
   increased type weight (0.50 * 1.0 = 0.50) pushes the overall score above
   the high threshold. Expected: xfail.

### Setup and Teardown Phases

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 8a | `test_setup_failure_same_issue` | Fixture fails in setup, signature matches | **xfail** (detail contains "same issue") |
| 8b | `test_teardown_failure_same_issue` | Fixture fails in teardown (non-loganalyzer), signature matches | **xfail** (detail contains "same issue") |

#### Details

8a. **test_setup_failure_same_issue**: A `setup_failure_fixture` raises
    `pytest.fail()` with a message loaded from `setup_teardown_failure.txt`
    (DUT health check failure) during setup. The signature for issue 990099008
    has `xfail_similarity_high_th: "0.55"`. The hook processes the setup-phase
    failure and reports xfail.

8b. **test_teardown_failure_same_issue**: A `teardown_failure_fixture` raises
    `pytest.fail()` with the same message during teardown. The traceback does
    NOT contain `tests/common/plugins/loganalyzer/__init__.py`, so the
    loganalyzer exemption does not apply. The hook processes the teardown-phase
    failure and reports xfail.

### Invalid Signature File

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 10 | `test_missing_mandatory_field_static_xfail_with_note` | Signature YAML missing `message` field | **xfail** (detail contains "no valid signatures could be loaded") |

#### Details

10. **test_missing_mandatory_field_static_xfail_with_note**: Signature YAML
    for issue 990099004 exists but is missing the mandatory `message` field.
    The parser skips it and returns an empty list. During collection,
    `has_any_stored_signatures()` returns True (the file exists), so the
    plugin attempts FV-xfail processing. However,
    `load_signatures_for_issues()` returns no valid signatures. The plugin
    falls back to static xfail with a note indicating that no valid
    signatures could be loaded. Expected: xfail with "no valid signatures
    could be loaded" in detail.

### Multiple Issues

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 11 | `test_multi_issue_clear_winner` | Two issues (OR), one scores high | **xfail** (detail contains "high threshold", "same issue") |
| 12 | `test_multi_issue_all_below_low` | Two issues (OR), both score low | **failed** |

#### Details

11. **test_multi_issue_clear_winner**: Mark conditions use
    `conditions_logical_operator: or` with issue URLs 990099010 and 990099011.
    Test fails with a message loaded from `multi_issue_interface_down.txt`
    (interface down after config reload), which closely matches issue
    990099010's signature but not 990099011's. The high-scoring issue wins
    directly. Expected: xfail.

12. **test_multi_issue_all_below_low**: Same two issue URLs. Test raises
    `KeyError("completely_unrelated_failure_xyz_12345")`. Neither signature
    matches. Both scores are below their low thresholds. Expected: failed.

### AI Agent (Mock Server)

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 13 | `test_ai_returns_same_issue` | Middle range, AI says same | **xfail** (detail contains "AI agent decision: same_issue") |
| 14 | `test_ai_returns_different_issue` | Middle range, AI says different | **failed** |
| 15 | `test_ai_timeout` | Middle range, AI times out | **xfail** (detail contains "unavailable") |
| 16 | `test_ai_error_500` | Middle range, AI returns 500 | **xfail** (detail contains "unavailable") |
| 17 | `test_ai_malformed_response` | Middle range, AI returns invalid JSON | **xfail** (detail contains "unavailable") |
| 18 | `test_ai_disabled_fallback` | Middle range, AI URL empty | **xfail** (detail contains "not configured") |

#### Details

All AI agent tests use issue 990099003 whose signature has
`xfail_similarity_high_th: "0.95"` and `xfail_similarity_low_th: "0.30"`.
The test fails with a message loaded from `middle_range_failure.txt` (PFC
watchdog timer with slightly different values). The similarity score lands
in the middle range (between 0.30 and 0.95), triggering AI agent consultation.

13. **test_ai_returns_same_issue**: Mock AI returns
    `{"is_same_issue": true, "reasoning": "Both failures are PFC watchdog
    timer accuracy issues", "processing_time_ms": 500}`. Expected: xfail
    with AI reasoning in detail.

14. **test_ai_returns_different_issue**: Mock AI returns
    `{"is_same_issue": false, "reasoning": "Different root cause detected",
    "processing_time_ms": 300}`. Expected: failed.

15. **test_ai_timeout**: Mock server sleeps for 60 seconds. Signature sets
    `xfail_ai_agent_timeout: "10"`. Client times out. Expected: xfail
    fallback with "unavailable" in detail.

16. **test_ai_error_500**: Mock server returns HTTP 500. Expected: xfail
    fallback with "unavailable" in detail.

17. **test_ai_malformed_response**: Mock server returns
    `{"garbage": true, "no_is_same_issue_field": 42}` (missing
    `is_same_issue`). Expected: xfail fallback with "unavailable" in detail.

18. **test_ai_disabled_fallback**: `XFAIL_AI_AGENT_URL` is monkeypatched
    to an empty string. Score in middle range. Expected: xfail with
    "not configured" in detail.

### Multi-Issue AI Disambiguation

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 19 | `test_multi_issue_ai_one_match` | Close scores, AI matches one | **xfail** (detail contains "AI agent decision: same_issue") |
| 20 | `test_multi_issue_ai_none_match` | Close scores, AI rejects all | **failed** |
| 21 | `test_multi_issue_ai_all_error` | Close scores, AI errors for all | **xfail** (detail contains "unavailable") |

#### Details

All multi-issue AI tests use issues 990099012 and 990099013 (OR condition).
Both signatures have `xfail_similarity_high_th: "0.95"`,
`xfail_similarity_low_th: "0.30"`, and `xfail_ai_agent_timeout: "10"`. Test
fails with a message loaded from `multi_issue_close_scores.txt` (route
redistribution failure). Both issues produce similar middle-range scores
(gap < 0.10), triggering AI disambiguation.

19. **test_multi_issue_ai_one_match**: Mock AI returns `same_issue` for the
    first request (BGP redistribution match) and `different_issue` for the
    second (OSPF redistribution). Expected: xfail based on the matched issue.

20. **test_multi_issue_ai_none_match**: Mock AI returns `different_issue`
    for both requests. Expected: failed.

21. **test_multi_issue_ai_all_error**: Mock AI returns HTTP 500 for all
    requests. Expected: xfail fallback.

### Edge Case

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 22 | `test_no_excinfo_fallback` | Test passes, no `_dynamic_xfail_info` | **passed** |

#### Details

22. **test_no_excinfo_fallback**: Test function passes. This test has no
    entry in the mark conditions YAML, so no `_dynamic_xfail_info` is set.
    The hook does not process it. Expected: passed.

---

## Test Cases -- Real AI Tests (test_fvxfail_real_ai.py)

These tests hit the real AI agent service at the URL configured in
`failure_signature.XFAIL_AI_AGENT_URL`. They validate that the end-to-end
flow works with a live LLM backend. These tests require the AI agent service
to be running and accessible.

| # | Test Name | Flow | Expected Outcome |
|---|---|---|---|
| 23 | `test_real_ai_same_issue` | Middle range score, real AI evaluates | **xfail** (detail contains "AI agent decision: same_issue") |
| 24 | `test_real_ai_multi_issue` | Two close-score issues, real AI disambiguates | **xfail** (detail contains "AI agent decision: same_issue") |

#### Details

23. **test_real_ai_same_issue**: Uses issue 990099003 (PFC watchdog timer).
    Test fails with a message loaded from `middle_range_failure.txt`. The
    similarity score lands in the middle range, triggering a real AI agent
    call. The AI should recognize the same PFC watchdog timer pattern and
    return `same_issue`. Expected: xfail.

24. **test_real_ai_multi_issue**: Uses issues 990099012 and 990099013 (route
    redistribution, OR condition). Test fails with a message loaded from
    `multi_issue_close_scores.txt`. Both issues produce close middle-range
    scores. The real AI should match one of them (the BGP redistribution
    issue). Expected: xfail.

---

## Not Covered (requires real DUT)

- **Loganalyzer teardown exemption**: Requires a real DUT to inject syslog
  errors and trigger the real loganalyzer fixture teardown. The exemption is
  a simple string match (`tests/common/plugins/loganalyzer/__init__.py` in
  `longreprtext`) and can be verified in a real regression run.

## Running the Tests

### Mock Tests (recommended for CI)

Run the wrapper to validate all mock test outcomes automatically:

```bash
cd tests
pytest common/plugins/conditional_mark/integration_test/test_fvxfail_mock_wrapper.py -v
```

Or run the mock tests directly to see raw pytest results:

```bash
cd tests
pytest common/plugins/conditional_mark/integration_test/test_fvxfail_mock.py -v --tb=short -ra
```

### Real AI Tests (requires AI agent service)

Run the wrapper to validate real AI test outcomes automatically:

```bash
cd tests
pytest common/plugins/conditional_mark/integration_test/test_fvxfail_real_ai_wrapper.py -v
```

Or run the real AI tests directly:

```bash
cd tests
pytest common/plugins/conditional_mark/integration_test/test_fvxfail_real_ai.py -v --tb=short -ra
```
