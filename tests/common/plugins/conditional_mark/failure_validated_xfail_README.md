# Failure-Validated xfail

## Problem

The `conditional_mark` plugin allows tests to be marked as `xfail` (expected
failure) when a known issue is linked in the conditions YAML. However, if a
test fails for a **completely different reason** than the known issue, the
failure is still silently xfail'd. This masks new regressions behind existing
known issues.

## Solution

The Failure-Validated xfail feature validates whether the actual test failure
matches the known issue **before** accepting the xfail. It does this by:

1. Storing a **failure signature** (exception type, message, stack trace, and
   a human-authored matching rule) for each known issue.
2. When a test fails at runtime, comparing the actual failure against the
   stored signature using a similarity score.
3. Using a **three-tier decision**:
   - **High similarity** (>= high threshold): same issue, apply xfail.
   - **Low similarity** (<= low threshold): different issue, report as failure.
   - **Middle range**: optionally consult an external AI agent for a more
     nuanced comparison.

If no signature file exists for an issue, the test falls back to the original
static xfail behavior. If the AI agent is unavailable, the test falls back to
xfail (preserving current behavior).

## How It Works

### Collection Phase

During `pytest_collection_modifyitems`, when a test has an `xfail` condition
that references a known issue URL:

1. The plugin checks if a signature file exists for any of the issue URLs.
2. If signature files are found, the plugin does **not** add the `xfail` mark.
   Instead, it stores the issue URLs and loaded signatures on the test item
   as `item._dynamic_xfail_info`.
3. If no signature files exist, the standard static xfail mark is applied
   (current behavior, unchanged).

### Runtime Phase

During `pytest_runtest_makereport`, when a test with `_dynamic_xfail_info`
fails (in any phase: setup, call, or teardown):

1. The current failure signature is extracted from the pytest exception info.
2. Each issue's stored signatures are scored against the current failure.
3. The three-tier decision logic determines whether the failure matches.
4. The test report is updated accordingly:
   - `same_issue`: report is changed to xfail (expected failure).
   - `different_issue`: report remains as a failure, with a note prepended
     to the status message indicating that the known issue did not match.

### Loganalyzer Exemption

Teardown failures originating from the `loganalyzer` fixture
(`tests/common/plugins/loganalyzer/__init__.py`) are excluded from
Failure-Validated xfail processing, as these are reported separately by the
bug handler.

## File Structure

```
tests/common/plugins/conditional_mark/
    __init__.py                  # Modified: collection + runtime hooks
    failure_signature.py         # Signature loading, scoring, evaluation
    ai_agent_client.py           # HTTP client for the AI agent service
    dice_similarity.py           # Sorensen-Dice string similarity algorithm
    known_issue_signatures/      # Directory for signature YAML files
        known_issue_signatures_mgmt_1234.yaml
        known_issue_signatures_buildimage_5678.yaml
```

## Signature YAML Format

Each known issue has a YAML file under `known_issue_signatures/` named:

```
known_issue_signatures_{source}_{number}.yaml
```

Where `{source}` is derived from the issue URL (`mgmt` for sonic-mgmt,
`buildimage` for sonic-buildimage) and `{number}` is the issue ID.

### Schema

```yaml
signatures:
  - name: descriptive_name_for_this_failure_pattern
    exception_type: |-
      Failed
    message: |-
      The pytest exception message (from exconly()).
      Can be multi-line.
    stack_trace: |-
      The full stack trace (from longreprtext).
      Can be very long.
    failure_matching_rule: >-
      A human-authored rule describing how to identify this failure.
      This is used by the AI agent as a "golden rule" when the similarity
      score is in the middle range. Example: "If the error is a timeout
      in _wait_on_pending_results, then it is the same issue."
    # Optional per-signature threshold overrides:
    xfail_similarity_high_th: 0.90
    xfail_similarity_low_th: 0.60
    xfail_ai_agent_timeout: 30
```

### Required Fields

These three fields are mandatory for each signature entry. If any is
missing or empty, the signature is skipped and the test falls back to
static xfail behavior:

| Field | Description |
|---|---|
| `message` | The exception message string (from `call.excinfo.exconly()`). |
| `stack_trace` | The full pytest stack trace (from `report.longreprtext`). |
| `failure_matching_rule` | Engineer-authored natural language rule for the AI agent. |

### Optional Fields

| Field | Default | Description |
|---|---|---|
| `name` | `signature_N` | Human-readable name for logging. |
| `exception_type` | (empty) | Exception class name. See details below. |
| `xfail_similarity_high_th` | `0.90` | Score at or above this is treated as the same issue. |
| `xfail_similarity_low_th` | `0.60` | Score at or below this is treated as a different issue. |
| `xfail_ai_agent_timeout` | `30` | Timeout in seconds for the AI agent request. |
| `w_type` | `0.00` | Weight for exception_type in similarity scoring. |
| `w_message` | `0.60` | Weight for message in similarity scoring. |
| `w_trace` | `0.40` | Weight for stack_trace in similarity scoring. |

The `w_type`, `w_message`, and `w_trace` fields allow per-signature tuning
of the similarity scoring weights. They must sum to 1.0. For example, if you
know that the exception type is a reliable signal for a particular issue, you
can increase its weight:

```yaml
signatures:
  - name: specific_key_error
    exception_type: KeyError
    message: |-
      ...
    stack_trace: |-
      ...
    failure_matching_rule: "..."
    w_type: "0.15"
    w_message: "0.50"
    w_trace: "0.35"
```

#### About exception_type

The `exception_type` corresponds to `call.excinfo.typename` in pytest -- the
class name of the exception, without the module path. Common values in
sonic-mgmt tests:

| `exception_type` | Source | Example |
|---|---|---|
| `Failed` | `pytest.fail("reason")` | Most explicit test failures |
| `AssertionError` | `assert expr, "message"` | Assertion-based checks |
| `RunAnsibleModuleFail` | Ansible module execution failure | PTF test runner failures |
| `KeyError` | `dict[missing_key]` | Unexpected data structure |
| `TimeoutError` | Timeout waiting for condition | Polling/wait failures |

At runtime, `exception_type` is obtained from `call.excinfo.typename` in the
`pytest_runtest_makereport` hook. In pytest terminal output, it appears on the
lines prefixed with `E` in the traceback (e.g. `E  KeyError`,
`E  Failed: ...`, `E  AssertionError: ...`). The `message` comes from
`call.excinfo.exconly()` and the `stack_trace` from `report.longreprtext`.

The `exception_type` weight in similarity scoring is set to 0.0 by default
because it is easy to get wrong (the same root cause can surface as different
exception types depending on the code path). It is still useful for
documentation purposes and as context for the AI agent, but it does not affect
the similarity score unless `w_type` is explicitly set in the signature YAML.

### Multiple Signatures Per Issue

A single issue may manifest with different failure patterns (e.g. different
error messages in different tests). Add multiple entries under
`signatures:` to handle this. The best-matching signature is used.

### Multiple Issues Per Condition

When a condition uses the `or` operator with multiple active issue URLs, signatures
for all issues are loaded and scored. The evaluation logic:

1. Classifies each issue by its score against the thresholds (high match,
   middle range, or low reject).
2. If any issue scores above its high threshold, it is used immediately.
3. If multiple issues are in the middle range with close scores (gap < 0.10),
   the AI agent is consulted for all of them.

## Similarity Scoring

The similarity score is a weighted combination of three components:

| Component | Default Weight | Method |
|---|---|---|
| `exception_type` | 0.00 | Exact match (1.0 if equal, 0.0 otherwise) |
| `message` | 0.60 | Dice coefficient on the full message strings |
| `stack_trace` | 0.40 | Dice coefficient on the full stack trace strings |

The `exception_type` weight is 0.0 by default because the same root cause
can manifest as different exception types (e.g. `Failed` vs `AssertionError`
vs `RunAnsibleModuleFail`). The default weights can be adjusted globally in
`failure_signature.py` (`W_TYPE`, `W_MESSAGE`, `W_TRACE`), or per-signature
in the YAML file using `w_type`, `w_message`, `w_trace`. Weights must sum
to 1.0.

The Sorensen-Dice coefficient computes similarity based on shared character
bigrams, producing a score between 0.0 and 1.0.

## Adding Custom Issue Tracker URL Patterns

By default, the plugin recognizes GitHub sonic-mgmt and sonic-buildimage issue
URLs. To add support for additional issue trackers (e.g. an internal bug
tracker), create a file `fv_custom_url_patterns.py` in the
`conditional_mark` directory:

```python
import re

CUSTOM_URL_PATTERNS = [
    # Internal tracker: https://tracker.example.com/issues/12345
    (re.compile(r'https?://tracker\.example\.com/issues/(\d+)'), 'internal'),
]
```

Each entry is a tuple of `(compiled_regex, source_name)`. The regex must have
one capture group for the issue number. The `source_name` is used in the
signature filename (e.g. `known_issue_signatures_internal_12345.yaml`).

## AI Agent Backend Service (Optional)

The AI agent is an optional external service that provides LLM-based failure
comparison for cases where the similarity score is inconclusive (middle
range). The feature works without it -- middle-range scores fall back to
xfail when no agent is configured.

### Configuration

Set the `XFAIL_AI_AGENT_URL` constant in `failure_signature.py` to the base
URL of your AI agent service. Set it to an empty string to disable the
feature.

### REST API Contract

The client sends a `POST` request to `{XFAIL_AI_AGENT_URL}/compare-failures`.

#### Request

```http
POST /compare-failures
Content-Type: application/json
```

```json
{
  "reference_failure": {
    "exception_type": "Failed",
    "exception_message": "The stored exception message from the signature.",
    "stack_trace": "The stored stack trace from the signature.",
    "failure_matching_rule": "Engineer-authored rule for identifying this failure."
  },
  "current_failure": {
    "exception_type": "Failed",
    "exception_message": "The actual exception message from the live test.",
    "stack_trace": "The actual stack trace from the live test."
  },
  "issue_url": "https://github.com/sonic-net/sonic-mgmt/issues/1234",
  "stream": false
}
```

| Field | Required | Description |
|---|---|---|
| `reference_failure` | Yes | The stored failure signature from the YAML file. |
| `reference_failure.exception_type` | Yes | Exception class name. |
| `reference_failure.exception_message` | Yes | Exception message. |
| `reference_failure.stack_trace` | Yes | Full stack trace. |
| `reference_failure.failure_matching_rule` | Yes | Engineer-authored matching rule. |
| `current_failure` | Yes | The live test failure to compare against. |
| `current_failure.exception_type` | Yes | Exception class name. |
| `current_failure.exception_message` | Yes | Exception message. |
| `current_failure.stack_trace` | Yes | Full stack trace. |
| `issue_url` | No | Known issue URL, for context only (not queried). |
| `stream` | No | Set to `false` for JSON response (default). |

#### Response

```json
{
  "is_same_issue": true,
  "reasoning": "Both failures show the same timeout pattern in _wait_on_pending_results...",
  "processing_time_ms": 1200
}
```

| Field | Type | Description |
|---|---|---|
| `is_same_issue` | boolean | `true` if the failures are caused by the same issue. |
| `reasoning` | string | Explanation of the decision. |
| `processing_time_ms` | integer | Time taken to process the request in milliseconds. |

#### Error Responses

- `400`: Invalid request (missing fields, invalid values).
- `500`: Internal server error.
- `502`: Upstream LLM service error.

### Implementation Guidelines

When implementing an AI agent backend, the service should:

1. Accept the request payload described above.
2. Use the `failure_matching_rule` as a primary guide -- it is an
   engineer-authored "golden rule" describing how to identify this specific
   failure pattern.
3. Compare the `reference_failure` and `current_failure` to determine if they
   share the same root cause.
4. Return a JSON response with `is_same_issue`, `reasoning`, and
   `processing_time_ms`.
5. Respond within the configured timeout (default 30 seconds).

### Fallback Behavior

| Scenario | Behavior |
|---|---|
| `XFAIL_AI_AGENT_URL` is empty | Middle-range scores fall back to xfail. |
| AI agent is unreachable | Middle-range scores fall back to xfail. |
| AI agent times out | Middle-range scores fall back to xfail. |
| AI agent returns an error | Middle-range scores fall back to xfail. |

## Quick Start

1. **Create a signature file** for a known issue:

   ```bash
   # File: known_issue_signatures/known_issue_signatures_mgmt_1234.yaml
   ```

   Populate it with the exception type, message, and stack trace from an
   Allure report or pytest output for the known failure, plus a matching rule.

2. **Add or verify the xfail condition** in `tests_mark_conditions.yaml`:

   ```yaml
   path/to/test.py::test_name:
     xfail:
       reason: "Known issue: https://github.com/sonic-net/sonic-mgmt/issues/1234"
       conditions:
         - "https://github.com/sonic-net/sonic-mgmt/issues/1234"
   ```

3. **Run the test**. If the failure matches the stored signature, it will be
   reported as xfail. If it does not match, it will be reported as a failure
   with a note indicating the known issue did not match.
