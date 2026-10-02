"""
Test cases for sFlow drop_monitor_limit (YANG and CLI).

Valid range:
    0       -> disable
    1..500  -> valid

Invalid:
    < 0
    > 500
    non-numeric values

YANG tests validate values directly against the installed SONiC YANG models
with sonic_yang (no CONFIG_DB change). CLI tests use
'config sflow drop-monitor-limit' and verify CONFIG_DB.
"""

import json
import shlex

import pytest

pytestmark = [
    pytest.mark.topology("t0", "t1"),
]

SFLOW_TABLE = "SFLOW|global"
DROP_LIMIT_FIELD = "drop_monitor_limit"
CLI_CMD = "config sflow drop-monitor-limit"
PLATFORM_UNSUPPORTED_MSG = "not supported on this platform"

BASELINE_VALUE = 100

# CLI error messages
CLI_RANGE_ERROR_MSG = "Drop monitor limit must be between 1-500 (0 to disable)"
CLI_TYPE_ERROR_MSG = "is not a valid integer"

# YANG
YANG_DIR = "/usr/local/yang-models"
SFLOW_YANG_FILE = "{}/sonic-sflow.yang".format(YANG_DIR)
YANG_ERROR_MSG_PREFIX = "sFlow packet drop monitor limit must be"
YANG_OK_MARKER = "YANG_VALIDATION_OK"
YANG_FAILED_MARKER = "YANG_VALIDATION_FAILED"
YANG_LOGANALYZER_IGNORE = [
    r".*ERR sonic_yang: Data Loading Failed.*",
]


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def run_drop_limit_cli(duthost, value):
    """
    Run 'config sflow drop-monitor-limit <value>'.

    '--' ends option parsing so negative numbers (e.g. -1) are passed to the
    command as values instead of being parsed by Click as unknown options.
    """
    result = duthost.shell(
        "{} -- {}".format(CLI_CMD, value),
        module_ignore_errors=True,
    )
    return result


def skip_if_platform_unsupported(result):
    """
    Skip when the CLI reports that drop monitoring is not supported on this
    platform.
    """
    output = "{}\n{}".format(result.get("stdout", ""), result.get("stderr", ""))
    if result["rc"] != 0 and PLATFORM_UNSUPPORTED_MSG in output.lower():
        pytest.skip("Drop monitor is not supported on this platform: {!r}".format(output.strip()))


def get_drop_limit_from_db(duthost, required=True):
    """
    Read drop_monitor_limit from CONFIG_DB.

    Args:
        required: if True, fail when the field is absent; if False, return None.

    Returns:
        int value, or None when absent and required is False.
    """
    result = duthost.shell(
        "redis-cli -n 4 hget '{}' {}".format(SFLOW_TABLE, DROP_LIMIT_FIELD),
        module_ignore_errors=True,
    )

    assert result["rc"] == 0, (
        "Failed to read {} from CONFIG_DB: stdout={!r}, stderr={!r}".format(
            DROP_LIMIT_FIELD,
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
    )

    value = result["stdout"].strip()
    if value == "":
        assert not required, (
            "{} is missing from CONFIG_DB table {}".format(DROP_LIMIT_FIELD, SFLOW_TABLE)
        )
        return None

    try:
        return int(value)
    except ValueError:
        pytest.fail(
            "Invalid CONFIG_DB value for {}: {!r}".format(DROP_LIMIT_FIELD, value)
        )


def run_drop_limit_yang_validation(duthost, value):
    """
    Validate drop_monitor_limit directly against the SONiC YANG models.

    This does not modify CONFIG_DB. The equivalent CONFIG_DB structure passed
    to SonicYang is:

        {"SFLOW": {"global": {"drop_monitor_limit": "<value>"}}}

    stdout contains:
        YANG_VALIDATION_OK              -> accepted
        YANG_VALIDATION_FAILED: <msg>   -> rejected by data validation

    Import or model-load errors happen outside the try block and print
    neither marker, so they cannot be mistaken for a YANG rejection.
    """
    config = {"SFLOW": {"global": {DROP_LIMIT_FIELD: str(value)}}}

    script = (
        "import json, sys\n"
        "import sonic_yang\n"
        "sy = sonic_yang.SonicYang({yang_dir!r}, print_log_enabled=False)\n"
        "sy.loadYangModel()\n"
        "try:\n"
        "    sy.loadData(json.loads({cfg!r}))\n"
        "except Exception as e:\n"
        "    print({failed!r} + ': ' + str(e))\n"
        "    sys.exit(1)\n"
        "print({ok!r})\n"
    ).format(
        yang_dir=YANG_DIR,
        cfg=json.dumps(config),
        failed=YANG_FAILED_MARKER,
        ok=YANG_OK_MARKER,
    )

    return duthost.shell(
        "python3 -c {}".format(shlex.quote(script)),
        module_ignore_errors=True,
    )


# ------------------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def cli_sflow_drop_monitor_support(duthost):
    """
    Verify that 'config sflow drop-monitor-limit' exists on the image.
    """
    result = duthost.shell(
        "{} --help".format(CLI_CMD),
        module_ignore_errors=True,
    )
    output = "{}\n{}".format(
        result.get("stdout", ""),
        result.get("stderr", ""),
    ).lower()

    assert result["rc"] == 0 and "drop-monitor-limit" in output, (
        "Required CLI '{}' is not available on the image "
        "(provided by sonic-buildimage PR #24421): "
        "rc={}, stdout={!r}, stderr={!r}".format(
            CLI_CMD,
            result["rc"],
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
    )
    return True


@pytest.fixture(autouse=True)
def preserve_sflow_drop_limit(duthost):
    """
    Save and restore drop_monitor_limit around every test in this module.

    Module-level autouse: it does not run for other test files in tests/sflow.
    """
    original = duthost.shell(
        "redis-cli -n 4 hget '{}' {}".format(SFLOW_TABLE, DROP_LIMIT_FIELD),
        module_ignore_errors=True,
    )
    # A redis-cli failure must not be mistaken for an absent field.
    assert original["rc"] == 0, (
        "Failed to snapshot {} from CONFIG_DB: stdout={!r}, stderr={!r}".format(
            DROP_LIMIT_FIELD,
            original.get("stdout", ""),
            original.get("stderr", ""),
        )
    )
    original_value = original.get("stdout", "").strip()
    originally_present = original_value != ""

    yield

    if originally_present:
        restore = duthost.shell(
            "redis-cli -n 4 hset '{}' {} '{}'".format(
                SFLOW_TABLE, DROP_LIMIT_FIELD, original_value
            ),
            module_ignore_errors=True,
        )
    else:
        restore = duthost.shell(
            "redis-cli -n 4 hdel '{}' {}".format(SFLOW_TABLE, DROP_LIMIT_FIELD),
            module_ignore_errors=True,
        )

    assert restore["rc"] == 0, (
        "Failed to restore {} after test: stdout={!r}, stderr={!r}".format(
            DROP_LIMIT_FIELD,
            restore.get("stdout", ""),
            restore.get("stderr", ""),
        )
    )


@pytest.fixture
def ignore_yang_validation_errors(duthost, loganalyzer):
    """
    Ignore the syslog ERR that sonic_yang logs for rejected data, since the
    rejection is the expected result of the invalid-value YANG tests.
    """
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(YANG_LOGANALYZER_IGNORE)


# ------------------------------------------------------------------------------
# YANG tests
# ------------------------------------------------------------------------------
def test_sflow_drop_monitor_limit_yang_schema(duthost):
    """
    Verify the installed sonic-sflow.yang defines drop_monitor_limit as:

        leaf drop_monitor_limit {
            type uint16 {
                range "0|1..500" {
                    error-message "sFlow packet drop monitor limit must be ...";
                }
            }
        }
    """
    file_check = duthost.shell(
        "test -f {}".format(shlex.quote(SFLOW_YANG_FILE)),
        module_ignore_errors=True,
    )
    assert file_check["rc"] == 0, (
        "{} does not exist on the DUT".format(SFLOW_YANG_FILE)
    )

    result = duthost.shell(
        "grep -A12 -B2 'leaf {}' {}".format(DROP_LIMIT_FIELD, shlex.quote(SFLOW_YANG_FILE)),
        module_ignore_errors=True,
    )
    assert result["rc"] == 0, (
        "{} leaf is not present in {} "
        "(provided by sonic-buildimage PR #24421): stdout={!r}, stderr={!r}".format(
            DROP_LIMIT_FIELD,
            SFLOW_YANG_FILE,
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
    )

    schema = result.get("stdout", "")
    for expected in ("type uint16", 'range "0|1..500"', YANG_ERROR_MSG_PREFIX):
        assert expected in schema, (
            "YANG leaf {} does not contain {!r}: {!r}".format(DROP_LIMIT_FIELD, expected, schema)
        )


@pytest.mark.parametrize("value", [0, 1, 250, 500])
def test_sflow_drop_monitor_limit_yang_valid(duthost, value):
    """
    Verify YANG accepts valid drop_monitor_limit values: 0, 1, 250, 500.
    """
    result = run_drop_limit_yang_validation(duthost, value)

    assert result["rc"] == 0 and YANG_OK_MARKER in result.get("stdout", ""), (
        "YANG rejected valid drop_monitor_limit value {}: "
        "rc={}, stdout={!r}, stderr={!r}".format(
            value,
            result["rc"],
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
    )


@pytest.mark.parametrize("value", [-1, -10, 501, 999, 10000, 65535, 65536, "abc"])
def test_sflow_drop_monitor_limit_yang_invalid(
    ignore_yang_validation_errors,
    duthost,
    value,
):
    """
    Verify YANG rejects invalid drop_monitor_limit values:
        -1, -10, 65536    -> not a uint16
        501, 999, 10000   -> outside range "0|1..500"
        65535             -> valid uint16 but outside range "0|1..500"
        abc               -> not an integer
    """
    result = run_drop_limit_yang_validation(duthost, value)
    stdout = result.get("stdout", "")

    assert result["rc"] != 0, (
        "YANG unexpectedly accepted invalid drop_monitor_limit value {}: "
        "stdout={!r}, stderr={!r}".format(value, stdout, result.get("stderr", ""))
    )

    # The rejection must come from data validation, not from an import or
    # YANG model load error.
    assert YANG_FAILED_MARKER in stdout, (
        "Expected YANG validation failure for value {}, got something else "
        "(import/model error?): rc={}, stdout={!r}, stderr={!r}".format(
            value, result["rc"], stdout, result.get("stderr", "")
        )
    )

    # In-type numbers above 500 must be rejected by the YANG range check.
    if value in (501, 999, 10000, 65535):
        assert YANG_ERROR_MSG_PREFIX in stdout, (
            "Value {} was rejected, but not by the {} range check: stdout={!r}".format(
                value, DROP_LIMIT_FIELD, stdout
            )
        )


# ------------------------------------------------------------------------------
# CLI tests
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("value", [0, 1, 250, 500])
def test_sflow_drop_monitor_limit_valid(
    cli_sflow_drop_monitor_support,
    duthost,
    value,
):
    """
    Verify that valid drop-monitor-limit values are accepted.

    Verify:
        1. CLI succeeds.
        2. CONFIG_DB contains the requested value.
    """

    result = run_drop_limit_cli(duthost, value)
    skip_if_platform_unsupported(result)

    assert result["rc"] == 0, (
        "CLI rejected valid drop-monitor-limit value {}: "
        "rc={}, stdout={!r}, stderr={!r}".format(
            value,
            result["rc"],
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
    )

    db_value = get_drop_limit_from_db(duthost)

    assert db_value == value, (
        "CONFIG_DB mismatch after setting drop-monitor-limit: "
        "expected={}, actual={}".format(value, db_value)
    )


@pytest.mark.parametrize("value", [-1, -10, 501, 999, 10000, "abc"])
def test_sflow_drop_monitor_limit_invalid(
    cli_sflow_drop_monitor_support,
    duthost,
    value,
):
    """
    Verify invalid drop-monitor-limit values are rejected and do not modify
    CONFIG_DB.

    Steps:
        1. Set a known baseline value.
        2. Apply the invalid value; CLI must fail with the expected error:
               numbers outside 0..500 -> range error
               non-numeric            -> integer type error
        3. CONFIG_DB must still hold the baseline value.
    """

    baseline = run_drop_limit_cli(duthost, BASELINE_VALUE)
    skip_if_platform_unsupported(baseline)
    assert baseline["rc"] == 0, (
        "Failed to set baseline drop-monitor-limit {}: stdout={!r}, stderr={!r}".format(
            BASELINE_VALUE,
            baseline.get("stdout", ""),
            baseline.get("stderr", ""),
        )
    )
    baseline_value = get_drop_limit_from_db(duthost)

    result = run_drop_limit_cli(duthost, value)
    raw_output = "{}\n{}".format(
        result.get("stdout", ""),
        result.get("stderr", ""),
    )
    output = raw_output.lower()

    assert result["rc"] != 0, (
        "CLI unexpectedly accepted invalid drop-monitor-limit "
        "value {}: stdout={!r}, stderr={!r}".format(
            value,
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
    )

    # The rejection must come from value validation, not from Click
    # treating the value as an unknown option.
    assert "no such option" not in output, (
        "Value {} was parsed as a CLI option instead of being validated: "
        "{!r}".format(value, output)
    )

    # The CLI must report the expected validation error.
    expected_error = CLI_TYPE_ERROR_MSG if value == "abc" else CLI_RANGE_ERROR_MSG
    assert expected_error in raw_output, (
        "Unexpected CLI error for invalid value {}: expected {!r} in {!r}".format(
            value, expected_error, raw_output
        )
    )

    # Invalid input must not modify the existing CONFIG_DB value.
    db_value = get_drop_limit_from_db(duthost)

    assert db_value == baseline_value, (
        "Invalid value {} modified CONFIG_DB: before={}, after={}".format(
            value, baseline_value, db_value
        )
    )
