"""
Test cases for sFlow drop_monitor_limit (CLI).

Valid range:
    0       -> disable
    1..500  -> valid

Invalid:
    < 0
    > 500
    non-numeric values

"""

import pytest

pytestmark = [
    pytest.mark.topology("t0", "t1"),
]

SFLOW_TABLE = "SFLOW|global"
DROP_LIMIT_FIELD = "drop_monitor_limit"
CLI_CMD = "config sflow drop-monitor-limit"
PLATFORM_UNSUPPORTED_MSG = "not supported on this platform"

BASELINE_VALUE = 100


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


def read_drop_limit_raw(duthost):
    """
    Return drop_monitor_limit as a raw string, or None when the field is absent.

    A redis-cli failure must not be mistaken for an absent field, so a non-zero
    rc is an assertion failure rather than None.
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

    value = result.get("stdout", "").strip()
    return value if value != "" else None


def write_drop_limit_raw(duthost, value):
    """
    Write drop_monitor_limit directly to CONFIG_DB, or delete it when value is
    None. Used only to undo writes made by this module.
    """
    if value is None:
        cmd = "redis-cli -n 4 hdel '{}' {}".format(SFLOW_TABLE, DROP_LIMIT_FIELD)
    else:
        cmd = "redis-cli -n 4 hset '{}' {} '{}'".format(
            SFLOW_TABLE, DROP_LIMIT_FIELD, value
        )

    result = duthost.shell(cmd, module_ignore_errors=True)

    assert result["rc"] == 0, (
        "Failed to restore {}: stdout={!r}, stderr={!r}".format(
            DROP_LIMIT_FIELD,
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
    )


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


# ------------------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def cli_sflow_drop_monitor_support(duthost):
    """
    Skip the whole module when the image or the platform lacks drop-monitor-limit.

    '--help' only proves the command is present; the platform capability check
    runs at execution time, so the probe has to actually invoke the command.
    The probe writes to CONFIG_DB and runs before the function-scoped
    preserve_sflow_drop_limit fixture, so it snapshots and restores on its own --
    otherwise the probed value would become the "original" that every later test
    restores to.
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

    original = read_drop_limit_raw(duthost)
    try:
        probe = run_drop_limit_cli(duthost, BASELINE_VALUE)
    finally:
        write_drop_limit_raw(duthost, original)

    skip_if_platform_unsupported(probe)

    assert probe["rc"] == 0, (
        "CLI '{}' failed for valid value {} for an unrecognized reason: "
        "rc={}, stdout={!r}, stderr={!r}".format(
            CLI_CMD,
            BASELINE_VALUE,
            probe["rc"],
            probe.get("stdout", ""),
            probe.get("stderr", ""),
        )
    )
    return True


@pytest.fixture(autouse=True)
def preserve_sflow_drop_limit(duthost):
    """
    Save and restore drop_monitor_limit around every test in this module.

    Module-level autouse: it does not run for other test files in tests/sflow.
    """
    original = read_drop_limit_raw(duthost)

    yield

    write_drop_limit_raw(duthost, original)


# ------------------------------------------------------------------------------
# Tests
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


@pytest.mark.parametrize("value", [-1, -10, 501, 999, "abc"])
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
        2. Apply the invalid value; CLI must fail.
        3. CONFIG_DB must still hold the baseline value.
    """

    baseline = run_drop_limit_cli(duthost, BASELINE_VALUE)
    assert baseline["rc"] == 0, (
        "Failed to set baseline drop-monitor-limit {}: stdout={!r}, stderr={!r}".format(
            BASELINE_VALUE,
            baseline.get("stdout", ""),
            baseline.get("stderr", ""),
        )
    )
    baseline_value = get_drop_limit_from_db(duthost)

    result = run_drop_limit_cli(duthost, value)
    output = "{}\n{}".format(
        result.get("stdout", ""),
        result.get("stderr", ""),
    ).lower()

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

    # Invalid input must not modify the existing CONFIG_DB value.
    db_value = get_drop_limit_from_db(duthost)

    assert db_value == baseline_value, (
        "Invalid value {} modified CONFIG_DB: before={}, after={}".format(
            value, baseline_value, db_value
        )
    )
