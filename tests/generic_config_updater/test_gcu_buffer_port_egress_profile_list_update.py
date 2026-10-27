import ast
import json
import logging
import pytest

from tests.common.utilities import skip_release
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import format_json_patch_for_multiasic, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import apply_json_patch_to_duts, get_dualtor_duts

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

MIN_RELEASE_SKIP_LIST = ["201811", "201911", "202012", "202106", "202111", "202205", "202211", "202305", "202311"]


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthosts, rand_one_dut_hostname):
    """Skip for releases older than 202412."""
    duthost = duthosts[rand_one_dut_hostname]
    skip_release(duthost, MIN_RELEASE_SKIP_LIST)


@pytest.fixture(scope="function")
def ensure_dut_readiness(rand_selected_dut, rand_unselected_dut):
    """Create checkpoints and rollback after each test (dualtor-aware)."""
    duts = get_dualtor_duts(rand_selected_dut, rand_unselected_dut)
    for dut in duts:
        verify_orchagent_running_or_assert(dut)
        create_checkpoint(dut)

    yield duts

    try:
        for dut in duts:
            verify_orchagent_running_or_assert(dut)
            rollback_or_reload(dut)
    finally:
        for dut in duts:
            delete_checkpoint(dut)


def _get_config_db_keys(duthost, cli_namespace_prefix, table):
    keys = duthost.shell(
        f"sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}|*'"
    )["stdout_lines"]
    return [k for k in keys if k]


def _get_table_names(duthost, cli_namespace_prefix, table):
    return [k.split("|", 1)[1] for k in _get_config_db_keys(duthost, cli_namespace_prefix, table)]


def _get_profile_list_value(duthost, cli_namespace_prefix, port):
    key = f"BUFFER_PORT_EGRESS_PROFILE_LIST|{port}"
    return duthost.shell(
        f"sonic-db-cli {cli_namespace_prefix} CONFIG_DB hget '{key}' profile_list"
    )["stdout"].strip()


def _parse_profile_list(value):
    if not value:
        return [], ""
    if value.startswith("["):
        return ast.literal_eval(value), "json"
    return [v.strip() for v in value.split(",") if v.strip()], "csv"


def _serialize_profile_list(profiles, fmt):
    if fmt == "json":
        return json.dumps(profiles)
    return ",".join(profiles)


def _assert_profile_list(duthost, cli_namespace_prefix, port, expected_value):
    actual = _get_profile_list_value(duthost, cli_namespace_prefix, port)
    assert actual == expected_value, (
        f"Unexpected profile_list for {port}. expected={expected_value}, actual={actual}"
    )


@pytest.mark.parametrize("operation", ["replace"])
def test_gcu_buffer_port_egress_profile_list_replace_succeeds(ensure_dut_readiness, rand_unselected_dut,
                                                              cli_namespace_prefix, operation):
    """Replace BUFFER_PORT_EGRESS_PROFILE_LIST and expect success."""
    duthost = ensure_dut_readiness[0]
    ports = _get_table_names(duthost, cli_namespace_prefix, "BUFFER_PORT_EGRESS_PROFILE_LIST")
    profiles = _get_table_names(duthost, cli_namespace_prefix, "BUFFER_PROFILE")
    if not ports or not profiles:
        pytest.skip("Insufficient BUFFER_PORT_EGRESS_PROFILE_LIST or BUFFER_PROFILE entries")

    port = ports[0]
    current_value = _get_profile_list_value(duthost, cli_namespace_prefix, port)
    current_list, fmt = _parse_profile_list(current_value)

    new_profile = next((p for p in profiles if p not in current_list), None)
    if not new_profile:
        pytest.skip("No additional BUFFER_PROFILE to add to profile_list")

    new_list = current_list + [new_profile]
    new_value = _serialize_profile_list(new_list, fmt or "json")

    json_patch = [{
        "op": operation,
        "path": f"/BUFFER_PORT_EGRESS_PROFILE_LIST/{port}/profile_list",
        "value": new_value
    }]
    json_patch = format_json_patch_for_multiasic(duthost, json_patch)

    for dut, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
        expect_op_success(dut, output)

    _assert_profile_list(duthost, cli_namespace_prefix, port, new_value)


@pytest.mark.parametrize("operation", ["add"])
def test_gcu_buffer_port_egress_profile_list_add_succeeds(ensure_dut_readiness, rand_unselected_dut,
                                                          cli_namespace_prefix, operation):
    """Add BUFFER_PORT_EGRESS_PROFILE_LIST profile_list and expect success."""
    duthost = ensure_dut_readiness[0]
    ports = _get_table_names(duthost, cli_namespace_prefix, "BUFFER_PORT_EGRESS_PROFILE_LIST")
    profiles = _get_table_names(duthost, cli_namespace_prefix, "BUFFER_PROFILE")
    if not ports or not profiles:
        pytest.skip("Insufficient BUFFER_PORT_EGRESS_PROFILE_LIST or BUFFER_PROFILE entries")

    port = ports[0]
    current_value = _get_profile_list_value(duthost, cli_namespace_prefix, port)
    current_list, fmt = _parse_profile_list(current_value)

    if not current_list:
        new_list = [profiles[0]]
    else:
        new_list = current_list

    new_value = _serialize_profile_list(new_list, fmt or "json")

    json_patch = [{
        "op": operation,
        "path": f"/BUFFER_PORT_EGRESS_PROFILE_LIST/{port}/profile_list",
        "value": new_value
    }]
    json_patch = format_json_patch_for_multiasic(duthost, json_patch)

    for dut, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
        expect_op_success(dut, output)

    _assert_profile_list(duthost, cli_namespace_prefix, port, new_value)


@pytest.mark.parametrize("operation", ["remove"])
def test_gcu_buffer_port_egress_profile_list_remove_succeeds(ensure_dut_readiness, rand_unselected_dut,
                                                             cli_namespace_prefix, operation):
    """Remove BUFFER_PORT_EGRESS_PROFILE_LIST profile_list and expect success."""
    duthost = ensure_dut_readiness[0]
    ports = _get_table_names(duthost, cli_namespace_prefix, "BUFFER_PORT_EGRESS_PROFILE_LIST")
    if not ports:
        pytest.skip("No BUFFER_PORT_EGRESS_PROFILE_LIST entries found")

    port = ports[0]
    json_patch = [{
        "op": operation,
        "path": f"/BUFFER_PORT_EGRESS_PROFILE_LIST/{port}/profile_list"
    }]
    json_patch = format_json_patch_for_multiasic(duthost, json_patch)

    for dut, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
        expect_op_success(dut, output)


@pytest.mark.parametrize("operation", ["replace"])
def test_gcu_buffer_port_egress_profile_list_invalid_fails(ensure_dut_readiness, rand_unselected_dut,
                                                           cli_namespace_prefix, operation):
    """Replace BUFFER_PORT_EGRESS_PROFILE_LIST with invalid profile and expect failure."""
    duthost = ensure_dut_readiness[0]
    ports = _get_table_names(duthost, cli_namespace_prefix, "BUFFER_PORT_EGRESS_PROFILE_LIST")
    if not ports:
        pytest.skip("No BUFFER_PORT_EGRESS_PROFILE_LIST entries found")

    port = ports[0]
    json_patch = [{
        "op": operation,
        "path": f"/BUFFER_PORT_EGRESS_PROFILE_LIST/{port}/profile_list",
        "value": json.dumps(["NON_EXISTENT_PROFILE"])
    }]
    json_patch = format_json_patch_for_multiasic(duthost, json_patch)

    for _, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
        expect_op_failure(output)
