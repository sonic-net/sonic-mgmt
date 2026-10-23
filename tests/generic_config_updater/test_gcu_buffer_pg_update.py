import logging
import pytest

from tests.common.utilities import skip_release, wait_until
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


def _get_buffer_profiles(duthost, cli_namespace_prefix):
    profiles = _get_config_db_keys(duthost, cli_namespace_prefix, "BUFFER_PROFILE")
    return [p.split("|", 1)[1] for p in profiles]


def _get_buffer_pg_entries(duthost, cli_namespace_prefix):
    keys = _get_config_db_keys(duthost, cli_namespace_prefix, "BUFFER_PG")
    entries = []
    for key in keys:
        parts = key.split("|")
        if len(parts) < 3:
            continue
        port = parts[1]
        pg_token = parts[2]
        pg_num = pg_token.split("-")[0]
        entry_key = "|".join(parts[1:])
        entries.append((port, pg_num, entry_key))
    return entries


def _get_cable_length(duthost, cli_namespace_prefix, port):
    return duthost.shell(
        f"sonic-db-cli {cli_namespace_prefix} CONFIG_DB hget 'CABLE_LENGTH|AZURE' '{port}'"
    )["stdout"].strip()


def _is_zero_cable_length(duthost, cli_namespace_prefix, port):
    value = _get_cable_length(duthost, cli_namespace_prefix, port)
    return value in {"0", "0m", "0M"}


def _find_pg_key(duthost, cli_namespace_prefix, port, pg_num):
    keys = _get_config_db_keys(duthost, cli_namespace_prefix, "BUFFER_PG")
    prefix = f"BUFFER_PG|{port}|{pg_num}"
    for key in keys:
        if key.startswith(prefix):
            return key
    return None


def _entry_exists_by_key(duthost, cli_namespace_prefix, entry_key):
    actual = duthost.shell(
        f"sonic-db-cli {cli_namespace_prefix} CONFIG_DB exists 'BUFFER_PG|{entry_key}'"
    )["stdout"].strip()
    return actual == "1"


def _pg_profile_equals(duthost, cli_namespace_prefix, port, pg_num, expected_profile):
    key = _find_pg_key(duthost, cli_namespace_prefix, port, pg_num)
    if not key:
        return False
    profile = duthost.shell(
        f"sonic-db-cli {cli_namespace_prefix} CONFIG_DB hget '{key}' profile"
    )["stdout"].strip()
    return profile == expected_profile


def _pg_entry_exists_bool(duthost, cli_namespace_prefix, port, pg_num):
    key = _find_pg_key(duthost, cli_namespace_prefix, port, pg_num)
    if not key:
        return False
    actual = duthost.shell(
        f"sonic-db-cli {cli_namespace_prefix} CONFIG_DB exists '{key}'"
    )["stdout"].strip()
    return actual == "1"


def _get_pg_entry_profile(duthost, cli_namespace_prefix, entry_key):
    return duthost.shell(
        f"sonic-db-cli {cli_namespace_prefix} CONFIG_DB hget 'BUFFER_PG|{entry_key}' profile"
    )["stdout"].strip()


def _pick_pg_entry_for_replace(duthost, cli_namespace_prefix, profiles):
    entries = _get_buffer_pg_entries(duthost, cli_namespace_prefix)
    for port, pg_num, entry_key in entries:
        if _is_zero_cable_length(duthost, cli_namespace_prefix, port):
            continue
        current = _get_pg_entry_profile(duthost, cli_namespace_prefix, entry_key)
        if not current:
            continue

        if "lossless" in current:
            candidates = [p for p in profiles if "lossless" in p and p != current]
        elif "lossy" in current:
            candidates = [p for p in profiles if "lossy" in p and p != current]
        else:
            continue

        if candidates:
            return port, pg_num, entry_key, current, candidates[0]

    return None


def _pick_pg_entry_for_remove(duthost, cli_namespace_prefix):
    entries = _get_buffer_pg_entries(duthost, cli_namespace_prefix)
    for port, pg_num, entry_key in entries:
        if _is_zero_cable_length(duthost, cli_namespace_prefix, port):
            continue
        current = _get_pg_entry_profile(duthost, cli_namespace_prefix, entry_key)
        if current and "lossless" not in current:
            return port, pg_num, entry_key, current

    return None


@pytest.mark.parametrize("operation", ["replace"])
def test_gcu_buffer_pg_profile_replace_succeeds(ensure_dut_readiness, rand_unselected_dut,
                                                cli_namespace_prefix, operation):
    """Replace BUFFER_PG profile and expect success."""
    duthost = ensure_dut_readiness[0]
    profiles = _get_buffer_profiles(duthost, cli_namespace_prefix)

    if len(profiles) < 2:
        pytest.skip("Insufficient BUFFER_PG entries or BUFFER_PROFILEs")

    pick = _pick_pg_entry_for_replace(duthost, cli_namespace_prefix, profiles)
    if not pick:
        pytest.skip("No suitable BUFFER_PG entry found for replace")

    port, pg_num, entry_key, current_profile, new_profile = pick

    json_patch = [{
        "op": operation,
        "path": f"/BUFFER_PG/{entry_key}/profile",
        "value": new_profile
    }]
    json_patch = format_json_patch_for_multiasic(duthost, json_patch)

    for dut, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
        expect_op_success(dut, output)

    pytest_asserted = wait_until(30, 3, 0,
                                 _pg_profile_equals,
                                 duthost,
                                 cli_namespace_prefix,
                                 port,
                                 pg_num,
                                 new_profile)
    assert pytest_asserted, "BUFFER_PG profile did not update in CONFIG_DB"


@pytest.mark.parametrize("operation", ["add"])
def test_gcu_buffer_pg_add_entry_succeeds(ensure_dut_readiness, rand_unselected_dut,
                                          cli_namespace_prefix, operation):
    """Re-create a BUFFER_PG entry via add and expect success."""
    duthost = ensure_dut_readiness[0]
    profiles = _get_buffer_profiles(duthost, cli_namespace_prefix)
    if not profiles:
        pytest.skip("No BUFFER_PROFILE entries found")

    pick = _pick_pg_entry_for_remove(duthost, cli_namespace_prefix)
    if not pick:
        pytest.skip("No suitable BUFFER_PG entry found for remove/add")

    port, pg_num, entry_key, profile = pick

    remove_patch = [{
        "op": "remove",
        "path": f"/BUFFER_PG/{entry_key}"
    }]
    remove_patch = format_json_patch_for_multiasic(duthost, remove_patch)

    for dut, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, remove_patch):
        expect_op_success(dut, output)

    if _entry_exists_by_key(duthost, cli_namespace_prefix, entry_key):
        pytest.skip("BUFFER_PG entry removal not effective; skipping add test")

    json_patch = [{
        "op": operation,
        "path": f"/BUFFER_PG/{entry_key}",
        "value": {"profile": profile}
    }]
    json_patch = format_json_patch_for_multiasic(duthost, json_patch)

    for dut, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
        expect_op_success(dut, output)

    pytest_asserted = wait_until(30, 3, 0,
                                 _pg_entry_exists_bool,
                                 duthost,
                                 cli_namespace_prefix,
                                 port,
                                 pg_num)
    assert pytest_asserted, "BUFFER_PG entry not re-created in CONFIG_DB"

    pytest_asserted = wait_until(30, 3, 0,
                                 _pg_profile_equals,
                                 duthost,
                                 cli_namespace_prefix,
                                 port,
                                 pg_num,
                                 profile)
    assert pytest_asserted, "BUFFER_PG profile not restored in CONFIG_DB"


@pytest.mark.parametrize("operation", ["remove"])
def test_gcu_buffer_pg_entry_remove_succeeds(ensure_dut_readiness, rand_unselected_dut,
                                             cli_namespace_prefix, operation):
    """Remove a BUFFER_PG entry and expect success."""
    duthost = ensure_dut_readiness[0]
    pick = _pick_pg_entry_for_remove(duthost, cli_namespace_prefix)
    if not pick:
        pytest.skip("No suitable BUFFER_PG entry found for remove")

    port, pg_num, entry_key, _ = pick
    json_patch = [{
        "op": operation,
        "path": f"/BUFFER_PG/{entry_key}"
    }]
    json_patch = format_json_patch_for_multiasic(duthost, json_patch)

    for dut, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
        expect_op_success(dut, output)

    pytest_asserted = wait_until(30, 3, 0,
                                 lambda: not _pg_entry_exists_bool(duthost, cli_namespace_prefix, port, pg_num))
    assert pytest_asserted, "BUFFER_PG entry was not removed from CONFIG_DB"


@pytest.mark.parametrize("operation", ["remove"])
def test_gcu_buffer_pg_profile_remove_fails(ensure_dut_readiness, rand_unselected_dut,
                                            cli_namespace_prefix, operation):
    """Remove BUFFER_PG profile field and expect failure (leafref)."""
    duthost = ensure_dut_readiness[0]
    entries = _get_buffer_pg_entries(duthost, cli_namespace_prefix)
    if not entries:
        pytest.skip("No BUFFER_PG entries found")

    port, pg_num, entry_key = entries[0]
    json_patch = [{
        "op": operation,
        "path": f"/BUFFER_PG/{entry_key}/profile"
    }]
    json_patch = format_json_patch_for_multiasic(duthost, json_patch)

    for _, output in apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
        expect_op_failure(output)
