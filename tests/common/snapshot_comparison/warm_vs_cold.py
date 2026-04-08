"""Utilities specific for warm vs cold boot snapshots"""

from typing import Dict, List, Tuple
from tests.common.db_comparison import DBType, SnapshotDiff

AFTER_WARMBOOT = "after_warmboot"
AFTER_COLDBOOT = "after_coldboot"


def process_state_db_warm_restart_table_diff(state_db_snapshot_diff: SnapshotDiff) -> Tuple[List[str], List[str]]:
    """
    Processes the diff of the WARM_RESTART_TABLE from the state DB snapshot comparison between warm and cold boots.

    Args:
        state_db_snapshot_diff (SnapshotDiff): An object containing the diff between state DB snapshots after warm and
        cold boots.

    Returns:
        Tuple[List[str], List[str]]:
            - processed_keys: A list of keys from the diff that correspond to entries in the WARM_RESTART_TABLE.
            - errors: A list of error messages encountered during processing, including mismatches with the expected
                      WARM_RESTART_TABLE format or unexpected diff formats.
    """
    diff = state_db_snapshot_diff.diff
    processed_keys = []
    processed_warm_restart_table = {}
    errors = []
    for key, content in diff.items():
        if key.startswith("WARM_RESTART_TABLE|"):
            processed_keys.append(key)
            process = key.split("|", 1)[1]
            if AFTER_WARMBOOT in content and AFTER_COLDBOOT in content:
                # Diff is immediately at the key level (therefore key is only in one snapshot)
                warm_restart_table_entry = {}
                if content[AFTER_WARMBOOT] is not None:
                    warm_restart_table_entry = {AFTER_WARMBOOT: content[AFTER_WARMBOOT].get("value", {})}
                else:
                    # Cold has the entry
                    warm_restart_table_entry = {AFTER_COLDBOOT: content[AFTER_COLDBOOT].get("value", {})}
                processed_warm_restart_table[process] = warm_restart_table_entry
            elif "value" in content:
                # Diff is amongst the values
                processed_warm_restart_table[process] = content["value"]
            else:
                errors.append(f"Unexpected WARM_RESTART_TABLE diff format for key {key}: {content}")

    EXPECTED_WARM_RESTART_TABLE = {
        "warm-shutdown": {
            "after_warmboot": {"restore_count": "0", "state": "warm-shutdown-succeeded"}
        },
        "vlanmgrd": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": None},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "neighsyncd": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": None},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "teammgrd": {
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "gearsyncd": {
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "tunnelmgrd": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": None},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "coppmgrd": {
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "bgp": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": "disabled"},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "fdbsyncd": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": "disabled"},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "orchagent": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": None},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "vxlanmgrd": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": None},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "teamsyncd": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": None},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "vrfmgrd": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": "disabled"},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "syncd": {
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "nbrmgrd": {
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "portsyncd": {
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "intfmgrd": {
            "state": {"after_warmboot": "reconciled", "after_coldboot": "disabled"},
            "restore_count": {"after_warmboot": "1", "after_coldboot": "0"},
        },
        "xcvrd": {"after_warmboot": {"restore_count": "0"}}
    }

    if processed_warm_restart_table != EXPECTED_WARM_RESTART_TABLE:
        errors.append(f"WARM_RESTART_TABLE mismatch: expected {EXPECTED_WARM_RESTART_TABLE}, "
                      f"found {processed_warm_restart_table}")

    return processed_keys, errors


def prune_expected_from_diff_state_db(state_db_snapshot_diff: SnapshotDiff):
    """
    Process the diff to remove known expected differences. Any known expected differences that are not found
    will be reported as errors.

    Args:
        state_db_snapshot_diff (SnapshotDiff): The snapshot diff for the state database.
    """
    state_db_diff = state_db_snapshot_diff.diff
    # The following assert is because cold boot has an additional Reboot cause
    assert state_db_snapshot_diff is not None, "STATE DB diff should always be present"

    processed_keys = []

    # Find the reboot cause diffs and check they are as expected
    num_warmboot_keys = 0
    num_coldboot_keys = 0
    for key, content in state_db_diff.items():
        if key.startswith("REBOOT_CAUSE|"):
            processed_keys.append(key)
            assert AFTER_WARMBOOT in content and AFTER_COLDBOOT in content, \
                "warm and cold snapshots had the same reboot time - should not happen"
            after_warmboot_content = content[AFTER_WARMBOOT]
            after_coldboot_content = content[AFTER_COLDBOOT]
            if after_warmboot_content and not after_coldboot_content:
                # Warmboot happens first, coldboot last. There are a limited number of reboot causes stored in the DB
                # therefore any difference in history at warmboot snapshot time is the reboot cause that has rolled off
                # the end come coldboot snapshot time. This could be any reboot cause. All we check for here is that we
                # have a reboot cause.
                reboot_cause = after_warmboot_content.get("value", {}).get("cause")
                assert reboot_cause, "No reboot cause found in warmboot diff."
                num_warmboot_keys += 1
            elif after_coldboot_content and not after_warmboot_content:
                # For coldboot there is an expected reboot cause which is the cold boot that was done immediately before
                # the snapshot.
                reboot_cause = after_coldboot_content.get("value", {}).get("cause")
                assert reboot_cause == "reboot", f"reboot cause should have been 'reboot' but it was {reboot_cause}"
                num_coldboot_keys += 1
            else:
                assert False, "Unexpected reboot cause keys found"

    assert 0 <= num_warmboot_keys <= 1, \
        f"Expected between zero and one warmboot REBOOT_CAUSE key, found {num_warmboot_keys}"
    assert num_coldboot_keys == 1, f"Expected exactly one coldboot REBOOT_CAUSE key, found {num_coldboot_keys}"

    # Find the "WARM_RESTART_ENABLE_TABLE|system" key - only warmboot should have it
    warm_restart_enable_table_system = "WARM_RESTART_ENABLE_TABLE|system"
    assert warm_restart_enable_table_system in state_db_diff, \
        "WARM_RESTART_ENABLE_TABLE|system should be in state_db diff"
    assert state_db_diff[warm_restart_enable_table_system].get(AFTER_WARMBOOT, {}).get("value", {})\
        .get("enable") == "false", "WARM_RESTART_ENABLE_TABLE|system after_warmboot enable should be false"
    assert state_db_diff[warm_restart_enable_table_system].get(AFTER_COLDBOOT) is None, \
        "WARM_RESTART_ENABLE_TABLE|system after_coldboot should be missing"
    processed_keys.append(warm_restart_enable_table_system)

    # Process the WARM_RESTART_TABLE
    warm_restart_table_processed_keys, warm_restart_table_errors = process_state_db_warm_restart_table_diff(
        state_db_snapshot_diff)
    assert len(warm_restart_table_errors) == 0, f"WARM_RESTART_TABLE processing errors: {warm_restart_table_errors}"
    processed_keys.extend(warm_restart_table_processed_keys)

    # Process the NEIGH_RESTORE_TABLE
    neigh_restore_table_flags = "NEIGH_RESTORE_TABLE|Flags"
    assert neigh_restore_table_flags in state_db_diff, "NEIGH_RESTORE_TABLE|Flags should be in state_db diff"
    assert state_db_diff[neigh_restore_table_flags].get(AFTER_WARMBOOT, {}).get("value", {})\
        .get("restored") == "true", "NEIGH_RESTORE_TABLE|Flags after_warmboot enable should be false"
    assert state_db_diff[neigh_restore_table_flags].get(AFTER_COLDBOOT) is None, \
        "NEIGH_RESTORE_TABLE|Flags after_coldboot should be missing"
    processed_keys.append(neigh_restore_table_flags)

    for key in processed_keys:
        # These keys have been processed so they can now be removed
        state_db_snapshot_diff.remove_top_level_key(key)


def prune_expected_from_diff(diff: Dict[DBType, SnapshotDiff]):
    """
    Process the diff to remove known expected differences. Any known expected differences that are not found
    will be reported as errors.

    Args:
        diff (Dict[DBType, SnapshotDiff]): A dictionary mapping database types to their snapshot differences.
    """
    for db_type, snapshot_diff in diff.items():
        if db_type == DBType.STATE:
            prune_expected_from_diff_state_db(snapshot_diff)
            continue
