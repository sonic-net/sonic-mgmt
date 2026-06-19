"""Utilities specific for warm vs cold boot snapshots"""

import json
import logging
import re
from typing import Dict, List, Tuple
from tests.common.db_comparison import DBType, SnapshotDiff
from tests.common.snapshot_comparison.warm_vs_cold_assertion_mask import (
    KeyMatchMode,
    TopLevelKeyBothValueDiffExpectation,
    TopLevelKeyOneSideExpectation,
    ValueSpecMode,
    resolve_warm_cold_diff_mask,
)

AFTER_WARMBOOT = "after_warmboot"
AFTER_COLDBOOT = "after_coldboot"
logger = logging.getLogger(__name__)


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
            # gearsyncd may restart multiple times during the warm-boot sequence,
            # so any restore_count >= 1 is acceptable on the warm side. The
            # comparison below special-cases this leaf.
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
    }

    # Compare processed_warm_restart_table against EXPECTED_WARM_RESTART_TABLE
    # and produce one mismatch line per diverging leaf so the first failure can
    # be located without parsing the entire nested dict.
    mismatches: List[str] = []

    def _walk(expected, actual, path: str):
        # gearsyncd is a one-shot config loader (not a daemon), so its
        # restore_count tracks supervisord spawns. A timing race in
        # supervisord-dependent-startup can fire a second startProcess RPC,
        # producing restore_count >= 2. Accept any int >= 1 here.
        # NOTE: If more such exceptions are needed, consider refactoring into a per-path
        #       validator table.
        if path == "gearsyncd.restore_count.after_warmboot":
            try:
                ok = actual is not None and int(actual) >= 1
            except (TypeError, ValueError):
                ok = False
            if not ok:
                mismatches.append(f"{path}: expected int >= 1, got {actual!r}")
            return
        if isinstance(expected, dict) and isinstance(actual, dict):
            for k in sorted(set(expected) | set(actual), key=str):
                sub_path = f"{path}.{k}" if path else str(k)
                if k not in expected:
                    mismatches.append(f"{sub_path}: unexpected key (actual={actual[k]!r})")
                elif k not in actual:
                    mismatches.append(f"{sub_path}: missing key (expected={expected[k]!r})")
                else:
                    _walk(expected[k], actual[k], sub_path)
            return
        if expected != actual:
            mismatches.append(f"{path}: expected={expected!r}, got={actual!r}")

    _walk(EXPECTED_WARM_RESTART_TABLE, processed_warm_restart_table, "")
    if mismatches:
        errors.append("WARM_RESTART_TABLE mismatch:\n  " + "\n  ".join(mismatches))

    return processed_keys, errors


def process_process_stats_table_diff(state_db_snapshot_diff: SnapshotDiff) -> Tuple[List[str], List[str]]:
    """Process expected PROCESS_STATS|* differences between warm and cold boot snapshots.

    PROCESS_STATS rows are pre-paired in :meth:`SnapshotDiff._diff_state_db_process_stats`
    into synthesized `PROCESS_STATS|<seq>` presence-style entries where exactly one of
    `AFTER_WARMBOOT` / `AFTER_COLDBOOT` carries `{"value": {"CMD": ...}}` and the
    other side is `None`.

    Currently handles:

    - `teamd`: warmboot starts `teamd` with `-w -o` while coldboot uses `-r`;
      otherwise the command lines are identical. We pair warm-only and cold-only teamd
      entries by the `-t PortChannelNNN` argument and verify the rest of the command
      line is unchanged once those flags are normalized. Matched pairs are added to
      `processed_keys` so the caller can remove them; mismatches are reported as errors.
    - `finalize-warmboot.sh`: warmboot has a `/bin/bash /usr/local/bin/finalize-warmboot.sh`
      process that coldboot does not. The warm-only entry is added to `processed_keys`;
      a cold-only entry or both/neither sides present is reported as an error.

    Returns:
        (processed_keys, errors)
    """
    diff = state_db_snapshot_diff.diff
    processed_keys: List[str] = []
    errors: List[str] = []

    # Group warm-only and cold-only teamd PROCESS_STATS entries by their PortChannel
    # target so they can be paired and validated.
    teamd_re = re.compile(r"(?:^|/)teamd\s.*\s-t\s+(PortChannel\d+)\b")
    teamd_warm: Dict[str, Tuple[str, str]] = {}  # PortChannel -> (diff_key, cmd)
    teamd_cold: Dict[str, Tuple[str, str]] = {}
    finalize_warmboot_re = re.compile(r"/bin/bash\s+/usr/local/bin/finalize-warmboot\.sh\b")
    finalize_warmboot_warm: List[Tuple[str, str]] = []  # (diff_key, cmd)
    finalize_warmboot_cold: List[Tuple[str, str]] = []
    for key, content in diff.items():
        if not key.startswith("PROCESS_STATS|"):
            continue
        if AFTER_WARMBOOT not in content or AFTER_COLDBOOT not in content:
            errors.append(f"PROCESS_STATS diff entry {key} should have both warmboot and coldboot sides: {content}")
            continue
        warm_content = content[AFTER_WARMBOOT]
        cold_content = content[AFTER_COLDBOOT]
        if warm_content is not None and cold_content is None:
            cmd = warm_content["value"]["CMD"]
            side = "warm"
        elif cold_content is not None and warm_content is None:
            cmd = cold_content["value"]["CMD"]
            side = "cold"
        else:
            # Only one side should have the entry, never both or neither
            errors.append(
                f"Unexpected PROCESS_STATS diff entry {key} with "
                f"warm_content={warm_content} and cold_content={cold_content}"
            )
            continue

        if finalize_warmboot_re.search(cmd):
            (finalize_warmboot_warm if side == "warm" else finalize_warmboot_cold).append((key, cmd))
            continue

        match = teamd_re.search(cmd)
        if not match:
            # Not a process this function is responsible for; leave it in the diff for
            # downstream handlers (e.g. assertion mask / regression reporting).
            continue
        portchannel = match.group(1)
        store = teamd_warm if side == "warm" else teamd_cold
        if portchannel in store:
            errors.append(f"Multiple teamd PROCESS_STATS entries for {portchannel} on the same side")
            continue
        store[portchannel] = (key, cmd)

    for portchannel in sorted(set(teamd_warm) | set(teamd_cold)):
        warm_entry = teamd_warm.get(portchannel)
        cold_entry = teamd_cold.get(portchannel)
        if warm_entry is None:
            errors.append(
                f"teamd PROCESS_STATS for {portchannel} present in coldboot but not warmboot: "
                f"{cold_entry[1]}"
            )
            continue
        if cold_entry is None:
            errors.append(
                f"teamd PROCESS_STATS for {portchannel} present in warmboot but not coldboot: "
                f"{warm_entry[1]}"
            )
            continue
        warm_key, warm_cmd = warm_entry
        cold_key, cold_cmd = cold_entry
        # Warmboot uses '-w -o' where coldboot uses '-r'; normalize the warm command and
        # verify the rest of the command line is identical.
        normalized_warm = warm_cmd.replace(" -w -o ", " -r ", 1)
        if normalized_warm != cold_cmd:
            errors.append(
                f"Unexpected teamd warm/cold cmd diff for {portchannel}.\n"
                f"  warm: {warm_cmd}\n"
                f"  cold: {cold_cmd}"
            )
            continue
        processed_keys.append(warm_key)
        processed_keys.append(cold_key)

    # finalize-warmboot.sh should appear only on the warm side.
    for cold_key, cold_cmd in finalize_warmboot_cold:
        errors.append(f"Unexpected finalize-warmboot.sh PROCESS_STATS entry on coldboot side: {cold_cmd}")
    if len(finalize_warmboot_warm) > 1:
        errors.append(
            f"Expected at most one finalize-warmboot.sh PROCESS_STATS entry on warmboot side, "
            f"found {len(finalize_warmboot_warm)}: {[c for _, c in finalize_warmboot_warm]}"
        )
    elif len(finalize_warmboot_warm) == 1 and not finalize_warmboot_cold:
        warm_key, _ = finalize_warmboot_warm[0]
        processed_keys.append(warm_key)

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
    assert len(warm_restart_table_errors) == 0, (
        "WARM_RESTART_TABLE processing errors:\n" + "\n".join(warm_restart_table_errors)
    )
    processed_keys.extend(warm_restart_table_processed_keys)

    # Process the NEIGH_RESTORE_TABLE
    neigh_restore_table_flags = "NEIGH_RESTORE_TABLE|Flags"
    assert neigh_restore_table_flags in state_db_diff, "NEIGH_RESTORE_TABLE|Flags should be in state_db diff"
    assert state_db_diff[neigh_restore_table_flags].get(AFTER_WARMBOOT, {}).get("value", {})\
        .get("restored") == "true", "NEIGH_RESTORE_TABLE|Flags after_warmboot enable should be false"
    assert state_db_diff[neigh_restore_table_flags].get(AFTER_COLDBOOT) is None, \
        "NEIGH_RESTORE_TABLE|Flags after_coldboot should be missing"
    processed_keys.append(neigh_restore_table_flags)

    # Process the PROCESS_STATS|* table
    process_stats_processed_keys, process_stats_errors = process_process_stats_table_diff(state_db_snapshot_diff)
    assert len(process_stats_errors) == 0, (
        "PROCESS_STATS processing errors:\n" + "\n".join(process_stats_errors)
    )
    processed_keys.extend(process_stats_processed_keys)

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


def is_assertion_mask_supported_for_platform(platform: str) -> bool:
    """Returns True if there is an assertion mask for the given platform, False otherwise."""
    mask = resolve_warm_cold_diff_mask(platform)
    return mask is not None


def apply_diff_assertion_mask(diff: Dict[DBType, SnapshotDiff], platform: str):
    """Apply assertion mask after metrics are recorded to detect regressions.

    This function is intentionally separate from prune_expected_from_diff() so
    "known expected" pruning behavior is unchanged, and so callers can first
    record post-prune metrics before any mask-driven removals.

    For every diff entry that matches a mask expectation, the entry is removed
    from the per-DB `SnapshotDiff` via `remove_top_level_key` (which also
    updates SnapshotDiff's diff metrics but it is not recorded after this point
    so it is not an issue). Any entries remaining in the diff afterwards
    are surfaced as regressions by the caller's post-mask inspection of `diff`.

    If the platform has no mask registered, a warning is logged and the diff is
    left unchanged. Callers should gate this with
    :func:`is_assertion_mask_supported_for_platform` if they want to skip
    regression assertions for unsupported platforms.
    """
    mask = resolve_warm_cold_diff_mask(platform)
    if mask is None:
        logger.warning(
            f"No warm-vs-cold assertion mask found for platform={platform!r}; "
            "regression assertions are skipped for this DUT."
        )
        return

    for db_type, snapshot_diff in diff.items():
        expectations = mask.get(db_type, [])
        unused = _apply_expectations_to_snapshot(snapshot_diff, expectations, db_type)
        if unused:
            logger.warning(
                f"{len(unused)} {db_type.name} mask expectation(s) did not match any "
                f"diff entry; the underlying difference may have been fixed and the "
                f"mask can likely be reduced. Unused expectations:\n"
                + "\n".join(f"  - {e}" for e in unused)
            )


def assert_no_unmasked_regressions(diff: Dict[DBType, SnapshotDiff], platform: str):
    """Apply the platform's assertion mask and assert no unmasked regressions remain.

    This is the single entry point for the post-prune regression check used by
    the warm-vs-cold consistency tests. It:

    1. Resolves the platform's assertion mask. If none exists, the remaining
       diff is logged as a warning and the function returns without asserting
       (the platform needs a mask added before regressions can be enforced).
    2. Applies the mask via :func:`apply_diff_assertion_mask`, removing
       expected-difference entries from each per-DB `SnapshotDiff`.
    3. Logs any per-DB residual diff and asserts that none remain; any
       residual entry is a regression not covered by the mask.
    """
    if not is_assertion_mask_supported_for_platform(platform):
        logger.warning(
            f"No warm-vs-cold assertion mask found for platform={platform!r}; "
            "regression assertions are skipped for this DUT."
        )
        if diff:
            pretty_diff = json.dumps(
                {db_type.name: db_snapshot.diff for db_type, db_snapshot in diff.items()},
                indent=4,
            )
            logger.warning(
                "Differences found in snapshots after warm vs cold boot "
                f"(no assertion mask applied):\n{pretty_diff}"
            )
        # Don't fail the test; this platform needs an assertion mask added in future.
        return

    apply_diff_assertion_mask(diff, platform)

    # Report per-DB residual diffs and collect any regressions for the final assertion.
    all_unexpected = []
    for db_type, db_snapshot in diff.items():
        if db_snapshot.diff:
            pretty_diff = json.dumps(db_snapshot.diff, indent=4)
            logger.warning(f"Differences found in {db_type.name} DB after pruning:\n{pretty_diff}")
            all_unexpected.append((db_type.name, db_snapshot.diff))
        else:
            logger.info(f"No unmasked differences found in {db_type.name} DB")

    assert not all_unexpected, (
        f"Unexpected diffs found after applying assertion mask (potential regression). "
        f"Unexpected diffs: {all_unexpected}"
    )


def _key_matches(key_match, candidate: str) -> bool:
    if key_match.mode == KeyMatchMode.EXACT:
        return candidate == key_match.pattern
    if key_match.mode == KeyMatchMode.PREFIX:
        return candidate.startswith(key_match.pattern)
    if key_match.mode == KeyMatchMode.REGEX:
        return re.fullmatch(key_match.pattern, candidate) is not None
    return False


def _value_matches(value_spec, actual) -> bool:
    if value_spec.mode == ValueSpecMode.ANY:
        return True
    if value_spec.mode == ValueSpecMode.NULL:
        return actual is None
    if value_spec.mode == ValueSpecMode.LITERAL:
        return actual == value_spec.value
    if value_spec.mode == ValueSpecMode.REGEX:
        return actual is not None and re.fullmatch(value_spec.value, str(actual)) is not None
    if value_spec.mode == ValueSpecMode.ONE_OF:
        return actual in value_spec.value
    return False


def _entry_matches_expectation(expectation, content) -> bool:
    """True if a diff entry's content matches the given expectation's shape/values."""
    if isinstance(expectation, TopLevelKeyOneSideExpectation):
        # Presence diff: content has AFTER_WARMBOOT / AFTER_COLDBOOT at top level.
        if AFTER_WARMBOOT not in content or AFTER_COLDBOOT not in content:
            return False
        warm_present = content[AFTER_WARMBOOT] is not None
        cold_present = content[AFTER_COLDBOOT] is not None
        if (warm_present != expectation.after_warmboot_present
                or cold_present != expectation.after_coldboot_present):
            return False

        # Optional per-field shape check on the present side.
        specs = expectation.present_side_value_specs
        if not specs:
            return True
        present_content = content[AFTER_WARMBOOT] if warm_present else content[AFTER_COLDBOOT]
        if not isinstance(present_content, dict) or "value" not in present_content:
            return False
        fields = present_content["value"]
        if not isinstance(fields, dict):
            return False
        if set(fields.keys()) != set(specs.keys()):
            return False
        return all(_value_matches(specs[name], fields[name]) for name in specs)

    if isinstance(expectation, TopLevelKeyBothValueDiffExpectation):
        # Field-level diff: content["value"] maps field name -> {warm, cold}.
        if "value" not in content:
            return False
        fields = content["value"]
        if not fields:
            return False
        for field_name, field_diff in fields.items():
            if not isinstance(field_diff, dict):
                return False
            warm_actual = field_diff.get(AFTER_WARMBOOT)
            cold_actual = field_diff.get(AFTER_COLDBOOT)
            covered = any(
                _key_matches(fe.field_match, field_name)
                and _value_matches(fe.after_warmboot, warm_actual)
                and _value_matches(fe.after_coldboot, cold_actual)
                for fe in expectation.fields
            )
            if not covered:
                return False
        return True

    return False


def _apply_expectations_to_snapshot(snapshot_diff: SnapshotDiff, expectations, db_type: DBType):
    """For each expectation, remove matching top-level keys from the snapshot_diff.

    Returns the list of expectations that did not match any diff entry, so the
    caller can surface them as candidates for mask reduction.
    """
    unused = []
    for expectation in expectations:
        matched_keys = []
        for key, content in snapshot_diff.diff.items():
            if not _key_matches(expectation.key_match, key):
                continue
            if _entry_matches_expectation(expectation, content):
                matched_keys.append(key)
        if not matched_keys:
            unused.append(expectation)
            continue
        for key in matched_keys:
            snapshot_diff.remove_top_level_key(key)
    return unused
