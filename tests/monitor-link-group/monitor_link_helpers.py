"""Helpers for monitor-link-group tests.

Configuration is applied via `config load` of a JSON file holding the
MONITOR_LINK_GROUP CONFIG_DB table (the user-facing config path per HLD).
Cleanup deletes group keys directly from CONFIG_DB since the user-facing
config path has no imperative remove operation.

State is observed by reading STATE_DB tables:
    MONITOR_LINK_GROUP_STATE|<group>     -> group state (up/down/pending)
    MONITOR_LINK_GROUP_MEMBER|<intf>     -> managed-link state (allow_up/force_down)
"""

import json
import logging
import os
from typing import Dict, Iterable, List

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import SonicDbCli, SonicDbKeyNotFound
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

CFG_TABLE = "MONITOR_LINK_GROUP"
STATE_GROUP_TABLE = "MONITOR_LINK_GROUP_STATE"
STATE_MEMBER_TABLE = "MONITOR_LINK_GROUP_MEMBER"

DEFAULT_TIMEOUT = 30
PENDING_TIMEOUT = 60

MLG_DAEMON = "monitorlinkgroupd"
MLG_DAEMON_CONTAINER = "swss"


def is_mlg_daemon_present(duthost) -> bool:
    """Return True if the monitorlinkgroupd daemon is present on the DUT.

    Works for both single- and multi-ASIC: MultiAsicSonicHost.is_service_running
    iterates ASIC containers (swss0/swss1/...) and returns True only when the
    daemon is RUNNING in every one. On images that pre-date the MLG feature
    the supervisor entry is absent and this returns False.
    """
    return duthost.is_service_running(MLG_DAEMON, MLG_DAEMON_CONTAINER)


def _remote_cfg_path():
    # Include pid so parallel test runs against the same DUT don't collide.
    return "/tmp/monitor_link_group_test_{}.json".format(os.getpid())


def make_group(
    monitored: Iterable[str],
    managed: Iterable[str],
    min_monitored_links: int = 1,
    link_up_delay: int = 0,
    description: str = "",
) -> Dict:
    # YANG model requires description length >= 1, so omit the field entirely
    # when empty rather than writing "" (which fails YANG validation).
    entry = {
        "monitored-links": list(monitored),
        "managed-links": list(managed),
        "min-monitored-links": str(min_monitored_links),
        "link-up-delay": str(link_up_delay),
    }
    if description:
        entry["description"] = description
    return entry


def apply_groups(duthost, groups: Dict[str, Dict]) -> None:
    """Write MONITOR_LINK_GROUP entries via `config load`.

    `config load` merges into existing CONFIG_DB, so callers that need a
    clean slate must delete prior groups first.
    """
    path = _remote_cfg_path()
    payload = {CFG_TABLE: groups}
    duthost.copy(content=json.dumps(payload), dest=path)
    try:
        duthost.shell("config load {} -y".format(path))
    finally:
        duthost.shell("rm -f {}".format(path), module_ignore_errors=True)
    logger.info("Applied monitor-link-group config: %s", list(groups))


def delete_group(duthost, name: str) -> None:
    duthost.shell(
        "sonic-db-cli CONFIG_DB DEL '{}|{}'".format(CFG_TABLE, name),
    )


def get_group_state(duthost, name: str) -> Dict[str, str]:
    return _hgetall(duthost, "STATE_DB", "{}|{}".format(STATE_GROUP_TABLE, name))


def get_member_state(duthost, intf: str) -> Dict[str, str]:
    return _hgetall(duthost, "STATE_DB", "{}|{}".format(STATE_MEMBER_TABLE, intf))


def group_state_exists(duthost, name: str) -> bool:
    # Use EXISTS instead of KEYS/HGETALL: EXISTS always returns "0" or "1"
    # (non-empty stdout), so SonicDbCli._run_and_check does not log an
    # ERROR for the legitimate "key absent" case.
    result = duthost.shell(
        "sonic-db-cli STATE_DB EXISTS '{}|{}'".format(STATE_GROUP_TABLE, name),
        module_ignore_errors=True,
    )
    return result.get("stdout", "0").strip() == "1"


def wait_group_state(duthost, name: str, expected: str, timeout: int = DEFAULT_TIMEOUT) -> None:
    def _check():
        return get_group_state(duthost, name).get("state") == expected

    pytest_assert(
        wait_until(timeout, 1, 0, _check),
        "monitor-link group '{}' did not reach state '{}' within {}s (actual: {})".format(
            name, expected, timeout, get_group_state(duthost, name)
        ),
    )


def wait_group_field(duthost, name: str, field: str, expected: str,
                     timeout: int = DEFAULT_TIMEOUT) -> None:
    def _check():
        return get_group_state(duthost, name).get(field) == expected

    pytest_assert(
        wait_until(timeout, 1, 0, _check),
        "monitor-link group '{}' field '{}' did not reach '{}' within {}s (actual: {})".format(
            name, field, expected, timeout, get_group_state(duthost, name)
        ),
    )


def wait_member_state(duthost, intf: str, expected: str, timeout: int = DEFAULT_TIMEOUT) -> None:
    def _check():
        return get_member_state(duthost, intf).get("state") == expected

    pytest_assert(
        wait_until(timeout, 1, 0, _check),
        "interface '{}' MONITOR_LINK_GROUP_MEMBER state did not reach '{}' within {}s "
        "(actual: {})".format(intf, expected, timeout, get_member_state(duthost, intf)),
    )


def wait_oper(duthost, intf: str, expected: str, timeout: int = DEFAULT_TIMEOUT) -> None:
    def _check():
        return duthost.get_interfaces_status().get(intf, {}).get("oper") == expected

    pytest_assert(
        wait_until(timeout, 1, 0, _check),
        "interface '{}' oper did not reach '{}' within {}s (actual: {})".format(
            intf, expected, timeout, duthost.get_interfaces_status().get(intf, {})
        ),
    )


def shutdown(duthost, intf: str) -> None:
    duthost.shutdown(intf)


def no_shutdown(duthost, intf: str) -> None:
    duthost.no_shutdown(intf)


def _hgetall(duthost, db: str, key: str) -> Dict[str, str]:
    try:
        return SonicDbCli(duthost, db).hget_all(key)
    except SonicDbKeyNotFound:
        return {}


def assert_member_states(
    duthost,
    members: Dict[str, str],
    timeout: int = DEFAULT_TIMEOUT,
) -> None:
    """Wait until every interface reaches its expected member state.

    `members` maps interface -> 'allow_up' or 'force_down'.
    """
    for intf, expected in members.items():
        wait_member_state(duthost, intf, expected, timeout=timeout)


def assert_oper_states(
    duthost,
    intfs: Dict[str, str],
    timeout: int = DEFAULT_TIMEOUT,
) -> None:
    for intf, expected in intfs.items():
        wait_oper(duthost, intf, expected, timeout=timeout)


def cleanup_groups(duthost, names: List[str]) -> None:
    for name in names:
        delete_group(duthost, name)


def apply_config_raw(duthost, groups: Dict[str, Dict]) -> Dict:
    """Apply groups via `config apply-patch` without raising on non-zero rc.

    Uses apply-patch (not config load) because apply-patch invokes YANG
    validation; config load -y silently accepts YANG violations on this
    platform. Returns the duthost.shell result so callers can assert on
    rc/stderr (used for YANG-negative tests).
    """
    path = _remote_cfg_path() + ".patch"
    patch = [
        {"op": "add", "path": "/{}/{}".format(CFG_TABLE, name), "value": entry}
        for name, entry in groups.items()
    ]
    duthost.copy(content=json.dumps(patch), dest=path)
    result = duthost.shell(
        "config apply-patch {}".format(path),
        module_ignore_errors=True,
    )
    duthost.shell("rm -f {}".format(path), module_ignore_errors=True)
    return result


def show_monitor_link_group(duthost, name: str = None) -> str:
    """Run `show monitor-link-group [<name>]` and return stdout."""
    cmd = "show monitor-link-group"
    if name:
        cmd += " {}".format(name)
    return duthost.shell(cmd)["stdout"]
