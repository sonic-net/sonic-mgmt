"""
Tests for the Redfish <-> pmon (bmcctld) interaction on the BMC.

pmon-bmc-design.md section 2.2: bmcweb never touches the switch host itself.
A ComputerSystem.Reset is turned into a RACK_MANAGER_COMMAND row by
sonic-dbus-bridge and bmcctld, running in the BMC pmon container, consumes it:

    bmcweb -> D-Bus RequestedHostTransition -> sonic-dbus-bridge
      -> STATE_DB RACK_MANAGER_COMMAND|CMD_<ts>_<n> {command, status=PENDING}
    bmcctld -> status IN_PROGRESS -> DONE|FAILED + result
    bmcctld -> STATE_DB HOST_STATE|switch-host {device_power_state, device_status}
            -> STATE_DB CHASSIS_MODULE_TABLE|SWITCH-HOST {oper_status}

STATE_DB is the only contract between the two sides, so the tests observe it
directly: the command row lifecycle, agreement of the power state across
Redfish / HOST_STATE / CHASSIS_MODULE_TABLE, the CRITICAL rack manager alert
interlock that makes bmcctld refuse POWER_ON, and bmcctld restarting without
disturbing either side.

Every reset issued here is ResetType=On against a host that is already On,
which bmcctld resolves as a successful no-op, so the switch host is never
power cycled.
"""
import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.sonic_db import (
    CONFIG_DB,
    STATE_DB,
    redis_del,
    redis_hgetall,
    redis_hset,
    redis_keys,
)
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import assert_no_content, assert_status_ok

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

SYSTEM_PATH = "/redfish/v1/Systems/system"
RESET_PATH = SYSTEM_PATH + "/Actions/ComputerSystem.Reset"
MANAGER_PATH = "/redfish/v1/Managers/bmc"
SUBMIT_ALERT_ACTION = "#SONiC.SubmitAlert"

COMMAND_TABLE = "RACK_MANAGER_COMMAND"
COMMAND_KEY_GLOB = "{}|*".format(COMMAND_TABLE)
HOST_STATE_KEY = "HOST_STATE|switch-host"
MODULE_INFO_KEY = "CHASSIS_MODULE_TABLE|SWITCH-HOST"

ALERT_TABLE = "RACK_MANAGER_ALERT"
ALERT_KEY_GLOB = "{}|*".format(ALERT_TABLE)
LEAK_KEY = "{}|Rack_level_leak".format(ALERT_TABLE)
LEAK_CONTROL_POLICY_KEY = "LEAK_CONTROL_POLICY"
# bmcctld defaults when LEAK_CONTROL_POLICY is absent (pmon-bmc-design.md 2.3.1).
DEFAULT_RACK_MGR_LEAK_POLICY = "enabled"
DEFAULT_RACK_MGR_CRITICAL_ALERT_ACTION = "syslog_only"

BMCCTLD = "bmcctld"
PMON_CONTAINER = "pmon"

# Redfish PowerState -> (HOST_STATE.device_power_state, HOST_STATE.device_status / oper_status)
POWER_STATE_MAP = {
    "On": ("POWERED_ON", "ONLINE"),
    "Off": ("POWERED_OFF", "OFFLINE"),
}

CMD_POWER_ON = "POWER_ON"
CMD_DONE = "DONE"
CMD_FAILED = "FAILED"
TERMINAL_STATUSES = (CMD_DONE, CMD_FAILED)
RESULT_SUCCESS = "SUCCESS"
RESULT_CRITICAL = "CRITICAL_LEAK_PRESENT"

COMMAND_ROW_TIMEOUT = 30
COMMAND_DONE_TIMEOUT = 60
ALERT_TIMEOUT = 20
RESTART_TIMEOUT = 120
POLL = 1
RETENTION_SETTLE = 5

CRITICAL_LEAK_PAYLOAD = {"redfish_alert_data": {"LeakDetected": {"Severity": "Critical"}}}
CLEARED_LEAK_PAYLOAD = {"redfish_alert_data": {"LeakDetected": {"Severity": "Normal"}}}


def _command_keys(bmc_duthost):
    return set(redis_keys(bmc_duthost, STATE_DB, COMMAND_KEY_GLOB))


def _power_state(redfish_client):
    response = redfish_client.get(SYSTEM_PATH)
    assert_status_ok(response, SYSTEM_PATH)
    return response.json().get("PowerState")


def _post_reset_on(redfish_client):
    response = redfish_client.post(RESET_PATH, json={"ResetType": "On"})
    logger.info("POST {} ResetType=On -> {}".format(RESET_PATH, response.status_code))
    pytest_assert(
        response.status_code in (200, 204),
        "ResetType=On must be accepted with HTTP 200 or 204, got {}: {}".format(
            response.status_code, response.text[:200])
    )


def _wait_for_new_command(bmc_duthost, keys_before):
    """Wait for exactly one new RACK_MANAGER_COMMAND row and return (key, fields)."""
    pytest_assert(
        wait_until(COMMAND_ROW_TIMEOUT, POLL, 0, lambda: _command_keys(bmc_duthost) - keys_before),
        "No new {} row within {}s of the reset".format(COMMAND_TABLE, COMMAND_ROW_TIMEOUT)
    )
    new_keys = _command_keys(bmc_duthost) - keys_before
    pytest_assert(len(new_keys) == 1, "One reset must create one command row, got: {}".format(sorted(new_keys)))
    key = new_keys.pop()
    fields = redis_hgetall(bmc_duthost, STATE_DB, key)
    logger.info("{} -> {}".format(key, fields))
    return key, fields


def _wait_for_terminal(bmc_duthost, key):
    """Wait for bmcctld to move the command row to DONE or FAILED and return the row."""
    pytest_assert(
        wait_until(COMMAND_DONE_TIMEOUT, POLL, 0,
                   lambda: redis_hgetall(bmc_duthost, STATE_DB, key).get("status") in TERMINAL_STATUSES),
        "{} not consumed by {} within {}s: {}".format(
            key, BMCCTLD, COMMAND_DONE_TIMEOUT, redis_hgetall(bmc_duthost, STATE_DB, key))
    )
    fields = redis_hgetall(bmc_duthost, STATE_DB, key)
    logger.info("{} -> {}".format(key, fields))
    return fields


def _assert_command_outcome(key, fields, status, result):
    pytest_assert(fields.get("command") == CMD_POWER_ON,
                  "{} command must be {}, got: {}".format(key, CMD_POWER_ON, fields))
    pytest_assert(fields.get("status") == status and fields.get("result") == result,
                  "{} must end status={} result={}, got: {}".format(key, status, result, fields))
    pytest_assert(fields.get("last_change_timestamp"),
                  "{} must carry last_change_timestamp, got: {}".format(key, fields))


def _run_reset_to_completion(redfish_client, bmc_duthost):
    """POST ResetType=On and return (key, terminal_row) once bmcctld has consumed it."""
    keys_before = _command_keys(bmc_duthost)
    _post_reset_on(redfish_client)
    key, _ = _wait_for_new_command(bmc_duthost, keys_before)
    return key, _wait_for_terminal(bmc_duthost, key)


def _leak_alert_is(bmc_duthost, severity):
    return redis_hgetall(bmc_duthost, STATE_DB, LEAK_KEY).get("leak") == severity


def _rack_mgr_policy(bmc_duthost):
    """Effective rack manager alert policy: CONFIG_DB LEAK_CONTROL_POLICY over bmcctld defaults."""
    policy = {
        "rack_mgr_leak_policy": DEFAULT_RACK_MGR_LEAK_POLICY,
        "rack_mgr_critical_alert_action": DEFAULT_RACK_MGR_CRITICAL_ALERT_ACTION,
    }
    policy.update(redis_hgetall(bmc_duthost, CONFIG_DB, LEAK_CONTROL_POLICY_KEY))
    return policy


def _bmcctld_pid(bmc_duthost):
    status, pid = bmc_duthost.get_pmon_daemon_status(BMCCTLD)
    return pid if status == "RUNNING" else -1


def _host_state_newer_than(bmc_duthost, before):
    current = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY).get("last_change_timestamp", "")
    return bool(current) and current > before.get("last_change_timestamp", "")


@pytest.fixture(scope="function")
def system_is_on(redfish_client):
    """Skip unless the switch host is On, so every ResetType=On here is a no-op for it."""
    power_state = _power_state(redfish_client)
    pyrequire(power_state == "On",
              "System PowerState is {!r}, ResetType=On would change the switch host".format(power_state))
    return power_state


@pytest.fixture(scope="function")
def bmcctld_running(bmc_duthost):
    """Skip unless bmcctld is RUNNING in the BMC pmon container."""
    pid = _bmcctld_pid(bmc_duthost)
    pyrequire(pid != -1, "{} is not RUNNING in the {} container".format(BMCCTLD, PMON_CONTAINER))
    return pid


@pytest.fixture(scope="module")
def alert_target(redfish_client):
    """Resolve the SubmitAlert action target from the Manager resource."""
    response = redfish_client.get(MANAGER_PATH)
    assert_status_ok(response, MANAGER_PATH)
    actions = response.json().get("Oem", {}).get("SONiC", {}).get("RackManager", {}).get("Actions", {})
    target = actions.get(SUBMIT_ALERT_ACTION, {}).get("target", "")
    pyrequire(target, "{} does not advertise {}".format(MANAGER_PATH, SUBMIT_ALERT_ACTION))
    return target


@pytest.fixture(scope="function")
def clean_rack_manager_alerts(bmc_duthost):
    """Start from an empty RACK_MANAGER_ALERT table and restore the prior contents afterwards.

    A CRITICAL entry left behind would make bmcctld refuse every later POWER_ON.
    """
    keys = redis_keys(bmc_duthost, STATE_DB, ALERT_KEY_GLOB)
    snapshot = {key: redis_hgetall(bmc_duthost, STATE_DB, key) for key in keys}
    if keys:
        logger.info("Snapshotting and clearing existing {} keys: {}".format(ALERT_TABLE, keys))
        redis_del(bmc_duthost, STATE_DB, *keys)

    yield

    leftover = redis_keys(bmc_duthost, STATE_DB, ALERT_KEY_GLOB)
    if leftover:
        redis_del(bmc_duthost, STATE_DB, *leftover)
    for key, fields in snapshot.items():
        if fields:
            redis_hset(bmc_duthost, STATE_DB, key, **fields)


@pytest.fixture(scope="function")
def critical_alert_blocks_power_on(bmc_duthost):
    """Skip unless a CRITICAL alert is both enforced by bmcctld and harmless to the host.

    bmcctld only checks RACK_MANAGER_ALERT when rack_mgr_leak_policy is enabled,
    and on a CRITICAL alert it dispatches rack_mgr_critical_alert_action. The
    interlock is observable without a power change only when that action is
    syslog_only.
    """
    policy = _rack_mgr_policy(bmc_duthost)
    logger.info("Effective rack manager alert policy: {}".format(policy))
    pyrequire(policy["rack_mgr_leak_policy"] != "disabled",
              "LEAK_CONTROL_POLICY rack_mgr_leak_policy=disabled, bmcctld ignores rack manager alerts")
    pyrequire(policy["rack_mgr_critical_alert_action"] == "syslog_only",
              "LEAK_CONTROL_POLICY rack_mgr_critical_alert_action={!r} would act on the switch host; "
              "refusing to inject a CRITICAL rack manager alert".format(policy["rack_mgr_critical_alert_action"]))


class TestRedfishPmonInteraction:

    def test_reset_command_consumed_by_bmcctld(self, redfish_client, bmc_duthost, system_is_on, bmcctld_running):
        """
        A ComputerSystem.Reset becomes one RACK_MANAGER_COMMAND row that bmcctld drives to DONE.

        POST ResetType=On. The bridge must write exactly one new row with
        command=POWER_ON, bmcctld must consume it to status=DONE result=SUCCESS
        (the host is already On, so the action is a successful no-op), and the
        row must remain in STATE_DB afterwards: neither side deletes command
        history, so it stays available for audit. PowerState must still be On.
        """
        keys_before = _command_keys(bmc_duthost)
        logger.info("{} rows before: {}".format(COMMAND_TABLE, len(keys_before)))

        _post_reset_on(redfish_client)
        key, pending = _wait_for_new_command(bmc_duthost, keys_before)
        pytest_assert(pending.get("command") == CMD_POWER_ON,
                      "{} command must be {}, got: {}".format(key, CMD_POWER_ON, pending))

        fields = _wait_for_terminal(bmc_duthost, key)
        _assert_command_outcome(key, fields, CMD_DONE, RESULT_SUCCESS)

        time.sleep(RETENTION_SETTLE)
        retained = redis_hgetall(bmc_duthost, STATE_DB, key)
        pytest_assert(retained == fields,
                      "{} must be retained unchanged after completion, got: {}".format(key, retained))
        pytest_assert(_power_state(redfish_client) == "On", "PowerState must still be On after ResetType=On")

    def test_power_state_consistent_across_layers(self, redfish_client, bmc_duthost, bmcctld_running):
        """
        Redfish PowerState agrees with what bmcctld publishes in STATE_DB.

        PowerState On maps to HOST_STATE device_power_state=POWERED_ON and
        device_status=ONLINE and to CHASSIS_MODULE_TABLE oper_status=ONLINE,
        Off to POWERED_OFF/OFFLINE. Any other PowerState or transitional
        device_power_state is reported as a failure since the system should be
        settled when nothing is in flight.
        """
        power_state = _power_state(redfish_client)
        host_state = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)
        module_info = redis_hgetall(bmc_duthost, STATE_DB, MODULE_INFO_KEY)
        logger.info("PowerState={} {}={} {}={}".format(power_state, HOST_STATE_KEY, host_state,
                                                       MODULE_INFO_KEY, module_info))

        pytest_assert(power_state in POWER_STATE_MAP,
                      "PowerState must be one of {}, got {!r}".format(sorted(POWER_STATE_MAP), power_state))
        expected_power, expected_status = POWER_STATE_MAP[power_state]
        pytest_assert(host_state.get("device_power_state") == expected_power,
                      "{} device_power_state must be {} for PowerState={}, got: {}".format(
                          HOST_STATE_KEY, expected_power, power_state, host_state))
        pytest_assert(host_state.get("device_status") == expected_status,
                      "{} device_status must be {} for PowerState={}, got: {}".format(
                          HOST_STATE_KEY, expected_status, power_state, host_state))
        pytest_assert(module_info.get("oper_status") == expected_status,
                      "{} oper_status must be {} for PowerState={}, got: {}".format(
                          MODULE_INFO_KEY, expected_status, power_state, module_info))

    def test_critical_alert_blocks_power_on_command(self, redfish_client, bmc_duthost, alert_target,
                                                    system_is_on, bmcctld_running,
                                                    clean_rack_manager_alerts, critical_alert_blocks_power_on):
        """
        A CRITICAL rack manager alert makes bmcctld refuse POWER_ON until it is cleared.

        Submit a CRITICAL LeakDetected alert through SONiC.SubmitAlert. bmcweb
        still accepts the following ResetType=On, but bmcctld must fail the
        command row with result=CRITICAL_LEAK_PRESENT and the host must stay On.
        Once the alert is cleared to Normal the next ResetType=On must complete
        with DONE/SUCCESS again.
        """
        response = redfish_client.post(alert_target, json=CRITICAL_LEAK_PAYLOAD)
        assert_no_content(response, alert_target)
        pytest_assert(wait_until(ALERT_TIMEOUT, POLL, 0, _leak_alert_is, bmc_duthost, "CRITICAL"),
                      "{} did not reach leak=CRITICAL within {}s".format(LEAK_KEY, ALERT_TIMEOUT))

        key, fields = _run_reset_to_completion(redfish_client, bmc_duthost)
        _assert_command_outcome(key, fields, CMD_FAILED, RESULT_CRITICAL)
        pytest_assert(_power_state(redfish_client) == "On", "PowerState must stay On while the alert is active")

        response = redfish_client.post(alert_target, json=CLEARED_LEAK_PAYLOAD)
        assert_no_content(response, alert_target)
        pytest_assert(wait_until(ALERT_TIMEOUT, POLL, 0, _leak_alert_is, bmc_duthost, "NORMAL"),
                      "{} did not return to leak=NORMAL within {}s".format(LEAK_KEY, ALERT_TIMEOUT))

        key, fields = _run_reset_to_completion(redfish_client, bmc_duthost)
        _assert_command_outcome(key, fields, CMD_DONE, RESULT_SUCCESS)

    def test_bmcctld_restart_resyncs_host_state(self, redfish_client, bmc_duthost, system_is_on, bmcctld_running):
        """
        Restarting bmcctld re-publishes HOST_STATE and leaves Redfish and the host untouched.

        supervisorctl restart bmcctld in the pmon container. bmcctld must come
        back RUNNING with a new pid, refresh HOST_STATE|switch-host from the
        live oper status (newer last_change_timestamp, still POWERED_ON/ONLINE),
        create no RACK_MANAGER_COMMAND row of its own, and leave PowerState On.
        A ResetType=On issued afterwards must again be consumed to DONE/SUCCESS,
        proving the restarted daemon re-subscribed to the command table.
        """
        pid_before = bmcctld_running
        keys_before = _command_keys(bmc_duthost)
        host_state_before = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)
        logger.info("{} pid {} and {} before restart: {}".format(
            BMCCTLD, pid_before, HOST_STATE_KEY, host_state_before))

        bmc_duthost.shell("docker exec {} supervisorctl restart {}".format(PMON_CONTAINER, BMCCTLD))

        pytest_assert(
            wait_until(RESTART_TIMEOUT, 5, 0, lambda: _bmcctld_pid(bmc_duthost) not in (-1, pid_before)),
            "{} did not come back RUNNING with a new pid within {}s".format(BMCCTLD, RESTART_TIMEOUT)
        )
        pytest_assert(
            wait_until(RESTART_TIMEOUT, POLL, 0, _host_state_newer_than, bmc_duthost, host_state_before),
            "{} was not refreshed by the restarted {} within {}s: {}".format(
                HOST_STATE_KEY, BMCCTLD, RESTART_TIMEOUT, redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY))
        )
        host_state_after = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)
        logger.info("{} after restart: {}".format(HOST_STATE_KEY, host_state_after))
        expected_power, expected_status = POWER_STATE_MAP["On"]
        pytest_assert(
            host_state_after.get("device_power_state") == expected_power
            and host_state_after.get("device_status") == expected_status,
            "{} must read {}/{} after restart, got: {}".format(
                HOST_STATE_KEY, expected_power, expected_status, host_state_after)
        )

        spurious = _command_keys(bmc_duthost) - keys_before
        pytest_assert(not spurious,
                      "{} restart must not create command rows, got: {}".format(BMCCTLD, sorted(spurious)))
        pytest_assert(_power_state(redfish_client) == "On",
                      "PowerState must still be On after restarting {}".format(BMCCTLD))

        key, fields = _run_reset_to_completion(redfish_client, bmc_duthost)
        _assert_command_outcome(key, fields, CMD_DONE, RESULT_SUCCESS)
