import json
import logging
import re
import pytest

from tests.common.reboot import REBOOT_TYPE_SUPERVISOR_HEARTBEAT_LOSS, reboot_ctrl_dict, wait_for_startup, \
    REBOOT_TYPE_POWEROFF
from tests.common.platform.processes_utils import wait_critical_processes, check_critical_processes
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.psu_helpers import get_grouped_pdus_by_psu
from tests.platform_tests.test_reboot import check_interfaces_and_services, \
    reboot_and_check
from tests.common.utilities import get_plt_reboot_ctrl, wait_until

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

INTERFACE_WAIT_TIME = 300

DPU_STATUS_TIMEOUT = 360
DPU_STATUS_INTERVAL = 30
PSU_STATUS_CMD = "show platform psustatus --json"


def _normalize_psu_name(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _is_present(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ["1", "present", "true", "yes"]


def _get_dut_psu_status(duthost):
    result = duthost.command(PSU_STATUS_CMD, module_ignore_errors=True)
    pytest_assert(result.get("rc") == 0,
                  "Failed to run '{}': {}".format(PSU_STATUS_CMD, result))
    try:
        entries = json.loads(result.get("stdout", ""))
    except (TypeError, ValueError) as error:
        pytest.fail("Failed to parse '{}': {}".format(PSU_STATUS_CMD, error))
    pytest_assert(isinstance(entries, list),
                  "Unexpected '{}' output: {}".format(PSU_STATUS_CMD, entries))
    return {
        _normalize_psu_name(entry.get("name")): entry
        for entry in entries
        if entry.get("name")
    }


def _validate_psu_power(duthost, psu, pdus, dut_psu_status=None):
    pytest_assert(any(pdu.get("outlet_on") is True for pdu in pdus),
                  "No mapped PDU outlet is ON for PSU {}".format(psu))

    watt_readings = []
    for pdu in pdus:
        if pdu.get("outlet_on") is not True or "output_watts" not in pdu:
            continue
        try:
            watt_readings.append(float(pdu["output_watts"]))
        except (TypeError, ValueError):
            pytest.fail("Invalid PDU output_watts for PSU {}: {}".format(psu, pdu["output_watts"]))

    if not watt_readings or any(reading > 0 for reading in watt_readings):
        return dut_psu_status

    if dut_psu_status is None:
        dut_psu_status = _get_dut_psu_status(duthost)
    psu_status = dut_psu_status.get(_normalize_psu_name(psu))
    pytest_assert(psu_status,
                  "PDU meters report 0 W for PSU {}, but '{}' has no matching entry"
                  .format(psu, PSU_STATUS_CMD))
    pytest_assert(_is_present(psu_status.get("presence"))
                  and str(psu_status.get("status", "")).strip().upper() == "OK",
                  "PDU meters report 0 W for PSU {}, and DUT status is presence={} status={}"
                  .format(psu, psu_status.get("presence"), psu_status.get("status")))
    logging.warning("PDU meters report 0 W for PSU %s, but the outlet is ON and DUT status is present/OK",
                    psu)
    return dut_psu_status


@pytest.fixture(scope="module", autouse=True)
def set_max_time_for_interfaces(duthosts, enum_supervisor_dut_hostname):
    """
    For chassis testbeds, we need to specify plt_reboot_ctrl in inventory file,
    to let MAX_TIME_TO_REBOOT to be overwritten by specified timeout value
    """
    global INTERFACE_WAIT_TIME
    duthost = duthosts[enum_supervisor_dut_hostname]
    plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, 'test_reboot.py', 'cold')
    if plt_reboot_ctrl:
        INTERFACE_WAIT_TIME = plt_reboot_ctrl.get('timeout', 300)


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthosts, enum_supervisor_dut_hostname, conn_graph_facts, xcvr_skip_list):
    duthost = duthosts[enum_supervisor_dut_hostname]
    yield

    logging.info(
        "Tearing down: to make sure all the critical services, interfaces and transceivers are good")
    interfaces = conn_graph_facts.get(
        "device_conn", {}).get(duthost.hostname, {})
    check_critical_processes(duthost, watch_secs=10)
    check_interfaces_and_services(
        duthost, interfaces, xcvr_skip_list, INTERFACE_WAIT_TIME)


def _power_off_reboot_helper(kwargs, power_on_event=None):
    """
    @summary: used to parametrized test cases on power_off_delay
    @param kwargs: the delay time between turning off and on the PSU
    """
    pdu_ctrl = kwargs["pdu_ctrl"]
    all_outlets = kwargs["all_outlets"]
    power_on_seq = kwargs["power_on_seq"]
    for outlet in all_outlets:
        logging.debug("turning off {}".format(outlet))
        pdu_ctrl.turn_off_outlet(outlet)

    # Wait for wait_for_shutdown assertion finished.
    power_on_event.wait()
    logging.debug("Turning off all_outlets finished.")

    # Check outlets status?
    outlet_status = pdu_ctrl.get_outlet_status()
    for outlet in outlet_status:
        logging.debug("After turn off outlet, its status is {}".format(outlet))

    logging.info("Power on {}".format(power_on_seq))
    for outlet in power_on_seq:
        logging.debug("turning on {}".format(outlet))
        pdu_ctrl.turn_on_outlet(outlet)

    # Clean the flag to let next run still blocking power on action.
    power_on_event.clear()


@pytest.fixture
def adjust_reboot_cause_sequence():
    """
    TODO: Fix this workaround
    By removing the key and readding it, we make sure that the key will append at the end of the list. Therefore modify
    the sequence of to fix https://github.com/sonic-net/sonic-mgmt/pull/18488

    After this, we add back REBOOT_TYPE_POWEROFF so that it will appear at the end default
    """
    heartbeat_loss_reboot = reboot_ctrl_dict.pop(
        REBOOT_TYPE_SUPERVISOR_HEARTBEAT_LOSS)
    reboot_ctrl_dict[REBOOT_TYPE_SUPERVISOR_HEARTBEAT_LOSS] = heartbeat_loss_reboot

    yield

    reboot_type_poweroff = reboot_ctrl_dict.pop(REBOOT_TYPE_POWEROFF)
    reboot_ctrl_dict[REBOOT_TYPE_POWEROFF] = reboot_type_poweroff


def _get_dpu_module_status(duthost):
    """
    @summary: Return the admin/oper status of every DPU module as reported by
              'show chassis modules status'.
    @param duthost: NPU (switch) host object
    @return: dict keyed by DPU name, e.g.
             {"DPU0": {"admin": "down", "oper": "offline"}, ...}
    """
    rows = duthost.show_and_parse("show chassis modules status", module_ignore_errors=True)
    dpu_status = {}
    for row in rows:
        name = row.get("name", "")
        if not re.match(r"^DPU\d+$", name):
            continue
        if "oper-status" not in row or "admin-status" not in row:
            logging.warning("Skipping unexpected chassis module status row: %s", row)
            continue
        dpu_status[name] = {
            "admin": row["admin-status"].strip().lower(),
            "oper": row["oper-status"].strip().lower(),
        }
    return dpu_status


def _dpu_status_matches(duthost, expected_status):
    """
    @summary: Return True when every DPU's admin/oper status equals expected_status.
    """
    current_status = _get_dpu_module_status(duthost)
    for dpu_name, expected in expected_status.items():
        current = current_status.get(dpu_name)
        if current != expected:
            logging.info("DPU %s status is %s, waiting for %s", dpu_name, current, expected)
            return False
    return True


def verify_dpu_status_consistency(duthost, expected_status):
    """
    @summary: Assert that all DPU admin/oper statuses returned to their
              pre-power-off values after a power-cycle.

    On a SmartSwitch the DPUs lose power together with the NPU, so once the NPU
    is back their admin state must be unchanged and their oper state must return
    to what it was before the power-off (Offline in dark mode, Online in lit
    mode). The DPUs may still be booting when the NPU is already up (lit mode),
    so poll until they settle.

    @param duthost: NPU (switch) host object
    @param expected_status: DPU status snapshot captured before the power-off
    """
    pytest_assert(
        wait_until(DPU_STATUS_TIMEOUT, DPU_STATUS_INTERVAL, 0,
                   _dpu_status_matches, duthost, expected_status),
        "DPU admin/oper status is not consistent after power-off reboot. "
        "Expected {}, got {}".format(expected_status, _get_dpu_module_status(duthost))
    )


def test_power_off_reboot(duthosts, localhost, enum_supervisor_dut_hostname, conn_graph_facts,
                          xcvr_skip_list, get_pdu_controller, power_off_delay, adjust_reboot_cause_sequence):
    """
    @summary: This test case is to perform reboot via powercycle and check platform status
    @param duthost: Fixture for DUT AnsibleHost object
    @param localhost: Fixture for interacting with localhost through ansible
    @param conn_graph_facts: Fixture parse and return lab connection graph
    @param xcvr_skip_list: list of DUT's interfaces for which transeiver checks are skipped
    @param get_pdu_controller: The python object of psu controller
    @param power_off_delay: Pytest parameter. The delay between turning off and on the PSU
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    pdu_ctrl = get_pdu_controller(duthost)
    if pdu_ctrl is None:
        pytest.skip(
            "No PSU controller for %s, skip rest of the testing in this case" % duthost.hostname)
    # Fail fast with a clear reason when a PDU is configured for one of the DUT's
    # PSUs but the PDU could not be reached (typically an SNMP timeout). Without
    # this check, the test would silently power-cycle only the reachable PSU and
    # later fail with the misleading "DUT did not shutdown" message.
    if hasattr(pdu_ctrl, "get_unreachable_psus"):
        unreachable_psus = pdu_ctrl.get_unreachable_psus()
        if unreachable_psus:
            pytest.fail(
                "PDU is not accessible for DUT {} PSU(s) {}. The configured peer "
                "PDU(s) {} could not be initialized (most likely SNMP is not "
                "reachable or the credentials are wrong). Power-off reboot cannot "
                "guarantee a full power loss while any PSU remains powered, so "
                "the test is failing early instead of reporting the misleading "
                "'DUT did not shutdown' error. Please verify the PDU "
                "reachability and re-run.".format(
                    duthost.hostname,
                    list(unreachable_psus.keys()),
                    unreachable_psus,
                )
            )
    is_chassis = duthost.get_facts().get("modular_chassis")
    if is_chassis and duthost.is_supervisor_node():
        # Following is to accomodate for chassis, when no '--power_off_delay' option is given on pipeline run
        power_off_delay = 60
    all_outlets = pdu_ctrl.get_outlet_status()
    pytest_assert(all_outlets, "No outlets found for {}".format(duthost.hostname))

    # If PDU supports returning output_watts, making sure that all PSUs has power.
    psu_to_pdus = get_grouped_pdus_by_psu(pdu_ctrl)

    # Purpose of this list is to control sequence of turning on PSUs in power off testing.
    # If there are 2 PSUs, then 3 scenarios would be covered:
    # 1. Turn off all PSUs, turn on PSU1, then check.
    # 2. Turn off all PSUs, turn on PSU2, then check.
    # 3. Turn off all PSUs, turn on one of the PSU, then turn on the other PSU, then check.
    power_on_seq_list = []
    dut_psu_status = None
    for psu, pdus in psu_to_pdus.items():
        dut_psu_status = _validate_psu_power(duthost, psu, pdus, dut_psu_status)
        if not is_chassis:
            power_on_seq_list.append(pdus)
    # Append all_outlets unless it would duplicate the single existing entry
    # For chassis the list is empty here, so all_outlets becomes the only entry
    if len(power_on_seq_list) != 1:
        power_on_seq_list.append(all_outlets)
    logging.info("Got all power on sequences {}".format(power_on_seq_list))

    poweroff_reboot_kwargs = {"dut": duthost}
    poweroff_reboot_kwargs["pdu_ctrl"] = pdu_ctrl
    poweroff_reboot_kwargs["all_outlets"] = all_outlets
    poweroff_reboot_kwargs["delay_time"] = power_off_delay

    # On a SmartSwitch the on-board DPUs lose power together with the NPU during a
    # power-off. Snapshot their admin/oper status beforehand so we can assert it is
    # unchanged after every power-cycle (e.g. DPUs stay down/offline in dark mode).
    is_smartswitch = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_smartswitch")
    dpu_status_before = {}
    if is_smartswitch:
        dpu_status_before = _get_dpu_module_status(duthost)
        pytest_assert(
            dpu_status_before,
            "Failed to read any DPU module status before power-off reboot; "
            "'show chassis modules status' returned no DPU entries. Cannot verify "
            "post-reboot DPU consistency."
        )
        logging.info("SmartSwitch DPU admin/oper status before power-off reboot: %s", dpu_status_before)

    try:
        duthosts_arg = duthosts if is_chassis else None

        for power_on_seq in power_on_seq_list:
            poweroff_reboot_kwargs["power_on_seq"] = power_on_seq
            reboot_and_check(
                localhost, duthost, conn_graph_facts.get(
                    "device_conn", {}).get(duthost.hostname, {}),
                xcvr_skip_list, REBOOT_TYPE_POWEROFF,
                _power_off_reboot_helper, poweroff_reboot_kwargs, duthosts=duthosts_arg)

            if is_smartswitch:
                logging.info("Verifying DPU admin/oper status consistency after power-off reboot")
                verify_dpu_status_consistency(duthost, dpu_status_before)

    except Exception as e:
        logging.debug("Restore power after test failure")
        for outlet in all_outlets:
            logging.debug("turning on {}".format(outlet))
            pdu_ctrl.turn_on_outlet(outlet)
        # Wait for ssh port to open up on the DUT
        reboot_time = 600 if is_chassis else 120
        wait_for_startup(duthost, localhost, 0, reboot_time)
        wait_critical_processes(duthost)
        raise e
