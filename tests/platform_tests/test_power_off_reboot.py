import logging
import pytest
import time

from tests.common.reboot import wait_for_startup, REBOOT_TYPE_POWEROFF
from tests.common.platform.processes_utils import wait_critical_processes, check_critical_processes
from tests.common.helpers.assertions import pytest_assert
from tests.platform_tests.test_reboot import check_interfaces_and_services,\
    reboot_and_check
from tests.common.utilities import get_plt_reboot_ctrl

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

INTERFACE_WAIT_TIME = 300


@pytest.fixture(scope="module", autouse=True)
def set_max_time_for_interfaces(duthost):
    """
    For chassis testbeds, we need to specify plt_reboot_ctrl in inventory file,
    to let MAX_TIME_TO_REBOOT to be overwritten by specified timeout value
    """
    global INTERFACE_WAIT_TIME
    plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, 'test_reboot.py', 'cold')
    if plt_reboot_ctrl:
        INTERFACE_WAIT_TIME = plt_reboot_ctrl.get('timeout', 300)


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthosts, enum_supervisor_dut_hostname, conn_graph_facts, xcvr_skip_list):
    duthost = duthosts[enum_supervisor_dut_hostname]
    yield

    logging.info("Tearing down: to make sure all the critical services, interfaces and transceivers are good")
    interfaces = conn_graph_facts["device_conn"][duthost.hostname]
    check_critical_processes(duthost, watch_secs=10)
    check_interfaces_and_services(duthost, interfaces, xcvr_skip_list, INTERFACE_WAIT_TIME)


def _power_off_reboot_helper(kwargs):
    """
    @summary: used to parametrized test cases on power_off_delay
    @param kwargs: the delay time between turning off and on the PSU
    """
    pdu_ctrl = kwargs["pdu_ctrl"]
    all_outlets = kwargs["all_outlets"]
    power_on_seq = kwargs["power_on_seq"]
    delay_time = kwargs["delay_time"]

    for outlet in all_outlets:
        logging.debug("turning off {}".format(outlet))
        pdu_ctrl.turn_off_outlet(outlet)
    time.sleep(delay_time)
    logging.info("Power on {}".format(power_on_seq))
    for outlet in power_on_seq:
        logging.debug("turning on {}".format(outlet))
        pdu_ctrl.turn_on_outlet(outlet)


def test_power_off_reboot(duthosts, localhost, enum_supervisor_dut_hostname, conn_graph_facts,
                          xcvr_skip_list, get_pdu_controller, power_off_delay):
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
    UNSUPPORTED_ASIC_TYPE = ["cisco-8000"]
    if duthost.facts["asic_type"] in UNSUPPORTED_ASIC_TYPE:
        pytest.skip("Skipping test_power_off_reboot. Test unsupported on {} platform"
                    .format(duthost.facts["asic_type"]))
    pdu_ctrl = get_pdu_controller(duthost)
    if pdu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % duthost.hostname)
    is_chassis = duthost.get_facts().get("modular_chassis")
    if is_chassis and duthost.is_supervisor_node():
        # Following is to accomodate for chassis, when no '--power_off_delay' option is given on pipeline run
        power_off_delay = 60
    all_outlets = pdu_ctrl.get_outlet_status()
    # If PDU supports returning output_watts, making sure that all outlets has power.
    no_power = [item for item in all_outlets if int(item.get('output_watts', '1')) == 0]
    pytest_assert(not no_power, "Not all outlets have power output: {}".format(no_power))

    # Purpose of this list is to control sequence of turning on PSUs in power off testing.
    # If there are 2 PSUs, then 3 scenarios would be covered:
    # 1. Turn off all PSUs, turn on PSU1, then check.
    # 2. Turn off all PSUs, turn on PSU2, then check.
    # 3. Turn off all PSUs, turn on one of the PSU, then turn on the other PSU, then check.
    power_on_seq_list = []
    if all_outlets:
        power_on_seq_list = [[item] for item in all_outlets]
        power_on_seq_list.append(all_outlets)

    logging.info("Got all power on sequences {}".format(power_on_seq_list))

    poweroff_reboot_kwargs = {"dut": duthost}

    try:
        for power_on_seq in power_on_seq_list:
            poweroff_reboot_kwargs["pdu_ctrl"] = pdu_ctrl
            poweroff_reboot_kwargs["all_outlets"] = all_outlets
            poweroff_reboot_kwargs["power_on_seq"] = power_on_seq
            poweroff_reboot_kwargs["delay_time"] = power_off_delay
            reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname],
                             xcvr_skip_list, REBOOT_TYPE_POWEROFF,
                             _power_off_reboot_helper, poweroff_reboot_kwargs)
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
