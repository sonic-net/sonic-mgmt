import logging
import pytest
from tests.common.broadcom_data import is_broadcom_device
from tests.common.helpers.assertions import pytest_require
from tests.common.cisco_data import is_cisco_device
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.common.config_reload import config_reload
from tests.common.reboot import reboot
from tests.common.helpers.parallel import parallel_run
from tests.common.utilities import wait_until
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.snappi_tests.snappi_fixtures import get_snappi_ports_for_rdma, \
    snappi_dut_base_config, is_snappi_multidut

logger = logging.getLogger(__name__)


def skip_warm_reboot(duthost, reboot_type):
    """
    Skip warm/fast reboot tests for TD2 asics and Cisco devices

    Args:
        duthost (pytest fixture): device under test
        reboot_type (string): type of reboot (can be warm, cold, fast)

    Returns:
        None
    """
    SKIP_LIST = ["td2"]
    asic_type = duthost.get_asic_name()
    reboot_case_supported = True
    if (reboot_type == "warm" or reboot_type == "fast") and is_cisco_device(duthost):
        reboot_case_supported = False
    elif is_broadcom_device(duthost) and asic_type in SKIP_LIST and "warm" in reboot_type:
        reboot_case_supported = False
    msg = "Reboot type {} is {} supported on {} switches".format(
            reboot_type, "" if reboot_case_supported else "not", duthost.facts['asic_type'])
    logger.info(msg)
    pytest_require(reboot_case_supported, msg)


def skip_ecn_tests(duthost):
    """
    Skip ECN tests for Cisco devices

    Args:
        duthost (pytest fixture): device under test

    Returns:
        None
    """
    pytest_require(not is_cisco_device(duthost), "ECN tests are not supported on Cisco switches yet.")


def skip_pfcwd_test(duthost, trigger_pfcwd):
    """
    Skip PFC watchdog tests that may cause fake alerts

    PFC watchdog on Broadcom devices use some approximation techniques to detect
    PFC storms, which may cause some fake alerts. Therefore, we skip test cases
    whose trigger_pfcwd is False for Broadcom devices.

    Args:
        duthost (obj): device to test
        trigger_pfcwd (bool): if PFC watchdog is supposed to trigger

    Returns:
        N/A
    """
    pytest_require(trigger_pfcwd is True or is_broadcom_device(duthost) is False,
                   'Skip trigger_pfcwd=False test cases for Broadcom devices')


@pytest.fixture(autouse=True, params=MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def multidut_port_info(request):
    yield request.param


@pytest.fixture(autouse=True)
def setup_ports_and_dut(
        duthosts,
        snappi_api,
        get_snappi_ports,
        multidut_port_info,
        number_of_tx_rx_ports):
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count, rx_port_count = number_of_tx_rx_ports
        if len(get_snappi_ports) < tx_port_count + rx_port_count:
            pytest.skip(
                "Need Minimum of 2 ports defined in ansible/files/*links.csv"
                " file, got:{}".format(len(get_snappi_ports)))

        if len(rdma_ports['tx_ports']) < tx_port_count:
            pytest.skip(
                "MULTIDUT_PORT_INFO doesn't have the required Tx ports defined for "
                "testbed {}, subtype {} in variables.py".format(
                    MULTIDUT_TESTBED, testbed_subtype))

        if len(rdma_ports['rx_ports']) < rx_port_count:
            pytest.skip(
                "MULTIDUT_PORT_INFO doesn't have the required Rx ports defined for "
                "testbed {}, subtype {} in variables.py".format(
                    MULTIDUT_TESTBED, testbed_subtype))
        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))
        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(
                get_snappi_ports,
                rdma_ports,
                tx_port_count,
                rx_port_count,
                MULTIDUT_TESTBED)
        else:
            snappi_ports = get_snappi_ports
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(
            duthosts, snappi_ports, snappi_api, setup=True)

    if len(port_config_list) < 2:
        pytest.skip("This test requires at least 2 ports")
    yield (testbed_config, port_config_list, snappi_ports)

    snappi_dut_base_config(duthosts, snappi_ports, snappi_api, setup=False)


@pytest.fixture(params=['warm', 'cold', 'fast'])
def reboot_duts(setup_ports_and_dut, localhost, request):
    reboot_type = request.param
    _, _, snappi_ports = setup_ports_and_dut
    skip_warm_reboot(snappi_ports[0]['duthost'], reboot_type)
    skip_warm_reboot(snappi_ports[1]['duthost'], reboot_type)

    def save_config_and_reboot(node, results=None):
        up_bgp_neighbors = node.get_bgp_neighbors_per_asic("established")
        logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, node.hostname))
        node.shell("mkdir /etc/sonic/orig_configs; mv /etc/sonic/config_db* /etc/sonic/orig_configs/")
        node.shell("sudo config save -y")
        reboot(node, localhost, reboot_type=reboot_type, safe_reboot=True)
        logger.info("Wait until the system is stable")
        wait_until(180, 20, 0, node.critical_services_fully_started)
        wait_until(180, 20, 0, check_interface_status_of_up_ports, node)
        wait_until(300, 10, 0, node.check_bgp_session_state_all_asics, up_bgp_neighbors, "established")

    # Convert the list of duthosts into a list of tuples as required for parallel func.
    args = set((snappi_ports[0]['duthost'], snappi_ports[1]['duthost']))
    parallel_run(save_config_and_reboot, {}, {}, list(args), timeout=900)
    yield

    def revert_config_and_reload(node, results=None):
        node.shell("mv /etc/sonic/orig_configs/* /etc/sonic/ ; rmdir /etc/sonic/orig_configs; ")
        config_reload(node, safe_reload=True)

    # parallel_run(revert_config_and_reload, {}, {}, list(args), timeout=900)
    for duthost in args:
        revert_config_and_reload(node=duthost)
