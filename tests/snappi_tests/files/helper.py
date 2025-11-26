import logging
import re
import pytest
import json
from itertools import cycle
from tests.common.broadcom_data import is_broadcom_device
from tests.common.helpers.assertions import pytest_require
from tests.common.cisco_data import is_cisco_device
from tests.common.nokia_data import is_nokia_device
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.common.config_reload import config_reload
from tests.common.reboot import reboot
from tests.common.helpers.parallel import parallel_run
from tests.common.utilities import wait_until
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.snappi_tests.snappi_fixtures import get_snappi_ports_for_rdma, \
    snappi_dut_base_config, is_snappi_multidut
from tests.common.snappi_tests.qos_fixtures import reapply_pfcwd, get_pfcwd_config
from tests.common.snappi_tests.common_helpers import \
        stop_pfcwd, disable_packet_aging, enable_packet_aging
from tests.snappi_tests.cisco.helper import modify_voq_watchdog_cisco_8000

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
    SKIP_LIST = ["td2", "jr2", "j2c+"]
    asic_type = duthost.get_asic_name()
    reboot_case_supported = True
    if (reboot_type == "fast") and asic_type in ["jr2", "j2c+"]:
        reboot_case_supported = False
    elif (reboot_type == "warm" or reboot_type == "fast") and is_cisco_device(duthost):
        reboot_case_supported = False
    elif (reboot_type == "warm" or reboot_type == "fast") and is_nokia_device(duthost):
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


def get_number_of_streams(duthost, tx_ports, rx_ports):
    """
    Determines the number of test streams to use based on DUT type and port configurations.

    Args:
        duthost (obj): Device under test.
        tx_ports (list|dict): Snappi TX ports list or single port dict.
        rx_ports (list|dict): Snappi RX ports list or single port dict.

    Returns:
        int: Number of test streams to use.
    """
    def extract_unique_values(ports, key):
        if isinstance(ports, list):
            return list({port[key] for port in ports})
        return [ports[key]]

    no_of_test_streams = 1

    if duthost.facts["platform_asic"] != 'cisco-8000':
        return no_of_test_streams

    if duthost.get_facts().get("modular_chassis"):
        tx_duthosts = extract_unique_values(tx_ports, 'duthost')
        rx_duthosts = extract_unique_values(rx_ports, 'duthost')

        if tx_duthosts != rx_duthosts or (
            extract_unique_values(tx_ports, 'asic_value') != extract_unique_values(rx_ports, 'asic_value')
        ):
            tx_ports = tx_ports if isinstance(tx_ports, list) else [tx_ports]
            if any(int(port['speed']) >= 200000 for port in tx_ports):
                no_of_test_streams = 10

    return no_of_test_streams


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
        if node.facts.get('asic_type') == "cisco-8000":
            modify_voq_watchdog_cisco_8000(node, False)

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


@pytest.fixture(autouse=True)
def enable_debug_shell(setup_ports_and_dut):  # noqa: F811
    _, _, snappi_ports = setup_ports_and_dut
    rx_duthost = snappi_ports[0]['duthost']

    if is_cisco_device(rx_duthost):
        dutport = snappi_ports[0]['peer_port']
        asic_namespace_string = ""
        syncd_string = "syncd"
        if rx_duthost.is_multi_asic:
            asic = rx_duthost.get_port_asic_instance(dutport)
            asic_namespace_string = " -n " + asic.namespace
            asic_id = rx_duthost.get_asic_id_from_namespace(asic.namespace)
            syncd_string += str(asic_id)

        dshell_status = "".join(rx_duthost.shell("docker exec {} supervisorctl status dshell_client | \
                                                 grep \"dshell_client.*RUNNING\"".format(syncd_string),
                                                 module_ignore_errors=True)["stdout_lines"])
        if 'RUNNING' not in dshell_status:
            debug_shell_enable = rx_duthost.command("docker exec {} supervisorctl start dshell_client".
                                                    format(syncd_string))
            logging.info(debug_shell_enable)

        def is_debug_shell_enabled():
            output = "".join(rx_duthost.shell("sudo show platform npu voq voq_globals -i {}{}".format(
                                                dutport, asic_namespace_string))["stdout_lines"])
            if "cisco sdk-debug enable" in output:
                return False
            return True

        wait_until(360, 5, 0, is_debug_shell_enabled)
    yield
    pass


def compute_expected_packets(flow_rate_bps, pkt_size_bytes, duration_s, num_streams=1):
    """
    Computes the expected packet count and threshold based on traffic parameters.

    Args:
        flow_rate_bps (int): Flow rate in bits per second.
        pkt_size_bytes (int): Packet size in bytes.
        duration_s (int): Duration in seconds.
        threshold_pct (int): Percentage threshold for filtering significant traffic.

    Returns:
        int: Minimum packet count threshold.
    """
    pkt_size_bits = (pkt_size_bytes + 20) * 8
    expected_packets = (flow_rate_bps * duration_s) // pkt_size_bits
    return int(expected_packets / num_streams * 0.95)  # 5 % margin


def get_fabric_mapping(duthost, asic=""):
    """
    Retrieves the mapping between backplane and fabric interfaces dynamically.

    Returns:
        dict: Dictionary mapping backplane interfaces to fabric interfaces.
    """

    asic_namespace = ""
    if asic:
        asic_namespace = " --namespace {}".format(asic.namespace)

    cmd = "show platform npu bp-interface-map" + asic_namespace
    result = duthost.shell(cmd)['stdout']
    fabric_map = {}

    for line in result.split("\n"):
        match = re.search(r"(Ethernet-BP\d+)\(S\).*(Ethernet-BP\d+)", line)
        if match:
            fabric_map[match.group(1)] = match.group(2)

    return fabric_map


def load_port_stats(stats, threshold, direction="both"):
    """
    Parses port statistics and filters interfaces involved in traffic forwarding.

    Args:
        stats (dict): Dictionary containing port statistics.
        threshold (int): Minimum packet count to consider an interface active.
        direction (str): Filter interfaces based on "tx", "rx", or "both"

    Returns:
        dict: Dictionary of interfaces with nonzero TX_OK and RX_OK above threshold.
    """
    active_interfaces = {}

    for interface, data in stats.items():
        tx_ok = int(data.get("TX_OK", 0).replace(",", ""))
        rx_ok = int(data.get("RX_OK", 0).replace(",", ""))

        # Consider interfaces with TX/RX OK counts above threshold
        if (direction == "tx" and tx_ok > threshold):
            active_interfaces[interface] = {"TX_OK": tx_ok}

        if (direction == "rx" and rx_ok > threshold):
            active_interfaces[interface] = {"RX_OK": rx_ok}

        if (direction == "both" and (tx_ok > threshold or rx_ok > threshold)):
            active_interfaces[interface] = {"TX_OK": tx_ok, "RX_OK": rx_ok}

    return active_interfaces


def infer_ecmp_backplane_ports(
                                ingress_active_interfaces,
                                egress_active_interfaces,
                                ingress,
                                egress,
                                ingress_fabric_mapping,
                                egress_fabric_mapping):
    """
    Identifies all backplane ports involved in ECMP traffic forwarding.

    Args:
        ingress_active_interfaces (dict): Interfaces on ingress DUT with TX_OK > threshold.
        egress_active_interfaces (dict): Interfaces on egress DUT with RX_OK > threshold.
        ingress (str): Known ingress port.
        egress (str): Known egress port.
        ingress_fabric_mapping (dict): Mapping of ingress DUT backplane interfaces to fabric interfaces.
        egress_fabric_mapping (dict): Mapping of egress DUT backplane interfaces to fabric interfaces.

    Returns:
        list: List of traffic paths, each as an ordered list of interfaces.
    """
    # Step 1: Remove ingress and egress from active interfaces
    ingress_active_interfaces = {k: v for k, v in ingress_active_interfaces.items() if k not in {ingress, egress}}
    egress_active_interfaces = {k: v for k, v in egress_active_interfaces.items() if k not in {ingress, egress}}

    tx_ports = []
    rx_ports = []

    for interface, stats in ingress_active_interfaces.items():
        tx_ok = stats.get('TX_OK', 0)
        rx_ok = stats.get('RX_OK', 0)

        if tx_ok > rx_ok:  # Ports with more TX are considered transmitting backplanes
            tx_ports.append((interface, tx_ok))

    for interface, stats in egress_active_interfaces.items():
        tx_ok = stats.get('TX_OK', 0)
        rx_ok = stats.get('RX_OK', 0)

        if rx_ok > tx_ok:
            rx_ports.append((interface, rx_ok))

    # Sort the lists based on TX_OK (for transmitting) or RX_OK (for receiving)
    tx_ports = sorted(tx_ports, key=lambda x: x[1], reverse=True)
    rx_ports = sorted(rx_ports, key=lambda x: x[1], reverse=True)

    backplane_tx_ports = [port[0] for port in tx_ports]
    backplane_rx_ports = [port[0] for port in rx_ports]

    traffic_paths = []

    # Always cycle the smaller list
    if len(backplane_tx_ports) >= len(backplane_rx_ports):
        rx_cycle = cycle(backplane_rx_ports)  # RX cycles if fewer or equal
        for tx_bp in backplane_tx_ports:
            rx_bp = next(rx_cycle)
            fabric_rx = ingress_fabric_mapping.get(tx_bp)
            fabric_tx = egress_fabric_mapping.get(rx_bp)
            if fabric_rx and fabric_tx:
                path = [ingress, tx_bp, fabric_rx, fabric_tx, rx_bp, egress]
                traffic_paths.append(path)
    else:
        tx_cycle = cycle(backplane_tx_ports)  # TX cycles if fewer
        for rx_bp in backplane_rx_ports:
            tx_bp = next(tx_cycle)
            fabric_rx = ingress_fabric_mapping.get(tx_bp)
            fabric_tx = egress_fabric_mapping.get(rx_bp)
            if fabric_rx and fabric_tx:
                path = [ingress, tx_bp, fabric_rx, fabric_tx, rx_bp, egress]
                traffic_paths.append(path)

    return traffic_paths


def set_cir_cisco_8000(dut, ports, asic="", speed=240151205000):
    dshell_script = '''
from common import *
from sai_utils import *

def set_port_cir(interface, rate):
    mp = get_mac_port(interface)
    sch = mp.get_scheduler()
    sch.set_credit_cir(rate)
'''

    for intf in ports:
        dshell_script += f'\nset_port_cir("{intf}", {speed})'

    script_path = "/tmp/set_scheduler.py"
    dut.copy(content=dshell_script, dest=script_path)
    dest = f"syncd{asic.asic_index}"

    dut.docker_copy_to_all_asics(
        container_name=dest,
        src=script_path,
        dst="/")

    cmd = "sudo show platform npu script -n {} -s set_scheduler.py".format(asic.namespace)
    dut.shell(cmd)


def get_npu_voq_queue_counters(duthost, interface, priority, clear=False):
    asic_namespace_string = ""
    if duthost.is_multi_asic:
        asic = duthost.get_port_asic_instance(interface)
        asic_namespace_string = " -n " + asic.namespace

    clear_cmd = ""
    if clear:
        clear_cmd = " -c"

    full_line = "".join(duthost.shell(
        "show platform npu voq queue_counters -t {} -i {} -d{}{}".
        format(priority, interface, asic_namespace_string, clear_cmd))['stdout_lines'])
    dict_output = json.loads(full_line)
    for entry, value in zip(dict_output['stats_name'], dict_output['counters']):
        dict_output[entry] = value

    return dict_output


@pytest.fixture(params=['warm', 'cold', 'fast'])
def reboot_duts_and_disable_wd(tgen_port_info, localhost, request):
    '''
    Purpose of the function is to have reboot_duts and disable watchdogs.
    '''
    reboot_type = request.param
    _, _, snappi_ports = tgen_port_info
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

    pfcwd_value = {}

    for duthost in list(args):
        pfcwd_value[duthost.hostname] = get_pfcwd_config(duthost)
        stop_pfcwd(duthost)
        disable_packet_aging(duthost)
        if duthost.facts['asic_type'] == "cisco-8000":
            modify_voq_watchdog_cisco_8000(duthost, False)

    yield

    for duthost in list(args):
        reapply_pfcwd(duthost, pfcwd_value[duthost.hostname])
        enable_packet_aging(duthost)

    def revert_config_and_reload(node, results=None):
        node.shell("mv /etc/sonic/orig_configs/* /etc/sonic/ ; rmdir /etc/sonic/orig_configs; ")
        config_reload(node, safe_reload=True)

    # parallel_run(revert_config_and_reload, {}, {}, list(args), timeout=900)
    for duthost in args:
        revert_config_and_reload(node=duthost)


def adjust_test_flow_rate(dut, test_def):
    '''
    Set the test flow rate for Cisco 8000 series switches.
    Args:
        dut (object): Device under test.
        test_def (dict): Test definition containing the flow rate and background traffic.
    Returns:
        None: The function modifies the `test_def` dictionary in place.
    '''
    # Cisco devices send continuous XOFF packets this can reduce the effective bandwidth
    # available for test traffic. To accommodate this limitation and avoid oversubscription, we define
    # a SAFETY_MARGIN to ensure the aggregated traffic rate remains below 100% line rate.
    SAFETY_MARGIN = 0.5
    if dut.facts["platform_asic"] != 'cisco-8000':
        return
    test_def['TEST_FLOW_AGGR_RATE_PERCENT'] = 100 - SAFETY_MARGIN
    if test_def.get('background_traffic'):
        test_def['TEST_FLOW_AGGR_RATE_PERCENT'] = (
            test_def['TEST_FLOW_AGGR_RATE_PERCENT'] - test_def.get('BG_FLOW_AGGR_RATE_PERCENT', 0)
            )
