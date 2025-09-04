import logging
import pytest

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import get_dscp_to_queue_value, configure_packet_aging
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links, peer_links    # noqa F401
from tests.common.mellanox_data import is_mellanox_device
from tests.common.helpers.srv6_helper import create_srv6_locator, del_srv6_locator, create_srv6_sid, del_srv6_sid
from tests.packet_trimming.constants import (SERVICE_PORT, COUNTERPOLL_INTERVAL, DEFAULT_DSCP,
                                             SRV6_TUNNEL_MODE, SRV6_MY_LOCATOR_LIST, SRV6_MY_SID_LIST)
from tests.packet_trimming.packet_trimming_helper import (delete_blocking_scheduler, check_trimming_capability,
                                                          prepare_service_port, get_test_ports,
                                                          get_interface_peer_addresses, configure_tc_to_dscp_map,
                                                          set_buffer_profiles_for_block_and_trim_queues,
                                                          create_blocking_scheduler, configure_trimming_action,
                                                          cleanup_trimming_acl)


logger = logging.getLogger(__name__)


@pytest.fixture(scope="session", autouse=True)
def skip_if_packet_trimming_not_supported(duthost):
    """
    Check if the current device supports packet trimming feature.

    Logic:
    Check if the SWITCH_TRIMMING_CAPABLE capability is true. If not, skip the test.

    Args:
        duthost: DUT host object
    """
    platform = duthost.facts["platform"]
    logger.info(f"Checking packet trimming support for platform: {platform}")

    # Check if the SWITCH_TRIMMING_CAPABLE capability is true
    trimming_capable = duthost.command('redis-cli -n 6 HGET "SWITCH_CAPABILITY|switch" "SWITCH_TRIMMING_CAPABLE"')[
        'stdout'].strip()
    if trimming_capable.lower() != 'true':
        pytest.skip("Packet trimming is not supported")

    # For Nvidia SPC1/2/3 platforms, skip the test
    elif any(platform_id in platform.lower() for platform_id in ["sn2", "sn3", "sn4"]):
        pytest.skip(f"Packet trimming is not supported on {platform}")

    # For Nvidia SPC4 platforms, check if the "SAI_ADAPTIVE_ROUTING_CIRCULATION_PORT" exists in sai.profile
    elif "sn5600" in platform:
        hwsku = duthost.facts["hwsku"]
        sai_profile = f"/usr/share/sonic/device/{platform}/{hwsku}/sai.profile"
        sai_profile_content = duthost.command(f"cat {sai_profile}")["stdout_lines"]

        if "SAI_ADAPTIVE_ROUTING_CIRCULATION_PORT" not in sai_profile_content:
            pytest.skip("Packet trimming is not supported")


@pytest.fixture(scope="module")
def test_params(duthost, mg_facts, dut_qos_maps_module, downstream_links, upstream_links, peer_links, tbinfo): # noqa F811
    """
    Prepare test parameters for packet trimming tests.

    ingress_port: The first downlink port
    egress_port_1: The first uplink port
    egress_port_2: The second downlink port (For T0 topology no egress_port_2, because downlink interface does not
    have BGP neighbor in T0 topology)

    Returns:
        dict: Dictionary containing test parameters needed for packet trimming tests
    """
    logger.info("Preparing test parameters for packet trimming tests")

    with allure.step("Get trimming test ports"):
        ports = get_test_ports(upstream_links, downstream_links, peer_links, mg_facts)
        logger.info(f"The test ports: {ports}")

        ingress_port = ports["ingress_port"]
        egress_port_1 = ports["egress_port_1"]
        egress_port_2 = ports["egress_port_2"]

        ingress_port_name = list(ingress_port.keys())[0]
        egress_port_1_name = list(egress_port_1.keys())[0]
        egress_port_2_name = list(egress_port_2.keys())[0]

        egress_port_1_ipv4, egress_port_1_ipv6 = get_interface_peer_addresses(mg_facts, egress_port_1_name)
        egress_port_2_ipv4, egress_port_2_ipv6 = get_interface_peer_addresses(mg_facts, egress_port_2_name)
        logger.info(f"ingress_port: {ingress_port}, egress_port_1: {egress_port_1}, egress_port_2: {egress_port_2}, "
                    f"egress_port_1_ipv4: {egress_port_1_ipv4}, egress_port_1_ipv6: {egress_port_1_ipv6}, "
                    f"egress_port_2_ipv4: {egress_port_2_ipv4}, egress_port_2_ipv6: {egress_port_2_ipv6}")

    with allure.step(f"Get queue id for packet with dscp value {DEFAULT_DSCP}"):
        # Get port QoS map for the downlink port
        port_qos_map = dut_qos_maps_module['port_qos_map']
        logger.info(f"Retrieving QoS maps for port: {ingress_port_name}")

        # Extract the DSCP to TC map name from the port QoS configuration
        dscp_to_tc_map_name = port_qos_map[ingress_port_name]['dscp_to_tc_map'].split('|')[-1].strip(']')
        logger.info(f"DSCP to TC map name: {dscp_to_tc_map_name}")

        # Extract the TC to Queue map name from the port QoS configuration
        tc_to_queue_map_name = port_qos_map[ingress_port_name]['tc_to_queue_map'].split('|')[-1].strip(']')
        logger.info(f"TC to Queue map name: {tc_to_queue_map_name}")

        # Get the actual DSCP to TC mapping from the QoS maps
        dscp_to_tc_map = dut_qos_maps_module['dscp_to_tc_map'][dscp_to_tc_map_name]
        logger.debug(f"DSCP to TC mapping details: {dscp_to_tc_map}")

        # Get the actual TC to Queue mapping from the QoS maps
        tc_to_queue_map = dut_qos_maps_module['tc_to_queue_map'][tc_to_queue_map_name]
        logger.debug(f"TC to Queue mapping details: {tc_to_queue_map}")

        # Calculate the queue ID, this queue will be blocked during testing
        block_queue = get_dscp_to_queue_value(DEFAULT_DSCP, dscp_to_tc_map, tc_to_queue_map)
        logger.info(f"The tested queue: {block_queue}")

    # Build egress_port_1 dictionary
    egress_port_1_dict = {
        'name': egress_port_1_name,
        'ptf_id': egress_port_1[egress_port_1_name]['ptf_port_id'],
        'ipv4': egress_port_1_ipv4,
        'ipv6': egress_port_1_ipv6,
        'dut_members': egress_port_1[egress_port_1_name]['dut_members'],
    }

    egress_ports = [egress_port_1_dict]
    # The egress_port_2 is a downlink interface.
    # For t0 topology, downlink interfaces do not have IP address, so do not add it to test_param.
    if tbinfo["topo"]["type"] != "t0":
        # Build egress_port_2 dictionary
        egress_port_2_dict = {
            'name': egress_port_2_name,
            'ptf_id': egress_port_2[egress_port_2_name]['ptf_port_id'],
            'ipv4': egress_port_2_ipv4,
            'ipv6': egress_port_2_ipv6,
            'dut_members': egress_port_2[egress_port_2_name]['dut_members'],
        }

        egress_ports.append(egress_port_2_dict)

    test_param = {
        'block_queue': block_queue,
        'trim_buffer_profiles': {
            'uplink': f"queue{block_queue}_uplink_lossy_profile",
            'downlink': f"queue{block_queue}_downlink_lossy_profile",
        },
        'ingress_port': {
            'name': ingress_port_name,
            'ptf_id': ingress_port[ingress_port_name]['ptf_port_id'],
        },
        'egress_ports': egress_ports
    }

    logger.info(f"The test parameters: {test_param}")

    return test_param


@pytest.fixture(scope="module", autouse=True)
def setup_trimming(duthost, test_params):
    """
    Set up all prerequisites for packet trimming tests.

    Args:
        duthost: DUT host object
        test_params: Test parameters from test_params fixture
    """
    logger.info("Prepare packet trimming related configurations")
    platform = duthost.facts['platform']

    with allure.step("Backup configuration"):
        logger.info("Backup configuration before trimming test")
        duthost.shell("sudo config save -y /etc/sonic/config_db_before_trimming_test.json")

    # For Nvidia sn5600 platform, the service port will be used as packets trimming feature.
    # So need to check trimming capability and prepare service port before test tests.
    if "sn5600" in platform:
        with allure.step("Check trimming capability and prepare service port"):
            logger.info("Check trimming capability")
            check_trimming_capability(duthost)

            logger.info("Prepare service port")
            prepare_service_port(duthost, SERVICE_PORT)

    if is_mellanox_device(duthost):
        with allure.step("Disable packet aging"):
            configure_packet_aging(duthost, disabled=True)

    with allure.step("Configure buffer profile for blocked queue and trimmed queue"):
        # The first interface is uplink interface, use uplink buffer profile
        uplink_port = test_params['egress_ports'][0]
        block_interface = uplink_port['dut_members']
        logger.info(f"Apply uplink buffer profile to interfaces: {block_interface}")
        set_buffer_profiles_for_block_and_trim_queues(duthost, block_interface, test_params['block_queue'],
                                                      test_params['trim_buffer_profiles']['uplink'])

        # The second interface is downlink interface. If the second interface exists, use downlink buffer profile
        if len(test_params['egress_ports']) > 1:
            downlink_port = test_params['egress_ports'][1]
            block_interface = downlink_port['dut_members']
            logger.info(f"Apply downlink buffer profile to interfaces: {block_interface}")
            set_buffer_profiles_for_block_and_trim_queues(duthost, block_interface, test_params['block_queue'],
                                                          test_params['trim_buffer_profiles']['downlink'])

    with allure.step("Create scheduler used for blocking egress queues"):
        create_blocking_scheduler(duthost)

    with allure.step("Configure TC_TO_DSCP_MAP for asymmetric DSCP"):
        configure_tc_to_dscp_map(duthost, test_params['egress_ports'])

    with allure.step("Configure counterpoll interval"):
        duthost.command(f"counterpoll queue interval {COUNTERPOLL_INTERVAL}")

    with allure.step("Clear ports and queue counters"):
        duthost.command("sonic-clear queuecounters")
        duthost.command("sonic-clear counters")

    yield

    with allure.step("Disable trimming in buffer profile"):
        for buffer_profile in test_params['trim_buffer_profiles']:
            configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "off")

    with allure.step("Delete the blocking scheduler"):
        delete_blocking_scheduler(duthost)

    if is_mellanox_device(duthost):
        with allure.step("Enable packet aging"):
            configure_packet_aging(duthost, disabled=False)

    with allure.step("Restore original configuration"):
        logger.info("Restoring original configuration")
        duthost.shell("sudo config load -y /etc/sonic/config_db_before_trimming_test.json")
        duthost.shell("sudo config save -y")


@pytest.fixture(params=SRV6_TUNNEL_MODE)
def setup_srv6(duthost, request, rand_selected_dut, upstream_links, peer_links, test_params):    # noqa F811
    """
    Configure 10 instances of SRV6_MY_SIDS
    """
    for locator_param in SRV6_MY_LOCATOR_LIST:
        locator_name = locator_param[0]
        locator_prefix = locator_param[1]
        create_srv6_locator(rand_selected_dut, locator_name, locator_prefix)

    for sid_param in SRV6_MY_SID_LIST:
        locator_name = sid_param[0]
        ip_addr = sid_param[1]
        action = sid_param[2]
        vrf = sid_param[3]
        dscp_mode = request.param
        create_srv6_sid(rand_selected_dut, locator_name, ip_addr, action, vrf, dscp_mode)

    # If there are multiple uplink interfaces, they are in ECMP relationship, and SRv6 packets would
    # be sent out through a randomly selected interface. For trimming with SRv6 test, we use the first
    # uplink interface as the test interface and shutdown all other interfaces to ensure packet forwarding.
    egress_port_1 = test_params['egress_ports'][0]
    exclude_ports = egress_port_1['dut_members']
    all_ports = set(upstream_links.keys()) | set(peer_links.keys())
    shutdown_ports = [k for k in all_ports if k not in exclude_ports]
    logger.info(f"Shutting down ports: {shutdown_ports}")

    # Shut down all collected ports
    for port in shutdown_ports:
        logger.info(f"Shutting down port: {port}")
        duthost.shutdown(port)

    yield dscp_mode

    # Restore all previously shutdown ports
    for port in shutdown_ports:
        logger.info(f"Starting up port: {port}")
        duthost.no_shutdown(port)

    for locator_param in SRV6_MY_LOCATOR_LIST:
        locator_name = locator_param[0]
        del_srv6_locator(rand_selected_dut, locator_name)

    for sid_param in SRV6_MY_SID_LIST:
        locator_name = sid_param[0]
        ip_addr = sid_param[1]
        del_srv6_sid(rand_selected_dut, locator_name, ip_addr)


@pytest.fixture(scope="function")
def clean_trimming_acl_tables(duthost):
    """
    Clean up ACL tables after testing.
    """

    yield

    logger.info("Cleaning up ACL tables after testing")
    cleanup_trimming_acl(duthost)


def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the packet trimming reboot tests.
    """
    parser.addoption(
        "--packet_trimming_reboot_type",
        action="store",
        choices=['reload', 'cold'],
        default=None,
        required=False,
        help="reboot type such as reload, cold"
    )
