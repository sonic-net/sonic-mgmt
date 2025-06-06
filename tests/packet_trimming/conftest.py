import logging
import pytest

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import get_dscp_to_queue_value, configure_packet_aging
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links, service_links    # noqa F401
from tests.common.mellanox_data import is_mellanox_device
from tests.common.helpers.srv6_helper import create_srv6_locator, del_srv6_locator, create_srv6_sid, del_srv6_sid
from tests.packet_trimming.constants import (SERVICE_PORT, BLOCK_QUEUE_PROFILE, COUNTERPOLL_INTERVAL, DEFAULT_DSCP,
                                             SRV6_TUNNEL_MODE, SRV6_MY_LOCATOR_LIST, SRV6_MY_SID_LIST)
from tests.packet_trimming.packet_trimming_helper import (delete_blocking_scheduler, check_trimming_capability,
                                                          prepare_service_port, get_test_ports,
                                                          get_interface_peer_addresses,
                                                          set_buffer_profiles_for_block_and_trim_queues,
                                                          create_blocking_scheduler, configure_trimming_action)


logger = logging.getLogger(__name__)


@pytest.fixture(scope="session", autouse=True)
def is_packet_trimming_supported(duthost):
    """
    Check if the current device supports packet trimming feature.

    Logic:
    1. For Nvidia SPC1/SPC2/SPC3 platform, do not support packet trimming, skip the test.
    2. For Nvidia SPC4 platform, check if the "SAI_ADAPTIVE_ROUTING_CIRCULATION_PORT" exists in sai.profile.
       If not, skip the test.

    Args:
        duthost: DUT host object
    """
    platform = duthost.facts["platform"]
    logger.info(f"Checking packet trimming support for platform: {platform}")

    # For Nvidia SPC1/2/3 platforms, skip the test
    if any(platform_id in platform.lower() for platform_id in ["sn2", "sn3", "sn4"]):
        pytest.skip(f"Packet trimming is not supported on {platform}")

    # For Nvidia SPC4 platforms, check if the "SAI_ADAPTIVE_ROUTING_CIRCULATION_PORT" exists in sai.profile
    elif any(spc4_platform in platform for spc4_platform in ["sn5600", "sn5610"]):
        hwsku = duthost.facts["hwsku"]
        sai_profile = f"/usr/share/sonic/device/{platform}/{hwsku}/sai.profile"
        sai_profile_content = duthost.command(f"cat {sai_profile}")["stdout_lines"]

        if "SAI_ADAPTIVE_ROUTING_CIRCULATION_PORT" not in sai_profile_content:
            pytest.skip("Packet trimming is not supported")


@pytest.fixture(scope="module")
def test_params(duthost, mg_facts, dut_qos_maps_module, downstream_links, upstream_links):    # noqa F401
    """
    Prepare test parameters for packet trimming tests.

    Returns:
        dict: Dictionary containing test parameters needed for packet trimming tests
    """
    logger.info("Preparing test parameters for packet trimming tests")

    with allure.step("Get trimming test ports"):
        uplink_port, downlink_port = get_test_ports(upstream_links, downstream_links)
        uplink_port_name = list(uplink_port.keys())[0]
        downlink_port_name = list(downlink_port.keys())[0]
        dst_ipv4_addr, dst_ipv6_addr = get_interface_peer_addresses(mg_facts, uplink_port_name)
        logger.info(f"uplink_port: {uplink_port}, downlink_port: {downlink_port}, dst_ipv4_addr: {dst_ipv4_addr}, "
                    f"dst_ipv6_addr: {dst_ipv6_addr}")

    with allure.step("Get queue id for packet with dscp value 0"):
        # Get port QoS map for the downlink port
        port_qos_map = dut_qos_maps_module['port_qos_map']
        logger.info(f"Retrieving QoS maps for port: {downlink_port_name}")

        # Extract the DSCP to TC map name from the port QoS configuration
        dscp_to_tc_map_name = port_qos_map[downlink_port_name]['dscp_to_tc_map'].split('|')[-1].strip(']')
        logger.info(f"DSCP to TC map name: {dscp_to_tc_map_name}")

        # Extract the TC to Queue map name from the port QoS configuration
        tc_to_queue_map_name = port_qos_map[downlink_port_name]['tc_to_queue_map'].split('|')[-1].strip(']')
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

    test_param = {
        'dst_ipv4_addr': dst_ipv4_addr,
        'dst_ipv6_addr': dst_ipv6_addr,
        'block_queue': block_queue,
        'uplink_port': uplink_port_name,
        'uplink_port_ptf_id': uplink_port[uplink_port_name]['ptf_port_id'],
        'downlink_port': downlink_port_name,
        'downlink_port_ptf_id': downlink_port[downlink_port_name]['ptf_port_id']
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
    uplink_port_name = test_params['uplink_port']
    block_queue = test_params['block_queue']

    with allure.step("Backup configuration"):
        logger.info("Backup configuration before trimming test")
        duthost.shell("sudo config save -y /etc/sonic/config_db_before_trimming_test.json")

    # For Nvidia sn5600 and sn5610 platform, the service port will be used as packets trimming feature.
    # So need to check trimming capability and prepare service port before test tests.
    if "sn5600" in platform or "sn5610" in platform:
        with allure.step("Check trimming capability and prepare service port"):
            logger.info("Check trimming capability")
            check_trimming_capability(duthost)

            logger.info("Prepare service port")
            prepare_service_port(duthost, SERVICE_PORT)

    if is_mellanox_device(duthost):
        with allure.step("Disable packet aging"):
            configure_packet_aging(duthost, disabled=True)

    with allure.step("Configure buffer profile for blocked queue and trimmed queue"):
        set_buffer_profiles_for_block_and_trim_queues(duthost, uplink_port_name, block_queue)

    with allure.step("Create scheduler used for blocking egress queues"):
        create_blocking_scheduler(duthost)

    with allure.step("Configure counterpoll interval"):
        duthost.command(f"counterpoll queue interval {COUNTERPOLL_INTERVAL}")

    with allure.step("Clear ports and queue counters"):
        duthost.command("sonic-clear queuecounters")
        duthost.command("sonic-clear counters")

    yield

    with allure.step("Disable trimming in buffer profile"):
        configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "off")

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
def setup_srv6(duthost, request, rand_selected_dut, upstream_links, service_links):    # noqa F401
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
    shutdown_ports = []
    if len(upstream_links) >= 2:
        interfaces = list(upstream_links.keys())
        shutdown_ports.extend(interfaces[1:])

    # Service ports also act as SRv6 ECMP next hops, need to shut them down in SRv6 tests
    shutdown_ports.extend(service_links.keys())

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
