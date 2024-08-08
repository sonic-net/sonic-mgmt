import random
import json
import time
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common import config_reload
from tests.conftest import get_testbed_metadata
from tests.vxlan.vxlan_ecmp_utils import Ecmp_Utils as VxLAN_Ecmp_Utils
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports  # noqa:F401
from tests.common.dualtor.constants import UPPER_TOR

SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
DST_IP_RANGE = ['9.0.0.0', '9.255.255.255']
SRC_IPV6_RANGE = ['20D0:A800:0:00::', '20D0:FFFF:0:00::FFFF']
DST_IPV6_RANGE = ['20D0:A800:0:01::', '20D0:FFFF:0:01::FFFF']
IP_RANGE = {'ipv4': {'src': SRC_IP_RANGE, 'dst': DST_IP_RANGE},
            'ipv6': {'src': SRC_IPV6_RANGE, 'dst': DST_IPV6_RANGE},
            'None': {'src': [], 'dst': []}}
PTF_QLEN = 20000
VLAN_RANGE = [1032, 1060]
ETHERTYPE_RANGE = [0x0800, 0x0900]
ENCAPSULATION = ['ipinip', 'vxlan', 'nvgre']
MELLANOX_SUPPORTED_HASH_ALGORITHM = ['CRC', 'CRC_CCITT']
DEFAULT_SUPPORTED_HASH_ALGORITHM = ['CRC', 'CRC_CCITT', 'RANDOM', 'XOR']

MELLANOX_ECMP_HASH_FIELDS = [
    'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT',
    'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_L4_SRC_PORT',
    'INNER_L4_DST_PORT', 'INNER_SRC_MAC', 'INNER_DST_MAC'
]
MELLANOX_LAG_HASH_FIELDS = [
    'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT',
    'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_L4_SRC_PORT',
    'INNER_L4_DST_PORT', 'INNER_SRC_MAC', 'INNER_DST_MAC'
]
DEFAULT_ECMP_HASH_FIELDS = [
    'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT',
    'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_L4_SRC_PORT',
    'INNER_L4_DST_PORT', 'INNER_SRC_MAC', 'INNER_DST_MAC'
]
DEFAULT_LAG_HASH_FIELDS = [
    'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT',
    'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_L4_SRC_PORT',
    'INNER_L4_DST_PORT', 'INNER_SRC_MAC', 'INNER_DST_MAC'
]
HASH_CAPABILITIES = {'mellanox': {'ecmp': MELLANOX_ECMP_HASH_FIELDS,
                                  'lag': MELLANOX_LAG_HASH_FIELDS},
                     'default': {'ecmp': DEFAULT_ECMP_HASH_FIELDS,
                                 'lag': DEFAULT_LAG_HASH_FIELDS}}

logger = logging.getLogger(__name__)
vlan_member_to_restore = {}
ip_interface_to_restore = []
l2_ports = set()
vlans_to_remove = []
interfaces_to_startup = []
balancing_test_times = 240
balancing_range = 0.25
vxlan_ecmp_utils = VxLAN_Ecmp_Utils()
vxlan_port_list = [13330, 4789]
restore_vxlan = False


@pytest.fixture(scope="module")
def get_supported_hash_algorithms(request):
    asic_type = get_asic_type(request)
    if asic_type in 'mellanox':
        supported_hash_algorithm_list = MELLANOX_SUPPORTED_HASH_ALGORITHM[:]
    else:
        supported_hash_algorithm_list = DEFAULT_SUPPORTED_HASH_ALGORITHM[:]
    return supported_hash_algorithm_list


@pytest.fixture(scope="module", autouse=True)
def skip_vs_setups(duthost):
    """ Fixture to skip the test on vs setups. """
    if duthost.facts['asic_type'] in ["vs"]:
        pytest.skip("Generic hash test only runs on physical setups.")


@pytest.fixture(scope="module")
def mg_facts(duthost, tbinfo):
    """ Fixture to get the extended minigraph facts """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    return mg_facts


@pytest.fixture(scope='function', autouse=True)
def restore_init_hash_config(duthost):
    """ Fixture to restore the initial generic hash configurations after the test. """
    logger.info("Store the initial generic hash configurations")
    init_ecmp_hash_fields, init_ecmp_hash_algo, init_lag_hash_fields, init_lag_hash_algo = \
        get_global_hash_config(duthost)
    yield
    if init_ecmp_hash_fields:
        duthost.set_switch_hash_global('ecmp', init_ecmp_hash_fields)
    if init_lag_hash_fields:
        duthost.set_switch_hash_global('lag', init_lag_hash_fields)
    if init_ecmp_hash_algo and init_ecmp_hash_algo != 'N/A':
        duthost.set_switch_hash_global_algorithm('ecmp', init_ecmp_hash_algo)
    if init_lag_hash_algo and init_lag_hash_algo != 'N/A':
        duthost.set_switch_hash_global_algorithm('lag', init_lag_hash_algo)
    logger.info("The initial generic hash configurations have been restored.")


@pytest.fixture(scope='function')
def reload(duthost):
    """ Fixture to do the config reload after the test. """
    yield
    config_reload(duthost, safe_reload=True)


@pytest.fixture(scope='function')
def restore_configuration(duthost):
    """ Fixture to restore the interface and vlan configurations after the L2 test.
        The configurations are restored from the global variables. """

    yield
    try:
        logger.info("Restore the interface and vlan configurations after the L2 test.")
        # Remove vlans
        for vlan in vlans_to_remove:
            for interface in l2_ports:
                duthost.shell(f'config vlan member del {vlan} {interface}')
            duthost.shell(f'config vlan del {vlan}')
        # Re-config ip interface
        for ip_interface in ip_interface_to_restore:
            duthost.shell(f"config interface ip add {ip_interface['attachto']} "
                          f"{ip_interface['addr']}/{ip_interface['mask']}")
        # Re-config vlan interface
        if vlan_member_to_restore:
            duthost.shell(f"config vlan member add {vlan_member_to_restore['vlan_id']} "
                          f"{vlan_member_to_restore['interface']} --untagged")
    except Exception as err:
        config_reload(duthost, safe_reload=True)
        logger.info("Exception occurred when restoring the configuration.")
        raise err
    finally:
        del ip_interface_to_restore[:]
        del vlans_to_remove[:]
        vlan_member_to_restore.clear()
        l2_ports.clear()


@pytest.fixture(scope='function')
def restore_interfaces(duthost):
    """ Fixture to startup interfaces after the flap test in case the test fails and some
        interfaces are shutdown during the test. The interfaces to start are from a global variable """

    yield
    logger.info("Startup the interfaces which were shutdown during the test")
    if interfaces_to_startup:
        duthost.no_shutdown_multiple(interfaces_to_startup)
    try:
        for interface in interfaces_to_startup:
            pytest_assert(wait_until(30, 5, 0, duthost.check_intf_link_state, interface),
                          "Not all interfaces are restored to up after the flap test.")
    finally:
        del interfaces_to_startup[:]


@pytest.fixture(scope='function')
def restore_vxlan_port(duthost):
    """ Fixture to restore the vxlan port to default 4789 """
    global restore_vxlan
    yield
    if restore_vxlan:
        vxlan_ecmp_utils.Constants['DEBUG'] = False
        vxlan_ecmp_utils.Constants['KEEP_TEMP_FILES'] = False
        vxlan_ecmp_utils.configure_vxlan_switch(duthost, 4789, duthost.facts['router_mac'])
        restore_vxlan = False


@pytest.fixture(scope='module')
def global_hash_capabilities(duthost):
    """
    Get the generic hash capabilities.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
    Returns:
        ecmp_hash_fields: a list of supported ecmp hash fields
        lag_hash_fields: a list of supported lag hash fields
    """
    global_hash_capabilities = duthost.get_switch_hash_capabilities()
    return {'ecmp': global_hash_capabilities['ecmp'], 'ecmp_algo': global_hash_capabilities['ecmp_algo'],
            'lag': global_hash_capabilities['lag'], 'lag_algo': global_hash_capabilities['lag_algo']}


@pytest.fixture()
def toggle_all_simulator_ports_to_upper_tor(toggle_all_simulator_ports):  # noqa:F811
    """ Fixture to toggle all ports to upper tor """
    toggle_all_simulator_ports(UPPER_TOR)


def get_global_hash_config(duthost):
    """
    Get the generic hash configurations.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
    Returns:
        ecmp_hash_fields: a list of currently configured ecmp hash fields
        lag_hash_fields: a list of currently configured lag hash fields
    """
    logger.info("Get current generic hash configurations.")
    global_hash_config = duthost.get_switch_hash_configurations()
    ecmp_hash_fields = global_hash_config['ecmp']
    lag_hash_fields = global_hash_config['lag']
    ecmp_hash_algo = global_hash_config['ecmp_algo']
    lag_hash_algo = global_hash_config['lag_algo']
    return ecmp_hash_fields, ecmp_hash_algo, lag_hash_fields, lag_hash_algo


def check_global_hash_config(duthost, ecmp_hash_fields, lag_hash_fields):
    """
    Validate if the current generic hash configurations are as expected. Assert when validation fails.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ecmp_hash_fields: a list of expected ecmp hash fields
        lag_hash_fields: a list of expected lag hash fields
    """
    ecmp_hash_fields_fact, _, lag_hash_fields_fact, _ = get_global_hash_config(duthost)
    ecmp_hash_matched = set(ecmp_hash_fields) == set(ecmp_hash_fields_fact)
    lag_hash_matched = set(lag_hash_fields) == set(lag_hash_fields_fact)
    pytest_assert(ecmp_hash_matched == lag_hash_matched is True,
                  'The global hash configuration is not as expected:\n'
                  f'expected ecmp hash fields: {ecmp_hash_fields}\n'
                  f'actual ecmp hash fields: {ecmp_hash_fields_fact}\n'
                  f'expected lag hash fields: {lag_hash_fields}\n'
                  f'actual lag hash fields: {lag_hash_fields_fact}')


def check_global_hash_algorithm(duthost, ecmp_hash_algo=None, lag_hash_algo=None):
    """
    Validate if the current generic hash algorithm configurations are as expected. Assert when validation fails.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ecmp_hash_algo: ecmp hash algorithm
        lag_hash_algo: lag hash algorithm
    """
    _, ecmp_hash_algorithm, _, lag_hash_algorithm = get_global_hash_config(duthost)
    if ecmp_hash_algo:
        pytest_assert(ecmp_hash_algo == ecmp_hash_algorithm,
                      'The global hash algorithm configuration is not as expected:\n'
                      f'expected ecmp hash algorithm: {ecmp_hash_algo}\n'
                      f'actual ecmp hash algorithm: {ecmp_hash_algorithm}\n')
    if lag_hash_algo:
        pytest_assert(lag_hash_algo == lag_hash_algorithm,
                      'The global hash algorithm configuration is not as expected:\n'
                      f'expected lag hash algorithm: {lag_hash_algo}\n'
                      f'actual lag hash algorithm: {lag_hash_algorithm}\n')


def get_ip_route_nexthops(duthost, destination):
    """
    Get nexthop interfaces for a specific destination
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        destination: get the nexthops of this route
    Returns:
        The nexthop interfaces
    """
    output = duthost.shell(f'show ip route {destination} json')['stdout']
    ip_route_json = json.loads(output)
    nexthop_list = []
    for route in ip_route_json[destination]:
        nexthop_list.extend(route["nexthops"])
    nexthops = []
    for nexthop in nexthop_list:
        nexthops.append(nexthop["interfaceName"])
    return nexthops


def check_default_route(duthost, expected_nexthops):
    """
    Check the default route exists and the nexthops interfaces are as expected.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        expected_nexthops: expected nexthop interfaces
    Returns:
        True if the nexthops are the same as the expected.
    """
    logger.info("Check if the default route is available.")
    nexthops = get_ip_route_nexthops(duthost, "0.0.0.0/0")
    return set(nexthops) == set(expected_nexthops)


def get_ptf_port_indices(mg_facts, downlink_interfaces, uplink_interfaces):
    """
    Get the ptf port indices for the interfaces under test.
    Args:
        mg_facts: minigraph facts
        downlink_interfaces: a list of downlink interfaces on dut
        uplink_interfaces: a dictionary of uplink(egress) interfaces on dut
    Returns:
        sending_ports: a list of the ptf port indices which will be used to send the test traffic example: [57]
        expected_port_groups: a list of the ptf port indices which will be used to received the test traffic,
                              the indices in a group means the ports are in a same portchannel
                              example: [[0, 2], [8, 10], [21, 22], [40, 41]]
    """
    sending_ports = []
    for interface in downlink_interfaces:
        sending_ports.append(mg_facts['minigraph_ptf_indices'][interface])
    expected_port_groups = []
    for index, portchannel in enumerate(uplink_interfaces.keys()):
        expected_port_groups.append([])
        for interface in uplink_interfaces[portchannel]:
            expected_port_groups[index].append(mg_facts['minigraph_ptf_indices'][interface])
        expected_port_groups[index].sort()
    return sending_ports, expected_port_groups


def flap_interfaces(duthost, interfaces, portchannels=[], times=3):
    """
    Flap the specified interfaces. Assert when any of the interfaces is not up after the flapping.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        interfaces: a list of interfaces to be flapped
        portchannels: a list of portchannels which need to check the status after the flapping
        times: flap times, every interface will be shutdown/startup for the value number times
    """
    logger.info(f"Flap the interfaces {interfaces} for {times} times.")
    # Flap the interface
    for _ in range(times):
        for interface in interfaces:
            shutdown_interface(duthost, interface)
            startup_interface(duthost, interface)
    # Check the interfaces status are up
    for interface in interfaces:
        pytest_assert(wait_until(30, 2, 0, duthost.is_interface_status_up, interface),
                      f"The interface {interface} is not up after the flapping.")
    for portchannel in portchannels:
        pytest_assert(wait_until(30, 2, 0, duthost.is_interface_status_up, portchannel),
                      f"The portchannel {portchannel} is not up after the flapping.")


def remove_add_portchannel_member(duthost, interface, portchannel):
    """
    Remove and then add the specified members. Assert when any of the interfaces is not up after the remove/add.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        interface: the member to be removed/added
        portchannel: the portchannel which the member belongs to
    """
    logger.info(f"Remove the member {interface} from the portchannel {portchannel}.")
    duthost.shell(f"config portchannel member del {portchannel} {interface}")
    logger.info(f"Add back {interface} to {portchannel}.")
    duthost.shell(f"config portchannel member add {portchannel} {interface}")
    # Check the portchannel is up
    pytest_assert(wait_until(30, 2, 0, duthost.is_interface_status_up, portchannel),
                  f"The portchannel {portchannel} is not up after the member remove/add.")


def get_ip_range(ipver, inner_ipver):
    """
    Generate the ip address range according to the ip versions.
    If the hash field is a inner field, generate both outer and inner versions.
    Args:
        ipver: outer frame ip version
        inner_ipver: inner frame ip version
    Returns:
        src_ip_range: outer source ip address range
        dst_ip_range: outer destination ip address range
        inner_src_ip_range: inner source ip address range
        inner_dst_ip_range: inner destination ip address range
    """
    src_ip_range = IP_RANGE[ipver]['src']
    dst_ip_range = IP_RANGE[ipver]['dst']
    inner_src_ip_range = IP_RANGE[inner_ipver]['src']
    inner_dst_ip_range = IP_RANGE[inner_ipver]['dst']
    return src_ip_range, dst_ip_range, inner_src_ip_range, inner_dst_ip_range


def get_interfaces_for_test(duthost, mg_facts, hash_field):
    """
    Get the interfaces used in the test according to the hash field.
    On t0 and t1 topologies, all uplink interfaces are portchannel interfaces.
    Down link interfaces could be ethernet interfaces or members of vlan interface or portchannel interfaces
    which differs with the topologies. Here we need the name of the ethernet interface.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        mg_facts: minigraph facts
        hash_field: the hash field under test
    Returns:
        uplink_interfaces: a dictionary of the uplink interfaces
            example: {'PortChannel101': ['Ethernet0', 'Ethernet2'],
                      'PortChannel102': ['Ethernet8', 'Ethernet10']}
        downlink_interfaces: a list of the downlink interfaces on the dut. If the hash field is not IN_PORT,
                            only one interface is randomly selected, otherwise all the downlinks are used.
            example: ['Ethernet48']
                     ['Ethernet2', 'Ethernet4', ..., 'Ethernet48'] for IN_PORT test
    """
    # Get uplink interfaces
    uplink_interfaces = {}
    # Find the uplink interfaces which are the nexthop interfaces of the default route
    for interface in get_ip_route_nexthops(duthost, "0.0.0.0/0"):
        uplink_interfaces[interface] = []
        # All uplink interfaces are portchannels, need to find the members
        portchannel_members = mg_facts['minigraph_portchannels'][interface]['members']
        uplink_interfaces[interface].extend(portchannel_members)
    # Randomly choose a downlink interface
    downlink_interfaces = []
    if mg_facts['minigraph_vlan_interfaces']:
        vlan_interface = mg_facts['minigraph_vlan_interfaces'][0]['attachto']
        downlink_interfaces = mg_facts['minigraph_vlans'][vlan_interface]['members']
    elif mg_facts['minigraph_interfaces']:
        for interface in mg_facts['minigraph_interfaces']:
            downlink_interfaces.append(interface['attachto'])
    else:
        portchannels = mg_facts['minigraph_portchannels']
        for portchannel in portchannels.keys():
            if portchannel not in uplink_interfaces.keys():
                downlink_interfaces.extend(portchannels[portchannel]['members'])
    if hash_field != 'IN_PORT':
        downlink_interfaces = [random.choice(downlink_interfaces)]
    logger.info(
        f"Interfaces are selected for the test: downlink: {downlink_interfaces}, uplink: {uplink_interfaces}")

    return uplink_interfaces, downlink_interfaces


def get_asic_type(request):
    metadata = get_testbed_metadata(request)
    if metadata is None:
        logger.warning("Failed to get asic type, "
                       "need to run test_update_testbed_metadata in test_pretest.py to collect dut asic type .")
        logger.warning("Using the default hash capabilities for asic type is unknown.")
        asic_type = 'unknown'
    else:
        # Always get the asic type from the first dut
        dut_info = metadata[list(metadata.keys())[0]]
        asic_type = dut_info.get('asic_type', "")
    return asic_type


def get_hash_fields_from_option(request, test_type, hash_field_option):
    """
    Generate the hash fields to test based on the pytest option.
    Args:
        request: pytest request
        test_type: indicates if it is a ecmp test or lag test. DST_MAC, ETHERTYPE, VLAN_ID are not suitable
                   for ecmp test because the traffic need to be L2
        hash_field_option: the value of pytest option "--hash_field"
    Returns:
        a list of the hash fields to test
    """
    asic_type = get_asic_type(request)
    if asic_type in HASH_CAPABILITIES:
        hash_fields = HASH_CAPABILITIES[asic_type][test_type]
    else:
        hash_fields = HASH_CAPABILITIES['default'][test_type]

    if hash_field_option == "all":
        return hash_fields
    elif hash_field_option == "random":
        return [random.choice(hash_fields)]
    elif hash_field_option in hash_fields:
        return [hash_field_option]
    elif set(hash_field_option.split(',')).issubset(hash_fields):
        return hash_field_option.split(',')
    else:
        pytest.fail("Invalid value of the '--hash_field' option.")


def get_hash_algorithm_from_option(request, hash_algorithm_identifier):
    """
    Generate the hash algorithm to test based on the pytest option.
    Args:
        hash_algorithm_identifier: the pytest option value of the --algorithm
    Returns:
        a list of the hash algorithm to test
    """
    asic_type = get_asic_type(request)
    if asic_type in 'mellanox':
        supported_hash_algorithm_list = MELLANOX_SUPPORTED_HASH_ALGORITHM[:]
    else:
        supported_hash_algorithm_list = DEFAULT_SUPPORTED_HASH_ALGORITHM[:]
    if hash_algorithm_identifier == 'all':
        return supported_hash_algorithm_list
    elif hash_algorithm_identifier == 'random':
        return [random.choice(supported_hash_algorithm_list)]
    elif hash_algorithm_identifier in supported_hash_algorithm_list:
        return [hash_algorithm_identifier]
    elif set(hash_algorithm_identifier.split(',')).issubset(set(supported_hash_algorithm_list)):
        return hash_algorithm_identifier.split(',')
    else:
        pytest.fail("Invalid value of the '--algorithm' option.")


def get_diff_hash_algorithm(supported_algorithm, get_supported_hash_algorithms):
    """
    Get a different supported hash algorithm
    :param supported_algorithm: current supported algorithm
    :return: another supported algorithm
    """
    supported_hash_algorithm_list = get_supported_hash_algorithms[:]
    if supported_algorithm in supported_hash_algorithm_list:
        temp_hash_algo_list = supported_hash_algorithm_list
        temp_hash_algo_list.remove(supported_algorithm)
        return random.choice(temp_hash_algo_list)
    else:
        return random.choice(supported_hash_algorithm_list)


def get_ip_version_from_option(ip_version_option):
    """
    Generate the ip version to test based on the pytest option.
    Args:
        ip_version_option: the pytest option value of the --ip_version or --inner_ip_version
    Returns:
        a list of the ip versions to test
    """
    if ip_version_option == 'all':
        return ['ipv4', 'ipv6']
    elif ip_version_option == 'random':
        return [random.choice(['ipv4', 'ipv6'])]
    else:
        return [ip_version_option]


def get_reboot_type_from_option(reboot_option):
    """
    Generate the reboot type to test based on the pytest option.
    Args:
        reboot_option: the pytest option value of --reboot
    Returns:
        the list of reboot types
    """
    if reboot_option == 'all':
        return ['cold', 'warm', 'fast', 'reload']
    elif reboot_option == 'random':
        return [random.choice(['cold', 'warm', 'fast', 'reload'])]
    else:
        return [reboot_option]


def get_encap_type_from_option(encap_type_option):
    """
    Generate the encapsulation type to test based on the pytest option.
    Args:
        encap_type_option: the pytest option value of --encap_type
    Returns:
        the encap type
    """
    if encap_type_option == 'random':
        return [random.choice(['ipinip', 'vxlan', 'nvgre'])]
    elif encap_type_option == 'all':
        return ['ipinip', 'vxlan', 'nvgre']
    else:
        return [encap_type_option]


def remove_ip_interface_and_config_vlan(duthost, mg_facts, tbinfo, downlink_interface, uplink_interfaces, hash_field):
    """
    Re-configure the interface and vlan on dut to enable switching of L2 traffic.
    Only for testing DST_MAC, ETHERTYPE, VLAN_ID fields.
    The changed configurations are stored in global variables for later restoration
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        mg_facts: minigraph facts
        tbinfo: testbed info
        downlink_interface: the downlink(ingress) interface under test
        uplink_interfaces: the uplink(egress) interfaces under test
        hash_field: the hash field to test
    """
    logger.info("Modify the interface and vlan configurations for L2 test.")
    # re-config the downlink interfaces
    # if topology is t0, move the downlink interfaces out of the VLAN
    if tbinfo['topo']['type'] == 't0':
        for vlan in mg_facts['minigraph_vlans'].keys():
            if downlink_interface in mg_facts['minigraph_vlans'][vlan]['members']:
                duthost.shell(f"config vlan member del {vlan.strip('Vlan')} {downlink_interface}")
                vlan_member_to_restore['vlan_id'] = vlan.strip('Vlan')
                vlan_member_to_restore['interface'] = downlink_interface
                l2_ports.add(downlink_interface)
    else:
        # if topology is t1, remove the ip address on downlink interface
        for ip_interface in mg_facts['minigraph_interfaces']:
            if ip_interface['attachto'] == downlink_interface:
                duthost.shell(f"config interface ip remove {ip_interface['attachto']} "
                              f"{ip_interface['addr']}/{ip_interface['mask']}")
                ip_interface_to_restore.append(ip_interface)
                l2_ports.add(downlink_interface)
        for portchannel in mg_facts['minigraph_portchannels'].values():
            if downlink_interface in portchannel['members']:
                for portchannel_ip_interface in mg_facts['minigraph_portchannel_interfaces']:
                    if portchannel_ip_interface['attachto'] == portchannel['name']:
                        duthost.shell(f"config interface ip remove {portchannel_ip_interface['attachto']} "
                                      f"{portchannel_ip_interface['addr']}/{portchannel_ip_interface['mask']}")
                        ip_interface_to_restore.append(portchannel_ip_interface)
                        l2_ports.add(portchannel_ip_interface['attachto'])
    # re-config the uplink interfaces, remove the ip address on the egress portchannel interfaces
    for ip_interface in mg_facts['minigraph_portchannel_interfaces']:
        if ip_interface['attachto'] in uplink_interfaces:
            duthost.shell(f"config interface ip remove {ip_interface['attachto']} "
                          f"{ip_interface['addr']}/{ip_interface['mask']}")
            ip_interface_to_restore.append(ip_interface)
            l2_ports.add(ip_interface['attachto'])
    # Configure VLANs for VLAN_ID test
    if hash_field == 'VLAN_ID':
        for vlan in range(VLAN_RANGE[0], VLAN_RANGE[1]):
            duthost.shell(f'config vlan add {vlan}')
            for port in l2_ports:
                duthost.shell(f'config vlan member add {vlan} {port}')
        vlans_to_remove.extend(list(range(VLAN_RANGE[0], VLAN_RANGE[1])))
    else:
        # Add the interfaces into one vlan for other hash fields
        duthost.shell(f'config vlan add {VLAN_RANGE[0]}')
        for port in l2_ports:
            duthost.shell(f'config vlan member add {VLAN_RANGE[0]} {port} --untagged')
        vlans_to_remove.append(VLAN_RANGE[0])
    # Wait 10 seconds for the configurations to take effect
    time.sleep(10)


def shutdown_interface(duthost, interface):
    """
    Shutdown interface and add it to the global variable.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        interface: interface to shutdown
    """
    duthost.shutdown(interface)
    interfaces_to_startup.append(interface)


def startup_interface(duthost, interface):
    """
    Startup interface and remove it from the global variable.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        interface: interface to startup
    """
    duthost.no_shutdown(interface)
    if interface in interfaces_to_startup:
        interfaces_to_startup.remove(interface)


def get_vlan_intf_mac(duthost):
    config_facts = duthost.get_running_config_facts()
    vlan_intfs = list(config_facts['VLAN_INTERFACE'])
    vlan_intf_mac = config_facts['VLAN'][vlan_intfs[0]]['mac']
    return vlan_intf_mac


def generate_test_params(duthost, tbinfo, mg_facts, hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
                         downlink_interfaces, ecmp_hash, lag_hash, is_l2_test=False):
    """
    Generate ptf test parameters.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        mg_facts: minigraph facts
        hash_field: hash field to test
        ipver: outer frame IP version
        inner_ipver: inner frame ip version
        uplink_interfaces: uplink interfaces of dut
        downlink_interfaces: downlink interfaces used in the test
        ecmp_hash: if ecmp hash is tested
        lag_hash: if lag hash is tested
        encap_type: the encapsulation type when testing inner fields
        is_l2_test: if L2 traffic is should be used in test
    """
    src_ip_range, dst_ip_range, inner_src_ip_range, inner_dst_ip_range = get_ip_range(ipver, inner_ipver)
    # Get the ptf src and dst ports
    ptf_sending_ports, ptf_expected_port_groups = get_ptf_port_indices(
        mg_facts, downlink_interfaces=downlink_interfaces, uplink_interfaces=uplink_interfaces)
    if 'dualtor' in tbinfo['topo']['name']:
        dest_mac = get_vlan_intf_mac(duthost)
    else:
        dest_mac = duthost.facts['router_mac']
    ptf_params = {"router_mac": dest_mac,
                  "sending_ports": ptf_sending_ports,
                  "expected_port_groups": ptf_expected_port_groups,
                  "hash_field": hash_field,
                  "vlan_range": VLAN_RANGE,
                  'ethertype_range': ETHERTYPE_RANGE,
                  "ipver": ipver,
                  "src_ip_range": ",".join(src_ip_range),
                  "dst_ip_range": ",".join(dst_ip_range),
                  "balancing_test_times": balancing_test_times,
                  "balancing_range": balancing_range,
                  "ecmp_hash": ecmp_hash,
                  "lag_hash": lag_hash,
                  "is_l2_test": is_l2_test}
    if "INNER" in hash_field:
        ptf_params['inner_ipver'] = inner_ipver
        ptf_params['inner_src_ip_range'] = ",".join(inner_src_ip_range)
        ptf_params['inner_dst_ip_range'] = ",".join(inner_dst_ip_range)
        ptf_params['encap_type'] = encap_type
        if encap_type == 'vxlan':
            ptf_params['vxlan_port'] = random.choice(vxlan_port_list)
    return ptf_params


def config_custom_vxlan_port(duthost, port):
    """
    Configure the custom VxLAN udp dport
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        port: the custom port number
    """
    global restore_vxlan
    logger.info(f"Configure VxLAN port to {port}")
    vxlan_ecmp_utils.Constants['DEBUG'] = False
    vxlan_ecmp_utils.Constants['KEEP_TEMP_FILES'] = False
    vxlan_ecmp_utils.configure_vxlan_switch(duthost, port, duthost.facts['router_mac'])
    restore_vxlan = True
