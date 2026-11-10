import random
import json
import time
import logging
import pytest
import ipaddress
import re
import shlex
from contextlib import contextmanager

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common import config_reload
from tests.conftest import get_specified_duts, get_tbinfo, get_testbed_metadata
from tests.common.vxlan_ecmp_utils import Ecmp_Utils as VxLAN_Ecmp_Utils
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports  # noqa:F401
from tests.common.dualtor.constants import UPPER_TOR
from tests.common.helpers.sonic_db import redis_cli_command

SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
DST_IP_RANGE = ['9.0.0.0', '9.255.255.255']
SRC_IPV6_RANGE = ['20D0:A800:0:00::', '20D0:FFFF:0:00::FFFF']
DST_IPV6_RANGE = ['20D0:A800:0:01::', '20D0:FFFF:0:01::FFFF']
IP_RANGE = {'ipv4': {'src': SRC_IP_RANGE, 'dst': DST_IP_RANGE},
            'ipv6': {'src': SRC_IPV6_RANGE, 'dst': DST_IPV6_RANGE},
            'None': {'src': [], 'dst': []}}
PTF_QLEN = 20000
VLAN_RANGE = [1032, 1060]
ETHERTYPE_RANGE = [0x0801, 0x0900]
ENCAPSULATION = ['ipinip', 'vxlan', 'nvgre']
MELLANOX_SUPPORTED_HASH_ALGORITHM = ['CRC', 'CRC_CCITT']
CISCO_SUPPORTED_HASH_ALGORITHM = ['CRC', 'CRC_CCITT']
VPP_SUPPORTED_HASH_ALGORITHM = ['CRC']
MARVELL_TERALYNX_HASH_ALGORITHM = ['CRC', 'XOR']
DEFAULT_SUPPORTED_HASH_ALGORITHM = ['CRC', 'CRC_CCITT', 'RANDOM', 'XOR']
VPP_SUPPORTED_REBOOT_TYPES = ['cold', 'reload']
DEFAULT_SUPPORTED_REBOOT_TYPES = ['cold', 'warm', 'fast', 'reload']

MELLANOX_ECMP_HASH_FIELDS = [
    'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT',
    'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_L4_SRC_PORT',
    'INNER_L4_DST_PORT', 'INNER_SRC_MAC', 'INNER_DST_MAC', 'IPV6_FLOW_LABEL'
]
MELLANOX_LAG_HASH_FIELDS = [
    'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT',
    'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_L4_SRC_PORT',
    'INNER_L4_DST_PORT', 'INNER_SRC_MAC', 'INNER_DST_MAC', 'IPV6_FLOW_LABEL'
]
CISCO_ECMP_HASH_FIELDS = [
    'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT'
]
CISCO_LAG_HASH_FIELDS = [
    'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT'
]
VPP_ECMP_HASH_FIELDS = [
    'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT'
]
VPP_LAG_HASH_FIELDS = [
    'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT'
]
MARVELL_TERALYNX_ECMP_HASH_FIELDS = [
    'SRC_IP', 'DST_IP', 'VLAN_ID', 'IP_PROTOCOL', 'ETHERTYPE', 'L4_SRC_PORT', 'L4_DST_PORT', 'SRC_MAC',
    'DST_MAC', 'IN_PORT'
]
MARVELL_TERALYNX_LAG_HASH_FIELDS = [
    'SRC_IP', 'DST_IP', 'VLAN_ID', 'IP_PROTOCOL', 'ETHERTYPE', 'L4_SRC_PORT', 'L4_DST_PORT', 'SRC_MAC',
    'DST_MAC', 'IN_PORT'
]
DEFAULT_ECMP_HASH_FIELDS = [
    'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT',
    'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_L4_SRC_PORT',
    'INNER_L4_DST_PORT', 'INNER_SRC_MAC', 'INNER_DST_MAC', 'IPV6_FLOW_LABEL'
]
DEFAULT_LAG_HASH_FIELDS = [
    'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT',
    'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_L4_SRC_PORT',
    'INNER_L4_DST_PORT', 'INNER_SRC_MAC', 'INNER_DST_MAC', 'IPV6_FLOW_LABEL'
]
HASH_CAPABILITIES = {'mellanox': {'ecmp': MELLANOX_ECMP_HASH_FIELDS,
                                  'lag': MELLANOX_LAG_HASH_FIELDS},
                     'default': {'ecmp': DEFAULT_ECMP_HASH_FIELDS,
                                 'lag': DEFAULT_LAG_HASH_FIELDS},
                     'cisco-8000': {'ecmp': CISCO_ECMP_HASH_FIELDS,
                                    'lag': CISCO_LAG_HASH_FIELDS},
                     'vpp': {'ecmp': VPP_ECMP_HASH_FIELDS,
                             'lag': VPP_LAG_HASH_FIELDS},
                     'marvell-teralynx': {'ecmp': MARVELL_TERALYNX_ECMP_HASH_FIELDS,
                                          'lag': MARVELL_TERALYNX_LAG_HASH_FIELDS}}

logger = logging.getLogger(__name__)
vlan_member_to_restore = {}
ip_interface_to_restore = []
l2_ports = set()
vlans_to_remove = []
interfaces_to_startup = []
base_balancing_test_times = 480
base_balancing_range = 0.3
balancing_range_in_port = 0.8
vxlan_ecmp_utils = VxLAN_Ecmp_Utils()
vxlan_port_list = [13330, 4789]
restore_vxlan = False


@pytest.fixture(scope="module")
def get_supported_hash_algorithms(request):
    asic_type = get_asic_type(request)
    if asic_type in 'mellanox':
        supported_hash_algorithm_list = MELLANOX_SUPPORTED_HASH_ALGORITHM[:]
    elif asic_type in 'cisco-8000':
        supported_hash_algorithm_list = CISCO_SUPPORTED_HASH_ALGORITHM[:]
    elif asic_type in 'vpp':
        supported_hash_algorithm_list = VPP_SUPPORTED_HASH_ALGORITHM[:]
    elif asic_type in 'marvell-teralynx':
        supported_hash_algorithm_list = MARVELL_TERALYNX_HASH_ALGORITHM[:]
    else:
        supported_hash_algorithm_list = DEFAULT_SUPPORTED_HASH_ALGORITHM[:]
    return supported_hash_algorithm_list


@pytest.fixture(scope="module", autouse=True)
def skip_vs_setups(rand_selected_dut):
    """ Fixture to skip the test on vs setups. """
    if rand_selected_dut.facts['asic_type'] in ["vs"]:
        pytest.skip("Generic hash test only runs on physical setups.")


@pytest.fixture(scope="function", autouse=True)
def skip_lag_tests_on_no_lag_topos(request, rand_selected_dut):
    if "lag" in request.node.name and \
            "PORTCHANNEL" not in rand_selected_dut.get_running_config_facts():
        pytest.skip("The topology doesn't have portchannels, skip the lag test cases.")


@pytest.fixture(scope="function", autouse=True)
def skip_tests_on_isolated_topos(request, tbinfo):
    if 'isolated' in tbinfo['topo']['name']:
        uplink_count = re.search(r'u(\d+)', tbinfo['topo']['name'])
        downlink_count = re.search(r'd(\d+)', tbinfo['topo']['name'])
        if uplink_count:
            uplink_count = int(uplink_count.group(1))
        else:
            pytest.skip("Isolated topologies with no uplinks is not supported by the test.")
        if downlink_count:
            downlink_count = int(downlink_count.group(1))
        else:
            pytest.skip("Isolated topologies with no downlinks is not supported by the test.")
        if uplink_count > 32 and "IP_PROTOCOL" in request.node.name:
            pytest.skip("IP_PROTOCOL hash field is not supported on topos with more than 32 uplinks.")
        if downlink_count / uplink_count < 2 and "IN_PORT" in request.node.name:
            pytest.skip("At least twice the number of downlinks compared"
                        " to uplinks is required for IN_PORT hash test.")


@pytest.fixture(scope="module")
def mg_facts(rand_selected_dut, tbinfo):
    """ Fixture to get the extended minigraph facts """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    return mg_facts


def running_config_matches(duthost, snapshot):
    command = (
        "import json, subprocess, sys; "
        "saved = json.load(open(sys.argv[1])); "
        "running = json.loads(subprocess.check_output(['sonic-cfggen', '-d', '--print-data'])); "
        "print(saved == running)"
    )
    result = duthost.shell(f"python3 -c {shlex.quote(command)} {shlex.quote(snapshot)}")['stdout'].strip()
    pytest_assert(result in ('True', 'False'), "Could not compare the hash test's running configuration.")
    return result == 'True'


def track_hash_interface(recovery, config, interface):
    if recovery is None:
        return
    recovery['interfaces'].add(interface)
    for portchannel, members in config.get('PORTCHANNEL_MEMBER', {}).items():
        if interface == portchannel or interface in members:
            recovery['interfaces'].add(portchannel)
            recovery['members'].update(
                (portchannel, member) for member in members if interface in (portchannel, member))


def check_hash_interfaces(duthost, recovery):
    for interface in sorted(recovery['interfaces']):
        if not duthost.is_interface_status_up(interface):
            logger.info("Hash test interface %s is not operationally up.", interface)
            return False
    for portchannel in sorted({portchannel for portchannel, _ in recovery['members']}):
        ports = duthost.get_port_channel_status(portchannel).get('ports', {})
        for pc, member in sorted(recovery['members']):
            if pc != portchannel:
                continue
            state = ports.get(member, {})
            if state.get('link', {}).get('up') is not True or state.get('runner', {}).get('selected') is not True:
                logger.info("Hash test member %s is not linked and selected in %s.", member, portchannel)
                return False
    return True


@contextmanager
def preserve_hash_config(duthost, loganalyzer=None, preserve_running=True):
    """Keep private, reboot-persistent snapshots of running and saved configuration."""
    initial_hash_config = get_global_hash_config(duthost)
    if not preserve_running:
        try:
            yield
        finally:
            restore_hash_config(duthost, initial_hash_config)
        return
    backup_dir = duthost.shell("mktemp -d /host/generic-hash.XXXXXX")['stdout'].strip()
    saved = shlex.quote(f"{backup_dir}/config_db.json")
    running = f"{backup_dir}/running.json"
    duthost.shell(f"cp -p /etc/sonic/config_db.json {saved} && "
                  f"sonic-cfggen -d --print-data > {shlex.quote(running)}")
    recovery = {'interfaces': set(), 'members': set(), 'failed': False}
    try:
        yield recovery
    except BaseException:
        recovery['failed'] = True
        raise
    finally:
        try:
            try:
                restore_hash_config(duthost, initial_hash_config)
            finally:
                # Deleting hash fields is unsupported by orchagent. Reload the original
                # running config to restore absent fields and failed operational recovery.
                needs_reload = not running_config_matches(duthost, running)
                if recovery['interfaces']:
                    needs_reload = needs_reload or recovery['failed'] or not wait_until(
                        30, 2, 0, check_hash_interfaces, duthost, recovery)
                if needs_reload:
                    duthost.shell(f"cp {shlex.quote(running)} /etc/sonic/config_db.json")
                    # Scope expected service-restart logs to recovery, not the test.
                    config_reload(duthost, safe_reload=True, check_intf_up_ports=True,
                                  ignore_loganalyzer=loganalyzer)
                    pytest_assert(running_config_matches(duthost, running),
                                  f"Hash test configuration was not restored; snapshots remain in {backup_dir}.")
                    if recovery['interfaces']:
                        pytest_assert(wait_until(120, 2, 0, check_hash_interfaces, duthost, recovery),
                                      f"Hash test interfaces/members were not restored; "
                                      f"snapshots remain in {backup_dir}.")
        finally:
            duthost.shell(f"cp -p {saved} /etc/sonic/config_db.json && "
                          f"cmp -s {saved} /etc/sonic/config_db.json")
        duthost.shell(f"rm {saved} {shlex.quote(running)} && rmdir {shlex.quote(backup_dir)}")
        logger.info("Restored the initial running configuration and exact saved config_db.json.")


def restore_hash_config(duthost, initial_hash_config):
    ecmp_fields, ecmp_algorithm, lag_fields, lag_algorithm = initial_hash_config
    if ecmp_fields:
        duthost.set_switch_hash_global('ecmp', ecmp_fields)
    if lag_fields:
        duthost.set_switch_hash_global('lag', lag_fields)
    if ecmp_algorithm and ecmp_algorithm != 'N/A':
        duthost.set_switch_hash_global_algorithm('ecmp', ecmp_algorithm)
    if lag_algorithm and lag_algorithm != 'N/A':
        duthost.set_switch_hash_global_algorithm('lag', lag_algorithm)


@pytest.fixture(scope='function', autouse=True)
def restore_init_hash_config(rand_selected_dut, loganalyzer, tbinfo, request):
    preserve_running = rand_selected_dut.facts['asic_type'] == 'vpp' and tbinfo['topo']['name'] == 't1-lag'
    if preserve_running:
        validate_vpp_hash_metadata(get_testbed_metadata(request), get_specified_duts(request))
        # Collection generates unselected functions too; validate only the executing reboot case.
        if 'reboot_type' in request.fixturenames:
            reboot_type = request.getfixturevalue('reboot_type')
            if reboot_type not in VPP_SUPPORTED_REBOOT_TYPES:
                pytest.fail(f"Invalid value of the '--reboot' option for VPP: {reboot_type!r}. "
                            f"Supported reboot types: {', '.join(VPP_SUPPORTED_REBOOT_TYPES)}.")
    with preserve_hash_config(rand_selected_dut, loganalyzer, preserve_running=preserve_running) as recovery:
        try:
            yield recovery
        finally:
            # Pytest reports call failures separately instead of throwing them into fixture generators.
            report = getattr(request.node, 'rep_call', None) if preserve_running else None
            if recovery is not None and report is not None and report.failed:
                recovery['failed'] = True


@pytest.fixture(scope='function')
def reload(rand_selected_dut, restore_init_hash_config):
    """ Fixture to do the config reload after the test. """
    yield
    config_reload(rand_selected_dut, safe_reload=True)


@pytest.fixture(scope='function')
def restore_configuration(rand_selected_dut):
    """ Fixture to restore the interface and vlan configurations after the L2 test.
        The configurations are restored from the global variables. """

    yield
    try:
        logger.info("Restore the interface and vlan configurations after the L2 test.")
        # Remove vlans
        for vlan in vlans_to_remove:
            for interface in l2_ports:
                rand_selected_dut.shell(f'config vlan member del {vlan} {interface}')
            rand_selected_dut.shell(f'config vlan del {vlan}')
        # Re-config ip interface
        for ip_interface in ip_interface_to_restore:
            formatted_ip_addr = format_ip_mask(f"{ip_interface['addr']}/{ip_interface['mask']}")
            rand_selected_dut.shell(f"config interface ip add {ip_interface['attachto']} {formatted_ip_addr.upper()}")
        # Re-config vlan interface
        if vlan_member_to_restore:
            rand_selected_dut.shell(f"config vlan member add {vlan_member_to_restore['vlan_id']} "
                                    f"{vlan_member_to_restore['interface']} --untagged")
    except Exception as err:
        config_reload(rand_selected_dut, safe_reload=True)
        logger.info("Exception occurred when restoring the configuration.")
        raise err
    finally:
        del ip_interface_to_restore[:]
        del vlans_to_remove[:]
        vlan_member_to_restore.clear()
        l2_ports.clear()


@pytest.fixture(scope='function')
def restore_interfaces(rand_selected_dut, restore_init_hash_config):
    """ Fixture to startup interfaces after the flap test in case the test fails and some
        interfaces are shutdown during the test. The interfaces to start are from a global variable """

    yield
    logger.info("Startup the interfaces which were shutdown during the test")
    if interfaces_to_startup:
        rand_selected_dut.no_shutdown_multiple(interfaces_to_startup)
    try:
        for interface in interfaces_to_startup:
            pytest_assert(wait_until(30, 5, 0, rand_selected_dut.check_intf_link_state, interface),
                          "Not all interfaces are restored to up after the flap test.")
    finally:
        del interfaces_to_startup[:]


@pytest.fixture(scope='function')
def restore_vxlan_port(rand_selected_dut):
    """ Fixture to restore the vxlan port to default 4789 """
    global restore_vxlan
    yield
    if restore_vxlan:
        vxlan_ecmp_utils.Constants['DEBUG'] = False
        vxlan_ecmp_utils.Constants['KEEP_TEMP_FILES'] = False
        vxlan_ecmp_utils.configure_vxlan_switch(rand_selected_dut, 4789, rand_selected_dut.facts['router_mac'])
        restore_vxlan = False


@pytest.fixture(scope='module')
def global_hash_capabilities(rand_selected_dut):
    """
    Get the generic hash capabilities.
    Args:
        rand_selected_dut (AnsibleHost): Device Under Test (DUT)
    Returns:
        ecmp_hash_fields: a list of supported ecmp hash fields
        lag_hash_fields: a list of supported lag hash fields
    """
    global_hash_capabilities = rand_selected_dut.get_switch_hash_capabilities()
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


def check_default_route_asic_db(duthost):
    """
    Check the default route exists in the asic db.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
    Returns:
        True if the default route and nexthop id exist in the asic db.
    """
    logger.info("Check if the default route exists in the asic db.")
    route_entry = duthost.shell(
        'sonic-db-cli -s ASIC_DB keys "*ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*0.0.0.0/0*"',
        module_ignore_errors=True)["stdout"]
    if not route_entry:
        return False
    route_entry_content = duthost.shell((redis_cli_command(duthost, 'ASIC_DB') + f" hgetall '{route_entry}'"))["stdout"]
    if "SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID" in route_entry_content:
        return True
    else:
        return False


def check_vpp_fib_paths(duthost, expected_path_count, destination='0.0.0.0/0'):
    """
    Check that the VPP FIB has programmed all expected paths for a given destination.
    Runs 'docker exec syncd vppctl show ip fib <destination>' and parses the
    'len:N' value from the path-list output line.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        expected_path_count: expected number of paths (i.e. len(expected_port_groups))
        destination: FIB destination prefix to check (default: '0.0.0.0/0')
    Returns:
        True if the number of paths matches expected_path_count.
    """
    logger.info("Check VPP FIB paths for %s, expecting %d paths.", destination, expected_path_count)
    output = duthost.shell('docker exec syncd vppctl show ip fib {}'.format(destination),
                           module_ignore_errors=True)["stdout"]
    # Parse "len:N" from the path-list line, e.g.:
    #   path-list:[430] locks:12738 flags:shared,popular, uPRF-list:346 len:8 itfs:[65, 66, ...]
    # Note: There is also a "len:0" on the default-route drop entry whose line contains "flags:drop".
    # We skip any line containing "flags:drop" and match the active path-list line only.
    for line in output.splitlines():
        if 'path-list:' in line and 'flags:drop' not in line:
            match = re.search(r'len:(\d+)', line)
            if match:
                actual_paths = int(match.group(1))
                logger.info("VPP FIB %s: expected %d paths, got %d paths.",
                            destination, expected_path_count, actual_paths)
                return actual_paths >= expected_path_count
    logger.warning("Could not parse path count from VPP FIB output: %s", output)
    return False


def check_vpp_nexthop_paths(duthost, tbinfo, expected_path_count, ip_version):
    """Check resolved forwarding paths, not the uRPF list, around a nexthop flap."""
    if duthost.facts['asic_type'] != 'vpp' or tbinfo['topo']['name'] != 't1-lag':
        return check_vpp_fib_paths(duthost, expected_path_count)
    pytest_assert(ip_version in ('ipv4', 'ipv6'), f"Unsupported VPP hash IP version: {ip_version}")
    cli, destination = ('ip6', '::/0') if ip_version == 'ipv6' else ('ip', '0.0.0.0/0')
    result = duthost.shell(f"docker exec syncd vppctl show {cli} fib {destination}", module_ignore_errors=True)
    if result['rc'] != 0:
        return False
    sections = result['stdout'].split('forwarding:')
    if len(sections) != 2:
        logger.info("Expected one VPP forwarding section for %s.", destination)
        return False
    buckets = re.findall(r'^\s+\[\d+(?:-\d+)?\]\s+\[@\d+\]: (.+)$', sections[1], re.MULTILINE)
    paths = [re.fullmatch(rf'{ip_version} via (\S+) ([^:\s]+):.*', bucket) for bucket in buckets]
    if not paths or not all(paths):
        logger.info("VPP %s has missing, unresolved or non-adjacency forwarding buckets: %s", destination, buckets)
        return False
    # VPP can replicate an adjacency across buckets; replicas are not additional nexthops.
    nexthops = {(path.group(1), path.group(2)) for path in paths}
    logger.info("VPP %s: expected %d resolved nexthops, got %d: %s",
                destination, expected_path_count, len(nexthops), sorted(nexthops))
    return len(nexthops) == expected_path_count


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
    for index, interface in enumerate(uplink_interfaces.keys()):
        expected_port_groups.append([])
        for port in uplink_interfaces[interface]:
            expected_port_groups[index].append(mg_facts['minigraph_ptf_indices'][port])
        expected_port_groups[index].sort()
    return sending_ports, expected_port_groups


def ignore_expected_vpp_link_churn(duthost, tbinfo, loganalyzer, interfaces):
    if not loganalyzer or duthost.facts['asic_type'] != 'vpp' or tbinfo['topo']['name'] != 't1-lag':
        return
    # The shared VS netlink listener sees Linux-CP TAP names outside its lane map.
    # Match only this known message for ports deliberately disrupted by this test.
    for interface in interfaces:
        loganalyzer[duthost.hostname].ignore_regex.append(
            rf".*syncd.*syncOnLinkMsg: skipping newlink for {re.escape(interface)}, name not found in map\]?$")
    logger.info("Expect VPP hostif link-churn messages only for disrupted ports: %s", interfaces)


def flap_interfaces(duthost, interfaces, portchannels=[], times=3, tbinfo=None, recovery=None):
    """
    Flap the specified interfaces. Assert when any of the interfaces is not up after the flapping.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        interfaces: a list of interfaces to be flapped
        portchannels: a list of portchannels which need to check the status after the flapping
        times: flap times, every interface will be shutdown/startup for the value number times
    """
    logger.info(f"Flap the interfaces {interfaces} for {times} times.")
    target = tbinfo and duthost.facts['asic_type'] == 'vpp' and tbinfo['topo']['name'] == 't1-lag'
    if target and recovery is None:
        recovery = {'interfaces': set(), 'members': set()}
    # Flap the interface
    for _ in range(times):
        for interface in interfaces:
            shutdown_interface(duthost, interface, tbinfo=tbinfo, recovery=recovery)
            startup_interface(duthost, interface)
    # Check the interfaces status are up
    for interface in interfaces:
        pytest_assert(wait_until(30, 2, 0, duthost.is_interface_status_up, interface),
                      f"The interface {interface} is not up after the flapping.")
    for portchannel in portchannels:
        pytest_assert(wait_until(30, 2, 0, duthost.is_interface_status_up, portchannel),
                      f"The portchannel {portchannel} is not up after the flapping.")
    if target:
        pytest_assert(wait_until(30, 2, 0, check_hash_interfaces, duthost, recovery),
                      "Disrupted interfaces/members are not up and selected after the flapping.")


def remove_add_portchannel_member(duthost, interface, portchannel, tbinfo=None, recovery=None):
    """
    Remove and then add the specified members. Assert when any of the interfaces is not up after the remove/add.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        interface: the member to be removed/added
        portchannel: the portchannel which the member belongs to
    """
    logger.info(f"Remove the member {interface} from the portchannel {portchannel}.")
    if tbinfo and duthost.facts['asic_type'] == 'vpp' and tbinfo['topo']['name'] == 't1-lag':
        config = duthost.get_running_config_facts()
        pytest_assert(
            interface in config.get('PORTCHANNEL_MEMBER', {}).get(portchannel, {}),
            f"{interface} is not initially a member of {portchannel}.")
        if recovery is None:
            recovery = {'interfaces': set(), 'members': set()}
        track_hash_interface(recovery, config, interface)
        try:
            duthost.shell(f"config portchannel member del {portchannel} {interface}")
        finally:
            members = duthost.get_running_config_facts().get('PORTCHANNEL_MEMBER', {}).get(portchannel, {})
            if interface not in members:
                logger.info(f"Add back {interface} to {portchannel}.")
                duthost.shell(f"config portchannel member add {portchannel} {interface}")
        pytest_assert(wait_until(30, 2, 0, check_hash_interfaces, duthost, recovery),
                      f"The member {interface} is not up and selected in {portchannel} after remove/add.")
    else:
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
        if interface in mg_facts['minigraph_portchannels']:
            # All uplink interfaces are portchannels, need to find the members
            portchannel_members = mg_facts['minigraph_portchannels'][interface]['members']
            uplink_interfaces[interface].extend(portchannel_members)
        else:
            uplink_interfaces[interface].append(interface)
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
    downlink_interfaces = [interface for interface in downlink_interfaces if interface not in uplink_interfaces]
    if hash_field != 'IN_PORT':
        downlink_interfaces = [random.choice(downlink_interfaces)]
    logger.info(
        f"Interfaces are selected for the test: downlink: {downlink_interfaces}, uplink: {uplink_interfaces}")

    return uplink_interfaces, downlink_interfaces


def get_updated_balancing_test_times_and_range(uplink_interfaces):
    """
    Update the balancing test times and range based on the number of uplink interfaces.
    When the number of egress ports gets larger, the variations in some of the fields
    may be not enough to get a perfect balancing result.
    For example the IP_PROTOCOL field has only 256 values and VLAN_ID field has only 4096 values.
    So we relax the threshold based on the number of egress ports.
    Args:
        uplink_interfaces: a dictionary of the uplink interfaces
    Returns:
        the new balancing test times and range
    """
    uplink_physicalport_count = sum(len(members) for members in uplink_interfaces.values())
    balancing_test_times = base_balancing_test_times
    balancing_range = base_balancing_range
    if uplink_physicalport_count >= 32 and uplink_physicalport_count < 64:
        balancing_test_times = int(base_balancing_test_times * 0.75)
        balancing_range = round(balancing_range + 0.05, 2)
    elif uplink_physicalport_count >= 64 and uplink_physicalport_count < 128:
        balancing_test_times = int(base_balancing_test_times * 0.5)
        balancing_range = round(balancing_range + 0.1, 2)
    elif uplink_physicalport_count >= 128:
        balancing_test_times = int(base_balancing_test_times * 0.25)
        balancing_range = round(balancing_range + 0.15, 2)
    return balancing_test_times, balancing_range


def validate_vpp_hash_metadata(metadata, duts):
    if not metadata or not duts or any(
            not metadata.get(dut, {}).get('asic_type') for dut in duts):
        pytest.fail("Missing ASIC metadata for the selected DUTs. Run "
                    "test_pretest.py::test_update_testbed_metadata before running VPP t1-lag hash tests.")
    asic_types = {metadata[dut]['asic_type'] for dut in duts}
    if asic_types != {'vpp'}:
        pytest.fail(f"VPP t1-lag hash tests require vpp metadata for selected DUTs, got {sorted(asic_types)}. "
                    "Run test_pretest.py::test_update_testbed_metadata to refresh the metadata.")


def get_asic_type(request):
    metadata = get_testbed_metadata(request)
    if metadata is None:
        logger.warning("Failed to get asic type, "
                       "need to run test_update_testbed_metadata in test_pretest.py to collect dut asic type .")
        logger.warning("Using the default hash capabilities for asic type is unknown.")
        asic_type = 'unknown'
    else:
        _, tbinfo = get_tbinfo(request)
        if tbinfo['topo']['name'] == 't1-lag':
            duts = get_specified_duts(request)
            if any(metadata.get(dut, {}).get('asic_type') == 'vpp' for dut in duts):
                validate_vpp_hash_metadata(metadata, duts)
                return 'vpp'
        # Preserve legacy collection outside known VPP t1-lag; do not query a DUT here.
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
    elif asic_type in 'cisco-8000':
        supported_hash_algorithm_list = CISCO_SUPPORTED_HASH_ALGORITHM[:]
    elif asic_type in 'vpp':
        supported_hash_algorithm_list = VPP_SUPPORTED_HASH_ALGORITHM[:]
    elif asic_type in 'marvell-teralynx':
        supported_hash_algorithm_list = MARVELL_TERALYNX_HASH_ALGORITHM[:]
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
    :return: another supported algorithm, or the same one if only one is supported
    """
    supported_hash_algorithm_list = get_supported_hash_algorithms[:]
    if supported_algorithm in supported_hash_algorithm_list:
        temp_hash_algo_list = supported_hash_algorithm_list
        temp_hash_algo_list.remove(supported_algorithm)
        if not temp_hash_algo_list:
            return supported_algorithm
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


def get_reboot_type_from_option(request, reboot_option):
    """
    Generate the reboot type to test based on the pytest option.
    Args:
        request: pytest metafunc or request object for getting asic type
        reboot_option: the pytest option value of --reboot
    Returns:
        the list of reboot types
    """
    asic_type = get_asic_type(request)
    if asic_type == 'vpp':
        supported_reboot_types = VPP_SUPPORTED_REBOOT_TYPES
    else:
        supported_reboot_types = DEFAULT_SUPPORTED_REBOOT_TYPES

    if reboot_option == 'all':
        return supported_reboot_types[:]
    elif reboot_option == 'random':
        return [random.choice(supported_reboot_types)]
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


def format_ip_mask(ip_network, strict=False):
    """
    Format the full mask notation to the mask in dotted decimal notation
    """
    ip_addr = ipaddress.ip_network(ip_network, strict=strict)
    if ip_addr.version == 4:
        return str(ip_addr)
    else:
        return ip_network


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
                formatted_ip_addr = format_ip_mask(f"{ip_interface['addr']}/{ip_interface['mask']}")
                duthost.shell(f"config interface ip remove {ip_interface['attachto']} {formatted_ip_addr.upper()}")
                ip_interface_to_restore.append(ip_interface)
                l2_ports.add(downlink_interface)
        for portchannel in mg_facts['minigraph_portchannels'].values():
            if downlink_interface in portchannel['members']:
                for portchannel_ip_interface in mg_facts['minigraph_portchannel_interfaces']:
                    if portchannel_ip_interface['attachto'] == portchannel['name']:
                        formatted_ip_addr = format_ip_mask(
                            f"{portchannel_ip_interface['addr']}/{portchannel_ip_interface['mask']}")
                        duthost.shell(
                            f"config interface ip remove {portchannel_ip_interface['attachto']} "
                            f"{formatted_ip_addr.upper()}")
                        ip_interface_to_restore.append(portchannel_ip_interface)
                        l2_ports.add(portchannel_ip_interface['attachto'])
    # re-config the uplink interfaces, remove the ip address on the egress portchannel interfaces
    for ip_interface in mg_facts['minigraph_portchannel_interfaces']:
        if ip_interface['attachto'] in uplink_interfaces:
            formatted_ip_addr = format_ip_mask(f"{ip_interface['addr']}/{ip_interface['mask']}")
            duthost.shell(f"config interface ip remove {ip_interface['attachto']} {formatted_ip_addr.upper()}")
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


def shutdown_interface(duthost, interface, tbinfo=None, recovery=None):
    """
    Shutdown interface and add it to the global variable.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        interface: interface to shutdown
    """
    if tbinfo and duthost.facts['asic_type'] == 'vpp' and tbinfo['topo']['name'] == 't1-lag':
        config = duthost.get_running_config_facts()
        table = 'PORTCHANNEL' if interface.startswith('PortChannel') else 'PORT'
        pytest_assert(config.get(table, {}).get(interface, {}).get('admin_status') == 'up',
                      f"Refusing to flap initially administratively down interface {interface}.")
        track_hash_interface(recovery, config, interface)
        if interface not in interfaces_to_startup:
            interfaces_to_startup.append(interface)
        duthost.shutdown(interface)
    else:
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


def get_hash_balance_expectations(asic_type, topology, hash_field, ecmp_hash, lag_hash):
    if asic_type == 'vpp' and topology == 't1-lag' and hash_field == 'IP_PROTOCOL' and lag_hash:
        pytest_assert(ecmp_hash, "VPP does not support LAG balancing with IP_PROTOCOL alone.")
        logger.info("VPP IP_PROTOCOL: validate ECMP balance and exactly one receiving member per LAG, "
                    "not LAG balance. SAI advertises one shared field list for both operations.")
        return True, False
    return ecmp_hash, lag_hash


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
    ecmp_hash, lag_hash = get_hash_balance_expectations(
        duthost.facts['asic_type'], tbinfo['topo']['name'], hash_field, ecmp_hash, lag_hash)
    src_ip_range, dst_ip_range, inner_src_ip_range, inner_dst_ip_range = get_ip_range(ipver, inner_ipver)
    # Get the ptf src and dst ports
    ptf_sending_ports, ptf_expected_port_groups = get_ptf_port_indices(
        mg_facts, downlink_interfaces=downlink_interfaces, uplink_interfaces=uplink_interfaces)
    if 'dualtor' in tbinfo['topo']['name']:
        dest_mac = get_vlan_intf_mac(duthost)
    else:
        dest_mac = duthost.facts['router_mac']
    # Update the balancing_test_times and balancing_range based on the number of uplink interfaces
    # The test will run too long time if the balancing_test_times is big when
    # the number of uplink interfaces is large
    # Meanwhile relax the balancing_range to make sure the test is still stable.
    balancing_test_times, balancing_range = get_updated_balancing_test_times_and_range(uplink_interfaces)
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
    if duthost.facts['asic_type'] == 'vpp' and tbinfo['topo']['name'] == 't1-lag' and hash_field == 'IP_PROTOCOL':
        ptf_params['protocol_domain_validation'] = True
    if (duthost.facts['asic_type'] == 'vpp' and tbinfo['topo']['name'] == 't1-lag'
            and hash_field in ('SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT') and ecmp_hash and lag_hash):
        ptf_params['require_all_expected_ports'] = True
    if "INNER" in hash_field:
        ptf_params['inner_ipver'] = inner_ipver
        ptf_params['inner_src_ip_range'] = ",".join(inner_src_ip_range)
        ptf_params['inner_dst_ip_range'] = ",".join(inner_dst_ip_range)
        ptf_params['encap_type'] = encap_type
        if encap_type == 'vxlan':
            ptf_params['vxlan_port'] = random.choice(vxlan_port_list)
    if hash_field == "IN_PORT" and duthost.facts['asic_type'] == "mellanox":
        ptf_params['balancing_range'] = balancing_range_in_port
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
