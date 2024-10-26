import re
import time
import logging

from datetime import datetime

import pytest

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses         # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa F401
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # noqa F401
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map_active_active, ptf_test_port_map
from tests.common.fixtures.ptfhost_utils import skip_traffic_test           # noqa F401

from tests.ptf_runner import ptf_runner
from tests.common.dualtor.mux_simulator_control import mux_server_url       # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_random_side            # noqa F401
from tests.common.dualtor.dual_tor_utils import config_active_active_dualtor_active_standby                 # noqa F401
from tests.common.dualtor.dual_tor_utils import validate_active_active_dualtor_setup                        # noqa F401
from tests.common.dualtor.dual_tor_common import active_active_ports                                        # noqa F401
from tests.common.utilities import is_ipv4_address

from tests.common.fixtures.fib_utils import single_fib_for_duts, get_fib_info, get_t2_fib_info, gen_fib_info_file             # noqa F401
from tests.common.utilities import wait
from tests.common.helpers.assertions import pytest_require

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# Usually src-mac, dst-mac, vlan-id are optional hash keys. Not all the platform supports these optional hash keys.
# Not enable these three by default.
# The 'ingress-port' key is not used in hash by design. We are doing negative test for 'ingress-port'.
# When 'ingress-port' is included in HASH_KEYS, the PTF test will try to inject same packet to different ingress ports
# and expect that they are forwarded from same egress port.
# HASH_KEYS = ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ingress-port', 'src-mac', 'dst-mac', 'ip-proto', 'vlan-id']
HASH_KEYS = ['src-ip', 'dst-ip', 'src-port',
             'dst-port', 'ingress-port', 'ip-proto']
SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
DST_IP_RANGE = ['9.0.0.0', '9.255.255.255']
SRC_IPV6_RANGE = ['20D0:A800:0:00::', '20D0:FFFF:0:00::FFFF']
DST_IPV6_RANGE = ['20D0:A800:0:01::', '20D0:FFFF:0:01::FFFF']
VLANIDS = list(range(1032, 1279))
VLANIP = '192.168.{}.1/24'
PTF_QLEN = 20000
DEFAULT_MUX_SERVER_PORT = 8080

PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'

# Helper Functions
def check_default_route_from_fib_info(ptfhost, file_path):
    """
    Check for the default route (0.0.0.0/0) in the FIB information file
    and return a list of next hop port indices.

    Args:
        ptfhost: The PTF host object.
        file_path: The path to the FIB info file.

    Returns:
        A list of next hop port indices or an empty list if not found.
    """

    # Attempt to read the FIB info file
    result = ptfhost.shell("cat {}".format(file_path))
    if result['rc'] != 0:
        logger.error("Failed to read file {} from PTF host.".format(file_path))
        return []

    lines = result['stdout_lines']

    # Find the line containing the default route
    default_route_line = next((line.strip() for line in lines if '0.0.0.0/0' in line), None)

    if not default_route_line:
        logger.info("No default route found. Returning an empty list.")
        return []  # Return an empty list if no default route is found

    # Count the number of next hops (each '[]' represents one nexthop)
    nexthops_count = len(re.findall(r'\[.*?\]', default_route_line))

    if nexthops_count <= 1:
        logger.info("Number of nexthops is less than or equal to 1. Returning an empty list.")
        return []  # Return empty list if only one or no nexthop

    # Extract all numbers inside square brackets and convert them to integers
    matches = re.findall(r'\[(\d+(?: \d+)*)\]', default_route_line)
    ports = [int(num) for group in matches for num in group.split()]

    return ports

def get_all_ptf_port_indices_from_mg_facts(mg_facts):
    """
    Retrieve all ptf port indices from the minigraph facts.

    Args:
        mg_facts: The minigraph facts containing ASIC information.

    Returns:
        A dictionary containing mapping of ptf port indices to dutport(asic_id, port_name).
    """

    all_port_indices = {}  # Dictionary to store (port_index, (asic_id, port_name))

    # Iterate over all ASICs in mg_facts
    for asic_id, asic_data in mg_facts:
        minigraph_indices = asic_data['minigraph_ptf_indices']

        # Store (port_index: (asic_id, port_name)) in the dictionary
        for port_name, port_index in minigraph_indices.items():
            all_port_indices[port_index] = (asic_id, port_name)

    return all_port_indices

def map_ptf_ports_to_dut_port(ptf_ports, all_dut_port_indices):
    """
    Map PTF port indices to DUT port information.

    Args:
        ptf_ports: List of PTF port indices.
        all_dut_port_indices: Dictionary of DUT port indices.

    Returns:
        A list of tuples containing (asic_id, port_name) for mapped ports.
    """

    ethernet_ports_with_asic = [
        (asic_id, port_name)
        for port in ptf_ports
        if (port_info := all_dut_port_indices.get(port))
        for asic_id, port_name in [port_info]
    ]

    return ethernet_ports_with_asic

def filter_ports(all_port_indices, tbinfo):
    """
    Filter PTF ports that need to be skipped while picking up src_port for ptf traffic test.

    Args:
        all_port_indices: Dictionary with available port indices.
                          Keys represent PTF ports; values are port numbers.
        tbinfo: Dictionary with testbed information, including topology type.

    Returns:
        A list of PTF ports to be skipped as src_port.
    """

    # Note: this filteration is useful for multilinecard DUTs to make sure incoming traffic is
    # landing on a different linecard; NA for pizza boxes

    if tbinfo['topo']['type'] != 't2':
        return []

    # Collect all port indices (keys) from all_port_indices
    host_ptf_ports_all = list(all_port_indices.keys())

    return host_ptf_ports_all



def fib_info_files_per_function(duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request):
    """Get FIB info from database and store to text files on PTF host.

    For T2 topology, generate a single file to /root/fib_info_all_duts.txt to PTF host.
    For other topologies, generate one file for each duthost. File name pattern:
        /root/fib_info_dut<dut_index>.txt

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.
        ptfhost (PTFHost): Instance of PTFHost for interacting with the PTF host.
        duts_running_config_facts (dict): Running config facts of all DUT hosts.
        duts_minigraph_facts (dict): Minigraph facts of all DUT hosts.
        tbinfo (object): Instance of TestbedInfo.

    Returns:
        list: List of FIB info file names on PTF host.
    """
    duts_config_facts = duts_running_config_facts
    testname = request.node.name
    files = []
    if tbinfo['topo']['type'] != "t2":
        for dut_index, duthost in enumerate(duthosts):
            fib_info = get_fib_info(
                duthost, duts_config_facts[duthost.hostname], duts_minigraph_facts[duthost.hostname], testname
            )
            if 'test_basic_fib' in testname and 'backend' in tbinfo['topo']['name']:
                # if it is a storage backend topology(bt0 or bt1) and testcase is test_basic_fib
                # add a default route as failover in the prefix matching
                fib_info['0.0.0.0/0'] = []
                fib_info['::/0'] = []
            filename = '/root/fib_info_dut_{0}_{1}.txt'.format(testname, dut_index)
            gen_fib_info_file(ptfhost, fib_info, filename)
            files.append(filename)
    else:
        fib_info = get_t2_fib_info(duthosts, duts_config_facts, duts_minigraph_facts, testname)
        filename = '/root/fib_info_all_duts.txt'
        gen_fib_info_file(ptfhost, fib_info, filename)
        files.append(filename)

    return files


@pytest.fixture(scope="module")
def ignore_ttl(duthosts):
    # on the multi asic devices, the packet can have different ttl based on how the packet is routed
    # within in the device. So set this flag to mask the ttl in the ptf test
    for duthost in duthosts:
        if duthost.sonichost.is_multi_asic:
            return True
    return False


@pytest.fixture(scope="module")
def updated_tbinfo(tbinfo):
    if tbinfo['topo']['name'] == 't0-56-po2vlan':
        # skip ifaces from PortChannel 201 iface
        ifaces_po_201 = tbinfo['topo']['properties']['topology']['DUT']['portchannel_config']['PortChannel201']['intfs']
        for iface in ifaces_po_201:
            ptf_map_iface_index = tbinfo['topo']['ptf_map']['0'][str(iface)]
            tbinfo['topo']['ptf_map_disabled']['0'].update(
                {str(iface): ptf_map_iface_index})
            tbinfo['topo']['properties']['topology']['disabled_host_interfaces'].append(
                iface)
    return tbinfo


@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, True, 1514)])
def test_basic_fib(duthosts, ptfhost, tbinfo, ipv4, ipv6, mtu,
                   toggle_all_simulator_ports_to_random_side,           # noqa F811
                   updated_tbinfo, mux_server_url,                      # noqa F401
                   mux_status_from_nic_simulator,
                   ignore_ttl, single_fib_for_duts,                     # noqa F401
                   duts_running_config_facts, duts_minigraph_facts,
                   validate_active_active_dualtor_setup,                # noqa F401
                   skip_traffic_test, request):                         # noqa F811

    if 'dualtor' in updated_tbinfo['topo']['name']:
        wait(30, 'Wait some time for mux active/standby state to be stable after toggled mux state')

    fib_files = fib_info_files_per_function(duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request)
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    switch_type = duthosts[0].facts.get('switch_type')

    # do not test load balancing for vs platform as kernel 4.9
    # can only do load balance base on L3
    asic_type = duthosts[0].facts['asic_type']
    if asic_type in ["vs"]:
        test_balancing = False
    else:
        test_balancing = True

    logging.info("run ptf test")
    log_file = "/tmp/fib_test.FibTest.ipv4.{}.ipv6.{}.{}.log".format(
        ipv4, ipv6, timestamp)
    logging.info("PTF log file: %s" % log_file)
    if skip_traffic_test is True:
        return
    ptf_runner(
        ptfhost,
        "ptftests",
        "fib_test.FibTest",
        platform_dir="ptftests",
        params={
            # Test at most 3 DUTs
            "fib_info_files": fib_files[:3],
            "ptf_test_port_map": ptf_test_port_map_active_active(
                ptfhost, updated_tbinfo, duthosts, mux_server_url,
                duts_running_config_facts, duts_minigraph_facts,
                mux_status_from_nic_simulator()
            ),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "testbed_mtu": mtu,
            "test_balancing": test_balancing,
            "ignore_ttl": ignore_ttl,
            "single_fib_for_duts": single_fib_for_duts,
            "switch_type": switch_type,
            "asic_type": asic_type
        },
        log_file=log_file,
        qlen=PTF_QLEN,
        socket_recv_size=16384,
        is_python3=True
    )


def get_vlan_untag_ports(duthosts, duts_running_config_facts):
    """Get vlan untagged ports.

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.
        duts_running_config_facts (dict): Running config facts of all DUT hosts.

    Returns:
        [type]: [description]
    """
    vlan_untag_ports = {}
    for duthost in duthosts:
        if duthost.is_multi_asic:
            continue
        ports = []
        for asic_cfg_facts in duts_running_config_facts[duthost.hostname]:

            vlans = list(asic_cfg_facts[1].get('VLAN_INTERFACE', {}).keys())
            for vlan in vlans:
                vlan_member_info = asic_cfg_facts[1].get(
                    'VLAN_MEMBER', {}).get(vlan, {})
                if vlan_member_info:
                    for port_name, tag_mode in list(vlan_member_info.items()):
                        if tag_mode['tagging_mode'] == 'untagged':
                            ports.append(port_name)
        vlan_untag_ports[duthost.hostname] = ports
    return vlan_untag_ports


@pytest.fixture(scope="module")
def hash_keys(duthost):
    # Copy from global var to avoid side effects of multiple iterations
    hash_keys = HASH_KEYS[:]
    if 'dst-mac' in hash_keys:
        hash_keys.remove('dst-mac')

    # do not test load balancing on L4 port on vs platform as kernel 4.9
    # can only do load balance base on L3
    if duthost.facts['asic_type'] in ["vs"]:
        if 'src-port' in hash_keys:
            hash_keys.remove('src-port')
        if 'dst-port' in hash_keys:
            hash_keys.remove('dst-port')
    if duthost.facts['asic_type'] in ["mellanox"]:
        if 'ip-proto' in hash_keys:
            hash_keys.remove('ip-proto')
    if duthost.facts['asic_type'] in ["barefoot"]:
        if 'ingress-port' in hash_keys:
            hash_keys.remove('ingress-port')
        if 'ip-proto' in hash_keys:
            hash_keys.remove('ip-proto')
    # removing ingress-port and ip-proto from hash_keys not supported by Marvell SAI
    if duthost.facts['platform'] in ['armhf-nokia_ixs7215_52x-r0']:
        if 'ip-proto' in hash_keys:
            hash_keys.remove('ip-proto')
        if 'ingress-port' in hash_keys:
            hash_keys.remove('ingress-port')
    if duthost.facts['asic_type'] in ["innovium", "cisco-8000"]:
        if 'ip-proto' in hash_keys:
            hash_keys.remove('ip-proto')
    # remove the ingress port from multi asic platform
    # In multi asic platform each asic has different hash seed,
    # the same packet coming in different asic
    # could egress out of different port
    # the hash_test condition for hash_key == ingress_port will fail
    if duthost.sonichost.is_multi_asic:
        hash_keys.remove('ingress-port')

    return hash_keys


def configure_vlan(duthost, ports):
    for vlan in VLANIDS:
        duthost.shell('config vlan add {}'.format(vlan))
        for port in ports:
            duthost.shell('config vlan member add {} {}'.format(vlan, port))
        duthost.shell('config interface ip add Vlan{} '.format(
            vlan) + VLANIP.format(vlan % 256))
    time.sleep(5)


def unconfigure_vlan(duthost, ports):
    for vlan in VLANIDS:
        for port in ports:
            duthost.shell('config vlan member del {} {}'.format(vlan, port))
        duthost.shell('config interface ip remove Vlan{} '.format(
            vlan) + VLANIP.format(vlan % 256))
        duthost.shell('config vlan del {}'.format(vlan))
    time.sleep(5)


@pytest.fixture
def setup_vlan(tbinfo, duthosts, duts_running_config_facts, hash_keys):

    vlan_untag_ports = get_vlan_untag_ports(
        duthosts, duts_running_config_facts)
    need_to_clean_vlan = False

    # add some vlan for hash_key vlan-id test
    if tbinfo['topo']['type'] == 't0' and 'dualtor' not in tbinfo['topo']['name'] and 'vlan-id' in hash_keys:
        for duthost in duthosts:
            configure_vlan(duthost, vlan_untag_ports[duthost.hostname])
        need_to_clean_vlan = True

    yield

    # remove added vlan
    if need_to_clean_vlan:
        for duthost in duthosts:
            unconfigure_vlan(duthost, vlan_untag_ports[duthost.hostname])


@pytest.fixture(params=["ipv4", "ipv6"])
def ipver(request):
    return request.param


@pytest.fixture(scope='module')
def add_default_route_to_dut(duts_running_config_facts, duthosts, tbinfo):
    """
    Add a default route to the device for storage backend testbed.
    This is to ensure the IO packets could be successfully directed.
    """
    if "backend" in tbinfo["topo"]["name"]:
        logging.info("Add default route on the DUT.")
        try:
            for duthost in duthosts:
                cfg_facts = duts_running_config_facts[duthost.hostname]
                for asic_cfg_facts_tuple in (cfg_facts):
                    asic_index, asic_cfg_facts = asic_cfg_facts_tuple
                    asic = duthost.asic_instance(asic_index)
                    bgp_neighbors = asic_cfg_facts["BGP_NEIGHBOR"]
                    ipv4_cmd_parts = ["ip route add default"]
                    ipv6_cmd_parts = ["ip -6 route add default"]
                    for neighbor in list(bgp_neighbors.keys()):
                        if is_ipv4_address(neighbor):
                            ipv4_cmd_parts.append("nexthop via %s" % neighbor)
                        else:
                            ipv6_cmd_parts.append("nexthop via %s" % neighbor)
                    ipv4_cmd_parts.sort()
                    ipv6_cmd_parts.sort()
                    # limit to 4 nexthop entries
                    ipv4_cmd = " ".join(ipv4_cmd_parts[:5])
                    ipv6_cmd = " ".join(ipv6_cmd_parts[:5])
                    asic.shell(ipv4_cmd)
                    asic.shell(ipv6_cmd)
            yield
        finally:
            logging.info("Remove default route on the DUT.")
            for duthost in duthosts:
                for asic in duthost.asics:
                    if asic.is_it_backend():
                        continue
                    asic.shell("ip route del default",
                               module_ignore_errors=True)
                    asic.shell("ip -6 route del default",
                               module_ignore_errors=True)
    else:
        yield


@pytest.fixture
def setup_active_active_ports(
    active_active_ports, rand_selected_dut, rand_unselected_dut,                        # noqa F811
    config_active_active_dualtor_active_standby, validate_active_active_dualtor_setup   # noqa F811
):
    if active_active_ports:
        # The traffic from active-active mux ports are ECMPed twice:first time on the NiC to
        # choose the ToR, second time on the ToR to choose the uplinks. The NiC ECMP is not
        # within the test scope, and we also cannot guarantee that the traffic is evenly
        # distributed among all the uplinks. So let's configure the active-active mux ports
        # to let them work in active-standby mode.
        logger.info("Configuring {} as active".format(rand_selected_dut.hostname))
        logger.info("Configuring {} as standby".format(rand_unselected_dut.hostname))
        config_active_active_dualtor_active_standby(rand_selected_dut, rand_unselected_dut, active_active_ports)

    return


def test_hash(add_default_route_to_dut, duthosts, tbinfo, setup_vlan,      # noqa F811
              hash_keys, ptfhost, ipver, toggle_all_simulator_ports_to_rand_selected_tor_m,     # noqa F811
              updated_tbinfo, mux_server_url, mux_status_from_nic_simulator, ignore_ttl,        # noqa F811
              single_fib_for_duts, duts_running_config_facts, duts_minigraph_facts,             # noqa F811
              setup_active_active_ports, active_active_ports, skip_traffic_test, request):      # noqa F811

    if 'dualtor' in updated_tbinfo['topo']['name']:
        wait(30, 'Wait some time for mux active/standby state to be stable after toggled mux state')

    fib_files = fib_info_files_per_function(duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request)

    is_active_active_dualtor = bool(active_active_ports)
    switch_type = duthosts[0].facts.get('switch_type')
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/hash_test.HashTest.{}.{}.log".format(ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)
    if ipver == "ipv4":
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE
    else:
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE
    if skip_traffic_test is True:
        return
    ptf_runner(
        ptfhost,
        "ptftests",
        "hash_test.HashTest",
        platform_dir="ptftests",
        params={
            "fib_info_files": fib_files[:3],   # Test at most 3 DUTs
            "ptf_test_port_map": ptf_test_port_map_active_active(
                ptfhost, updated_tbinfo, duthosts, mux_server_url,
                duts_running_config_facts, duts_minigraph_facts,
                mux_status_from_nic_simulator()
            ),
            "hash_keys": hash_keys,
            "src_ip_range": ",".join(src_ip_range),
            "dst_ip_range": ",".join(dst_ip_range),
            "vlan_ids": VLANIDS,
            "ignore_ttl": ignore_ttl,
            "single_fib_for_duts": single_fib_for_duts,
            "switch_type": switch_type,
            "is_active_active_dualtor": is_active_active_dualtor
        },
        log_file=log_file,
        qlen=PTF_QLEN,
        socket_recv_size=16384,
        is_python3=True
    )

# The test case is to verify src-ip, dst-ip, src-port, dst-port and ip-proto of inner_frame in a IPinIP packet are
# used as hash keys


def test_ipinip_hash(add_default_route_to_dut, duthost, duthosts,  # noqa F811
                     hash_keys, ptfhost, ipver, tbinfo, mux_server_url,             # noqa F811
                     ignore_ttl, single_fib_for_duts, duts_running_config_facts,    # noqa F811
                     duts_minigraph_facts, skip_traffic_test, request):                      # noqa F811
    # Skip test on none T1 testbed
    pytest_require('t1' == tbinfo['topo']['type'],
                   "The test case runs on T1 topology")

    fib_files = fib_info_files_per_function(duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request)

    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/hash_test.IPinIPHashTest.{}.{}.log".format(
        ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)
    if ipver == "ipv4":
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE
    else:
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE
    if skip_traffic_test is True:
        return
    ptf_runner(ptfhost,
               "ptftests",
               "hash_test.IPinIPHashTest",
               platform_dir="ptftests",
               params={"fib_info_files": fib_files[:3],   # Test at most 3 DUTs
                       "ptf_test_port_map": ptf_test_port_map(ptfhost, tbinfo, duthosts, mux_server_url,
                                                              duts_running_config_facts, duts_minigraph_facts),
                       "hash_keys": hash_keys,
                       "src_ip_range": ",".join(src_ip_range),
                       "dst_ip_range": ",".join(dst_ip_range),
                       "vlan_ids": VLANIDS,
                       "ignore_ttl": ignore_ttl,
                       "single_fib_for_duts": single_fib_for_duts,
                       "ipver": ipver
                       },
               log_file=log_file,
               qlen=PTF_QLEN,
               socket_recv_size=16384,
               is_python3=True)

# The test is to verify the hashing logic is not using unexpected field as keys
# Only inner frame length is tested at this moment


def test_ipinip_hash_negative(add_default_route_to_dut, duthosts,           # noqa F811
                              ptfhost, ipver, tbinfo, mux_server_url, ignore_ttl, single_fib_for_duts,  # noqa F811
                              duts_running_config_facts, duts_minigraph_facts, mux_status_from_nic_simulator,
                              skip_traffic_test, request):                                                       # noqa F811
    hash_keys = ['inner_length']
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/hash_test.IPinIPHashTest.{}.{}.log".format(
        ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)
    if ipver == "ipv4":
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE
    else:
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE
    if skip_traffic_test is True:
        return
    ptf_runner(ptfhost,
               "ptftests",
               "hash_test.IPinIPHashTest",
               platform_dir="ptftests",
               params={"fib_info_files": fib_files[:3],   # Test at most 3 DUTs
                       "ptf_test_port_map": ptf_test_port_map_active_active(
                           ptfhost, tbinfo, duthosts, mux_server_url,
                           duts_running_config_facts, duts_minigraph_facts,
                           mux_status_from_nic_simulator()
               ),
                   "hash_keys": hash_keys,
                   "src_ip_range": ",".join(src_ip_range),
                   "dst_ip_range": ",".join(dst_ip_range),
                   "vlan_ids": VLANIDS,
                   "ignore_ttl": ignore_ttl,
                   "single_fib_for_duts": single_fib_for_duts,
                   "ipver": ipver
               },
               log_file=log_file,
               qlen=PTF_QLEN,
               socket_recv_size=16384,
               is_python3=True)




@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, False, 1514)])
def test_ecmp_group_member_flap(
    duthosts, ptfhost, tbinfo, ipv4, ipv6, mtu,
    toggle_all_simulator_ports_to_random_side,  # noqa F811
    updated_tbinfo, mux_server_url,  # noqa F401
    mux_status_from_nic_simulator, ignore_ttl,
    single_fib_for_duts,  # noqa F401
    duts_running_config_facts, duts_minigraph_facts,
    validate_active_active_dualtor_setup, request  # noqa F401
):
    """Test ECMP group member flap handling."""

    # Skip the test if not running on dualtor topology
    if 'dualtor' in updated_tbinfo['topo']['name']:
        wait(30, 'Waiting for MUX active/standby state stabilization.')

    # --- Load initial FIB files ---
    fib_files = fib_info_files_per_function(
        duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request
    )

    # Verify that the default route has valid nexthops
    nh_ptf_ports = check_default_route_from_fib_info(ptfhost, fib_files[0])
    logging.info("nh_ptf_ports: {}".format(nh_ptf_ports))
    if not nh_ptf_ports:
        pytest.skip("Skipping test as default route is missing or has fewer than 2 nexthops.")

    # --- Identify the DUT and ports from the minigraph facts ---
    upstream_lc = duthosts[0].hostname
    logging.info("upstream_lc: {}".format(upstream_lc))

    all_port_indices = get_all_ptf_port_indices_from_mg_facts(duts_minigraph_facts[upstream_lc])
    nh_dut_ports = map_ptf_ports_to_dut_port(nh_ptf_ports, all_port_indices)
    filtered_ports = filter_ports(all_port_indices, tbinfo)

    logging.info("nh_dut_ports: {}".format(nh_dut_ports))
    logging.info("filtered_ports: {}".format(filtered_ports))

    # Determine test balancing based on asic type and switch platform
    asic_type = duthosts[0].facts['asic_type']
    switch_type = duthosts[0].facts.get('switch_type')
    test_balancing = asic_type not in ["vs"]

    # --- Prepare logging and timestamps ---
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/fib_test.ecmp_member_flap.ipv4.{}.ipv6.{}.{}.log".format(ipv4,ipv6,timestamp)
    logging.info("PTF log file: {}".format(log_file))

    # --- Run the initial PTF test to verify default route behavior ---
    logging.info("Starting ECMP test for default route.")
    ptf_runner(
        ptfhost,
        "ptftests",
        "fib_test.FibTest",
        platform_dir="ptftests",
        params={
            "fib_info_files": fib_files[:3],  # Test up to 3 DUTs
            "ptf_test_port_map": ptf_test_port_map_active_active(
                ptfhost, updated_tbinfo, duthosts, mux_server_url,
                duts_running_config_facts, duts_minigraph_facts,
                mux_status_from_nic_simulator()
            ),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "testbed_mtu": mtu,
            "test_balancing": test_balancing,
            "ignore_ttl": ignore_ttl,
            "single_fib_for_duts": single_fib_for_duts,
            "switch_type": switch_type,
            "asic_type": asic_type,
            "skip_src_ports": filtered_ports
        },
        log_file=log_file,
        qlen=PTF_QLEN,
        socket_recv_size=16384,
        is_python3=True
    )

    # --- Simulate port flap: shutdown one uplink port ---
    logging.info("Shutting down one uplink port.")
    cfg_facts = duts_running_config_facts[upstream_lc]
    num_asic = duthosts[0].num_asics()
    asic_ns = ""
    if num_asic > 1 :
        asic_ns = "-n asic{}".format(nh_dut_ports[0][0])
    logging.info("Shutting down port {}".format(nh_dut_ports[0][1]))
    duthosts[0].shell(" sudo config interface {} shutdown {}".format(asic_ns, nh_dut_ports[0][1]))

    time.sleep(10)  # Allow time for the state to stabilize

    # --- Re-run the PTF test after member down ---
    logging.info("Verifying ECMP behavior after member down.")
    new_fib_files1 = fib_info_files_per_function(
        duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request
    )
    member_down_log_file = "/tmp/fib_test.ecmp_member_flap.member_down.ipv4.{}.ipv6.{}.{}.log".format(ipv4, ipv6, timestamp)
    logging.info("PTF log file: {}".format(member_down_log_file))

    ptf_runner(
        ptfhost,
        "ptftests",
        "fib_test.FibTest",
        platform_dir="ptftests",
        params={
            "fib_info_files": new_fib_files1[:3],
            "ptf_test_port_map": ptf_test_port_map_active_active(
                ptfhost, updated_tbinfo, duthosts, mux_server_url,
                duts_running_config_facts, duts_minigraph_facts,
                mux_status_from_nic_simulator()
            ),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "testbed_mtu": mtu,
            "test_balancing": test_balancing,
            "ignore_ttl": ignore_ttl,
            "single_fib_for_duts": single_fib_for_duts,
            "switch_type": switch_type,
            "asic_type": asic_type,
            "skip_src_ports": filtered_ports
        },
        log_file=member_down_log_file,
        qlen=PTF_QLEN,
        socket_recv_size=16384,
        is_python3=True
    )

    # --- Bring the port back up and verify ---
    logging.info("Bringing the uplink port back up.")

    logging.info("Enabling port {}".format(nh_dut_ports[0][1]))
    duthosts[0].shell("sudo config interface {} startup {}".format(asic_ns, nh_dut_ports[0][1]))

    time.sleep(60)  # Allow time for the state to stabilize

    # --- Re-run the PTF test after member is back up ---
    logging.info("Re-verifying ECMP behavior after member up.")
    new_fib_files2 = fib_info_files_per_function(
        duthosts, ptfhost, duts_running_config_facts, duts_minigraph_facts, tbinfo, request
    )
    member_up_log_file = "/tmp/fib_test.ecmp_member_flap.member_up.ipv4.{}.ipv6.{}.{}.log".format(ipv4,ipv6,timestamp)
    logging.info("PTF log file: {}".format(member_up_log_file))

    ptf_runner(
        ptfhost,
        "ptftests",
        "fib_test.FibTest",
        platform_dir="ptftests",
        params={
            "fib_info_files": new_fib_files2[:3],
            "ptf_test_port_map": ptf_test_port_map_active_active(
                ptfhost, updated_tbinfo, duthosts, mux_server_url,
                duts_running_config_facts, duts_minigraph_facts,
                mux_status_from_nic_simulator()
            ),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "testbed_mtu": mtu,
            "test_balancing": test_balancing,
            "ignore_ttl": ignore_ttl,
            "single_fib_for_duts": single_fib_for_duts,
            "switch_type": switch_type,
            "asic_type": asic_type,
            "skip_src_ports": filtered_ports
        },
        log_file=member_up_log_file,
        qlen=PTF_QLEN,
        socket_recv_size=16384,
        is_python3=True
    )

    logging.info("All tests passed.")
