import time
import logging

from datetime import datetime

import pytest

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses         # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map_active_active
from tests.ptf_runner import ptf_runner
from tests.common.dualtor.mux_simulator_control import mux_server_url
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_random_side
from tests.common.utilities import is_ipv4_address

from tests.common.fixtures.fib_utils import fib_info_files_per_function
from tests.common.fixtures.fib_utils import single_fib_for_duts
from tests.common.utilities import wait

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# Usually src-mac, dst-mac, vlan-id are optional hash keys. Not all the platform supports these optional hash keys. Not enable these three by default.
# The 'ingress-port' key is not used in hash by design. We are doing negative test for 'ingress-port'.
# When 'ingress-port' is included in HASH_KEYS, the PTF test will try to inject same packet to different ingress ports
# and expect that they are forwarded from same egress port.
# HASH_KEYS = ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ingress-port', 'src-mac', 'dst-mac', 'ip-proto', 'vlan-id']
HASH_KEYS = ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ingress-port', 'ip-proto']
SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
DST_IP_RANGE = ['9.0.0.0', '9.255.255.255']
SRC_IPV6_RANGE = ['20D0:A800:0:00::', '20D0:FFFF:0:00::FFFF']
DST_IPV6_RANGE = ['20D0:A800:0:01::', '20D0:FFFF:0:01::FFFF']
VLANIDS = range(1032, 1279)
VLANIP = '192.168.{}.1/24'
PTF_QLEN = 20000
DEFAULT_MUX_SERVER_PORT = 8080

PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'


@pytest.fixture(scope="module")
def ignore_ttl(duthosts):
    # on the multi asic devices, the packet can have different ttl based on how the packet is routed
    # within in the device. So set this flag to mask the ttl in the ptf test
    for duthost in duthosts:
        if duthost.sonichost.is_multi_asic:
            return True
    return False


@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, True, 1514)])
def test_basic_fib(duthosts, ptfhost, ipv4, ipv6, mtu,
                   toggle_all_simulator_ports_to_random_side,
                   fib_info_files_per_function,
                   tbinfo, mux_server_url,
                   mux_status_from_nic_simulator,
                   ignore_ttl, single_fib_for_duts, duts_running_config_facts, duts_minigraph_facts):

    if 'dualtor' in tbinfo['topo']['name']:
        wait(30, 'Wait some time for mux active/standby state to be stable after toggled mux state')

    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    # do not test load balancing for vs platform as kernel 4.9
    # can only do load balance base on L3
    if duthosts[0].facts['asic_type'] in ["vs"]:
        test_balancing = False
    else:
        test_balancing = True

    logging.info("run ptf test")
    log_file = "/tmp/fib_test.FibTest.ipv4.{}.ipv6.{}.{}.log".format(ipv4, ipv6, timestamp)
    logging.info("PTF log file: %s" % log_file)
    ptf_runner(
        ptfhost,
        "ptftests",
        "fib_test.FibTest",
        platform_dir="ptftests",
        params={
            "fib_info_files": fib_info_files_per_function[:3],  # Test at most 3 DUTs
            "ptf_test_port_map": ptf_test_port_map_active_active(
                ptfhost, tbinfo, duthosts, mux_server_url,
                duts_running_config_facts, duts_minigraph_facts,
                mux_status_from_nic_simulator()
            ),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "testbed_mtu": mtu,
            "test_balancing": test_balancing,
            "ignore_ttl": ignore_ttl,
            "single_fib_for_duts": single_fib_for_duts
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

            vlans = asic_cfg_facts.get('VLAN_INTERFACE', {}).keys()
            for vlan in vlans:
                vlan_member_info = asic_cfg_facts.get('VLAN_MEMBER', {}).get(vlan, {})
                if vlan_member_info:
                    for port_name, tag_mode in vlan_member_info.items():
                        if tag_mode['tagging_mode'] == 'untagged':
                            ports.append(port_name)
        vlan_untag_ports[duthost.hostname] = ports
    return vlan_untag_ports


@pytest.fixture(scope="module")
def hash_keys(duthost):
    hash_keys = HASH_KEYS[:]    # Copy from global var to avoid side effects of multiple iterations
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
        duthost.shell('config interface ip add Vlan{} '.format(vlan) + VLANIP.format(vlan%256))
    time.sleep(5)


def unconfigure_vlan(duthost, ports):
    for vlan in VLANIDS:
        for port in ports:
            duthost.shell('config vlan member del {} {}'.format(vlan, port))
        duthost.shell('config interface ip remove Vlan{} '.format(vlan) + VLANIP.format(vlan%256))
        duthost.shell('config vlan del {}'.format(vlan))
    time.sleep(5)


@pytest.fixture
def setup_vlan(tbinfo, duthosts, duts_running_config_facts, hash_keys):

    vlan_untag_ports = get_vlan_untag_ports(duthosts, duts_running_config_facts)
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


@pytest.fixture
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
                for asic_index, asic_cfg_facts in enumerate(cfg_facts):
                    asic = duthost.asic_instance(asic_index)
                    bgp_neighbors = asic_cfg_facts["BGP_NEIGHBOR"]
                    ipv4_cmd_parts = ["ip route add default"]
                    ipv6_cmd_parts = ["ip -6 route add default"]
                    for neighbor in bgp_neighbors.keys():
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
                    asic.shell("ip route del default", module_ignore_errors=True)
                    asic.shell("ip -6 route del default", module_ignore_errors=True)
    else:
        yield


def test_hash(add_default_route_to_dut, duthosts, fib_info_files_per_function, setup_vlan, hash_keys, ptfhost, ipver,
              toggle_all_simulator_ports_to_rand_selected_tor_m,
              tbinfo, mux_server_url, mux_status_from_nic_simulator,
              ignore_ttl, single_fib_for_duts, duts_running_config_facts, duts_minigraph_facts):

    if 'dualtor' in tbinfo['topo']['name']:
        wait(30, 'Wait some time for mux active/standby state to be stable after toggled mux state')

    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/hash_test.HashTest.{}.{}.log".format(ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)
    if ipver == "ipv4":
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE
    else:
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE
    ptf_runner(
        ptfhost,
        "ptftests",
        "hash_test.HashTest",
        platform_dir="ptftests",
        params={"fib_info_files": fib_info_files_per_function[:3],   # Test at most 3 DUTs
                "ptf_test_port_map": ptf_test_port_map_active_active(
                    ptfhost, tbinfo, duthosts, mux_server_url,
                    duts_running_config_facts, duts_minigraph_facts,
                    mux_status_from_nic_simulator()
                ),
                "hash_keys": hash_keys,
                "src_ip_range": ",".join(src_ip_range),
                "dst_ip_range": ",".join(dst_ip_range),
                "vlan_ids": VLANIDS,
                "ignore_ttl":ignore_ttl,
                "single_fib_for_duts": single_fib_for_duts
                },
        log_file=log_file,
        qlen=PTF_QLEN,
        socket_recv_size=16384,
        is_python3=True
    )
