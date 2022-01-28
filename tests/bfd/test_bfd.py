import pytest
import ipaddress
import natsort
import random
import time
import json

from tests.common.fixtures.ptfhost_utils import change_mac_addresses, copy_arp_responder_py
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.mux_simulator_control import mux_server_url
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m
from pkg_resources import parse_version
from tests.common import constants

pytestmark = [
    pytest.mark.topology('t0', 't1', 't1-lag')
]

def skip_201911_and_older(duthost):
    """ Skip the current test if the DUT version is 201911 or older.
    """
    if parse_version(duthost.kernel_version) <= parse_version('4.9.0'):
        pytest.skip("Test not supported for 201911 images or older. Skipping the test")


def is_dualtor(tbinfo):
    """Check if the testbed is dualtor."""
    return "dualtor" in tbinfo["topo"]["name"]


def get_t0_intfs(mg_facts):
    t0_intfs = []

    for intf in mg_facts['minigraph_neighbors']:
        if 'T0' in mg_facts['minigraph_neighbors'][intf]['name']:
            t0_intfs.append(intf)

    return t0_intfs


def add_dut_ip(duthost, intfs, ips, prefix_len):
    for idx in range(len(intfs)):
        duthost.shell('sudo config interface ip add {} {}/{}'.format(intfs[idx], ips[idx], prefix_len))


def remove_dut_ip(duthost, intfs, ips, prefix_len):
    for idx in range(len(intfs)):
        duthost.shell('sudo config interface ip remove {} {}/{}'.format(intfs[idx], ips[idx], prefix_len))


def get_neighbors(duthost, tbinfo, ipv6=False, count=1):
    topo_type = tbinfo['topo']['name']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    if 't0' in topo_type:
        vlan_intf = mg_facts['minigraph_vlan_interfaces'][1 if ipv6 else 0]
        prefix_len = vlan_intf['prefixlen']
        vlan_addr = vlan_intf["addr"]

        is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)
        if is_dualtor(tbinfo):
            server_ips = mux_cable_server_ip(duthost)
            vlan_intfs = natsort.natsorted(server_ips.keys())
            neighbor_devs = [mg_facts["minigraph_ptf_indices"][_] for _ in vlan_intfs]
            server_ip_key = "server_ipv6" if ipv6 else "server_ipv4"
            neighbor_addrs = [server_ips[_][server_ip_key].split("/")[0] for _ in vlan_intfs]
            neighbor_interfaces = neighbor_devs
        else:
            vlan_subnet = ipaddress.ip_network(vlan_intf['subnet'])
            vlan = mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][1 if ipv6 else 0]['attachto']]
            vlan_ports = vlan['members']
            vlan_id = vlan['vlanid']
            vlan_ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in vlan_ports]
            neighbor_devs = vlan_ptf_ports
            # backend topology use ethx.x(e.g. eth30.1000) during servers and T0 in ptf
            # in other topology use ethx(e.g. eth30)
            if is_backend_topology:
                neighbor_interfaces = [str(dev) + constants.VLAN_SUB_INTERFACE_SEPARATOR + str(vlan_id) for dev in neighbor_devs]
            else:
                neighbor_interfaces = neighbor_devs
            neighbor_addrs = [str(vlan_subnet[i + 2]) for i in range(len(neighbor_devs))]
        count = min(count, len(neighbor_devs))
        indices = random.sample(list(range(len(neighbor_devs))), k=count)
        return [vlan_addr for _ in indices], prefix_len, [neighbor_addrs[_] for _ in indices], [neighbor_devs[_] for _ in indices], [neighbor_interfaces[_] for _ in indices]
    elif 't1' in topo_type:
        t1_ipv4_pattern = '101.0.0.{}'
        t1_ipv6_pattern = '2000:2000::{:x}'
        t0_intfs = get_t0_intfs(mg_facts)
        ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in t0_intfs]
        count = min(count, len(t0_intfs))
        indices = random.sample(list(range(len(t0_intfs))), k=count)
        if ipv6:
            return [t1_ipv6_pattern.format(idx * 2) for idx in indices], 127, [t1_ipv6_pattern.format(idx * 2 + 1) for idx in indices], [t0_intfs[_] for _ in indices], [ptf_ports[_] for _ in indices]
        else:
            return [t1_ipv4_pattern.format(idx * 2) for idx in indices], 31, [t1_ipv4_pattern.format(idx * 2 + 1) for idx in indices], [t0_intfs[_] for _ in indices], [ptf_ports[_] for _ in indices]


def init_ptf_bfd(ptfhost):
    ptfhost.shell("bfdd-beacon")


def stop_ptf_bfd(ptfhost):
    ptfhost.shell("bfdd-control stop")


def add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False):
    for idx in range(len(neighbor_addrs)):
        if ipv6:
            ptfhost.shell("ip -6 addr add {}/{} dev eth{}".format(neighbor_addrs[idx], prefix_len, neighbor_interfaces[idx]))
        else:
            ptfhost.shell("ip addr add {}/{} dev eth{}".format(neighbor_addrs[idx], prefix_len, neighbor_interfaces[idx]))


def del_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False):
    for idx in range(len(neighbor_addrs)):
        if ipv6:
            ptfhost.shell("ip -6 addr del {}/{} dev eth{}".format(neighbor_addrs[idx], prefix_len, neighbor_interfaces[idx]), module_ignore_errors=True)
        else:
            ptfhost.shell("ip addr del {}/{} dev eth{}".format(neighbor_addrs[idx], prefix_len, neighbor_interfaces[idx]), module_ignore_errors=True)


def check_ptf_bfd_status(ptfhost, neighbor_addr, local_addr, expected_state):
    bfd_state = ptfhost.shell("bfdd-control status local {} remote {}".format(neighbor_addr, local_addr))["stdout"].split("\n")
    for line in bfd_state:
        field = line.split('=')[0].strip()
        if field == "state":
            assert line.split('=')[1].strip() == expected_state


def check_dut_bfd_status(duthost, neighbor_addr, expected_state):
    bfd_state = duthost.shell("sonic-db-cli STATE_DB HGET 'BFD_SESSION_TABLE|default|default|{}' 'state'".format(neighbor_addr), module_ignore_errors=False)['stdout_lines']
    assert bfd_state[0] == expected_state


def create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs):
    # Create a tempfile for BFD sessions
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    bfd_config = []

    for idx, neighbor_addr in enumerate(neighbor_addrs):
        duthost.shell("sonic-db-cli APPL_DB hmset 'BFD_SESSION_TABLE:default:default:{}' local_addr {}".format(neighbor_addr, local_addrs[idx]))
        bfd_config.append({
            "BFD_SESSION_TABLE:default:default:{}".format(neighbor_addr): {
                "local_addr": local_addrs[idx]
            },
            "OP": "SET"
        })
        ptfhost.shell("bfdd-control connect local {} remote {}".format(neighbor_addr, local_addrs[idx]))

    # Copy json file to DUT
    duthost.copy(content=json.dumps(bfd_config, indent=4), dest=bfd_file_dir, verbose=False)

    # Apply BFD sessions with swssconfig
    result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(bfd_file_dir),
                           module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.fail('Failed to apply BFD session configuration file: {}'.format(result['stderr']))


def remove_bfd_sessions(duthost, local_addrs, neighbor_addrs):
    # Create a tempfile for BFD sessions
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    bfd_config = []

    for idx, neighbor_addr in enumerate(neighbor_addrs):
        duthost.shell("sonic-db-cli APPL_DB hmset 'BFD_SESSION_TABLE:default:default:{}' local_addr {}".format(neighbor_addr, local_addrs[idx]))
        bfd_config.append({
            "BFD_SESSION_TABLE:default:default:{}".format(neighbor_addr): {
                "local_addr": local_addrs[idx]
            },
            "OP": "DEL"
        })

    # Copy json file to DUT
    duthost.copy(content=json.dumps(bfd_config, indent=4), dest=bfd_file_dir, verbose=False)

    # Apply BFD session removal with swssconfig
    result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(bfd_file_dir),
                           module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.fail('Failed to apply BFD session configuration file: {}'.format(result['stderr']))


def update_bfd_session_state(ptfhost, neighbor_addr, local_addr, state):
    ptfhost.shell("bfdd-control session local {} remote {} state {}".format(neighbor_addr, local_addr, state))


@pytest.mark.skip(reason="Test may currently fail due to lack of hardware support")
def test_bfd(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    duthost = rand_selected_dut
    bfd_session_cnt = 5
    skip_201911_and_older(duthost)
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors(duthost, tbinfo, count = bfd_session_cnt)

    try:
        if 't1' in tbinfo['topo']['name']:
            add_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
        init_ptf_bfd(ptfhost)
        add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False)
        create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs)

        time.sleep(1)

        for idx, neighbor_addr in enumerate(neighbor_addrs):
            check_dut_bfd_status(duthost, neighbor_addr, "Up")
            check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Up")

        update_idx = random.choice(range(bfd_session_cnt))
        update_bfd_session_state(ptfhost, neighbor_addrs[update_idx], local_addrs[idx], "down")

        for idx in range(bfd_session_cnt):
            if idx == update_idx:
                check_dut_bfd_status(duthost, neighbor_addr, "Down")
                check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Down")
            else:
                check_dut_bfd_status(duthost, neighbor_addr, "Up")
                check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Up")
    finally:
        stop_ptf_bfd(ptfhost)
        del_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False)
        remove_bfd_sessions(duthost, local_addrs, neighbor_addrs)
        if 't1' in tbinfo['topo']['name']:
            remove_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)


@pytest.mark.skip(reason="Test may currently fail due to lack of hardware support")
def test_bfd_ipv6(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    duthost = rand_selected_dut
    bfd_session_cnt = 5
    skip_201911_and_older(duthost)
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors(duthost, tbinfo, ipv6=True, count = bfd_session_cnt)

    try:
        if 't1' in tbinfo['topo']['name']:
            add_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
        init_ptf_bfd(ptfhost)
        add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=True)
        create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs)

        time.sleep(1)

        for idx, neighbor_addr in enumerate(neighbor_addrs):
            check_dut_bfd_status(duthost, neighbor_addr, "Up")
            check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Up")

        update_idx = random.choice(range(bfd_session_cnt))
        update_bfd_session_state(ptfhost, neighbor_addrs[update_idx], local_addrs[idx], "down")

        for idx in range(bfd_session_cnt):
            if idx == update_idx:
                check_dut_bfd_status(duthost, neighbor_addr, "Down")
                check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Down")
            else:
                check_dut_bfd_status(duthost, neighbor_addr, "Up")
                check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Up")
    finally:
        stop_ptf_bfd(ptfhost)
        del_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=True)
        remove_bfd_sessions(duthost, local_addrs, neighbor_addrs)
        if 't1' in tbinfo['topo']['name']:
            remove_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
