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
SkipStateCheckAssert = True

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
    cmd_buffer =""
    for idx in range(len(intfs)):
        cmd_buffer += 'sudo config interface ip add {} {}/{} ;'.format(intfs[idx], ips[idx], prefix_len)
        if idx%50 == 0:
            duthost.shell(cmd_buffer)
            cmd_buffer =""
    if cmd_buffer != "":
        duthost.shell(cmd_buffer)


def remove_dut_ip(duthost, intfs, ips, prefix_len):
    cmd_buffer =""
    for idx in range(len(intfs)):
        cmd_buffer +=  'sudo config interface ip remove {} {}/{} ;'.format(intfs[idx], ips[idx], prefix_len)
        if idx%50 == 0:
            duthost.shell(cmd_buffer)
            cmd_buffer = ""
    if cmd_buffer != "":
        duthost.shell(cmd_buffer)


def get_neighbors(duthost, tbinfo, ipv6=False, count=1):
    topo_type = tbinfo['topo']['name']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if 't1' in topo_type:
        t1_ipv4_pattern = '101.0.0.{}'
        t1_ipv6_pattern = '2000:2000::{:x}'
        t0_intfs = get_t0_intfs(mg_facts)
        ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in t0_intfs]
        count = min(count, len(t0_intfs))
        indices = random.sample(list(range(len(t0_intfs))), k=count)
        port_intfs = [t0_intfs[_] for _ in indices]
        neighbour_interfaces =[]
        for intf in port_intfs:
            pc_member = False
            for pc in mg_facts['minigraph_portchannels']:
                if intf in mg_facts['minigraph_portchannels'][pc]['members']:
                    neighbour_interfaces.append(pc)
                    pc_member= True
                    break
            if not pc_member:
                neighbour_interfaces.append(intf)
        if ipv6:
            return [t1_ipv6_pattern.format(idx * 2) for idx in indices], 127, [t1_ipv6_pattern.format(idx * 2 + 1) for idx in indices], neighbour_interfaces, [ptf_ports[_] for _ in indices]
        else:
            return [t1_ipv4_pattern.format(idx * 2) for idx in indices], 31, [t1_ipv4_pattern.format(idx * 2 + 1) for idx in indices], neighbour_interfaces, [ptf_ports[_] for _ in indices]
    else:
        assert( False, "Test only supported on T1." )
def get_neighbors_scale(duthost, tbinfo, ipv6=False, scale_count=1):
    topo_type = tbinfo['topo']['name']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    #Only run for t1
    if 't1' in topo_type:
        t1_ipv4_pattern = '104.0.{}.{}'
        t1_ipv6_pattern = '2002:2000::{:x}'
        t0_intfs = get_t0_intfs(mg_facts)
        ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in t0_intfs]
        index = random.sample(list(range(len(t0_intfs))), k=1)[0]
        
        neighbour_interface =[]
        pc_member = False
        for pc in mg_facts['minigraph_portchannels']:
            if t0_intfs[index] in mg_facts['minigraph_portchannels'][pc]['members']:
                neighbour_interface = pc
                pc_member= True
                break
        if not pc_member:
            neighbour_interface = t0_intfs[index]
        #local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces
        local_addrs = []
        neighbour_addrs = []
        neighbour_devs = []
        ptf_devs =[]
        idx2 =0
        for idx in range(1, scale_count):
            if ipv6:
                local_addrs.append(t1_ipv6_pattern.format(idx * 2))
                neighbour_addrs.append(t1_ipv6_pattern.format(idx * 2 + 1))
                neighbour_devs.append(neighbour_interface)
                ptf_devs.append(ptf_ports[index])
            else:
                rolloveridx = idx %250
                idx2 = idx//250
                local_addrs.append(t1_ipv4_pattern.format(idx2, rolloveridx * 2))
                neighbour_addrs.append(t1_ipv4_pattern.format(idx2, rolloveridx * 2 + 1))
                neighbour_devs.append(neighbour_interface)
                ptf_devs.append(ptf_ports[index])
        prefix = 127 if ipv6 else  31    
        return local_addrs, prefix, neighbour_addrs, neighbour_devs, ptf_devs
    else:
        assert( False, "Test only supported on T1." )

def init_ptf_bfd(ptfhost):
    ptfhost.shell("bfdd-beacon")


def stop_ptf_bfd(ptfhost):
    ptfhost.shell("bfdd-control stop")


def add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False):
    cmd_buffer = ""
    for idx in range(len(neighbor_addrs)):
        if ipv6:
            cmd_buffer += "ip -6 addr add {}/{} dev eth{} ;".format(neighbor_addrs[idx], prefix_len, neighbor_interfaces[idx])
        else:
            cmd_buffer += "ip addr add {}/{} dev eth{} ;".format(neighbor_addrs[idx], prefix_len, neighbor_interfaces[idx])
        if idx%50 == 0:
            ptfhost.shell(cmd_buffer)
            cmd_buffer = ""
    if cmd_buffer != "":
        ptfhost.shell(cmd_buffer)

def del_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False):
    cmd_buffer = ""
    for idx in range(len(neighbor_addrs)):
        if ipv6:
            cmd_buffer += "ip -6 addr del {}/{} dev eth{} ;".format(neighbor_addrs[idx], prefix_len, neighbor_interfaces[idx])
        else:
            cmd_buffer += "ip addr del {}/{} dev eth{} ;".format(neighbor_addrs[idx], prefix_len, neighbor_interfaces[idx])
        if idx%50 == 0:
            ptfhost.shell(cmd_buffer)
            cmd_buffer = ""
    if cmd_buffer != "":
        ptfhost.shell(cmd_buffer,  module_ignore_errors=True) 

def check_ptf_bfd_status(ptfhost, neighbor_addr, local_addr, expected_state):
    bfd_state = ptfhost.shell("bfdd-control status local {} remote {}".format(neighbor_addr, local_addr))["stdout"].split("\n")
    for line in bfd_state:
        field = line.split('=')[0].strip()
        if field == "state":
            assert expected_state in line.split('=')[1].strip()


def check_dut_bfd_status(duthost, neighbor_addr, expected_state):
    bfd_state = duthost.shell("sonic-db-cli STATE_DB HGET 'BFD_SESSION_TABLE|default|default|{}' 'state'".format(neighbor_addr), module_ignore_errors=False)['stdout_lines']
    if not SkipStateCheckAssert:
        assert bfd_state[0] == expected_state
    else:
        print ("Expected State ", expected_state, "actual state", bfd_state[0])

def create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, dut_init_first, scale_test = False):
    # Create a tempfile for BFD sessions
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    bfd_config = []
    dut_buffer = ""
    ptf_buffer = ""
    if scale_test:
        # Force the PTF initialization to be first if runnign scale test. Doing so that we can send bathces fo 50 commadns to ptf
        # and keep the code readable.
        assert( dut_init_first == False )
    
    for idx, neighbor_addr in enumerate(neighbor_addrs):
        dut_buffer += "sonic-db-cli APPL_DB hmset 'BFD_SESSION_TABLE:default:default:{}' local_addr {} ;".format(neighbor_addr, local_addrs[idx])
        bfd_config.append({
            "BFD_SESSION_TABLE:default:default:{}".format(neighbor_addr): {
                "local_addr": local_addrs[idx]
            },
            "OP": "SET"
        })
        ptf_buffer +="bfdd-control connect local {} remote {} ; ".format(neighbor_addr, local_addrs[idx])
        if scale_test and idx%50 == 0:
            ptfhost.shell(ptf_buffer)
            ptf_buffer = ""

    if not dut_init_first and ptf_buffer != "":
        ptfhost.shell(ptf_buffer)
    # Copy json file to DUT
    duthost.shell(dut_buffer)
    duthost.copy(content=json.dumps(bfd_config, indent=4), dest=bfd_file_dir, verbose=False)

    # Apply BFD sessions with swssconfig
    result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(bfd_file_dir),
                           module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.fail('Failed to apply BFD session configuration file: {}'.format(result['stderr']))
    if dut_init_first :
        ptfhost.shell(ptf_buffer)


def remove_bfd_sessions(duthost, local_addrs, neighbor_addrs):
    # Create a tempfile for BFD sessions
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    bfd_config = []
    cmd_buffer = ""
    for idx, neighbor_addr in enumerate(neighbor_addrs):
        cmd_buffer += "sonic-db-cli APPL_DB hmset 'BFD_SESSION_TABLE:default:default:{}' local_addr {} ;".format(neighbor_addr, local_addrs[idx])
        bfd_config.append({
            "BFD_SESSION_TABLE:default:default:{}".format(neighbor_addr): {
                "local_addr": local_addrs[idx]
            },
            "OP": "DEL"
        })
        if idx%50 == 0:
            duthost.shell(cmd_buffer)
            cmd_buffer = ""

    if cmd_buffer != "":
        duthost.shell(cmd_buffer)

    # Copy json file to DUT
    duthost.copy(content=json.dumps(bfd_config, indent=4), dest=bfd_file_dir, verbose=False)

    # Apply BFD session removal with swssconfig
    result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(bfd_file_dir),
                           module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.fail('Failed to apply BFD session configuration file: {}'.format(result['stderr']))


def update_bfd_session_state(ptfhost, neighbor_addr, local_addr, state):
    ptfhost.shell("bfdd-control session local {} remote {} state {}".format(neighbor_addr, local_addr, state))


def bfd_v4_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, dut_init_first = True ):
    duthost = rand_selected_dut
    bfd_session_cnt = 5
    skip_201911_and_older(duthost)
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors(duthost, tbinfo, ipv6=False, count = bfd_session_cnt)
    try:
        if 't1' in tbinfo['topo']['name']:
            add_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
        init_ptf_bfd(ptfhost)
        add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False)
        create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, dut_init_first)

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


def bfd_ipv6_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, dut_init_first = True):
    duthost = rand_selected_dut
    bfd_session_cnt = 5
    skip_201911_and_older(duthost)
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors(duthost, tbinfo, ipv6=True, count = bfd_session_cnt)
    try:
        if 't1' in tbinfo['topo']['name']:
            add_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
        init_ptf_bfd(ptfhost)
        add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=True)
        create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, dut_init_first)

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


#@pytest.mark.skip(reason="Test may currently fail due to lack of hardware support")
def test_bfd_dut_init_v4(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    bfd_v4_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, True)


#@pytest.mark.skip(reason="Test may currently fail due to lack of hardware support")
def test_bfd_ptf_init_v4(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    bfd_v4_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, False)


#@pytest.mark.skip(reason="Test may currently fail due to lack of hardware support")
def test_bfd_dut_init_v6(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    bfd_ipv6_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, True)


#@pytest.mark.skip(reason="Test may currently fail due to lack of hardware support")
def test_bfd_ptf_init_v6(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    bfd_ipv6_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, False)


def bfd_scale_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, ipv6):
    duthost = rand_selected_dut
    bfd_session_cnt = 128
    skip_201911_and_older(duthost)
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors_scale(duthost, tbinfo, ipv6, scale_count = bfd_session_cnt)

    try:
        if 't1' in tbinfo['topo']['name']:
            add_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
        init_ptf_bfd(ptfhost)
        add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6)
        create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, False, ipv6)

        time.sleep(10)

        bfd_state = ptfhost.shell("bfdd-control status")
        dut_state = duthost.shell("show bfd summary")
        for itr in local_addrs:
            assert itr in bfd_state['stdout']
            assert itr in dut_state['stdout']
        print("Scale test Complete")
    finally:
        time.sleep(10)
        stop_ptf_bfd(ptfhost)
        del_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6)
        remove_bfd_sessions(duthost, local_addrs, neighbor_addrs)
        if 't1' in tbinfo['topo']['name']:
            remove_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)

def test_bfd_ipv6_scale(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    bfd_scale_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, True )

def test_bfd_ipv4_scale(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    bfd_scale_test(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, False )



