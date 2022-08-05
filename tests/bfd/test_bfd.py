import pytest
import random
import time
import json

from tests.common.fixtures.ptfhost_utils import change_mac_addresses, copy_arp_responder_py
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.mux_simulator_control import mux_server_url
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m

pytestmark = [
    pytest.mark.topology('t1', 't1-lag', 't1-64-lag')
]

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
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    t1_ipv4_pattern = '101.0.0.{}'
    t1_ipv6_pattern = '2000:2000::{:x}'
    t0_intfs = get_t0_intfs(mg_facts)
    ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in t0_intfs]
    count = min(count, len(t0_intfs))
    indices = random.sample(list(range(len(t0_intfs))), k=count)
    port_intfs = [t0_intfs[_] for _ in indices]
    neighbour_devs =[]
    for intf in port_intfs:
        pc_member = False
        for pc in mg_facts['minigraph_portchannels']:
            if intf in mg_facts['minigraph_portchannels'][pc]['members']:
                neighbour_devs.append(pc)
                pc_member= True
                break
        if not pc_member:
            neighbour_devs.append(intf)
    if ipv6:
        return [t1_ipv6_pattern.format(idx * 2) for idx in indices], 127, [t1_ipv6_pattern.format(idx * 2 + 1) for idx in indices], neighbour_devs, [ptf_ports[_] for _ in indices]
    else:
        return [t1_ipv4_pattern.format(idx * 2) for idx in indices], 31, [t1_ipv4_pattern.format(idx * 2 + 1) for idx in indices], neighbour_devs, [ptf_ports[_] for _ in indices]

def get_neighbors_scale(duthost, tbinfo, ipv6=False, scale_count=1):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    t1_ipv4_pattern = '104.0.{}.{}'
    t1_ipv6_pattern = '2002:2000::{:x}'
    t0_intfs = get_t0_intfs(mg_facts)
    ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in t0_intfs]
    count = min(2, len(t0_intfs))
    indices = random.sample(list(range(len(t0_intfs))), k=count)
    port_intfs = [t0_intfs[_] for _ in indices]
    neighbour_intfs =[]
    for intf in port_intfs:
        pc_member = False
        for pc in mg_facts['minigraph_portchannels']:
            if intf in mg_facts['minigraph_portchannels'][pc]['members']:
                neighbour_intfs.append(pc)
                pc_member= True
                break
    if not pc_member:
        neighbour_intfs.append(intf)
    ptf_intfs = [ptf_ports[_] for _ in indices]
    #local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces
    local_addrs = []
    neighbour_addrs = []
    neighbour_devs = []
    ptf_devs =[]
    idx2 =0
    index = 0
    for idx in range(1, scale_count):
        if idx !=0 and idx %127 == 0:
            index +=1
        if ipv6:
            local_addrs.append(t1_ipv6_pattern.format(idx * 2))
            neighbour_addrs.append(t1_ipv6_pattern.format(idx * 2 + 1))
            neighbour_devs.append(neighbour_intfs[index])
            ptf_devs.append(ptf_intfs[index])
        else:
            rolloveridx = idx %125
            idx2 = idx//125
            local_addrs.append(t1_ipv4_pattern.format(idx2, rolloveridx * 2))
            neighbour_addrs.append(t1_ipv4_pattern.format(idx2, rolloveridx * 2 + 1))
            neighbour_devs.append(neighbour_intfs[index])
            ptf_devs.append(ptf_intfs[index])
    prefix = 127 if ipv6 else  31
    return local_addrs, prefix, neighbour_addrs, neighbour_devs, ptf_devs

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
    assert  expected_state in bfd_state[0]

def create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, dut_init_first, scale_test = False):
    # Create a tempfile for BFD sessions
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    bfd_config = []
    ptf_buffer = ""
    if scale_test:
        # Force the PTF initialization to be first if runnign scale test. Doing so that we can send bathces fo 50 commadns to ptf
        # and keep the code readable.
        assert( dut_init_first == False )
    
    for idx, neighbor_addr in enumerate(neighbor_addrs):
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
    for idx, neighbor_addr in enumerate(neighbor_addrs):
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

def update_bfd_state(ptfhost, neighbor_addr, local_addr, state):
    ptfhost.shell("bfdd-control session local {} remote {} {}".format(neighbor_addr, local_addr, state))

@pytest.mark.parametrize('dut_init_first', [True, False], ids=['dut_init_first', 'ptf_init_first'])
@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bfd_basic(request, rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, ipv6, dut_init_first):
    duthost = rand_selected_dut
    bfd_session_cnt =  int(request.config.getoption('--num_sessions'))
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors(duthost, tbinfo, ipv6, count = bfd_session_cnt)
    try:
        add_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
        init_ptf_bfd(ptfhost)
        add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6)
        create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, dut_init_first)

        time.sleep(1)
        for idx, neighbor_addr in enumerate(neighbor_addrs):
            check_dut_bfd_status(duthost, neighbor_addr, "Up")
            check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Up")

        update_idx = random.choice(range(bfd_session_cnt))
        update_bfd_session_state(ptfhost, neighbor_addrs[update_idx], local_addrs[update_idx], "admin")
        time.sleep(1)

        for idx, neighbor_addr in enumerate(neighbor_addrs):
            if idx == update_idx:
                check_dut_bfd_status(duthost, neighbor_addr, "Admin_Down")
                check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "AdminDown")
            else:
                check_dut_bfd_status(duthost, neighbor_addr, "Up")
                check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Up")
        
        update_bfd_session_state(ptfhost, neighbor_addrs[update_idx], local_addrs[update_idx], "up")
        time.sleep(1)

        check_dut_bfd_status(duthost, neighbor_addrs[update_idx], "Up")
        check_ptf_bfd_status(ptfhost, neighbor_addrs[update_idx], local_addrs[update_idx], "Up")

        
        update_idx = random.choice(range(bfd_session_cnt))
        update_bfd_state(ptfhost, neighbor_addrs[update_idx], local_addrs[update_idx], "suspend")
        time.sleep(1)

        for idx, neighbor_addr in enumerate(neighbor_addrs):
            if idx == update_idx:
                check_dut_bfd_status(duthost, neighbor_addr, "Down")
                check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Init")
            else:
                check_dut_bfd_status(duthost, neighbor_addr, "Up")
                check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Up")
        
    finally:
        stop_ptf_bfd(ptfhost)
        del_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6)
        remove_bfd_sessions(duthost, local_addrs, neighbor_addrs)
        remove_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)


@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bfd_scale(rand_selected_dut, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m, ipv6):
    duthost = rand_selected_dut
    bfd_session_cnt =  int(request.config.getoption('--num_sessions_scale'))
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors_scale(duthost, tbinfo, ipv6, scale_count = bfd_session_cnt)

    try:
        add_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
        init_ptf_bfd(ptfhost)
        add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6)
        create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, False, True)

        time.sleep(10)

        bfd_state = ptfhost.shell("bfdd-control status")
        dut_state = duthost.shell("show bfd summary")
        for itr in local_addrs:
            assert itr in bfd_state['stdout']
            assert itr in dut_state['stdout']

    finally:
        time.sleep(10)
        stop_ptf_bfd(ptfhost)
        del_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6)
        remove_bfd_sessions(duthost, local_addrs, neighbor_addrs)
        remove_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
