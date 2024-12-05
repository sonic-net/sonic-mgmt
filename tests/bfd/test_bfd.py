import pytest
import random
import time
import json
import logging

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.snappi_tests.common_helpers import get_egress_queue_count

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('physical')
]

BFD_RESPONDER_SCRIPT_SRC_PATH = '../ansible/roles/test/files/helpers/bfd_responder.py'
BFD_RESPONDER_SCRIPT_DEST_PATH = '/opt/bfd_responder.py'

logger = logging.getLogger(__name__)


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
    cmd_buffer = ""
    for idx in range(len(intfs)):
        cmd_buffer += 'sudo config interface ip add {} {}/{} ;'.format(intfs[idx], ips[idx], prefix_len)
        if idx % 50 == 0:
            duthost.shell(cmd_buffer)
            cmd_buffer = ""
    if cmd_buffer != "":
        duthost.shell(cmd_buffer)


def remove_dut_ip(duthost, intfs, ips, prefix_len):
    cmd_buffer = ""
    for idx in range(len(intfs)):
        cmd_buffer += 'sudo config interface ip remove {} {}/{} ;'.format(intfs[idx], ips[idx], prefix_len)
        if idx % 50 == 0:
            duthost.shell(cmd_buffer)
            cmd_buffer = ""
    if cmd_buffer != "":
        duthost.shell(cmd_buffer)


def get_neighbors(duthost, tbinfo, ipv6=False, count=1):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    prefix_len = 127 if ipv6 else 31
    ip_pattern = '2000:2000::{:x}' if ipv6 else '101.0.0.{}'
    t0_intfs = get_t0_intfs(mg_facts)
    ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in t0_intfs]
    count = min(count, len(t0_intfs))
    indices = random.sample(list(range(len(t0_intfs))), k=count)
    port_intfs = [t0_intfs[_] for _ in indices]
    neighbor_devs = []
    for intf in port_intfs:
        pc_member = False
        for pc in mg_facts['minigraph_portchannels']:
            if intf in mg_facts['minigraph_portchannels'][pc]['members']:
                neighbor_devs.append(pc)
                pc_member = True
                break
        if not pc_member:
            neighbor_devs.append(intf)

    local_addrs = [ip_pattern.format(idx * 2) for idx in indices]
    neighbor_addrs = [ip_pattern.format(idx * 2 + 1) for idx in indices]
    neighbor_interfaces = [ptf_ports[_] for _ in indices]

    return local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces


def get_neighbors_scale(duthost, tbinfo, ipv6=False, scale_count=1):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    t1_ipv4_pattern = '104.0.{}.{}'
    t1_ipv6_pattern = '2002:2000::{:x}'
    t0_intfs = get_t0_intfs(mg_facts)
    ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in t0_intfs]
    count = min(2, len(t0_intfs))
    indices = random.sample(list(range(len(t0_intfs))), k=count)
    port_intfs = [t0_intfs[_] for _ in indices]
    neighbor_intfs = []
    for intf in port_intfs:
        pc_member = False
        for pc in mg_facts['minigraph_portchannels']:
            if intf in mg_facts['minigraph_portchannels'][pc]['members']:
                neighbor_intfs.append(pc)
                pc_member = True
                break
        if not pc_member:
            neighbor_intfs.append(intf)
    ptf_intfs = [ptf_ports[_] for _ in indices]
    # local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces
    local_addrs = []
    neighbor_addrs = []
    neighbor_devs = []
    ptf_devs = []
    index = 0
    # The arrays: neighbor_intfs and ptf_intfs are filled only upto 128.
    # Beyond that we need to re-use the same addresses. We do this by
    # using the modulus(% operation) instead of the actual index intself.
    for idx in range(1, scale_count):
        if idx != 0 and idx % 127 == 0:
            index += 1
        if ipv6:
            local_addrs.append(t1_ipv6_pattern.format(idx * 2))
            neighbor_addrs.append(t1_ipv6_pattern.format(idx * 2 + 1))
            neighbor_devs.append(neighbor_intfs[index % len(neighbor_intfs)])
            ptf_devs.append(ptf_intfs[index % len(ptf_intfs)])
        else:
            rolloveridx = idx % 125
            idx2 = idx // 125
            local_addrs.append(t1_ipv4_pattern.format(idx2, rolloveridx * 2))
            neighbor_addrs.append(t1_ipv4_pattern.format(idx2, rolloveridx * 2 + 1))
            neighbor_devs.append(neighbor_intfs[index % len(neighbor_intfs)])
            ptf_devs.append(ptf_intfs[index % len(ptf_intfs)])
    prefix = 127 if ipv6 else 31
    return local_addrs, prefix, neighbor_addrs, neighbor_devs, ptf_devs


def get_loopback_intf(mg_facts, ipv6):
    ipv6idx = 0 if mg_facts['minigraph_lo_interfaces'][0]['prefixlen'] == 128 else 1
    if ipv6:
        return mg_facts['minigraph_lo_interfaces'][ipv6idx]['addr']
    else:
        return mg_facts['minigraph_lo_interfaces'][(ipv6idx + 1) % 2]['addr']


def get_neighbors_multihop(duthost, tbinfo, ipv6=False, count=1):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    t0_ipv4_pattern = '4.{}.{}.1'
    t0_ipv6_pattern = '3000:3000:{:x}::3000'
    t0_intfs = get_t0_intfs(mg_facts)
    ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in t0_intfs]
    loopback_addr = get_loopback_intf(mg_facts, ipv6)

    index = random.sample(list(range(len(t0_intfs))), k=1)[0]
    port_intf = t0_intfs[index]
    ptf_intf = ptf_ports[index]
    logger.debug("BFD multihop, DUT interface name: {}".format(port_intf))
    nexthop_ip = ""
    neighbour_dev_name = mg_facts['minigraph_neighbors'][port_intf]['name']
    for bgpinfo in mg_facts['minigraph_bgp']:
        if bgpinfo['name'] == neighbour_dev_name:
            nexthop_ip = bgpinfo['addr']
            if ipv6 and ":" not in nexthop_ip:
                nexthop_ip = ""
                continue
            break
    if nexthop_ip == "":
        assert False
    neighbor_addrs = []
    idx2 = 0
    for idx in range(1, count):
        if idx % 250 == 0:
            idx2 += 1
        if ipv6:
            neighbor_addrs.append(t0_ipv6_pattern.format(idx))
        else:
            neighbor_addrs.append(t0_ipv4_pattern.format((idx % 250), idx2))

    return loopback_addr, ptf_intf, nexthop_ip, neighbor_addrs, port_intf


def init_ptf_bfd(ptfhost):
    ptfhost.shell("bfdd-beacon")


def stop_ptf_bfd(ptfhost):
    ptfhost.shell("bfdd-control stop")


def add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False):
    cmd_buffer = ""
    for idx in range(len(neighbor_addrs)):
        if ipv6:
            cmd_buffer += "ip -6 addr add {}/{} dev eth{} ;".format(neighbor_addrs[idx], prefix_len,
                                                                    neighbor_interfaces[idx])
        else:
            cmd_buffer += "ip addr add {}/{} dev eth{} ;".format(neighbor_addrs[idx], prefix_len,
                                                                 neighbor_interfaces[idx])
        if idx % 50 == 0:
            ptfhost.shell(cmd_buffer)
            cmd_buffer = ""
    if cmd_buffer != "":
        ptfhost.shell(cmd_buffer)


def del_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6=False):
    cmd_buffer = ""
    for idx in range(len(neighbor_addrs)):
        if ipv6:
            cmd_buffer += "ip -6 addr del {}/{} dev eth{} ;".format(neighbor_addrs[idx], prefix_len,
                                                                    neighbor_interfaces[idx])
        else:
            cmd_buffer += "ip addr del {}/{} dev eth{} ;".format(neighbor_addrs[idx], prefix_len,
                                                                 neighbor_interfaces[idx])
        if idx % 50 == 0:
            ptfhost.shell(cmd_buffer, module_ignore_errors=True)
            cmd_buffer = ""
    if cmd_buffer != "":
        ptfhost.shell(cmd_buffer, module_ignore_errors=True)


def check_ptf_bfd_status(ptfhost, neighbor_addr, local_addr, expected_state):
    bfd_state = ptfhost.shell("bfdd-control status local {} remote {}"
                              .format(neighbor_addr, local_addr))["stdout"].split("\n")
    for line in bfd_state:
        field = line.split('=')[0].strip()
        if field == "state":
            assert expected_state in line.split('=')[1].strip()


def check_dut_bfd_status(duthost, neighbor_addr, expected_state, max_attempts=12, retry_interval=10):
    for i in range(max_attempts + 1):
        bfd_state = duthost.shell("sonic-db-cli STATE_DB HGET 'BFD_SESSION_TABLE|default|default|{}' 'state'"
                                  .format(neighbor_addr), module_ignore_errors=False)['stdout_lines']
        logger.info("BFD state check: {} - {}".format(neighbor_addr, bfd_state[0]))

        if expected_state in bfd_state[0]:
            return  # Success, no need to retry

        logger.error("BFD state check failed: {} - {}".format(neighbor_addr, bfd_state[0]))
        if i < max_attempts:
            time.sleep(retry_interval)

    assert expected_state in bfd_state[0]  # If all attempts fail, raise an assertion error


def create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, dut_init_first, scale_test=False):
    # Create a tempfile for BFD sessions
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    bfd_config = []
    ptf_buffer = ""
    if scale_test:
        # Force the PTF initialization to be first if running a scale test.
        # Doing so that we can send batches of 50 commands to PTF and keep the code readable.
        assert (dut_init_first is False)

    for idx, neighbor_addr in enumerate(neighbor_addrs):
        bfd_config.append({
            "BFD_SESSION_TABLE:default:default:{}".format(neighbor_addr): {
                "local_addr": local_addrs[idx]
            },
            "OP": "SET"
        })
        ptf_buffer += "bfdd-control connect local {} remote {} ; ".format(neighbor_addr, local_addrs[idx])
        if scale_test and idx % 50 == 0:
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
    if dut_init_first:
        ptfhost.shell(ptf_buffer)


def create_bfd_sessions_multihop(ptfhost, duthost, loopback_addr, ptf_intf, neighbor_addrs):
    # Create a tempfile for BFD sessions
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    ptf_file_dir = ptfhost.shell('mktemp')['stdout']
    bfd_config = []
    ptf_config = []
    for neighbor_addr in neighbor_addrs:
        logger.info("create BFD sessions, loopback {} neighbor ip {}".format(loopback_addr, neighbor_addr))
        bfd_config.append({
            "BFD_SESSION_TABLE:default:default:{}".format(neighbor_addr): {
                "local_addr": loopback_addr,
                "multihop": "true"
            },
            "OP": "SET"
        })
        ptf_config.append(
            {
                "neighbor_addr": loopback_addr,
                "local_addr": neighbor_addr,
                "multihop": "true",
                "ptf_intf": "eth{}".format(ptf_intf)
            }
        )

    # Copy json file to DUT
    duthost.copy(content=json.dumps(bfd_config, indent=4), dest=bfd_file_dir, verbose=False)

    # Apply BFD sessions with swssconfig
    result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(bfd_file_dir),
                           module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.fail('Failed to apply BFD session configuration file: {}'.format(result['stderr']))
    # Copy json file to PTF
    ptfhost.copy(content=json.dumps(ptf_config, indent=4), dest=ptf_file_dir, verbose=False)

    ptfhost.copy(src=BFD_RESPONDER_SCRIPT_SRC_PATH, dest=BFD_RESPONDER_SCRIPT_DEST_PATH)

    extra_vars = {"bfd_responder_args": "-c {}".format(ptf_file_dir)}
    ptfhost.host.options["variable_manager"].extra_vars.update(extra_vars)

    ptfhost.template(src='templates/bfd_responder.conf.j2', dest='/etc/supervisor/conf.d/bfd_responder.conf')
    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')
    ptfhost.command('supervisorctl restart bfd_responder')
    logger.info("Waiting for bfd session to be in Up state")
    time.sleep(30)
    temp = duthost.shell('show bfd summary')
    logger.info("BFD Summary dump: {}".format(temp['stdout']))


def bfd_echo_mode(duthost, neighbor_addrs,):
    # Apply BFD echo mode configuration with vtysh
    cmd = "vtysh -c 'configure terminal' -c 'bfd'"
    for neighbor_addr in neighbor_addrs:
        cmd += " -c 'bfd peer {}' -c 'echo-mode'".format(neighbor_addr)
    cmd += " -c 'end' -c 'do write' -c 'exit'"
    duthost.shell(cmd)


def remove_bfd_sessions(duthost, neighbor_addrs):
    # Create a tempfile for BFD sessions
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    bfd_config = []
    for idx, neighbor_addr in enumerate(neighbor_addrs):
        bfd_config.append({
            "BFD_SESSION_TABLE:default:default:{}".format(neighbor_addr): {
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


def verify_bfd_queue_counters(duthost, dut_intf):
    queue_output = duthost.shell("show queue counters {}".format(dut_intf))
    logger.debug("Queue output: {}".format(queue_output['stdout']))

    for queue_val in range(0, 7):
        queue_pkt_count, _ = get_egress_queue_count(duthost, dut_intf, int(queue_val))
        logger.debug("Interface {}, Queue {}, counter {}".format(dut_intf, queue_val, queue_pkt_count))
        if queue_pkt_count != 0:
            pytest.fail('Queue {} count is not zero, BFD packets might use this'.format(queue_val))

    bfd_queue = 7
    queue_pkt_count, _ = get_egress_queue_count(duthost, dut_intf, int(bfd_queue))
    logger.debug("Queue counters: {}".format(queue_pkt_count))
    if queue_pkt_count == 0:
        pytest.fail('Queue 7 packet count is zero, no BFD traffic')


@pytest.mark.parametrize('dut_init_first', [True, False], ids=['dut_init_first', 'ptf_init_first'])
@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bfd_basic(request, rand_selected_dut, ptfhost, tbinfo, ipv6, dut_init_first):
    duthost = rand_selected_dut
    bfd_session_cnt = int(request.config.getoption('--num_sessions'))
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors(duthost, tbinfo, ipv6,
                                                                                                count=bfd_session_cnt)
    try:
        add_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)
        init_ptf_bfd(ptfhost)
        add_ipaddr(ptfhost, neighbor_addrs, prefix_len, neighbor_interfaces, ipv6)
        create_bfd_sessions(ptfhost, duthost, local_addrs, neighbor_addrs, dut_init_first)

        time.sleep(1)
        for idx, neighbor_addr in enumerate(neighbor_addrs):
            check_dut_bfd_status(duthost, neighbor_addr, "Up")
            check_ptf_bfd_status(ptfhost, neighbor_addr, local_addrs[idx], "Up")

        update_idx = random.choice(list(range(bfd_session_cnt)))
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

        update_idx = random.choice(list(range(bfd_session_cnt)))
        update_bfd_state(ptfhost, neighbor_addrs[update_idx], local_addrs[update_idx], "suspend")
        time.sleep(5)

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
        remove_bfd_sessions(duthost, neighbor_addrs)
        remove_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)


@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bfd_scale(request, rand_selected_dut, ptfhost, tbinfo, ipv6):
    duthost = rand_selected_dut
    bfd_session_cnt = int(request.config.getoption('--num_sessions_scale'))
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = \
        get_neighbors_scale(duthost, tbinfo, ipv6, scale_count=bfd_session_cnt)

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
        remove_bfd_sessions(duthost, neighbor_addrs)
        remove_dut_ip(duthost, neighbor_devs, local_addrs, prefix_len)


@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bfd_multihop(request, rand_selected_dut, ptfhost, tbinfo,
                      toggle_all_simulator_ports_to_rand_selected_tor_m, ipv6):    # noqa F811
    duthost = rand_selected_dut

    bfd_session_cnt = int(request.config.getoption('--num_sessions'))
    loopback_addr, ptf_intf, nexthop_ip, neighbor_addrs, dut_intf = get_neighbors_multihop(duthost, tbinfo, ipv6,
                                                                                           count=bfd_session_cnt)
    try:
        cmd_buffer = ""
        for neighbor in neighbor_addrs:
            cmd_buffer += 'sudo ip route add {} via {} ;'.format(neighbor, nexthop_ip)
        duthost.shell(cmd_buffer, module_ignore_errors=True)

        create_bfd_sessions_multihop(ptfhost, duthost, loopback_addr, ptf_intf, neighbor_addrs)

        duthost.shell("sonic-clear queuecounters")
        # sleep for 10 seconds to check queue counters
        time.sleep(10)
        verify_bfd_queue_counters(duthost, dut_intf)

        for neighbor_addr in neighbor_addrs:
            check_dut_bfd_status(duthost, neighbor_addr, "Up")
    finally:
        remove_bfd_sessions(duthost, neighbor_addrs)
        cmd_buffer = ""
        for neighbor in neighbor_addrs:
            cmd_buffer += 'sudo ip route delete {} via {} ;'.format(neighbor, nexthop_ip)
        duthost.shell(cmd_buffer, module_ignore_errors=True)
        ptfhost.command('supervisorctl stop bfd_responder')
        ptfhost.file(path=BFD_RESPONDER_SCRIPT_DEST_PATH, state="absent")


@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bfd_echo_mode(request, rand_selected_dut, ptfhost, tbinfo, ipv6):
    duthost = rand_selected_dut
    bfd_session_cnt = int(request.config.getoption('--num_sessions'))

    # Get neighbors for BFD sessions
    neighbor_addrs = get_neighbors(duthost, tbinfo, ipv6, count=bfd_session_cnt)[2]

    try:
        # Use bfd_echo_mode function for direct configuration
        bfd_echo_mode(duthost, neighbor_addrs)  # Pass None for optional logger

        # Verify BFD sessions with echo mode enabled
        time.sleep(30)  # Wait for BFD sessions to be established
        result = duthost.shell("vtysh -c 'show bfd peer'")['stdout'].split('\n')
        error = False
        for line in result:
            if ('Echo transmission interval:' in line) or (
                    'Echo receive interval:' in line):
                if 'disabled' in line:
                    error = True
        assert error is False
    finally:
        # Cleanup: Remove BFD sessions and echo mode configurations
        remove_bfd_sessions(duthost, neighbor_addrs)

        # No need for temporary BFD echo mode config file or cleanup for it

        # FRR commands to disable bfd instances.
        duthost.shell("vtysh -c 'configure terminal' -c 'no bfd' -c 'end' -c 'do write' -c 'exit'")
