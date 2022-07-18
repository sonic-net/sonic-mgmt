import pytest
import random
import time
import json
import logging
import itertools
import math

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m
from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1', 't1-lag', 't1-64-lag')
]
BFD_SESSIONS_COUNT = 5
SCALED_BFD_SESSIONS_COUNT = 128
IPV4_PREFIX = 31
IPV6_PREFIX = 127


def skip_201911_and_older(duthost):
    """
    Skip the current test if the DUT version is 201911 or older.
    """
    if parse_version(duthost.kernel_version) <= parse_version('4.9.0'):
        pytest.skip("Test not supported for 201911 images or older. Skipping the test")


def is_dualtor(tbinfo):
    """
    Check if the testbed is dualtor.
    """
    return "dualtor" in tbinfo["topo"]["name"]


def add_dut_ip_addrs(duthost, intfs, ips, prefix_len):
    """
    Adding IP addresses on DUT (faster method for scaled test)
    """
    ips_config = {"INTERFACE": {}}
    ips_config_file = duthost.shell('mktemp')['stdout']
    intfs = itertools.cycle(intfs)
    for ip, intf in zip(ips, intfs):
        key = "{}|{}/{}".format(intf, ip, prefix_len)
        ips_config["INTERFACE"][key] = {}

    logger.info('Copying json file to DUT')
    duthost.copy(content=json.dumps(ips_config, indent=4), dest=ips_config_file, verbose=False)
    duthost.shell("sonic-cfggen -j {} --write-to-db".format(ips_config_file))


def update_dut_ip_addrs(duthost, intfs, ips, prefix_len, op='add'):
    """
    Adding/removing IP addresses on DUT
    """
    cmds = ""
    intfs = itertools.cycle(intfs)
    for ip, intf in zip(ips, intfs):
        cmds += 'sudo config interface ip {} {} {}/{}; '.format(op, intf, ip, prefix_len)
    duthost.shell(cmds)


def update_ptf_ip_addrs(ptfhost, intfs, ips, prefix_len, op='add'):
    """
    Adding/removing IP addresses on PTF
    """
    base_cmd = "ip -6 addr" if prefix_len == IPV6_PREFIX else "ip addr"
    ptf_cmds = ''
    intfs = itertools.cycle(intfs)
    for i, (ip, intf) in enumerate(zip(ips, intfs)):
        ptf_cmds += "{} {} {}/{} dev eth{}; ".format(base_cmd, op, ip, prefix_len, intf)
        if i % 100 == 0:  # Dividing the list of cmds because of .shell(cmd) length limitation
            ptfhost.shell(ptf_cmds)
            ptf_cmds = ''
    if ptf_cmds:
        ptfhost.shell(ptf_cmds)


def suspend_bfd_session(ptfhost, ptf_ip, dut_ip):
    """
    Suspending BFD session on PTF.
    Used "suspend" instead of "down", because the session continues to communicate with the remote session
    even in the down state and on the SONiC side it shows "Up".
    """
    ptfhost.shell("bfdd-control session local {} remote {} suspend".format(ptf_ip, dut_ip))


def check_ptf_bfd_status(ptfhost, ptf_ip, dut_ip, expected_state):
    """
    Checks BFD state on PTF
    """
    ptf_bfd_state = ptfhost.shell("bfdd-control status local {} remote {} | "
                                  "grep 'state' | sed 's/state=//g'".format(ptf_ip, dut_ip))["stdout"]
    logger.info("BFD session local {} remote {} in {} state".format(ptf_ip, dut_ip, ptf_bfd_state))
    return expected_state in ptf_bfd_state


def check_dut_bfd_status(duthost, ptf_ip, expected_state):
    """
    Checks BFD state on DUT
    """
    dut_bfd_state = duthost.shell("sonic-db-cli STATE_DB HGET "
                                  "'BFD_SESSION_TABLE|default|default|{}' 'state'".format(ptf_ip))['stdout']
    logger.info("BFD session for {} on DUT in {} state".format(ptf_ip, dut_bfd_state))
    return expected_state in dut_bfd_state


def create_ptf_bfd_sessions(ptfhost, dut_ip_addrs, ptf_ip_addrs):
    """
    Creates BFD sessions for PTF.
    """
    ptf_cmds = ''
    for i, (dut_ip, ptf_ip) in enumerate(zip(dut_ip_addrs, ptf_ip_addrs)):
        ptf_cmds += "bfdd-control connect local {} remote {} ; ".format(ptf_ip, dut_ip)
        if i % 100 == 0:  # Dividing the list of cmds because of .shell(cmd) length limitation
            ptfhost.shell(ptf_cmds)
            ptf_cmds = ''
    if ptf_cmds:
        ptfhost.shell(ptf_cmds)


def update_dut_bfd_sessions(duthost, dut_ip_addrs, ptf_ip_addrs, op):
    """
    Creates or removes BFD sessions for DUT.
    """
    logger.info("Creating a tempfile for BFD sessions")
    bfd_file_dir = duthost.shell('mktemp')['stdout']
    bfd_config = []
    for dut_ip, ptf_ip in zip(dut_ip_addrs, ptf_ip_addrs):
        bfd_config.append({"BFD_SESSION_TABLE:default:default:{}".format(ptf_ip): {"local_addr": dut_ip}, "OP": op})

    logger.info("Copying BFD config json file to DUT")
    duthost.copy(content=json.dumps(bfd_config, indent=4), dest=bfd_file_dir, verbose=False)

    logger.info("Applying BFD session {} with swssconfig".format(op))
    result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(bfd_file_dir))
    if result['rc'] != 0:
        pytest.fail('Failed to apply BFD session configuration file: {}'.format(result['stderr']))


def replace_pc_members(data, intfs):
    """
    Replaces the intf name if it's a member of a PortChannel
    """
    output = []
    for intf in intfs:
        for pc in data['mg_facts']['minigraph_portchannels']:
            if intf in data['mg_facts']['minigraph_portchannels'][pc]['members']:
                output.append(pc)
                break
        else:
            output.append(intf)
    return output


def ip_addr_generator(addr_count, ipv6):
    """
    Generates a certain amount of IPv4 or IPv6 addresses
    """
    base_pattern = "8f::a{:x}:a{:x}:{:x}" if ipv6 else "143.{}.{}.{}"
    for i in range(addr_count):
        fourth_octet = i % 256
        third_octet = (i // 256) % 256
        second_octet = (i // 65536) % 256
        yield base_pattern.format(second_octet, third_octet, fourth_octet)


@pytest.fixture(scope='module')
def data(rand_selected_dut, tbinfo, ptfhost):
    """
    Basic setup data
    """
    duthost = rand_selected_dut
    skip_201911_and_older(duthost)
    data = {'duthost': rand_selected_dut,
            'ptfhost': ptfhost,
            'tbinfo': tbinfo,
            'mg_facts': duthost.get_extended_minigraph_facts(tbinfo),
            'topo_type': tbinfo['topo']['name'],
            't0_intfs': [],
            'ptf_intfs': []}

    for intf in data['mg_facts']['minigraph_neighbors']:
        if 'T0' in data['mg_facts']['minigraph_neighbors'][intf]['name']:
            data['t0_intfs'].append(intf)
    for intf in data['t0_intfs']:
        data['ptf_intfs'].append(data['mg_facts']['minigraph_ptf_indices'][intf])
    return data


def bfd_test_setup(data, ipv6, intfs_count, sessions_count, dut_init_first=True):
    """
    Extends basic data and setting up DUT and PTF
    """
    logger.info('Extending basic data')
    indices = random.sample(list(range(len(data['t0_intfs']))), k=intfs_count)
    data['selected_dut_intfs'] = replace_pc_members(data, [data['t0_intfs'][i] for i in indices])
    data['selected_ptf_intfs'] = [data['ptf_intfs'][i] for i in indices]
    data['prefix_len'] = IPV6_PREFIX if ipv6 else IPV4_PREFIX

    logger.info('Generating lists of IPs')
    ip_gen = ip_addr_generator(sessions_count * 2, ipv6)
    data['dut_ip_addrs'] = []
    data['ptf_ip_addrs'] = []
    for _ in range(sessions_count):
        data['dut_ip_addrs'].append(next(ip_gen))
        data['ptf_ip_addrs'].append(next(ip_gen))

    logger.info('Setting IPs for the selected intfs on DUT')
    if sessions_count == SCALED_BFD_SESSIONS_COUNT:
        add_dut_ip_addrs(data['duthost'], data['selected_dut_intfs'], data['dut_ip_addrs'], data['prefix_len'])
    else:
        update_dut_ip_addrs(data['duthost'], data['selected_dut_intfs'], data['dut_ip_addrs'], data['prefix_len'], op='add')

    logger.info('Setting IPs for the selected intfs on PTF')
    update_ptf_ip_addrs(data['ptfhost'], data['selected_ptf_intfs'], data['ptf_ip_addrs'], data['prefix_len'], op='add')

    logger.info('Initiating BFD on PTF')
    data['ptfhost'].shell("bfdd-beacon")

    logger.info('Creating BFD sessions')
    if dut_init_first:
        update_dut_bfd_sessions(data['duthost'], data['dut_ip_addrs'], data['ptf_ip_addrs'], "SET")
        create_ptf_bfd_sessions(data['ptfhost'], data['dut_ip_addrs'], data['ptf_ip_addrs'])
    else:
        create_ptf_bfd_sessions(data['ptfhost'], data['dut_ip_addrs'], data['ptf_ip_addrs'])
        update_dut_bfd_sessions(data['duthost'], data['dut_ip_addrs'], data['ptf_ip_addrs'], "SET")

    logger.info("Sleeping for {} sec until BFD sessions going UP". format(math.log(sessions_count * 2)))
    time.sleep(math.log(sessions_count * 2))

    return data


def bfd_test_teardown(data, sessions_count, prefix_len):
    """
    Cleanup code after th test. 
    For scaled test using reloading minigraph to get rid of assigned IPs faster
    """   
    logger.info('Removing BFD sessions')
    update_dut_bfd_sessions(data['duthost'], data['dut_ip_addrs'], data['ptf_ip_addrs'], "DEL")
    
    logger.info('Stopping BFD (removing sessions) on PTF.')
    data['ptfhost'].shell("bfdd-control stop", module_ignore_errors=True)

    logger.info('Removing IP addresses on PTF')
    update_ptf_ip_addrs(data['ptfhost'], data['selected_ptf_intfs'], data['ptf_ip_addrs'], prefix_len, op='del')
    
    if sessions_count == SCALED_BFD_SESSIONS_COUNT:
        logger.info("Reloading minigraph")
        config_reload(data['duthost'], config_source='minigraph')
    else:
        update_dut_ip_addrs(data['duthost'], data['selected_dut_intfs'], data['dut_ip_addrs'], prefix_len, op='remove')


@pytest.mark.parametrize('dut_init_first', [True, False], ids=['dut_init_first', 'ptf_init_first'])
@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bfd(data, toggle_all_simulator_ports_to_rand_selected_tor_m, ipv6, dut_init_first):
    try:
        data = bfd_test_setup(data, ipv6, 5, BFD_SESSIONS_COUNT, dut_init_first)
        err_msg = "BFD session in an unexpected state"
        for dut_ip, ptf_ip in zip(data['dut_ip_addrs'], data['ptf_ip_addrs']):
            pytest_assert(wait_until(20, 5, 0, check_ptf_bfd_status, data['ptfhost'], ptf_ip, dut_ip, "Up"), err_msg)
            pytest_assert(wait_until(20, 5, 0, check_dut_bfd_status, data['duthost'], ptf_ip, "Up"), err_msg)

        random_index = random.choice(range(BFD_SESSIONS_COUNT))
        logger.info("Bringing down one BFD session on PTF for {} interface. "
                    "On the DUT side: {}".format(data['ptf_ip_addrs'][random_index], data['dut_ip_addrs'][random_index]))
        suspend_bfd_session(data['ptfhost'], data['ptf_ip_addrs'][random_index], data['dut_ip_addrs'][random_index])

        logger.info("Checking all BFD sessions status")
        for i in range(BFD_SESSIONS_COUNT):
            err_msg = "BFD session in an unexpected state"
            expected_ptf_state = "Suspended" if i == random_index else "Up"
            pytest_assert(wait_until(20, 5, 0, check_ptf_bfd_status, data['ptfhost'],
                                     data['ptf_ip_addrs'][i], data['dut_ip_addrs'][i], expected_ptf_state), err_msg)

            expected_dut_state = "Down" if i == random_index else "Up"
            pytest_assert(wait_until(20, 5, 0, check_dut_bfd_status, data['duthost'],
                                     data['ptf_ip_addrs'][i], expected_dut_state), err_msg)
    finally:
        bfd_test_teardown(data, BFD_SESSIONS_COUNT, data['prefix_len'])


@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bfd_scaled(data, toggle_all_simulator_ports_to_rand_selected_tor_m, ipv6):
    try:
        data = bfd_test_setup(data, ipv6, 1, SCALED_BFD_SESSIONS_COUNT)
        for dut_ip, ptf_ip in zip(data['dut_ip_addrs'], data['ptf_ip_addrs']):
            err_msg = "BFD session in an unexpected state"
            pytest_assert(wait_until(20, 5, 0, check_ptf_bfd_status, data['ptfhost'], ptf_ip, dut_ip, "Up"), err_msg)
            pytest_assert(wait_until(20, 5, 0, check_dut_bfd_status, data['duthost'], ptf_ip, "Up"), err_msg)
        logger.info("Scaled test completed")
    finally:
        bfd_test_teardown(data, SCALED_BFD_SESSIONS_COUNT, data['prefix_len'])
