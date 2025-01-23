import logging
import pytest
import time
import random
from bmp.helper import enable_bmp_neighbor_table

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def check_dut_bmp_neighbor_status(duthost, neighbor_addr, expected_state, max_attempts=12, retry_interval=10):
    for i in range(max_attempts + 1):
        bmp_info = duthost.shell("redis-cli -n 20 -p 6400 HGETALL 'BGP_NEIGHBOR_TABLE|{}' 'state'"
                                 .format(neighbor_addr), module_ignore_errors=False)['stdout_lines']
        logger.info("BMP state check: {} - {}".format(neighbor_addr, bmp_info[0]))

        if expected_state in bmp_info[0]:
            return  # Success, no need to retry

        logger.error("BMP state check failed: {} - {}".format(neighbor_addr, bmp_info[0]))
        if i < max_attempts:
            time.sleep(retry_interval)

    assert expected_state in bmp_info[0]  # If all attempts fail, raise an assertion error


def get_t0_intfs(mg_facts):
    t0_intfs = []

    for intf in mg_facts['minigraph_neighbors']:
        if 'T0' in mg_facts['minigraph_neighbors'][intf]['name']:
            t0_intfs.append(intf)

    return t0_intfs


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


@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4', 'ipv6'])
def test_bmp_basic(request, rand_selected_dut, ptfhost, tbinfo, ipv6, dut_init_first):
    duthost = rand_selected_dut
    local_addrs, prefix_len, neighbor_addrs, neighbor_devs, neighbor_interfaces = get_neighbors(duthost, tbinfo, ipv6)

    enable_bmp_neighbor_table(duthost)
    time.sleep(1)
    for idx, neighbor_addr in enumerate(neighbor_addrs):
        check_dut_bmp_neighbor_status(duthost, neighbor_addr, "Up")