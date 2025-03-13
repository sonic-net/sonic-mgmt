import logging
import pytest
import time
import re
import json
from bmp.helper import enable_bmp_neighbor_table, enable_bmp_rib_in_table, enable_bmp_rib_out_table, enable_bmp_feature # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def check_dut_bmp_neighbor_status(duthost, neighbor_addr, expected_state, max_attempts=120, retry_interval=3):
    for i in range(max_attempts + 1):
        bmp_info = duthost.shell("sonic-db-cli BMP_STATE_DB HGETALL 'BGP_NEIGHBOR_TABLE|{}'"
                                 .format(neighbor_addr), module_ignore_errors=False)['stdout_lines']
        logger.info("BMP neighbor state check: {} ".format(neighbor_addr))
        logger.info("sonic-db-cli output: {} ".format(bmp_info))

        parsed_output = json.loads(bmp_info[0].replace("'", "\""))
        if expected_state in parsed_output:
            return  # Success, no need to retry

        logger.info("BMP neighbor state check failed: {} - {}".format(neighbor_addr, bmp_info))
        if i < max_attempts:
            time.sleep(retry_interval)

    assert expected_state in parsed_output  # If all attempts fail, raise an assertion error


def check_dut_bmp_rib_in_status(duthost, neighbor_addr, max_attempts=120, retry_interval=3):
    for i in range(max_attempts + 1):
        bmp_info = duthost.shell("sonic-db-cli BMP_STATE_DB HGETALL 'BGP_RIB_IN_TABLE|*|{}'"
                                 .format(neighbor_addr), module_ignore_errors=False)['stdout_lines']
        logger.info("BMP rib_in state check: {} ".format(neighbor_addr))
        logger.info("sonic-db-cli output: {} ".format(bmp_info))
        entry_num = len(bmp_info)
        if entry_num != 0:
            return  # Success, no need to retry

        logger.error("BMP rib_in state check failed for neighbor: {}".format(neighbor_addr))
        if i < max_attempts:
            time.sleep(retry_interval)

    assert entry_num != 0  # If all attempts fail, raise an assertion error


def check_dut_bmp_rib_out_status(duthost, neighbor_addr, max_attempts=120, retry_interval=3):
    for i in range(max_attempts + 1):
        bmp_info = duthost.shell("sonic-db-cli BMP_STATE_DB HGETALL 'BGP_RIB_OUT_TABLE|*|{}'"
                                 .format(neighbor_addr), module_ignore_errors=False)['stdout_lines']
        logger.info("BMP rib_out state check: {} ".format(neighbor_addr))
        logger.info("sonic-db-cli output: {} ".format(bmp_info))
        entry_num = len(bmp_info)
        if entry_num != 0:
            return  # Success, no need to retry

        logger.error("BMP rib_out state check failed for neighbor: {}".format(neighbor_addr))
        if i < max_attempts:
            time.sleep(retry_interval)

    assert entry_num != 0  # If all attempts fail, raise an assertion error


def get_neighbors(duthost):

    cmd_bgp_summary = 'show ip bgp summary'
    logging.debug("get_neighbors command is: {}".format(cmd_bgp_summary))
    ret = duthost.command(cmd_bgp_summary, module_ignore_errors=True)
    logging.debug("get_neighbors output is: {}".format(ret))
    start_index = ret['stdout'].find("NeighborName")
    neighbor_addrs = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ret['stdout'][start_index:])

    return neighbor_addrs


def get_ipv6_neighbors(duthost):

    cmd_bgp_summary = 'show ipv6 bgp summary'
    logging.debug("get_ipv6_neighbors command is: {}".format(cmd_bgp_summary))
    ret = duthost.command(cmd_bgp_summary, module_ignore_errors=True)
    logging.debug("get_ipv6_neighbors output is: {}".format(ret))
    start_index = ret['stdout'].find("NeighborName")
    neighbor_addrs = re.findall(r'([0-9a-fA-F:]+)', ret['stdout'][start_index:])
    ipv6_addresses = [addr for addr in neighbor_addrs if re.match(
        r'[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}', addr)]

    return ipv6_addresses


def test_bmp_population(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost,
                        enable_bmp_feature): # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # neighbor table - ipv4 neighbor
    # only pick-up sent_cap attributes for typical check first.
    enable_bmp_neighbor_table(duthost)
    neighbor_addrs = get_neighbors(duthost)
    for idx, neighbor_addr in enumerate(neighbor_addrs):
        check_dut_bmp_neighbor_status(duthost, neighbor_addr, "sent_cap")

    # rib_in table - ipv4 neighbor
    enable_bmp_rib_in_table(duthost)
    for idx, neighbor_addr in enumerate(neighbor_addrs):
        check_dut_bmp_rib_in_status(duthost, neighbor_addr)

    # rib_out table - ipv4 neighbor
    enable_bmp_rib_out_table(duthost)
    for idx, neighbor_addr in enumerate(neighbor_addrs):
        check_dut_bmp_rib_out_status(duthost, neighbor_addr)

    # neighbor table - ipv6 neighbor
    # only pick-up recv_cap attributes for typical check first.
    neighbor_v6addrs = get_ipv6_neighbors(duthost)
    for idx, neighbor_v6addr in enumerate(neighbor_v6addrs):
        check_dut_bmp_neighbor_status(duthost, neighbor_v6addr, "recv_cap")

    # rib_in table - ipv6 neighbor
    enable_bmp_rib_in_table(duthost)
    for idx, neighbor_v6addr in enumerate(neighbor_v6addrs):
        check_dut_bmp_rib_in_status(duthost, neighbor_v6addr)

    # rib_out table - ipv6 neighbor
    enable_bmp_rib_out_table(duthost)
    for idx, neighbor_v6addr in enumerate(neighbor_v6addrs):
        check_dut_bmp_rib_out_status(duthost, neighbor_v6addr)
