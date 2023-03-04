import random

import pytest
import json
import logging
from tests.common.helpers.assertions import pytest_assert
from natsort import natsorted
import tests.common.utilities as utilities
import time

from RDMA_COMMON import start_cpu_overload, end_cpu_overload, clierr, get_show_result, get_empty_result, clean_data, \
    log_show, start_flow, stop_flow, start_test_module, start_flow_stl, start_flow_v4, start_flow_pfc

CLIOUT_PATH = '/home/test/cliout'

################################################################
pytestmark = [
    pytest.mark.topology('t0')
]
logger = logging.getLogger(__name__)

################################################################

pkt_count = 100
repeat = 10
cell_size = 256
dut_ip = '10.110.199.6'
eth = 6
eth_egress = 5
pfc_interval = 1
bufferProfileIngress = 'ingressBufferProfileTest'
bufferProfileEgress = 'egressBufferProfileTest'


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return get_cfg_facts(duthost)


def get_cfg_facts(duthost):
    tmp_facts = json.loads(
        duthost.shell("sonic-cfggen -d --print-data")['stdout'])  # return config db contents(running-config)
    port_name_list_sorted = natsorted(tmp_facts['PORT'].keys())
    port_index_map = {}
    for idx, val in enumerate(port_name_list_sorted):
        port_index_map[val] = idx
    tmp_facts['config_port_indices'] = port_index_map
    return tmp_facts


@pytest.fixture(scope='module', autouse=True)
def check_config(duthost, nbrhosts):
    global cell_size, dut_ip, eth, eth_egress
    cell_size, dut_ip, eth, eth_egress = start_test_module(duthost, '100G')
    create_test_module(duthost, nbrhosts)
    start_flow_stl(pfc=True)
    yield
    del_test_module(duthost, nbrhosts)
    stop_flow()


def create_test_module(duthost, nbrhosts):
    duthost.shell("sonic-cli -c 'configure terminal' -c 'pfc-deadlock detect-precision 10' "
                  "-c 'pfc-deadlock recovery-action forward' "
                  "-c 'pfc-deadlock queue 0-7 detect-time 10 recovery-time 100' "
                  "-c 'interface Ethernet {}' -c 'pfc-deadlock enable queue 0-7'".format(eth_egress))


def del_test_module(duthost, nbrhosts):
    duthost.shell("sonic-cli -c 'configure terminal' "
                  "-c 'interface Ethernet {}' -c 'no pfc-deadlock enable queue 0-7' "
                  "-c 'exit' -c 'no pfc-deadlock detect-precision 10' "
                  "-c 'no pfc-deadlock recovery-action forward' "
                  "-c 'no pfc-deadlock queue 0-7'".format(eth_egress))
    utilities.log_info("DUT side restore finish")


@pytest.fixture(scope='function', autouse=True)
def check_err(duthost, nbrhosts):
    start_time = duthost.shell('date +"%b %e %H:%M:%S"')['stdout']

    yield
    end_time = duthost.shell('date +"%b %e %H:%M:%S"')['stdout']
    log_show(start_time)
    command = "sudo cat /var/log/message | sed -n '/{}/,/{}/p' | grep ERR".format(start_time, end_time)
    result = duthost.shell(command)['stdout_lines']
    result = [n for n in result if "cat /var/log/message | sed -n" not in n]
    log_show(result)


def set_Buffer_Ingress(duthost, inPort=5):
    log_show("Apply ingress buffer profile in Ethernet {}".format(inPort))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'buffer pool headroom {}'".format(cell_size * 20000))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'buffer profile {} ingress share-static {} "
                  "buffer-size {} headroom {}'".format(bufferProfileIngress, cell_size * 1000, cell_size * 10,
                                                       cell_size * 100))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'interface Ethernet {}' -c 'apply-buffer profile {} "
                  "priority-group 0-7'".format(inPort, bufferProfileIngress))


def set_Buffer_Egress(duthost, outPort=6):
    log_show("Apply egress buffer profile in Ethernet {}".format(outPort))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'buffer profile {} egress share-static {} "
                  "buffer-size {}'".format(bufferProfileEgress, cell_size * 2000, cell_size * 10))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'interface Ethernet {}' -c 'apply-buffer profile {} "
                  "queue 0-7 unicast'".format(outPort, bufferProfileEgress))


def del_Buffer_Ingress(duthost, inPort=5):
    log_show("Del ingress buffer profile in Ethernet {}".format(inPort))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'interface Ethernet {}' -c 'no apply-buffer profile {} "
                  "priority-group 0-7'".format(inPort, bufferProfileIngress))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'no buffer profile {}'".format(bufferProfileIngress))


def del_Buffer_Egress(duthost, outPort=6):
    log_show("Del egress buffer profile in Ethernet {}".format(outPort))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'interface Ethernet {}' -c 'no apply-buffer profile {} "
                  "queue 0-7 unicast'".format(outPort, bufferProfileEgress))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'no buffer profile {}'".format(bufferProfileEgress))


def pfc_statistics(port=6):
    log_show("show pfc statistics Ethernet {}".format(port))
    duthost.shell(
        "sonic-cli -c 'clear queue counters'")
    duthost.shell(
        "sonic-cli -c 'clear pfc statistics'")
    duthost.shell(
        "sonic-cli -c 'show queue counters Ethernet {}'".format(port))
    time.sleep(3)
    duthost.shell(
        "sonic-cli -c 'show queue counters Ethernet {}'".format(port))
    time.sleep(3)
    duthost.shell(
        "sonic-cli -c 'show pfc counters Ethernet {}'".format(port))
    time.sleep(3)
    duthost.shell(
        "sonic-cli -c 'show pfc counters Ethernet {}'".format(port))
    time.sleep(3)


# @pytest.mark.skip(reason='ok')
def test_RDMA_PFC_GN_01(duthost, title=''):
    #########################################################################
    #  -*- coding:utf-8 -*-
    #  name     : test_RDMA_PFC_GN_01
    #  author   : xulei3
    #  contents : 'With buffer profile, pfc enable'
    #  create   : 22-03-02
    #  update   : 22-03-02
    #########################################################################
    title = title + "RDMA_PFC_GN_01"
    utilities.log_info("Test {} Start".format(title))
    try:
        # Apply buffer profile
        set_Buffer_Ingress(duthost, eth)
        # Set priority 0-7
        log_show("Pfc enable priority 0-7")
        duthost.shell(
            "sonic-cli -c 'configure terminal' -c 'interface Ethernet {}' -c 'pfc enable priority 0-7'".format(eth))
        result = get_show_result(duthost, "sonic-cli -c 'show pfc enable Ethernet {}'".format(eth), 2, -1)
        #pytest_assert('7' in result[0][2], "Set pfc priority 7 fail!")

        # Set PFC statistics
        log_show("Pfc statistics enabled")
        duthost.shell(
            "sonic-cli -c 'configure terminal' -c 'pfc statistics enable')
        duthost.shell(
            "sonic-cli -c 'configure terminal' -c 'pfc statistics poll-interval 1')
        #pytest_assert('0,1,2,3,4,5,6,7' in result[0][2], "Set pfc priority 0-6 fail!")

        # Start RDMA traffic
        start_flow_v4()
        log_show("V4 traffic started")

        # pfc class enable vector 00
        start_flow_pfc(ls_octet="00")
        log_show("Pfc packets sent")
        pfc_statistics(port=6)

        # pfc class enable vector 0f
        start_flow_pfc(ls_octet="0f")
        log_show("Pfc packets sent")
        pfc_statistics(port=6)

        # pfc class enable vector ff
        start_flow_pfc(ls_octet="ff")
        log_show("Pfc packets sent")
        pfc_statistics(port=6)
        
    finally:
        duthost.shell(
            "sonic-cli -c 'configure terminal' -c 'interface Ethernet {}' -c 'no pfc enable priority 0-7'".format(eth))
        del_Buffer_Ingress(duthost, eth)
        utilities.log_info("Test {} finish".format(title))


def setPfcDefault(duthost):
    log_show("Set all values to default")
    # duthost.shell("sonic-cli -c 'configure terminal' -c 'no pfc statistics poll-interval'"
    #               " -c 'no pfc statistics enable'")
    duthost.shell("sonic-cli -c 'configure terminal' -c 'interface Ethernet {}' -c 'no pfc asymmetric enable' "
                  "-c 'no pfc enable priority 0-7'".format(eth))
    duthost.shell("sonic-cli -c 'configure terminal' -c 'interface Ethernet {}' -c 'no pfc asymmetric enable' "
                  "-c 'no pfc enable priority 0-7'".format(eth_egress))
    del_Buffer_Ingress(duthost, eth)
    del_Buffer_Egress(duthost, eth_egress)


def checkFunction(duthost, title=''):
    test_RDMA_PFC_GN_01(duthost, title)


