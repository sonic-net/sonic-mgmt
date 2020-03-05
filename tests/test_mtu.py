import pytest
import pytest
from netaddr import *
import time
import logging
import requests
from ptf_runner import ptf_runner
from ansible_host import AnsibleHost
from datetime import datetime


@pytest.mark.parametrize("mtu", [1514,9114])
def test_mtu(ansible_adhoc, testbed, duthost, ptfhost, mtu):

    hostname = testbed['dut']
    testbed_type = testbed['topo']['name']

    props= testbed['topo']['properties']['configuration_properties']['spine']
    props_tor = testbed['topo']['properties']['configuration_properties']['tor']

    ans_host = AnsibleHost(ansible_adhoc, hostname)
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    log_file = "/tmp/mtu_test.{}-{}.log".format(mtu,datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    logging.info("PTF log file: %s" % log_file)

    logging.info("Starting MTU test")
    ptfhost.copy(src="ptftests", dest="/root")

    ptf_runner(ptfhost,
               "ptftests",
               "mtu_test.MtuTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": router_mac,
                       "testbed_mtu": mtu },
               log_file=log_file,
               socket_recv_size=16384)
