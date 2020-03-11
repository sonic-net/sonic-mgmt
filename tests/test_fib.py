import pytest
from netaddr import *
import time
import logging
import requests
from ptf_runner import ptf_runner
from ansible_host import AnsibleHost
from datetime import datetime 

@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, True, 1514)])
def test_fib(ansible_adhoc, testbed, duthost, ptfhost,ipv4, ipv6, mtu):

    t1_topologies =  ['t1', 't1-lag', 't1-64-lag', 't1-64-lag-clet']
    t0_topologies =  ['t0',  't0-52', 't0-56', 't0-64', 't0-64-32', 't0-116']

    hostname = testbed['dut']
    testbed_type = testbed['topo']['name']
    if testbed_type in t1_topologies:
        props= testbed['topo']['properties']['configuration_properties']['spine']
        props_tor = testbed['topo']['properties']['configuration_properties']['tor']
    elif testbed_type in t0_topologies:
        props = testbed['topo']['properties']['configuration_properties']['common']
        props_tor = None
    else:
        py.test.fail('Unknown testbed topology type {}'.format(testbed_type))

    ans_host = AnsibleHost(ansible_adhoc, hostname)
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    extra_vars = {'testbed_type': testbed_type,
                  'props': props,
                  'props_tor': props_tor,
                  'minigraph_portchannels': mg_facts['minigraph_portchannels'],
                  'minigraph_vlans': mg_facts['minigraph_vlans'],
                  'minigraph_port_indices': mg_facts['minigraph_port_indices'],
                  'minigraph_neighbors': mg_facts['minigraph_neighbors']
    }
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    logging.info("extra_vars: %s" % str(ptfhost.host.options['variable_manager'].extra_vars))

    log_file = "/tmp/fib_test.FibTest.ipv4.{}.ipv6.{}.{}.log".format(ipv4,ipv6,datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    logging.info("PTF log file: %s" % log_file)

    ptfhost.template(src="fib/fib.j2", dest="/root/fib_info.txt")
    ptfhost.copy(src="ptftests", dest="/root")
    logging.info("run ptf test")

    ptf_runner(ptfhost,
                "ptftests",
                "fib_test.FibTest",
                platform_dir="ptftests",
                params={"testbed_type": testbed_type,
                        "router_mac": router_mac,
                        "fib_info": "/root/fib_info.txt",
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "testbed_mtu": mtu },
                log_file=log_file,
                socket_recv_size=16384)
