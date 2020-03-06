import pytest
from netaddr import *
import time
import logging
import requests
from ptf_runner import ptf_runner
from ansible_host import AnsibleHost
from datetime import datetime




def decap_entry_cfg_swss(duthost, decap_setup, outer_ipv4, outer_ipv6, op):
    testbed_type, lo_ipv6, lo_ipv4,dscp_mode, ecn_mode,ttl_mode = decap_setup
    dst_ip = lo_ipv4 if outer_ipv4 is True else lo_ipv6
    extra_vars = {
        'outer_ipv4': outer_ipv4,
        'outer_ipv6': outer_ipv6,
        'lo_ip': lo_ipv4,
        'lo_ipv6': lo_ipv6,
        "dscp_mode": dscp_mode,
        "ecn_mode": ecn_mode,
        "ttl_mode": ttl_mode,
        "op": op
    }

    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
    duthost.template(src="decap/decap_conf.j2", dest="/tmp/decap_conf.json")
    duthost.shell('docker cp /tmp/decap_conf.json swss:/decap_conf.json')
    duthost.shell('docker exec swss sh -c "swssconfig /decap_conf.json"')

def decap_config_ptfhost(ptf_vars,ptfhost):
    ptfhost.host.options['variable_manager'].extra_vars.update(ptf_vars)
    logging.info("extra_vars: %s" % str(ptfhost.host.options['variable_manager'].extra_vars))
    ptfhost.template(src="fib/fib.j2", dest="/root/fib_info.txt")
    ptfhost.copy(src="ptftests", dest="/root")


@pytest.fixture(scope="module")
def decap_setup(ansible_adhoc, testbed,duthost,ptfhost):
    hostname = testbed['dut']
    testbed_type = testbed['topo']['name']

    props= testbed['topo']['properties']['configuration_properties']['spine']
    props_tor = testbed['topo']['properties']['configuration_properties']['tor']

    ans_host = AnsibleHost(ansible_adhoc, hostname)
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    ptf_vars = {'testbed_type': testbed_type,
                  'props': props,
                  'props_tor': props_tor,
                  'minigraph_portchannels': mg_facts['minigraph_portchannels'],
                  'minigraph_vlans': mg_facts['minigraph_vlans'],
                  'minigraph_port_indices': mg_facts['minigraph_port_indices'],
                  'minigraph_neighbors': mg_facts['minigraph_neighbors']
    }

    
    for intf in mg_facts['minigraph_lo_interfaces']:
        addr = intf['addr'].decode("utf-8")
        if ":" in addr:
            lo_ipv6 = addr
        else:
            lo_ipv4 = addr

    dscp_mode =None
    ecn_mode = None
    asic_type= duthost.facts['asic_type']
    
    if asic_type.lower() == 'broadcom' or asic_type.lower() == 'marvell':
        dscp_mode = 'pipe'
        ecn_mode = 'copy_from_outer'
    elif asic_type.lower() == 'mellanox':
        dscp_mode = 'uniform'
        ecn_mode = 'standard'
    ttl_mode = 'pipe'

    decap_config_ptfhost(ptf_vars, ptfhost)

    yield testbed_type, lo_ipv6, lo_ipv4,dscp_mode, ecn_mode,ttl_mode


@pytest.mark.parametrize("outer_ipv4, outer_ipv6", [pytest.param(True, False),pytest.param(False,True)])
def test_decap(decap_setup,duthost, ptfhost,outer_ipv4, outer_ipv6):

    testbed_type, lo_ipv6, lo_ipv4,dscp_mode, ecn_mode,ttl_mode = decap_setup

    decap_entry_cfg_swss(duthost, decap_setup, outer_ipv4, outer_ipv6, "SET")
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    log_file = "/tmp/decap.{}".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    logging.info("PTF log file: %s" % log_file)

    logging.info("run ptf test")

    ptf_runner(ptfhost,
               "ptftests",
               "IP_decap_test.DecapPacketTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": router_mac,
                       "fib_info": "/root/fib_info.txt",
                       "dscp_mode": dscp_mode,
                       "ttl_mode": ttl_mode,
                       "lo_ip": lo_ipv4,
                       "lo_ipv6": lo_ipv6,
                       "outer_ipv4": outer_ipv4,
                        "outer_ipv6": outer_ipv6,
                        "inner_ipv4": True,
                        "inner_ipv6": True,
                },
                log_file=log_file,
                socket_recv_size=16384)

    decap_entry_cfg_swss(duthost, decap_setup, outer_ipv4, outer_ipv6,"SET")

