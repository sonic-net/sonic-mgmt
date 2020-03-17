import pytest
from netaddr import *
import time
import json
import logging
import requests
from ptf_runner import ptf_runner
from ansible_host import AnsibleHost
from datetime import datetime 

logger = logging.getLogger(__name__)

@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, True, 1514)])
def test_fib(ansible_adhoc, testbed, duthost, ptfhost, ipv4, ipv6, mtu):

    hostname = testbed['dut']
    testbed_type = testbed['topo']['name']

    ans_host = AnsibleHost(ansible_adhoc, hostname)
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    po = config_facts.get('PORTCHANNEL', {})
    ports = config_facts.get('PORT', {})
    meta = config_facts.get('DEVICE_METADATA')

    print po
    print mg_facts['minigraph_port_indices']

    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    t = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/fib_test.FibTest.ipv4.{}.ipv6.{}.{}.log".format(ipv4, ipv6, t)
    logging.info("PTF log file: %s" % log_file)

    duthost.shell("redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(t))
    res = duthost.fetch(src="/tmp/fib.{}.txt".format(t), dest="/tmp/fib")

    ofpname = "/tmp/fib/{}/tmp/fib_info.{}.txt".format(duthost.hostname, t)
    with open("/tmp/fib/{}/tmp/fib.{}.txt".format(duthost.hostname, t)) as fp, \
         open(ofpname, 'w') as ofp:
        fib = json.load(fp)

        for k, v in fib.items():
            skip = False
            prefix = k.split(':', 1)[1]
            ifnames = v['value']['ifname'].split(',')
            nh = v['value']['nexthop']

            oports = []
            for ifname in ifnames:
                if po.has_key(ifname):
                    oports.append([str(mg_facts['minigraph_port_indices'][x]) for x in po[ifname]['members']])
                else:
                    if ports.has_key(ifname):
                        oports.append([str(mg_facts['minigraph_port_indices'][ifname])])
                    else:
                        logger.info("Route point to non front panel port {}:{}".format(k, v))
                        skip = True
            # skip direct attached subnet
            if nh == '0.0.0.0' or nh == '::':
                skip = True

            if not skip:
                ofp.write("{}".format(prefix))
                for op in oports:
                    ofp.write(" [{}]".format(" ".join(op)))
                ofp.write("\n")
            else:
                ofp.write("{} []\n".format(prefix))

    ptfhost.copy(src=ofpname, dest="/root/fib_info.txt")
    ptfhost.copy(src="ptftests", dest="/root")
    logging.info("run ptf test")

    # do not test load balancing for vs platform as kernel 4.9
    # can only do load balance base on L3
    if meta['localhost']['platform'] == 'x86_64-kvm_x86_64-r0':
        test_balancing = False
    else:
        test_balancing = True

    ptf_runner(ptfhost,
                "ptftests",
                "fib_test.FibTest",
                platform_dir="ptftests",
                params={"testbed_type": testbed_type,
                        "router_mac": router_mac,
                        "fib_info": "/root/fib_info.txt",
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "testbed_mtu": mtu,
                        "test_balancing": test_balancing },
                log_file=log_file,
                socket_recv_size=16384)
