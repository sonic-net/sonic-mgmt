import pytest
from netaddr import *
import time
import json
import logging
import requests
from ptf_runner import ptf_runner
from datetime import datetime 

logger = logging.getLogger(__name__)

def build_fib(duthost, config_facts, fibfile, t):

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    duthost.shell("redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(t))
    res = duthost.fetch(src="/tmp/fib.{}.txt".format(t), dest="/tmp/fib")

    po = config_facts.get('PORTCHANNEL', {})
    ports = config_facts.get('PORT', {})

    with open("/tmp/fib/{}/tmp/fib.{}.txt".format(duthost.hostname, t)) as fp, \
         open(fibfile, 'w') as ofp:
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


@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, True, 1514)])
def test_fib(testbed, duthost, ptfhost, ipv4, ipv6, mtu):

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    t = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    ofpname = "/tmp/fib/{}/tmp/fib_info.{}.txt".format(duthost.hostname, t)

    build_fib(duthost, config_facts, ofpname, t)

    ptfhost.copy(src=ofpname, dest="/root/fib_info.txt")
    ptfhost.copy(src="ptftests", dest="/root")
    logging.info("run ptf test")

    # do not test load balancing for vs platform as kernel 4.9
    # can only do load balance base on L3
    meta = config_facts.get('DEVICE_METADATA')
    if meta['localhost']['platform'] == 'x86_64-kvm_x86_64-r0':
        test_balancing = False
    else:
        test_balancing = True

    testbed_type = testbed['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
    log_file = "/tmp/fib_test.FibTest.ipv4.{}.ipv6.{}.{}.log".format(ipv4, ipv6, t)
    logging.info("PTF log file: %s" % log_file)
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

@pytest.mark.parametrize("ipv4, ipv6", [pytest.param(True, True)])
def test_hash(testbed, duthost, ptfhost, ipv4, ipv6):

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    t = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    ofpname = "/tmp/fib/{}/tmp/fib_info.{}.txt".format(duthost.hostname, t)

    build_fib(duthost, config_facts, ofpname, t)

    ptfhost.copy(src=ofpname, dest="/root/fib_info.txt")
    ptfhost.copy(src="ptftests", dest="/root")
    logging.info("run ptf test")

    # do not test load balancing on L4 port on vs platform as kernel 4.9
    # can only do load balance base on L3
    hash_srcport = True
    hash_dstport = True
    meta = config_facts.get('DEVICE_METADATA')
    if meta['localhost']['platform'] == 'x86_64-kvm_x86_64-r0':
        hash_srcport = False
        hash_dstport = False

    testbed_type = testbed['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
            
    if ipv4:
        log_file = "/tmp/hash_test.HashTest.ipv4.{}.ipv6.{}.{}.log".format(True, False, t)
        logging.info("PTF log file: %s" % log_file)
    
        src_ip_range = ['8.0.0.0', '9.0.0.0'] 
        dst_ip_range = ['8.0.0.0', '9.0.0.0'] 
        ptf_runner(ptfhost,
                "ptftests",
                "hash_test.HashTest",
                platform_dir="ptftests",
                params={"testbed_type": testbed_type,
                        "router_mac": router_mac,
                        "fib_info": "/root/fib_info.txt",
                        "src_ip_range": ",".join(src_ip_range),
                        "dst_ip_range": ",".join(dst_ip_range),
                        "hash_srcport": hash_srcport,
                        "hash_dstport": hash_dstport,
                        "ipv4": True,
                        "ipv6": False },
                log_file=log_file,
                socket_recv_size=16384)
    if ipv6:
        log_file = "/tmp/hash_test.HashTest.ipv4.{}.ipv6.{}.{}.log".format(False, True, t)
        logging.info("PTF log file: %s" % log_file)
    
        src_ip_range = ['20D0:A800:0:00::', '20D0:A800:0:00::FFFF']
        dst_ip_range = ['20D0:A800:0:00::', '20D0:A800:0:00::FFFF']
        ptf_runner(ptfhost,
                "ptftests",
                "hash_test.HashTest",
                platform_dir="ptftests",
                params={"testbed_type": testbed_type,
                        "router_mac": router_mac,
                        "fib_info": "/root/fib_info.txt",
                        "src_ip_range": ",".join(src_ip_range),
                        "dst_ip_range": ",".join(dst_ip_range),
                        "ipv4": False,
                        "ipv6": True },
                log_file=log_file,
                socket_recv_size=16384)
