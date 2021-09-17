# Summary: Inner packet hashing test
# How to run this test: sudo ./run_tests.sh -n <tb name> -i <inventory files> -u -m group -e --skip_sanity -l info -c ecmp/test_inner_hashing.py

import time
import json
import logging
import tempfile

from datetime import datetime

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory, change_mac_addresses   # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox')
]

# Standard HASH_KEYs of 'src-ip', 'dst-ip', 'src-port', 'dst-port', 'ip-proto' varied in the inner packets sent and used to validate hashing
# outer-tuples is also used as a HASH_KEY to validate that varying any outer tuples for encap traffic does not affect inner hashing
HASH_KEYS = ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ip-proto', 'outer-tuples']
SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
DST_IP_RANGE = ['9.0.0.0', '9.255.255.255']
SRC_IPV6_RANGE = ['20D0:A800:0:00::', '20D0:A800:0:00::FFFF']
DST_IPV6_RANGE = ['20D0:A800:0:01::', '20D0:A800:0:01::FFFF']
PTF_QLEN = 2000

PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'
FIB_INFO_FILE_DST = '/root/fib_info.txt'

VXLAN_PORT = 13330
DUT_VXLAN_PORT_JSON_FILE = '/tmp/vxlan.switch.json'

@pytest.fixture(scope='module')
def config_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source='running')['ansible_facts']

@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    vxlan_switch_config = [{
        "SWITCH_TABLE:switch": {
            "vxlan_port": VXLAN_PORT
        },
        "OP": "SET"
    }]

    logger.info("Copying vxlan.switch.json with data: " + str(vxlan_switch_config))

    duthost.copy(content=json.dumps(vxlan_switch_config, indent=4), dest=DUT_VXLAN_PORT_JSON_FILE)
    duthost.shell("docker cp {} swss:/vxlan.switch.json".format(DUT_VXLAN_PORT_JSON_FILE))
    duthost.shell("docker exec swss sh -c \"swssconfig /vxlan.switch.json\"")
    time.sleep(3)


@pytest.fixture(scope='module')
def build_fib(duthosts, rand_one_dut_hostname, ptfhost, config_facts, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    duthost.shell("redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(timestamp))
    duthost.fetch(src="/tmp/fib.{}.txt".format(timestamp), dest="/tmp/fib")

    po = config_facts.get('PORTCHANNEL', {})
    ports = config_facts.get('PORT', {})

    tmp_fib_info = tempfile.NamedTemporaryFile()
    with open("/tmp/fib/{}/tmp/fib.{}.txt".format(duthost.hostname, timestamp)) as fp:
        fib = json.load(fp)
        for k, v in fib.items():
            skip = False
            prefix = k.split(':', 1)[1]
            ifnames = v['value']['ifname'].split(',')
            nh = v['value']['nexthop']

            oports = []
            for ifname in ifnames:
                if po.has_key(ifname):
                    oports.append([str(mg_facts['minigraph_ptf_indices'][x]) for x in po[ifname]['members']])
                else:
                    if ports.has_key(ifname):
                        oports.append([str(mg_facts['minigraph_ptf_indices'][ifname])])
                    else:
                        logger.info("Route point to non front panel port {}:{}".format(k, v))
                        skip = True
            # skip direct attached subnet
            if nh == '0.0.0.0' or nh == '::' or nh == "":
                skip = True

            if not skip:
                tmp_fib_info.write("{}".format(prefix))
                for op in oports:
                    tmp_fib_info.write(" [{}]".format(" ".join(op)))
                tmp_fib_info.write("\n")
            else:
                tmp_fib_info.write("{} []\n".format(prefix))
    tmp_fib_info.flush()

    ptfhost.copy(src=tmp_fib_info.name, dest=FIB_INFO_FILE_DST)
    msg = "Copied FIB info to PTF host '{}': local_path={}, remote_path={}"
    logger.info(msg.format(ptfhost.hostname, tmp_fib_info.name, FIB_INFO_FILE_DST))

    tmp_fib_info.close()


@pytest.fixture(scope='module')
def vlan_ptf_ports(config_facts, tbinfo):
    ports = []
    for vlan_members in config_facts.get('VLAN_MEMBER', {}).values():
        for intf in vlan_members.keys():
            dut_port_index = config_facts.get('port_index_map', {})[intf]
            logging.info("Added " + str(dut_port_index))
            ports.append(dut_port_index)

    return ports


@pytest.fixture(scope='module')
def router_mac(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.facts['router_mac']


@pytest.fixture(scope="module")
def hash_keys():
    hash_keys = HASH_KEYS[:]
    return hash_keys


@pytest.fixture(scope="module")
def symmetric_hashing(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    symmetric_hashing = False

    if duthost.facts['asic_type'] in ["mellanox"]:
        symmetric_hashing = True

    return symmetric_hashing


@pytest.fixture(params=["ipv4", "ipv6"])
def ipver(request):
    return request.param

# The test case is expected to fail since some setup is missing.
# Please remove the xfail marker when the issue is fixed.
@pytest.mark.xfail
def test_inner_hashing(hash_keys, ptfhost, ipver, router_mac, vlan_ptf_ports, symmetric_hashing, build_fib, setup):
    logging.info("Executing inner hash test for " + ipver + " with symmetric_hashing set to " + str(symmetric_hashing))
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/inner_hash_test.InnerHashTest.{}.{}.log".format(ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)

    inner_src_ip_range = SRC_IP_RANGE
    inner_dst_ip_range = DST_IP_RANGE

    if ipver == "ipv4":
        outer_src_ip_range = SRC_IP_RANGE
        outer_dst_ip_range = DST_IP_RANGE
    else:
        outer_src_ip_range = SRC_IPV6_RANGE
        outer_dst_ip_range = DST_IPV6_RANGE

    ptf_runner(ptfhost,
            "ptftests",
            "inner_hash_test.InnerHashTest",
            platform_dir="ptftests",
            params={"fib_info": FIB_INFO_FILE_DST,
                    "router_mac": router_mac,
                    "src_ports": vlan_ptf_ports,
                    "hash_keys": hash_keys,
                    "vxlan_port": VXLAN_PORT,
                    "inner_src_ip_range": ",".join(inner_src_ip_range),
                    "inner_dst_ip_range": ",".join(inner_dst_ip_range),
                    "outer_src_ip_range": ",".join(outer_src_ip_range),
                    "outer_dst_ip_range": ",".join(outer_dst_ip_range),
                    "symmetric_hashing": symmetric_hashing},
            log_file=log_file,
            qlen=PTF_QLEN,
            socket_recv_size=16384)
