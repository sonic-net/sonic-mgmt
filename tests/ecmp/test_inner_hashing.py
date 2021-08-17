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

IP_VERSIONS_LIST = ["ipv4", "ipv6"]
TABLE_NAME = "pbh_table"
TABLE_DESCRIPTION = "NVGRE and VXLAN"
HASH_NAME = "inner_hash"
VXLAN_RULE_NAME = "vxlan_{}_{}"
NVGRE_RULE_NAME = "nvgre_{}_{}"
VXLAN_RULE_PRIO = "1"
NVGRE_RULE_PRIO = "2"
ECMP_PACKET_ACTION = "SET_ECMP_HASH"
V4_ETHER_TYPE = "0x0800"
V6_ETHER_TYPE = "0x86dd"
VXLAN_IP_PROTOCOL = "0x11"
NVGRE_IP_PROTOCOL = "0x2f"
VXLAN_L4_DST_PORT = "0x3412"
VXLAN_L4_DST_PORT_OPTION = " --l4-dst-port {}".format(VXLAN_L4_DST_PORT)
ADD_PBH_TABLE_CMD = "sudo config pbh table add '{}' --interface-list '{}' --description '{}'"
DEL_PBH_TABLE_CMD = "sudo config pbh table delete '{}'"
ADD_PBH_RULE_BASE_CMD = "sudo config pbh rule add '{}' '{}' --priority '{}' --ether-type {}" \
                        " --inner-ether-type '{}' --hash '{}' --packet-action '{}' --flow-counter 'ENABLED'"
DEL_PBH_RULE_CMD = "sudo config pbh rule delete '{}' '{}'"
ADD_PBH_HASH_CMD = "sudo config pbh hash add '{}' --hash-field-list '{}'"
DEL_PBH_HASH_CMD = "sudo config pbh hash delete '{}'"
ADD_PBH_HASH_FIELD_CMD = "sudo config pbh hash-field add '{}' --hash-field '{}' --sequence-id '{}'"
DEL_PBH_HASH_FIELD_CMD = "sudo config pbh hash-field delete '{}'"

PBH_HASH_FIELD_LIST = "inner_ip_proto," \
                      "inner_l4_dst_port,inner_l4_src_port," \
                      "inner_dst_ipv4,inner_src_ipv4," \
                      "inner_src_ipv6,inner_dst_ipv6"
HASH_FIELD_CONFIG = {
    "inner_ip_proto": {"field": "INNER_IP_PROTOCOL", "sequence": "1"},
    "inner_l4_dst_port": {"field": "INNER_L4_DST_PORT", "sequence": "2"},
    "inner_l4_src_port": {"field": "INNER_L4_SRC_PORT", "sequence": "2"},
    "inner_src_ipv4": {"field": "INNER_SRC_IPV4", "sequence": "3", "mask": "255.255.255.255"},
    "inner_dst_ipv4": {"field": "INNER_DST_IPV4", "sequence": "3", "mask": "255.255.255.255"},
    "inner_src_ipv6": {"field": "INNER_SRC_IPV6", "sequence": "4", "mask": "ffff:ffff::"},
    "inner_dst_ipv6": {"field": "INNER_DST_IPV6", "sequence": "4", "mask": "ffff:ffff::"}
}


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
def vlan_ptf_ports(config_facts, tbinfo, duthost):
    ports = []
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for vlan_members in config_facts.get('VLAN_MEMBER', {}).values():
        for intf in vlan_members.keys():
            dut_port_index = mg_facts['minigraph_ptf_indices'][intf]
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


@pytest.fixture(scope="module", params=IP_VERSIONS_LIST)
def outer_ipver(request):
    return request.param


@pytest.fixture(scope="module", params=IP_VERSIONS_LIST)
def inner_ipver(request):
    return request.param


@pytest.fixture(scope="module")
def dynamic_pbh(request):
    request.getfixturevalue("config_pbh_table")
    request.getfixturevalue("config_hash_fields")
    request.getfixturevalue("config_hash")
    request.getfixturevalue("config_rules")


@pytest.fixture(scope="module")
def config_pbh_table(duthost, vlan_ptf_ports, tbinfo):
    tested_intfs = []
    # get ports according to chosen ptf ports indices
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for intf, index in mg_facts['minigraph_ptf_indices'].items():
        if index in vlan_ptf_ports:
            tested_intfs.append(intf)
    tested_intfs_str = ",".join(tested_intfs)
    duthost.command(ADD_PBH_TABLE_CMD.format(TABLE_NAME,
                                             tested_intfs_str,
                                             TABLE_DESCRIPTION))

    yield

    duthost.command(DEL_PBH_TABLE_CMD.format(TABLE_NAME))


@pytest.fixture(scope="module")
def config_hash_fields(duthost):
    for hash_filed, hash_filed_params_dict in HASH_FIELD_CONFIG.items():
        cmd = get_hash_filed_add_cmd(hash_filed, hash_filed_params_dict)
        duthost.command(cmd)

    yield

    for hash_filed in HASH_FIELD_CONFIG.keys():
        duthost.command(DEL_PBH_HASH_FIELD_CMD.format(hash_filed))


def get_hash_filed_add_cmd(hash_filed_name, hash_filed_params_dict):
    cmd = ADD_PBH_HASH_FIELD_CMD.format(hash_filed_name,
                                        hash_filed_params_dict["field"],
                                        hash_filed_params_dict["sequence"])
    if "mask" in hash_filed_params_dict:
        cmd += " --ip-mask '{}'".format(hash_filed_params_dict["mask"])
    return cmd


@pytest.fixture(scope="module")
def config_hash(duthost):
    duthost.command(ADD_PBH_HASH_CMD.format(HASH_NAME, PBH_HASH_FIELD_LIST))

    yield

    duthost.command(DEL_PBH_HASH_CMD.format(HASH_NAME))


@pytest.fixture(scope="module")
def config_rules(duthost):
    for ipver in IP_VERSIONS_LIST:
        config_ipv4_rules(duthost, ipver)
        config_ipv6_rules(duthost, ipver)

    yield

    for ipver in IP_VERSIONS_LIST:
        delete_ipv4_rules(duthost, ipver)
        delete_ipv6_rules(duthost, ipver)


def config_ipv4_rules(duthost, inner_ipver):
    config_vxlan_rule(duthost, " --ip-protocol {}", V4_ETHER_TYPE, "ipv4", inner_ipver)
    config_nvgre_rule(duthost, " --ip-protocol {}", V4_ETHER_TYPE, "ipv4", inner_ipver)


def config_ipv6_rules(duthost, inner_ipver):
    config_vxlan_rule(duthost, " --ipv6-next-header {}", V6_ETHER_TYPE, "ipv6", inner_ipver)
    config_nvgre_rule(duthost, " --ipv6-next-header {}", V6_ETHER_TYPE, "ipv6", inner_ipver)


def config_vxlan_rule(duthost, ip_ver_option, ether_type, outer_ipver, inner_ipver):
    inner_ether_type = V4_ETHER_TYPE if inner_ipver == "ipv4" else V6_ETHER_TYPE
    duthost.command((ADD_PBH_RULE_BASE_CMD + ip_ver_option + VXLAN_L4_DST_PORT_OPTION)
                    .format(TABLE_NAME,
                            VXLAN_RULE_NAME.format(outer_ipver, inner_ipver),
                            VXLAN_RULE_PRIO,
                            ether_type,
                            inner_ether_type,
                            HASH_NAME,
                            ECMP_PACKET_ACTION,
                            VXLAN_IP_PROTOCOL,
                            VXLAN_L4_DST_PORT))


def config_nvgre_rule(duthost, ip_ver_option, ether_type, outer_ipver, inner_ipver):
    inner_ether_type = V4_ETHER_TYPE if inner_ipver == "ipv4" else V6_ETHER_TYPE
    duthost.command((ADD_PBH_RULE_BASE_CMD + ip_ver_option)
                    .format(TABLE_NAME,
                            NVGRE_RULE_NAME.format(outer_ipver, inner_ipver),
                            NVGRE_RULE_PRIO,
                            ether_type,
                            inner_ether_type,
                            HASH_NAME,
                            ECMP_PACKET_ACTION,
                            NVGRE_IP_PROTOCOL))


def delete_ipv4_rules(duthost, inner_ipver):
    delete_vxlan_nvgre_rules(duthost, "ipv4", inner_ipver)


def delete_ipv6_rules(duthost, inner_ipver):
    delete_vxlan_nvgre_rules(duthost, "ipv6", inner_ipver)


def delete_vxlan_nvgre_rules(duthost, outer_ipver, inner_ipver):
    duthost.command(DEL_PBH_RULE_CMD.format(TABLE_NAME, VXLAN_RULE_NAME.format(outer_ipver, inner_ipver)))
    duthost.command(DEL_PBH_RULE_CMD.format(TABLE_NAME, NVGRE_RULE_NAME.format(outer_ipver, inner_ipver)))


def test_inner_hashing(duthost, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac,
                       vlan_ptf_ports, symmetric_hashing, build_fib, setup, dynamic_pbh):
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/inner_hash_test.InnerHashTest.{}.{}.{}.log".format(outer_ipver, inner_ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)

    if outer_ipver == "ipv4":
        outer_src_ip_range = SRC_IP_RANGE
        outer_dst_ip_range = DST_IP_RANGE
    else:
        outer_src_ip_range = SRC_IPV6_RANGE
        outer_dst_ip_range = DST_IPV6_RANGE

    if inner_ipver == "ipv4":
        inner_src_ip_range = SRC_IP_RANGE
        inner_dst_ip_range = DST_IP_RANGE
    else:
        inner_src_ip_range = SRC_IPV6_RANGE
        inner_dst_ip_range = DST_IPV6_RANGE

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
