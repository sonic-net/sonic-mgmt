import time
import json
import logging
import tempfile
import re
import allure

from datetime import datetime

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory, change_mac_addresses   # lgtm[py/unused-import]

logger = logging.getLogger(__name__)


# Standard HASH_KEYs of 'src-ip', 'dst-ip', 'src-port', 'dst-port', 'ip-proto' varied in the inner packets sent and used to validate hashing
# outer-tuples is also used as a HASH_KEY to validate that varying any outer tuples for encap traffic does not affect inner hashing
HASH_KEYS = ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ip-proto', 'outer-tuples']
SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
DST_IP_RANGE = ['9.0.0.0', '9.255.255.255']
SRC_IPV6_RANGE = ['20D0:A800:0:00::', '20D0:A800:0:00::FFFF:FFFF']
DST_IPV6_RANGE = ['20D0:A800:0:01::', '20D0:A800:0:01::FFFF:FFFF']
PTF_QLEN = 2000

PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'
FIB_INFO_FILE_DST = '/root/fib_info.txt'

VXLAN_PORT = 13330
DUT_VXLAN_PORT_JSON_FILE = '/tmp/vxlan.switch.json'

T0_VLAN = "1000"
IP_VERSIONS_LIST = ["ipv4", "ipv6"]
OUTER_ENCAP_FORMATS = ["vxlan", "nvgre"]
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
GRE_KEY = "0x2500"
NVGRE_TNI = 0x25
GRE_MASK = "0xffffff00"
VXLAN_L4_DST_PORT = "0x3412"
VXLAN_L4_DST_PORT_OPTION = " --l4-dst-port {}".format(VXLAN_L4_DST_PORT)
NVGRE_GRE_KEY_OPTION = " --gre-key {}/{}".format(GRE_KEY, GRE_MASK)
ADD_PBH_TABLE_CMD = "sudo config pbh table add '{}' --interface-list '{}' --description '{}'"
DEL_PBH_TABLE_CMD = "sudo config pbh table delete '{}'"
ADD_PBH_RULE_BASE_CMD = "sudo config pbh rule add '{}' '{}' --priority '{}' --ether-type {}" \
                        " --inner-ether-type '{}' --hash '{}' --packet-action '{}' --flow-counter 'ENABLED'"
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
    "inner_src_ipv6": {"field": "INNER_SRC_IPV6", "sequence": "4", "mask": "::ffff:ffff"},
    "inner_dst_ipv6": {"field": "INNER_DST_IPV6", "sequence": "4", "mask": "::ffff:ffff"}
}


def pytest_addoption(parser):
    parser.addoption('--static_config', action='store_true', default=False,
                     help="Test configurations done before the test - static config")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--static_config"):
        # --static_config given in cli: skip test with dynamic config
        skip_dynamic_config = pytest.mark.skip(reason="need to remove '--static_config'"
                                                      " option to run the dynamic config tests")
        for item in items:
            if "dynamic_config" in item.keywords:
                item.add_marker(skip_dynamic_config)
    else:
        skip_static_config = pytest.mark.skip(reason="need '--static_config'"
                                                     " option to run the static config tests")
        for item in items:
            if "static_config" in item.keywords:
                item.add_marker(skip_static_config)


@pytest.fixture(scope='module')
def config_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source='running')['ansible_facts']


@pytest.fixture(scope='module', autouse=True)
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


@pytest.fixture(scope='module', autouse=True)
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
def lag_port_map(duthost, config_facts, vlan_ptf_ports, tbinfo):
    '''
    Create lag-port map for vlan ptf ports
    '''
    portchannels = config_facts.get('PORTCHANNEL', {}).keys()
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_list_idx = 0
    lag_port_map = {}
    port_key_list = list(mg_facts['minigraph_ptf_indices'].keys())
    port_val_list = list(mg_facts['minigraph_ptf_indices'].values())

    for portchannel_idx in range(1, 10000):  # Max len of PortChannel index can be '9999'
        lag_port = 'PortChannel{}'.format(portchannel_idx)

        if lag_port not in portchannels:
            port_idx_value = vlan_ptf_ports[port_list_idx]
            position = port_val_list.index(port_idx_value)
            port_name = port_key_list[position]
            lag_port_map[lag_port] = port_name
            port_list_idx += 1

        if len(lag_port_map) == len(vlan_ptf_ports):
            break

    return lag_port_map


@pytest.fixture(scope='module')
def lag_ip_map(lag_port_map):
    index = 1
    base_ipv4_addr = '100.0.{}.1/31'
    base_ipv6_addr = 'fc00:{}::1/126'
    lag_ip_map = {}

    for lag_port, _ in lag_port_map.items():
        ipv4_addr = base_ipv4_addr.format(index)
        ipv6_addr = base_ipv6_addr.format(index)
        lag_ip_map[lag_port] = {'ipv4': ipv4_addr, 'ipv6': ipv6_addr}
        index += 1

    return lag_ip_map


@pytest.fixture(scope='module')
def config_lag_ports(duthost, lag_port_map, lag_ip_map):
    add_lag_config(duthost, lag_port_map, lag_ip_map)

    yield

    remove_lag_config(duthost, lag_port_map, lag_ip_map)


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
def config_pbh_table_lag(duthost, lag_port_map):
    logging.info("Create PBH table: {}".format(TABLE_NAME))
    test_intfs_str = ",".join(lag_port_map.keys())

    duthost.command(ADD_PBH_TABLE_CMD.format(TABLE_NAME,
                                             test_intfs_str,
                                             TABLE_DESCRIPTION))

    yield

    duthost.command(DEL_PBH_TABLE_CMD.format(TABLE_NAME))


@pytest.fixture(scope="module")
def config_pbh_table(duthost, vlan_ptf_ports, tbinfo):
    logging.info("Create PBH table: {}".format(TABLE_NAME))
    test_intfs_str = get_dut_test_intfs_str(duthost, vlan_ptf_ports, tbinfo)

    duthost.command(ADD_PBH_TABLE_CMD.format(TABLE_NAME,
                                             test_intfs_str,
                                             TABLE_DESCRIPTION))

    yield

    duthost.command(DEL_PBH_TABLE_CMD.format(TABLE_NAME))


def get_dut_test_intfs_str(duthost, vlan_ptf_ports, tbinfo):
    test_intfs = []
    # get ports according to chosen ptf ports indices
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for intf, index in mg_facts['minigraph_ptf_indices'].items():
        if index in vlan_ptf_ports:
            test_intfs.append(intf)
    return ",".join(test_intfs)


@pytest.fixture(scope="module")
def config_hash_fields(duthost):
    logging.info("Create PBH hash-fields")
    for hash_field, hash_field_params_dict in HASH_FIELD_CONFIG.items():
        cmd = get_hash_field_add_cmd(hash_field, hash_field_params_dict)
        duthost.command(cmd)

    yield

    for hash_field in HASH_FIELD_CONFIG.keys():
        duthost.command(DEL_PBH_HASH_FIELD_CMD.format(hash_field))


def get_hash_field_add_cmd(hash_field_name, hash_field_params_dict):
    cmd = ADD_PBH_HASH_FIELD_CMD.format(hash_field_name,
                                        hash_field_params_dict["field"],
                                        hash_field_params_dict["sequence"])
    if "mask" in hash_field_params_dict:
        cmd += " --ip-mask '{}'".format(hash_field_params_dict["mask"])
    return cmd


@pytest.fixture(scope="module")
def config_hash(duthost):
    logging.info("Create PBH hash: {}".format(HASH_NAME))
    duthost.command(ADD_PBH_HASH_CMD.format(HASH_NAME, PBH_HASH_FIELD_LIST))

    yield

    duthost.command(DEL_PBH_HASH_CMD.format(HASH_NAME))


@pytest.fixture(scope="module")
def config_rules(duthost):
    for inner_ipver in IP_VERSIONS_LIST:
        config_ipv4_rules(duthost, inner_ipver)
        config_ipv6_rules(duthost, inner_ipver)

    yield

    for inner_ipver in IP_VERSIONS_LIST:
        delete_ipv4_rules(duthost, inner_ipver)
        delete_ipv6_rules(duthost, inner_ipver)


def config_ipv4_rules(duthost, inner_ipver):
    config_vxlan_rule(duthost, " --ip-protocol {}", V4_ETHER_TYPE, "ipv4", inner_ipver)
    config_nvgre_rule(duthost, " --ip-protocol {}", V4_ETHER_TYPE, "ipv4", inner_ipver)


def config_ipv6_rules(duthost, inner_ipver):
    config_vxlan_rule(duthost, " --ipv6-next-header {}", V6_ETHER_TYPE, "ipv6", inner_ipver)
    config_nvgre_rule(duthost, " --ipv6-next-header {}", V6_ETHER_TYPE, "ipv6", inner_ipver)


def config_vxlan_rule(duthost, ip_ver_option, ether_type, outer_ipver, inner_ipver):
    logging.info("Create PBH rule: {}".format(VXLAN_RULE_NAME.format(outer_ipver, inner_ipver)))
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
    logging.info("Create PBH rule: {}".format(NVGRE_RULE_NAME.format(outer_ipver, inner_ipver)))
    inner_ether_type = V4_ETHER_TYPE if inner_ipver == "ipv4" else V6_ETHER_TYPE
    duthost.command((ADD_PBH_RULE_BASE_CMD + ip_ver_option + NVGRE_GRE_KEY_OPTION)
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


def get_src_dst_ip_range(ipver):
    if ipver == "ipv4":
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE
    else:
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE
    return src_ip_range, dst_ip_range


def check_pbh_counters(duthost, outer_ipver, inner_ipver, balancing_test_times, symmetric_hashing, hash_keys):
    logging.info('Verify PBH counters')
    with allure.step('Verify PBH counters'):
        symmetric_multiplier = 2 if symmetric_hashing else 1
        exp_port_multiplier = 4  # num of POs in t0 topology
        hash_keys_multiplier = len(hash_keys)
        # for hash key "ip-proto", the traffic sends always in one way
        exp_count = str((balancing_test_times * symmetric_multiplier * exp_port_multiplier * (hash_keys_multiplier-1))
                        + (balancing_test_times * exp_port_multiplier))
        pbh_statistic_output = duthost.shell("show pbh statistic")['stdout']
        for outer_encap_format in OUTER_ENCAP_FORMATS:
            regex = r'{}\s+{}_{}_{}\s+(\d+)\s+\d+'.format(TABLE_NAME, outer_encap_format, outer_ipver, inner_ipver)
            current_count = re.search(regex, pbh_statistic_output).group(1)
            assert current_count == exp_count,\
                "PBH counters are different from expected for {}, outer ipver {}, inner ipver {}. Expected: {}, " \
                "Current: {}".format(outer_encap_format, outer_ipver, inner_ipver, exp_count, current_count)


def add_lag_config(duthost, lag_port_map, lag_ip_map):
    logging.info('Add LAG configuration')
    with allure.step('Add LAG configuration'):
        for lag_port, port_name in lag_port_map.items():
            duthost.shell('sudo config vlan member del {} {}'.format(T0_VLAN, port_name))
            duthost.shell('sudo config portchannel add {} --fallback enable'.format(lag_port))
            duthost.shell('sudo config portchannel member add {} {}'.format(lag_port, port_name))
            duthost.shell('config interface ip add {} {}'.format(lag_port, lag_ip_map[lag_port]['ipv4']))
            duthost.shell('config interface ip add {} {}'.format(lag_port, lag_ip_map[lag_port]['ipv6']))


def remove_lag_config(duthost, lag_port_map, lag_ip_map):
    logging.info('Remove LAG configuration')
    with allure.step('Remove LAG configuration'):
        for lag_port, port_name in lag_port_map.items():
            duthost.shell('config interface ip remove {} {}'.format(lag_port, lag_ip_map[lag_port]['ipv4']))
            duthost.shell('config interface ip remove {} {}'.format(lag_port, lag_ip_map[lag_port]['ipv6']))
            duthost.shell('sudo config portchannel member del {} {}'.format(lag_port, port_name))
            duthost.shell('sudo config portchannel del {}'.format(lag_port))
            duthost.shell('sudo config vlan member add {} {} --untagged'.format(T0_VLAN, port_name))
