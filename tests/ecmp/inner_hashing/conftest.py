import time
import json
import logging
import tempfile
import re
import allure

from datetime import datetime

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory, change_mac_addresses   # lgtm[py/unused-import]
from tests.common.config_reload import config_reload

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

ACL_DEPENDENCY_TABLES = ["EVERFLOW","EVERFLOWV6"]

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
ADD_PBH_RULE_BASE_CMD = "sudo config pbh rule add '{}' '{}' --priority '{}' --ether-type {}" \
                        " --inner-ether-type '{}' --hash '{}' --packet-action '{}' --flow-counter 'ENABLED'"
ADD_PBH_HASH_CMD = "sudo config pbh hash add '{}' --hash-field-list '{}'"
ADD_PBH_HASH_FIELD_CMD = "sudo config pbh hash-field add '{}' --hash-field '{}' --sequence-id '{}'"

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
def setup(duthosts, rand_one_dut_hostname, teardown):
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.back")

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


@pytest.fixture(scope="module")
def teardown(duthosts, rand_one_dut_hostname):
    """
    Teardown fixture to clean up DUT to initial state

    Args:
        duthosts: All DUTs objects belonging to the testbed
        rand_one_dut_hostname: Hostname of a random chosen dut to run test
    """
    yield
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell("mv /etc/sonic/config_db.json.back /etc/sonic/config_db.json")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)


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
def lag_mem_ptf_ports_groups(config_facts, tbinfo, duthost):
    lag_mem_ptf_ports_groups = []
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for lag_members in config_facts.get('PORTCHANNEL_MEMBER', {}).values():
        lag_group = []
        for intf in lag_members.keys():
            dut_port_index = mg_facts['minigraph_ptf_indices'][intf]
            lag_group.append(dut_port_index)
        lag_mem_ptf_ports_groups.append(lag_group)

    return lag_mem_ptf_ports_groups


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


def setup_lag_config(duthost, lag_port_map, lag_ip_map):
    remove_lag_acl_dependency(duthost)
    add_lag_config(duthost, lag_port_map, lag_ip_map)


def remove_lag_acl_dependency(duthost):
    for acl_table in ACL_DEPENDENCY_TABLES:
        duthost.command("sudo config acl remove table {}".format(acl_table))


def add_lag_config(duthost, lag_port_map, lag_ip_map):
    logging.info('Add LAG configuration')
    with allure.step('Add LAG configuration'):
        for lag_port, port_name in lag_port_map.items():
            duthost.shell('sudo config vlan member del {} {}'.format(T0_VLAN, port_name))
            duthost.shell('sudo config portchannel add {} --fallback enable'.format(lag_port))
            duthost.shell('sudo config portchannel member add {} {}'.format(lag_port, port_name))
            duthost.shell('config interface ip add {} {}'.format(lag_port, lag_ip_map[lag_port]['ipv4']))
            duthost.shell('config interface ip add {} {}'.format(lag_port, lag_ip_map[lag_port]['ipv6']))


def config_pbh_lag(duthost, lag_port_map):
    config_pbh_table_lag(duthost, lag_port_map)
    config_hash_fields(duthost)
    config_hash(duthost)
    config_rules(duthost)


def config_pbh_table_lag(duthost, lag_port_map):
    logging.info("Create PBH table: {}".format(TABLE_NAME))
    test_intfs_str = ",".join(lag_port_map.keys())

    duthost.command(ADD_PBH_TABLE_CMD.format(TABLE_NAME,
                                             test_intfs_str,
                                             TABLE_DESCRIPTION))


def config_pbh(duthost, vlan_ptf_ports, tbinfo):
    config_pbh_table(duthost, vlan_ptf_ports, tbinfo)
    config_hash_fields(duthost)
    config_hash(duthost)
    config_rules(duthost)


def config_pbh_table(duthost, vlan_ptf_ports, tbinfo):
    logging.info("Create PBH table: {}".format(TABLE_NAME))
    test_intfs_str = get_dut_test_intfs_str(duthost, vlan_ptf_ports, tbinfo)

    duthost.command(ADD_PBH_TABLE_CMD.format(TABLE_NAME,
                                             test_intfs_str,
                                             TABLE_DESCRIPTION))


def get_dut_test_intfs_str(duthost, vlan_ptf_ports, tbinfo):
    test_intfs = []
    # get ports according to chosen ptf ports indices
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for intf, index in mg_facts['minigraph_ptf_indices'].items():
        if index in vlan_ptf_ports:
            test_intfs.append(intf)
    return ",".join(test_intfs)


def config_hash_fields(duthost):
    logging.info("Create PBH hash-fields")
    for hash_field, hash_field_params_dict in HASH_FIELD_CONFIG.items():
        cmd = get_hash_field_add_cmd(hash_field, hash_field_params_dict)
        duthost.command(cmd)


def get_hash_field_add_cmd(hash_field_name, hash_field_params_dict):
    cmd = ADD_PBH_HASH_FIELD_CMD.format(hash_field_name,
                                        hash_field_params_dict["field"],
                                        hash_field_params_dict["sequence"])
    if "mask" in hash_field_params_dict:
        cmd += " --ip-mask '{}'".format(hash_field_params_dict["mask"])
    return cmd


def config_hash(duthost):
    logging.info("Create PBH hash: {}".format(HASH_NAME))
    duthost.command(ADD_PBH_HASH_CMD.format(HASH_NAME, PBH_HASH_FIELD_LIST))


def config_rules(duthost):
    logging.info("Create PBH rules")
    for inner_ipver in IP_VERSIONS_LIST:
        config_ipv4_rules(duthost, inner_ipver)
        config_ipv6_rules(duthost, inner_ipver)


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


def get_src_dst_ip_range(ipver):
    if ipver == "ipv4":
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE
    else:
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE
    return src_ip_range, dst_ip_range


def check_pbh_counters(duthost, outer_ipver, inner_ipver, balancing_test_times, symmetric_hashing, hash_keys, ports_groups):
    logging.info('Verify PBH counters')
    with allure.step('Verify PBH counters'):
        symmetric_multiplier = 2 if symmetric_hashing else 1
        exp_ports_multiplier = 0
        for group in ports_groups:
            exp_ports_multiplier += len(group)
        hash_keys_multiplier = len(hash_keys)
        # for hash key "ip-proto", the traffic sends always in one way
        exp_count = str((balancing_test_times * symmetric_multiplier * exp_ports_multiplier * (hash_keys_multiplier-1))
                        + (balancing_test_times * exp_ports_multiplier))
        pbh_statistic_output = duthost.shell("show pbh statistic")['stdout']
        for outer_encap_format in OUTER_ENCAP_FORMATS:
            regex = r'{}\s+{}_{}_{}\s+(\d+)\s+\d+'.format(TABLE_NAME, outer_encap_format, outer_ipver, inner_ipver)
            current_count = re.search(regex, pbh_statistic_output).group(1)
            assert current_count == exp_count,\
                "PBH counters are different from expected for {}, outer ipver {}, inner ipver {}. Expected: {}, " \
                "Current: {}".format(outer_encap_format, outer_ipver, inner_ipver, exp_count, current_count)


@pytest.fixture(scope="function")
def update_rule(duthost, outer_ipver, inner_ipver):
    '''
    This function will update the rules: original, according to given outer/inner IP ver, and its mirrored rule
    (ipv4 -> ipv6 and vice versa).
    The rules will perform each other's actions.
    For example, when given the ipv4-ipv4 rule:
        Before:
               RULE                     MATCH
               vxlan_ipv4_ipv4          ether_type:        0x0800
                                        ip_protocol:       0x11
                                        l4_dst_port:       0x3412
                                        inner_ether_type:  0x0800

                vxlan_ipv6_ipv6         ether_type:        0x86dd
                                        ipv6_next_header:  0x11
                                        l4_dst_port:       0x3412
                                        inner_ether_type:  0x86dd
        After:
                vxlan_ipv4_ipv4         ether_type:        0x86dd
                                        ipv6_next_header:  0x11
                                        l4_dst_port:       0x3412
                                        inner_ether_type:  0x86dd

                vxlan_ipv6_ipv6         ether_type:        0x0800
                                        ip_protocol:       0x11
                                        l4_dst_port:       0x3412
                                        inner_ether_type:  0x0800
    '''

    def update_rule_del(outer_ipver, inner_ipver, option):
        rule_name = encap_format + '_{}_{}'.format(outer_ipver, inner_ipver)
        cmd = 'config pbh rule update field del {} {} --{}'.format(TABLE_NAME, rule_name, option)
        duthost.command(cmd)

    def update_rule_set(outer_ipver, inner_ipver, set_dict):
        rule_name = encap_format + '_{}_{}'.format(outer_ipver, inner_ipver)
        cmd = 'config pbh rule update field set {} {}'.format(TABLE_NAME, rule_name)
        for option, value in set_dict.items():
            cmd += ' --{} {}'.format(option, value)
        duthost.command(cmd)

    # define original and swapped keys and values
    if outer_ipver == "ipv4":
        swapped_outer_ipver = "ipv6"
        ether_type = V4_ETHER_TYPE
        swapped_ether_type = V6_ETHER_TYPE
        prot = 'ip-protocol'
        swapped_prot = 'ipv6-next-header'
    else:
        swapped_outer_ipver = "ipv4"
        ether_type = V6_ETHER_TYPE
        swapped_ether_type = V4_ETHER_TYPE
        prot = 'ipv6-next-header'
        swapped_prot = 'ip-protocol'

    if inner_ipver == "ipv4":
        inner_ether_type = V4_ETHER_TYPE
        swapped_inner_ether_type = V6_ETHER_TYPE
        swapped_inner_ipver = "ipv6"
    else:
        inner_ether_type = V6_ETHER_TYPE
        swapped_inner_ether_type = V4_ETHER_TYPE
        swapped_inner_ipver = "ipv4"

    update_set_dict = {prot: '',
                       'ether-type': ether_type,
                       'inner-ether-type': inner_ether_type}
    swapped_update_set_dict = {swapped_prot: '',
                               'ether-type': swapped_ether_type,
                               'inner-ether-type': swapped_inner_ether_type}

    logging.info(" Update Rules. Swap the configuration of {}_{} and {}_{} rules"
                 .format(outer_ipver, inner_ipver, swapped_outer_ipver, swapped_inner_ipver))
    for encap_format in OUTER_ENCAP_FORMATS:
        prot_value = VXLAN_IP_PROTOCOL if encap_format == 'vxlan' else NVGRE_IP_PROTOCOL

        update_set_dict.update({prot: prot_value})
        swapped_update_set_dict.update({swapped_prot: prot_value})

        update_rule_del(outer_ipver, inner_ipver, prot)
        update_rule_set(outer_ipver, inner_ipver, swapped_update_set_dict)

        update_rule_del(swapped_outer_ipver, swapped_inner_ipver, swapped_prot)
        update_rule_set(swapped_outer_ipver, swapped_inner_ipver, update_set_dict)

    yield

    logging.info(" Restore Updated Rules ")
    for encap_format in OUTER_ENCAP_FORMATS:
        prot_value = VXLAN_IP_PROTOCOL if encap_format == 'vxlan' else NVGRE_IP_PROTOCOL

        update_set_dict.update({prot: prot_value})
        swapped_update_set_dict.update({swapped_prot: prot_value})

        update_rule_del(outer_ipver, inner_ipver, swapped_prot)
        update_rule_set(outer_ipver, inner_ipver, update_set_dict)

        update_rule_del(swapped_outer_ipver, swapped_inner_ipver, prot)
        update_rule_set(swapped_outer_ipver, swapped_inner_ipver, swapped_update_set_dict)
