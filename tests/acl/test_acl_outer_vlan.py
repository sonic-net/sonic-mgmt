"""
Tests Acl Vlan Outer ID match in SONiC.
"""

import os
import time
import logging
import pytest
import ipaddress
import ptf.testutils as testutils

from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

ACL_COUNTERS_UPDATE_INTERVAL = 10
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"
ACL_ADD_RULES_FILE = "acltb_test_rules_outer_vlan.j2"
ACL_RULES_FILE = 'acl_config.json'
TMP_DIR = '/tmp'
ACTION_FORWARD = 'forward'
ACTION_DROP = 'drop'
RULE_1, RULE_2 = 'rule_1', 'rule_2'
TABLES = [{'name': 'DATA_INGRESS_{}', 'stage': 'ingress'},
          {'name': 'DATA_EGRESS_{}', 'stage': 'egress'}]


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    """
    Collect and return ansible config_facts

    Args:
        duthosts: All DUTs objects belonging to the testbed
        rand_one_dut_hostname: Hostname of a random chosen dut to run test

    Returns:
        Collected ansible config_facts
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def ip_version(request):
    """
    Parametrize Ip version

    Args:
        request: pytest request object

    Returns:
        Ip version needed for test case
    """
    return request.param


@pytest.fixture(scope="module")
def vlan_ports_list(cfg_facts, ptfhost, ptfadapter):
    """
    Get Vlan ports list for test run

    Args:
        cfg_facts: Ansible config_facts
        ptfhost: PTF host object

    Returns:
        Vlan ports list for test
    """
    vlan_ports_list = []
    config_ports = cfg_facts['PORT']
    config_port_indices = cfg_facts['port_index_map']
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")

    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_port_channel_member_ports = [config_portchannels[port].get('members')[0] for port in config_portchannels]

    intf_up = [port for port in config_ports if config_ports[port].get('admin_status', 'down') == 'up']
    ports_for_test = [port for port in intf_up if config_port_indices.get(port, '') in
                      ptf_ports_available_in_topo and port not in config_port_channel_member_ports]

    for idx, port in enumerate(ports_for_test[:4]):
        vlan = 100 if idx % 2 == 0 else 200
        vlan_ports_list.append({'port': port,
                                'port_index' : [config_port_indices[port]],
                                'vlan': vlan
                               })

    if config_portchannels:
        for idx, port in enumerate(config_portchannels.keys()[:2]):
            vlan = 100 if idx % 2 == 0 else 200
            vlan_ports_list.append({
                'port': port,
                'port_index' : [config_port_indices[member] for member in config_portchannels[port]['members']],
                'vlan': vlan})

    for table in TABLES:
        if 'INGRESS' in table['name']:
            table['ports'] = [port['port'] for port in vlan_ports_list if port['vlan'] == 200][0]
        else:
            table['ports'] = [port['port'] for port in vlan_ports_list if port['vlan'] == 100][-1]

    return vlan_ports_list


@pytest.fixture(scope="module", autouse=True)
def setup(duthosts, rand_one_dut_hostname, vlan_ports_list, cfg_facts):
    """
    Apply Vlan configuration on the DUT

    Args:
        duthosts: All DUTs objects belonging to the testbed
        rand_one_dut_hostname: Hostname of a random chosen dut to run test
        vlan_ports_list: Vlan ports list
        cfg_facts: Ansible config_facts
    """
    duthost = duthosts[rand_one_dut_hostname]
    portchannel_interfaces = cfg_facts.get('PORTCHANNEL_INTERFACE', {})

    logger.info("Shutdown lags, flush IP addresses")
    for portchannel, ips in portchannel_interfaces.items():
        duthost.command('config interface shutdown {}'.format(portchannel))
        for ip in ips:
            duthost.command('config interface ip remove {} {}'.format(portchannel, ip))

    # Wait some time for route, neighbor, next hop groups to be removed, from PortChannel
    time.sleep(60)

    logger.info("Add vlans")
    for vlan in [100, 200]:
        duthost.command('config vlan add {}'.format(vlan))

    logger.info("Delete Vlan members from Vlan1000, Add members to Vlans")
    for vlan_port in vlan_ports_list:
        if vlan_port['port'] in cfg_facts['VLAN_MEMBER']['Vlan1000']:
            duthost.command('config vlan member del 1000 {}'.format(vlan_port['port']))
        duthost.command('config vlan member add {} {}'.format(
            vlan_port['vlan'],
            vlan_port['port']
            ))

    logger.info("Bringup lags")
    for portchannel in portchannel_interfaces:
        duthost.command('config interface startup {}'.format(portchannel))

    pytest_assert(wait_until(30, 2, check_lag_up, duthost, cfg_facts), "Not all PortChannels are UP")


@pytest.fixture(scope="module")
def vlan_members_index(vlan_ports_list):
    """
    Get vlan members port index

    Args:
        Vlan ports list for test
    Retuns:
        Dict with vlan members port index
    """
    vlan100, vlan200 = [], []
    for port in vlan_ports_list:
        if port['vlan'] == 100:
            vlan100.append(port['port_index'][0])
        elif port['vlan'] == 200:
            vlan200.append(port['port_index'][0])
    return {'100': {'source_port': vlan100[0], 'destination_port': vlan100[-1]},
            '200': {'source_port': vlan200[0], 'destination_port': vlan200[1]}}


@pytest.fixture(scope="class")
def setup_acl(duthosts, rand_one_dut_hostname, ip_version):
    """
    Apply Acl tables and rules needed for test

    Args:
        duthosts: All DUTs objects belonging to the testbed
        rand_one_dut_hostname: Hostname of a random chosen dut to run test
        ip_version: Traffic Ip version
    """
    duthost = duthosts[rand_one_dut_hostname]

    for table in TABLES:
        duthost.command(
            "config acl add table {} {} -s {} -p {}".format(
                table['name'].format(ip_version),
                'L3' if ip_version == 'ipv4' else 'L3V6',
                table['stage'],
                "{}".format(table['ports']),
                )
        )

    extra_vars = {
        'table_ingress': TABLES[0]['name'].format(ip_version),
        'table_egress': TABLES[1]['name'].format(ip_version),
    }

    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
    duthost.template(src=os.path.join(TEMPLATES_DIR, ACL_ADD_RULES_FILE), dest=os.path.join(TMP_DIR, ACL_RULES_FILE))
    duthost.shell("config load -y {}".format(os.path.join(TMP_DIR, ACL_RULES_FILE)))

    pytest_assert(wait_until(60, 2, check_rule_counters, duthost), "Acl rule counters are not ready")

    yield

    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)

    duthost.command("config acl update full {}".format(remove_rules_dut_path))
    duthost.command("config acl remove table {}".format(TABLES[0]['name'].format(ip_version)))
    duthost.command("config acl remove table {}".format(TABLES[1]['name'].format(ip_version)))


def send_and_verify_traffic(ptfadapter, pkt, src_port, dst_port, pkt_action=ACTION_FORWARD):
    """
    Send traffic and verify that traffic was received

    Args:
        ptfadapter: PTF adapter
        pkt: Packet that should be sent
        src_port: Source port
        dst_port: Destination port
        pkt_action: Packet action (forward or drop)
    """
    ptfadapter.dataplane.flush()
    logger.info("Send packet from port {} to port {}".format(src_port, dst_port))
    testutils.send(ptfadapter, src_port, pkt)

    if pkt_action == ACTION_FORWARD:
        testutils.verify_packet(ptfadapter, pkt, dst_port)
    elif pkt_action == ACTION_DROP:
        testutils.verify_no_packet(ptfadapter, pkt, dst_port)

def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL):
    """
    Get Acl counter packets value

    Args:
        duthost: DUT host object
        table_name: Acl Table name
        rule_name: Acl rule name
        timeout: Timeout for Acl counters to update

    Returns:
        Acl counter value for packets
    """
    cmd = "redis-cli -n 2 hget 'COUNTERS:{}:{}' Packets"
    # Wait for orchagent to update the ACL counters
    time.sleep(timeout)
    result = duthost.shell(cmd.format(table_name, rule_name))['stdout']
    return int(result)


def craft_packet(ptfadapter, cfg_facts, ip_version, src_port, dst_port, vlan_id, outer_vlan_id=0, pkt_type=None):
    """
    Generate ipv4/ipv6 packets with single or double Vlan Header

    Args:
        ptfadapter: PTF adapter
        ip_version: Ip version of packet that should be generated
        src_port: Source port
        dst_port: Destination port
        vlan_id: Vlan Id number
        dl_vlan_outer: Outer Vlan ID
        pkt_type: paket type to be created, by default UDP

    Returns:
        Simple UDP, QinQ or TCP packet
    """
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    dst_mac = ptfadapter.dataplane.get_mac(0, dst_port)

    vlan_ips = cfg_facts['VLAN_INTERFACE']['Vlan1000'].keys()
    for ip in vlan_ips:
        if ipaddress.ip_network(ip, strict=False).version == 4:
            ipv4_addr = ipaddress.ip_address(ip.split('/')[0])
        elif ipaddress.ip_network(ip, strict=False).version == 6:
            ipv6_addr = ipaddress.ip_address(ip.split('/')[0])

    if ip_version == 'ipv4':
        ip_src = str(ipv4_addr)
        ip_dst = str(ipv4_addr + 1)

        if pkt_type == 'qinq':
            pkt = testutils.simple_qinq_tcp_packet(eth_dst=dst_mac,
                                                   eth_src=src_mac,
                                                   dl_vlan_outer=outer_vlan_id,
                                                   vlan_vid=vlan_id,
                                                   ip_src=ip_src,
                                                   ip_dst=ip_dst)

        pkt = testutils.simple_udp_packet(eth_dst=dst_mac,
                                          eth_src=src_mac,
                                          dl_vlan_enable=True,
                                          vlan_vid=vlan_id,
                                          ip_dst=ip_dst,
                                          ip_src=ip_src)
    else:
        ip_src = str(ipv6_addr)
        ip_dst = str(ipv6_addr + 1)
        pkt = testutils.simple_tcpv6_packet(eth_dst=dst_mac,
                                            eth_src=src_mac,
                                            dl_vlan_enable=True,
                                            vlan_vid=vlan_id,
                                            ipv6_src=ip_src,
                                            ipv6_dst=ip_dst)
    return pkt


def check_rule_counters(duthost):
    """
    Check if Acl rule counters initialized

    Args:
        duthost: DUT host object
    Returns:
        Bool value
    """
    res = duthost.shell("aclshow -a")['stdout_lines']
    if len(res) <= 2 or [line for line in res if 'N/A' in line]:
        return False
    else:
        return True


def check_lag_up(duthost, cfg_facts):
    """
    Check PortChannels status

    Args:
        duthost: DUT host object
    Returns:
        Bool value
    """
    res = duthost.interface_facts(up_ports=cfg_facts['PORTCHANNEL'].keys())['ansible_facts']["ansible_interface_link_down_ports"]
    if res:
        return False
    return True


@pytest.fixture(scope="module", autouse=True)
def teardown(duthosts, rand_one_dut_hostname):
    """
    Teardown fixture to clean up DUT to initial state

    Args:
        duthosts: All DUTs objects belonging to the testbed
        rand_one_dut_hostname: Hostname of a random chosen dut to run test
    """
    yield
    duthost = duthosts[rand_one_dut_hostname]
    config_reload(duthost)


@pytest.mark.usefixtures('setup_acl')
class TestAclVlanOuter(object):
    """
    TestAclVlanOuter class for testing Acl Vlan Outer ID
    """

    def test_egress_vlan_outer_forward(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                       vlan_members_index, ip_version, cfg_facts):
        """
        Validate that packet is switched if egress ACL rule with action forward is matched with Outer Vlan ID
        """
        duthost = duthosts[rand_one_dut_hostname]
        src_port = vlan_members_index['100']['source_port']
        dst_port = vlan_members_index['100']['destination_port']

        pkt = craft_packet(ptfadapter, cfg_facts, ip_version, src_port=src_port, dst_port=dst_port, vlan_id=100)
        count_before = get_acl_counter(duthost, TABLES[1]['name'].format(ip_version), RULE_1, timeout=0)
        send_and_verify_traffic(ptfadapter, pkt, src_port, dst_port)
        count_after = get_acl_counter(duthost, TABLES[1]['name'].format(ip_version), RULE_1)

        logger.info("Verify Acl counter incremented {} > {}".format(count_after, count_before))
        pytest_assert(count_after == count_before + 1,
                      "Unexpected results, counter_after {} > counter_befoure {}".format(count_after, count_before))


    def test_ingress_vlan_outer_forward(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                        vlan_members_index, ip_version, cfg_facts):
        """
        Validate that packet is switched if ingress ACL rule with action forward is matched with Outer Vlan ID
        """
        duthost = duthosts[rand_one_dut_hostname]
        src_port = vlan_members_index['200']['source_port']
        dst_port = vlan_members_index['200']['destination_port']

        pkt = craft_packet(ptfadapter, cfg_facts, ip_version, src_port=src_port, dst_port=dst_port, vlan_id=200,
                           outer_vlan_id=300, pkt_type='qinq')
        count_before = get_acl_counter(duthost, TABLES[0]['name'].format(ip_version), RULE_1, timeout=0)
        send_and_verify_traffic(ptfadapter, pkt, src_port, dst_port)
        count_after = get_acl_counter(duthost, TABLES[0]['name'].format(ip_version), RULE_1)

        logger.info("Verify Acl counter incremented {} > {}".format(count_after, count_before))
        pytest_assert(count_after == count_before + 1,
                      "Unexpected results, counter_after {} > counter_befoure {}".format(count_after, count_before))


    def test_ingress_vlan_outer_drop(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                     vlan_members_index, ip_version, cfg_facts):
        """
        Validate that packet will be dropped if egress ACL rule with action drop is mathched with Outer Vlan ID
        """
        duthost = duthosts[rand_one_dut_hostname]
        duthost.shell("redis-cli -n 4 del 'ACL_RULE|{}|{}'".format(TABLES[0]['name'].format(ip_version), RULE_1))
        src_port = vlan_members_index['200']['source_port']
        dst_port = vlan_members_index['200']['destination_port']

        pkt = craft_packet(ptfadapter, cfg_facts, ip_version, src_port=src_port, dst_port=dst_port, vlan_id=200,
                           outer_vlan_id=300, pkt_type='qinq')
        count_before = get_acl_counter(duthost, TABLES[0]['name'].format(ip_version), RULE_2, timeout=0)
        send_and_verify_traffic(ptfadapter, pkt, src_port, dst_port, pkt_action=ACTION_DROP)
        count_after = get_acl_counter(duthost, TABLES[0]['name'].format(ip_version), RULE_2)

        logger.info("Verify Acl counter incremented {} > {}".format(count_after, count_before))
        pytest_assert(count_after == count_before + 1,
                      "Unexpected results, counter_after {} > counter_befoure {}".format(count_after, count_before))


    def test_egress_vlan_outer_drop(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                    vlan_members_index, ip_version, cfg_facts):
        """
        Validate that packet will be droped if egress ACL rule with action drop is matched with Outer Vlan ID
        """
        duthost = duthosts[rand_one_dut_hostname]
        duthost.shell("redis-cli -n 4 del 'ACL_RULE|{}|{}'".format(TABLES[1]['name'].format(ip_version), RULE_1))
        src_port = vlan_members_index['100']['source_port']
        dst_port = vlan_members_index['100']['destination_port']

        pkt = craft_packet(ptfadapter, cfg_facts, ip_version, src_port=src_port, dst_port=dst_port, vlan_id=100)
        count_before = get_acl_counter(duthost, TABLES[1]['name'].format(ip_version), RULE_2, timeout=0)
        send_and_verify_traffic(ptfadapter, pkt, src_port, dst_port, pkt_action=ACTION_DROP)
        count_after = get_acl_counter(duthost, TABLES[1]['name'].format(ip_version), RULE_2)

        logger.info("Verify Acl counter incremented {} > {}".format(count_after, count_before))
        pytest_assert(count_after == count_before + 1,
                      "Unexpected results, counter_after {} > counter_befoure {}".format(count_after, count_before))
