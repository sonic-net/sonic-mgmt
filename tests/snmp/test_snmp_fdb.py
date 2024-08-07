import pytest
import ptf.testutils as testutils
import logging
import pprint
import time

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.utilities import wait_until
from tests.common.helpers.snmp_helpers import get_snmp_facts
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_orig          # noqa F401
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_add           # noqa F401
from tests.common.helpers.backend_acl import apply_acl_rules, bind_acl_table        # noqa F401
from tests.common.fixtures.duthost_utils import ports_list            # noqa F401
from tests.common.helpers.portchannel_to_vlan import setup_acl_table  # noqa F401
from tests.common.helpers.portchannel_to_vlan import acl_rule_cleanup # noqa F401
from tests.common.helpers.portchannel_to_vlan import vlan_intfs_dict  # noqa F401
from tests.common.helpers.portchannel_to_vlan import setup_po2vlan    # noqa F401
from tests.common.helpers.portchannel_to_vlan import running_vlan_ports_list

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx')
]

# Use original ports intead of sub interfaces for ptfadapter if it's t0-backend
PTF_PORT_MAPPING_MODE = "use_orig_interface"

DUMMY_MAC_PREFIX = "02:11:22:33"


def get_fdb_dynamic_mac_count(duthost):
    res = duthost.command('show mac')
    logger.info('"show mac" output on DUT:\n{}'.format(
        pprint.pformat(res['stdout_lines'])))
    total_mac_count = 0
    for mac in res['stdout_lines']:
        if "dynamic" in mac.lower() and DUMMY_MAC_PREFIX in mac.lower():
            total_mac_count += 1
    return total_mac_count


def fdb_table_has_no_dynamic_macs(duthost):
    return (get_fdb_dynamic_mac_count(duthost) == 0)


@pytest.fixture(scope="module", autouse=True)
def fdb_cleanup(duthost):
    """ cleanup FDB before test run """
    if fdb_table_has_no_dynamic_macs(duthost):
        return
    else:
        duthost.command('sonic-clear fdb all')
        assert wait_until(20, 2, 0, fdb_table_has_no_dynamic_macs,
                          duthost), "FDB Table Cleanup failed"


def build_icmp_packet(vlan_id, src_mac="00:22:00:00:00:02", dst_mac="ff:ff:ff:ff:ff:ff",
                      src_ip="192.168.0.1", dst_ip="192.168.0.2", ttl=64):

    pkt = testutils.simple_icmp_packet(pktlen=100 if vlan_id == 0 else 104,
                                       eth_dst=dst_mac,
                                       eth_src=src_mac,
                                       dl_vlan_enable=False if vlan_id == 0 else True,
                                       vlan_vid=vlan_id,
                                       vlan_pcp=0,
                                       ip_src=src_ip,
                                       ip_dst=dst_ip,
                                       ip_ttl=ttl)
    return pkt


def is_port_channel_up(duthost, config_portchannels):
    portchannel_status = duthost.show_and_parse("show int po")
    portchannel_status_obj = {}
    for item in portchannel_status:
        all_members_up = True
        for port in item["ports"].split(" "):
            all_members_up = all_members_up and port.endswith("(S)")
        portchannel_status_obj[item["team dev"]] = {
            "pc_up": True if item["protocol"].endswith("(Up)") else False,
            "all_members_up": all_members_up
        }
    for portchannel in config_portchannels.keys():
        if portchannel not in portchannel_status_obj:
            return False
        if not (portchannel_status_obj[portchannel]["pc_up"] and
                portchannel_status_obj[portchannel]["all_members_up"]):
            return False
    return True


@pytest.mark.bsl
@pytest.mark.po2vlan
def test_snmp_fdb_send_tagged(ptfadapter, duthosts, rand_one_dut_hostname,          # noqa F811
                              toggle_all_simulator_ports_to_rand_selected_tor_m,    # noqa F811
                              setup_standby_ports_on_rand_unselected_tor,           # noqa F811
                              rand_selected_dut, tbinfo, ports_list, localhost, creds_all_duts): # noqa F811
    """
    Send tagged packets from each port.
    Verify SNMP FDB entry
    """
    duthost = duthosts[rand_one_dut_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")[
        'ansible_facts']
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    assert wait_until(60, 2, 0, is_port_channel_up, duthost, config_portchannels), "Portchannel is not up"
    send_cnt = 0
    send_portchannels_cnt = 0
    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for vlan_port in vlan_ports_list:
        port_index = vlan_port["port_index"][0]
        for permit_vlanid in map(int, vlan_port["permit_vlanid"]):
            dummy_mac = '{}:{:02x}:{:02x}'.format(
                DUMMY_MAC_PREFIX, (port_index >> 8) & 0xFF, port_index & 0xFF)
            pkt = build_icmp_packet(permit_vlanid, dummy_mac)
            logger.info("Send tagged({}) packet from {} ...".format(
                permit_vlanid, port_index))
            logger.info(pkt.sprintf(
                "%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
            testutils.send(ptfadapter, port_index, pkt)
            send_cnt += 1
            if vlan_port['dev'] in config_portchannels:
                send_portchannels_cnt += 1
    # Flush dataplane
    ptfadapter.dataplane.flush()

    time.sleep(20)
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(
        localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
    assert 'snmp_fdb' in snmp_facts
    assert 'snmp_interfaces' in snmp_facts
    dummy_mac_cnt = 0
    recv_portchannels_cnt = 0
    for key in snmp_facts['snmp_fdb']:
        # key is string: vlan.mac
        items = key.split('.')
        if len(items) != 2:
            continue
        logger.info("FDB entry: {}".format(items))
        if DUMMY_MAC_PREFIX in items[1]:
            dummy_mac_cnt += 1
            idx = str(snmp_facts['snmp_fdb'][key])
            assert idx in snmp_facts['snmp_interfaces']
            assert 'name' in snmp_facts['snmp_interfaces'][idx]
            if snmp_facts['snmp_interfaces'][idx]['name'] in config_portchannels:
                recv_portchannels_cnt += 1
    assert send_cnt == dummy_mac_cnt, "Dummy MAC count does not match"
    assert send_portchannels_cnt == recv_portchannels_cnt, "Portchannels count does not match"
