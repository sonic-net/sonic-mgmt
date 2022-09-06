import pytest
import ptf.testutils as testutils
import logging
import pprint

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m  # lgtm[py/unused-import]
from tests.common.fixtures.duthost_utils import ports_list, utils_vlan_ports_list
from tests.common.utilities import wait_until
from tests.common.helpers.snmp_helpers import get_snmp_facts

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 'm0')
]

# Use original ports intead of sub interfaces for ptfadapter if it's t0-backend
PTF_PORT_MAPPING_MODE = "use_orig_interface"

DUMMY_MAC_PREFIX = "02:11:22:33"

def get_fdb_dynamic_mac_count(duthost):
    res = duthost.command('show mac')
    logger.info('"show mac" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))
    total_mac_count = 0
    for l in res['stdout_lines']:
        if "dynamic" in l.lower() and DUMMY_MAC_PREFIX in l.lower():
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
        assert wait_until(20, 2, 0, fdb_table_has_no_dynamic_macs, duthost), "FDB Table Cleanup failed"


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


@pytest.mark.bsl
def test_snmp_fdb_send_tagged(ptfadapter, utils_vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor_m, duthost, localhost, creds_all_duts):
    """
    Send tagged packets from each port.
    Verify SNMP FDB entry
    """
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    send_cnt = 0
    send_portchannels_cnt = 0
    for vlan_port in utils_vlan_ports_list:
        port_index = vlan_port["port_index"][0]
        for permit_vlanid in map(int, vlan_port["permit_vlanid"]):
            dummy_mac = '{}:{:02x}:{:02x}'.format(DUMMY_MAC_PREFIX, (port_index>>8)&0xFF, port_index&0xFF)
            pkt = build_icmp_packet(permit_vlanid, dummy_mac)
            logger.info("Send tagged({}) packet from {} ...".format(permit_vlanid, port_index))
            logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
            testutils.send(ptfadapter, port_index, pkt)
            send_cnt += 1
            if vlan_port['dev'] in config_portchannels:
                send_portchannels_cnt += 1
    # Flush dataplane
    ptfadapter.dataplane.flush()

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
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
