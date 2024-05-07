
import pytest
import ptf.testutils as testutils

import logging
import pprint

from tests.common.fixtures.ptfhost_utils import change_mac_addresses    # noqa F401
from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_orig          # noqa F401
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_add           # noqa F401
from tests.common.helpers.backend_acl import apply_acl_rules, bind_acl_table        # noqa F401
from tests.common.fixtures.duthost_utils import ports_list   # noqa F401
from tests.common.helpers.portchannel_to_vlan import setup_acl_table  # noqa F401
from tests.common.helpers.portchannel_to_vlan import acl_rule_cleanup  # noqa F401
from tests.common.helpers.portchannel_to_vlan import vlan_intfs_dict  # noqa F401
from tests.common.helpers.portchannel_to_vlan import setup_po2vlan    # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses   # noqa F401
from tests.common.helpers.portchannel_to_vlan import running_vlan_ports_list

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx')
]

PTF_PORT_MAPPING_MODE = "use_orig_interface"
DUMMY_MAC_PREFIX = "02:11:22:33"
DUMMY_IP_PREFIX = "188.123"
DUMMY_ARP_COUNT = 10


@pytest.fixture(scope="module")
def skip_dualtor(tbinfo):
    """Skip running `test_tagged_arp` over dualtor."""
    pytest_require("dualtor" not in tbinfo["topo"]["name"], "Skip 'test_tagged_arp' over dualtor.")


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname, skip_dualtor):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


def enable_arp(duthost, cfg_facts, enable):
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    on_cmd = "echo 1 > /proc/sys/net/ipv4/conf/%s/arp_accept"
    off_cmd = "echo 0 > /proc/sys/net/ipv4/conf/%s/arp_accept"
    for vlan in list(vlan_members.keys()):
        if enable:
            logger.info("Enable ARP for %s" % vlan)
            duthost.shell(on_cmd % vlan)
        else:
            logger.info("Disable ARP for %s" % vlan)
            duthost.shell(off_cmd % vlan)


def arp_cleanup(duthost):
    """ cleanup ARP entry """
    duthost.command('sonic-clear arp')


@pytest.fixture(scope="module", autouse=True)
def setup_arp(duthosts, rand_one_dut_hostname, ptfhost, rand_selected_dut, ptfadapter,
                ports_list, tbinfo, vlan_intfs_dict, setup_acl_table, setup_po2vlan, cfg_facts):  # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    # --------------------- Setup -----------------------
    try:
        enable_arp(duthost, cfg_facts, True)
    # --------------------- Testing -----------------------
        yield
    # --------------------- Teardown -----------------------
    finally:
        enable_arp(duthost, cfg_facts, False)
        arp_cleanup(duthost)


def build_arp_packet(vlan_id, neighbor_mac, dst_mac, neighbor_ip):

    pkt = testutils.simple_arp_packet(pktlen=60 if vlan_id == 0 else 64,
                                      eth_dst=dst_mac,
                                      eth_src=neighbor_mac,
                                      vlan_vid=vlan_id,
                                      arp_op=2,
                                      hw_snd=neighbor_mac,
                                      ip_snd=neighbor_ip,
                                      ip_tgt=neighbor_ip)
    return pkt


@pytest.mark.bsl
@pytest.mark.po2vlan
def test_tagged_arp_pkt(ptfadapter, duthosts, rand_one_dut_hostname,
                        rand_selected_dut, tbinfo, ports_list):  # noqa F811
    """
    Send tagged GARP packets from each port.
    Verify packets egress without tag from ports whose PVID same with ingress port.
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    verify show arp command on DUT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    router_mac = duthost.facts['router_mac']
    vlan_ports_list = running_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list)
    for vlan_port in vlan_ports_list:
        port_index = vlan_port["port_index"][0]
        # Send GARP packets to switch to populate the arp table with dummy MACs for each port
        # Totally 10 dummy MACs for each port, send 1 packet for each dummy MAC
        # ARP table will be cleaned up before each iteration, so there won't be any conflict MAC and IP
        dummy_macs = ['{}:{:02x}:{:02x}'.format(DUMMY_MAC_PREFIX, port_index & 0xFF, i + 1)
                      for i in range(DUMMY_ARP_COUNT)]
        dummy_ips = ['{}.{:d}.{:d}'.format(DUMMY_IP_PREFIX, port_index & 0xFF, i + 1)
                     for i in range(DUMMY_ARP_COUNT)]
        for permit_vlanid in map(int, vlan_port["permit_vlanid"]):
            logger.info('Test ARP: interface %s, VLAN %u' % (vlan_port["dev"], permit_vlanid))
            # Perform ARP clean up
            arp_cleanup(duthost)
            for i in range(DUMMY_ARP_COUNT):
                pkt = build_arp_packet(permit_vlanid, dummy_macs[i], router_mac, dummy_ips[i])
                logger.info("Send tagged({}) packet from {} ...".format(permit_vlanid, port_index))
                testutils.send(ptfadapter, port_index, pkt)

            try:
                res = duthost.command('show arp')
                assert res['rc'] == 0
                logger.info('"show arp" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))

                arp_cnt = 0
                for arp_entry in res['stdout_lines']:
                    # Address MacAddress Iface Vlan
                    items = arp_entry.split()
                    if len(items) != 4:
                        continue
                    # Vlan must be number
                    if not items[3].isdigit():
                        continue
                    arp_cnt += 1
                    ip = items[0]
                    mac = items[1]
                    ifname = items[2]
                    vlan_id = int(items[3])
                    assert ip in dummy_ips
                    assert mac in dummy_macs
                    # 'show arp' command gets iface from FDB table,
                    # if 'show arp' command was earlier than FDB table update, ifname would be '-'
                    if ifname == '-':
                        logger.info('Ignore unknown iface...')
                    else:
                        assert ifname == vlan_port["dev"]
                    assert vlan_id == permit_vlanid
                assert arp_cnt == DUMMY_ARP_COUNT, "Expect {} entries, but {} found".format(DUMMY_ARP_COUNT, arp_cnt)
            except Exception as detail:
                logger.error("Except: {}".format(detail))
                # Dump status for debug
                import time
                time.sleep(10)
                res = duthost.command('show mac')
                logger.info('"show mac" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))
                res = duthost.command('show arp')
                logger.info('"show arp" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))
                res = duthost.command('show int counter')
                logger.info('"show int counter" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))
                res = duthost.command('show int portchannel')
                logger.info('"show int portchannel" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))
                raise
