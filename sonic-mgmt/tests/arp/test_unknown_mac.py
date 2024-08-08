import functools
import inspect
import json
import logging
import pytest
import random
import re
import time

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.common import constants
from tests.common.fixtures.ptfhost_utils import change_mac_addresses    # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py   # noqa F401
from tests.common.fixtures.ptfhost_utils import skip_traffic_test       # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.utilities import get_intf_by_sub_intf, wait_until

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("t0")]

TEST_PKT_CNT = 10


def initClassVars(func):
    """
    Automatically assign instance variables. currently handles only arg list
    """
    names, varargs, keywords, defaults = inspect.getargspec(func)

    @functools.wraps(func)
    def wrapper(self, *args):
        for name, value in list(zip(names[1:], args)):
            setattr(self, name, value)

        func(self, *args)
    return wrapper


@pytest.fixture(autouse=True, scope="module")
def unknownMacSetup(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Fixture to populate all the parameters needed for the test

    Args:
        duthosts(AnsibleHost) : multi dut instance
        rand_one_dut_hostname(string) : one of the dut instances from the multi dut
        tbinfo(TestbedInfo) : testbed info

    Yields:
        setup(dict): dict of vlan, ptf, portchannel intf mappings

    """
    duthost = duthosts[rand_one_dut_hostname]
    # The behavior on Mellanox for unknown MAC is flooding rather than DROP,
    # so we need to skip this test on Mellanox platform
    asic_type = duthost.facts["asic_type"]
    pytest_require(asic_type not in ["mellanox", "barefoot"], "Test is not supported for platform {}".format(asic_type))

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)
    server_ips = []
    if 'dualtor' in tbinfo['topo']['name']:
        servers = mux_cable_server_ip(duthost)
        for ips in list(servers.values()):
            server_ips.append(ips['server_ipv4'].split('/')[0])
            if 'soc_ipv4' in ips:
                server_ips.append(ips['soc_ipv4'].split('/')[0])

    # populate vlan info
    vlan = dict()
    vlan['addr'] = mg_facts['minigraph_vlan_interfaces'][0]['addr']
    vlan['pfx'] = mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']
    vlan['ips'] = duthost.get_ip_in_range(num=1, prefix="{}/{}".format(vlan['addr'], vlan['pfx']),
                                          exclude_ips=[vlan['addr']] + server_ips)['ansible_facts']['generated_ips']
    vlan['hostip'] = vlan['ips'][0].split('/')[0]
    vlan['ports'] = list(mg_facts["minigraph_vlans"].values())[0]["members"]
    # populate dst intf and ptf id
    ptf_portmap = mg_facts['minigraph_ptf_indices']
    dst_port = random.choice(vlan['ports'])
    if is_backend_topology:
        ptf_dst_port = str(ptf_portmap[dst_port]) + constants.VLAN_SUB_INTERFACE_SEPARATOR + \
                       list(mg_facts["minigraph_vlans"].values())[0]["vlanid"]
    else:
        ptf_dst_port = ptf_portmap[dst_port]
    ptf_vlan_ports = [ptf_portmap[ifname] for ifname in vlan['ports']]
    # populate portchannel intf, peer address and ptf ids
    pc = dict()
    intfs = list()
    ptf_ports = dict()
    sub_intfs = set()
    if is_backend_topology:
        for vlan_sub_interface in mg_facts['minigraph_vlan_sub_interfaces']:
            sub_intf_name = vlan_sub_interface['attachto']
            if sub_intf_name in intfs:
                continue
            vlan_id = vlan_sub_interface['vlan']
            intf_name = get_intf_by_sub_intf(sub_intf_name, vlan_id)
            sub_intfs.add(sub_intf_name)
            ptf_ports[sub_intf_name] = (ptf_portmap[intf_name], sub_intf_name,
                                        vlan_sub_interface['peer_addr'],
                                        vlan_id)
            intfs = list(sub_intfs)
    else:
        for key in mg_facts['minigraph_portchannels']:
            value = mg_facts['minigraph_portchannels'][key]
            for item in value['members']:
                intfs.append(item)
                ptf_ports[item] = (ptf_portmap[item], item, None, None)
                pc.setdefault(key, []).append(item)

            for element in mg_facts['minigraph_portchannel_interfaces']:
                if key in element['attachto']:
                    for member in pc[key]:
                        tmp_list = list(ptf_ports[member])
                        tmp_list[2] = element['peer_addr']
                        ptf_ports[member] = tuple(tmp_list)
                    break

    setup = {'vlan': vlan,
             'dst_port': dst_port,
             'ptf_dst_port': ptf_dst_port,
             'ptf_vlan_ports': ptf_vlan_ports,
             'intfs': intfs,
             'ptf_ports': ptf_ports
             }
    yield setup


@pytest.fixture
def flushArpFdb(duthosts, rand_one_dut_hostname):
    """
    Fixture to flush all ARP and FDB entries

    Args:
        duthosts(AnsibleHost) : multi dut instance
        rand_one_dut_hostname(string) : one of the dut instances from the multi dut
    """
    duthost = duthosts[rand_one_dut_hostname]
    logger.info("Clear all ARP and FDB entries on the DUT")
    duthost.shell("sonic-clear fdb all")
    duthost.shell("ip neigh flush all")

    yield

    logger.info("Clear all ARP and FDB entries on the DUT")
    duthost.shell("sonic-clear fdb all")
    duthost.shell("ip neigh flush all")


@pytest.fixture(autouse=True)
def populateArp(unknownMacSetup, flushArpFdb, ptfhost, duthosts, rand_one_dut_hostname,
                toggle_all_simulator_ports_to_rand_selected_tor_m,           # noqa F811
                setup_standby_ports_on_rand_unselected_tor_unconditionally): # noqa F811
    """
    Fixture to populate ARP entry on the DUT for the traffic destination

    Args:
        unknownMacSetup(fixture) : module scope autouse fixture for test setup
        flushArpFdb(fixture) : func scope fixture
        ptfhost(AnsibleHost) : ptf host instance
        duthosts(AnsibleHost) : multi dut instance
        rand_one_dut_hostname(string) : one of the dut instances from the multi dut
    """
    # Wait 5 seconds for mux to toggle
    time.sleep(5)
    setup = unknownMacSetup
    ptfhost.script("./scripts/remove_ip.sh")
    logger.info("Populate ARP entry for dest port")
    ptfhost.command("ifconfig eth{} {}".format(setup['ptf_dst_port'], setup['vlan']['ips'][0]))
    ptfhost.command("ping {} -c 3".format(setup['vlan']['addr']))
    # Wait 5 seconds for secondary ARP before proceeding to clear FDB
    time.sleep(5)

    logger.info("Clean up all ips on the PTF")
    ptfhost.script("./scripts/remove_ip.sh")


class PreTestVerify(object):
    """ Verify ARP and FDB entries are populated correctly """
    def __init__(self, duthost, dst_ip, dst_port):
        """
        Args:
            duthost(AnsibleHost) : dut instance
            dst_ip(string): traffic dest ip
            dst_port(int): ptf id for the dest port
        """
        self.duthost = duthost
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.arp_entry = dict()

    def _checkArpEntryExist(self):
        """
        Check if the ARP entry is present and populate the ARP to mac mapping
        """
        logger.info("Verify if the ARP entry is present for {}".format(self.dst_ip))
        result = self.duthost.command("show arp {}".format(self.dst_ip))
        pytest_assert("Total number of entries 1" in result['stdout'],
                      "ARP entry for {} missing in ASIC".format(self.dst_ip))
        result = self.duthost.shell("ip neigh show {}".format(self.dst_ip))
        pytest_assert(result['stdout_lines'], "{} not in arp table".format(self.dst_ip))
        match = re.match(r"{}.*lladdr\s+(.*)\s+[A-Z]+".format(self.dst_ip),
                         result['stdout_lines'][0])
        pytest_assert(match,
                      "Regex failed while retreiving arp entry for {}".format(self.dst_ip))
        self.arp_entry.update({self.dst_ip: match.group(1)})

    def _checkFdbEntryMiss(self):
        """
        Check if the FDB entry is missing for the port
        """
        result = self.duthost.command("show mac")
        out = result['stdout']
        pytest_assert(self.arp_entry[self.dst_ip].lower() not in out.lower(), "{} present in FDB"
                      .format(self.arp_entry[self.dst_ip]))
        logger.info("'{}' not present in fdb as expected".format(self.arp_entry[self.dst_ip]))

    def verifyArpFdb(self):
        """
        Validate ARP and FDB entries prior to the test run

        Returns:
               arp_entry(dict) : ARP to mac mapping
        """
        self._checkArpEntryExist()
        logger.info("Clear all FDB entries")
        self.duthost.shell("sonic-clear fdb all")
        time.sleep(5)
        self._checkFdbEntryMiss()
        return self.arp_entry


class TrafficSendVerify(object):
    """ Send traffic and check interface counters and ptf ports """
    @initClassVars
    def __init__(self, duthost, ptfadapter, dst_ip, ptf_dst_port, ptf_vlan_ports,
                 intfs, ptf_ports, arp_entry, dscp, skip_traffic_test):     # noqa F811
        """
        Args:
            duthost(AnsibleHost) : dut instance
            ptfadapter(dataplane) : ptf runner instance
            dst_ip(string) : traffic dest ip
            ptf_dst_port(int) : ptf index of dest port
            ptf_vlan_ports(list) : ptf indices of all DUT vlan ports
            intfs(list) : all portchannel members/sub interfaces
            ptf_ports(dict) : mapping of pc member/sub interface to ptf id, peer addr
            arp_entry(dict) : ARP to mac mapping
            dscp(int) : dscp value to be used for the packet that gets send out
        """
        self.pkts = list()
        self.exp_pkts = list()
        self.pkt_map = dict()
        self.pre_rx_drops = dict()
        self.dut_mac = duthost.facts['router_mac']
        self.skip_traffic_test = skip_traffic_test

    def _constructPacket(self):
        """
        Build list of packets to be sent and expected
        """
        for idx, intf in enumerate(self.ptf_ports):
            udp_sport = random.randint(0, 65535)
            udp_dport = random.randint(0, 65535)
            src_port = self.ptf_ports[intf][0]
            src_ip = self.ptf_ports[intf][2]
            vlan_id = self.ptf_ports[intf][3]
            pkt = testutils.simple_udp_packet(eth_dst=self.dut_mac,
                                              eth_src=self.ptfadapter.dataplane.get_mac(0, src_port),
                                              ip_dst=self.dst_ip,
                                              ip_src=src_ip,
                                              ip_tos=self.dscp << 2,
                                              udp_sport=udp_sport,
                                              udp_dport=udp_dport,
                                              ip_ttl=64
                                              )
            self.pkts.append(pkt)
            tmp_pkt = testutils.simple_udp_packet(eth_dst=self.arp_entry[self.dst_ip],
                                                  eth_src=self.dut_mac,
                                                  ip_dst=self.dst_ip,
                                                  ip_src=src_ip,
                                                  ip_tos=self.dscp << 2,
                                                  udp_sport=udp_sport,
                                                  udp_dport=udp_dport,
                                                  ip_ttl=63
                                                  )
            tmp_pkt = mask.Mask(tmp_pkt)
            tmp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
            self.exp_pkts.append(tmp_pkt)
            # if inft is a sub interface, tuple be like ("Eth0.10", "Eth0")
            # if inft is a general interface, tuple be like ("Eth0", "Eth0")
            self.pkt_map[str(pkt)] = (intf, get_intf_by_sub_intf(intf, vlan_id), pkt)

    def _parseCntrs(self):
        """
        Parse the port stats

        Returns:
               stats(dict) : mapping of interface to interface counters
        """
        result = self.duthost.command("portstat -j")["stdout"]
        match = re.search("Last cached time was.*\n", result)
        if match:
            result = re.sub("Last cached time was.*\n", "", result)
        stats = json.loads(result)
        return stats

    def _verifyIntfCounters(self, pretest=False):
        """
        Collect counters before and after the test and verify them

        Args:
            pretest(bool): collect counters before or after the test run
        """
        stats = self._parseCntrs()
        for key, value in list(self.pkt_map.items()):
            intf = value[1]
            if pretest:
                self.pre_rx_drops[intf] = int(stats[intf]['RX_DRP'])
            else:
                actual_cnt = int(stats[intf]['RX_DRP'])
                exp_cnt = self.pre_rx_drops[intf] + TEST_PKT_CNT
                logger.info("Pkt count dropped on interface {}: {}, Expected: {}".format(intf, actual_cnt, exp_cnt))
                if actual_cnt < exp_cnt:
                    return False
        return True

    def verifyIntfCounters(self):
        pytest_assert(wait_until(10, 2, 0, self._verifyIntfCounters),
                      "Drop counters failed to increment")

    def runTest(self):
        """
        Test run and verification
        """
        self._constructPacket()
        logger.info("Clear all counters before test run")
        self.duthost.command("sonic-clear counters")
        if not self.skip_traffic_test:
            time.sleep(1)
            logger.info("Collect drop counters before test run")
            self._verifyIntfCounters(pretest=True)
            for pkt, exp_pkt in zip(self.pkts, self.exp_pkts):
                self.ptfadapter.dataplane.flush()
                out_intf = self.pkt_map[str(pkt)][0]
                src_port = self.ptf_ports[out_intf][0]
                logger.info("Sending traffic on intf {}".format(out_intf))
                testutils.send(self.ptfadapter, src_port, pkt, count=TEST_PKT_CNT)
                testutils.verify_no_packet_any(self.ptfadapter, exp_pkt, ports=self.ptf_vlan_ports)
            logger.info("Collect and verify drop counters after test run")
            self.verifyIntfCounters()


class TestUnknownMac(object):
    @pytest.mark.parametrize("dscp", ["dscp-3", "dscp-4", "dscp-8"])
    def test_unknown_mac(self, unknownMacSetup, dscp, duthosts, rand_one_dut_hostname, ptfadapter, skip_traffic_test):  # noqa F811
        """
        Verify unknown mac behavior for lossless and lossy priority

        This test ensures that packets send on lossless and lossy priority get dropped
        when the arp to mac mapping is present in the arp table and mac to port mapping
        is absent in the mac table

        Args:
            unknownMacSetup(fixture) : module scope autouse fixture for test setup
            dscp(string) : parametrized values for dscp
            duthosts(AnsibleHost) : multi dut instance
            rand_one_dut_hostname(AnsibleHost) : one of the dut instances from the multi dut
            ptfadapter(dataplane) : ptf runner instance
        """
        setup = unknownMacSetup
        self.dscp = int(dscp.split("-")[-1])
        self.duthost = duthosts[rand_one_dut_hostname]
        self.ptfadapter = ptfadapter
        self.dst_port = setup['dst_port']
        self.ptf_dst_port = setup['ptf_dst_port']
        self.dst_ip = setup['vlan']['hostip']
        self.vlan_ports = setup['vlan']['ports']
        self.ptf_vlan_ports = setup['ptf_vlan_ports']
        self.intfs = setup['intfs']
        self.ptf_ports = setup['ptf_ports']
        self.skip_traffic_test = skip_traffic_test
        self.validateEntries()
        self.run()

    def validateEntries(self):
        """
        Validate ARP and FDB prior to the test run
        """
        pre_handle = PreTestVerify(self.duthost, self.dst_ip, self.dst_port)
        self.arp_entry = pre_handle.verifyArpFdb()

    def run(self):
        """
        Traffic test and verification
        """
        thandle = TrafficSendVerify(self.duthost, self.ptfadapter, self.dst_ip, self.ptf_dst_port,
                                    self.ptf_vlan_ports,
                                    self.intfs, self.ptf_ports,
                                    self.arp_entry, self.dscp, self.skip_traffic_test)
        thandle.runTest()
