"""Test neighbor lifecycle on VoQ chassis."""
import logging
import pytest
import time
import random
from scapy.all import Ether
from scapy.layers.l2 import Dot1Q
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

from tests.common.helpers.parallel import parallel_run
from tests.common.helpers.parallel import reset_ansible_local_tmp

from voq_helpers import get_neighbor_info
from voq_helpers import get_port_by_ip
from voq_helpers import check_all_neighbors_present, check_one_neighbor_present
from voq_helpers import asic_cmd, sonic_ping
from voq_helpers import check_neighbor_is_gone

from ptf.testutils import simple_arp_packet, send_packet, ip_make_tos, MINSIZE

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]

NEW_MAC = "00:01:94:00:00:01"


@pytest.fixture(scope="module")
def setup(duthosts, nbrhosts, all_cfg_facts):
    """
    Setup fixture to disable all neighbors on DUT and VMs.

    Args:
        duthosts: Duthosts fixture
        nbrhosts: Nbrhosts fixture
        all_cfg_facts: all_cfg_facts fixture from voq/conftest.py

    """

    @reset_ansible_local_tmp
    def disable_dut_bgp_neighs(cfg_facts, node=None, results=None):
        """Target function do disable BGP neighbors on sonic DUTs.

        Args:
            cfg_facts: instance of fixture from voq/conftest.py
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        node_results = []
        for asic in node.asics:
            asic_cfg_facts = cfg_facts[node.hostname][asic.asic_index]['ansible_facts']
            logger.info('disable neighbors {} on dut host {}'.format(asic_cfg_facts['BGP_NEIGHBOR'], node.hostname))

            for neighbor in asic_cfg_facts['BGP_NEIGHBOR']:
                logger.info(
                    "Shut down neighbor: {} on host {} asic {}".format(neighbor, node.hostname, asic.asic_index))

                node_results.append(node.command("sudo config bgp shutdown neighbor {}".format(neighbor)))

        results[node['host'].hostname] = node_results

    parallel_run(disable_dut_bgp_neighs, [all_cfg_facts], {}, duthosts.frontend_nodes, timeout=120)

    # disable bgp neighbors on vms
    @reset_ansible_local_tmp
    def disable_nbr_bgp_neighs(node=None, results=None):
        """Target function to disable bgp neighbors on VMS.

        Args:
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        node_results = []
        logger.info(
            'disable neighbors {} on neighbor host {}'.format(node['conf']['bgp']['peers'], node['host'].hostname))
        for peer in node['conf']['bgp']['peers']:
            for neighbor in node['conf']['bgp']['peers'][peer]:
                node_results.append(node['host'].eos_config(
                    lines=["neighbor %s shutdown" % neighbor],
                    parents=['router bgp {}'.format(node['conf']['bgp']['asn'])],
                    module_ignore_errors=True)
                )
                if ":" in neighbor:
                    node_results.append(node['host'].eos_config(
                        lines=["ipv6 route ::/0 %s " % neighbor],
                        module_ignore_errors=True)
                    )
                else:
                    node_results.append(node['host'].eos_config(
                        lines=["ip route 0.0.0.0/0 %s " % neighbor],
                        module_ignore_errors=True)
                    )

        results[node['host'].hostname] = node_results

    parallel_run(disable_nbr_bgp_neighs, [], {}, nbrhosts.values(), timeout=120)

    yield

    # cleanup

    # restore neighbors on duts
    @reset_ansible_local_tmp
    def enable_dut_bgp_neighs(cfg_facts, node=None, results=None):
        """Target function to enable BGP neighbors on the sonic hosts..

        Args:
            cfg_facts: Instance of all_cfg_facts fixture from voq/conftest.py
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        node_results = []
        for asic in node.asics:
            asic_cfg_facts = cfg_facts[node.hostname][asic.asic_index]['ansible_facts']
            logger.info('enable neighbors {} on dut host {}'.format(asic_cfg_facts['BGP_NEIGHBOR'], node.hostname))
            asnum = asic_cfg_facts['DEVICE_METADATA']['localhost']['bgp_asn']

            for neighbor in asic_cfg_facts['BGP_NEIGHBOR']:
                logger.info(
                    "Startup neighbor: {} on host {} asic {}".format(neighbor, node.hostname, asic.asic_index))

                node_results.append(node.command("sudo config bgp startup neighbor {}".format(neighbor)))
                node_results.append(node.command(
                    "docker exec bgp vtysh -c \"config t\" -c \"router bgp {}\" -c \"no neighbor {} shutdown\"".format(
                        asnum, neighbor)))

        results[node['host'].hostname] = node_results

    parallel_run(enable_dut_bgp_neighs, [all_cfg_facts], {}, duthosts.frontend_nodes, timeout=120)

    # restore neighbors on vms
    @reset_ansible_local_tmp
    def enable_nbr_bgp_neighs(node=None, results=None):
        """Target function to enable BGP neighbors on VMs.

        Args:
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        node_results = []
        logger.info(
            'enable neighbors {} on neighbor host {}'.format(node['conf']['bgp']['peers'], node['host'].hostname))
        for peer in node['conf']['bgp']['peers']:
            for neighbor in node['conf']['bgp']['peers'][peer]:
                node_results.append(node['host'].eos_config(
                    lines=["no neighbor %s shutdown" % neighbor],
                    parents=['router bgp {}'.format(node['conf']['bgp']['asn'])],
                    module_ignore_errors=True)
                )
                if ":" in neighbor:
                    node_results.append(node['host'].eos_config(
                        lines=["no ipv6 route ::/0 %s " % neighbor],
                        module_ignore_errors=True)
                    )
                else:
                    node_results.append(node['host'].eos_config(
                        lines=["no ip route 0.0.0.0/0 %s " % neighbor],
                        module_ignore_errors=True)
                    )

        results[node['host'].hostname] = node_results

    parallel_run(enable_nbr_bgp_neighs, [], {}, nbrhosts.values(), timeout=120)


def ping_all_dut_local_nbrs(duthosts):
    """
    Pings all neighbors locally attached to each frontend node on the DUT.

    Args:
        duthosts: An instance of the duthosts fixture.

    """
    logger.info("Pinging neighbors to establish ARP")
    for per_host in duthosts.frontend_nodes:
        for asic in per_host.asics:
            cfg_facts = asic.config_facts(source="persistent")['ansible_facts']
            neighs = cfg_facts['BGP_NEIGHBOR']
            for neighbor in neighs:
                sonic_ping(asic, neighbor)


def ping_all_neighbors(duthosts, neighbors):
    """
    Pings all neighbors in the neighbor list from all frontend hosts on the DUT..

    Args:
        duthosts: An instance of the duthosts fixture.
        neighbors: A list of neighbor IP addresses.

    """
    for per_host in duthosts.frontend_nodes:
        for asic in per_host.asics:
            for neighbor in neighbors:
                logger.info("Ping %s from %s/%s", neighbor, per_host.hostname, asic.asic_index)
                sonic_ping(asic, neighbor)


@pytest.fixture()
def established_arp(duthosts):
    """
    Fixture to establish ARP to all neighbors at start of test.

    Args:
        duthosts: Instance of duthosts fixture.
    """
    ping_all_dut_local_nbrs(duthosts)


@pytest.fixture()
def cleared_arp(duthosts):
    """
    Fixture to clear ARP an NDP on all neighbors at start of test.

    Args:
        duthosts: Instance of duthosts fixture.
    """
    for per_host in duthosts.frontend_nodes:
        for asic in per_host.asics:
            asic_cmd(asic, "sonic-clear arp")
            asic_cmd(asic, "sonic-clear ndp")


def test_neighbor_clear_all(duthosts, setup, nbrhosts, all_cfg_facts, established_arp):
    """
    Verify tables, databases, and kernel routes are correctly deleted when the entire neighbor table is cleared.

    Test Steps
    * On local linecard:
        * Issue `sonic-clear arp` command. and verify all addresses are removed and kernel routes are deleted on
          all hosts and ASICs.
        * Verify ARP/NDP entries are removed from CLI.
        * Verify table entries in ASIC, AppDb are removed for all cleared addresses.
    * On Supervisor card:
        * Verify Chassis App DB entry are removed for only the cleared address.  Entries for addresses on other line
        cards should still be present.
    * On remote linecards:
        * Verify table entries in ASICDB, APPDB, and host ARP table are removed for cleared addresses.
        * Verify kernel routes for cleared address are deleted.
    * Send full mesh traffic and verify relearn and DB.

    Args:
        duthosts: duthosts fixture.
        setup: setup fixture for this module.
        nbrhosts: nbrhosts fixture.
        all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
        established_arp: Fixture to establish ARP to all neighbors.

    """
    all_neighbors = []

    for per_host in duthosts.frontend_nodes:
        for asic in per_host.asics:
            asic_cmd(asic, "sonic-clear arp")
            asic_cmd(asic, "sonic-clear ndp")
            time.sleep(1)

            cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']
            neighs = cfg_facts['BGP_NEIGHBOR']

            for neighbor in neighs:
                all_neighbors.append(neighbor)
                check_neighbor_is_gone(duthosts, all_cfg_facts, per_host, asic, neighbor)

    # relearn and check
    logger.info("Relearn neighbors on all nodes")
    ping_all_dut_local_nbrs(duthosts)
    ping_all_neighbors(duthosts, all_neighbors)
    check_all_neighbors_present(duthosts, nbrhosts, all_cfg_facts)


def test_neighbor_clear_one(duthosts, setup, nbrhosts, all_cfg_facts, established_arp):
    """
    Verify tables, databases, and kernel routes are correctly deleted when a single neighbor adjacency is cleared.

    Test Steps
    * On local linecard:
        * Clear single address with command:  `ip neigh flush to "addr"`.
        * Verify ARP/NDP entry removed from CLI.
        * Verify table entries in ASIC, AppDb are removed for only the cleared address.
    * On Supervisor card:
        * Verify Chassis App DB entry are removed for only the cleared address.
    * On remote linecards:
        * Verify table entries in ASICDB, APPDB, and host ARP table are removed.
        * Verify kernel route for cleared address is deleted.
    * Restart traffic, verify relearn.

    Args:
        duthosts: duthosts fixture.
        setup: setup fixture for this module.
        nbrhosts: nbrhosts fixture.
        all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
        established_arp: Fixture to establish ARP to all neighbors.

    """
    all_neighbors = []
    for per_host in duthosts.frontend_nodes:

        for asic in per_host.asics:
            cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']
            neighs = cfg_facts['BGP_NEIGHBOR']

            for neighbor in neighs:
                logger.info(
                    "Flushing neighbor: {} on host {}/{}".format(neighbor, per_host.hostname, asic.asic_index))
                asic_cmd(asic, "ip neigh flush to %s" % neighbor)
                all_neighbors.append(neighbor)
                check_neighbor_is_gone(duthosts, all_cfg_facts, per_host, asic, neighbor)

    # relearn and check
    logger.info("Relearn neighbors on all nodes")
    ping_all_dut_local_nbrs(duthosts)
    logger.info("Check neighbor relearn on all nodes.")
    check_all_neighbors_present(duthosts, nbrhosts, all_cfg_facts)


def change_mac(nbr, intf, mac):
    """
    Change the mac of a CEOS interface on the linux host OS.

    Args:
        nbr: Instance of the neighbor host.
        intf: Interface to change in linux interface format. (ethX)
        mac: New MAC address


    """
    nbr['host'].command("sudo ifconfig {} down".format(intf))
    nbr['host'].command("sudo ifconfig {} hw ether {}".format(intf, mac))
    nbr['host'].command("sudo ifconfig {} up".format(intf))


def change_mac_ptf(ptfhost, intf, mac):
    """
    Change the mac of an interface on the PTF.

    Args:
        ptfhost: ptfhost fixture.
        intf: Interface to change in linux interface format. (ethX)
        mac: New MAC address

    """
    ptfhost.shell("ifconfig {} down".format(intf))
    ptfhost.shell("ifconfig {} hw ether {}".format(intf, mac))
    ptfhost.shell("ifconfig {} up".format(intf))


def check_arptable_mac(host, neighbor, mac, checkstate=True):
    arptable = host.switch_arptable()['ansible_facts']

    if ':' in neighbor:
        table = arptable['arptable']['v6']
    else:
        table = arptable['arptable']['v4']

    logger.info("Poll neighbor: %s, mac: %s, state: %s", neighbor, table[neighbor]['macaddress'],
                table[neighbor]['state'])
    if checkstate:
        return table[neighbor]['macaddress'] == mac and table[neighbor]['state'].lower() == "reachable"
    else:
        return table[neighbor]['macaddress'] == mac


def test_neighbor_hw_mac_change(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                                setup, nbrhosts, established_arp, all_cfg_facts):
    """
    Verify tables, databases, and kernel routes are correctly updated when the MAC address of a neighbor changes
    and is updated via request/reply exchange.

    Test Steps
    * Change the MAC address on a remote host that is already present in the ARP table.
    * Without clearing the entry in the DUT, allow the existing entry to time out and the new reply to have the new MAC
      address.
    * On local linecard:
        * Verify table entries in local ASIC, APP, and host ARP table are updated with new MAC.
    * On supervisor card:
        * Verify Chassis App DB entry is correct for with the updated MAC address.
    * On remote linecards:
        * Verify table entries in remote hosts/ASICs in APPDB, and host ARP table are still present with inband MAC
          address
        * Verify ASIC DB is updated with new MAC.
        * Verify kernel route in remote hosts are still present to inband port.
    * Verify that packets can be sent from local and remote linecards to the learned address.

    Args:
        duthosts: duthosts fixture.
        enum_rand_one_per_hwsku_frontend_hostname: frontend iteration fixture.
        enum_asic_index: asic iteration fixture.
        setup: setup fixture for this module.
        nbrhosts: nbrhosts fixture.
        all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
        established_arp: Fixture to establish ARP to all neighbors.
    """

    per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

    neighs = cfg_facts['BGP_NEIGHBOR']

    for neighbor in neighs:
        local_ip = neighs[neighbor]['local_addr']

        # Check neighbor on local linecard
        local_port = get_port_by_ip(cfg_facts, local_ip)
        if "portchannel" in local_port.lower():
            logger.warning("Skip portchannel, MAC change doesn't seem supported on CEOS docker.")
            continue

        nbrinfo = get_neighbor_info(neighbor, nbrhosts)
        original_mac = nbrinfo['mac']
        logger.info("*" * 60)
        logger.info("Verify initial neighbor: %s, port %s", neighbor, local_port)
        pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, neighbor, original_mac, checkstate=False),
                      "MAC {} didn't change in ARP table".format(original_mac))
        sonic_ping(asic, neighbor, verbose=True)
        pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, neighbor, original_mac),
                      "MAC {} didn't change in ARP table".format(original_mac))
        check_one_neighbor_present(duthosts, per_host, asic, neighbor, nbrhosts, all_cfg_facts)

        try:
            logger.info("Changing ethernet mac on neighbor: %s, port %s, vm %s", neighbor,
                        nbrinfo['shell_intf'], nbrinfo['vm'])

            change_mac(nbrhosts[nbrinfo['vm']], nbrinfo['shell_intf'], NEW_MAC)
            if ":" in neighbor:
                logger.info("Force neighbor solicitation to workaround long IPV6 timer.")
                asic_cmd(asic, "ndisc6 %s %s" % (neighbor, local_port))
            pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, neighbor, NEW_MAC, checkstate=False),
                          "MAC {} didn't change in ARP table".format(NEW_MAC))

            sonic_ping(asic, neighbor, verbose=True)
            pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, neighbor, NEW_MAC),
                          "MAC {} didn't change in ARP table".format(NEW_MAC))
            logger.info("Verify neighbor after mac change: %s, port %s", neighbor, local_port)
            check_one_neighbor_present(duthosts, per_host, asic, neighbor, nbrhosts, all_cfg_facts)
            logger.info("Ping neighbor: %s from all line cards", neighbor)
            ping_all_neighbors(duthosts, [neighbor])
        finally:
            logger.info("-" * 60)
            logger.info("Will Restore ethernet mac on neighbor: %s, port %s, vm %s", neighbor,
                        nbrinfo['shell_intf'], nbrinfo['vm'])
            change_mac(nbrhosts[nbrinfo['vm']], nbrinfo['shell_intf'], original_mac)
            if ":" in neighbor:
                logger.info("Force neighbor solicitation to workaround long IPV6 timer.")
                asic_cmd(asic, "ndisc6 %s %s" % (neighbor, local_port))
            pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, neighbor, original_mac, checkstate=False),
                          "MAC {} didn't change in ARP table".format(original_mac))
            sonic_ping(asic, neighbor, verbose=True)
            pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, neighbor, original_mac),
                          "MAC {} didn't change in ARP table".format(original_mac))

        check_one_neighbor_present(duthosts, per_host, asic, neighbor, nbrhosts, all_cfg_facts)
        ping_all_neighbors(duthosts, [neighbor])


class LinkFlap(object):

    def check_intf_status(self, dut, dut_intf, exp_status):
        """
        Helper to poll on interface oper status

        Args:
            dut: Instance of duthost.
            dut_intf: Interface to poll.
            exp_status: Expected status (up or down)

        Returns:
            True if interface matches expected status, False otherwise.

        """
        status = dut.show_interface(command='status', interfaces=[dut_intf])['ansible_facts']['int_status']
        logging.info("status: %s", status)
        return status[dut_intf]['oper_state'] == exp_status

    def linkflap_down(self, fanout, fanport, dut, dut_intf):
        """
        Brings down an interface on a fanout and polls the DUT for the interface to be operationally down.

        Args:
            fanout: Instance of fanouthost.
            fanport: Port on the fanout to bring down.
            dut: Instance of duthost.
            dut_intf: DUT interface that connects to fanout port.

        Raises:
            pytest.Failed of DUT interface does not go down.

        """
        logger.info("Bring down link: %s/%s <-> %s/%s", fanout.hostname, fanport, dut.hostname, dut_intf)
        fanout.shutdown(fanport)
        pytest_assert(wait_until(30, 1, self.check_intf_status, dut, dut_intf, 'down'),
                      "dut port {} didn't go down as expected".format(dut_intf))

    def linkflap_up(self, fanout, fanport, dut, dut_intf):
        """
        Brings up an interface on a fanout and polls the DUT for the interface to be operationally up.

        Args:
            fanout: Instance of fanouthost.
            fanport: Port on the fanout to bring down.
            dut: Instance of duthost.
            dut_intf: DUT interface that connects to fanout port.

        Raises:
            pytest.Failed of DUT interface does not go up.

        """
        logger.info("Bring up link: %s/%s <-> %s/%s", fanout.hostname, fanport, dut.hostname, dut_intf)
        fanout.no_shutdown(fanport)
        pytest_assert(wait_until(30, 1, self.check_intf_status, dut, dut_intf, 'up'),
                      "dut port {} didn't go down as expected".format(dut_intf))

    def localport_admindown(self, dut, dut_intf):
        """
        Admins down a port on the DUT and polls for oper status to be down.

        Args:
            dut: Instance of duthost.
            dut_intf: Port to admin down.

        Raises:
            pytest.Failed of DUT interface does not go down.

        """
        logger.info("Admin down port %s/%s", dut.hostname, dut_intf)
        dut.shutdown(dut_intf)
        pytest_assert(wait_until(30, 1, self.check_intf_status, dut, dut_intf, 'down'),
                      "dut port {} didn't go down as expected".format(dut_intf))

    def localport_adminup(self, dut, dut_intf):
        """
        Admins up a port on the DUT and polls for oper status to be up.

        Args:
            dut: Instance of duthost.
            dut_intf: Port to admin up.

        Raises:
            pytest.Failed of DUT interface does not go up.

        """
        logger.info("Admin up port %s/%s", dut.hostname, dut_intf)
        dut.no_shutdown(dut_intf)
        pytest_assert(wait_until(30, 1, self.check_intf_status, dut, dut_intf, 'up'),
                      "dut port {} didn't go up as expected".format(dut_intf))


def pick_ports(cfg_facts):
    """
    Selects ports to bounce by sampling the interface and port channel lists.

    Args:
        cfg_facts: The ansible_facts for the asic.

    Returns:
        intfs: A merged dictionary of ethernet and portchannel interfaces.
        intfs_to_test: A list of the chosen interfaces names.

    """
    intfs = {}
    intfs.update(cfg_facts['INTERFACE'])
    if "PORTCHANNEL_INTERFACE" in cfg_facts:
        intfs.update(cfg_facts['PORTCHANNEL_INTERFACE'])

    eths = [intf for intf in intfs if "ethernet" in intf.lower()]
    pos = [intf for intf in intfs if "portchannel" in intf.lower()]

    intfs_to_test = []
    if len(eths) > 0:
        intfs_to_test.extend(random.sample(eths, 1))

    if len(pos) > 0:
        intfs_to_test.extend(random.sample(pos, 1))

    return intfs, intfs_to_test


class TestNeighborLinkFlap(LinkFlap):

    def test_front_panel_admindown_port(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                                        all_cfg_facts,
                                        setup, nbrhosts, established_arp):
        """
        Verify tables, databases, and kernel routes are correctly deleted when the DUT port is admin down/up.

        Test Steps

        * Admin down interface on DUT.
        * On local linecard:
            * Verify ARP/NDP entries are removed from CLI for neighbors on down port.
            * Verify table entries in ASIC, AppDb are removed for addresses on down port.
        * On Supervisor card:
            * Verify Chassis App DB entry are removed for only the cleared address.  Entries for addresses on other
            line cards should still be present.
        * On remote linecards:
            * Verify table entries in ASICDB, APPDB, and host ARP table are removed for cleared addresses.
            * Verify kernel routes for cleared address are deleted.
        * Admin interface up, verify recreation after restarting traffic.

        Args:
            duthosts: duthosts fixture.
            enum_rand_one_per_hwsku_frontend_hostname: frontend iteration fixture.
            enum_asic_index: asic iteration fixture.
            all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
            setup: setup fixture for this module.
            nbrhosts: nbrhosts fixture.
            established_arp: Fixture to establish ARP to all neighbors.

        """

        per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

        neighs = cfg_facts['BGP_NEIGHBOR']

        intfs, intfs_to_test = pick_ports(cfg_facts)

        logger.info("Will test interfaces: %s", intfs_to_test)

        for intf in intfs_to_test:
            local_ips = [i.split("/")[0] for i in intfs[intf].keys()]  # [u'2064:100::2/64', u'100.0.0.2/24']
            neighbors = [n for n in neighs if neighs[n]['local_addr'] in local_ips]
            logger.info("Testing neighbors: %s on intf: %s", neighbors, intf)
            self.localport_admindown(per_host, intf)
            try:
                for neighbor in neighbors:
                    check_neighbor_is_gone(duthosts, all_cfg_facts, per_host, asic, neighbor)
            finally:
                self.localport_adminup(per_host, intf)

            for neighbor in neighbors:
                sonic_ping(asic, neighbor)
                check_one_neighbor_present(duthosts, per_host, asic, neighbor, nbrhosts, all_cfg_facts)


def make_ndp_grat_ndp_packet(pktlen=64,
                             eth_dst='00:01:02:03:04:05',
                             eth_src='00:06:07:08:09:0a',
                             dl_vlan_enable=False,
                             vlan_vid=0,
                             vlan_pcp=0,
                             ipv6_src='2001:db8:85a3::8a2e:370:7334',
                             ipv6_dst='2001:db8:85a3::8a2e:370:7335',
                             ipv6_tc=0,
                             ipv6_ecn=None,
                             ipv6_dscp=None,
                             ipv6_hlim=64,
                             ipv6_fl=0,
                             ipv6_tgt='2001:db8:85a3::8a2e:370:7334',
                             hw_tgt='00:06:07:08:09:0a', ):
    """
    Generates a simple NDP advertisement similar to PTF testutils simple_arp_packet.

    Args:
        pktlen: length of packet
        eth_dst: etheret destination address.
        eth_src: ethernet source address
        dl_vlan_enable: True to add vlan header.
        vlan_vid: vlan ID
        vlan_pcp: vlan priority
        ipv6_src: IPv6 source address
        ipv6_dst: IPv6 destination address
        ipv6_tc: IPv6 traffic class
        ipv6_ecn: IPv6 traffic class ECN
        ipv6_dscp: IPv6 traffic class DSCP
        ipv6_hlim: IPv6 hop limit/ttl
        ipv6_fl: IPv6 flow label
        ipv6_tgt: ICMPv6 ND advertisement target address.
        hw_tgt: IPv6 ND advertisement destination link-layer address.

    Returns:
        Crafted scapy packet for using with send_packet().
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    ipv6_tc = ip_make_tos(ipv6_tc, ipv6_ecn, ipv6_dscp)

    pkt = Ether(dst=eth_dst, src=eth_src)
    if dl_vlan_enable or vlan_vid or vlan_pcp:
        pkt /= Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
    pkt /= IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim)
    pkt /= ICMPv6ND_NA(R=0, S=0, O=1, tgt=ipv6_tgt)
    pkt /= ICMPv6NDOptDstLLAddr(lladdr=hw_tgt)
    pkt /= ("D" * (pktlen - len(pkt)))

    return pkt


class TestGratArp(object):
    ADDR_OFFSET = 100

    def send_grat_arp(self, vm_mac, vmip, port):
        """
        Sends a unsolicited ARP packet.

        Args:
            vm_mac: Target MAC on the VM to send in packet.
            vmip: Target IP on the VM to send in ARP packet.
            port: PTF port number

        """
        logger.info("Send GRAT ARP on port: %s, hwsnd=%s, hwtgt: bcast, ipsnd=iptgt=%s", port, vm_mac, vmip)
        pkt = simple_arp_packet(
            eth_dst='ff:ff:ff:ff:ff:ff',
            eth_src=vm_mac,
            arp_op=1,
            ip_snd=vmip,
            ip_tgt=vmip,
            hw_snd=vm_mac,
            hw_tgt='ff:ff:ff:ff:ff:ff',
        )

        send_packet(self.ptfadapter, port, pkt)

    def send_grat_ndp(self, vm_mac, vmip, port):
        """
        Sends an IPv6 Neighbor Advertisement packet.

        Args:
            vm_mac: Target MAC on the VM to send in packet.
            vmip: Target IP on the VM to send in NDP packet.
            port: PTF port number

        """
        logger.info("Send GRAT NDP on port: %s, hwsnd=%s, hwtgt: bcast, ipsnd=iptgt=%s", port, vm_mac, vmip)
        pkt = make_ndp_grat_ndp_packet(eth_dst='33:33:00:00:00:01',
                                       eth_src=vm_mac,
                                       ipv6_src=vmip,
                                       ipv6_dst="ff02::1",
                                       ipv6_tgt=vmip,
                                       hw_tgt=vm_mac,
                                       )
        send_packet(self.ptfadapter, port, pkt)
        time.sleep(0.500)
        send_packet(self.ptfadapter, port, pkt)

    def send_grat_pkt(self, vm_mac, vmip, port):
        """
        Send a unsolicited ARP or NDP packet.

        Args:
            vm_mac: Target MAC on the VM to send in packet.
            vmip: Target IP on the VM to send in ARP packet.
            port: PTF port number

        """
        if ":" in vmip:
            self.send_grat_ndp(vm_mac, vmip, port)
        else:
            self.send_grat_arp(vm_mac, vmip, port)
        logger.info("Grat packet sent.")

    def test_gratarp_macchange(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                               ptfadapter, tbinfo, nbrhosts,
                               setup, established_arp, all_cfg_facts):
        """
        Verify tables, databases, and kernel routes are correctly updated when a unsolicited ARP packet changes
        the MAC address of learned neighbor.

        Test Steps

        * Send unsolicited ARP packet into DUT for an IP known by DUT with a different MAC address for the neighbor.
        * Change the MAC address of the neighbor VM.
        * On local linecard:
            * Verify table entries in local ASIC, APP, and host ARP table are updated with new MAC.
        * On supervisor card:
            * Verify Chassis App DB entry is correct for with the updated MAC address.
        * On remote linecards:
            * Verify table entries in remote hosts/ASICs in APPDB, and host ARP table are still present with inband MAC
              address
            * Verify ASIC DB is updated with new MAC.
            * Verify kernel route in remote hosts are still present to inband port.
        * Verify that packets can be sent from local and remote linecards to learned address.

        Args:
            duthosts: The duthosts fixture
            enum_rand_one_per_hwsku_frontend_hostname: frontend enumeration fixture
            enum_asic_index: asic enumeration fixture
            ptfadapter: The ptfadapter fixure.
            tbinfo: The tbinfo fixture
            nbrhosts: The nbrhosts fixture.
            setup: The setup fixture from this module.
            established_arp: The established_arp fixture from this module.
            all_cfg_facts: The all_cfg_facts fixture from voq/contest.py


        """
        self.ptfadapter = ptfadapter
        devices = {}
        for k, v in tbinfo['topo']['properties']['topology']['VMs'].items():
            devices[k] = {'vlans': v['vlans']}
        logger.info("devices: %s", devices)

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        asic = duthost.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[duthost.hostname][asic.asic_index]['ansible_facts']

        neighs = cfg_facts['BGP_NEIGHBOR']
        for neighbor in neighs:
            if ":" in neighbor:
                # TODO: Fix IPV6 packet transmission.
                continue
            local_ip = neighs[neighbor]['local_addr']

            local_port = get_port_by_ip(cfg_facts, local_ip)
            if "portchannel" in local_port.lower():
                logger.info("Skip portchannel, MAC change doesn't seem supported on CEOS docker.")
                continue
            else:
                inject_port = local_port

            nbrinfo = get_neighbor_info(neighbor, nbrhosts)

            # 0.1@1 = dut_index.dut_port@ptfport
            tb_port = devices[nbrinfo['vm']]['vlans'][0].split("@")[1]
            logging.info("%s port %s is on ptf port: %s", duthost.hostname, inject_port, tb_port)

            original_mac = nbrinfo['mac']

            logger.info("*" * 60)
            logger.info("Verify initial neighbor: %s, port %s", neighbor, local_port)
            sonic_ping(asic, neighbor)
            pytest_assert(wait_until(60, 2, check_arptable_mac, duthost, neighbor, original_mac),
                          "MAC {} didn't change in ARP table".format(original_mac))

            check_one_neighbor_present(duthosts, duthost, asic, neighbor, nbrhosts, all_cfg_facts)

            try:
                change_mac(nbrhosts[nbrinfo['vm']], nbrinfo['shell_intf'], NEW_MAC)
                self.send_grat_pkt(NEW_MAC, neighbor, int(tb_port))

                pytest_assert(wait_until(60, 2, check_arptable_mac, duthost, neighbor, NEW_MAC, checkstate=False),
                              "MAC {} didn't change in ARP table".format(NEW_MAC))
                sonic_ping(asic, neighbor)
                pytest_assert(wait_until(60, 2, check_arptable_mac, duthost, neighbor, NEW_MAC, checkstate=True),
                              "MAC {} didn't change in ARP table".format(NEW_MAC))
                check_one_neighbor_present(duthosts, duthost, asic, neighbor, nbrhosts, all_cfg_facts)
                ping_all_neighbors(duthosts, [neighbor])
            finally:
                logger.info("Will Restore ethernet mac on neighbor: %s, port %s, vm %s", neighbor,
                            nbrinfo['shell_intf'], nbrinfo['vm'])
                change_mac(nbrhosts[nbrinfo['vm']], nbrinfo['shell_intf'], original_mac)
                sonic_ping(asic, neighbor)
                pytest_assert(wait_until(60, 2, check_arptable_mac, duthost, neighbor, original_mac),
                              "MAC {} didn't change in ARP table".format(original_mac))
            sonic_ping(asic, neighbor)
            check_one_neighbor_present(duthosts, duthost, asic, neighbor, nbrhosts, all_cfg_facts)
            ping_all_neighbors(duthosts, [neighbor])
