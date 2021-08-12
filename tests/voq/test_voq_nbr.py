"""Test neighbor lifecycle on VoQ chassis."""
import logging
import pytest
import time
from datetime import datetime
import random

from tests.ptf_runner import ptf_runner

from tests.common.platform.device_utils import fanout_switch_port_lookup

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

from tests.common.helpers.parallel import parallel_run
from tests.common.helpers.parallel import reset_ansible_local_tmp

from voq_helpers import get_neighbor_info
from voq_helpers import get_port_by_ip
from voq_helpers import check_all_neighbors_present, check_one_neighbor_present
from voq_helpers import asic_cmd, sonic_ping
from voq_helpers import check_neighbors_are_gone
from voq_helpers import dump_and_verify_neighbors_on_asic
from voq_helpers import check_host_arp_table_deleted
from voq_helpers import get_inband_info
from voq_helpers import get_ptf_port
from voq_helpers import get_vm_with_ip

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # lgtm[py/unused-import]

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]

NEW_MAC = "00:01:94:00:00:01"


def check_bgp_restored(duthosts, all_cfg_facts):
    """
    Checks for bgp neighbors to be established.

    Args:
        duthosts: duthosts fixture
        all_cfg_facts: fixture from voq/conftest.py

    Returns:
        True if all neighbors are established, False if not.
    """
    down_nbrs = 0
    for node in duthosts.frontend_nodes:
        for asic in node.asics:
            asic_cfg_facts = all_cfg_facts[node.hostname][asic.asic_index]['ansible_facts']
            if 'BGP_NEIGHBOR' not in asic_cfg_facts:
                continue

            bgp_facts = asic.bgp_facts()['ansible_facts']

            for address in asic_cfg_facts['BGP_NEIGHBOR'].keys():
                if bgp_facts['bgp_neighbors'][address]['state'] != "established":
                    logger.info("BGP internal neighbor: %s is down: %s." % (
                        address, bgp_facts['bgp_neighbors'][address]['state']))
                    down_nbrs += 1
    if down_nbrs != 0:
        logger.warning("Neighbors are still down: %d", down_nbrs)
        return False
    else:
        logger.info("All BGP neighbors are restored.")
        return True


def restore_bgp(duthosts, nbrhosts, all_cfg_facts):
    """
    Attempts to restore BGP config.

    Args:
        duthosts: duthosts fixture
        nbrhosts: nbrhosts fixture
        all_cfg_facts: fixture from voq/conftest.py

    """
    for node in duthosts.frontend_nodes:
        for asic in node.asics:
            asic_cfg_facts = all_cfg_facts[node.hostname][asic.asic_index]['ansible_facts']
            if 'BGP_NEIGHBOR' not in asic_cfg_facts:
                continue

            bgp_facts = asic.bgp_facts()['ansible_facts']

            for address in asic_cfg_facts['BGP_NEIGHBOR'].keys():
                if bgp_facts['bgp_neighbors'][address]['state'] == "established":
                    logger.info("BGP internal neighbor: %s is established: %s, no action." % (
                        address, bgp_facts['bgp_neighbors'][address]['state']))
                else:
                    logger.info("BGP internal neighbor: %s is not established: %s, will enable" % (
                        address, bgp_facts['bgp_neighbors'][address]['state']))

                    logger.info(
                        "Startup neighbor: {} on host {} asic {}".format(address, node.hostname, asic.asic_index))

                    node.command("sudo config bgp startup neighbor {}".format(address))
                    vm_info = get_vm_with_ip(address, nbrhosts)
                    nbr = nbrhosts[vm_info['vm']]
                    logger.info(
                        'enable neighbors {} on neighbor host {}'.format(nbr['conf']['bgp']['peers'],
                                                                         nbr['host'].hostname))

                    for peer in nbr['conf']['bgp']['peers']:
                        for neighbor in nbr['conf']['bgp']['peers'][peer]:
                            nbr['host'].eos_config(
                                lines=["no neighbor %s shutdown" % neighbor],
                                parents=['router bgp {}'.format(nbr['conf']['bgp']['asn'])])

                            if ":" in address:
                                nbr['host'].eos_config(
                                    lines=["no ipv6 route ::/0 %s " % neighbor])
                            else:
                                nbr['host'].eos_config(
                                    lines=["no ip route 0.0.0.0/0 %s " % neighbor])


@pytest.fixture(scope="module", autouse=True)
def verify_bgp_restored(duthosts, nbrhosts, all_cfg_facts):
    """
    After teardown brings up any sessions that are not in case of failure.   Sometimes VMs are not reachable and this
    needs to be retried over a period of time to restore the config.

    Args:
        duthosts:  The duthosts fixture
        nbrhosts: nbrhosts fixture.
        all_cfg_facts: all_cfg_facts fixture from voq/conftest.py

    """

    yield

    restored = False
    endtime = time.time() + 300
    while not restored and time.time() < endtime:

        restored = check_bgp_restored(duthosts, all_cfg_facts)
        if restored:
            break
        else:
            restore_bgp(duthosts, nbrhosts, all_cfg_facts)
        time.sleep(5)
    else:
        logger.error("BGP was never restored.")
        pytest.fail("BGP was never restored after test_voq_nbr tests ran.")


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

            if 'BGP_NEIGHBOR' not in asic_cfg_facts:
                continue

            for neighbor in asic_cfg_facts['BGP_NEIGHBOR']:
                logger.info(
                    "Shut down neighbor: {} on host {} asic {}".format(neighbor, node.hostname, asic.asic_index))

                node_results.append(node.command("sudo config bgp shutdown neighbor {}".format(neighbor)))

        results[node.hostname] = node_results

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

    logger.info("Poll for routes to be gone.")
    endtime = time.time() + 120
    for dut in duthosts.frontend_nodes:
        for asc in dut.asics:
            routes = len(asic_cmd(asc, 'redis-cli -n 0 KEYS ROUTE_TABLE*')['stdout_lines'])
            logger.info("Found %d routes in appdb on %s/%s", routes, dut.hostname, asc.asic_index)

            while routes > 1000:
                time.sleep(5)
                routes = len(asic_cmd(asc, 'redis-cli -n 0 KEYS ROUTE_TABLE*')['stdout_lines'])
                logger.info("Found %d routes in appdb on %s/%s, polling", routes, dut.hostname, asc.asic_index)
                if time.time() > endtime:
                    break

            routes = len(asic_cmd(asc, 'redis-cli -n 1 KEYS *ROUTE_ENTRY*')['stdout_lines'])
            logger.info("Found %d routes in asicdb on %s/%s", routes, dut.hostname, asc.asic_index)
            while routes > 1000:
                time.sleep(5)
                routes = len(asic_cmd(asc, 'redis-cli -n 1 KEYS *ROUTE_ENTRY*')['stdout_lines'])
                logger.info("Found %d routes in asicdb on %s/%s, polling", routes, dut.hostname, asc.asic_index)
                if time.time() > endtime:
                    break


@pytest.fixture(scope="module")
def teardown(duthosts, nbrhosts, all_cfg_facts):
    """
    Teardown fixture for the module, restore bgp neighbors.
    """
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
            if 'BGP_NEIGHBOR' not in asic_cfg_facts:
                continue
            logger.info('enable neighbors {} on dut host {}'.format(asic_cfg_facts['BGP_NEIGHBOR'], node.hostname))
            asnum = asic_cfg_facts['DEVICE_METADATA']['localhost']['bgp_asn']

            for neighbor in asic_cfg_facts['BGP_NEIGHBOR']:
                logger.info(
                    "Startup neighbor: {} on host {} asic {}".format(neighbor, node.hostname, asic.asic_index))

                node_results.append(node.command("sudo config bgp startup neighbor {}".format(neighbor)))
                if node.is_multi_asic:
                    node_results.append(node.command(
                        "docker exec bgp{} vtysh -c \"config t\" -c \"router bgp {}\" -c \"no neighbor {} shutdown\"".format(
                            asic.asic_index, asnum, neighbor)))
                else:
                    node_results.append(node.command(
                        "docker exec bgp vtysh -c \"config t\" -c \"router bgp {}\" -c \"no neighbor {} shutdown\"".format(
                            asnum, neighbor)))

        results[node.hostname] = node_results

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
                try:
                    node_results.append(node['host'].eos_config(
                        lines=["no neighbor %s shutdown" % neighbor],
                        parents=['router bgp {}'.format(node['conf']['bgp']['asn'])])
                    )
                    if ":" in neighbor:
                        node_results.append(node['host'].eos_config(
                            lines=["no ipv6 route ::/0 %s " % neighbor])
                        )
                    else:
                        node_results.append(node['host'].eos_config(
                            lines=["no ip route 0.0.0.0/0 %s " % neighbor],
                        )
                        )
                except Exception:
                    logger.warning("Enable of neighbor on VM: %s failed, retrying", node['host'].hostname)
                    time.sleep(10)
                    node_results.append(node['host'].eos_config(
                        lines=["no neighbor %s shutdown" % neighbor],
                        parents=['router bgp {}'.format(node['conf']['bgp']['asn'])])
                    )
                    if ":" in neighbor:
                        node_results.append(node['host'].eos_config(
                            lines=["no ipv6 route ::/0 %s " % neighbor],
                        )
                        )
                    else:
                        node_results.append(node['host'].eos_config(
                            lines=["no ip route 0.0.0.0/0 %s " % neighbor],
                        )
                        )

        results[node['host'].hostname] = node_results

    try:
        parallel_run(enable_dut_bgp_neighs, [all_cfg_facts], {}, duthosts.frontend_nodes, timeout=300)
    finally:
        parallel_run(enable_nbr_bgp_neighs, [], {}, nbrhosts.values(), timeout=120)


def ping_all_dut_local_nbrs(duthosts):
    """
    Pings all neighbors locally attached to each frontend node on the DUT.

    Args:
        duthosts: An instance of the duthosts fixture.

    """

    @reset_ansible_local_tmp
    def _ping_all_local_nbrs(node=None, results=None):
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        node_results = []
        logger.info("Pinging neighbors to establish ARP on node: %s", node.hostname)

        for asic in node.asics:
            cfg_facts = asic.config_facts(source="persistent")['ansible_facts']
            if 'BGP_NEIGHBOR' in cfg_facts:
                neighs = cfg_facts['BGP_NEIGHBOR']
            else:
                logger.info("No local neighbors for host: %s/%s, skipping", node.hostname, asic.asic_index)
                continue

            for neighbor in neighs:
                node_results.append(sonic_ping(asic, neighbor, verbose=True))
        results[node.hostname] = node_results

    parallel_run(_ping_all_local_nbrs, [], {}, duthosts.frontend_nodes, timeout=120)


def ping_all_neighbors(duthosts, all_cfg_facts, neighbors):
    """
    Pings all neighbors in the neighbor list from all frontend hosts on the DUT..

    Args:
        duthosts: An instance of the duthosts fixture.
        all_cfg_facts: Fixture from voq/conftest.py
        neighbors: A list of neighbor IP addresses.

    """
    for per_host in duthosts.frontend_nodes:
        for asic in per_host.asics:
            cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']
            inband = get_inband_info(cfg_facts)
            if inband == {}:
                continue

            for neighbor in neighbors:
                logger.info("Ping %s from %s/%s", neighbor, per_host.hostname, asic.asic_index)
                sonic_ping(asic, neighbor, verbose=True)


@pytest.fixture()
def established_arp(duthosts):
    """
    Fixture to establish ARP to all neighbors at start of test.

    Args:
        duthosts: Instance of duthosts fixture.
    """
    logger.info("Ping all local neighbors to establish ARP")
    ping_all_dut_local_nbrs(duthosts)


def poll_neighbor_table_delete(duthosts, neighs, delay=1, poll_time=180):
    """
    Poller for clear tests to determine when to proceed with test after issuing
    clear commands.

    Args:
        duthosts: The duthosts fixture.
        neighs: List of neighbor IPs which should be cleared.
        delay: How long to delay between checks.
        poll_time: How long to poll for.

    """

    t0 = time.time()
    endtime = t0 + poll_time

    for node in duthosts.frontend_nodes:
        for asic in node.asics:
            logger.info("Poll for ARP clear on host: %s/%s", node.hostname, asic.asic_index)
            node_cleared = False
            while time.time() < endtime and node_cleared is False:
                if node.is_multi_asic:
                    arptable = node.switch_arptable(namespace=asic.namespace)['ansible_facts']
                else:
                    arptable = node.switch_arptable()['ansible_facts']
                for nbr in neighs:
                    try:
                        check_host_arp_table_deleted(node, asic, nbr, arptable)
                    except AssertionError:
                        time.sleep(delay)
                        break
                    else:
                        node_cleared = True

    logger.info("Neighbor poll ends after %s seconds", str(time.time() - t0))


def test_neighbor_clear_all(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                            setup, teardown, nbrhosts, all_cfg_facts, nbr_macs, established_arp):
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

    per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']
    if 'BGP_NEIGHBOR' in cfg_facts:
        neighs = cfg_facts['BGP_NEIGHBOR']
    else:
        logger.info("No local neighbors for host: %s/%s, skipping", per_host.hostname, asic.asic_index)
        return

    asic_cmd(asic, "sonic-clear arp")
    asic_cmd(asic, "sonic-clear ndp")

    logger.info("Wait for clear.")
    poll_neighbor_table_delete(duthosts, neighs)

    logger.info("Verify neighbors are gone.")
    check_neighbors_are_gone(duthosts, all_cfg_facts, per_host, asic, neighs.keys())

    # relearn and check
    logger.info("Relearn neighbors on all nodes")
    ping_all_dut_local_nbrs(duthosts)
    check_all_neighbors_present(duthosts, nbrhosts, all_cfg_facts, nbr_macs)


def select_neighbors(port_cfg, cfg_facts):
    """
    Helper to select a neighbors to be tested out of a set of ports.  Pass in all of the INTERFACE
    or PORTCHANNEL_INTERFACE and it will chose one and return the neighbors as a list.

    Args:
        port_cfg: The config facts for the interfaces to check.
        cfg_facts: The config facts for the asic for looking up neighbors.

    Returns:
        A list of neighbor IPs.

    """
    neighs = cfg_facts['BGP_NEIGHBOR']

    nbr_to_test = []
    eth_ports = [intf for intf in port_cfg]
    local_port = random.choice(eth_ports)

    for neighbor in neighs:
        local_ip = neighs[neighbor]['local_addr']
        nbr_port = get_port_by_ip(cfg_facts, local_ip)
        if local_port == nbr_port:
            nbr_to_test.append(neighbor)

    return nbr_to_test


def test_neighbor_clear_one(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                            setup, teardown, nbrhosts, all_cfg_facts, nbr_macs, established_arp):
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
    per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']
    if 'BGP_NEIGHBOR' in cfg_facts:
        neighs = cfg_facts['BGP_NEIGHBOR']
    else:
        logger.info("No local neighbors for host: %s/%s, skipping", per_host.hostname, asic.asic_index)
        return

    eth_cfg = cfg_facts['INTERFACE'] if 'INTERFACE' in cfg_facts else {}
    pos_cfg = cfg_facts['PORTCHANNEL_INTERFACE'] if 'PORTCHANNEL_INTERFACE' in cfg_facts else {}
    nbr_to_test = []
    if eth_cfg != {}:
        nbr_to_test.extend(select_neighbors(eth_cfg, cfg_facts))

    if pos_cfg != {}:
        nbr_to_test.extend(select_neighbors(pos_cfg, cfg_facts))

    untouched_nbrs = [nbr for nbr in neighs if nbr not in nbr_to_test]

    logger.info("We will test these neighbors: %s", nbr_to_test)
    logger.info("These neighbors should not be affected: %s", untouched_nbrs)

    for neighbor in nbr_to_test:
        logger.info(
            "Flushing neighbor: {} on host {}/{}".format(neighbor, per_host.hostname, asic.asic_index))
        asic_cmd(asic, "ip neigh flush to %s" % neighbor)

    logger.info("Wait for flush.")
    poll_neighbor_table_delete(duthosts, nbr_to_test)
    logger.info("Verify neighbors are gone.")
    check_neighbors_are_gone(duthosts, all_cfg_facts, per_host, asic, nbr_to_test)

    logger.info("Verify other neighbors are not affected.")
    dump_and_verify_neighbors_on_asic(duthosts, per_host, asic, untouched_nbrs, nbrhosts, all_cfg_facts, nbr_macs)

    # relearn and check
    logger.info("Relearn neighbors on all nodes")
    ping_all_dut_local_nbrs(duthosts)
    logger.info("Check neighbor relearn on all nodes.")
    check_all_neighbors_present(duthosts, nbrhosts, all_cfg_facts, nbr_macs)


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


def check_arptable_mac(host, asic, neighbor, mac, checkstate=True):
    if host.is_multi_asic:
        arptable = host.switch_arptable(namespace=asic.namespace)['ansible_facts']
    else:
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


def check_arptable_state(host, asic, neighbor, state):
    arptable = asic.switch_arptable()['ansible_facts']

    if ':' in neighbor:
        table = arptable['arptable']['v6']
    else:
        table = arptable['arptable']['v4']

    logger.info("Poll neighbor: %s, mac: %s, current state: %s", neighbor, table[neighbor]['macaddress'],
                table[neighbor]['state'])

    return table[neighbor]['state'] == state


def test_neighbor_hw_mac_change(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                                setup, teardown, nbrhosts, all_cfg_facts, nbr_macs, established_arp):
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
        established_arp: Fixture to establish arp on all nodes
        all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
    """

    per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

    if 'BGP_NEIGHBOR' in cfg_facts:
        neighs = cfg_facts['BGP_NEIGHBOR']
    else:
        logger.info("No local neighbors for host: %s/%s, skipping", per_host.hostname, asic.asic_index)
        return

    eth_cfg = cfg_facts['INTERFACE'] if 'INTERFACE' in cfg_facts else {}
    if eth_cfg == {}:
        pytest.skip("Can't run this test without any IP interfaces on ethernet ports")
    eth_ports = [intf for intf in eth_cfg]
    local_port = random.choice(eth_ports)

    logger.info("We will test port: %s on host %s, asic %s", local_port, per_host.hostname, asic.asic_index)

    nbr_to_test = []
    for neighbor in neighs:
        local_ip = neighs[neighbor]['local_addr']
        nbr_port = get_port_by_ip(cfg_facts, local_ip)
        if local_port == nbr_port:
            nbr_to_test.append(neighbor)

    logger.info("We will test neighbors: %s", nbr_to_test)
    nbrinfo = get_neighbor_info(nbr_to_test[0], nbrhosts)
    original_mac = nbrinfo['mac']

    for neighbor in nbr_to_test:
        # Check neighbor on local linecard
        logger.info("*" * 60)
        logger.info("Verify initial neighbor: %s, port %s", neighbor, local_port)
        pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, asic, neighbor, original_mac, checkstate=False),
                      "MAC {} didn't change in ARP table".format(original_mac))
        sonic_ping(asic, neighbor, verbose=True)
        pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, asic, neighbor, original_mac),
                      "MAC {} didn't change in ARP table".format(original_mac))

    dump_and_verify_neighbors_on_asic(duthosts, per_host, asic, nbr_to_test, nbrhosts, all_cfg_facts, nbr_macs)

    try:
        logger.info("Changing ethernet mac on port %s, vm %s", nbrinfo['shell_intf'], nbrinfo['vm'])

        change_mac(nbrhosts[nbrinfo['vm']], nbrinfo['shell_intf'], NEW_MAC)

        for neighbor in nbr_to_test:
            if ":" in neighbor:
                logger.info("Force neighbor solicitation to workaround long IPV6 timer.")
                asic_cmd(asic, "ndisc6 %s %s" % (neighbor, local_port))
            pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, asic, neighbor, NEW_MAC, checkstate=False),
                          "MAC {} didn't change in ARP table".format(NEW_MAC))

            sonic_ping(asic, neighbor, verbose=True)
            pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, asic, neighbor, NEW_MAC),
                          "MAC {} didn't change in ARP table".format(NEW_MAC))
            logger.info("Verify neighbor after mac change: %s, port %s", neighbor, local_port)
            check_one_neighbor_present(duthosts, per_host, asic, neighbor, nbrhosts, all_cfg_facts)

        logger.info("Ping neighbors: %s from all line cards", nbr_to_test)

        ping_all_neighbors(duthosts, all_cfg_facts, nbr_to_test)

    finally:
        logger.info("-" * 60)
        logger.info("Will Restore ethernet mac on port %s, vm %s", nbrinfo['shell_intf'], nbrinfo['vm'])
        change_mac(nbrhosts[nbrinfo['vm']], nbrinfo['shell_intf'], original_mac)
        for neighbor in nbr_to_test:
            if ":" in neighbor:
                logger.info("Force neighbor solicitation to workaround long IPV6 timer.")
                asic_cmd(asic, "ndisc6 %s %s" % (neighbor, local_port))
            pytest_assert(
                wait_until(60, 2, check_arptable_mac, per_host, asic, neighbor, original_mac, checkstate=False),
                "MAC {} didn't change in ARP table".format(original_mac))
            sonic_ping(asic, neighbor, verbose=True)
            pytest_assert(wait_until(60, 2, check_arptable_mac, per_host, asic, neighbor, original_mac),
                          "MAC {} didn't change in ARP table".format(original_mac))

        dump_and_verify_neighbors_on_asic(duthosts, per_host, asic, nbr_to_test, nbrhosts, all_cfg_facts, nbr_macs)

    ping_all_neighbors(duthosts, all_cfg_facts, nbr_to_test)


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
        pytest_assert(wait_until(60, 1, self.check_intf_status, dut, dut_intf, 'up'),
                      "dut port {} didn't go up as expected".format(dut_intf))

    def localport_admindown(self, dut, asic, dut_intf):
        """
        Admins down a port on the DUT and polls for oper status to be down.

        Args:
            dut: Instance of duthost.
            dut_intf: Port to admin down.

        Raises:
            pytest.Failed of DUT interface does not go down.

        """
        logger.info("Admin down port %s/%s", dut.hostname, dut_intf)
        asic.shutdown_interface(dut_intf)
        pytest_assert(wait_until(30, 1, self.check_intf_status, dut, dut_intf, 'down'),
                      "dut port {} didn't go down as expected".format(dut_intf))

    def localport_adminup(self, dut, asic, dut_intf):
        """
        Admins up a port on the DUT and polls for oper status to be up.

        Args:
            dut: Instance of duthost.
            dut_intf: Port to admin up.

        Raises:
            pytest.Failed of DUT interface does not go up.

        """
        logger.info("Admin up port %s/%s", dut.hostname, dut_intf)
        asic.startup_interface(dut_intf)
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
    intfs.update(cfg_facts.get('INTERFACE', {}))
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
                                        all_cfg_facts, setup, teardown, nbrhosts, nbr_macs, established_arp):
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

        if 'BGP_NEIGHBOR' in cfg_facts:
            neighs = cfg_facts['BGP_NEIGHBOR']
        else:
            logger.info("No local neighbors for host: %s/%s, skipping", per_host.hostname, asic.asic_index)
            return

        intfs, intfs_to_test = pick_ports(cfg_facts)

        logger.info("Will test interfaces: %s", intfs_to_test)

        for intf in intfs_to_test:
            local_ips = [i.split("/")[0] for i in intfs[intf].keys()]  # [u'2064:100::2/64', u'100.0.0.2/24']
            neighbors = [n for n in neighs if neighs[n]['local_addr'] in local_ips]

            logger.info("Testing neighbors: %s on intf: %s", neighbors, intf)
            self.localport_admindown(per_host, asic, intf)

            try:
                check_neighbors_are_gone(duthosts, all_cfg_facts, per_host, asic, neighbors)
            finally:
                self.localport_adminup(per_host, asic, intf)

            for neighbor in neighbors:
                sonic_ping(asic, neighbor)

            for neighbor in neighbors:
                pytest_assert(wait_until(60, 2, check_arptable_state, per_host, asic, neighbor, "REACHABLE"),
                              "STATE for neighbor {} did not change to reachable".format(neighbor))

            dump_and_verify_neighbors_on_asic(duthosts, per_host, asic, neighbors, nbrhosts, all_cfg_facts, nbr_macs)

    def test_front_panel_linkflap_port(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                                       all_cfg_facts,
                                       fanouthosts, setup, teardown, nbrhosts, established_arp):
        """
        Verify tables, databases, and kernel routes are correctly deleted when the front panel port flaps.

        Test Steps
        * Admin down interface on fanout to cause LOS on DUT.
        * On local linecard:
            * Verify ARP/NDP entries are removed from CLI for neighbors on down port.
            * Verify table entries in ASIC, AppDb are removed for addresses on down port.
        * On Supervisor card:
            * Verify Chassis App DB entry are removed for only the cleared address.  Entries for addresses on other line cards
            should still be present.
        * On remote linecards:
            * Verify table entries in ASICDB, APPDB, and host ARP table are removed for cleared addresses.
            * Verify kernel routes for cleared address are deleted.
        * Admin interface up, verify recreation after restarting traffic.

        Args:
            duthosts: duthosts fixture.
            enum_rand_one_per_hwsku_frontend_hostname: frontend iteration fixture.
            enum_asic_index: asic iteration fixture.
            all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
            fanouthosts: fanouthosts fixture.
            setup: setup fixture for this module.
            nbrhosts: nbrhosts fixture.
            established_arp: Fixture to establish ARP to all neighbors.

        """
        if fanouthosts == {}:
            pytest.skip("Fanouthosts fixture did not return anything, this test case can not run.")

        per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

        if 'BGP_NEIGHBOR' in cfg_facts:
            neighs = cfg_facts['BGP_NEIGHBOR']
        else:
            logger.info("No local neighbors for host: %s/%s, skipping", per_host.hostname, asic.asic_index)
            return

        intfs, intfs_to_test = pick_ports(cfg_facts)

        logger.info("Will test interfaces: %s", intfs_to_test)

        for intf in intfs_to_test:
            local_ips = [i.split("/")[0] for i in intfs[intf].keys()]  # [u'2064:100::2/64', u'100.0.0.2/24']
            neighbors = [n for n in neighs if neighs[n]['local_addr'] in local_ips]
            logger.info("Testing neighbors: %s on intf: %s", neighbors, intf)

            if "portchannel" in intf.lower():
                pc_cfg = cfg_facts['PORTCHANNEL_MEMBER']
                pc_members = pc_cfg[intf]
                logger.info("Portchannel members %s: %s", intf, pc_members.keys())
                portbounce_list = pc_members.keys()
            else:
                portbounce_list = [intf]

            try:
                for lport in portbounce_list:
                    fanout, fanport = fanout_switch_port_lookup(fanouthosts, per_host.hostname, lport)
                    logger.info("fanout port: %s %s, host: %s", fanout, fanport, fanout.host)
                    self.linkflap_down(fanout, fanport, per_host, lport)

                for neighbor in neighbors:
                    check_one_neighbor_present(duthosts, per_host, asic, neighbor, nbrhosts, all_cfg_facts)

            finally:
                for lport in portbounce_list:
                    fanout, fanport = fanout_switch_port_lookup(fanouthosts, per_host.hostname, lport)
                    self.linkflap_up(fanout, fanport, per_host, lport)

            for neighbor in neighbors:
                check_one_neighbor_present(duthosts, per_host, asic, neighbor, nbrhosts, all_cfg_facts)


class TestGratArp(object):
    ADDR_OFFSET = 100

    def send_grat_pkt(self, vm_mac, vmip, port):
        """
        Send a unsolicited ARP or NDP packet.

        Args:
            vm_mac: Target MAC on the VM to send in packet.
            vmip: Target IP on the VM to send in ARP packet.
            port: PTF port number

        """
        params = {
            'vm_mac': vm_mac,
            'vmip': vmip,
            'port': port
        }
        if ":" in vmip:
            f = "voq.GNDP"
        else:
            f = "voq.GARP"
        log_file = "/tmp/voq.garp.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
        logger.info("Call PTF runner")
        ptf_runner(self.ptfhost, 'ptftests', f, '/root/ptftests', params=params,
                   log_file=log_file, timeout=3)
        logger.info("Grat packet sent.")

    def test_gratarp_macchange(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                               ptfhost, tbinfo, nbrhosts, setup, teardown, all_cfg_facts, established_arp):
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
            ptfhost: The ptfhost fixure.
            tbinfo: The tbinfo fixture
            nbrhosts: The nbrhosts fixture.
            setup: The setup fixture from this module.
            established_arp: The established_arp fixture from this module.
            all_cfg_facts: The all_cfg_facts fixture from voq/contest.py


        """
        self.ptfhost = ptfhost

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        asic = duthost.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[duthost.hostname][asic.asic_index]['ansible_facts']

        if 'BGP_NEIGHBOR' in cfg_facts:
            neighs = cfg_facts['BGP_NEIGHBOR']
        else:
            logger.info("No local neighbors for host: %s/%s, skipping", duthost.hostname, asic.asic_index)
            return

        eth_cfg = cfg_facts['INTERFACE'] if 'INTERFACE' in cfg_facts else {}
        if eth_cfg == {}:
            pytest.skip("Can't run this test without any IP interfaces on ethernet ports")
        eth_ports = [intf for intf in eth_cfg]
        local_port = random.choice(eth_ports)

        logger.info("We will test port: %s on host %s, asic %s", local_port, duthost.hostname, asic.asic_index)

        nbr_to_test = []
        for neighbor in neighs:
            local_ip = neighs[neighbor]['local_addr']
            nbr_port = get_port_by_ip(cfg_facts, local_ip)
            if local_port == nbr_port:
                nbr_to_test.append(neighbor)

        logger.info("We will test neighbors: %s", nbr_to_test)

        for neighbor in nbr_to_test:

            nbrinfo = get_neighbor_info(neighbor, nbrhosts)

            tb_port = get_ptf_port(duthosts,
                                   all_cfg_facts[duthost.hostname][asic.asic_index]['ansible_facts'],
                                   tbinfo, duthost, local_port)[0]
            original_mac = nbrinfo['mac']

            logger.info("*" * 60)
            logger.info("Verify initial neighbor: %s, port %s", neighbor, local_port)
            logger.info("%s port %s is on ptf port: %s", duthost.hostname, local_port, tb_port)
            logger.info("-" * 60)
            sonic_ping(asic, neighbor)
            pytest_assert(wait_until(60, 2, check_arptable_mac, duthost, asic, neighbor, original_mac),
                          "MAC {} didn't change in ARP table".format(original_mac))

            check_one_neighbor_present(duthosts, duthost, asic, neighbor, nbrhosts, all_cfg_facts)

            try:
                change_mac(nbrhosts[nbrinfo['vm']], nbrinfo['shell_intf'], NEW_MAC)
                self.send_grat_pkt(NEW_MAC, neighbor, int(tb_port))

                pytest_assert(wait_until(60, 2, check_arptable_mac, duthost, asic, neighbor, NEW_MAC, checkstate=False),
                              "MAC {} didn't change in ARP table of neighbor {}".format(NEW_MAC, neighbor))
                try:
                    sonic_ping(asic, neighbor)
                except AssertionError:
                    logging.info("No initial response from ping, begin poll to see if ARP table responds.")
                pytest_assert(wait_until(60, 2, check_arptable_mac, duthost, asic, neighbor, NEW_MAC, checkstate=True),
                              "MAC {} didn't change in ARP table of neighbor {}".format(NEW_MAC, neighbor))
                check_one_neighbor_present(duthosts, duthost, asic, neighbor, nbrhosts, all_cfg_facts)
                ping_all_neighbors(duthosts, all_cfg_facts, [neighbor])
            finally:
                logger.info("Will Restore ethernet mac on neighbor: %s, port %s, vm %s", neighbor,
                            nbrinfo['shell_intf'], nbrinfo['vm'])
                change_mac(nbrhosts[nbrinfo['vm']], nbrinfo['shell_intf'], original_mac)

                if ":" in neighbor:
                    logger.info("Force neighbor solicitation to workaround long IPV6 timer.")
                    asic_cmd(asic, "ndisc6 %s %s" % (neighbor, local_port))
                pytest_assert(
                    wait_until(60, 2, check_arptable_mac, duthost, asic, neighbor, original_mac, checkstate=False),
                    "MAC {} didn't change in ARP table".format(original_mac))
                sonic_ping(asic, neighbor, verbose=True)
                pytest_assert(wait_until(60, 2, check_arptable_mac, duthost, asic, neighbor, original_mac),
                              "MAC {} didn't change in ARP table".format(original_mac))

            check_one_neighbor_present(duthosts, duthost, asic, neighbor, nbrhosts, all_cfg_facts)
            ping_all_neighbors(duthosts, all_cfg_facts, [neighbor])
