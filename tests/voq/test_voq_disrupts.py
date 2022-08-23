import pytest
import logging
import time

from voq_helpers import sonic_ping
from voq_helpers import eos_ping

from test_voq_ipfwd import pick_ports
from test_voq_ipfwd import check_packet

from test_voq_init import check_voq_interfaces
from voq_helpers import dump_and_verify_neighbors_on_asic

from tests.common import reboot
from tests.common import config_reload

from tests.common.helpers.parallel import parallel_run
from tests.common.helpers.parallel import reset_ansible_local_tmp
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


def check_bgp_neighbors(duthosts, excluded_ips=[]):
    """
    Validates neighbors are established

    Args:
        duthosts: Duthosts fixture

    Returns:
        True if all neighbors are established, False if one or more are down.

    """
    down_nbrs = 0
    for node in duthosts.frontend_nodes:
        for asic in node.asics:
            bgp_facts = asic.bgp_facts()['ansible_facts']

            for address in bgp_facts['bgp_neighbors']:
                if address.lower() not in excluded_ips and bgp_facts['bgp_neighbors'][address]['state'] != "established":
                    logger.info("BGP neighbor: %s is down: %s." % (
                        address, bgp_facts['bgp_neighbors'][address]['state']))
                    down_nbrs += 1
    if down_nbrs != 0:
        logger.warning("Neighbors are still down: %d", down_nbrs)
        return False
    else:
        logger.info("All BGP neighbors are restored.")
        return True


def poll_bgp_restored(duthosts, timeout=900, delay=20):
    """
    Polls for all neighbors to be established.

    Args:
        duthosts: The duthosts fixture.
        timeout: how long to poll
        delay: time between checks.

    Raises:
        AssertionError if neighbors did not come up.

    """
    logger.info("Poll for BGP to recover.")
    pytest_assert(wait_until(timeout, 10, 0, check_bgp_neighbors, duthosts),
                  "All BGP's are not established after config reload from original minigraph")


def check_intfs_and_nbrs(duthosts, all_cfg_facts, nbrhosts, nbr_macs):
    """
    Checks interfaces and neighbors are correct on frontend nodes and chassisdb.

    Args:
        duthosts: duthosts fixture
        all_cfg_facts: all_cfg_facts fixture
        nbrhosts: nbrhosts fixture
        nbr_macs: nbr_macs fixture

    """
    for host in duthosts.frontend_nodes:
        for asic in host.asics:
            cfg_facts = all_cfg_facts[host.hostname][asic.asic_index]['ansible_facts']
            check_voq_interfaces(duthosts, host, asic, cfg_facts)

            logger.info("Checking local neighbors on host: %s, asic: %s", host.hostname, asic.asic_index)
            if 'BGP_NEIGHBOR' in cfg_facts:
                neighs = cfg_facts['BGP_NEIGHBOR']
            else:
                logger.info("No local neighbors for host: %s/%s, skipping", host.hostname, asic.asic_index)
                continue

            dump_and_verify_neighbors_on_asic(duthosts, host, asic, neighs, nbrhosts, all_cfg_facts, nbr_macs)


def check_ip_fwd(duthosts, all_cfg_facts, nbrhosts, tbinfo):
    """
    Checks basic IP connectivity through the voq system.

    Args:
        duthosts: duthosts fixture
        all_cfg_facts: all_cfg_facts fixture
        nbrhosts: nbrhosts fixture
    """
    for porttype in ["ethernet", "portchannel"]:
        for version in [4, 6]:

            ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, tbinfo, port_type_a=porttype, version=version)

            for ttl, size in [(2, 64), (1, 1450)]:
                # local interfaces
                check_packet(sonic_ping, ports, 'portB', 'portA', size=size, ttl=ttl, ttl_change=0)

                # local neighbors
                check_packet(sonic_ping, ports, 'portA', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=0)

                vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

                check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                             dev=vm_host_to_A, size=size, ttl=ttl)

                # loopbacks
                check_packet(sonic_ping, ports, 'portA', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=0)

                # inband
                check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='inband', size=size, ttl=ttl, ttl_change=0)

                # DUT loopback
                # these don't decrement ttl
                check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='my_ip', size=size,
                             ttl=ttl, ttl_change=0)
                check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_ip', size=size,
                             ttl=ttl, ttl_change=0)
                check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_lb', size=size,
                             ttl=ttl, ttl_change=0)

                vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']
                check_packet(eos_ping, ports, 'portA', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                             dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=0)

                # end to end
                vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']
                check_packet(eos_ping, ports, 'portB', 'portA', dst_ip_fld='nbr_lb', src_ip_fld='nbr_lb',
                             dev=vm_host_to_A, size=size, ttl=ttl)
                check_packet(eos_ping, ports, 'portC', 'portA', dst_ip_fld='nbr_lb', src_ip_fld='nbr_lb',
                             dev=vm_host_to_A, size=size, ttl=ttl)
                check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='nbr_lb', src_ip_fld='nbr_lb',
                             dev=vm_host_to_A, size=size, ttl=ttl)


@pytest.mark.skip(reason="Not yet implemented - reboot of supervisor does not reset line cards.")
def test_reboot_supervisor(duthosts, localhost, all_cfg_facts, nbrhosts, nbr_macs):
    """
    Tests the system after supervisor reset, all cards should reboot and interfaces/neighbors should be in sync across
    the system.

    Args:
        duthosts: duthosts fixture
        localhost: localhost fixture
        all_cfg_facts: all_cfg_facts fixture
        nbrhosts: nbrhosts fixture
        nbr_macs: nbr_macs fixture
    """
    logger.info("=" * 80)
    logger.info("Precheck")
    logger.info("-" * 80)

    check_intfs_and_nbrs(duthosts, all_cfg_facts, nbrhosts, nbr_macs)
    check_ip_fwd(duthosts, all_cfg_facts, nbrhosts)

    logger.info("=" * 80)
    logger.info("Coldboot on node: %s", duthosts.supervisor_nodes[0].hostname)
    logger.info("-" * 80)

    reboot(duthosts.supervisor_nodes[0], localhost, wait=600)
    assert wait_until(300, 20, duthosts.supervisor_nodes[0].critical_services_fully_started), "Not all critical services are fully started"
    reboot(duthosts.supervisor_nodes[0], localhost, wait=240)
    assert wait_until(300, 20, 2, duthosts.supervisor_nodes[0].critical_services_fully_started), "Not all critical services are fully started"

    poll_bgp_restored(duthosts)

    logger.info("=" * 80)
    logger.info("Postcheck")
    logger.info("-" * 80)

    check_intfs_and_nbrs(duthosts, all_cfg_facts, nbrhosts, nbr_macs)
    check_ip_fwd(duthosts, all_cfg_facts, nbrhosts)


def test_reboot_system(duthosts, localhost, all_cfg_facts, nbrhosts, nbr_macs):
    """
    Tests the system after all cards are explicitly reset, interfaces/neighbors should be in sync across the system.

    Args:
        duthosts: duthosts fixture
        localhost: localhost fixture
        all_cfg_facts: all_cfg_facts fixture
        nbrhosts: nbrhosts fixture
        nbr_macs: nbr_macs fixture
    """

    @reset_ansible_local_tmp
    def reboot_node(lh, node=None, results=None):
        node_results = []
        node_results.append(reboot(node, lh, wait=120))
        results[node.hostname] = node_results

    logger.info("=" * 80)
    logger.info("Precheck")
    logger.info("-" * 80)

    check_intfs_and_nbrs(duthosts, all_cfg_facts, nbrhosts, nbr_macs)
    check_ip_fwd(duthosts, all_cfg_facts, nbrhosts)

    logger.info("=" * 80)
    logger.info("Coldboot on all nodes")
    logger.info("-" * 80)

    t0 = time.time()

    parallel_run(reboot_node, [localhost], {}, duthosts.nodes, timeout=1000)
    for node in duthosts.nodes:
        assert wait_until(300, 20, 2, node.critical_services_fully_started), "Not all critical services are fully started"
    poll_bgp_restored(duthosts)

    t1 = time.time()
    elapsed = t1 - t0

    logger.info("-" * 80)
    logger.info("Time to reboot and recover: %s seconds.", str(elapsed))
    logger.info("-" * 80)

    logger.info("=" * 80)
    logger.info("Postcheck")
    logger.info("-" * 80)

    check_intfs_and_nbrs(duthosts, all_cfg_facts, nbrhosts, nbr_macs)
    check_ip_fwd(duthosts, all_cfg_facts, nbrhosts)


def test_config_reload_lc(duthosts, all_cfg_facts, nbrhosts, nbr_macs):
    """
    Tests the system after a config reload on a linecard, interfaces/neighbors should be in sync across the system.

    Args:
        duthosts: duthosts fixture
        all_cfg_facts: all_cfg_facts fixture
        nbrhosts: nbrhosts fixture
        nbr_macs: nbr_macs fixture
    """
    logger.info("=" * 80)
    logger.info("Precheck")
    logger.info("-" * 80)

    check_intfs_and_nbrs(duthosts, all_cfg_facts, nbrhosts, nbr_macs)
    check_ip_fwd(duthosts, all_cfg_facts, nbrhosts)

    logger.info("=" * 80)
    logger.info("Config reload on node: %s", duthosts.frontend_nodes[0].hostname)
    logger.info("-" * 80)

    config_reload(duthosts.frontend_nodes[0], config_source='config_db', safe_reload=True, check_intf_up_ports=True)
    poll_bgp_restored(duthosts)

    logger.info("=" * 80)
    logger.info("Postcheck")
    logger.info("-" * 80)
    check_intfs_and_nbrs(duthosts, all_cfg_facts, nbrhosts, nbr_macs)
    check_ip_fwd(duthosts, all_cfg_facts, nbrhosts)
