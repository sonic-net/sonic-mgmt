import contextlib
import ipaddress
import json
import logging
import netaddr
import pytest
import random

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.generators import generate_ips
from tests.common.helpers.parallel import parallel_run
from tests.common.helpers.parallel import reset_ansible_local_tmp
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

@pytest.fixture(scope='module')
def setup_keepalive_and_hold_timer(duthosts, rand_one_dut_hostname, nbrhosts):
    duthost = duthosts[rand_one_dut_hostname]
    # incrase the keepalive and hold timer
    duthost.command("vtysh -c \"configure terminal\" \
                           -c \"router bgp {}\" \
                           -c \"neighbor {} timers 60 180\"".format(
                               metadata['localhost']['bgp_asn'], \
                               bgp_nbr_ip))

    for k, nbr in nbrhosts.items():
        nbr['host'].eos_config(lines=["timers 60 180"], parents=["router bgp {}".format(bgp_nbr['asn'])])

    yield


def check_results(results):
    """Helper function for checking results of parallel run.

    Args:
        results (Proxy to shared dict): Results of parallel run, indexed by node name.
    """
    failed_results = {}
    for node_name, node_results in results.items():
        failed_node_results = [res for res in node_results if res['failed']]
        if len(failed_node_results) > 0:
            failed_results[node_name] = failed_node_results
    if failed_results:
        logger.error('failed_results => {}'.format(json.dumps(failed_results, indent=2)))
        pt_assert(False, 'Some processes for updating nbr hosts configuration returned failed results')


@pytest.fixture(scope='module')
def setup_bgp_graceful_restart(duthosts, rand_one_dut_hostname, nbrhosts):
    duthost = duthosts[rand_one_dut_hostname]

    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})

    @reset_ansible_local_tmp
    def configure_nbr_gr(node=None, results=None):
        """Target function will be used by multiprocessing for configuring VM hosts.

        Args:
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        node_results = []
        logger.info('enable graceful restart on neighbor host {}'.format(node['host'].hostname))
        logger.info('bgp asn {}'.format(node['conf']['bgp']['asn']))
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart restart-time 300'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn'])], \
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv4'], \
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv6'], \
                module_ignore_errors=True)
            )
        results[node['host'].hostname] = node_results

    results = parallel_run(configure_nbr_gr, (), {}, nbrhosts.values(), timeout=120)

    check_results(results)

    logger.info("bgp neighbors: {}".format(bgp_neighbors.keys()))
    if not wait_until(300, 10, duthost.check_bgp_session_state, bgp_neighbors.keys()):
        pytest.fail("not all bgp sessions are up after enable graceful restart")

    if not wait_until(60, 5, duthost.check_default_route):
        pytest.fail("ipv4 or ipv6 default route not available")

    yield

    @reset_ansible_local_tmp
    def restore_nbr_gr(node=None, results=None):
        """Target function will be used by multiprocessing for restoring configuration for the VM hosts.

        Args:
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        # start bgpd if not started
        node_results = []
        node['host'].start_bgpd()
        logger.info('disable graceful restart on neighbor {}'.format(k))
        node_results.append(node['host'].eos_config(
                lines=['no graceful-restart'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv4'], \
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['no graceful-restart'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv6'], \
                module_ignore_errors=True)
            )
        results[node['host'].hostname] = node_results

    results = parallel_run(restore_nbr_gr, (), {}, nbrhosts.values(), timeout=120)

    check_results(results)

    if not wait_until(300, 10, duthost.check_bgp_session_state, bgp_neighbors.keys()):
        pytest.fail("not all bgp sessions are up after disable graceful restart")


@pytest.fixture(scope="module")
def setup_interfaces(duthost, ptfhost, request, tbinfo):
    """Setup interfaces for the new BGP peers on PTF."""

    def _is_ipv4_address(ip_addr):
        return ipaddress.ip_address(ip_addr).version == 4

    @contextlib.contextmanager
    def _setup_interfaces_t0(mg_facts, peer_count):
        try:
            connections = []
            vlan_intf = None
            for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
                if _is_ipv4_address(vlan_intf["addr"]):
                    break
            if vlan_intf is None:
                raise ValueError("No Vlan interface defined in T0.")
            vlan_intf_name = vlan_intf["attachto"]
            vlan_intf_addr = "%s/%s" % (vlan_intf["addr"], vlan_intf["prefixlen"])
            vlan_members = mg_facts["minigraph_vlans"][vlan_intf_name]["members"]
            local_interfaces = random.sample(vlan_members, peer_count)
            neighbor_addresses = generate_ips(
                peer_count,
                vlan_intf["subnet"],
                [netaddr.IPAddress(vlan_intf["addr"])]
            )

            for local_intf, neighbor_addr in zip(local_interfaces, neighbor_addresses):
                conn = {}
                conn["local_intf"] = vlan_intf_name
                conn["local_addr"] = vlan_intf_addr
                conn["neighbor_addr"] = neighbor_addr
                conn["neighbor_intf"] = "eth%s" % mg_facts["minigraph_port_indices"][local_intf]
                connections.append(conn)

            for conn in connections:
                ptfhost.shell("ifconfig %s %s" % (conn["neighbor_intf"],
                                                  conn["neighbor_addr"]))

            yield connections

        finally:
            for conn in connections:
                ptfhost.shell("ifconfig %s 0.0.0.0" % conn["neighbor_intf"])

    @contextlib.contextmanager
    def _setup_interfaces_t1(mg_facts, peer_count):
        try:
            connections = []
            ipv4_interfaces = [_ for _ in mg_facts["minigraph_interfaces"] if _is_ipv4_address(_['addr'])]
            used_subnets = [ipaddress.ip_network(_["subnet"]) for _ in ipv4_interfaces]
            subnet_prefixlen = used_subnets[0].prefixlen
            used_subnets = set(used_subnets)
            for pt in mg_facts["minigraph_portchannel_interfaces"]:
                if _is_ipv4_address(pt["addr"]):
                    used_subnets.add(ipaddress.ip_network(pt["subnet"]))
            _subnets = ipaddress.ip_network(u"10.0.0.0/24").subnets(new_prefix=subnet_prefixlen)
            subnets = (_ for _ in _subnets if _ not in used_subnets)

            for intf, subnet in zip(random.sample(ipv4_interfaces, peer_count), subnets):
                conn = {}
                local_addr, neighbor_addr = [_ for _ in subnet][:2]
                conn["local_intf"] = "%s" % intf["attachto"]
                conn["local_addr"] = "%s/%s" % (local_addr, subnet_prefixlen)
                conn["neighbor_addr"] = "%s/%s" % (neighbor_addr, subnet_prefixlen)
                conn["neighbor_intf"] = "eth%s" % mg_facts["minigraph_port_indices"][intf["attachto"]]
                connections.append(conn)

            for conn in connections:
                # bind the ip to the interface and notify bgpcfgd 
                duthost.shell("config interface ip add %s %s" % (conn["local_intf"], conn["local_addr"]))
                ptfhost.shell("ifconfig %s %s" % (conn["neighbor_intf"], conn["neighbor_addr"]))

            yield connections

        finally:
            for conn in connections:
                duthost.shell("config interface ip remove %s %s" % (conn["local_intf"], conn["local_addr"]))
                ptfhost.shell("ifconfig %s 0.0.0.0" % conn["neighbor_intf"])

    peer_count = getattr(request.module, "PEER_COUNT", 1)
    if tbinfo["topo"]["type"] == "t0":
        setup_func = _setup_interfaces_t0
    elif tbinfo["topo"]["type"] == "t1":
        setup_func = _setup_interfaces_t1
    else:
        raise TypeError("Unsupported topology: %s" % tbinfo["topo"]["type"])

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    with setup_func(mg_facts, peer_count) as connections:
        yield connections

    duthost.shell("sonic-clear arp")
