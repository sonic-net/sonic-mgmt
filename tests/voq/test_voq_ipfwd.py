import logging
import pytest
import random
import ipaddress
import json
from tests.common.helpers.assertions import pytest_assert
from tests.common.errors import RunAnsibleModuleFail

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

from tests.common.utilities import wait_until
from tests.common.helpers.parallel import parallel_run
from tests.common.platform.device_utils import fanout_switch_port_lookup

from ptf.testutils import simple_udp_packet, simple_icmp_packet, simple_udpv6_packet, simple_icmpv6_packet
from ptf.testutils import send, dp_poll, verify_no_packet_any
from ptf.mask import Mask
import ptf.packet as scapy

from test_voq_nbr import LinkFlap

from voq_helpers import sonic_ping
from voq_helpers import eos_ping
from voq_helpers import get_inband_info
from voq_helpers import get_vm_with_ip
from voq_helpers import asic_cmd
from voq_helpers import get_port_by_ip
from voq_helpers import get_sonic_mac
from voq_helpers import get_eos_mac

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.sanity_check(check_items=["-monit"], allow_recover=False),
    pytest.mark.disable_loganalyzer
]

LOG_PING = True
DEFAULT_EOS_TTL = 64
DEFAULT_SONIC_TTL = 64


# Analyze logs at the beginning and end of all tests in the module, instead of each test.
@pytest.fixture(scope="module", autouse=True)
def loganalyzer(duthosts, request):
    analyzers = {}
    markers = {}
    # Analyze all the duts
    for duthost in duthosts:
        # Force rotate logs
        try:
            duthost.shell("/usr/sbin/logrotate -f /etc/logrotate.conf > /dev/null 2>&1")
        except RunAnsibleModuleFail as e:
            logging.warning("logrotate is failed. Command returned:\n"
                            "Stdout: {}\n"
                            "Stderr: {}\n"
                            "Return code: {}".format(e.results["stdout"], e.results["stderr"], e.results["rc"]))

        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=request.node.name)
        logging.info("Add start marker into DUT syslog")
        marker = loganalyzer.init()
        logging.info("Load config and analyze log")
        # Read existed common regular expressions located with legacy loganalyzer module
        loganalyzer.load_common_config()
        analyzers[duthost.hostname] = loganalyzer
        markers[duthost.hostname] = marker

    yield analyzers

    for dut_hostname, dut_analyzer in analyzers.items():
        dut_analyzer.analyze(markers[dut_hostname])


def _get_nbr_macs(nbrhosts, node=None, results=None):
    vm = nbrhosts[node]
    node_results = {}

    for intf in vm['conf']['interfaces'].keys():
        logger.info("Get MAC on vm %s for intf: %s", node, intf)
        mac = get_eos_mac(vm, intf)
        logger.info("Found MAC on vm %s for intf: %s, mac: %s", node, intf, mac['mac'])
        node_results[intf] = mac['mac']

    results[node] = node_results


@pytest.fixture(scope="module")
def nbr_macs(nbrhosts):
    """
    Fixture to get all the neighbor mac addresses in parallel.

    Args:
        nbrhosts:

    Returns:

    """
    results = {}

    parallel_run(_get_nbr_macs, [nbrhosts], results, nbrhosts.keys(), timeout=120)

    for res in results['results']:
        logger.info("parallel_results %s = %s", res, results['results'][res])

    return results['results']


def log_port_info(ports):
    """
    Dumps the picked ports to the log file.

    Args:
        ports: Output of pick_ports.

    """
    port_dict_to_print = {}
    for a_port_name, a_port in ports.items():
        port_dict_to_print[a_port_name] = {}
        for a_fld_name in a_port:
            if a_fld_name == 'dut':
                port_dict_to_print[a_port_name]['dut'] = a_port['dut'].hostname
            elif a_fld_name == 'asic':
                port_dict_to_print[a_port_name]['asic'] = a_port['asic'].asic_index
            elif isinstance(a_port[a_fld_name], ipaddress.IPv4Address) or isinstance(a_port[a_fld_name],
                                                                                     ipaddress.IPv6Address):
                port_dict_to_print[a_port_name][a_fld_name] = "%s" % a_port[a_fld_name]
            else:
                port_dict_to_print[a_port_name][a_fld_name] = a_port[a_fld_name]

    logger.info("Ports picked are:\n%s" % json.dumps(port_dict_to_print, indent=4))


def get_info_for_a_port(cfg_facts, iface_list, version, dut, asic_index, nbrhosts):
    """
    Picks a port from the interface list and gets all the required data for a port to test
    with, IP, portnames, attached VMs, etc.

    Args:
        cfg_facts: config facts fot the asic.
        iface_list: Interface list for the ASIC.
        version: 4 or 6 for IP version.
        dut: Duthost instance the port is on.
        asic_index: Asic index the port is on (0, 1, etc).
        nbrhosts: nbrhosts fixture.

    Returns:

    """
    rtn_dict = {}
    port = random.choice(iface_list)
    rtn_dict['port'] = port
    rtn_dict['my_ip'] = get_ip_address(cfg_facts, port, version)
    rtn_dict['dut'] = dut
    rtn_dict['asic'] = dut.asics[asic_index]

    # Get nbr VM info from the configured facts
    nbr_in_cfg = cfg_facts['BGP_NEIGHBOR']
    nbr_ip = [n for n in nbr_in_cfg if ipaddress.ip_address(nbr_in_cfg[n]['local_addr']) == rtn_dict['my_ip']][0]
    nbr_dict = get_vm_with_ip(nbr_ip, nbrhosts)
    rtn_dict['nbr_ip'] = nbr_ip
    rtn_dict['nbr_vm'] = nbr_dict['vm']
    rtn_dict['nbr_port'] = nbr_dict['port']
    rtn_dict['nbr_lb'] = ipaddress.ip_interface(
        unicode(nbrhosts[nbr_dict['vm']]['conf']['interfaces']['Loopback0']['ipv%s' % version])).ip

    # Get my lbk addresses
    lbs = cfg_facts['LOOPBACK_INTERFACE']['Loopback0'].keys()
    for lb in lbs:
        lbintf = ipaddress.ip_interface(lb)
        if lbintf.ip.version == version:
            rtn_dict['my_lb_ip'] = lbintf.ip

    # Get the inband interface ip
    inband_ips = get_inband_info(cfg_facts)
    rtn_dict['inband'] = inband_ips['ipv%s_addr' % version]

    return rtn_dict


def pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a="ethernet", version=4):
    """
    Selects ports to test by sampling the interface and port channel lists.

    Args:
        duthosts: The duthosts fixture.
        all_cfg_facts: The config_facts for all the duts.
        nbrhosts: The nbrhosts fixture.
        port_type_a: ethernet or portchannel, the port type for the main test port.
        version: 4 or 6, the IP version to test.

    Returns:
        intfs_to_test: A merged dictionary of ethernet and portchannel interfaces to test
            portA - interface of type port_type_A on first frontend node in an asic.
            portB - interface on first frontend node in the same asic as portA - preferably of type different than
                    port_type_A.
            portC - interface on any asic other than portA asic in the chassis of type port_type_A - preferably on
                    another frontend node.
            portD - interface on any asic other than portA asic in the chassis of type different than port_type_A -
                    preferably on another frontend node.

        if we can't find portA we will skip the test.
        if we can't find any portB, portC, or portD, then their respective dictionary will be None, and the ping tests
             to that port would be ignored.
        intfs_to_test: A list of the chosen interfaces names.

    """
    intfs_to_test = {}
    # Lets find portA and portB in the first frontend node
    dutA = duthosts.frontend_nodes[0]

    for a_asic_index, a_asic_cfg in enumerate(all_cfg_facts[dutA.hostname]):
        cfg_facts = a_asic_cfg['ansible_facts']
        cfgd_intfs = cfg_facts['INTERFACE'] if 'INTERFACE' in cfg_facts else {}
        cfgd_pos = cfg_facts['PORTCHANNEL_INTERFACE'] if 'PORTCHANNEL_INTERFACE' in cfg_facts else {}
        eths = [intf for intf in cfgd_intfs if "ethernet" in intf.lower()]
        pos = [intf for intf in cfgd_pos if "portchannel" in intf.lower()]
        if port_type_a == "ethernet":
            if len(eths) != 0:
                intfs_to_test['portA'] = get_info_for_a_port(cfg_facts, eths, version, dutA, a_asic_index, nbrhosts)
                # We have one ethernet interface, lets check for a pos interface for portB
                if len(pos) != 0:
                    intfs_to_test['portB'] = get_info_for_a_port(cfg_facts, pos, version, dutA, a_asic_index, nbrhosts)
                else:
                    # No pos interfaces, let see if we have other ethernet ports in this asic
                    if len(eths) != 1:
                        # We have more than 1 eth interface, pick it for port B
                        intfs_to_test['portB'] = get_info_for_a_port(cfg_facts, eths, version, dutA, a_asic_index,
                                                                     nbrhosts)
        else:
            # port type is portchannel
            if len(pos) != 0:
                intfs_to_test['portA'] = get_info_for_a_port(cfg_facts, pos, version, dutA, a_asic_index, nbrhosts)
                # We have one pc interface, lets check for a eth interface for portB
                if len(eths) != 0:
                    intfs_to_test['portB'] = get_info_for_a_port(cfg_facts, eths, version, dutA, a_asic_index, nbrhosts)
                else:
                    # No eth interfaces, let see if we have other pc ports in this asic
                    if len(pos) != 1:
                        # We have more than 1 pc interface, pick it for port B
                        intfs_to_test['portB'] = get_info_for_a_port(cfg_facts, pos, version, dutA, a_asic_index,
                                                                     nbrhosts)

        if 'portA' in intfs_to_test:
            break

    if len(duthosts.frontend_nodes) == 1:
        # We are dealing with a single card, lets find the portC and portD in other asic on the same card
        other_duts = [dutA]
    else:
        other_duts = duthosts.frontend_nodes[1:]

    # Lets try to find portC and portD on other asics/linecards.
    for a_dut in other_duts:
        for a_asic_index, a_asic_cfg in enumerate(all_cfg_facts[a_dut.hostname]):
            if a_dut == dutA and a_asic_index == intfs_to_test['portA']['asic']:
                # Ignore the asic we used for portA
                continue
            cfg_facts = a_asic_cfg['ansible_facts']
            cfgd_intfs = cfg_facts['INTERFACE'] if 'INTERFACE' in cfg_facts else {}
            cfgd_pos = cfg_facts['PORTCHANNEL_INTERFACE'] if 'PORTCHANNEL_INTERFACE' in cfg_facts else {}
            eths = [intf for intf in cfgd_intfs if "ethernet" in intf.lower()]
            pos = [intf for intf in cfgd_pos if "portchannel" in intf.lower()]
            if len(eths) != 0:
                if port_type_a == "ethernet":
                    intfs_to_test['portC'] = get_info_for_a_port(cfg_facts, eths, version, a_dut, a_asic_index,
                                                                 nbrhosts)
                else:
                    intfs_to_test['portD'] = get_info_for_a_port(cfg_facts, eths, version, a_dut, a_asic_index,
                                                                 nbrhosts)

            if len(pos) != 0:
                if port_type_a == "ethernet":
                    intfs_to_test['portD'] = get_info_for_a_port(cfg_facts, pos, version, a_dut, a_asic_index, nbrhosts)
                else:
                    intfs_to_test['portC'] = get_info_for_a_port(cfg_facts, pos, version, a_dut, a_asic_index, nbrhosts)

            if 'portC' in intfs_to_test and 'portD' in intfs_to_test:
                # We have found both portC and portD - no need to check other asics
                break

        if 'portC' in intfs_to_test and 'portD' in intfs_to_test:
            # We have found both portC and portD - no need to check other DUTs
            break
    log_port_info(intfs_to_test)
    return intfs_to_test


def get_ip_address(cfg_facts, port, ipver):
    """
    Gets the IP address of a port.

    Args:
        cfg_facts: Config facts for an asic.
        port: Port name.
        ipver: IP version, 4 or 6.

    Returns:
        an ipaddress.IPAddress() for the port.

    """

    intfs = {}
    intfs.update(cfg_facts['INTERFACE'])
    if "PORTCHANNEL_INTERFACE" in cfg_facts:
        intfs.update(cfg_facts['PORTCHANNEL_INTERFACE'])

    addresses = intfs[port]
    for address in addresses:
        intf = ipaddress.ip_interface(address)
        if intf.ip.version == ipver:
            return intf.ip


def check_packet(function, ports, dst_port, src_port, dev=None, dst_ip_fld='my_ip', ttl=64, size=64, src_ip_fld='my_ip',
                 ttl_change=1):
    """
    Calls a ping function and verifies the output and whether TTL was decremented on the RX packet.

    Args:
        function: Traffic function to call, sonic_ping or eos_ping.
        ports: pick_ports output.
        dst_port: entry in pick_ports of destination port ("portD")
        src_port: entry in pick_ports of source port ("portA")
        dev: Device to run function on, and EosHost or SonicAsic.
        dst_ip_fld: Entry in pick_ports dictionary to use as IP destination.
        ttl: Initial TTL.
        size: Initial packet ICMP data size.
        src_ip_fld: Entry in pick_ports dictionary to use as IP source.
        ttl_change: Expected TTL change.

    Raises:
        pytest.Failed if the checks failed.

    """
    if dst_port in ports and src_port in ports:
        if not dev:
            dev = ports[src_port]['asic']
        src_ip = ports[src_port][src_ip_fld]
        dst_ip = ports[dst_port][dst_ip_fld]

        if ttl > ttl_change:
            out = function(dev, dst_ip, count=1, size=size, ttl=ttl, interface=src_ip, verbose=LOG_PING)
            for response in out['parsed']:
                logger.info("response: %s", response)
                pytest_assert(response['ttl'] == str(DEFAULT_EOS_TTL - ttl_change),
                              "TTL did not change by: %d, %s => %s, %s != %s" % (
                                  ttl_change, src_ip, dst_ip, response['ttl'], str(DEFAULT_EOS_TTL - ttl_change)))
        else:
            logger.info("Testing a TTL 0 scenario, packet should be lost: %d, %s => %s" % (ttl_change, src_ip, dst_ip))
            with pytest.raises((AssertionError, RunAnsibleModuleFail)) as exc:
                function(dev, dst_ip, count=1, size=size, ttl=ttl, interface=src_ip, verbose=LOG_PING)

            logger.info("Raised exception: %s, value: %s", str(exc), str(exc.value))
            if isinstance(exc.type, AssertionError):
                logging.info("exc.value = %s ... entry0 %s", exc.value, exc.value[0][0])
                pytest_assert(exc.value[0][0]['ttl_exceed'] is True, "Packet with ttl 1 should not have arrived")


class TestTableValidation(object):
    """
    Verify the kernel route table is correct based on the topology.

    Test Steps

    * Verify routes for local addresses on both line cards are directly connected.
    * Verify routes for local inband interfaces are directly connected.
    * Verify BGP established between line cards.
    * Verify routes of remote linecard inband interfaces are connected via local linecard inband interface.
    * Verify IP interface addresses on remote network ports have a next hop of their inband IP. On linecard 1,
      route 10.0.0.64/31 next hop is 133.133.133.5.
    * Verify all learned prefixes from neighbors have their neighbors as next hop.
    * Repeat for IPv4 only, IPv6 only, dual-stack.
    """

    def test_host_route_table_local_addr(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                                         all_cfg_facts):
        """
        Verify routes for local addresses on both line cards are directly connected.

        Args:
            duthosts: duthosts fixture
            enum_rand_one_per_hwsku_frontend_hostname: linecard enum fixture.
            enum_asic_index: asic enum fixture.
            all_cfg_facts: all_cfg_facts fixture from voq/conftest.py

        """

        per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

        ipv4_routes = asic_cmd(asic, "ip -4 route")["stdout_lines"]
        ipv6_routes = asic_cmd(asic, "ip -6 route")["stdout_lines"]

        intfs = {}
        intfs.update(cfg_facts['INTERFACE'])
        if "PORTCHANNEL_INTERFACE" in cfg_facts:
            intfs.update(cfg_facts['PORTCHANNEL_INTERFACE'])

        for port in intfs:
            for address in intfs[port]:
                ip_intf = ipaddress.ip_interface(address)
                logger.info("Network %s v%s, is connected via: %s", str(ip_intf.network), ip_intf.network.version, port)
                if ip_intf.network.version == 6:
                    routes = ipv6_routes
                else:
                    routes = ipv4_routes

                for route in routes:
                    if route.startswith("{} dev {} proto kernel".format(str(ip_intf.network), port)):
                        logger.info("Matched route for %s", str(ip_intf.network))
                        break
                else:
                    pytest.fail("Did not find route for: %s" % str(ip_intf.network))

    def test_host_route_table_inband_addr(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                                          all_cfg_facts):
        """
        Verify routes for local inband interfaces are directly connected. Verify routes of remote linecard inband
        interfaces are connected via local linecard inband interface.

        Args:
            duthosts: duthosts fixture
            enum_rand_one_per_hwsku_frontend_hostname: linecard enum fixture.
            enum_asic_index: asic enum fixture.
            all_cfg_facts: all_cfg_facts fixture from voq/conftest.py


        """

        per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

        ipv4_routes = asic_cmd(asic, "ip -4 route")["stdout_lines"]
        ipv6_routes = asic_cmd(asic, "ip -6 route")["stdout_lines"]

        intf = cfg_facts['VOQ_INBAND_INTERFACE']
        for port in intf:
            for address in cfg_facts['BGP_INTERNAL_NEIGHBOR'].keys():
                ip_intf = ipaddress.ip_interface(address)
                logger.info("Network %s v%s, is connected via: %s", str(ip_intf.network), ip_intf.network.version, port)
                if ip_intf.network.version == 6:
                    routes = ipv6_routes
                else:
                    routes = ipv4_routes

                for route in routes:
                    if route.startswith("{} dev {}".format(str(ip_intf.ip), port)):
                        logger.info("Matched route for %s", str(ip_intf.ip))
                        break
                else:
                    pytest.fail("Did not find route for: %s" % str(ip_intf.ip))

    def test_host_route_table_bgp(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                                  all_cfg_facts):
        """
        Verify BGP established between line cards.

        Args:
            duthosts: duthosts fixture
            enum_rand_one_per_hwsku_frontend_hostname: linecard enum fixture.
            enum_asic_index: asic enum fixture.
            all_cfg_facts: all_cfg_facts fixture from voq/conftest.py


        """
        per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

        bgp_facts = per_host.bgp_facts(instance_id=enum_asic_index)['ansible_facts']

        for address in cfg_facts['BGP_INTERNAL_NEIGHBOR'].keys():
            pytest_assert(bgp_facts['bgp_neighbors'][address]['state'] == "established",
                          "BGP internal neighbor: %s is not established: %s" % (
                              address, bgp_facts['bgp_neighbors'][address]['state']))

    def test_host_route_table_remote_interface_addr(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                                    enum_asic_index, all_cfg_facts):
        """
        Verify IP interface addresses on remote network ports have a next hop of their inband IP.
        On linecard 1, route 10.0.0.64/31 next hop is 133.133.133.5.

        Args:
            duthosts: duthosts fixture
            enum_rand_one_per_hwsku_frontend_hostname: linecard enum fixture.
            enum_asic_index: asic enum fixture.
            all_cfg_facts: all_cfg_facts fixture from voq/conftest.py


        """
        per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

        ipv4_routes = asic_cmd(asic, "ip -4 route")["stdout_lines"]
        ipv6_routes = asic_cmd(asic, "ip -6 route")["stdout_lines"]

        inband = get_inband_info(cfg_facts)
        for rem_host in duthosts.frontend_nodes:
            for rem_asic in rem_host.asics:
                if rem_host == per_host and rem_asic == asic:
                    # skip remote check on local host
                    continue

                rem_cfg_facts = all_cfg_facts[rem_host.hostname][rem_asic.asic_index]['ansible_facts']
                rem_inband_info = get_inband_info(rem_cfg_facts)
                rem_intfs = {}
                rem_intfs.update(rem_cfg_facts['INTERFACE'])
                if "PORTCHANNEL_INTERFACE" in rem_cfg_facts:
                    rem_intfs.update(rem_cfg_facts['PORTCHANNEL_INTERFACE'])

                for port in rem_intfs:
                    for address in rem_intfs[port]:

                        ip_intf = ipaddress.ip_interface(address)
                        logger.info("Network %s v%s, is connected via: %s, on host: %s", str(ip_intf.network),
                                    ip_intf.network.version, inband['port'], per_host.hostname)
                        if ip_intf.network.version == 6:
                            routes = ipv6_routes
                            inband_ip = rem_inband_info['ipv6_addr']
                        else:
                            routes = ipv4_routes
                            inband_ip = rem_inband_info['ipv4_addr']

                        for route in routes:
                            if route.startswith(
                                    "{} via {} dev {}".format(str(ip_intf.network), inband_ip, inband['port'])):
                                logger.info("Matched route for %s", str(ip_intf.network))
                                break
                        else:
                            pytest.fail("Did not find route for: %s" % str(ip_intf.network))

    def test_host_route_table_nbr_lb_addr(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index,
                                          all_cfg_facts, nbrhosts):
        """
        Verify all learned prefixes from neighbors have their neighbors as next hop.

        Args:
            duthosts: duthosts fixture
            enum_rand_one_per_hwsku_frontend_hostname: linecard enum fixture.
            enum_asic_index: asic enum fixture.
            all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
            nbrhosts: nbrhosts fixture.

        """
        per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic = per_host.asics[enum_asic_index if enum_asic_index is not None else 0]
        cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

        ipv4_routes = asic_cmd(asic, "ip -4 route")["stdout_lines"]
        ipv6_routes = asic_cmd(asic, "ip -6 route")["stdout_lines"]

        # get attached neighbors
        neighs = cfg_facts['BGP_NEIGHBOR']
        for neighbor in neighs:
            local_ip = neighs[neighbor]['local_addr']

            local_port = get_port_by_ip(cfg_facts, local_ip)
            nbr = get_vm_with_ip(neighbor, nbrhosts)
            nbr_vm = nbr['vm']

            neigh_ip = ipaddress.ip_address(neighbor)
            lbip = ipaddress.ip_interface(
                unicode(nbrhosts[nbr_vm]['conf']['interfaces']['Loopback0']['ipv%s' % neigh_ip.version]))
            logger.info("Verify loopback0 ip: %s is connected via ip: %s port: %s", str(lbip), str(neigh_ip),
                        local_port)

            if lbip.ip.version == 6:
                routes = ipv6_routes
            else:
                routes = ipv4_routes

            for route in routes:
                if route.startswith("{} via {} dev {} proto bgp".format(str(lbip.ip), str(neigh_ip), local_port)):
                    logger.info("Matched route for %s", str(lbip.ip))
                    break
            else:
                pytest.fail("Did not find route for: %s" % str(lbip.ip))


class TestVoqIPFwd(object):

    @pytest.mark.parametrize('ttl, size', [(2, 1500), (255, 1500), (128, 64), (128, 9000)])
    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["portchannel", "ethernet"])
    def test_voq_local_interface_ping(self, duthosts, nbrhosts, all_cfg_facts, ttl, size, version, porttype):
        """
        Verify Host IP forwarding for IPv4 and IPv6 for various packet sizes and ttls to local line card interfaces.

        Test Steps

        * On linecard 1, send ping from:
            * DUT IP interface A to DUT IP Interface B. (10.0.0.0 to 10.0.0.2)
            * DUT IP interface A to DUT IP Interface D. (10.0.0.0 to 10.0.0.64)
        * On linecard 2, send ping from:
            * DUT IP interface D to DUT IP Interface A.
        * Repeat for TTL 0,1,2,255
        * Repeat for 64, 1500, 9100B packets
        * Repeat for IPv6

        Args:
            duthosts: The duthosts fixture.
            nbrhosts: The nbrhosts fixture.
            all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
            ttl: TTL of transmitted packet.
            size: ICMP data size
            version: IP version.
            porttype: Test port type, ethernet or portchannel

        """
        logger.info(
            "Pinging local interfaces for ip: {ipv}, ttl: {ttl}, size: {size}".format(ipv=version, ttl=ttl, size=size))
        ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)

        check_packet(sonic_ping, ports, 'portB', 'portA', size=size, ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portC', 'portA', size=size, ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', size=size, ttl=ttl, ttl_change=1)

        if 'portC' in ports:
            check_packet(sonic_ping, ports, 'portA', 'portC', size=size, ttl=ttl, ttl_change=1)
        else:
            check_packet(sonic_ping, ports, 'portA', 'portD', size=size, ttl=ttl, ttl_change=1)

    @pytest.mark.parametrize('ttl, size', [(2, 64), (128, 64), (255, 1456), (1, 1456)])
    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_voq_local_neighbor_ping(self, duthosts, all_cfg_facts, ttl, size, version, porttype, nbrhosts):
        """
        Verify Host IP forwarding for IPv4 and IPv6 for various packet sizes and ttls to neighbor addresses.

        Test Steps

        * On linecard 1, send ping from:
            * DUT IP Interface on port A to directly connected neighbor address. (10.0.0.0 to 10.0.0.1)
            * DUT IP Interface A to neighbor address on port B. (10.0.0.0 to 10.0.0.3)
            * DUT IP Interface A to neighbor address on port D. (10.0.0.0 to 10.0.0.65)
        * On linecard 2, send ping from:
            * DUT IP interface D to neighbor address on port A. (10.0.0.64 to 10.0.0.1)
        * On Router 01T3, send ping from:
            * Router IP interface to DUT address on port A. (10.0.0.1 to 10.0.0.0)
            * Router IP interface to DUT address on port D. (10.0.0.1 to 10.0.0.64)
        * Repeat for TTL 0,1,2,255
        * Repeat for 64, 1500, 9100B packets
        * Repeat for IPv6

        Args:
            duthosts: The duthosts fixture.
            nbrhosts: The nbrhosts fixture.
            all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
            ttl: TTL of transmitted packet.
            size: ICMP data size
            version: IP version.
            porttype: Test port type, ethernet or portchannel

        """
        ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)
        logger.info(
            "Pinging local interfaces for ip: {ipv}, ttl: {ttl}, size: {size}".format(ipv=version, ttl=ttl, size=size))
        check_packet(sonic_ping, ports, 'portA', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portB', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portC', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=1)

        vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

        if 'portC' in ports:
            check_packet(sonic_ping, ports, 'portA', 'portC', dev=ports['portC']['asic'], dst_ip_fld='nbr_ip',
                         size=size, ttl=ttl)
            check_packet(eos_ping, ports, 'portC', 'portA', dst_ip_fld='my_ip', src_ip_fld='nbr_ip',
                         dev=vm_host_to_A, size=size, ttl=ttl)
        else:
            check_packet(sonic_ping, ports, 'portA', 'portD', dev=ports['portD']['asic'], dst_ip_fld='nbr_ip',
                         size=size, ttl=ttl)
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_ip', src_ip_fld='nbr_ip',
                         dev=vm_host_to_A, size=size, ttl=ttl)

        check_packet(eos_ping, ports, 'portA', 'portA', src_ip_fld='nbr_ip', dst_ip_fld='my_ip',
                     dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=0)

    @pytest.mark.parametrize('ttl, size', [(2, 64), (128, 64), (255, 1456), (1, 1456)])
    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_voq_neighbor_lb_ping(self, duthosts, all_cfg_facts, ttl, size, version, porttype, nbrhosts):
        """
        Verify Host IP forwarding for IPv4 and IPv6 for various packet sizes and ttls to learned route addresses.

        Test Steps

        * On linecard 1, send ping from:
            * DUT IP Interface A to routed loopback address from router 01T3. (10.0.0.0 to 100.1.0.1)
            * DUT IP Interface A to routed loopback address from router 02T3. (10.0.0.0 to 100.1.0.2)
            * DUT IP Interface A to routed loopback address from router 01T1. (10.0.0.0 to 100.1.0.33)
        * On linecard 2, send ping from:
            * DUT IP interface D to routed loopback address from router 01T3. (200.0.0.1 to 100.1.0.1)
        * On Router 01T3, send ping from:
            * Router loopback interface to DUT address on port A. (100.1.0.1 to 10.0.0.0)
            * Router loopback interface to DUT address on port D. (100.1.0.1 to 10.0.0.64)
        * Repeat for TTL 0,1,2,255
        * Repeat for 64, 1500, 9100B packets
        * Repeat for IPv6

        Args:
            duthosts: The duthosts fixture.
            nbrhosts: The nbrhosts fixture.
            all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
            ttl: TTL of transmitted packet.
            size: ICMP data size
            version: IP version.
            porttype: Test port type, ethernet or portchannel

        """
        ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)
        logger.info("Pinging neighbor interfaces for ip: {ipv}, ttl: {ttl}, size: {size}".format(ipv=version, ttl=ttl,
                                                                                                 size=size))

        check_packet(sonic_ping, ports, 'portA', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portB', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portC', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=1)

        vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

        if 'portC' in ports:
            check_packet(sonic_ping, ports, 'portA', 'portC', dst_ip_fld='nbr_lb', dev=ports['portC']['asic'],
                         size=size, ttl=ttl)
            check_packet(eos_ping, ports, 'portC', 'portA', dst_ip_fld='my_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=1)
        else:
            check_packet(sonic_ping, ports, 'portA', 'portD', dst_ip_fld='nbr_lb', dev=ports['portD']['asic'],
                         size=size, ttl=ttl)
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=1)

    @pytest.mark.parametrize('ttl, size', [(2, 64), (128, 64), (255, 1456), (1, 1456)])
    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_voq_inband_ping(self, duthosts, all_cfg_facts, ttl, size, version, porttype, nbrhosts):
        """
        Verify IP connectivity over inband interfaces.

        * On linecard 1 send ping from:
            * Inband interface F0 to inband interface F1 (133.133.133.1 to 133.133.133.5)
            * Inband interface F0 to interface D (133.133.133.1 to 10.0.0.64)
            * Inband interface F0 to neighbor on port A (133.133.133.1 to 10.0.0.1)
            * Inband interface F0 to neighbor on port D (133.133.133.1 to 10.0.0.65)
            * Inband interface F0 to routed loopback from router 01T3 (133.133.133.1 to 100.1.0.1)
            * Inband interface F0 to routed loopback from router 01T1 (133.133.133.1 to 100.1.0.33)
        * On linecard 2, send ping from:
            * Inband interface F1 to inband interface F0 (133.133.133.5 to 133.133.133.1)
            * Inband interface F1 to interface D (133.133.133.5 to 10.0.0.64)
            * Inband interface F1 to neighbor on port A (133.133.133.5 to 10.0.0.1)
            * Inband interface F1 to neighbor on port D (133.133.133.5 to 10.0.0.65)
            * Inband interface F1 to routed loopback from router 01T3 (133.133.133.5 to 100.1.0.1)
            * Inband interface F1 to routed loopback from router 01T1 (133.133.133.5 to 100.1.0.33)
        * On Router 01T3, send ping from:
            * Router loopback interface to DUT inband address on linecard 1. (100.1.0.1 to 133.133.133.1)
            * Router loopback interface to DUT inband address on linecard 2. (100.1.0.1 to 133.133.133.5)
        * Repeat for TTL 0,1,2,255
        * Repeat for 64, 1500, 9100B packets
        * Repeat for IPv6

        Args:
            duthosts: The duthosts fixture.
            nbrhosts: The nbrhosts fixture.
            all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
            ttl: TTL of transmitted packet.
            size: ICMP data size
            version: IP version.
            porttype: Test port type, ethernet or portchannel

        """
        ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)
        logger.info("Pinging neighbor interfaces for ip: {ipv}, ttl: {ttl}, size: {size}".format(ipv=version, ttl=ttl,
                                                                                                 size=size))
        remote_port = 'portD'
        if 'portC' in ports:
            remote_port = 'portC'

        check_packet(sonic_ping, ports, remote_port, 'portA', src_ip_fld='inband', dst_ip_fld='inband', size=size,
                     ttl=ttl)

        check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='inband', size=size, ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portB', 'portA', src_ip_fld='inband', size=size, ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size, ttl=ttl,
                     ttl_change=0)
        check_packet(sonic_ping, ports, 'portB', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size, ttl=ttl,
                     ttl_change=0)
        check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size, ttl=ttl,
                     ttl_change=0)
        check_packet(sonic_ping, ports, 'portB', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size, ttl=ttl,
                     ttl_change=0)

        check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='inband', size=size, ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', src_ip_fld='inband', size=size, ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size, ttl=ttl,
                     ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size, ttl=ttl,
                     ttl_change=1)
        check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size, ttl=ttl,
                     ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size, ttl=ttl,
                     ttl_change=1)

        check_packet(sonic_ping, ports, 'portA', remote_port, src_ip_fld='inband', size=size, ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portB', remote_port, src_ip_fld='inband', size=size, ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portA', remote_port, src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portB', remote_port, src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portA', remote_port, src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portB', remote_port, src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=1)

        ttl_chg_port_C = 0
        if ports[remote_port]['asic'] != ports['portC']['asic']:
            ttl_chg_port_C = 1
        ttl_chg_port_D = 0
        if ports[remote_port]['asic'] != ports['portD']['asic']:
            ttl_chg_port_D = 1

        check_packet(sonic_ping, ports, 'portC', remote_port, src_ip_fld='inband', size=size, ttl=ttl,
                     ttl_change=ttl_chg_port_C)
        check_packet(sonic_ping, ports, 'portD', remote_port, src_ip_fld='inband', size=size, ttl=ttl,
                     ttl_change=ttl_chg_port_D)
        check_packet(sonic_ping, ports, 'portC', remote_port, src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=ttl_chg_port_C)
        check_packet(sonic_ping, ports, 'portD', remote_port, src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=ttl_chg_port_D)
        check_packet(sonic_ping, ports, 'portC', remote_port, src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=ttl_chg_port_C)
        check_packet(sonic_ping, ports, 'portD', remote_port, src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=ttl_chg_port_D)

        vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']
        check_packet(eos_ping, ports, 'portA', 'portA', dst_ip_fld='inband', src_ip_fld='nbr_lb',
                     dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=0)
        check_packet(eos_ping, ports, remote_port, 'portA', dst_ip_fld='inband', src_ip_fld='nbr_lb',
                     dev=vm_host_to_A, size=size, ttl=ttl)

    @pytest.mark.parametrize('ttl, size', [(2, 64), (128, 64), (1, 1456), (255, 1456)])
    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_voq_dut_lb_ping(self, duthosts, all_cfg_facts, ttl, size, version, porttype, nbrhosts):
        """
        Verify IP Connectivity to DUT loopback addresses.

        Test Steps

        * On linecard 1 send ping from:
            * Loopback to IP interface of port D (11.1.0.1 to 10.0.0.64)
            * Loopback to neighbor on port D (11.1.0.1 to 10.0.0.65)
            * Loopback to routed loopback address (11.1.0.1 to 100.1.0.1)
            * Loopback to routed loopback address (11.1.0.1 to 100.1.0.33)
        * On Router 01T3, send ping from:
            * Router loopback interface to DUT loopback address on linecard 1. (100.1.0.1 to 11.1.0.1)
            * Router loopback interface to DUT loopback address on linecard 2. (100.1.0.1 to 11.1.0.2)
        * Repeat for TTL 0,1,2,255
        * Repeat for 64, 1500, 9100B packets
        * Repeat for IPv6

        Args:
            duthosts: The duthosts fixture.
            nbrhosts: The nbrhosts fixture.
            all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
            ttl: TTL of transmitted packet.
            size: ICMP data size
            version: IP version.
            porttype: Test port type, ethernet or portchannel

        """
        ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)
        logger.info("Pinging neighbor interfaces for ip: {ipv}, ttl: {ttl}, size: {size}".format(ipv=version, ttl=ttl,
                                                                                                 size=size))
        # these don't decrement ttl
        check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='my_ip', size=size, ttl=ttl,
                     ttl_change=0)
        check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portA', 'portB', src_ip_fld='my_lb_ip', dst_ip_fld='my_ip', size=size, ttl=ttl,
                     ttl_change=0)
        check_packet(sonic_ping, ports, 'portA', 'portB', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portA', 'portB', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=0)

        # these do decrement ttl
        check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='my_ip', size=size, ttl=ttl,
                     ttl_change=1)
        check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='my_ip', size=size, ttl=ttl,
                     ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portD', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=1)

        vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']
        check_packet(eos_ping, ports, 'portA', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                     dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=0)
        if 'portC' in ports:
            check_packet(eos_ping, ports, 'portC', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=1)
        else:
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=1)

    @pytest.mark.parametrize('ttl, size', [(2, 64), (128, 64), (255, 1456)])
    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_voq_end_to_end_ping(self, duthosts, all_cfg_facts, ttl, size, version, porttype, nbrhosts):
        """
        Verify IP Connectivity to DUT loopback addresses.

        Test Steps

        * On Router 1, send ping from:
            * End to end port A to B, ports on same linecard.  (100.1.0.1 to 100.1.0.2)
            * End to end port A to D, ports across multiple linecards. (100.1.0.1 to 100.1.0.33)
        * Repeat for TTL 0,1,2,255
        * Repeat for 64, 1500, 9100B packets
        * Repeat for IPv6

        Args:
            duthosts: The duthosts fixture.
            nbrhosts: The nbrhosts fixture.
            all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
            ttl: TTL of transmitted packet.
            size: ICMP data size
            version: IP version.
            porttype: Test port type, ethernet or portchannel

        """
        ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)
        logger.info("Pinging neighbor interfaces for ip: {ipv}, ttl: {ttl}, size: {size}".format(ipv=version, ttl=ttl,
                                                                                                 size=size))
        vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']
        check_packet(eos_ping, ports, 'portB', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb', dev=vm_host_to_A,
                     size=size, ttl=ttl, ttl_change=0)
        check_packet(eos_ping, ports, 'portC', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb', dev=vm_host_to_A,
                     size=size, ttl=ttl)
        check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb', dev=vm_host_to_A,
                     size=size, ttl=ttl)


def build_ttl0_pkts(ports, nbr_macs, version, dst_mac, dst_ip):
    """
    Builds ttl0 packet to send and ICMP TTL exceeded packet to expect back.

    Args:
        ports: ports structure from pick_ports
        nbr_macs: nbr_macs fixture
        version: IP version, 4 or 6
        dst_mac: Destination MAC, of DUT port.
        dst_ip: Destination IP, a farend VM interface.

    Returns:
        3 packets, one with ttl0 to send, one as the ICMP expected packet, and one to check for TTL wrapping.

    """
    if version == 4:
        send_pkt = simple_udp_packet(eth_dst=dst_mac,  # mac address of dut
                                     eth_src=nbr_macs[ports['portA']['nbr_vm']][ports['portA']['nbr_port']],
                                     # mac address of vm1
                                     ip_src=str(ports['portA']['nbr_lb']),
                                     ip_dst=str(dst_ip),
                                     ip_ttl=0,
                                     pktlen=100)

        exp_pkt255 = simple_udp_packet(eth_dst=dst_mac,  # mac address of dut
                                       eth_src=nbr_macs[ports['portA']['nbr_vm']][ports['portA']['nbr_port']],
                                       # mac address of vm1
                                       ip_src=str(ports['portA']['nbr_lb']),
                                       ip_dst=str(dst_ip),
                                       ip_ttl=255,
                                       pktlen=100)
        V4_PKTSZ = 128
        exp_pkt = simple_icmp_packet(eth_dst=nbr_macs[ports['portA']['nbr_vm']][ports['portA']['nbr_port']],
                                     # mac address of vm1
                                     eth_src=dst_mac,  # mac address of dut
                                     ip_src=str(ports['portA']['my_lb_ip']),
                                     ip_dst=str(ports['portA']['nbr_lb']),
                                     ip_ttl=64,
                                     icmp_code=0,
                                     icmp_type=11,
                                     pktlen=V4_PKTSZ,
                                     )

        masked_pkt = Mask(exp_pkt)
        masked_pkt.set_do_not_care_scapy(scapy.IP, "tos")
        masked_pkt.set_do_not_care_scapy(scapy.IP, "len")
        masked_pkt.set_do_not_care_scapy(scapy.IP, "id")
        masked_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")
        masked_pkt.set_do_not_care(304, V4_PKTSZ * 8 - 304)  # ignore icmp data

    else:
        send_pkt = simple_udpv6_packet(eth_dst=dst_mac,  # mac address of dut
                                       eth_src=nbr_macs[ports['portA']['nbr_vm']][ports['portA']['nbr_port']],
                                       # mac address of vm1
                                       ipv6_src=str(ports['portA']['nbr_lb']),
                                       ipv6_dst=str(dst_ip),
                                       ipv6_hlim=0,
                                       pktlen=100)

        exp_pkt255 = simple_udpv6_packet(eth_dst=dst_mac,  # mac address of dut
                                         eth_src=nbr_macs[ports['portA']['nbr_vm']][ports['portA']['nbr_port']],
                                         # mac address of vm1
                                         ipv6_src=str(ports['portA']['nbr_lb']),
                                         ipv6_dst=str(dst_ip),
                                         ipv6_hlim=255,
                                         pktlen=100)

        V6_PKTSZ = 148
        exp_pkt = simple_icmpv6_packet(eth_dst=nbr_macs[ports['portA']['nbr_vm']][ports['portA']['nbr_port']],
                                       # mac address of vm1
                                       eth_src=dst_mac,  # mac address of dut
                                       ipv6_src=str(ports['portA']['my_lb_ip']),
                                       ipv6_dst=str(ports['portA']['nbr_lb']),
                                       ipv6_hlim=64,
                                       icmp_code=0,
                                       icmp_type=3,
                                       pktlen=V6_PKTSZ,
                                       )

        masked_pkt = Mask(exp_pkt)
        masked_pkt.set_do_not_care_scapy(scapy.IPv6, "tc")
        masked_pkt.set_do_not_care_scapy(scapy.IPv6, "fl")
        masked_pkt.set_do_not_care_scapy(scapy.IPv6, "plen")
        masked_pkt.set_do_not_care_scapy(scapy.ICMPv6Unknown, "cksum")
        masked_pkt.set_do_not_care(456, V6_PKTSZ * 8 - 456)  # ignore icmp data

    return send_pkt, masked_pkt, exp_pkt255


class TestVoqIPFwdTTL0(object):

    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_ipforwarding_ttl0(self, duthosts, all_cfg_facts, tbinfo, ptfadapter, version, porttype, nbrhosts,
                               nbr_macs):
        """
        Verifies that TTL0 packets are dropped and that ICMP time expired message is received

        Args:
            duthosts: The duthosts fixture
            all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
            tbinfo: The tbinfo fixture.
            ptfadapter: The ptfadapter fixture
            version: IP version, 4 or 6
            porttype: Port type to test, ethernet or portchannel.
            nbrhosts: The nbrhosts fixture.
            nbr_macs: The nbr_macs fixture

        """

        devices = {}
        for k, v in tbinfo['topo']['properties']['topology']['VMs'].items():
            devices[k] = {'vlans': v['vlans']}

        ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)

        for dst_rtr, dst_ip in [(ports['portB']['nbr_vm'], ports['portB']['nbr_lb']),
                                (ports['portD']['nbr_vm'], ports['portD']['nbr_lb'])]:  # (self.rtrD['vm'], self.lbD.ip)
            logger.info("Send TTL 0 packet from %s => %s", ports['portA']['nbr_lb'], str(dst_ip))
            # 0.1@1 = dut_index.dut_port@ptfport
            src_port = devices[ports['portA']['nbr_vm']]['vlans'][0].split("@")[1]

            src_rx_ports = []
            for item in devices[ports['portA']['nbr_vm']]['vlans']:
                src_rx_ports.append(item.split("@")[1])
            logger.info("PTF source ports: %s", src_rx_ports)

            dst_rx_ports = []
            for item in devices[dst_rtr]['vlans']:
                dst_rx_ports.append(item.split("@")[1])
            logger.info("PTF destination ports: %s", dst_rx_ports)

            dst_mac = get_sonic_mac(ports['portA']['dut'], ports['portA']['asic'].asic_index, ports['portA']['port'])

            send_pkt, masked_pkt, exp_pkt255 = build_ttl0_pkts(ports, nbr_macs, version, dst_mac, dst_ip)

            send(ptfadapter, src_port, send_pkt)
            logger.info("masked packet matched port: %s", src_port)

            result = dp_poll(ptfadapter, device_number=0, exp_pkt=masked_pkt, timeout=2)
            ptfadapter.at_receive(result.packet, device_number=result.device, port_number=result.port)

            logger.info("Found %s ICMP ttl expired packets on ports: %s", result, str(src_rx_ports))
            logger.info("port: %s", result.port)
            pytest_assert(str(result.port) in src_rx_ports, "Port %s not in %s" % (result.port, src_rx_ports))

            verify_no_packet_any(ptfadapter, send_pkt, dst_rx_ports)
            verify_no_packet_any(ptfadapter, exp_pkt255, dst_rx_ports)


def bgp_established(host, asic):
    """
    Helper function to poll for BGP state.

    Args:
        host: Instance of duthost.
        asic: Instance of SonicAsic.

    Returns:
        True if all neighbors are established, False if not.

    """
    if host.facts['num_asic'] > 1:
        bgp_facts = host.bgp_facts(instance_id=asic.asic_index)['ansible_facts']
    else:
        bgp_facts = host.bgp_facts()['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['state'] != 'established':
            logger.info("Neighbor %s not established yet: %s", k, v['state'])
            return False
    return True


class TestFPLinkFlap(LinkFlap):

    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_front_panel_linkflap_port(self, duthosts, all_cfg_facts,
                                       fanouthosts, porttype, version, nbrhosts):
        """
        Traffic to Sonic host interfaces recovers after the front panel port flaps.

        Test Steps

        * Admin down interface on fanout connected to DUT port A to cause LOS on DUT.
        * On linecard 1 verify ping is successful from:
            * DUT IP Interface B to DUT Interface D
            * DUT Neighbor IP B to DUT Neighbor IP D
        * On Router 02T3, verify ping is successful from Router Interface to DUT IP Interface B and D.
        * On linecard 1, verify ping fails from:
            * DUT IP Interface A to DUT IP interface B and D.
            * DUT IP Interface A to attached neighbor.
        * On Router 01T3, verify ping fails to all DUT addresses.
        * On fanout switch, admin up the downed interface.
        * Validate all traffic flows are correct as in test cases 2-7.
        * Retry traffic with TTL 0,1,2,255
        * Retry traffic with 64, 1500, 9100B packets
        * Retry traffic with IPv6

        Args:
            duthosts: The duthosts fixture.
            all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
            fanouthosts: The fanouthosts fixture.
            version: IP version, 4 or 6
            porttype: Port type to test, ethernet or portchannel.
            nbrhosts: The nbrhosts fixture.

        """
        pytest_assert(fanouthosts != {}, "Fanouthosts fixture did not return anything, this test case has no hope.")
        logger.info("Fanouthosts: %s", fanouthosts)

        ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)
        cfg_facts = all_cfg_facts[ports['portA']['dut'].hostname][ports['portA']['asic'].asic_index]['ansible_facts']

        if "portchannel" in ports['portA']['port'].lower():
            pc_cfg = cfg_facts['PORTCHANNEL_MEMBER']
            pc_members = pc_cfg[ports['portA']['port']]
            logger.info("Portchannel members %s: %s", ports['portA']['port'], pc_members.keys())
            portbounce_list = pc_members.keys()
        else:
            portbounce_list = [ports['portA']['port']]

        for lport in portbounce_list:
            logger.info("Lookup ports for %s, %s", ports['portA']['dut'].hostname, lport)
            fanout, fanport = fanout_switch_port_lookup(fanouthosts, ports['portA']['dut'].hostname, lport)
            logger.info("bring down fanout port: %s, host: %s", fanport, fanout.host.hostname)
            self.linkflap_down(fanout, fanport, ports['portA']['dut'], lport)

        try:
            logger.info("=" * 80)
            logger.info("Link down validations")
            logger.info("-" * 80)

            check_packet(sonic_ping, ports, "portD", "portB", dst_ip_fld='my_ip', src_ip_fld='my_ip',
                         dev=ports['portA']['asic'], size=256, ttl=2,
                         ttl_change=1)
            check_packet(eos_ping, ports, 'portB', 'portB', dst_ip_fld='my_ip', src_ip_fld='nbr_ip',
                         dev=nbrhosts[ports["portB"]['nbr_vm']]['host'], size=256, ttl=2, ttl_change=0)
            check_packet(eos_ping, ports, 'portD', 'portB', dst_ip_fld='my_ip', src_ip_fld='nbr_ip',
                         dev=nbrhosts[ports["portB"]['nbr_vm']]['host'], size=256, ttl=2)

            check_packet(sonic_ping, ports, "portB", "portA", dst_ip_fld='my_ip', src_ip_fld='my_ip',
                         dev=ports['portA']['asic'], size=256, ttl=2,
                         ttl_change=0)

            with pytest.raises(AssertionError):
                sonic_ping(ports['portA']['asic'], ports['portD']['my_ip'], size=256, ttl=2,
                           interface=ports['portA']['my_ip'], verbose=True)
            with pytest.raises(AssertionError):
                sonic_ping(ports['portA']['asic'], ports['portA']['nbr_ip'], size=256, ttl=2,
                           interface=ports['portA']['my_ip'], verbose=True)
            with pytest.raises(AssertionError):
                eos_ping(nbrhosts[ports['portA']['nbr_vm']]['host'], ports['portA']['my_ip'], size=256, ttl=2,
                         verbose=True)
            with pytest.raises(AssertionError):
                eos_ping(nbrhosts[ports['portA']['nbr_vm']]['host'], ports['portD']['my_ip'], size=256, ttl=2,
                         verbose=True)

        finally:
            for lport in portbounce_list:
                fanout, fanport = fanout_switch_port_lookup(fanouthosts, ports['portA']['dut'].hostname, lport)
                self.linkflap_up(fanout, fanport, ports['portA']['dut'], lport)

        # Validate from port A and neighbor A that everything is good after port is up.

        # need bgp to establish
        wait_until(200, 20, bgp_established, ports['portA']['dut'], ports['portA']['asic'])

        routes = asic_cmd(ports['portA']['asic'], "ip -%d route" % version)["stdout_lines"]
        for route in routes:
            logger.info("R: %s", route)
        bgp = asic_cmd(ports['portA']['asic'], "show ip bgp summary")["stdout_lines"]
        for route in bgp:
            logger.info("B: %s", route)

        logger.info("=" * 80)
        logger.info("Link up validations")
        logger.info("-" * 80)

        for ttl, size in [(2, 64), (128, 64), (1, 1450)]:
            # local interfaces
            check_packet(sonic_ping, ports, 'portB', 'portA', size=size, ttl=ttl, ttl_change=0)
            check_packet(sonic_ping, ports, 'portC', 'portA', size=size, ttl=ttl, ttl_change=1)
            check_packet(sonic_ping, ports, 'portD', 'portA', size=size, ttl=ttl, ttl_change=1)
            # local neighbors
            check_packet(sonic_ping, ports, 'portA', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=0)
            check_packet(sonic_ping, ports, 'portB', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=0)
            check_packet(sonic_ping, ports, 'portC', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=1)
            check_packet(sonic_ping, ports, 'portD', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=1)

            vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

            check_packet(sonic_ping, ports, 'portA', 'portD', dev=ports['portD']['asic'], dst_ip_fld='nbr_ip',
                         size=size, ttl=ttl)
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_ip', src_ip_fld='nbr_ip',
                         dev=vm_host_to_A, size=size, ttl=ttl)

            # loopbacks
            check_packet(sonic_ping, ports, 'portA', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=0)
            check_packet(sonic_ping, ports, 'portB', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=0)
            check_packet(sonic_ping, ports, 'portC', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=1)
            check_packet(sonic_ping, ports, 'portD', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=1)

            vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

            check_packet(sonic_ping, ports, 'portA', 'portD', dst_ip_fld='nbr_lb', dev=ports['portD']['asic'],
                         size=size, ttl=ttl)
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=1)

            # inband
            check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='inband', size=size, ttl=ttl, ttl_change=0)
            check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_ip', size=size,
                         ttl=ttl, ttl_change=0)
            check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='inband', dst_ip_fld='nbr_lb', size=size,
                         ttl=ttl, ttl_change=0)

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
            check_packet(eos_ping, ports, 'portB', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=0)
            check_packet(eos_ping, ports, 'portC', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl)
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl)
