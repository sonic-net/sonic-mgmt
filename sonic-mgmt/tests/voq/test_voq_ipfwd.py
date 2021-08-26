import logging
import pytest
import random
import ipaddress
import json
from tests.common.helpers.assertions import pytest_assert
from tests.common.errors import RunAnsibleModuleFail

from collections import defaultdict

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

from tests.common.utilities import wait_until
from tests.common.platform.device_utils import fanout_switch_port_lookup

from tests.ptf_runner import ptf_runner
from datetime import datetime
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # lgtm[py/unused-import]

from test_voq_nbr import LinkFlap

from voq_helpers import sonic_ping
from voq_helpers import eos_ping
from voq_helpers import get_inband_info
from voq_helpers import get_vm_with_ip
from voq_helpers import asic_cmd
from voq_helpers import get_port_by_ip
from voq_helpers import get_sonic_mac
from voq_helpers import get_ptf_port


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.sanity_check(check_items=["-monit"], allow_recover=False),
    pytest.mark.disable_loganalyzer
]

LOG_PING = True
DEFAULT_EOS_TTL = 64
DEFAULT_SONIC_TTL = 64
MAX_MTU = 9100


# Analyze logs at the beginning and end of all tests in the module, instead of each test.
@pytest.fixture(scope="module", autouse=True)
def loganalyzer(duthosts, request):
    analyzers = {}
    markers = {}
    # Analyze all the duts
    if duthosts[0].get_facts()['asic_type'] == "vs":
        logging.info("Log analyzer is disabled for vs platform")
        yield
        return

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


def log_port_info(ports):
    """
    Dumps the picked ports to the log file.

    Args:
        ports: Output of pick_ports.

    """
    port_dict_to_print = defaultdict(dict)
    for port_name, port in ports.items():
        for fld_name in port:
            if fld_name == 'dut':
                port_dict_to_print[port_name]['dut'] = port['dut'].hostname
            elif fld_name == 'asic':
                port_dict_to_print[port_name]['asic'] = port['asic'].asic_index
            elif isinstance(port[fld_name], ipaddress.IPv4Address) or isinstance(port[fld_name],
                                                                                 ipaddress.IPv6Address):
                port_dict_to_print[port_name][fld_name] = "%s" % port[fld_name]
            else:
                port_dict_to_print[port_name][fld_name] = port[fld_name]

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

        A dictionary with port information:
            {
                "my_lb_ip": "10.1.0.2", # Instance of ipaddress.IPv4Address (or IPv6Address)
                "inband": "3.3.3.7",
                "my_ip": "10.0.0.10", # Instance of ipaddress.IPv4Address (or IPv6Address)
                "nbr_ip": "10.0.0.11",
                "nbr_port": "Ethernet1",
                "asic": <SonicAsic>,  # Instance of SonicAsic the port is on
                "nbr_vm": "ARISTA03T1", # To index into nbrhosts fixture.
                "nbr_lb": "100.1.0.6", # Instance of ipaddress.IPv4Address (or IPv6Address)
                "dut": <MultiAsicSonicHost>,  # Instance of MultiAsicSonicHost the port is on
                "port": "Ethernet13"
            },


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

                          ---------- DUT ----------
                          |--- LC1 ---|--- LC2 ---|
    VM01T3   -------------|A          |          C|------------- VM02T1
                          |         F0|F1         |
    VM02T3   -------------|B     LB1  |   LB2    D|------------- VM01T1
                          |-----------|-----------|

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

    for asic_index, asic_cfg in enumerate(all_cfg_facts[dutA.hostname]):
        cfg_facts = asic_cfg['ansible_facts']
        cfgd_intfs = cfg_facts['INTERFACE'] if 'INTERFACE' in cfg_facts else {}
        cfgd_pos = cfg_facts['PORTCHANNEL_INTERFACE'] if 'PORTCHANNEL_INTERFACE' in cfg_facts else {}
        eths = [intf for intf in cfgd_intfs if "ethernet" in intf.lower()]
        pos = [intf for intf in cfgd_pos if "portchannel" in intf.lower()]
        if port_type_a == "ethernet":
            if len(eths) != 0:
                intfs_to_test['portA'] = get_info_for_a_port(cfg_facts, eths, version, dutA, asic_index, nbrhosts)
                # We have one ethernet interface, lets check for a pos interface for portB
                if len(pos) != 0:
                    intfs_to_test['portB'] = get_info_for_a_port(cfg_facts, pos, version, dutA, asic_index, nbrhosts)
                else:
                    # No pos interfaces, let see if we have other ethernet ports in this asic
                    if len(eths) != 1:
                        # We have more than 1 eth interface, pick it for port B
                        intfs_to_test['portB'] = get_info_for_a_port(cfg_facts, eths, version, dutA, asic_index,
                                                                     nbrhosts)
        else:
            # port type is portchannel
            if len(pos) != 0:
                intfs_to_test['portA'] = get_info_for_a_port(cfg_facts, pos, version, dutA, asic_index, nbrhosts)
                # We have one pc interface, lets check for a eth interface for portB
                if len(eths) != 0:
                    intfs_to_test['portB'] = get_info_for_a_port(cfg_facts, eths, version, dutA, asic_index, nbrhosts)
                else:
                    # No eth interfaces, let see if we have other pc ports in this asic
                    if len(pos) != 1:
                        # We have more than 1 pc interface, pick it for port B
                        intfs_to_test['portB'] = get_info_for_a_port(cfg_facts, pos, version, dutA, asic_index,
                                                                     nbrhosts)

        if 'portA' in intfs_to_test:
            break

    if len(duthosts.frontend_nodes) == 1:
        # We are dealing with a single card, lets find the portC and portD in other asic on the same card
        other_duts = [dutA]
    else:
        other_duts = duthosts.frontend_nodes[1:]

    # Lets try to find portC and portD on other asics/linecards.
    for dut in other_duts:
        for asic_index, asic_cfg in enumerate(all_cfg_facts[dut.hostname]):
            if dut == dutA and asic_index == intfs_to_test['portA']['asic'].asic_index:
                # Ignore the asic we used for portA
                continue
            cfg_facts = asic_cfg['ansible_facts']
            cfgd_intfs = cfg_facts['INTERFACE'] if 'INTERFACE' in cfg_facts else {}
            cfgd_pos = cfg_facts['PORTCHANNEL_INTERFACE'] if 'PORTCHANNEL_INTERFACE' in cfg_facts else {}
            eths = [intf for intf in cfgd_intfs if "ethernet" in intf.lower()]
            pos = [intf for intf in cfgd_pos if "portchannel" in intf.lower()]
            if len(eths) != 0:
                if port_type_a == "ethernet":
                    intfs_to_test['portC'] = get_info_for_a_port(cfg_facts, eths, version, dut, asic_index,
                                                                 nbrhosts)
                else:
                    intfs_to_test['portD'] = get_info_for_a_port(cfg_facts, eths, version, dut, asic_index,
                                                                 nbrhosts)

            if len(pos) != 0:
                if port_type_a == "ethernet":
                    intfs_to_test['portD'] = get_info_for_a_port(cfg_facts, pos, version, dut, asic_index, nbrhosts)
                else:
                    intfs_to_test['portC'] = get_info_for_a_port(cfg_facts, pos, version, dut, asic_index, nbrhosts)

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
    intfs.update(cfg_facts.get('INTERFACE', {}))
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
                if ports[src_port]['dut'].get_facts()['asic_type'] != 'vs':
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


@pytest.mark.express
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
        intfs.update(cfg_facts.get('INTERFACE', {}))
        if "PORTCHANNEL_INTERFACE" in cfg_facts:
            intfs.update(cfg_facts['PORTCHANNEL_INTERFACE'])

        for port in intfs:
            for address in intfs[port]:
                # self.check_is_connected(address, port, ipv4_routes, ipv6_routes)
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

        if 'VOQ_INBAND_INTERFACE' not in cfg_facts:
            # There are no inband interfaces, this must be an asic not connected to fabric
            pytest.skip("Asic {} on {} has no inband interfaces, so must not be connected to fabric".format(asic.asic_index, per_host.hostname))

        intf = cfg_facts['VOQ_INBAND_INTERFACE']
        for port in intf:
            for address in cfg_facts['BGP_INTERNAL_NEIGHBOR'].keys():
                # self.check_is_connected(address, port, ipv4_routes, ipv6_routes)
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

        if 'BGP_INTERNAL_NEIGHBOR' not in cfg_facts:
            # There are no inband interfaces, this must be an asic not connected to fabric
            pytest.skip("Asic {} on {} has no inband interfaces, so must not be connected to fabric".format(asic.asic_index, per_host.hostname))

        bgp_facts = per_host.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
        for address in cfg_facts['BGP_INTERNAL_NEIGHBOR'].keys():
            pytest_assert(bgp_facts['bgp_neighbors'][address]['state'] == "established",
                          "BGP internal neighbor: %s is not established: %s" % (
                              address, bgp_facts['bgp_neighbors'][address]['state']))

    def test_host_route_table_nbr_lb_addr(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                          all_cfg_facts, nbrhosts):
        """
        Verify all learned prefixes from neighbors have their neighbors as next hop.

        Args:
            duthosts: duthosts fixture
            enum_rand_one_per_hwsku_frontend_hostname: linecard enum fixture.
            all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
            nbrhosts: nbrhosts fixture.

        """
        per_host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        # Pick an asic that has BGP_NEIGHBOR
        asic_to_use = None
        for a_asic in per_host.asics:
            asic_cfg_facts = all_cfg_facts[per_host.hostname][a_asic.asic_index]['ansible_facts']
            if 'BGP_NEIGHBOR' in asic_cfg_facts:
                asic_to_use = a_asic
                break

        pytest_assert(asic_to_use is not None, "Did not find any asic on '{}' that has BGP_NEIGHBORS".format(per_host.hostname))

        cfg_facts = all_cfg_facts[per_host.hostname][asic_to_use.asic_index]['ansible_facts']

        ipv4_routes = asic_cmd(asic_to_use, "ip -4 route")["stdout_lines"]
        ipv6_routes = asic_cmd(asic_to_use, "ip -6 route")["stdout_lines"]

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

    @pytest.mark.parametrize('ttl, size', [(2, 64), (128, 64), (255, 1456), (1, 1456)])
    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_voq_local_neighbor_ping(self, duthosts, all_cfg_facts, ttl, size, version, porttype, nbrhosts):
        """
        Verify Host IP forwarding for IPv4 and IPv6 for various packet sizes and ttls to neighbor addresses.

        Test Steps

        * On linecard 1, send ping from:
            * DUT IP Interface on port A to directly connected neighbor address. (10.0.0.0 to 10.0.0.1)
        * On Router 01T3, send ping from:
            * Router IP interface to DUT address on port A. (10.0.0.1 to 10.0.0.0)
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

        vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

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
        * On Router 01T3, send ping from:
            * Router loopback interface to DUT address on port A. (100.1.0.1 to 10.0.0.0)
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

        vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

        check_packet(eos_ping, ports, 'portA', 'portA', dst_ip_fld='my_ip', src_ip_fld='nbr_lb',
                     dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=0)

    @pytest.mark.parametrize('ttl, size', [(2, 64), (128, 64,), (255, 1456), (1, 1456)])
    @pytest.mark.parametrize('version', [4, 6])
    @pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
    def test_voq_inband_ping(self, duthosts, all_cfg_facts, ttl, size, version, porttype, nbrhosts):
        """
        Verify IP connectivity over inband interfaces.

        * On linecard 1 send ping from:
            * Inband interface F0 to inband interface F1 (133.133.133.1 to 133.133.133.5)
            * Inband interface F0 to neighbor on port A (133.133.133.1 to 10.0.0.1)
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
        if ports[remote_port]['dut'].get_facts()['asic_type'] != 'vs':
            check_packet(sonic_ping, ports, remote_port, 'portA', src_ip_fld='inband', dst_ip_fld='inband', size=size,
                         ttl=ttl)
        else:
            check_packet(sonic_ping, ports, remote_port, 'portA', src_ip_fld='inband', dst_ip_fld='inband', size=size,
                         ttl=ttl, ttl_change=0)

        check_packet(sonic_ping, ports, 'portA', 'portA', src_ip_fld='inband', size=size, ttl=ttl, ttl_change=0)
        check_packet(sonic_ping, ports, 'portB', 'portA', src_ip_fld='inband', size=size, ttl=ttl, ttl_change=0)

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
        if ports['portC']['dut'].get_facts()['asic_type'] == 'vs':
            check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='my_lb_ip', size=size,
                         ttl=ttl, ttl_change=0)
        else:
            check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='my_lb_ip', size=size,
                         ttl=ttl, ttl_change=1)

        check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_ip', size=size,
                     ttl=ttl, ttl_change=1)
        check_packet(sonic_ping, ports, 'portC', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='nbr_lb', size=size,
                     ttl=ttl, ttl_change=1)
        if ports['portD']['dut'].get_facts()['asic_type'] == 'vs':
            check_packet(sonic_ping, ports, 'portD', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='my_lb_ip', size=size, ttl=ttl,
                         ttl_change=0)
        else:
            check_packet(sonic_ping, ports, 'portD', 'portA', src_ip_fld='my_lb_ip', dst_ip_fld='my_lb_ip', size=size, ttl=ttl,
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


@pytest.mark.parametrize('version', [4, 6])
@pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
def test_ipforwarding_ttl0(duthosts, all_cfg_facts, tbinfo, ptfhost, version, porttype, nbrhosts, nbr_macs):
    """
    Verifies that TTL0 packets are dropped and that ICMP time expired message is received

    Args:
        duthosts: The duthosts fixture
        all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
        tbinfo: The tbinfo fixture.
        ptfhost: The ptfhost fixture
        version: IP version, 4 or 6
        porttype: Port type to test, ethernet or portchannel.
        nbrhosts: The nbrhosts fixture.
        nbr_macs: The nbr_macs fixture

    """

    ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)

    if 'portB' in ports:
        dst_list = [('portB', ports['portB']['nbr_lb']), ('portD', ports['portD']['nbr_lb'])]
    else:
        dst_list = [('portD', ports['portD']['nbr_lb'])]

    for dst_port, dst_ip in dst_list:
        logger.info("Send TTL 0 packet from %s => %s", ports['portA']['nbr_lb'], str(dst_ip))
        # 0.1@1 = dut_index.dut_port@ptfport
        src_rx_ports = get_ptf_port(duthosts,
                                    all_cfg_facts[ports['portA']['dut'].hostname][ports['portA']['asic'].asic_index]['ansible_facts'],
                                    tbinfo, ports['portA']['dut'], ports['portA']['port'])

        src_port = src_rx_ports[0]
        logger.info("PTF source ports: %s", src_rx_ports)

        dst_rx_ports = get_ptf_port(duthosts,
                                    all_cfg_facts[ports[dst_port]['dut'].hostname][ports[dst_port]['asic'].asic_index]['ansible_facts'],
                                    tbinfo, ports[dst_port]['dut'], ports[dst_port]['port'])

        logger.info("PTF destination ports: %s", dst_rx_ports)

        dst_mac = get_sonic_mac(ports['portA']['dut'], ports['portA']['asic'].asic_index, ports['portA']['port'])

        params = {'dst_mac': dst_mac,
                  'version': version,
                  'dst_ip': str(dst_ip),
                  'src_port': src_port,
                  'src_rx_ports': src_rx_ports,
                  'dst_rx_ports': dst_rx_ports,
                  'vm_mac': nbr_macs[ports['portA']['nbr_vm']][ports['portA']['nbr_port']],
                  'vm_ip': str(ports['portA']['nbr_lb']),
                  'dut_lb': str(ports['portA']['my_lb_ip'])}

        log_file = "/tmp/voq.ttl0.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
        logger.info("Call TTL0 PTF runner")
        ptf_runner(ptfhost, 'ptftests', "voq.TTL0", '/root/ptftests', params=params,
                   log_file=log_file, timeout=10)
        logger.info("TTL0 PTF runner completed")


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
        if fanouthosts == {}:
            pytest.skip("Fanouthosts fixture did not return anything, this test case can not run.")
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

        try:

            for lport in portbounce_list:
                logger.info("Lookup ports for %s, %s", ports['portA']['dut'].hostname, lport)
                fanout, fanport = fanout_switch_port_lookup(fanouthosts, ports['portA']['dut'].hostname, lport)
                logger.info("bring down fanout port: %s, host: %s", fanport, fanout.host.hostname)
                self.linkflap_down(fanout, fanport, ports['portA']['dut'], lport)

            logger.info("=" * 80)
            logger.info("Link down validations")
            logger.info("-" * 80)

            if 'portB' in ports:
                check_packet(sonic_ping, ports, "portD", "portB", dst_ip_fld='my_lb_ip', src_ip_fld='my_lb_ip',
                             dev=ports['portA']['asic'], size=256, ttl=2,
                             ttl_change=1)
                check_packet(eos_ping, ports, 'portB', 'portB', dst_ip_fld='my_ip', src_ip_fld='nbr_ip',
                             dev=nbrhosts[ports["portB"]['nbr_vm']]['host'], size=256, ttl=2, ttl_change=0)
                check_packet(eos_ping, ports, 'portD', 'portB', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_ip',
                             dev=nbrhosts[ports["portB"]['nbr_vm']]['host'], size=256, ttl=2)

                check_packet(sonic_ping, ports, "portB", "portA", dst_ip_fld='my_ip', src_ip_fld='my_ip',
                             dev=ports['portA']['asic'], size=256, ttl=2,
                             ttl_change=0)

            with pytest.raises(AssertionError):
                sonic_ping(ports['portA']['asic'], ports['portD']['my_lb_ip'], size=256, ttl=2,
                           interface=ports['portA']['my_ip'], verbose=True)
            with pytest.raises(AssertionError):
                sonic_ping(ports['portA']['asic'], ports['portA']['nbr_ip'], size=256, ttl=2,
                           interface=ports['portA']['my_ip'], verbose=True)
            with pytest.raises(AssertionError):
                eos_ping(nbrhosts[ports['portA']['nbr_vm']]['host'], ports['portA']['my_ip'], size=256, ttl=2,
                         verbose=True)
            with pytest.raises(AssertionError):
                eos_ping(nbrhosts[ports['portA']['nbr_vm']]['host'], ports['portD']['my_lb_ip'], size=256, ttl=2,
                         verbose=True)

        finally:
            for lport in portbounce_list:
                fanout, fanport = fanout_switch_port_lookup(fanouthosts, ports['portA']['dut'].hostname, lport)
                self.linkflap_up(fanout, fanport, ports['portA']['dut'], lport)

        # need bgp to establish
        wait_until(200, 20, bgp_established, ports['portA']['dut'], ports['portA']['asic'])

        # Validate from port A and neighbor A that everything is good after port is up.
        logger.info("=" * 80)
        logger.info("Link up validations")
        logger.info("-" * 80)

        for ttl, size in [(2, 64), (128, 64), (1, 1450)]:
            # local interfaces
            check_packet(sonic_ping, ports, 'portB', 'portA', size=size, ttl=ttl, ttl_change=0)

            # local neighbors
            check_packet(sonic_ping, ports, 'portA', 'portA', dst_ip_fld='nbr_ip', size=size, ttl=ttl, ttl_change=0)

            vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

            check_packet(sonic_ping, ports, 'portA', 'portD', dev=ports['portD']['asic'], dst_ip_fld='nbr_lb',
                         size=size, ttl=ttl, src_ip_fld='my_lb_ip')
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl)

            # loopbacks
            check_packet(sonic_ping, ports, 'portA', 'portA', dst_ip_fld='nbr_lb', size=size, ttl=ttl, ttl_change=0)
            check_packet(sonic_ping, ports, 'portD', 'portA', dst_ip_fld='nbr_lb', src_ip_fld='my_lb_ip', size=size, ttl=ttl, ttl_change=1)

            vm_host_to_A = nbrhosts[ports['portA']['nbr_vm']]['host']

            check_packet(sonic_ping, ports, 'portA', 'portD', dst_ip_fld='nbr_lb', dev=ports['portD']['asic'],
                         size=size, ttl=ttl, src_ip_fld='my_lb_ip')
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=1)

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
            check_packet(eos_ping, ports, 'portB', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl, ttl_change=0)
            check_packet(eos_ping, ports, 'portC', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl)
            check_packet(eos_ping, ports, 'portD', 'portA', dst_ip_fld='my_lb_ip', src_ip_fld='nbr_lb',
                         dev=vm_host_to_A, size=size, ttl=ttl)


@pytest.mark.parametrize('port, ip', [('portA', 'my_ip'), ('portA', 'my_lb_ip'), ('portA', 'inband'),
                                      ('portD', 'my_lb_ip'), ('portD', 'inband')])
@pytest.mark.parametrize('version', [4, 6])
@pytest.mark.parametrize('porttype', ["ethernet", "portchannel"])
def test_ipforwarding_jumbo_to_dut(duthosts, all_cfg_facts, tbinfo, ptfhost, porttype, version, port, ip,
                                   nbrhosts, nbr_macs):
    """
    Verifies that jumbo packets are forwarded through system and jumbo ICMP packets are answered by
    linecard host CPU.

    Args:
        duthosts: The duthosts fixture
        all_cfg_facts: The all_cfg_facts fixture from voq/conftest.py
        tbinfo: The tbinfo fixture.
        ptfhost: The ptfhost fixture
        version: IP version, 4 or 6
        porttype: Port type to test, ethernet or portchannel.
        nbrhosts: The nbrhosts fixture.
        nbr_macs: The nbr_macs fixture

    """
    ports = pick_ports(duthosts, all_cfg_facts, nbrhosts, port_type_a=porttype, version=version)

    dst_ip = ports[port][ip]

    logger.info("Send Max MTU packet from %s => %s", ports['portA']['nbr_lb'], str(dst_ip))

    # 0.1@1 = dut_index.dut_port@ptfport
    src_rx_ports = get_ptf_port(duthosts,
                                all_cfg_facts[ports['portA']['dut'].hostname][ports['portA']['asic'].asic_index][
                                    'ansible_facts'],
                                tbinfo, ports['portA']['dut'], ports['portA']['port'])

    logger.info("PTF source ports: %s", src_rx_ports)

    dst_rx_ports = get_ptf_port(duthosts,
                                all_cfg_facts[ports['portD']['dut'].hostname][ports['portD']['asic'].asic_index][
                                    'ansible_facts'],
                                tbinfo, ports['portD']['dut'], ports['portD']['port'])
    logger.info("PTF destination ports: %s", dst_rx_ports)

    dst_mac = get_sonic_mac(ports['portA']['dut'], ports['portA']['asic'].asic_index, ports['portA']['port'])
    dst_mac_far = get_sonic_mac(ports['portD']['dut'], ports['portD']['asic'].asic_index, ports['portD']['port'])

    ignore_ttl = False
    if ports[port]['dut'].get_facts()['asic_type'] == 'vs':
        ignore_ttl = True

    # this will send jumbo ICMP to DUT and jumbo IP through to portD

    params = {'router_mac_src_side': dst_mac,
              'router_mac_dst_side': dst_mac_far,
              'pktlen': MAX_MTU,
              'src_host_ip': str(ports['portA']['nbr_lb']),
              'src_router_ip': str(dst_ip),
              'dst_host_ip': str(ports['portD']['nbr_lb']),
              'src_ptf_port_list': src_rx_ports,
              'dst_ptf_port_list': dst_rx_ports,
              'version': version,
              'ignore_ttl': ignore_ttl
              }

    log_file = "/tmp/voq.mtu.v{}.{}.{}.log".format(version, porttype, datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    logger.info("Call MTU PTF runner")
    ptf_runner(ptfhost, 'ptftests', "voq.MtuTest", '/root/ptftests', params=params,
               log_file=log_file, timeout=10, socket_recv_size=16384)
    logger.info("MTU PTF runner completed")
