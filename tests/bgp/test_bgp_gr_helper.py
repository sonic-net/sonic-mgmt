import pytest
import logging
import ipaddress
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

def test_bgp_gr_helper_routes_perserved(duthosts, rand_one_dut_hostname, nbrhosts, setup_bgp_graceful_restart, tbinfo):
    """
    Verify that DUT routes are preserved when peer performed graceful restart
    """
    duthost = duthosts[rand_one_dut_hostname]

    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    po = config_facts.get('PORTCHANNEL', {})
    dev_nbr = config_facts.get('DEVICE_NEIGHBOR', {})

    rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network(u'0.0.0.0/0'))
    if len(rtinfo_v4['nexthops']) == 0:
        pytest.skip("there is no next hop for v4 default route")

    rtinfo_v6 = duthost.get_ip_route_info(ipaddress.ip_network(u'::/0'))
    if len(rtinfo_v6['nexthops']) == 0:
        pytest.skip("there is no next hop for v6 default route")

    ifnames_v4 = [nh[1] for nh in rtinfo_v4['nexthops']]
    ifnames_v6 = [nh[1] for nh in rtinfo_v6['nexthops']]

    logger.info("ifnames_v4: %s" % ifnames_v4)
    logger.info("ifnames_v6: %s" % ifnames_v6)

    ifnames_common = [ ifname for ifname in ifnames_v4 if ifname in ifnames_v6 ]
    if len(ifnames_common) == 0:
        pytest.skip("No common ifnames between ifnames_v4 and ifname_v6: %s and %s" % (ifnames_v4, ifnames_v6))

    ifname = ifnames_common[0]

    # get neighbor device connected ports
    nbr_ports = []
    if ifname.startswith("PortChannel"):
        for member in po[ifname]['members']:
            nbr_ports.append(dev_nbr[member]['port'])
    else:
        nbr_ports.append(dev_nbr[ifname]['port'])
    logger.info("neighbor device connected ports {}".format(nbr_ports))

    # get nexthop ip
    for nh in rtinfo_v4['nexthops']:
        if nh[1] == ifname:
            bgp_nbr_ipv4 = nh[0]

    for nh in rtinfo_v6['nexthops']:
        if nh[1] == ifname:
            bgp_nbr_ipv6 = nh[0]

    # get the bgp neighbor
    bgp_nbr = bgp_neighbors[str(bgp_nbr_ipv4)]
    nbr_hostname = bgp_nbr['name']
    nbrhost = nbrhosts[nbr_hostname]['host']
    topo = tbinfo['topo']['properties']['configuration_properties']
    exabgp_ips = [topo['common']['nhipv4'], topo['common']['nhipv6']]
    exabgp_sessions = ['exabgp_v4', 'exabgp_v6']
    pytest_assert(nbrhost.check_bgp_session_state(exabgp_ips, exabgp_sessions), \
            "exabgp sessions {} are not up before graceful restart".format(exabgp_sessions))

    # shutdown Rib agent, starting gr process
    logger.info("shutdown rib process on neighbor {}".format(nbr_hostname))
    nbrhost.kill_bgpd()

    # wait till DUT enter NSF state
    pytest_assert(wait_until(60, 5, duthost.check_bgp_session_nsf, bgp_nbr_ipv4), \
            "neighbor {} does not enter NSF state".format(bgp_nbr_ipv4))
    pytest_assert(wait_until(60, 5, duthost.check_bgp_session_nsf, bgp_nbr_ipv6), \
            "neighbor {} does not enter NSF state".format(bgp_nbr_ipv6))

    # confirm ip route still there
    rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network(u'0.0.0.0/0'))
    pytest_assert(ipaddress.ip_address(bgp_nbr_ipv4) in [ nh[0] for nh in rtinfo_v4['nexthops'] ], \
        "cannot find nexthop {} in the new default route nexthops. {}".format(bgp_nbr_ipv4, rtinfo_v4))

    rtinfo_v6 = duthost.get_ip_route_info(ipaddress.ip_network(u'::/0'))
    pytest_assert(ipaddress.ip_address(bgp_nbr_ipv6) in [ nh[0] for nh in rtinfo_v6['nexthops'] ], \
        "cannot find nexthop {} in the new default route nexthops. {}".format(bgp_nbr_ipv6, rtinfo_v6))

    # shutdown the connected ports from nbr
    for nbr_port in nbr_ports:
        nbrhost.shutdown(nbr_port)

    try:
        # start Rib agent
        logger.info("startup rib process on neighbor {}".format(nbr_hostname))
        nbrhost.start_bgpd()

        # wait for exabgp sessions to establish
        pytest_assert(wait_until(300, 10, nbrhost.check_bgp_session_state, exabgp_ips, exabgp_sessions), \
            "exabgp sessions {} are not coming back".format(exabgp_sessions))
    except:
        raise
    finally:
        # unshut the connected ports from nbr
        for nbr_port in nbr_ports:
            nbrhost.no_shutdown(nbr_port)

    # confirm bgp session up
    graceful_restarted_bgp_sessions = [str(bgp_nbr_ipv4), str(bgp_nbr_ipv6)]
    pytest_assert(wait_until(300, 10, duthost.check_bgp_session_state, graceful_restarted_bgp_sessions), \
            "graceful restarted bgp sessions {} are not coming back".format(graceful_restarted_bgp_sessions))

    # Verify no route changes in the application db
    # TODO
