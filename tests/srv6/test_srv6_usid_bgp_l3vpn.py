import pytest
import logging
from tests.common.helpers.assertions import pytest_assert as py_assert

pytestmark = [
    pytest.mark.topology('t0')
]

Logger = logging.getLogger(__name__)

V6_PREFIX_NBR = "2001:db8:1::"
V6_MASK_NBR = "64"

V6_PREFIX_DUT = "2001:db8:2::"
V6_MASK_DUT = "64"


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(nbrhosts, duthosts, enum_frontend_dut_hostname):

    # pick dut
    duthost = duthosts[enum_frontend_dut_hostname]

    # pick one neighbor
    nbr = None
    nbrnames = list(nbrhosts.keys())
    for name in nbrnames:
        if 'T1' in name:
            nbr = nbrhosts[name]
            break
    py_assert(nbr is not None, "No T1 neighbors")

    yield (nbr, duthost)

    Logger.info("Performing cleanup")

    # cleanup neighbor
    cmd = "config vrf del Vrf10"
    nbr['host'].shell(cmd)

    # cleanup dut
    duthost = duthosts[enum_frontend_dut_hostname]
    cmd = "config vrf del Vrf10"
    duthost.shell(cmd)


def run_srv6_usid_bgp_l3vpn(enum_frontend_dut_hostname, hosts):
    """ Route added on All neighbor should be learned by the DUT"""
    Logger.info("Adding routes on neighbors")

    nbr = hosts[0]
    duthost = hosts[1]

    # configure bgp on neighbor
    cmd = "config vrf add Vrf10"
    nbr['host'].shell(cmd)
    cmd = "config loopback add Loopback1"
    nbr['host'].shell(cmd)
    cmd = "config interface vrf bind Loopback1 Vrf10"
    nbr['host'].shell(cmd)
    cmd = "config interface ip add Loopback1 2001:db8:1::1"
    nbr['host'].shell(cmd)
    cmd = (
        "vtysh"
        " -c 'configure'"
        " -c 'ipv6 route {}/{} Loopback1'"
        " -c 'segment-routing'"
        " -c 'srv6'"
        " -c 'locators'"
        " -c 'locator MAIN'"
        " -c 'prefix fcbb:bbbb:1::/48 block-len 32 node-len 16 func-bits 16'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'router bgp 64600'"
        " -c 'neighbor 2001:db8:2::1 remote-as 65100'"
        " -c 'address-family ipv6 unicast'"
        " -c 'network {}/{}'"
        " -c 'exit'"
        " -c 'address-family ipv6 vpn'"
        " -c 'neighbor 2001:db8:2::1 activate'"
        " -c 'exit-address-family'"
        " -c 'segment-routing srv6'"
        " -c 'locator MAIN'"
        " -c 'exit'"
        " -c 'router bgp 64600 vrf Vrf10'"
        " -c 'address-family ipv6 unicast'"
        " -c 'sid vpn export auto'"
        " -c 'rd vpn export 1:10'"
        " -c 'rt vpn both 99:99'"
        " -c 'import vpn'"
        " -c 'export vpn'"
        " -c 'redistribute connected'"
        " -c 'exit'"
        " -c 'exit'").format(V6_PREFIX_NBR, V6_MASK_NBR, V6_PREFIX_NBR, V6_MASK_NBR)
    nbr['host'].shell(cmd)
    Logger.info("Route %s added", V6_PREFIX_NBR)

    # configure bgp on dut
    cmd = "config vrf add Vrf10"
    duthost.shell(cmd)
    cmd = "config loopback add Loopback1"
    duthost.shell(cmd)
    cmd = "config interface vrf bind Loopback1 Vrf10"
    duthost.shell(cmd)
    cmd = "config interface ip add Loopback1 2001:db8:2::1"
    duthost.shell(cmd)
    cmd = (
        "vtysh"
        " -c 'configure'"
        " -c 'ipv6 route {}/{} Loopback1'"
        " -c 'segment-routing'"
        " -c 'srv6'"
        " -c 'locators'"
        " -c 'locator MAIN'"
        " -c 'prefix fcbb:bbbb:2::/48 block-len 32 node-len 16 func-bits 16'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'router bgp 65100'"
        " -c 'neighbor 2001:db8:1::1 remote-as 64600'"
        " -c 'address-family ipv6 unicast'"
        " -c 'network {}/{}'"
        " -c 'exit'"
        " -c 'address-family ipv6 vpn'"
        " -c 'neighbor 2001:db8:1::1 activate'"
        " -c 'exit-address-family'"
        " -c 'segment-routing srv6'"
        " -c 'locator MAIN'"
        " -c 'exit'"
        " -c 'router bgp 65100 vrf Vrf10'"
        " -c 'address-family ipv6 unicast'"
        " -c 'sid vpn export auto'"
        " -c 'rd vpn export 2:10'"
        " -c 'rt vpn both 99:99'"
        " -c 'import vpn'"
        " -c 'export vpn'"
        " -c 'redistribute connected'"
        " -c 'exit'"
        " -c 'exit'").format(V6_PREFIX_DUT, V6_MASK_DUT, V6_PREFIX_DUT, V6_MASK_DUT)
    duthost.shell(cmd)
    Logger.info("Route %s added to :duthost", V6_PREFIX_DUT)

    # check ROUTE_TABLE
    Logger.info("checking  DUT for route %s", V6_PREFIX_NBR)
    cmd = "redis-cli -n 0  hgetall \"ROUTE_TABLE:Vrf10:{}\"".format(V6_PREFIX_NBR)
    result = duthost.shell(cmd)
    result = result['stdout']
    Logger.info("Routes found: %s", result)
    py_assert(result != "", "The DUT did not program the SRv6 steering route")
    py_assert("segments: Vrf10:2001:db8::/64" not in result,
              "The DUT did not program the SRv6 steering route correctly, missing 'segments' field")
    py_assert("source: fc00:0:1::1" not in result,
              "The DUT did not program the SRv6 steering route correctly, missing 'source' field")

    # check SRV6_SID_LIST_TABLE
    Logger.info("checking  DUT for SID list %s", V6_PREFIX_NBR)
    cmd = "redis-cli -n 0  hgetall \"SRV6_SID_LIST_TABLE:Vrf10:{}\"".format(V6_PREFIX_NBR)
    result = duthost.shell(cmd)
    result = result['stdout']
    Logger.info("SID Lists found: %s", result)
    py_assert(result != "", "The DUT did not program the SRv6 SID list")
    py_assert("path: fcbb:bbbb:1:1::" not in result,
              "The DUT did not program the SRv6 SID list correctly, missing 'path' field")

    # check SRV6_MY_SID_TABLE
    Logger.info("checking  DUT for MY_SID fcbb:bbbb:2:1::")
    cmd = "redis-cli -n 0  hgetall \"SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:2:1::\""
    result = duthost.shell(cmd)
    result = result['stdout']
    Logger.info("MY SIDs found: %s", result)
    py_assert(result != "", "The DUT did not program SRv6 MySid entry")
    py_assert("action: udt6" not in result, "The DUT did not program SRv6 MySid entry, missing 'action' field")
    py_assert("vrf: Vrf10" not in result, "The DUT did not program SRv6 MySid entry correcly, missing 'vrf' field")


def test_srv6_usid_bgp_l3vpn(enum_frontend_dut_hostname, setUp):
    run_srv6_usid_bgp_l3vpn(enum_frontend_dut_hostname, setUp)
