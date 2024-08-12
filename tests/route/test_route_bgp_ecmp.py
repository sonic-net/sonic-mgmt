import requests
import json
import logging
import time
import pytest

pytestmark = [
    pytest.mark.topology("t0")
]

logger = logging.getLogger(__name__)

EXABGP_BASE_PORT = 5000
TEST_ROUTE = '20.0.0.1/32'
TEST_AS_PATH = '65000 65001 65002'
NHIPV4 = '10.10.246.254'
WITHDRAW = 'withdraw'
ANNOUNCE = 'announce'


@pytest.fixture(scope="module")
def setup_and_teardown():
    # Setup code
    logger.info("Setting up the test environment")

    # This is where the test function will be executed
    yield

    # Teardown code
    logger.info("Tearing down the test environment")


def change_route(operation, ptfip, route, nexthop, port, aspath):
    url = "http://%s:%d" % (ptfip, port)
    data = {
        "command": "%s route %s next-hop %s as-path [ %s ]" % (operation, route, nexthop, aspath)}
    r = requests.post(url, data=data, timeout=30)
    if r.status_code != 200:
        raise Exception(
            "Change routes failed: url={}, data={}, r.status_code={}, r.reason={}, r.headers={}, r.text={}".format(
                url,
                json.dumps(data),
                r.status_code,
                r.reason,
                r.headers,
                r.text
            )
        )


def announce_route(ptfip, route, nexthop, port, aspath):
    logger.info("Announce route {} to ptf".format(route))
    change_route(ANNOUNCE, ptfip, route, nexthop, port, aspath)


def withdraw_route(ptfip, route, nexthop, port, aspath):
    logger.info("Withdraw route {} to ptf".format(route))
    change_route(WITHDRAW, ptfip, route, nexthop, port, aspath)


def check_route(duthost, route, operation):
    cmd = 'vtysh -c "show ip route {} json"'.format(route)
    logger.info("Run cmd: %s" % cmd)
    out = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
    if (operation == ANNOUNCE):
        internalNextHopActiveNum = out[route][0]['internalNextHopActiveNum']
        logger.info("internalNextHopActiveNum = %d" % internalNextHopActiveNum)
        if (internalNextHopActiveNum < 2):
            logger.info("Cli output: %s" % out)
            pytest.fail("Active next hop number is less than 2")
    elif (operation == WITHDRAW):
        if (out != {}):
            logger.info("Cli output is NOT empty unexpectedly: %s" % out)
            pytest.fail("Route is not withdrawn")


def test_route_bgp_ecmp(duthosts, tbinfo, enum_rand_one_per_hwsku_frontend_hostname,
                        loganalyzer, setup_and_teardown):    # noqa F811
    ptf_ip = tbinfo['ptf_ip']
    common_config = tbinfo['topo']['properties']['configuration_properties'].get(
        'common', {})
    nexthop = common_config.get('nhipv4', NHIPV4)
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if loganalyzer:
        ignoreRegex = [
            ".*ERR.*\"missed_FRR_routes\".*"
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

    logger.info("ptf_ip = %s" % ptf_ip)
    logger.info("nexthop = %s" % nexthop)

    try:
        logger.info("Announce route")
        announce_route(ptf_ip, TEST_ROUTE, nexthop, EXABGP_BASE_PORT, TEST_AS_PATH)
        announce_route(ptf_ip, TEST_ROUTE, nexthop, EXABGP_BASE_PORT + 1, TEST_AS_PATH)
        logger.info("Sleep 5 seconds and check if route is announced")
        time.sleep(5)
        check_route(duthost, TEST_ROUTE, ANNOUNCE)

    finally:
        logger.info("Withdraw route")
        withdraw_route(ptf_ip, TEST_ROUTE, nexthop, EXABGP_BASE_PORT, TEST_AS_PATH)
        withdraw_route(ptf_ip, TEST_ROUTE, nexthop, EXABGP_BASE_PORT + 1, TEST_AS_PATH)
        logger.info("Sleep 5 seconds and check if route is withdrawn")
        time.sleep(5)
        check_route(duthost, TEST_ROUTE, WITHDRAW)
