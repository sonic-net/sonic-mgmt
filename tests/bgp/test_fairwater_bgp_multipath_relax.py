import json
import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0-isolated-d2u254s2')
]

logger = logging.getLogger(__name__)


def test_fairwater_bgp_multipath_relax(tbinfo,
    duthosts, enum_rand_one_per_hwsku_frontend_hostname
):
    """
    @summary: This test case is to verify if "bgp bestpath as-path multipath-relax"
    in the output of "show runningconfiguration bgp" command
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cmd = "show runningconfiguration bgp"

    bgp_config_result = duthost.shell(cmd)
    logger.debug("output of command '{}': {}".format(cmd, bgp_config_result))
    pytest_assert(
        bgp_config_result["rc"] == 0,
        "{} return value is not 0, output={}".format(
            cmd, bgp_config_result
        ),
    )
    pytest_assert(
        "bgp bestpath as-path multipath-relax" in bgp_config_result["stdout"],
        "Did not find bgp multipath relax in output={}".format(
            bgp_config_result
        ),
    )

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    logger.info("Starting test_bgp_multipath_relax on topology {}".format(tbinfo['topo']['name']))
    logger.debug("mg_facts {}".format(mg_facts))
    topo_config = tbinfo['topo']['properties']['configuration']
    logger.debug("topo_config {}".format(topo_config))

    # Get the route from the DUT for the prefix
    bgp_route = duthost.shell("show ipv6 route fc00:c:c:101::1 json")
    logger.debug("output of command 'show ipv6 route fc00:c:c:101::1 json': {}".format(bgp_route))
    pytest_assert(
        bgp_route["rc"] == 0,
        "{} return value is not 0, output={}".format(
            cmd, bgp_config_result
        ),
    )
    routes = json.loads(bgp_route['stdout'])
    logger.debug("output of bgp_route load json {}".format(routes))
    prefix, entries = next(iter(routes.items()))
    active_num = entries[0]["internalNextHopActiveNum"]
    pytest_assert(
        active_num > 1,
        "Did not find 2 or more active next hops for the route fc00:c:c:101::1, active_num={}".format(
            active_num
        ),
    )
    logger.info("Pass: Next hops for the route fc00:c:c:101::1 active_num={}".format(
        active_num
    ))

