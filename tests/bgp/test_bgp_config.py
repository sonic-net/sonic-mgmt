import logging

from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)


def test_bgp_config(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname
):
    """
    @summary: This test case is to verify if "set ipv6 next-hop prefer-global"
    in the output of "show runningconfiguration bgp" command
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cmd = "show runningconfiguration bgp"

    bgp_config_result = duthost.shell(cmd)
    logger.info("output of command '{}': {}".format(cmd, bgp_config_result))
    pytest_assert(
        bgp_config_result["rc"] == 0,
        "{} return value is not 0, output={}".format(
            cmd, bgp_config_result
        ),
    )
    pytest_assert(
        "set ipv6 next-hop prefer-global" in bgp_config_result["stdout"],
        "Did not find ipv6 next-hop in output={}".format(
            bgp_config_result
        ),
    )
