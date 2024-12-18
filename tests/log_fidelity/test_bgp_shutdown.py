import logging
import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(loganalyzer, duthosts):

    ignore_errors = [
        r".* ERR syncd#syncd: .*SAI_API_TUNNEL:_brcm_sai_mptnl_tnl_route_event_add:\d+ ecmp table entry lookup "
        "failed with error.*",
        r".* ERR syncd#syncd: .*SAI_API_TUNNEL:_brcm_sai_mptnl_process_route_add_mode_default_and_host:\d+ "
        "_brcm_sai_mptnl_tnl_route_event_add failed with error.*"
    ]

    if loganalyzer:
        for duthost in duthosts:
            loganalyzer[duthost.hostname].ignore_regex.extend(ignore_errors)

    return None


def check_syslog(duthost, prefix, trigger_action, expected_log, restore_action):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=prefix)
    loganalyzer.expect_regex = [expected_log]

    try:
        marker = loganalyzer.init()
        duthost.command(trigger_action)
        logger.info("Check for expected log {} in syslog".format(expected_log))
        loganalyzer.analyze(marker)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    finally:
        duthost.command(restore_action)


def test_bgp_shutdown(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    BGP_DOWN_EXPECTED_LOG_MESSAGE = "admin state is set to 'down'"
    BGP_DOWN_COMMAND = "config bgp shutdown all"
    BGP_UP_COMMAND = "config bgp startup all"

    check_syslog(duthost, "bgp_shutdown", BGP_DOWN_COMMAND, BGP_DOWN_EXPECTED_LOG_MESSAGE, BGP_UP_COMMAND)
