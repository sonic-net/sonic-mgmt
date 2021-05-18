import logging
import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger=logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

def check_syslog(duthost, prefix, trigger_action, expected_log, restore_action):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=prefix)
    loganalyzer.expect_regex=[expected_log]

    try:
        marker=loganalyzer.init()
        duthost.command(trigger_action)
        logger.info("Check for expected log {} in syslog".format(expected_log))
        loganalyzer.analyze(marker)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    finally:
        duthost.command(restore_action)

def test_bgp_shutdown(duthosts, rand_one_dut_hostname):
    duthost=duthosts[rand_one_dut_hostname]

    BGP_DOWN_EXPECTED_LOG_MESSAGE = "admin state is set to 'down'"
    BGP_DOWN_COMMAND = "config bgp shutdown all"
    BGP_UP_COMMAND = "config bgp startup all"

    check_syslog(duthost, "bgp_shutdown", BGP_DOWN_COMMAND, BGP_DOWN_EXPECTED_LOG_MESSAGE, BGP_UP_COMMAND)
    
