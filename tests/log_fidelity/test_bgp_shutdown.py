import logging
import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger=logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

BGP_DOWN_EXPECTED_LOG_MESSAGE = "admin state is set to 'down'"
BGP_DOWN_COMMAND = "sudo config bgp shutdown all"
BGP_UP_COMMAND = "sudo config bgp shutdown all"

def test_bgp_shutdown(duthosts, rand_one_dut_hostname):
    duthost=duthosts[rand_one_dut_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="bgp_shutdown")
    loganalyzer.expect_regex=[BGP_DOWN_EXPECTED_LOG_MESSAGE]

    try:
        marker=loganalyzer.init()
        duthost.command(BGP_DOWN_COMMAND)
        logger.info("Check for expected log {} in syslog".format(BGP_DOWN_EXPECTED_LOG_MESSAGE))
        loganalyzer.analyze(marker)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err
        
    finally:
        duthost.command(BGP_UP_COMMAND)
