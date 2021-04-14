import logging
import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger=logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

EXPECTED_LOG = "admin state is set to 'down'"
BGP_DOWN_EXPECTED_LOG_MESSAGE = "sudo config bgp shutdown all"

def test_bgp_shutdown(duthosts, rand_one_dut_hostname):
    duthost=duthosts[rand_one_dut_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="bgp_shutdown")
    loganalyzer.expect_regex=[EXPECTED_LOG]

    try:
        marker=loganalyzer.init()
        duthost.command(BGP_DOWN_EXPECTED_LOG_MESSAGE)
        logger.info("Check for expected log {} in syslog".format(EXPECTED_LOG))
        loganalyzer.analyze(marker)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err
        
