import logging
import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger=logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

expected_log = "admin state is set to 'down'"
defined_action = "sudo config bgp shutdown all"

def test_bgp_shutdown(duthosts, rand_one_dut_hostname):
    duthost=duthosts[rand_one_dut_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="bgp_shutdown")
    loganalyzer.expect_regex=[]

    try:
        loganalyzer.expect_regex.append(expected_log)
        marker=loganalyzer.init()
        duthost.command(defined_action)
        logger.info("check for expected log in syslog")
        loganalyzer.analyze(marker)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err