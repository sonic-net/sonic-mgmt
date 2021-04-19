import logging
import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger=logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

@pytest.fixture
def trigger_action():
    BGP_DOWN_COMMAND = "sudo config bgp shutdown all"
    return BGP_DOWN_COMMAND

@pytest.fixture
def bgp_shutdown_log():
    BGP_DOWN_EXPECTED_LOG_MESSAGE = "admin state is set to 'down'"
    return BGP_DOWN_EXPECTED_LOG_MESSAGE

@pytest.fixture
def restore_action():
    BGP_UP_COMMAND = "sudo config bgp startup all"
    return BGP_UP_COMMAND

def test_check_syslog(duthosts, rand_one_dut_hostname, bgp_shutdown_log, trigger_action, restore_action):
    duthost=duthosts[rand_one_dut_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="bgp_shutdown")
    loganalyzer.expect_regex=[]

    try:
        loganalyzer.expect_regex.append(bgp_shutdown_log)
        marker=loganalyzer.init()
        duthost.command(trigger_action)
        logger.info("Check for expected log in syslog")
        loganalyzer.analyze(marker)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    finally:
        duthost.command(restore_action)
        
