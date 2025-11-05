import pytest
import logging

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

LOG_ERROR_FAILED_TO_REMOVE_REF_COUNT = (r".*swss[01]#orchagent: :- removeLag: "
                                        r"Failed to remove ref count [0-9]+ LAG .*\|asic[01]\|PortChannel[0-9]+")

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function", autouse=True)
def post_health_check(duthosts):
    """
    This fixture is a final check at the end of the test to make sure all DUTs are healthy
    Any tests that need wait_until to stabilise after performing an action should have that in the test itself
    This may cause some duplicate effort but ensures DUT ends in an expected healthy state
    """
    # Get core dumps before action
    pre_core_count = {}
    for duthost in duthosts:
        core_count = int(duthost.shell("ls /var/core | wc -l")["stdout_lines"][0])
        pre_core_count[duthost] = core_count

    yield
    logger.info("Performing post-action health check on all DUTs")
    for duthost in duthosts:
        # Check all interfaces are up
        pt_assert(check_interface_status_of_up_ports(duthost),
                  "Not all ports that are admin up on are operationally up")
        # Check BGP sessions are all established
        pt_assert(duthost.check_bgp_session_state_all_asics(duthost.get_bgp_neighbors_per_asic(state="all")),
                  "Not all bgp sessions are established after config reload")
        # Get core dumps after action, compare to make sure the action didn't generate any new core dumps
        core_count = int(duthost.shell("ls /var/core | wc -l")["stdout_lines"][0])
        pt_assert(pre_core_count[duthost] == core_count,
                  f"Core counts before {pre_core_count[duthost]} and after {core_count} don't match")


@pytest.fixture(scope="function", autouse=True)
def loganalyzer_check(duthosts):
    loganalyzers = []
    markers = []
    for duthost in duthosts.frontend_nodes:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="consecutive_load_minigraph")
        loganalyzers.append(loganalyzer)
        # loganalyzer.load_common_config()
        marker = loganalyzer.init()
        markers.append(marker)
        # Populate below with any errors we want to monitor for
        loganalyzer.match_regex = [LOG_ERROR_FAILED_TO_REMOVE_REF_COUNT]

    yield

    logger.info("Checking loganalyzer")
    failures = []
    for loganalyzer, marker in zip(loganalyzers, markers):
        try:
            loganalyzer.analyze(marker)
        except LogAnalyzerError as e:
            failures.append(e)
    logger.info("Finish checking loganalyzer")

    if failures:
        logger.error("{} LogAnalyzer failures found:".format(len(failures)))
        for failure in failures:
            logger.error(failure)

        pytest.fail("Loganalyzer failures found, check logs for more details")
