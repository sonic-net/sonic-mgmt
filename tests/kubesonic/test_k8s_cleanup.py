import logging
import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CLEANUP_CONTAINER_IMAGE = "kubesonic-cleanup"
CLEANUP_CONTAINER_NAME = "k8s_cleanup"


def pytest_generate_tests(metafunc):
    if "containers" in metafunc.fixturenames:
        metafunc.parametrize("containers", [metafunc.config.getoption("containers")], scope="module")


def test_k8s_cleanup(duthosts, rand_one_dut_hostname, containers):
    """
    Test the cleanup of kubesonic containers
    """
    # Check if the test is called from container upgrade test
    if not containers:
        pytest.skip("Skipping test as this test is not called from container upgrade test")

    if CLEANUP_CONTAINER_IMAGE not in containers:
        pytest.skip("Skipping test as the cleanup container is not included in the container upgrade test")

    duthost = duthosts[rand_one_dut_hostname]
    status_cmd = r"docker inspect {} --format \{{\{{.State.Running\}}\}}".format(CLEANUP_CONTAINER_NAME)
    cleanup_container_status = duthost.shell(status_cmd, module_ignore_errors=True)

    if "No such object" in cleanup_container_status["stderr"]:
        pytest.fail("Skipping test as the kubesonic cleanup container is not present")
    elif cleanup_container_status["stdout"] != "true":
        pytest.fail("Kubesonic cleanup container is not running")
    else:
        logger.info("Kubesonic cleanup container is running")

    # Check if the watchdog script exited code is 0 or not
    exec_watchdog_cmd = f"docker exec {CLEANUP_CONTAINER_NAME} /watchdog.sh"
    exec_watchdog_status = duthost.shell(exec_watchdog_cmd, module_ignore_errors=True)
    if exec_watchdog_status["rc"] != 0:
        pytest.fail("Kubesonic watchdog script exited with non-zero code: {}".format(
            exec_watchdog_status["rc"]))
    else:
        logger.info("Kubesonic watchdog script executed successfully")

    # Check if the syslog contains the expected message
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="kubesonic_cleanup_test")
    loganalyzer.expect_regex = [r".*kubesonic-image-cleanup: root-overlay size status\(total available\): (\d+) (\d+)"]
    loganalyzer.match_regex = [r"(?i).*kubesonic-image-cleanup:.*fail.*"]
    marker = loganalyzer.init()
    try:
        exec_cleanup_script_cmd = f"docker exec {CLEANUP_CONTAINER_NAME} /image_cleanup.sh"
        exec_cleanup_script_status = duthost.shell(exec_cleanup_script_cmd, module_ignore_errors=True)
        if exec_cleanup_script_status["rc"] != 0:
            pytest.fail("Kubesonic cleanup script exited with non-zero code: {}".format(
                exec_cleanup_script_status["rc"]))
        else:
            logger.info("Kubesonic cleanup script executed successfully")

        exec_report_disk_size_cmd = f"docker exec {CLEANUP_CONTAINER_NAME} /report_disk_size.sh"
        exec_report_disk_size_status = duthost.shell(exec_report_disk_size_cmd, module_ignore_errors=True)
        if exec_report_disk_size_status["rc"] != 0:
            pytest.fail("Kubesonic report disk size script exited with non-zero code: {}".format(
                exec_report_disk_size_status["rc"]))
        else:
            logger.info("Kubesonic report disk size script executed successfully")

        loganalyzer_summary = loganalyzer.analyze(marker, fail=False)
        if loganalyzer_summary["total"]["match"] != 0:
            pytest.fail("Kubesonic cleanup container error log is found")
        if loganalyzer_summary["total"]["expected_match"] == 0:
            pytest.fail("Kubesonic cleanup container disk size log is not found")

    except Exception as e:
        pytest.fail(f"Failed to check syslog for kubesonic cleanup test: {e}")
