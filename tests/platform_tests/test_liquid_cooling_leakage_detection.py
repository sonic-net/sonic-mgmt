import pytest
import logging
import time
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.sensor_control_test_helper import mocker_factory
from tests.common.helpers.liquid_leakage_control_test_helper import verify_leakage_status, \
    verify_leakage_status_in_health_system, get_liquid_cooling_update_interval, is_liquid_cooling_system_supported, \
    startmonitor_gnmi_event,verify_gnmi_msg_is_sent, setup_gnmi_server, WAIT_GNMI_EVENT_TIMEOUT
from tests.common.mellanox_data import get_platform_data
from tests.common.helpers.mellanox_liquid_leakage_control_test_helper import MlxLiquidLeakageMocker
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, get_bughandler_instance
from concurrent.futures import ThreadPoolExecutor


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def skip_when_no_liquid_cooling_system(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not is_liquid_cooling_system_supported(duthost):
        pytest.skip("No liquid cooling leakage sensors found on device")


def test_verify_liquid_senors_number_and_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Verify the liquid sensors number and status.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    platform_data = get_platform_data(duthost)
    leak_sensors_num = platform_data['leak_sensors']['number']
    actual_leak_sensors_num = int(duthost.shell("ls /var/run/hw-management/system/leakage* |wc -l")['stdout'])
    assert leak_sensors_num <= actual_leak_sensors_num, \
        f"liquid cooling leakage sensors number mismatch, \
            expected: {leak_sensors_num}, actual: {actual_leak_sensors_num}"
    leak_sensor_index_list = list(range(1, leak_sensors_num + 1))
    verify_leakage_status(duthost, leak_sensor_index_list, 'No')
    verify_leakage_status_in_health_system(duthost, leak_sensor_index_list, "OK")

    return 0


@pytest.mark.disable_loganalyzer
def test_mock_liquid_leak_event(duthosts, enum_rand_one_per_hwsku_hostname, mocker_factory, ptfhost, setup_gnmi_server):
    """
    1. Mock liquid leak event and verify the dut has the correct response.
    2. Mock liquid leak event is fixed and verify the dut has the correct response.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Start to mock liquid leak event.")
    mocker = mocker_factory(duthost, 'LiquidLeakageMocker')
    pytest_require(mocker, "No LiquidLeakageMocker for %s, skip rest of the testing in this case" %
                   duthost.facts['asic_type'])

    logging.info("mock liquid leak event")
    loganalyzer = LogAnalyzer(ansible_host=duthost,
                              marker_prefix="test_mock_liquid_leak_event_mock_leak",
                              bughandler=get_bughandler_instance({"type": "default"}))
    marker = loganalyzer.init()
    loganalyzer.match_regex = []

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(startmonitor_gnmi_event, duthost, ptfhost)

        logging.info('Mock liquid leakage event.')
        mocker.mock_leakage()
        logging.info('Wait and check actual data with mocked liquid leakage data...')
        liquid_cooling_update_interval = get_liquid_cooling_update_interval(duthost)
        time.sleep(liquid_cooling_update_interval)
        mocker.verify_leakage()
        loganalyzer.expect_regex = []
        expected_log_messages = []
        for index in mocker.test_leakage_index_list:
            expected_log_messages.append(f".*Liquid cooling leakage sensor leakage{index} reported leaking.*")
        loganalyzer.expect_regex.extend(expected_log_messages)

        loganalyzer.analyze(marker)
        try:
            logging.info("Wait for gnmi event result...")
            result = future.result(timeout=WAIT_GNMI_EVENT_TIMEOUT)
            verify_gnmi_msg_is_sent(mocker.test_leakage_index_list, result, "leaking")
        except Exception as e:
            logging.error(f"gNMI monitoring thread failed: {e}")
            raise Exception(f"gNMI monitoring thread failed for mocking liquid leak event: {e}")

    logging.info("Mock liquid leak event is fixed.")
    marker = loganalyzer.update_marker_prefix("test_mock_liquid_leak_event_mock_no_leak")
    loganalyzer.match_regex = []

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(startmonitor_gnmi_event, duthost, ptfhost)

        logging.info('Mock liquid leak event is fixed.')
        mocker.mock_no_leakage()
        logging.info('Wait and check actual data with mocked liquid leakage data...')
        time.sleep(liquid_cooling_update_interval)
        mocker.verify_no_leakage()
        loganalyzer.match_regex = []
        expected_log_messages = []
        loganalyzer.expect_regex = []
        for index in mocker.test_leakage_index_list:
            expected_log_messages.append(f".*Liquid cooling leakage sensor leakage{index} recovered from leaking.*")
        loganalyzer.expect_regex.extend(expected_log_messages)

        loganalyzer.analyze(marker)
        try:
            logging.info("Wait for gnmi event result...")
            result = future.result(timeout=WAIT_GNMI_EVENT_TIMEOUT)
            verify_gnmi_msg_is_sent(mocker.test_leakage_index_list, result, "recovered")
        except Exception as e:
            logging.error(f"gNMI monitoring thread failed: {e}")
            raise Exception(f"gNMI monitoring thread failed for mocking liquid leak event is fixed: {e}")
