import allure
import json
import logging
import random
import time
import pytest

from tests.common.config_reload import config_reload
from .counterpoll_constants import CounterpollConstants
from tests.common.helpers.assertions import pytest_assert
from .counterpoll_helper import ConterpollHelper
from tests.common.helpers.sonic_db import SonicDbCli, SonicDbKeyNotFound
from tests.common.utilities import skip_release, wait_until
from tests.common.reboot import reboot
from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

ENABLE = 'enable'
DISABLE = 'disable'

# PORT_PHY_ATTR specific constants
PORT_PHY_ATTR = CounterpollConstants.PORT_PHY_ATTR
PORT_PHY_ATTR_TYPE = CounterpollConstants.PORT_PHY_ATTR_TYPE
FLEX_COUNTER_PREFIX = 'FLEX_COUNTER_TABLE:'
CONFIG_DB_TABLE = 'FLEX_COUNTER_TABLE|PORT_PHY_ATTR'
FLEX_COUNTER_GROUP_TABLE = 'FLEX_COUNTER_GROUP_TABLE:PORT_PHY_ATTR'
FLEX_COUNTER_TABLE_PREFIX = 'FLEX_COUNTER_TABLE:PORT_PHY_ATTR:*'

# PORT attributes to validate
PORT_PHY_ATTRIBUTES = [
    'SAI_PORT_ATTR_RX_SIGNAL_DETECT',
    'SAI_PORT_ATTR_FEC_ALIGNMENT_LOCK',
    'SAI_PORT_ATTR_RX_SNR'
]

# Global cache for port configuration and OID mapping
_port_config_cache = None
_port_oid_map_cache = None


def get_port_config_from_config_db(duthost):
    """
    Get port configuration from CONFIG_DB

    Args:
        duthost: DUT host object

    Returns:
        dict: Port configuration data
    """
    global _port_config_cache

    if _port_config_cache is not None:
        return _port_config_cache

    result = duthost.command('sonic-cfggen -d --var-json PORT')
    pytest_assert(result['rc'] == 0, "Failed to get PORT config from CONFIG_DB")

    _port_config_cache = json.loads(result['stdout'])
    logging.info("Fetched {} ports from CONFIG_DB".format(len(_port_config_cache)))
    return _port_config_cache


def get_port_lane_count_from_config(port_config):
    """
    Get lane count from port configuration

    Args:
        port_config: Port configuration dict

    Returns:
        int: Number of lanes
    """
    lanes_str = port_config.get('lanes', '')
    if not lanes_str:
        logging.warning("No lanes found in port config, defaulting to 4")
        return 4

    lane_count = len(lanes_str.split(','))
    return lane_count


def build_port_oid_map(duthost):
    """
    Build mapping of interface name to OID

    Args:
        duthost: DUT host object

    Returns:
        dict: Mapping of interface name to OID
    """
    global _port_oid_map_cache

    if _port_oid_map_cache is not None:
        return _port_oid_map_cache

    port_oid_map = {}
    for asic in duthost.asics:
        try:
            name_map = SonicDbCli(asic, 'COUNTERS_DB').hget_all('COUNTERS_PORT_NAME_MAP')
            port_oid_map.update(name_map)
            logging.info("Found {} port OID mappings on asic{}".format(len(name_map), asic.asic_index))
        except SonicDbKeyNotFound:
            logging.warning("COUNTERS_PORT_NAME_MAP not found on asic{}".format(asic.asic_index))

    _port_oid_map_cache = port_oid_map
    return port_oid_map


def verify_phy_attr_in_cli(duthost, expected_status):
    """
    Verify counterpoll show output for PHY counters

    Args:
        duthost: DUT host object
        expected_status: Expected status ('enable' or 'disable')
    """
    with allure.step("Verifying 'counterpoll show' output for PHY counters"):
        counterpoll_output = ConterpollHelper.get_counterpoll_show_output(duthost)
        pytest_assert(len(counterpoll_output) > 0, "counterpoll show returns no output")

        for entry in counterpoll_output:
            if PORT_PHY_ATTR_TYPE == entry.get(CounterpollConstants.TYPE, ''):
                actual_status = entry[CounterpollConstants.STATUS]
                pytest_assert(expected_status == actual_status,
                             "PHY counter status is '{}', expected '{}'".format(actual_status, expected_status))
                logging.info("PHY counter status verified: {}".format(actual_status))
                return

        pytest.fail("PHY counters not found in counterpoll show output")


def verify_phy_attr_in_config_db(duthost, expected_status, expected_interval=None):
    """
    Verify CONFIG_DB FLEX_COUNTER_TABLE|PORT_PHY_ATTR entry

    Args:
        duthost: DUT host object
        expected_status: Expected status ('enable' or 'disable')
        expected_interval: Expected poll interval in ms (optional)
    """
    with allure.step("Verifying CONFIG_DB FLEX_COUNTER_TABLE|PORT_PHY_ATTR"):
        for asic in duthost.asics:
            try:
                config_data = SonicDbCli(asic, 'CONFIG_DB').hget_all(CONFIG_DB_TABLE)

                pytest_assert('FLEX_COUNTER_STATUS' in config_data,
                             "FLEX_COUNTER_STATUS not found in CONFIG_DB")

                actual_status = config_data['FLEX_COUNTER_STATUS']
                pytest_assert(expected_status == actual_status,
                             "CONFIG_DB status is '{}', expected '{}'".format(actual_status, expected_status))

                if expected_interval is not None:
                    pytest_assert('POLL_INTERVAL' in config_data,
                                 "POLL_INTERVAL not found in CONFIG_DB")
                    actual_interval = config_data['POLL_INTERVAL']
                    pytest_assert(str(expected_interval) == actual_interval,
                                 "CONFIG_DB interval is '{}', expected '{}'".format(actual_interval, expected_interval))

                logging.info("CONFIG_DB verified: status={}, interval={}".format(
                    actual_status, config_data.get('POLL_INTERVAL', 'N/A')))

            except SonicDbKeyNotFound:
                pytest.fail("FLEX_COUNTER_TABLE|PORT_PHY_ATTR not found in CONFIG_DB")


def verify_phy_attr_in_flex_counter_db(duthost, expected_interval=None):
    """
    Verify FLEX_COUNTER_DB PORT_PHY_ATTR group table

    Args:
        duthost: DUT host object
        expected_interval: Expected poll interval in ms (optional)
    """
    with allure.step("Verifying FLEX_COUNTER_DB PORT_PHY_ATTR tables"):
        for asic in duthost.asics:
            try:
                group_data = SonicDbCli(asic, 'FLEX_COUNTER_DB').hget_all(FLEX_COUNTER_GROUP_TABLE)

                pytest_assert('FLEX_COUNTER_STATUS' in group_data,
                             "FLEX_COUNTER_STATUS not found in FLEX_COUNTER_DB group table")
                pytest_assert(group_data['FLEX_COUNTER_STATUS'] == ENABLE,
                             "FLEX_COUNTER_DB status is not enabled")

                if expected_interval is not None:
                    pytest_assert('POLL_INTERVAL' in group_data,
                                 "POLL_INTERVAL not found in FLEX_COUNTER_DB")
                    actual_interval = group_data['POLL_INTERVAL']
                    pytest_assert(str(expected_interval) == actual_interval,
                                 "FLEX_COUNTER_DB interval is '{}', expected '{}'".format(
                                     actual_interval, expected_interval))

                logging.info("FLEX_COUNTER_DB group table verified on asic{}".format(asic.asic_index))

            except SonicDbKeyNotFound:
                pytest.fail("FLEX_COUNTER_GROUP_TABLE:PORT_PHY_ATTR not found in FLEX_COUNTER_DB")


def get_sample_ports_with_lane_counts(duthost, sample_size=3):
    """
    Get random sample of ports with their lane counts

    Args:
        duthost: DUT host object
        sample_size: Number of ports to sample

    Returns:
        dict: Port OID to port info mapping
    """
    port_configs = get_port_config_from_config_db(duthost)
    pytest_assert(len(port_configs) > 0, "No ports found in CONFIG_DB")

    port_oid_map = build_port_oid_map(duthost)
    pytest_assert(len(port_oid_map) > 0, "No port OID mappings found in COUNTERS_PORT_NAME_MAP")

    sample_interfaces = random.sample(list(port_configs.keys()), sample_size)

    sample_ports = {}
    for intf_name in sample_interfaces:
        port_oid = port_oid_map[intf_name]
        port_config = port_configs[intf_name]
        lane_count = get_port_lane_count_from_config(port_config)

        asic_index = 0
        for asic in duthost.asics:
            try:
                name_map = SonicDbCli(asic, 'COUNTERS_DB').hget_all('COUNTERS_PORT_NAME_MAP')
                if intf_name in name_map and name_map[intf_name] == port_oid:
                    asic_index = asic.asic_index
                    break
            except SonicDbKeyNotFound:
                continue

        sample_ports[port_oid] = {
            'interface': intf_name,
            'lanes': lane_count,
            'asic': asic_index
        }
        logging.info("Sampled port: {} ({}) - {} lanes".format(port_oid, intf_name, lane_count))

    pytest_assert(len(sample_ports) > 0, "Failed to get any valid sample ports")
    return sample_ports


def verify_attribute_list_in_flex_counter_db(duthost, sample_ports):
    """
    Verify PORT_PHY_ATTR_ID_LIST contains all 3 PORT attributes

    Args:
        duthost: DUT host object
        sample_ports: Dictionary of sample ports with their metadata
    """
    with allure.step("Verifying PORT_PHY_ATTR_ID_LIST in FLEX_COUNTER_DB"):
        for port_oid, port_info in sample_ports.items():
            asic = duthost.asics[port_info['asic']]
            flex_counter_key = 'FLEX_COUNTER_TABLE:PORT_PHY_ATTR:{}'.format(port_oid)

            try:
                port_data = SonicDbCli(asic, 'FLEX_COUNTER_DB').hget_all(flex_counter_key)

                pytest_assert('PORT_PHY_ATTR_ID_LIST' in port_data,
                             "PORT_PHY_ATTR_ID_LIST not found for {}".format(port_oid))

                attr_list = port_data['PORT_PHY_ATTR_ID_LIST']
                for expected_attr in PORT_PHY_ATTRIBUTES:
                    pytest_assert(expected_attr in attr_list,
                                 "{} not found in attribute list for {}".format(expected_attr, port_oid))

                logging.info("Verified attribute list for {}: {}".format(port_oid, attr_list))

            except SonicDbKeyNotFound:
                pytest.fail("Port OID {} not found in FLEX_COUNTER_DB".format(port_oid))


def validate_latch_status_value(value, lane, port_oid, attribute_name):
    """Validate latch status value format: [status, timestamp, counter]"""
    pytest_assert(isinstance(value, list),
                 "{} lane {} value is not a list for {}".format(attribute_name, lane, port_oid))
    pytest_assert(len(value) == 3,
                 "{} lane {} has {} elements, expected 3 [status, timestamp, counter] for {}".format(
                     attribute_name, lane, len(value), port_oid))

    status, timestamp, counter = value
    pytest_assert(status in ["T", "T*", "F", "F*"],
                 "{} lane {} has invalid status '{}', expected T/T*/F/F* for {}".format(
                     attribute_name, lane, status, port_oid))
    pytest_assert(isinstance(timestamp, int) and timestamp >= 0,
                 "{} lane {} has invalid timestamp '{}', expected positive integer for {}".format(
                     attribute_name, lane, timestamp, port_oid))
    pytest_assert(isinstance(counter, int) and counter >= 0,
                 "{} lane {} has invalid counter '{}', expected positive integer for {}".format(
                     attribute_name, lane, counter, port_oid))

    return status, timestamp, counter


def read_port_latch_status(asic, port_oid, attribute_name):
    """
    Read latch status for a specific attribute

    Args:
        asic: ASIC object
        port_oid: Port OID
        attribute_name: Attribute name to read

    Returns:
        dict: Parsed latch status data
    """
    counters_key = 'PORT_PHY_ATTR:{}'.format(port_oid)
    counters_data = SonicDbCli(asic, 'COUNTERS_DB').hget_all(counters_key)
    pytest_assert(attribute_name in counters_data,
                 "{} not found for {}".format(attribute_name, port_oid))
    return json.loads(counters_data[attribute_name])


def poll_for_latch_status(asic, port_oid, expected_status, prev_signal_data=None, prev_fec_data=None,
                           max_attempts=11):
    """
    Poll for expected latch status with counter and timestamp validation

    Args:
        asic: ASIC object
        port_oid: Port OID
        expected_status: Expected status string (e.g., 'T*', 'F*', 'T', 'F')
        prev_signal_data: Previous signal data for counter/timestamp validation (optional)
        prev_fec_data: Previous FEC data for counter/timestamp validation (optional)
        max_attempts: Maximum polling attempts (default 11)

    Returns:
        tuple: (signal_data, fec_data) when expected status is found
    """
    for attempt in range(max_attempts):
        time.sleep(1)
        signal_data = read_port_latch_status(asic, port_oid, 'phy_rx_signal_detect')
        fec_data = read_port_latch_status(asic, port_oid, 'pcs_fec_lane_alignment_lock')

        signal_status = signal_data['0'][0]
        fec_status = fec_data['0'][0]

        logging.info("Attempt {}: signal={}, fec={} (expecting {})".format(
            attempt + 1, signal_status, fec_status, expected_status))

        if signal_status == expected_status and fec_status == expected_status:
            logging.info("{} detected on both attributes after {} seconds".format(
                expected_status, attempt + 1))

            if prev_signal_data and prev_fec_data:
                signal_ts = signal_data['0'][1]
                signal_counter = signal_data['0'][2]
                fec_ts = fec_data['0'][1]
                fec_counter = fec_data['0'][2]

                prev_signal_ts = prev_signal_data['0'][1]
                prev_signal_counter = prev_signal_data['0'][2]
                prev_fec_ts = prev_fec_data['0'][1]
                prev_fec_counter = prev_fec_data['0'][2]

                pytest_assert(signal_counter == prev_signal_counter + 1,
                             "Signal counter should increment by 1: {} -> {}".format(
                                 prev_signal_counter, signal_counter))
                pytest_assert(signal_ts != prev_signal_ts,
                             "Signal timestamp should change: {} -> {}".format(
                                 prev_signal_ts, signal_ts))
                pytest_assert(fec_counter == prev_fec_counter + 1,
                             "FEC counter should increment by 1: {} -> {}".format(
                                 prev_fec_counter, fec_counter))
                pytest_assert(fec_ts != prev_fec_ts,
                             "FEC timestamp should change: {} -> {}".format(
                                 prev_fec_ts, fec_ts))

            return signal_data, fec_data

    pytest.fail("{} not detected on both attributes within {} seconds".format(
        expected_status, max_attempts))


def get_test_port_info(duthost, fanouthosts):
    """
    Get test port information including OID, interface, asic, fanout object

    Args:
        duthost: DUT host object
        fanouthosts: Fanout hosts fixture

    Returns:
        dict: Port information including interface, oid, lanes, asic, fanout, fanout_port
    """
    candidates = build_test_candidates(duthost, fanouthosts, 'all_ports')
    pytest_assert(len(candidates) > 0, "No ports with fanout connectivity found")

    # Use first candidate
    test_interface, fanout, fanout_port = candidates[0]

    port_configs = get_port_config_from_config_db(duthost)
    port_oid_map = build_port_oid_map(duthost)

    test_port_oid = port_oid_map[test_interface]
    lane_count = get_port_lane_count_from_config(port_configs[test_interface])

    # Find ASIC for test port
    test_asic = duthost.asics[0]
    for asic in duthost.asics:
        try:
            name_map = SonicDbCli(asic, 'COUNTERS_DB').hget_all('COUNTERS_PORT_NAME_MAP')
            if test_interface in name_map and name_map[test_interface] == test_port_oid:
                test_asic = asic
                break
        except SonicDbKeyNotFound:
            continue

    return {
        'interface': test_interface,
        'oid': test_port_oid,
        'lanes': lane_count,
        'asic': test_asic,
        'fanout': fanout,
        'fanout_port': fanout_port
    }


def verify_counters_db_data(duthost, sample_ports):
    """
    Verify COUNTERS_DB PORT_PHY_ATTR table has all 3 attributes with correct lane counts

    Args:
        duthost: DUT host object
        sample_ports: Dictionary of sample ports with their metadata
    """
    with allure.step("Verifying COUNTERS_DB PORT_PHY_ATTR table data"):
        for port_oid, port_info in sample_ports.items():
            expected_lanes = port_info['lanes']
            interface_name = port_info['interface']
            asic = duthost.asics[port_info['asic']]

            counters_key = 'PORT_PHY_ATTR:{}'.format(port_oid)

            try:
                counters_data = SonicDbCli(asic, 'COUNTERS_DB').hget_all(counters_key)

                # Verify rx_snr (new short name)
                pytest_assert('rx_snr' in counters_data,
                             "rx_snr not found for {} ({})".format(port_oid, interface_name))

                # Parse flat dictionary format: {0: 3712, 1: 3840, ...}
                rx_snr_data = json.loads(counters_data['rx_snr'])
                pytest_assert(isinstance(rx_snr_data, dict),
                             "rx_snr data is not a dictionary for {} ({})".format(port_oid, interface_name))
                pytest_assert(len(rx_snr_data) == expected_lanes,
                             "rx_snr has {} lanes, expected {} for {} ({})".format(
                                 len(rx_snr_data), expected_lanes, port_oid, interface_name))

                # Verify all lane numbers are present and values are integers
                for lane in range(expected_lanes):
                    lane_key = str(lane)
                    pytest_assert(lane_key in rx_snr_data,
                                 "Lane {} missing in rx_snr for {} ({})".format(lane, port_oid, interface_name))
                    pytest_assert(isinstance(rx_snr_data[lane_key], int),
                                 "rx_snr lane {} value is not an integer for {}".format(lane, port_oid))

                logging.info("rx_snr verified for {}: {} lanes".format(interface_name, expected_lanes))

                # Verify pcs_fec_lane_alignment_lock (new short name)
                pytest_assert('pcs_fec_lane_alignment_lock' in counters_data,
                             "pcs_fec_lane_alignment_lock not found for {} ({})".format(
                                 port_oid, interface_name))

                # Parse new format: {0: ["T*", timestamp, counter], 1: ["F", timestamp, counter], ...}
                fec_lock_data = json.loads(counters_data['pcs_fec_lane_alignment_lock'])
                pytest_assert(isinstance(fec_lock_data, dict),
                             "pcs_fec_lane_alignment_lock data is not a dictionary for {} ({})".format(
                                 port_oid, interface_name))

                fec_count = len(fec_lock_data)
                valid_fec_counts = [expected_lanes, expected_lanes * 4]
                pytest_assert(fec_count in valid_fec_counts,
                             "pcs_fec_lane_alignment_lock has {} entries, expected {} or {} for {} ({})".format(
                                 fec_count, expected_lanes, expected_lanes * 4, port_oid, interface_name))

                # Verify values are in [status, timestamp, counter] format
                for lane, value in fec_lock_data.items():
                    validate_latch_status_value(value, lane, port_oid, 'pcs_fec_lane_alignment_lock')

                logging.info("pcs_fec_lane_alignment_lock verified for {}: {} values (lanes={})".format(
                    interface_name, fec_count, expected_lanes))

                # Verify phy_rx_signal_detect (new short name)
                pytest_assert('phy_rx_signal_detect' in counters_data,
                             "phy_rx_signal_detect not found for {} ({})".format(
                                 port_oid, interface_name))

                # Parse new format: {0: ["T", timestamp, counter], 1: ["F*", timestamp, counter], ...}
                rx_signal_data = json.loads(counters_data['phy_rx_signal_detect'])
                pytest_assert(isinstance(rx_signal_data, dict),
                             "phy_rx_signal_detect data is not a dictionary for {} ({})".format(
                                 port_oid, interface_name))
                pytest_assert(len(rx_signal_data) == expected_lanes,
                             "phy_rx_signal_detect has {} lanes, expected {} for {} ({})".format(
                                 len(rx_signal_data), expected_lanes, port_oid, interface_name))

                # Verify values are in [status, timestamp, counter] format
                for lane, value in rx_signal_data.items():
                    validate_latch_status_value(value, lane, port_oid, 'phy_rx_signal_detect')

                logging.info("phy_rx_signal_detect verified for {}: {} lanes".format(
                    interface_name, expected_lanes))

            except SonicDbKeyNotFound:
                pytest.fail("Port OID {} not found in COUNTERS_DB:PORT_PHY_ATTR".format(port_oid))
            except json.JSONDecodeError as e:
                pytest.fail("Failed to parse JSON data for {}: {}".format(port_oid, str(e)))


# ============================================================================
# Test Functions
# ============================================================================

def test_phy_enable_and_validate(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost):
    """
    Test 1: Configure PHY counters and validate show output + all DBs

    Steps:
    1. Enable PHY counters (counterpoll phy enable)
    2. Validate CLI, CONFIG_DB, FLEX_COUNTER_DB, and COUNTERS_DB
    3. Verify lane counts match for 3 random ports
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Enabling PHY counters"):
        for asic in duthost.asics:
            ConterpollHelper.enable_counterpoll(asic, [PORT_PHY_ATTR])

    verify_phy_attr_in_cli(duthost, ENABLE)

    verify_phy_attr_in_config_db(duthost, ENABLE)

    verify_phy_attr_in_flex_counter_db(duthost)

    sample_ports = get_sample_ports_with_lane_counts(duthost, sample_size=3)

    verify_attribute_list_in_flex_counter_db(duthost, sample_ports)

    with allure.step("Waiting for data collection cycle"):
        time.sleep(15)

    verify_counters_db_data(duthost, sample_ports)

    logging.info("Test 1 completed: PHY counter enable and validate - PASSED")


def test_phy_interval_change(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Test 2: Validate interval modification propagates to all DBs

    Steps:
    1. Change interval to 5000ms
    2. Verify CLI, CONFIG_DB, FLEX_COUNTER_DB
    3. Change interval to 10000ms
    4. Verify new interval in all locations
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Changing interval to 5000ms"):
        for asic in duthost.asics:
            asic.command(CounterpollConstants.COUNTERPOLL_INTERVAL_STR.format(PORT_PHY_ATTR, 5000))

    verify_phy_attr_in_cli(duthost, ENABLE)
    verify_phy_attr_in_config_db(duthost, ENABLE, expected_interval=5000)
    verify_phy_attr_in_flex_counter_db(duthost, expected_interval=5000)

    with allure.step("Changing interval to 10000ms"):
        for asic in duthost.asics:
            asic.command(CounterpollConstants.COUNTERPOLL_INTERVAL_STR.format(PORT_PHY_ATTR, 10000))

    verify_phy_attr_in_cli(duthost, ENABLE)
    verify_phy_attr_in_config_db(duthost, ENABLE, expected_interval=10000)
    verify_phy_attr_in_flex_counter_db(duthost, expected_interval=10000)

    logging.info("Test 2 completed: interval change validation - PASSED")


def test_phy_config_reload_persistence(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Test 3: Verify PHY counters persist after config save + disable + reload

    Steps:
    1. Save config
    2. Disable PHY counters
    3. Config reload
    4. Verify PHY counters restored to enabled
    5. Verify COUNTERS_DB has fresh data
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Saving config"):
        duthost.command('config save -y')

    with allure.step("Disabling PHY counters"):
        for asic in duthost.asics:
            ConterpollHelper.disable_counterpoll(asic, [PORT_PHY_ATTR])

    verify_phy_attr_in_cli(duthost, DISABLE)

    with allure.step("Performing config reload"):
        config_reload(duthost, config_source='config_db', safe_reload=True, yang_validate=False)

    time.sleep(60)

    verify_phy_attr_in_cli(duthost, ENABLE)

    verify_phy_attr_in_flex_counter_db(duthost)

    sample_ports = get_sample_ports_with_lane_counts(duthost, sample_size=3)

    with allure.step("Waiting for data collection after config reload"):
        time.sleep(15)

    verify_counters_db_data(duthost, sample_ports)

    logging.info("Test 3 completed: config reload persistence - PASSED")


def test_phy_reboot_persistence(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost):
    """
    Test 4: Verify PHY counters persist after disable + reboot

    Steps:
    1. Disable PHY counters
    2. Reboot
    3. Verify PHY counters restored to enabled
    4. Verify COUNTERS_DB has fresh data
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Disabling PHY counters"):
        for asic in duthost.asics:
            ConterpollHelper.disable_counterpoll(asic, [PORT_PHY_ATTR])

    verify_phy_attr_in_cli(duthost, DISABLE)

    with allure.step("Performing reboot"):
        reboot(duthost, localhost)

    verify_phy_attr_in_cli(duthost, ENABLE)

    verify_phy_attr_in_flex_counter_db(duthost)

    sample_ports = get_sample_ports_with_lane_counts(duthost, sample_size=3)

    with allure.step("Waiting for data collection after reboot"):
        time.sleep(15)

    verify_counters_db_data(duthost, sample_ports)

    logging.info("Test 4 completed: reboot persistence - PASSED")


def test_phy_latch_status_transition(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                      fanouthosts, tbinfo):
    """
    Test 5: Verify latch status transitions (T->T*, F->F*) on link state changes

    Steps:
    1. Enable PHY counters and get test port info
    2. Read initial latch status
    3. Shutdown link and verify * marker appears
    4. Read again and verify * marker behavior
    5. Bring link up and verify * marker appears again
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Enabling PHY counters"):
        for asic in duthost.asics:
            ConterpollHelper.enable_counterpoll(asic, [PORT_PHY_ATTR])

    verify_phy_attr_in_cli(duthost, ENABLE)

    config_data = SonicDbCli(duthost.asics[0], 'CONFIG_DB').hget_all(CONFIG_DB_TABLE)
    poll_interval_ms = int(config_data.get('POLL_INTERVAL', 10000))
    wait_time = (poll_interval_ms / 1000) + 1

    with allure.step("Waiting for initial data collection"):
        time.sleep(wait_time)

    port_info = get_test_port_info(duthost, fanouthosts)
    fanout = port_info['fanout']

    logging.info("Testing latch status transitions on {} ({})".format(
        port_info['interface'], port_info['oid']))

    with allure.step("Reading initial latch status"):
        initial_signal = read_port_latch_status(port_info['asic'], port_info['oid'], 'phy_rx_signal_detect')
        initial_fec = read_port_latch_status(port_info['asic'], port_info['oid'], 'pcs_fec_lane_alignment_lock')

        initial_signal_status = initial_signal['0'][0]
        initial_signal_ts = initial_signal['0'][1]
        initial_signal_counter = initial_signal['0'][2]
        initial_fec_status = initial_fec['0'][0]
        initial_fec_ts = initial_fec['0'][1]
        initial_fec_counter = initial_fec['0'][2]

        logging.info("Initial - signal: status={}, ts={}, counter={}".format(
            initial_signal_status, initial_signal_ts, initial_signal_counter))
        logging.info("Initial - fec: status={}, ts={}, counter={}".format(
            initial_fec_status, initial_fec_ts, initial_fec_counter))

    with allure.step("Shutting down link"):
        fanout.shutdown(port_info['fanout_port'])

    with allure.step("Polling for F* after link down"):
        after_down_signal, after_down_fec = poll_for_latch_status(
            port_info['asic'], port_info['oid'], 'F*',
            prev_signal_data=initial_signal, prev_fec_data=initial_fec)

    with allure.step("Polling for F (marker cleared)"):
        stable_signal, stable_fec = poll_for_latch_status(
            port_info['asic'], port_info['oid'], 'F')

    with allure.step("Bringing link up"):
        fanout.no_shutdown(port_info['fanout_port'])

    with allure.step("Polling for T* after link up"):
        after_up_signal, after_up_fec = poll_for_latch_status(
            port_info['asic'], port_info['oid'], 'T*',
            prev_signal_data=after_down_signal, prev_fec_data=after_down_fec)

    with allure.step("Polling for T (marker cleared)"):
        final_signal, final_fec = poll_for_latch_status(
            port_info['asic'], port_info['oid'], 'T')

    logging.info("Test 5 completed: latch status transition - PASSED")
