import allure
import json
import logging
import random
import time
import pytest

from tests.common.config_reload import config_reload
from tests.common.constants import CounterpollConstants
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.counterpoll_helper import ConterpollHelper
from tests.common.helpers.sonic_db import SonicDbCli, SonicDbKeyNotFound
from tests.common.utilities import skip_release, wait_until
from tests.common.reboot import reboot

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

ENABLE = CounterpollConstants.COUNTERPOLL_ENABLE.split(' ')[-1]
DISABLE = CounterpollConstants.COUNTERPOLL_DISABLE.split(' ')[-1]

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
    Get port configuration from CONFIG_DB using sonic-cfggen

    Args:
        duthost: DUT host object

    Returns:
        dict: Port configuration data (e.g., {'Ethernet0': {'lanes': '369,370,371,372', ...}, ...})
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
    Calculate lane count from port config lanes string

    Args:
        port_config: Port configuration dict (e.g., {'lanes': '369,370,371,372', ...})

    Returns:
        int: Number of lanes (e.g., 4)
    """
    lanes_str = port_config.get('lanes', '')
    if not lanes_str:
        logging.warning("No lanes found in port config, defaulting to 4")
        return 4

    lane_count = len(lanes_str.split(','))
    return lane_count


def build_port_oid_map(duthost):
    """
    Build mapping of interface name to OID from COUNTERS_PORT_NAME_MAP

    Args:
        duthost: DUT host object

    Returns:
        dict: Mapping of {interface_name: oid}
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
    Verify FLEX_COUNTER_DB PORT_PHY_ATTR group table and OID tables

    Args:
        duthost: DUT host object
        expected_interval: Expected poll interval in ms (optional)

    """

    with allure.step("Verifying FLEX_COUNTER_DB PORT_PHY_ATTR tables"):
        for asic in duthost.asics:
            # Verify group table
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
    Get random sample of ports and their lane counts from CONFIG_DB

    Args:
        duthost: DUT host object
        sample_size: Number of ports to sample

    Returns:
        dict: {port_oid: {'interface': name, 'lanes': count, 'asic': index}}
    """
    # Get all port configurations from CONFIG_DB
    port_configs = get_port_config_from_config_db(duthost)
    pytest_assert(len(port_configs) > 0, "No ports found in CONFIG_DB")

    # Get OID mapping (interface name -> OID)
    port_oid_map = build_port_oid_map(duthost)
    pytest_assert(len(port_oid_map) > 0, "No port OID mappings found in COUNTERS_PORT_NAME_MAP")

    sample_interfaces = random.sample(port_configs.keys(), sample_size)

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

                # Parse flat dictionary format: {0: "T*", 1: "F", ...}
                fec_lock_data = json.loads(counters_data['pcs_fec_lane_alignment_lock'])
                pytest_assert(isinstance(fec_lock_data, dict),
                             "pcs_fec_lane_alignment_lock data is not a dictionary for {} ({})".format(
                                 port_oid, interface_name))

                fec_count = len(fec_lock_data)
                valid_fec_counts = [expected_lanes, expected_lanes * 4]
                pytest_assert(fec_count in valid_fec_counts,
                             "pcs_fec_lane_alignment_lock has {} entries, expected {} or {} for {} ({})".format(
                                 fec_count, expected_lanes, expected_lanes * 4, port_oid, interface_name))

                # Verify values are in T/T*/F/F* format
                for lane, value in fec_lock_data.items():
                    pytest_assert(value in ["T", "T*", "F", "F*"],
                                 "pcs_fec_lane_alignment_lock lane {} has invalid value '{}' for {}".format(
                                     lane, value, port_oid))

                logging.info("pcs_fec_lane_alignment_lock verified for {}: {} values (lanes={})".format(
                    interface_name, fec_count, expected_lanes))

                # Verify phy_rx_signal_detect (new short name)
                pytest_assert('phy_rx_signal_detect' in counters_data,
                             "phy_rx_signal_detect not found for {} ({})".format(
                                 port_oid, interface_name))

                # Parse flat dictionary format: {0: "T", 1: "F*", ...}
                rx_signal_data = json.loads(counters_data['phy_rx_signal_detect'])
                pytest_assert(isinstance(rx_signal_data, dict),
                             "phy_rx_signal_detect data is not a dictionary for {} ({})".format(
                                 port_oid, interface_name))
                pytest_assert(len(rx_signal_data) == expected_lanes,
                             "phy_rx_signal_detect has {} lanes, expected {} for {} ({})".format(
                                 len(rx_signal_data), expected_lanes, port_oid, interface_name))

                # Verify values are in T/T*/F/F* format
                for lane, value in rx_signal_data.items():
                    pytest_assert(value in ["T", "T*", "F", "F*"],
                                 "phy_rx_signal_detect lane {} has invalid value '{}' for {}".format(
                                     lane, value, port_oid))

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
