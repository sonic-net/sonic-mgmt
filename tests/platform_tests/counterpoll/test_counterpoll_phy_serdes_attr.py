import allure
import logging
import random
import time
import pytest
import re

from tests.common.broadcom_data import is_broadcom_device
from tests.common.helpers.assertions import pytest_require
from tests.common.config_reload import config_reload
from tests.common.constants import CounterpollConstants
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.counterpoll_helper import ConterpollHelper
from tests.common.helpers.sonic_db import SonicDbCli, SonicDbKeyNotFound
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
FLEX_COUNTER_GROUP_TABLE = 'FLEX_COUNTER_GROUP_TABLE:PORT_PHY_SERDES_ATTR'
FLEX_COUNTER_TABLE_PREFIX = 'FLEX_COUNTER_TABLE:PORT_PHY_SERDES_ATTR:*'

# PORT SERDES attributes to validate
PORT_PHY_SERDES_ATTRIBUTES = [
   'SAI_PORT_SERDES_ATTR_RX_VGA',
   'SAI_PORT_SERDES_ATTR_TX_FIR_TAPS_LIST'
]

# Global cache for port configuration and OID mapping
_port_config_cache = None
_port_oid_map_cache = None


@pytest.fixture(scope="module", autouse=True)
def skip_non_th5_asics(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Skip the test on non-th5 asics

    Args:
        duthosts (pytest fixture): list of Duts
        enum_rand_one_per_hwsku_frontend_hostname (str): hostname of DUT

    Returns:
        None
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_type = duthost.get_asic_name()
    supported_asics = ["th5"]
    pytest_require((is_broadcom_device(duthost)
                    and asic_type in supported_asics),
                   "This test is not supported on {} asic".format(asic_type))


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


def verify_phy_serdes_attr_in_flex_counter_db(duthost, expected_interval=None):
    """
    Verify FLEX_COUNTER_DB PORT_PHY_SERDES_ATTR group table and OID tables

    Args:
        duthost: DUT host object
        expected_interval: Expected poll interval in ms (optional)

    """

    with allure.step("Verifying FLEX_COUNTER_DB PORT_PHY_SERDES_ATTR tables"):
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
                pytest.fail("FLEX_COUNTER_GROUP_TABLE:PORT_PHY_SERDES_ATTR not found in FLEX_COUNTER_DB")


def get_sample_port_serdes_with_asic_and_port_id(duthost, sample_size=3):
    """
    Get random sample of PORT_SERDES_IDs with their associated ASIC and PORT_ID

    This function reads COUNTERS_PORT_SERDES_ID_TO_PORT_ID_MAP from COUNTERS_DB
    and returns a random sample of serdes IDs along with their ASIC object and
    corresponding port ID.

    Args:
        duthost: DUT host object
        sample_size: Number of random serdes entries to sample (default: 3)

    Returns:
        dict: {port_serdes_id: [asic, port_id]}
              e.g., {'oid:0x5700000000015b': [asic_obj, 'oid:0x1000000000001']}
    """
    all_serdes_to_port_map = {}

    for asic in duthost.asics:
        try:
            # Get the full COUNTERS_PORT_SERDES_ID_TO_PORT_ID_MAP from COUNTERS_DB
            serdes_map = SonicDbCli(asic, 'COUNTERS_DB').hget_all('COUNTERS_PORT_SERDES_ID_TO_PORT_ID_MAP')

            # Store with asic information
            for serdes_id, port_id in serdes_map.items():
                all_serdes_to_port_map[serdes_id] = [asic, port_id]

            logging.info("Found {} PORT_SERDES_ID mappings on asic{}".format(
                len(serdes_map), asic.asic_index))

        except SonicDbKeyNotFound:
            logging.warning("COUNTERS_PORT_SERDES_ID_TO_PORT_ID_MAP not found on asic{}".format(
                asic.asic_index))

    pytest_assert(len(all_serdes_to_port_map) > 0,
                  "No PORT_SERDES_ID to PORT_ID mappings found in COUNTERS_DB")

    # Randomly sample entries
    all_serdes_ids = list(all_serdes_to_port_map.keys())
    sample_serdes_ids = random.sample(all_serdes_ids, min(sample_size, len(all_serdes_ids)))

    sampled_serdes_to_port_map = {
        serdes_id: all_serdes_to_port_map[serdes_id]
        for serdes_id in sample_serdes_ids
    }

    logging.info("Sampled {} PORT_SERDES_ID mappings from {} total".format(
        len(sampled_serdes_to_port_map), len(all_serdes_to_port_map)))

    for serdes_id, (asic, port_id) in sampled_serdes_to_port_map.items():
        logging.info("Sampled SERDES mapping: {} -> [asic{}, {}]".format(
            serdes_id, asic.asic_index, port_id))

    return sampled_serdes_to_port_map


def verify_port_serdes_attribute_list_in_flex_counter_db(duthost, port_serdes_info_map):
    """
    Verify PORT_PHY_SERDES_ATTR_ID_LIST contains valid attributes for sampled serdes OIDs

    Args:
        duthost: DUT host object
        port_serdes_info_map: Dictionary mapping {port_serdes_id: [asic, port_id]}
    """
    with allure.step("Verifying PORT_PHY_SERDES_ATTR_ID_LIST in FLEX_COUNTER_DB"):
        for port_serdes_oid, (asic, port_id) in port_serdes_info_map.items():
            flex_counter_key = 'FLEX_COUNTER_TABLE:PORT_PHY_SERDES_ATTR:{}'.format(port_serdes_oid)

            try:
                serdes_data = SonicDbCli(asic, 'FLEX_COUNTER_DB').hget_all(flex_counter_key)

                pytest_assert('PORT_PHY_SERDES_ATTR_ID_LIST' in serdes_data,
                              "PORT_PHY_SERDES_ATTR_ID_LIST not found for {}".format(port_serdes_oid))

                attr_list = serdes_data['PORT_PHY_SERDES_ATTR_ID_LIST']
                for expected_attr in PORT_PHY_SERDES_ATTRIBUTES:
                    pytest_assert(expected_attr in attr_list,
                                  "{} not found in attribute list for {}".format(expected_attr, port_serdes_oid))

                logging.info("Verified PORT PHY SERDES attribute list for {} (port: {}): {}".format(
                    port_serdes_oid, port_id, attr_list))

            except SonicDbKeyNotFound:
                pytest.fail("Port SERDES OID {} not found in FLEX_COUNTER_DB".format(port_serdes_oid))


def verify_counters_db_port_serdes_data(duthost, port_serdes_info_map):
    """
    Verify COUNTERS_DB PORT_PHY_ATTR table has all port serdes expected attributes

    Validates that for each port_id in the map, the COUNTERS_DB contains:
    - tx_fir_taps_list: Format '[{tap1:<vals>},{tap2:<vals>},...]' where:
        - Keys are incremental (tap1,tap2,tap3,...)
        - Values are comma-separated numbers (can be negative)
        - Values can be empty (e.g., {tap1:})
    - rx_vga: Format 'size:<val1>,<val2>,...,<val_size>' where:
        - size is a number
        - values are comma-separated matching the size

    Args:
        duthost: DUT host object
        port_serdes_info_map: Dictionary mapping {port_serdes_id: [asic, port_id]}
    """

    with allure.step("Verifying port serdes expected attributes in COUNTERS_DB PORT_PHY_ATTR table."):
        for port_serdes_oid, (asic, port_id) in port_serdes_info_map.items():
            try:
                counters_data = SonicDbCli(asic, 'COUNTERS_DB').hget_all(
                    'PORT_PHY_ATTR:{}'.format(port_id))

                # Verify tx_fir_taps_list format: [{tap1:vals},{tap2:vals},...]
                pytest_assert('tx_fir_taps_list' in counters_data,
                              "tx_fir_taps_list not found for port {}".format(port_id))

                tx_fir_taps = counters_data['tx_fir_taps_list']
                # Validate format and extract keys to check they're incremental (tap1, tap2, tap3, ...)
                pattern = (r'\[\{(tap[0-9]+):(?:-?[0-9]+(?:,-?[0-9]+)*)?\}'
                           r'(?:,\{(tap[0-9]+):(?:-?[0-9]+(?:,-?[0-9]+)*)?\})*\]')
                match = re.match(pattern, tx_fir_taps)
                pytest_assert(match,
                              "tx_fir_taps_list invalid format for port {}: {}".format(port_id, tx_fir_taps))

                # Check keys are incremental (tap1, tap2, tap3, ...)
                tap_keys = re.findall(r'\{(tap[0-9]+):', tx_fir_taps)
                tap_indices = [int(key.replace('tap', '')) for key in tap_keys]
                pytest_assert(tap_indices == list(range(1, len(tap_indices) + 1)),
                              "tx_fir_taps_list keys not incremental for port {}: {}".format(port_id, tap_keys))

                # Verify rx_vga format: size:val1,val2,...
                pytest_assert('rx_vga' in counters_data,
                              "rx_vga not found for port {}".format(port_id))

                rx_vga = counters_data['rx_vga']
                size_str, values_str = rx_vga.split(':', 1)
                pytest_assert(size_str.isdigit(), "rx_vga size not numeric: {}".format(rx_vga))
                pytest_assert(len(values_str.split(',')) == int(size_str),
                              "rx_vga size mismatch for port {}: {}".format(port_id, rx_vga))

                logging.info(
                    "Port serdes expected attributes in COUNTERS_DB PORT_PHY_ATTR table "
                    "verified for port {}: tx_fir_taps={}, rx_vga={}".format(
                        port_id, tx_fir_taps[:50], rx_vga))

            except SonicDbKeyNotFound:
                pytest.fail(
                    "Port serdes expected attributes not found in COUNTERS_DB "
                    "PORT_PHY_ATTR table for port {}".format(port_id))


# ============================================================================
# Test Functions
# ============================================================================

def test_phy_enable_and_validate(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost):
    """
    Test 1: Configure PHY counters and validate show output + all DBs

    Steps:
    1. Enable PHY counters (counterpoll phy enable)
    2. Validate CLI, CONFIG_DB, FLEX_COUNTER_DB, and COUNTERS_DB
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Enabling PHY counters"):
        for asic in duthost.asics:
            ConterpollHelper.enable_counterpoll(asic, [PORT_PHY_ATTR])

    verify_phy_attr_in_cli(duthost, ENABLE)
    # Leave time for modules to react to config change.
    time.sleep(5)

    verify_phy_attr_in_config_db(duthost, ENABLE)

    verify_phy_serdes_attr_in_flex_counter_db(duthost)

    sample_serdes_info_map = get_sample_port_serdes_with_asic_and_port_id(duthost, 3)

    verify_port_serdes_attribute_list_in_flex_counter_db(duthost, sample_serdes_info_map)

    with allure.step("Waiting for data collection cycle"):
        time.sleep(15)

    verify_counters_db_port_serdes_data(duthost, sample_serdes_info_map)

    logging.info("Test 1 completed: PHY Port Serdes counter enable and validate - PASSED")


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

    # Leave time for modules to react to config change.
    time.sleep(5)

    verify_phy_attr_in_cli(duthost, ENABLE)
    verify_phy_attr_in_config_db(duthost, ENABLE, expected_interval=5000)
    verify_phy_serdes_attr_in_flex_counter_db(duthost, expected_interval=5000)

    with allure.step("Changing interval to 10000ms"):
        for asic in duthost.asics:
            asic.command(CounterpollConstants.COUNTERPOLL_INTERVAL_STR.format(PORT_PHY_ATTR, 10000))

    # Leave time for modules to react to config change.
    time.sleep(5)

    verify_phy_attr_in_cli(duthost, ENABLE)
    verify_phy_attr_in_config_db(duthost, ENABLE, expected_interval=10000)
    verify_phy_serdes_attr_in_flex_counter_db(duthost, expected_interval=10000)

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

    # Leave time for modules to react to config change.
    time.sleep(5)

    verify_phy_attr_in_cli(duthost, DISABLE)

    with allure.step("Performing config reload"):
        config_reload(duthost, config_source='config_db', safe_reload=True, yang_validate=False)

    time.sleep(60)

    verify_phy_attr_in_cli(duthost, ENABLE)

    verify_phy_serdes_attr_in_flex_counter_db(duthost)

    sample_serdes_info_map = get_sample_port_serdes_with_asic_and_port_id(duthost, 3)

    with allure.step("Waiting for data collection cycle"):
        time.sleep(15)

    verify_counters_db_port_serdes_data(duthost, sample_serdes_info_map)

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

    # Leave time for modules to react to config change.
    time.sleep(5)

    verify_phy_attr_in_cli(duthost, DISABLE)

    with allure.step("Performing reboot"):
        reboot(duthost, localhost)

    verify_phy_attr_in_cli(duthost, ENABLE)

    verify_phy_serdes_attr_in_flex_counter_db(duthost)

    sample_serdes_info_map = get_sample_port_serdes_with_asic_and_port_id(duthost, 3)

    with allure.step("Waiting for data collection cycle"):
        time.sleep(15)

    verify_counters_db_port_serdes_data(duthost, sample_serdes_info_map)

    logging.info("Test 4 completed: reboot persistence - PASSED")
