import allure
import json
import logging
import random
import time
import pytest

from tests.common.broadcom_data import is_broadcom_device
from tests.common.helpers.assertions import pytest_require
from tests.common.config_reload import config_reload
from tests.common.constants import CounterpollConstants
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.counterpoll_helper import ConterpollHelper
from tests.common.helpers.sonic_db import SonicDbCli, SonicDbKeyNotFound
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
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

# COUNTERS_DB field names required for a port to be sampled by this test.
REQUIRED_PHY_COUNTER_FIELDS = {
    'phy_rx_signal_detect',
    'pcs_fec_lane_alignment_lock',
    'rx_snr'
}

# Sample once per second for 31 seconds.  In practice, a link transition can
# first be reported by either latch attribute in the next PORT_PHY_ATTR poll
# cycle rather than the cycle immediately following the fanout operation.  The
# default 10-second interval therefore needs up to three polling cycles, plus
# scheduling jitter, before declaring the transition missing.
LATCH_STATUS_POLL_INTERVAL_SEC = 1
LATCH_STATUS_MAX_ATTEMPTS = 31

# Global cache for port configuration and OID mapping
_port_config_cache = None
_port_oid_map_cache = None
_port_oid_asic_map_cache = None


def invalidate_port_caches():
    """Invalidate cached port configuration and runtime OID mappings."""
    global _port_config_cache, _port_oid_map_cache, _port_oid_asic_map_cache

    _port_config_cache = None
    _port_oid_map_cache = None
    _port_oid_asic_map_cache = None


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


@pytest.fixture(scope="module", autouse=True)
def backup_and_restore_config_db(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                 skip_non_th5_asics):
    """Restore the persistent and running configuration changed by this module."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    config_db = '/etc/sonic/config_db.json'
    backup_path = duthost.shell(
        'mktemp /host/config_db.json.before_counterpoll_phy_attr.XXXXXX')['stdout'].strip()

    duthost.shell('cp -p {} {}'.format(config_db, backup_path))
    try:
        yield
    finally:
        duthost.shell('mv {} {}'.format(backup_path, config_db))
        config_reload(duthost, config_source='config_db', safe_reload=True, yang_validate=False)


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
    global _port_oid_map_cache, _port_oid_asic_map_cache

    if _port_oid_map_cache is not None and _port_oid_asic_map_cache is not None:
        return _port_oid_map_cache

    port_oid_map = {}
    port_oid_asic_map = {}
    for asic in duthost.asics:
        try:
            name_map = SonicDbCli(asic, 'COUNTERS_DB').hget_all('COUNTERS_PORT_NAME_MAP')
            port_oid_map.update(name_map)
            port_oid_asic_map.update({port_oid: asic.asic_index for port_oid in name_map.values()})
            logging.info("Found {} port OID mappings on asic{}".format(len(name_map), asic.asic_index))
        except SonicDbKeyNotFound:
            logging.warning("COUNTERS_PORT_NAME_MAP not found on asic{}".format(asic.asic_index))

    _port_oid_map_cache = port_oid_map
    _port_oid_asic_map_cache = port_oid_asic_map
    return port_oid_map


def build_port_oid_asic_map(duthost):
    """Build mapping of port OID to owning ASIC index."""
    build_port_oid_map(duthost)
    return _port_oid_asic_map_cache


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
                                  "CONFIG_DB interval is '{}', expected '{}'".format(
                                      actual_interval, expected_interval))

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
    Get a random sample of ports that expose all required PHY attributes.

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

    port_oid_to_asic = build_port_oid_asic_map(duthost)

    eligible_ports = []
    port_candidates = list(port_configs.items())
    random.shuffle(port_candidates)
    for intf_name, port_config in port_candidates:
        port_oid = port_oid_map.get(intf_name)
        if port_oid is None:
            logging.info("Skipping {}: no COUNTERS_PORT_NAME_MAP entry".format(intf_name))
            continue

        asic_index = port_oid_to_asic.get(port_oid)
        if asic_index is None:
            logging.info("Skipping {}: no ASIC mapping for {}".format(intf_name, port_oid))
            continue

        try:
            counters_data = SonicDbCli(
                duthost.asics[asic_index], 'COUNTERS_DB').hget_all('PORT_PHY_ATTR:{}'.format(port_oid))
        except SonicDbKeyNotFound:
            logging.info("Skipping {}: PORT_PHY_ATTR data is not available".format(intf_name))
            continue

        missing_fields = REQUIRED_PHY_COUNTER_FIELDS - set(counters_data)
        if missing_fields:
            logging.info("Skipping {}: missing PHY fields {}".format(
                intf_name, ', '.join(sorted(missing_fields))))
            continue

        eligible_ports.append({
            'oid': port_oid,
            'interface': intf_name,
            'lanes': get_port_lane_count_from_config(port_config),
            'asic': asic_index
        })

        if len(eligible_ports) == sample_size:
            break

    pytest_assert(eligible_ports, "No port exposes all required PHY attributes")

    if len(eligible_ports) < sample_size:
        logging.info("Only {} ports expose all required PHY attributes; sampling all of them".format(
            len(eligible_ports)))

    sample_ports = {}
    for port_info in eligible_ports:
        port_oid = port_info['oid']
        sample_ports[port_oid] = {
            'interface': port_info['interface'],
            'lanes': port_info['lanes'],
            'asic': port_info['asic']
        }
        logging.info("Sampled port: {} ({}) - {} lanes".format(
            port_oid, port_info['interface'], port_info['lanes']))

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


def read_port_latch_statuses(asic, port_oid):
    """
    Read both latch attributes from one COUNTERS_DB hash snapshot.

    Args:
        asic: ASIC object
        port_oid: Port OID

    Returns:
        tuple: Parsed RX-signal and FEC latch data
    """
    counters_key = 'PORT_PHY_ATTR:{}'.format(port_oid)
    counters_data = SonicDbCli(asic, 'COUNTERS_DB').hget_all(counters_key)

    pytest_assert('phy_rx_signal_detect' in counters_data,
                  "phy_rx_signal_detect not found for {}".format(port_oid))
    pytest_assert('pcs_fec_lane_alignment_lock' in counters_data,
                  "pcs_fec_lane_alignment_lock not found for {}".format(port_oid))

    return (json.loads(counters_data['phy_rx_signal_detect']),
            json.loads(counters_data['pcs_fec_lane_alignment_lock']))


def validate_latch_metadata(current_data, previous_data, attribute_name):
    """Validate one latch attribute's timestamp and count after a marker event."""
    current_ts = current_data['0'][1]
    current_counter = current_data['0'][2]
    previous_ts = previous_data['0'][1]
    previous_counter = previous_data['0'][2]

    pytest_assert(current_counter == previous_counter + 1,
                  "{} counter should increment by 1: {} -> {}".format(
                      attribute_name, previous_counter, current_counter))
    pytest_assert(current_ts != previous_ts,
                  "{} timestamp should change: {} -> {}".format(
                      attribute_name, previous_ts, current_ts))


def poll_for_latch_statuses(asic, port_oid, expected_status, prev_signal_data=None, prev_fec_data=None,
                            max_attempts=LATCH_STATUS_MAX_ATTEMPTS):
    """
    Independently validate expected latch states for RX signal and FEC.

    RX signal detect and FEC lane-alignment lock are separate SAI attributes.
    syncd can update them in different PHY/flex-counter polling cycles for the
    same link event, even though they are read from the same COUNTERS_DB hash.
    Therefore, record and validate each attribute when it reaches the expected
    state; requiring both to match in one DB read creates a false failure when
    the first attribute's clear-on-read marker is consumed before the second
    attribute is sampled.
    """
    signal_match = None
    fec_match = None

    for attempt in range(max_attempts):
        time.sleep(LATCH_STATUS_POLL_INTERVAL_SEC)
        signal_data, fec_data = read_port_latch_statuses(asic, port_oid)

        signal_status = signal_data['0'][0]
        fec_status = fec_data['0'][0]

        logging.info(
            "Latch poll: attempt=%s oid=%s expected=%s "
            "signal=%s fec=%s",
            attempt + 1, port_oid, expected_status,
            signal_status, fec_status)

        if signal_match is None and signal_status == expected_status:
            logging.info("RX signal=%s detected after %s seconds",
                         expected_status, attempt + 1)
            if prev_signal_data:
                validate_latch_metadata(signal_data, prev_signal_data, 'Signal')
            signal_match = signal_data

        if fec_match is None and fec_status == expected_status:
            logging.info("FEC=%s detected after %s seconds",
                         expected_status, attempt + 1)
            if prev_fec_data:
                validate_latch_metadata(fec_data, prev_fec_data, 'FEC')
            fec_match = fec_data

        if signal_match is not None and fec_match is not None:
            return signal_match, fec_match

    missing = []
    if signal_match is None:
        missing.append('RX signal')
    if fec_match is None:
        missing.append('FEC')
    pytest.fail("{} not detected for {} within {} seconds".format(
        expected_status, ' and '.join(missing), max_attempts))


def get_test_port_info(duthost, fanouthosts):
    """
    Select a fanout-connected port with healthy latch status.

    A link flap is meaningful only when both latch attributes start in their
    stable, healthy state.  Scan fanout-connected ports and select one for
    which every reported lane is ``T`` for both RX signal detect and FEC
    lane-alignment lock.  This also avoids selecting ports that do not expose
    the required PHY attributes.

    Args:
        duthost: DUT host object
        fanouthosts: Fanout hosts fixture

    Returns:
        dict: Port information including interface, oid, lanes, asic, fanout, fanout_port
    """
    candidates = build_test_candidates(duthost, fanouthosts, 'all_ports')
    pytest_assert(len(candidates) > 0, "No ports with fanout connectivity found")

    port_configs = get_port_config_from_config_db(duthost)
    port_oid_map = build_port_oid_map(duthost)
    port_oid_to_asic = build_port_oid_asic_map(duthost)

    for test_interface, fanout, fanout_port in candidates:
        test_port_oid = port_oid_map.get(test_interface)
        port_config = port_configs.get(test_interface)
        if test_port_oid is None or port_config is None:
            logging.info("Skipping %s: missing port configuration or OID mapping", test_interface)
            continue

        asic_index = port_oid_to_asic.get(test_port_oid)
        if asic_index is None:
            logging.info("Skipping %s: no owning ASIC for %s", test_interface, test_port_oid)
            continue

        test_asic = duthost.asics[asic_index]
        try:
            counters_data = SonicDbCli(
                test_asic, 'COUNTERS_DB').hget_all('PORT_PHY_ATTR:{}'.format(test_port_oid))
        except SonicDbKeyNotFound:
            logging.info("Skipping %s: PORT_PHY_ATTR data is not available", test_interface)
            continue

        try:
            signal_data = json.loads(counters_data['phy_rx_signal_detect'])
            fec_data = json.loads(counters_data['pcs_fec_lane_alignment_lock'])
            signal_healthy = (
                isinstance(signal_data, dict) and signal_data and
                all(value[0] == 'T' for value in signal_data.values()))
            fec_healthy = (
                isinstance(fec_data, dict) and fec_data and
                all(value[0] == 'T' for value in fec_data.values()))
        except (KeyError, IndexError, TypeError, json.JSONDecodeError):
            logging.info("Skipping %s: required latch data is missing or malformed", test_interface)
            continue

        if not signal_healthy or not fec_healthy:
            logging.info("Skipping %s: latch status is not healthy (signal=%s, fec=%s)",
                         test_interface, signal_data, fec_data)
            continue

        logging.info("Selected healthy latch-test port %s (%s)", test_interface, test_port_oid)
        return {
            'interface': test_interface,
            'oid': test_port_oid,
            'lanes': get_port_lane_count_from_config(port_config),
            'asic': test_asic,
            'fanout': fanout,
            'fanout_port': fanout_port
        }

    pytest.skip("No fanout-connected port has stable T latch status for both PHY attributes")


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

                # Verify all lane numbers are present and values are float (dB)
                for lane in range(expected_lanes):
                    lane_key = str(lane)
                    pytest_assert(lane_key in rx_snr_data,
                                  "Lane {} missing in rx_snr for {} ({})".format(lane, port_oid, interface_name))
                    pytest_assert(isinstance(rx_snr_data[lane_key], float),
                                  "rx_snr lane {} value is not a float for {}".format(lane, port_oid))

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

    with allure.step("Waiting for data collection cycle"):
        time.sleep(15)

    sample_ports = get_sample_ports_with_lane_counts(duthost, sample_size=3)

    verify_attribute_list_in_flex_counter_db(duthost, sample_ports)

    verify_counters_db_data(duthost, sample_ports)


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

    with allure.step("Waiting for data collection after config reload"):
        time.sleep(15)

    sample_ports = get_sample_ports_with_lane_counts(duthost, sample_size=3)

    verify_counters_db_data(duthost, sample_ports)


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

    invalidate_port_caches()

    verify_phy_attr_in_cli(duthost, ENABLE)

    verify_phy_attr_in_flex_counter_db(duthost)

    with allure.step("Waiting for data collection after reboot"):
        time.sleep(15)

    sample_ports = get_sample_ports_with_lane_counts(duthost, sample_size=3)

    verify_counters_db_data(duthost, sample_ports)


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
        initial_signal = read_port_latch_status(
            port_info['asic'], port_info['oid'], 'phy_rx_signal_detect')
        initial_fec = read_port_latch_status(
            port_info['asic'], port_info['oid'], 'pcs_fec_lane_alignment_lock')

        initial_signal_status = initial_signal['0'][0]
        initial_signal_ts = initial_signal['0'][1]
        initial_signal_counter = initial_signal['0'][2]
        initial_fec_status = initial_fec['0'][0]
        initial_fec_ts = initial_fec['0'][1]
        initial_fec_counter = initial_fec['0'][2]

        logging.info("Initial signal: status={}, ts={}, counter={}".format(
            initial_signal_status, initial_signal_ts, initial_signal_counter))
        logging.info("Initial FEC: status={}, ts={}, counter={}".format(
            initial_fec_status, initial_fec_ts, initial_fec_counter))

    link_shutdown = False
    try:
        with allure.step("Shutting down link"):
            logging.info("Requesting shutdown of fanout port %s",
                         port_info['fanout_port'])
            fanout.shutdown(port_info['fanout_port'])
            link_shutdown = True
            logging.info("Shutdown request completed")

        with allure.step("Polling for F* after link down"):
            poll_for_latch_statuses(
                port_info['asic'], port_info['oid'], 'F*',
                prev_signal_data=initial_signal, prev_fec_data=initial_fec)

        # signal counter and timestamp are updated only when * is set.
        # Because these are clear-on-read counters
        # so prev_signal_data should be last signal data before any change(*) happened
        with allure.step("Polling for F (marker cleared)"):
            stable_signal, stable_fec = poll_for_latch_statuses(
                port_info['asic'], port_info['oid'], 'F',
                prev_signal_data=initial_signal, prev_fec_data=initial_fec)

        with allure.step("Bringing link up"):
            logging.info("Requesting no_shutdown of fanout port %s",
                         port_info['fanout_port'])
            fanout.no_shutdown(port_info['fanout_port'])
            link_shutdown = False
            logging.info("No_shutdown request completed")

        with allure.step("Polling for T* after link up"):
            poll_for_latch_statuses(
                port_info['asic'], port_info['oid'], 'T*',
                prev_signal_data=stable_signal, prev_fec_data=stable_fec)

        # signal counter and timestamp are updated only when * is set.
        # Because these are clear-on-read counters
        # so prev_signal_data should be last signal data before any change(*) happened
        with allure.step("Polling for T (marker cleared)"):
            poll_for_latch_statuses(
                port_info['asic'], port_info['oid'], 'T',
                prev_signal_data=stable_signal, prev_fec_data=stable_fec)
    finally:
        if link_shutdown:
            with allure.step("Restoring link after latch-status test failure"):
                logging.info("Restoring fanout port %s",
                             port_info['fanout_port'])
                fanout.no_shutdown(port_info['fanout_port'])
                link_recovered = wait_until(
                    60, 5, 0, duthost.is_interface_status_up, port_info['interface'])
                if not link_recovered:
                    logging.error(
                        "Interface %s did not return admin/oper up within 60 seconds "
                        "after restoring fanout port %s",
                        port_info['interface'], port_info['fanout_port'])
