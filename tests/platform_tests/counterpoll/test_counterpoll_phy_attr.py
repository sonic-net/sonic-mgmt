import allure
import json
import logging
import math
import random
import time
import pytest

from tests.common.config_reload import config_reload
from tests.common.constants import CounterpollConstants
from tests.common.gu_utils import restore_backup_test_config, save_backup_test_config
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

# COUNTERS_DB fields expected on each sampled port.
REQUIRED_PHY_COUNTER_FIELDS = {
    'phy_rx_signal_detect',
    'pcs_fec_lane_alignment_lock',
    'rx_snr'
}

# Sample once per second; allow three configured collection cycles plus a
# one-second scheduling margin before declaring a transition missing.
LATCH_STATUS_POLL_INTERVAL_SEC = 1


@pytest.fixture(scope="module", autouse=True)
def restore_config_after_phy_attr_tests(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Back up host/per-ASIC config files and restore them after this module."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    file_postfix = 'before_counterpoll_phy_attr_tests'

    save_backup_test_config(duthost, file_postfix=file_postfix)
    try:
        yield
    finally:
        restore_backup_test_config(duthost, file_postfix=file_postfix, config_reload=False)
        config_reload(duthost, config_source='config_db', safe_reload=True)


def get_port_config_from_config_db(asic):
    """
    Get port configuration from the selected ASIC's running CONFIG_DB.

    Args:
        asic: ASIC object

    Returns:
        dict: Port configuration data
    """
    config_facts = asic.config_facts(source='running')['ansible_facts']
    port_config = config_facts.get('PORT', {})
    logging.info("Fetched %s ports from CONFIG_DB on asic%s", len(port_config), asic.asic_index)
    return port_config


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


def build_port_oid_map(asic):
    """
    Build the current interface-to-OID mapping within one ASIC namespace.

    Args:
        asic: ASIC object

    Returns:
        dict: Mapping of interface name to OID
    """
    try:
        port_oid_map = SonicDbCli(asic, 'COUNTERS_DB').hget_all('COUNTERS_PORT_NAME_MAP')
    except SonicDbKeyNotFound:
        logging.warning("COUNTERS_PORT_NAME_MAP not found on asic%s", asic.asic_index)
        return {}
    logging.info("Found %s port OID mappings on asic%s", len(port_oid_map), asic.asic_index)
    return port_oid_map


def verify_phy_attr_in_cli(duthost, expected_status):
    """
    Verify counterpoll show output for PHY counters on every ASIC.

    Args:
        duthost: DUT host object
        expected_status: Expected status ('enable' or 'disable')
    """
    with allure.step("Verifying 'counterpoll show' output for PHY counters"):
        for asic in duthost.asics:
            counterpoll_output = ConterpollHelper.get_counterpoll_show_output(asic)
            pytest_assert(counterpoll_output,
                          "counterpoll show returns no output on asic{}".format(asic.asic_index))

            for entry in counterpoll_output:
                if PORT_PHY_ATTR_TYPE == entry.get(CounterpollConstants.TYPE, ''):
                    actual_status = entry[CounterpollConstants.STATUS]
                    pytest_assert(expected_status == actual_status,
                                  "PHY counter status on asic{} is '{}', expected '{}'".format(
                                      asic.asic_index, actual_status, expected_status))
                    logging.info("PHY counter status verified on asic%s: %s", asic.asic_index, actual_status)
                    break
            else:
                pytest.fail("PHY counters not found in counterpoll show output on asic{}".format(asic.asic_index))


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
    Wait for the enabled PHY group and requested interval in FLEX_COUNTER_DB.

    Args:
        duthost: DUT host object
        expected_interval: Expected poll interval in ms (optional)
    """
    expected_fields = {'FLEX_COUNTER_STATUS': ENABLE}
    if expected_interval is not None:
        expected_fields['POLL_INTERVAL'] = str(expected_interval)

    def group_matches(asic):
        try:
            group_data = SonicDbCli(asic, 'FLEX_COUNTER_DB').hget_all(FLEX_COUNTER_GROUP_TABLE)
        except SonicDbKeyNotFound:
            logging.debug("PHY group not available yet on asic%s", asic.asic_index)
            return False
        logging.debug("PHY group on asic%s: actual=%s expected=%s",
                      asic.asic_index, group_data, expected_fields)
        return all(group_data.get(field) == value for field, value in expected_fields.items())

    with allure.step("Verifying FLEX_COUNTER_DB PORT_PHY_ATTR tables"):
        for asic in duthost.asics:
            pytest_assert(
                wait_until(60, 2, 0, group_matches, asic),
                "PHY group did not reach {} in FLEX_COUNTER_DB on asic{} within 60 seconds".format(
                    expected_fields, asic.asic_index))
            logging.info("FLEX_COUNTER_DB group table verified on asic%s", asic.asic_index)


def check_phy_counters_populated(sample_ports):
    """Check that every sampled port has all required PHY fields."""
    if not sample_ports:
        return False
    for port_info in sample_ports:
        asic = port_info['asic']
        try:
            data = SonicDbCli(asic, 'COUNTERS_DB').hget_all('PORT_PHY_ATTR:{}'.format(port_info['oid']))
        except SonicDbKeyNotFound:
            logging.debug("PHY data is not available yet on asic%s port %s", asic.asic_index, port_info['interface'])
            return False
        missing_fields = REQUIRED_PHY_COUNTER_FIELDS - data.keys()
        if missing_fields:
            logging.debug("PHY fields are missing on asic%s port %s: %s",
                          asic.asic_index, port_info['interface'], sorted(missing_fields))
            return False
    return True


def get_sample_ports_with_lane_counts(duthost, sample_size=3):
    """
    Sample ports registered for all required PHY attributes across frontend ASICs.

    Args:
        duthost: DUT host object
        sample_size: Maximum number of ports to sample in total

    Returns:
        list: Port records containing OID, interface, lane count and owning ASIC
    """
    port_candidates = []
    frontend_asics = duthost.frontend_asics if duthost.is_multi_asic else duthost.asics
    pytest_assert(frontend_asics, "No frontend ASICs available for PHY validation")
    for asic in frontend_asics:
        port_configs = get_port_config_from_config_db(asic)
        port_oid_map = build_port_oid_map(asic)
        for intf_name, port_config in port_configs.items():
            if port_config.get('role', '').lower() in ['rec', 'inb']:
                continue
            port_oid = port_oid_map.get(intf_name)
            if port_oid is None:
                continue
            port_candidates.append({
                'oid': port_oid,
                'interface': intf_name,
                'lanes': get_port_lane_count_from_config(port_config),
                'asic': asic
            })
    random.shuffle(port_candidates)
    sample_ports = []
    for port_info in port_candidates:
        asic = port_info['asic']
        port_oid = port_info['oid']
        intf_name = port_info['interface']
        try:
            registration = SonicDbCli(asic, 'FLEX_COUNTER_DB').hget_all(
                'FLEX_COUNTER_TABLE:PORT_PHY_ATTR:{}'.format(port_oid))
        except SonicDbKeyNotFound:
            logging.info("Skipping asic%s port %s: no PHY attribute registration", asic.asic_index, intf_name)
            continue
        registered_attrs = {attr.strip() for attr in registration.get('PORT_PHY_ATTR_ID_LIST', '').split(',')}
        missing_attrs = set(PORT_PHY_ATTRIBUTES) - registered_attrs
        if missing_attrs:
            logging.info("Skipping asic%s port %s: PHY attributes are not registered: %s",
                         asic.asic_index, intf_name, sorted(missing_attrs))
            continue
        sample_ports.append(port_info)
        logging.info("Sampled asic%s port %s (%s)", asic.asic_index, intf_name, port_oid)
        if len(sample_ports) == sample_size:
            break
    pytest_assert(sample_ports, "No physical port is registered for all required PHY attributes")
    return sample_ports


def verify_attribute_list_in_flex_counter_db(sample_ports):
    """
    Verify PORT_PHY_ATTR_ID_LIST contains all 3 PORT attributes

    Args:
        sample_ports: List of sampled ports with their owning ASIC and metadata
    """
    with allure.step("Verifying PORT_PHY_ATTR_ID_LIST in FLEX_COUNTER_DB"):
        for port_info in sample_ports:
            port_oid = port_info['oid']
            asic = port_info['asic']
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
                  "{} lane {} has invalid timestamp '{}', expected non-negative integer for {}".format(
                      attribute_name, lane, timestamp, port_oid))
    pytest_assert(isinstance(counter, int) and counter >= 0,
                  "{} lane {} has invalid counter '{}', expected non-negative integer for {}".format(
                      attribute_name, lane, counter, port_oid))

    if status.endswith('*'):
        pytest_assert(timestamp > 0,
                      "{} lane {} has status {} but no change timestamp for {}".format(
                          attribute_name, lane, status, port_oid))
        pytest_assert(counter > 0,
                      "{} lane {} has status {} but no change count for {}".format(
                          attribute_name, lane, status, port_oid))

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
    """Validate metadata on a transition and after its marker clears."""
    for lane, value in current_data.items():
        # FEC can expose additional logical lanes when the link comes up.
        # Starred values are checked by validate_latch_status_value even if
        # this lane has no baseline for a relative metadata comparison.
        if lane not in previous_data:
            logging.info("%s lane %s has no previous sample for metadata comparison", attribute_name, lane)
            continue
        status, current_ts, current_counter = value
        previous_ts, previous_counter = previous_data[lane][1:]

        if status.endswith('*'):
            # Expect one changed collection for each requested link transition.
            pytest_assert(current_counter == previous_counter + 1,
                          "{} lane {} counter should increment by 1: {} -> {}".format(
                              attribute_name, lane, previous_counter, current_counter))
            pytest_assert(current_ts != previous_ts,
                          "{} lane {} timestamp should change: {} -> {}".format(
                              attribute_name, lane, previous_ts, current_ts))
        else:
            pytest_assert(current_counter == previous_counter,
                          "{} lane {} counter changed while clearing the marker: {} -> {}".format(
                              attribute_name, lane, previous_counter, current_counter))
            pytest_assert(current_ts == previous_ts,
                          "{} lane {} timestamp changed while clearing the marker: {} -> {}".format(
                              attribute_name, lane, previous_ts, current_ts))


def poll_for_latch_statuses(asic, port_oid, expected_status, max_attempts,
                            prev_signal_data=None, prev_fec_data=None):
    """
    Independently validate expected latch states for every RX signal and FEC lane.

    RX signal detect and FEC lane-alignment lock are separate SAI attributes.
    syncd can update them in different PHY/flex-counter polling cycles for the
    same link event, even though they are read from the same COUNTERS_DB hash.
    Therefore, record and validate each lane when it reaches the expected
    state; requiring both to match in one DB read creates a false failure when
    the first attribute's clear-on-read marker is consumed before the second
    attribute is sampled.
    """
    signal_matches = {}
    fec_matches = {}
    missing = []

    for attempt in range(max_attempts):
        time.sleep(LATCH_STATUS_POLL_INTERVAL_SEC)
        signal_data, fec_data = read_port_latch_statuses(asic, port_oid)

        missing = []
        for attribute, data, previous_data, matches in (
                ('RX signal', signal_data, prev_signal_data, signal_matches),
                ('FEC', fec_data, prev_fec_data, fec_matches)):
            pytest_assert(isinstance(data, dict) and data,
                          "{} has no lane data for {}".format(attribute, port_oid))
            if attribute == 'RX signal' and previous_data:
                pytest_assert(data.keys() == previous_data.keys(),
                              "RX signal lane set changed for {}".format(port_oid))
            for lane, value in data.items():
                status, _, _ = validate_latch_status_value(value, lane, port_oid, attribute)
                if lane not in matches and status == expected_status:
                    if previous_data:
                        validate_latch_metadata({lane: value}, previous_data, attribute)
                    matches[lane] = value

            # FEC lane count can change with link state; require all lanes in
            # the current sample, retaining markers captured on earlier reads.
            missing_lanes = sorted(data.keys() - matches.keys())
            logging.info("Latch poll: attempt=%s oid=%s expected=%s attribute=%s missing_lanes=%s",
                         attempt + 1, port_oid, expected_status, attribute, missing_lanes)
            if missing_lanes:
                missing.append('{} lanes {}'.format(attribute, ', '.join(missing_lanes)))

        if not missing:
            return ({lane: signal_matches[lane] for lane in signal_data},
                    {lane: fec_matches[lane] for lane in fec_data})

    pytest.fail("{} not detected for {} after {} polling attempts".format(
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

    frontend_asics = duthost.frontend_asics if duthost.is_multi_asic else duthost.asics
    for test_asic in frontend_asics:
        port_configs = get_port_config_from_config_db(test_asic)
        port_oid_map = build_port_oid_map(test_asic)

        for test_interface, fanout, fanout_port in candidates:
            test_port_oid = port_oid_map.get(test_interface)
            port_config = port_configs.get(test_interface)
            if test_port_oid is None or port_config is None:
                logging.info("Skipping %s: missing port configuration or OID mapping", test_interface)
                continue

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


def verify_counters_db_data(sample_ports):
    """
    Verify COUNTERS_DB PORT_PHY_ATTR table has all 3 attributes with correct lane counts

    Args:
        sample_ports: List of sampled ports with their owning ASIC and metadata
    """
    with allure.step("Verifying COUNTERS_DB PORT_PHY_ATTR table data"):
        for port_info in sample_ports:
            port_oid = port_info['oid']
            expected_lanes = port_info['lanes']
            interface_name = port_info['interface']
            asic = port_info['asic']

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
                valid_fec_multipliers = (1, 2, 4)
                pytest_assert(fec_count % expected_lanes == 0
                              and fec_count // expected_lanes in valid_fec_multipliers,
                              "pcs_fec_lane_alignment_lock has {} entries, expected {} lanes x {} for {} ({})".format(
                                  fec_count, expected_lanes, valid_fec_multipliers, port_oid, interface_name))

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

def test_phy_enable_and_validate(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
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

    with allure.step("Waiting for data collection cycle"):
        timeout = 180 if duthost.is_multi_asic else 120
        pytest_assert(
            wait_until(timeout, 5, 0, check_phy_counters_populated, sample_ports),
            "Required PHY fields did not populate on the sampled ports within {} seconds".format(timeout))

    verify_attribute_list_in_flex_counter_db(sample_ports)

    verify_counters_db_data(sample_ports)


def test_phy_interval_change(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Test 2: Validate interval modification propagates to all DBs

    Steps:
    1. Enable PHY counters and change interval to 5000ms
    2. Verify CLI, CONFIG_DB, FLEX_COUNTER_DB
    3. Change interval to 10000ms
    4. Verify new interval in all locations
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Enabling PHY counters"):
        for asic in duthost.asics:
            ConterpollHelper.enable_counterpoll(asic, [PORT_PHY_ATTR])

    with allure.step("Changing interval to 5000ms"):
        for asic in duthost.asics:
            ConterpollHelper.set_counterpoll_interval(asic, PORT_PHY_ATTR, 5000)

    verify_phy_attr_in_cli(duthost, ENABLE)
    verify_phy_attr_in_config_db(duthost, ENABLE, expected_interval=5000)
    verify_phy_attr_in_flex_counter_db(duthost, expected_interval=5000)

    with allure.step("Changing interval to 10000ms"):
        for asic in duthost.asics:
            ConterpollHelper.set_counterpoll_interval(asic, PORT_PHY_ATTR, 10000)

    verify_phy_attr_in_cli(duthost, ENABLE)
    verify_phy_attr_in_config_db(duthost, ENABLE, expected_interval=10000)
    verify_phy_attr_in_flex_counter_db(duthost, expected_interval=10000)


def test_phy_config_reload_persistence(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Test 3: Verify PHY counters persist after config save + disable + reload

    Steps:
    1. Enable PHY counters and save config
    2. Disable PHY counters
    3. Config reload
    4. Verify PHY counters restored to enabled
    5. Verify COUNTERS_DB has fresh data
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Enabling PHY counters"):
        for asic in duthost.asics:
            ConterpollHelper.enable_counterpoll(asic, [PORT_PHY_ATTR])

    with allure.step("Saving config"):
        duthost.command('config save -y')

    with allure.step("Disabling PHY counters"):
        for asic in duthost.asics:
            ConterpollHelper.disable_counterpoll(asic, [PORT_PHY_ATTR])

    verify_phy_attr_in_cli(duthost, DISABLE)

    with allure.step("Performing config reload"):
        config_reload(duthost, config_source='config_db', safe_reload=True)

    verify_phy_attr_in_cli(duthost, ENABLE)

    verify_phy_attr_in_flex_counter_db(duthost)

    sample_ports = get_sample_ports_with_lane_counts(duthost, sample_size=3)

    with allure.step("Waiting for data collection after config reload"):
        timeout = 180 if duthost.is_multi_asic else 120
        pytest_assert(
            wait_until(timeout, 5, 0, check_phy_counters_populated, sample_ports),
            "Required PHY fields did not populate after config reload within {} seconds".format(timeout))

    verify_counters_db_data(sample_ports)


def test_phy_reboot_persistence(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost):
    """
    Test 4: Verify PHY counters persist after disable + reboot

    Steps:
    1. Enable PHY counters and save config
    2. Disable PHY counters
    3. Reboot
    4. Verify PHY counters restored to enabled
    5. Verify COUNTERS_DB has fresh data
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    with allure.step("Enabling PHY counters and saving config"):
        for asic in duthost.asics:
            ConterpollHelper.enable_counterpoll(asic, [PORT_PHY_ATTR])
        duthost.command('config save -y')

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
        timeout = 180 if duthost.is_multi_asic else 120
        pytest_assert(
            wait_until(timeout, 5, 0, check_phy_counters_populated, sample_ports),
            "Required PHY fields did not populate after reboot within {} seconds".format(timeout))

    verify_counters_db_data(sample_ports)


# RX signal-detect can intermittently miss the F* latch indication.
# Tracking issue: https://github.com/sonic-net/sonic-buildimage/issues/30445
def test_phy_latch_status_transition(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                     fanouthosts):
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

    frontend_asics = duthost.frontend_asics if duthost.is_multi_asic else duthost.asics
    pytest_assert(frontend_asics, "No frontend ASICs available for PHY validation")
    poll_intervals_ms = {}
    for asic in frontend_asics:
        config_data = SonicDbCli(asic, 'CONFIG_DB').hget_all(CONFIG_DB_TABLE)
        poll_intervals_ms[asic.asic_index] = int(config_data.get('POLL_INTERVAL', 10000))

    with allure.step("Waiting for initial data collection"):
        time.sleep(max(poll_intervals_ms.values()) / 1000.0 + 1)

    port_info = get_test_port_info(duthost, fanouthosts)
    fanout = port_info['fanout']
    poll_interval_ms = poll_intervals_ms[port_info['asic'].asic_index]
    max_attempts = math.ceil((3 * poll_interval_ms / 1000.0 + 1) / LATCH_STATUS_POLL_INTERVAL_SEC)

    logging.info("Testing latch status transitions on {} ({})".format(
        port_info['interface'], port_info['oid']))

    with allure.step("Reading initial latch status"):
        initial_signal = read_port_latch_status(
            port_info['asic'], port_info['oid'], 'phy_rx_signal_detect')
        initial_fec = read_port_latch_status(
            port_info['asic'], port_info['oid'], 'pcs_fec_lane_alignment_lock')

        logging.info("Initial RX signal lanes: %s", initial_signal)
        logging.info("Initial FEC lanes: %s", initial_fec)

    restore_link = False
    try:
        with allure.step("Shutting down link"):
            logging.info("Requesting shutdown of fanout port %s",
                         port_info['fanout_port'])
            restore_link = True
            fanout.shutdown(port_info['fanout_port'])
            logging.info("Shutdown request completed")

        with allure.step("Polling for F* after link down"):
            down_signal, down_fec = poll_for_latch_statuses(
                port_info['asic'], port_info['oid'], 'F*',
                max_attempts=max_attempts, prev_signal_data=initial_signal, prev_fec_data=initial_fec)

        # Clearing the marker must preserve the captured transition metadata.
        with allure.step("Polling for F (marker cleared)"):
            stable_signal, stable_fec = poll_for_latch_statuses(
                port_info['asic'], port_info['oid'], 'F',
                max_attempts=max_attempts, prev_signal_data=down_signal, prev_fec_data=down_fec)

        with allure.step("Bringing link up"):
            logging.info("Requesting no_shutdown of fanout port %s",
                         port_info['fanout_port'])
            fanout.no_shutdown(port_info['fanout_port'])
            restore_link = False
            logging.info("No_shutdown request completed")

        with allure.step("Polling for T* after link up"):
            up_signal, up_fec = poll_for_latch_statuses(
                port_info['asic'], port_info['oid'], 'T*',
                max_attempts=max_attempts, prev_signal_data=stable_signal, prev_fec_data=stable_fec)

        # Clearing the marker must preserve the captured transition metadata.
        with allure.step("Polling for T (marker cleared)"):
            poll_for_latch_statuses(
                port_info['asic'], port_info['oid'], 'T',
                max_attempts=max_attempts, prev_signal_data=up_signal, prev_fec_data=up_fec)
    finally:
        if restore_link:
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
