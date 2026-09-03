import logging
import pytest

from .countersdb_helpers import countersdb_prefix, response_has_update
from tests.common.fixtures.grpc_fixtures import _gnmi_tls_lifecycle
from tests.common.helpers.assertions import pytest_assert
from tests.common.pygnmi_client import SubscribeMode


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]


@pytest.fixture(scope="module")
def gnmi_tls(duthosts, rand_one_dut_hostname, ptfhost,
             setup_gnmi_ntp_client_server, check_dut_timestamp):
    """Share one managed TLS lifecycle across the read-only COUNTERS_DB tests."""
    duthost = duthosts[rand_one_dut_hostname]
    yield from _gnmi_tls_lifecycle(duthost, ptfhost)


def _assert_responses_contain(result, text, expected):
    pytest_assert(len(result) == expected, (
        "Expected {} responses, got {}: {}"
    ).format(expected, len(result), result))
    pytest_assert(all(response_has_update(response, text) for response in result), (
        "Expected '{}' in every response: {}"
    ).format(text, result))


def test_gnmi_output(gnmi_tls):  # noqa: F811
    """
    Read COUNTERS table
    Get table key from COUNTERS_PORT_NAME_MAP
    """
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    logger.info('start gnmi output testing')
    # Get COUNTERS table key for Ethernet0
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}."
    ).format(counter_key)

    path = "COUNTERS/" + counter_key
    result = gnmi_tls.pygnmi_client.get(path, prefix=countersdb_prefix(duthost))
    logger.info("GNMI Server output")
    logger.info(result)
    pytest_assert(response_has_update(result, "SAI_PORT_STAT_IF_IN_ERRORS"), (
        "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi_output: {}."
    ).format(result))


test_data_counters_port_name_map = [
    {
        "name": "Subscribe table for COUNTERS_PORT_NAME_MAP",
        "port": "",
    },
    {
        "name": "Subscribe table field for COUNTERS_PORT_NAME_MAP",
        "port": "/Ethernet0"
    }
]


@pytest.mark.parametrize('test_data', test_data_counters_port_name_map)
def test_gnmi_counterdb_polling_01(gnmi_tls, test_data):  # noqa: F811
    '''
    Verify GNMI subscribe API
    Subscribe polling mode for COUNTERS_PORT_NAME_MAP
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    path = "COUNTERS_PORT_NAME_MAP{}".format(test_data['port'])
    result = list(gnmi_tls.pygnmi_client.subscribe(
        path, mode=SubscribeMode.POLL,
        poll_count=exp_cnt, poll_interval=1,
        prefix=countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "oid", exp_cnt)


def test_gnmi_counterdb_polling_02(gnmi_tls):  # noqa: F811
    '''
    Verify GNMI subscribe API
    Subscribe polling mode for COUNTERS
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    # Get COUNTERS table key for Ethernet0
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}. "
        "Expected 'oid' in counter key"
    ).format(counter_key)

    # Subscribe table
    counters_path = "COUNTERS/"
    result = list(gnmi_tls.pygnmi_client.subscribe(
        counters_path, mode=SubscribeMode.POLL,
        poll_count=exp_cnt, poll_interval=1,
        prefix=countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "SAI_PORT_STAT_IF_IN_ERRORS", exp_cnt)

    # Subscribe table key
    result = list(gnmi_tls.pygnmi_client.subscribe(
        counters_path + counter_key, mode=SubscribeMode.POLL,
        poll_count=exp_cnt, poll_interval=1,
        prefix=countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "SAI_PORT_STAT_IF_IN_ERRORS", exp_cnt)
    # Subscribe table field
    result = list(gnmi_tls.pygnmi_client.subscribe(
        counters_path + counter_key + "/SAI_PORT_STAT_IF_IN_ERRORS",
        mode=SubscribeMode.POLL, poll_count=exp_cnt, poll_interval=1,
        prefix=countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "SAI_PORT_STAT_IF_IN_ERRORS", exp_cnt)


@pytest.mark.parametrize('test_data', test_data_counters_port_name_map)
def test_gnmi_counterdb_streaming_sample_01(
        gnmi_tls, test_data):  # noqa: F811
    '''
    Verify GNMI subscribe API
    Subscribe streaming sample mode for COUNTERS_PORT_NAME_MAP
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    path = "COUNTERS_PORT_NAME_MAP{}".format(test_data['port'])
    result = list(gnmi_tls.pygnmi_client.subscribe(
        path, sample_interval=0,
        count=exp_cnt, collect_seconds=30,
        prefix=countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "oid", exp_cnt)


def test_gnmi_counterdb_streaming_sample_02(gnmi_tls):  # noqa: F811
    '''
    Verify GNMI subscribe API
    Subscribe streaming sample mode for COUNTERS
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    exp_cnt = 3
    # Get COUNTERS table key for Ethernet0
    asic = duthost.get_port_asic_instance("Ethernet0")
    result = asic.run_sonic_db_cli_cmd("COUNTERS_DB hget COUNTERS_PORT_NAME_MAP Ethernet0")
    counter_key = result['stdout'].strip()
    assert "oid" in counter_key, (
        "Invalid oid: {}. "
        "Expected 'oid' in counter key"
    ).format(counter_key)

    # Subscribe table field
    path = "COUNTERS/" + counter_key + "/SAI_PORT_STAT_IF_IN_ERRORS"
    result = list(gnmi_tls.pygnmi_client.subscribe(
        path, sample_interval=0, count=exp_cnt, collect_seconds=30,
        prefix=countersdb_prefix(duthost),
    ))
    _assert_responses_contain(result, "SAI_PORT_STAT_IF_IN_ERRORS", exp_cnt)
