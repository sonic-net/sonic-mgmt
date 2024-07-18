import json
import logging
import pytest

from collections import defaultdict

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.generic_config_updater.gu_utils import is_valid_platform_and_version

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

READ_FLEXDB_TIMEOUT = 20
READ_FLEXDB_INTERVAL = 5


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, loganalyzer):
    if not loganalyzer:
        return

    for duthost in duthosts:
        asic_name = duthost.get_asic_name()
        if asic_name in ['td2']:
            loganalyzer[duthost.hostname].ignore_regex.extend(
                [
                    '.*ERR syncd#syncd:.*SAI_API_QUEUE:_brcm_sai_cosq_stat_get:.* ',
                    '.*ERR syncd#syncd:.*SAI_API_SWITCH:sai_bulk_object_get_stats.* ',
                ]
            )
        if duthost.facts["asic_type"] == "vs":
            loganalyzer[duthost.hostname].ignore_regex.extend(
                [
                    '.*ERR syncd#syncd: :- queryStatsCapability: failed to find switch oid:.* in switch state map'
                ]
            )

    return


@pytest.fixture(scope="module", autouse=True)
def set_default_pfcwd_config(duthost):
    """
    Enable pfcwd config before all test runs and disable at the end of all test runs

    Args:
        duthost: DUT host object
    """
    res = duthost.shell('sonic-db-dump -n CONFIG_DB -y -k \"DEVICE_METADATA|localhost\"')
    meta_data = json.loads(res["stdout"])
    pfc_status = meta_data["DEVICE_METADATA|localhost"]["value"].get("default_pfcwd_status", "")
    if pfc_status == 'disable':
        duthost.shell('sonic-db-cli CONFIG_DB hset \"DEVICE_METADATA|localhost\" default_pfcwd_status enable')

    yield

    # Restore default config
    duthost.shell('config pfcwd stop')
    if pfc_status == 'disable':
        duthost.shell('sonic-db-cli CONFIG_DB hset \"DEVICE_METADATA|localhost\" default_pfcwd_status disable')
    else:
        start_pfcwd = duthost.shell('config pfcwd start_default')
        pytest_assert(not start_pfcwd['rc'], "Failed to start default pfcwd config")


@pytest.fixture
def ensure_dut_readiness(duthost):
    """
    Verify dut health/create and rollback checkpoint

    Args:
        duthost: DUT host object
    """
    verify_orchagent_running_or_assert(duthost)
    create_checkpoint(duthost)

    yield

    try:
        verify_orchagent_running_or_assert(duthost)
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture
def stop_pfcwd(duthost):
    """
    Stop pfcwd on all ports on the dut

    Args:
        duthost: DUT host object
    """
    duthost.shell('config pfcwd stop')
    yield


@pytest.fixture
def start_pfcwd(duthost):
    """
    Start pfcwd on all ports on the dut

    Args:
        duthost: DUT host object
    """
    duthost.shell('config pfcwd start_default')
    yield


@pytest.fixture
def extract_pfcwd_config(duthost, start_pfcwd):
    """
    Extract pfcwd info from running config

    Args:
        duthost: DUT host object

    Yields:
        pfcwd_config: dict of dicts with interface as the 1st level key and 'action', 'detect_time',
                      'restore_time' as the 2nd level keys
    """
    output = duthost.command('show pfcwd config')
    pytest_assert('Ethernet' in output['stdout'], 'No ports found in the pfcwd config')

    pfcwd_config = defaultdict()
    for line in output['stdout_lines']:
        if line.strip().startswith('Ethernet'):
            port, action, detect, restore = line.split()
            pfcwd_config.update({port: {'action': action,
                                        'detect_time': detect,
                                        'restore_time': restore}})

    yield pfcwd_config


def get_flex_db_count(duthost):
    """
    Get the count of the number of pfcwd entries seen in flex db
    For every port, there will be 3 entries - 1 for the port, 1 for queue 3 and 1 for queue 4
    Args:
        duthost: DUT host object

    Returns:
        Number of PFCWD related flex db entries
    """
    db_entries = duthost.shell('sonic-db-cli FLEX_COUNTER_DB keys *FLEX_COUNTER_TABLE:PFC_WD*')["stdout"]
    if db_entries == '':
        return 0
    else:
        return len(db_entries.split('\n'))


def check_config_update(duthost, expected_count):
    """
    Ensures application of the JSON patch config update

    Args:
        duthost: DUT host object
        expected_count: number of pfcwd entries expected in the updated config
    """
    def _confirm_value_in_flex_db(duthost, expected_count):
        pfcwd_entries_count = get_flex_db_count(duthost)
        logger.info("Actual number of entries: {}".format(pfcwd_entries_count))
        return pfcwd_entries_count == expected_count

    logger.info("Validating in FLEX COUNTER DB...")
    pytest_assert(
        wait_until(READ_FLEXDB_TIMEOUT, READ_FLEXDB_INTERVAL, 0, _confirm_value_in_flex_db, duthost, expected_count),
        "FLEX DB does not properly reflect Pfcwd status: Expected number of entries {}"
        .format(expected_count)
    )


@pytest.mark.parametrize('port', ['single', 'all'])
def test_stop_pfcwd(duthost, extract_pfcwd_config, ensure_dut_readiness, port):
    """
    Tests GCU config for pfcwd stop scenario
        1. Covers the case for stopping pfcwd on single port and all ports
        2. Verifies that the config is as expected in CONFIG DB
        3. Validates the number of PFC_WD related entries in FLEX DB is as expected
        4. Validates that orchagent is running fine pre and post test
    """
    pfcwd_config = extract_pfcwd_config

    if port == 'single':
        expected_count = get_flex_db_count(duthost) - 3
    else:
        expected_count = 0
    json_patch = list()
    exp_str = 'Ethernet'
    for interface in pfcwd_config:
        json_patch.extend([
                            {
                              'op': 'remove',
                              'path': '/PFC_WD/{}'.format(interface)
                            }])
        if port == 'single':
            exp_str = interface
            break

    try:
        tmpfile = generate_tmpfile(duthost)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        pfcwd_updated_config = duthost.shell("show pfcwd config")
        pytest_assert(not pfcwd_updated_config['rc'], "Unable to read updated pfcwd config")
        pytest_assert(exp_str not in pfcwd_updated_config['stdout'].split(),
                      "pfcwd unexpectedly still running")
        check_config_update(duthost, expected_count)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize('port', ['single', 'all'])
def test_start_pfcwd(duthost, extract_pfcwd_config, ensure_dut_readiness, stop_pfcwd, port):
    """
    Tests GCU config for pfcwd start scenario
        1. Covers the case for starting pfcwd on single port and all ports
        2. Verifies that the config is as expected in CONFIG DB
        3. Validates the number of PFC_WD related entries in FLEX DB is as expected
        4. Validates that orchagent is running fine pre and post test
    """
    pfcwd_config = extract_pfcwd_config

    if port == 'single':
        expected_count = 3
    else:
        expected_count = len(pfcwd_config) * 3
    json_patch = list()
    exp_str = 'Ethernet'
    op = 'add'
    for interface, value in pfcwd_config.items():
        json_patch.extend([
                            {
                              'op': op,
                              'path': '/PFC_WD/{}'.format(interface),
                              'value': {'action': value['action'],
                                        'detection_time': value['detect_time'],
                                        'restoration_time': value['restore_time']}}])
        if port == 'single':
            exp_str = interface
            break

    try:
        tmpfile = generate_tmpfile(duthost)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid_platform_and_version(duthost, "PFC_WD", "PFCWD enable/disable", op):
            expect_op_success(duthost, output)
            pfcwd_updated_config = duthost.shell("show pfcwd config")
            pytest_assert(not pfcwd_updated_config['rc'], "Unable to read updated pfcwd config")
            pytest_assert(exp_str in pfcwd_updated_config['stdout'],
                          "pfcwd not started - unexpected")
            check_config_update(duthost, expected_count)
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)
