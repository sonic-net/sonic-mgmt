import json
import logging
import pytest

from collections import defaultdict

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import is_valid_platform_and_version

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

READ_FLEXDB_TIMEOUT = 20
READ_FLEXDB_INTERVAL = 5
FLEXDB_COUNTERS_PER_PORT = 3


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
        cmd = 'sonic-db-cli CONFIG_DB hset \"DEVICE_METADATA|localhost\" default_pfcwd_status enable'
        for asic_id in duthost.get_asic_ids():
            if asic_id:
                duthost.asic_instance(asic_id).command(cmd)
            else:
                duthost.shell(cmd)

    yield

    # Restore default config
    duthost.shell('config pfcwd stop')
    if pfc_status == 'disable':
        cmd = 'sonic-db-cli CONFIG_DB hset \"DEVICE_METADATA|localhost\" default_pfcwd_status disable'
        for asic_id in duthost.get_asic_ids():
            if asic_id:
                duthost.asic_instance(asic_id).command(cmd)
            else:
                duthost.shell(cmd)
    else:
        start_pfcwd = duthost.shell('config pfcwd start_default')
        pytest_assert(not start_pfcwd['rc'], "Failed to start default pfcwd config")


@pytest.fixture
def ensure_dut_readiness(duthost, extract_pfcwd_config):
    """
    Verify dut health/create and rollback checkpoint

    Args:
        duthost: DUT host object
    """
    verify_orchagent_running_or_assert(duthost)
    create_checkpoint(duthost)

    pfcwd_config = extract_pfcwd_config
    number_of_ports = len(pfcwd_config)
    check_config_update(duthost, number_of_ports * FLEXDB_COUNTERS_PER_PORT)

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
    cmd = 'config pfcwd stop'
    for asic_id in duthost.get_asic_ids():
        if asic_id:
            duthost.asic_instance(asic_id).command(cmd)
        else:
            duthost.shell(cmd)
    yield


@pytest.fixture
def start_pfcwd(duthost):
    """
    Start pfcwd on all ports on the dut

    Args:
        duthost: DUT host object
    """
    cmd = 'config pfcwd start_default'
    for asic_id in duthost.get_asic_ids():
        if asic_id:
            duthost.asic_instance(asic_id).command(cmd)
        else:
            duthost.shell(cmd)
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
    # Add flag to show all internal interfaces (for multi-asic systems)
    cmd = 'show pfcwd config'
    if duthost.is_multi_asic:
        cmd += ' -d all'
    output = duthost.command(cmd)
    pytest_assert('Ethernet' in output['stdout'], 'No ports found in the pfcwd config')

    pfcwd_config = defaultdict()
    for line in output['stdout_lines']:
        if line.strip().startswith('Ethernet'):
            parts = line.split()
            port, action, detect, restore = parts[:4]
            pfcwd_config.update({port: {'action': action,
                                        'detect_time': detect,
                                        'restore_time': restore}})

    yield pfcwd_config


def get_flex_db_count(duthost, namespace=None):
    """
    Get the count of the number of pfcwd entries seen in flex db
    For every port, there will be 3 entries - 1 for the port, 1 for queue 3 and 1 for queue 4
    Args:
        duthost: DUT host object
        namespace: DUT asic namespace

    Returns:
        Number of PFCWD related flex db entries
    """
    ns_flag_prefix = '' if namespace is None else '-n ' + namespace
    cmd = 'sonic-db-cli {} FLEX_COUNTER_DB keys *FLEX_COUNTER_TABLE:PFC_WD*'.format(ns_flag_prefix)
    db_entries = duthost.shell(cmd)["stdout"]
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
    def _confirm_value_in_flex_db():
        if duthost.is_multi_asic:
            pfcwd_entries_count = 0
            num_asics = duthost.facts.get('num_asic', 0)
            for asic_index in range(num_asics):
                asic_ns = "asic{}".format(asic_index)
                pfcwd_entries_count += get_flex_db_count(duthost, asic_ns)
        else:
            pfcwd_entries_count = get_flex_db_count(duthost)
        return pfcwd_entries_count == expected_count

    logger.info("Validating in FLEX COUNTER DB...")
    pytest_assert(
        wait_until(
            READ_FLEXDB_TIMEOUT,
            READ_FLEXDB_INTERVAL,
            0,
            _confirm_value_in_flex_db
            ), "FLEX DB does not properly reflect Pfcwd status: Expected number of entries {}".format(expected_count))


@pytest.mark.parametrize('port', ['single', 'all'])
def test_stop_pfcwd(duthost, enum_rand_one_frontend_asic_index,
                    extract_pfcwd_config, ensure_dut_readiness, port):
    """
    Tests GCU config for pfcwd stop scenario
        1. Covers the case for stopping pfcwd on single port and all ports
        2. Verifies that the config is as expected in CONFIG DB
        3. Validates the number of PFC_WD related entries in FLEX DB is as expected
        4. Validates that orchagent is running fine pre and post test
    """
    pfcwd_config = extract_pfcwd_config
    initial_count = len(pfcwd_config) * FLEXDB_COUNTERS_PER_PORT

    if port == 'single':
        expected_count = initial_count - FLEXDB_COUNTERS_PER_PORT
    else:
        expected_count = 0
    json_patch = list()
    exp_str = 'Ethernet'
    for interface in pfcwd_config:
        asic_index = None
        json_namespace = ''
        if duthost.is_multi_asic:
            asic_index = duthost.get_port_asic_instance(interface).asic_index
            ns = duthost.get_namespace_from_asic_id(asic_index)
            json_namespace = '/' + ns
        json_patch.extend([
                            {
                              'op': 'remove',
                              'path': '{}/PFC_WD/{}'.format(json_namespace, interface)
                            }])
        if port == 'single':
            exp_str = interface
            break
    # Removing the JSON patch formatting because the above patch includes interfaces
    # that may belong to multiple ASICs, and the formatting has already been handled per interface.
    # json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch, is_asic_specific=True)
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
def test_start_pfcwd(duthost, enum_rand_one_frontend_asic_index,
                     extract_pfcwd_config, ensure_dut_readiness, stop_pfcwd, port):
    """
    Tests GCU config for pfcwd start scenario
        1. Covers the case for starting pfcwd on single port and all ports
        2. Verifies that the config is as expected in CONFIG DB
        3. Validates the number of PFC_WD related entries in FLEX DB is as expected
        4. Validates that orchagent is running fine pre and post test
    """
    pfcwd_config = extract_pfcwd_config

    if port == 'single':
        expected_count = FLEXDB_COUNTERS_PER_PORT
    else:
        expected_count = len(pfcwd_config) * FLEXDB_COUNTERS_PER_PORT
    json_patch = list()
    exp_str = 'Ethernet'
    op = 'add'
    for interface, value in pfcwd_config.items():
        asic_index = None
        json_namespace = ''
        if duthost.is_multi_asic:
            asic_index = duthost.get_port_asic_instance(interface).asic_index
            ns = duthost.get_namespace_from_asic_id(asic_index)
            json_namespace = '/' + ns
        json_patch.extend([
                            {
                              'op': op,
                              'path': '{}/PFC_WD/{}'.format(json_namespace, interface),
                              'value': {'action': value['action'],
                                        'detection_time': value['detect_time'],
                                        'restoration_time': value['restore_time']}}])
        if port == 'single':
            exp_str = interface
            break
    # Removing the JSON patch formatting because the above patch includes interfaces
    # that may belong to multiple ASICs, and the formatting has already been handled per interface.
    # json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch, is_asic_specific=True)
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
