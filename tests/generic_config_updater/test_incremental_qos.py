
import logging
import json
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.gu_utils import apply_patch, expect_op_success, \
    expect_op_failure         # noqa:F401
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import is_valid_platform_and_version
from tests.common.mellanox_data import is_mellanox_device

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox', 'barefoot', 'marvell-teralynx')
]

logger = logging.getLogger(__name__)

LOSSLESS_PGS = 2
LOSSY_PGS = 1
MGMT_POOL = 256
EGRESS_MIRRORING = 10
MIN_LOSSY_BUFFER_THRESHOLD = 19
EGRESS_POOL_THRESHOLD = 9
OPER_HEADROOM_SIZE = 19
INGRESS_POOL_THRESHOLD = 10
HEADROOM_POOL_OVERSUB = 2
MMU_SIZE = 13619
READ_ASICDB_TIMEOUT = 480
READ_ASICDB_INTERVAL = 20


@pytest.fixture(scope="module")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for incremental qos config update tst

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


def get_uplink_downlink_count(duthost, tbinfo):
    """
    Retrieves uplink and downlink count from DEVICE_NEIGHBOR_METADATA based on topology

    Args:
        duthost: DUT host object
        tbinfo: information about the running testbed

    Returns:
        uplink count, downlink count

    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    device_neighbor_metadata = config_facts['DEVICE_NEIGHBOR_METADATA']
    topo = tbinfo['topo']['name']

    if "t1" in topo:
        spine_router_count = 0
        tor_router_count = 0
        for neighbor in list(device_neighbor_metadata.keys()):
            neighbor_data = device_neighbor_metadata[neighbor]
            if neighbor_data['type'] == "SpineRouter":
                spine_router_count += 1
            elif neighbor_data['type'] == "ToRRouter":
                tor_router_count += 1
        return spine_router_count, tor_router_count

    elif "t0" in topo:
        leaf_router_count = 0
        server_count = 0
        for neighbor in list(device_neighbor_metadata.keys()):
            neighbor_data = device_neighbor_metadata[neighbor]
            if neighbor_data['type'] == "LeafRouter":
                leaf_router_count += 1
            elif neighbor_data['type'] == "Server":
                server_count += 1
        return leaf_router_count, server_count


def get_neighbor_type_to_pg_headroom_map(duthost):
    """
    Calculates pg headroom based on the present neighbor types

    Args:
        duthost: DUT host object

    Returns:
        A map of neighbor type to its corresponding pg headroom value
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    device_neighbor_metadata = config_facts['DEVICE_NEIGHBOR_METADATA']
    interfaces_data = config_facts['PORT']
    neighbor_set = set()
    neighbor_to_interface_map = {}
    neighbor_to_type_map = {}
    neighbor_type_to_pg_headroom_map = {}

    for neighbor in list(device_neighbor_metadata.keys()):
        neighbor_set.add(neighbor)
        neighbor_data = device_neighbor_metadata[neighbor]
        neighbor_to_type_map[neighbor] = neighbor_data['type']

    for interface in list(interfaces_data.keys()):
        for neighbor in neighbor_set:
            if neighbor in json.dumps(interfaces_data[interface]):
                neighbor_to_interface_map[neighbor] = interface
                break

    for neighbor in neighbor_set:
        interface = neighbor_to_interface_map[neighbor]

        cable_length = duthost.shell('sonic-db-cli CONFIG_DB hget "CABLE_LENGTH|AZURE" {}'
                                     .format(interface))['stdout']
        if cable_length == "0m":
            pytest.skip("skip the test due to no buffer lossless pg")

        port_speed = duthost.shell('sonic-db-cli CONFIG_DB hget "PORT|{}" speed'
                                   .format(interface))['stdout']

        expected_profile = 'pg_lossless_{}_{}_profile'.format(port_speed, cable_length)

        xoff = int(duthost.shell('sonic-db-cli APPL_DB hget "BUFFER_PROFILE_TABLE:{}" xoff'
                                 .format(expected_profile))['stdout'])
        xon = int(duthost.shell('sonic-db-cli APPL_DB hget "BUFFER_PROFILE_TABLE:{}" xon'
                                .format(expected_profile))['stdout'])
        pg_headroom = int((xoff + xon) / 1024)

        neighbor_type = neighbor_to_type_map[neighbor]
        neighbor_type_to_pg_headroom_map[neighbor_type] = pg_headroom

    return neighbor_type_to_pg_headroom_map


def calculate_field_value(duthost, tbinfo, field):
    """
    Calculates value of specified field

    Args:
        duthost: DUT host object
        tbinfo: information about the running testbed
        field: xoff, ingress_lossless_pool_size, or egress_lossy_pool_size

    """
    uplink, downlink = get_uplink_downlink_count(duthost, tbinfo)
    uplink_downlink_sum = uplink + downlink
    system_reserved = uplink_downlink_sum * EGRESS_MIRRORING + MGMT_POOL
    user_reserved = uplink_downlink_sum * LOSSY_PGS * MIN_LOSSY_BUFFER_THRESHOLD + \
        uplink_downlink_sum * EGRESS_POOL_THRESHOLD
    private_headroom = uplink_downlink_sum * LOSSLESS_PGS * OPER_HEADROOM_SIZE + \
        uplink_downlink_sum * INGRESS_POOL_THRESHOLD

    config_headroom_int_sum = 0
    neighbor_type_to_pg_headroom_map = get_neighbor_type_to_pg_headroom_map(duthost)
    for neighbor_type in neighbor_type_to_pg_headroom_map:
        if neighbor_type == "SpineRouter" or "LeafRouter":
            config_headroom_uplink_multiplier = neighbor_type_to_pg_headroom_map[neighbor_type]
            config_headroom_int_sum = uplink * config_headroom_uplink_multiplier + config_headroom_int_sum
        elif neighbor_type == "LeafRouter" or "Server":
            config_headroom_downlink_multiplier = neighbor_type_to_pg_headroom_map[neighbor_type]
            config_headroom_int_sum = downlink * config_headroom_downlink_multiplier + config_headroom_int_sum
    config_headroom = LOSSLESS_PGS * config_headroom_int_sum

    headroom_pool = int((config_headroom - private_headroom) / HEADROOM_POOL_OVERSUB)

    if ("xoff" in field):
        return headroom_pool
    else:
        operational_headroom = headroom_pool + private_headroom
        ingress_lossless_egress_lossy = MMU_SIZE - operational_headroom - user_reserved - system_reserved
        return ingress_lossless_egress_lossy


def ensure_application_of_updated_config(duthost, configdb_field, value):
    """
    Ensures application of the JSON patch config update

    Args:
        duthost: DUT host object
        configdb_field: config db field under test
        value: expected value of configdb_field
    """
    def _confirm_value_in_asic_db():
        if "ingress_lossless_pool" in configdb_field:
            buffer_pool = "ingress_lossless_pool"
        elif "egress_lossy_pool" in configdb_field:
            buffer_pool = "egress_lossy_pool"
        oid = duthost.shell('sonic-db-cli COUNTERS_DB HGET COUNTERS_BUFFER_POOL_NAME_MAP {}'
                            .format(buffer_pool))["stdout"]
        buffer_pool_data = duthost.shell('sonic-db-cli ASIC_DB hgetall ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:{}'
                                         .format(oid))["stdout"]
        return str(value) in buffer_pool_data

    pytest_assert(
        wait_until(READ_ASICDB_TIMEOUT, READ_ASICDB_INTERVAL, 0, _confirm_value_in_asic_db),
        "ASIC DB does not properly reflect newly configured field: {} expected value: {}"
        .format(configdb_field, value)
    )


@pytest.mark.parametrize("configdb_field", ["ingress_lossless_pool/xoff",
                                            "ingress_lossless_pool/size", "egress_lossy_pool/size"])
@pytest.mark.parametrize("op", ["add", "replace", "remove"])
def test_incremental_qos_config_updates(duthost, tbinfo, ensure_dut_readiness, configdb_field, op,
                                        skip_when_buffer_is_dynamic_model):
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of field: {} and operation: {}"
                .format(tmpfile, configdb_field, op))

    field_value = duthost.shell('sonic-db-cli CONFIG_DB hget "BUFFER_POOL|{}" {}'
                                .format(configdb_field.split("/")[0], configdb_field.split("/")[1]))['stdout']
    if op == "remove":
        if is_mellanox_device(duthost):
            pytest.skip("Skip remove test, because the mellanox device doesn't support removing qos config fields")
        value = ""
    else:
        value = calculate_field_value(duthost, tbinfo, configdb_field)
    logger.info("value to be added to json patch: {} operation: {} field: {}".format(value, op, configdb_field))

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/BUFFER_POOL/{}".format(configdb_field),
            "value": "{}".format(value)
        }]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch, is_asic_specific=True)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if op == "replace" and not field_value:
            logger.info("{} expects failure when configdb_field: {} does not have value.".format(op, configdb_field))
            expect_op_failure(output)
        else:
            if is_valid_platform_and_version(duthost,
                                             "BUFFER_POOL",
                                             "Shared/headroom pool size changes",
                                             op,
                                             field_value):
                expect_op_success(duthost, output)
                ensure_application_of_updated_config(duthost, configdb_field, value)
            else:
                expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_buffer_profile_add_remove_rollback(
        duthost, ensure_dut_readiness,
        enum_rand_one_frontend_asic_index,
        cli_namespace_prefix):
    """
    Test buffer profile removal via rollback using GCU

    Verifies fix for https://github.com/sonic-net/sonic-utilities/pull/4128
    which allows removing entire BUFFER_PROFILE objects during rollback

    Steps:
    1. Create checkpoint
    2. Shutdown an interface
    3. Change interface cable length and speed
    4. Startup the interface
    5. Check new buffer profile is generated
    6. Rollback (should succeed without errors)
    7. Check the new buffer profile is removed

    Args:
        duthost: DUT host object
        ensure_dut_readiness: Fixture for setup/teardown
        enum_rand_one_frontend_asic_index: Random frontend ASIC index
        cli_namespace_prefix: CLI namespace prefix for multi-asic
    """
    namespace = duthost.get_namespace_from_asic_id(
        enum_rand_one_frontend_asic_index)
    tmpfile = generate_tmpfile(duthost)

    # Get first available interface
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']
    ports = config_facts.get('PORT', {})
    if not ports:
        pytest.skip("No ports available for testing")

    test_interface = list(ports.keys())[0]
    original_speed = ports[test_interface].get('speed')
    original_cable_length = duthost.shell(
        'sonic-db-cli {} CONFIG_DB hget "CABLE_LENGTH|AZURE" {}'.format(
            cli_namespace_prefix, test_interface))['stdout']

    if not original_speed or not original_cable_length:
        pytest.skip("Interface {} missing speed or cable length".format(
            test_interface))

    # Determine new cable length (different from original)
    new_cable_length = '300m' if original_cable_length == '5m' else '5m'

    new_profile_name = 'pg_lossless_{}_{}_profile'.format(
        original_speed, new_cable_length)

    logger.info("Test interface: {}, speed: {}, "
                "original cable length: {}".format(
                    test_interface, original_speed, original_cable_length))
    logger.info("New cable length: {}, expected profile: {}".format(
        new_cable_length, new_profile_name))

    def check_profile_exists(profile_name, should_exist):
        """Check if profile exists in APPL_DB"""
        app_key = "BUFFER_PROFILE_TABLE:{}".format(profile_name)
        result = duthost.shell(
            'sonic-db-cli {} APPL_DB exists "{}"'.format(
                cli_namespace_prefix, app_key),
            module_ignore_errors=True)
        exists = int(result["stdout"]) == 1 if result["rc"] == 0 else False
        return exists == should_exist

    try:
        # Step 1: Create checkpoint
        checkpoint_name = "before_interface_change"
        duthost.shell("config checkpoint {}".format(checkpoint_name))
        logger.info("Step 1: Created checkpoint {}".format(checkpoint_name))

        # Step 2: Shutdown interface
        logger.info("Step 2: Shutting down interface {}".format(
            test_interface))
        json_patch = [{
            "op": "add",
            "path": "/PORT/{}/admin_status".format(test_interface),
            "value": "down"
        }]
        json_patch = format_json_patch_for_multiasic(
            duthost=duthost, json_data=json_patch,
            is_asic_specific=True, asic_namespaces=[namespace])
        output = apply_patch(duthost, json_data=json_patch,
                           dest_file=tmpfile)
        expect_op_success(duthost, output)

        # Step 3: Change cable length
        logger.info("Step 3: Changing interface cable length to {}".format(
            new_cable_length))
        json_patch = [{
            "op": "replace",
            "path": "/CABLE_LENGTH/AZURE/{}".format(test_interface),
            "value": new_cable_length
        }]
        json_patch = format_json_patch_for_multiasic(
            duthost=duthost, json_data=json_patch,
            is_asic_specific=True, asic_namespaces=[namespace])
        output = apply_patch(duthost, json_data=json_patch,
                           dest_file=tmpfile)
        expect_op_success(duthost, output)

        # Step 4: Startup interface
        logger.info("Step 4: Starting up interface {}".format(
            test_interface))
        json_patch = [{
            "op": "replace",
            "path": "/PORT/{}/admin_status".format(test_interface),
            "value": "up"
        }]
        json_patch = format_json_patch_for_multiasic(
            duthost=duthost, json_data=json_patch,
            is_asic_specific=True, asic_namespaces=[namespace])
        output = apply_patch(duthost, json_data=json_patch,
                           dest_file=tmpfile)
        expect_op_success(duthost, output)

        import time
        time.sleep(10)

        # Step 5: Check new buffer profile is generated
        logger.info("Step 5: Checking if profile {} exists".format(
            new_profile_name))
        pytest_assert(
            wait_until(30, 5, 0,
                      lambda: check_profile_exists(new_profile_name, True)),
            "New buffer profile {} was not generated".format(
                new_profile_name)
        )
        logger.info("New buffer profile {} successfully generated".format(
            new_profile_name))

        # Step 6: Rollback (this tests object-level remove support)
        logger.info("Step 6: Rolling back to checkpoint {}".format(
            checkpoint_name))
        rollback_output = duthost.shell(
            "config rollback {}".format(checkpoint_name))
        pytest_assert(
            rollback_output["rc"] == 0,
            "Rollback failed: {}".format(
                rollback_output.get("stderr", ""))
        )
        logger.info("Rollback completed without errors")

        time.sleep(10)

        # Step 7: Check buffer profile is removed
        logger.info("Step 7: Verifying profile {} is removed".format(
            new_profile_name))
        pytest_assert(
            wait_until(30, 5, 0,
                      lambda: check_profile_exists(new_profile_name, False)),
            "Buffer profile {} was not removed after rollback".format(
                new_profile_name)
        )
        logger.info("Buffer profile {} successfully removed".format(
            new_profile_name))

        # Clean up checkpoint
        duthost.shell("config checkpoint delete {}".format(
            checkpoint_name), module_ignore_errors=True)

    finally:
        delete_tmpfile(duthost, tmpfile)
