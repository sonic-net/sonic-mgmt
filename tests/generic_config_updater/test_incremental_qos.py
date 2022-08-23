from __future__ import division
import logging
import json
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox', 'barefoot')
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
        for neighbor in device_neighbor_metadata.keys():
            neighbor_data = device_neighbor_metadata[neighbor]
            if neighbor_data['type'] == "SpineRouter":
                spine_router_count += 1
            elif neighbor_data['type'] == "ToRRouter":
                tor_router_count += 1
        return spine_router_count, tor_router_count

    elif "t0" in topo:
        leaf_router_count = 0
        server_count = 0
        for neighbor in device_neighbor_metadata.keys():
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
    neighbor_to_type_map =  {}
    neighbor_type_to_pg_headroom_map = {}

    for neighbor in device_neighbor_metadata.keys():
        neighbor_set.add(neighbor)
        neighbor_data = device_neighbor_metadata[neighbor]
        neighbor_to_type_map[neighbor] = neighbor_data['type']

    for interface in interfaces_data.keys():
        for neighbor in neighbor_set:
            if neighbor in json.dumps(interfaces_data[interface]):
                neighbor_to_interface_map[neighbor] = interface
                break

    for neighbor in neighbor_set:
        interface = neighbor_to_interface_map[neighbor]

        cable_length = duthost.shell('sonic-db-cli CONFIG_DB hget "CABLE_LENGTH|AZURE" {}'.format(interface))['stdout']
        port_speed = duthost.shell('sonic-db-cli CONFIG_DB hget "PORT|{}" speed'.format(interface))['stdout']

        expected_profile = 'pg_lossless_{}_{}_profile'.format(port_speed, cable_length)

        xoff = int(duthost.shell('sonic-db-cli APPL_DB hget "BUFFER_PROFILE_TABLE:{}" xoff'.format(expected_profile))['stdout'])
        xon = int(duthost.shell('sonic-db-cli APPL_DB hget "BUFFER_PROFILE_TABLE:{}" xon'.format(expected_profile))['stdout'])
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
    user_reserved = uplink_downlink_sum * LOSSY_PGS * MIN_LOSSY_BUFFER_THRESHOLD + uplink_downlink_sum * EGRESS_POOL_THRESHOLD
    private_headroom = uplink_downlink_sum * LOSSLESS_PGS * OPER_HEADROOM_SIZE + uplink_downlink_sum * INGRESS_POOL_THRESHOLD

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
        oid = duthost.shell('sonic-db-cli COUNTERS_DB HGET COUNTERS_BUFFER_POOL_NAME_MAP {}'.format(buffer_pool))["stdout"]
        buffer_pool_data = duthost.shell('sonic-db-cli ASIC_DB hgetall ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:{}'.format(oid))["stdout"]
        return str(value) in buffer_pool_data

    pytest_assert(
        wait_until(READ_ASICDB_TIMEOUT, READ_ASICDB_INTERVAL, 0, _confirm_value_in_asic_db),
        "ASIC DB does not properly reflect newly configured field: {} expected value: {}".format(configdb_field, value)
    )


@pytest.mark.parametrize("configdb_field", ["ingress_lossless_pool/xoff", "ingress_lossless_pool/size", "egress_lossy_pool/size"])
@pytest.mark.parametrize("operation", ["add", "replace", "remove"])
def test_incremental_qos_config_updates(duthost, tbinfo, ensure_dut_readiness, configdb_field, operation):
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of field: {} and operation: {}".format(tmpfile, configdb_field, operation))

    if operation == "remove":
        value= ""
    else:
        value = calculate_field_value(duthost, tbinfo, configdb_field)
    logger.info("value to be added to json patch: {} operation: {} field: {}".format(value, operation, configdb_field))

    json_patch = [
        {
            "op": "{}".format(operation),
            "path": "/BUFFER_POOL/{}".format(configdb_field),
            "value": "{}".format(value)
        }]

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        ensure_application_of_updated_config(duthost, configdb_field, value)
    finally:
        delete_tmpfile(duthost, tmpfile)
