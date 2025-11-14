import ast
from functools import cmp_to_key
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import is_valid_platform_and_version

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

READ_ASICDB_TIMEOUT = 20
READ_ASICDB_INTERVAL = 5
WRED_MAPPING = {'green_min_threshold': 'SAI_WRED_ATTR_GREEN_MIN_THRESHOLD',
                'green_max_threshold': 'SAI_WRED_ATTR_GREEN_MAX_THRESHOLD',
                'green_drop_probability': 'SAI_WRED_ATTR_GREEN_DROP_PROBABILITY'}


@pytest.fixture(scope="function")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture ecn config update tst

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


def get_asic_db_values(duthost, fields, cli_namespace_prefix):
    """
    Args:
        duthost: DUT host object
        fields: CONFIG DB field(s) under test

    Returns:
        A dictionary where keys are WRED profile OIDs in ASIC DB and values are the field-value pairs
        for the fields in configdb_field.
    """
    wred_objects = get_wred_objects(duthost, cli_namespace_prefix)
    asic_db_values = {}
    for wred_object in wred_objects:
        oid = wred_object[wred_object.rfind(':') + 1:]
        wred_data = duthost.shell('sonic-db-cli {} ASIC_DB hgetall {}'
                                  .format(cli_namespace_prefix, wred_object))["stdout"]
        if "NULL" in wred_data:
            continue
        wred_data = ast.literal_eval(wred_data)
        values = {}
        for field in fields:
            values[field] = int(wred_data[WRED_MAPPING[field]])
        if values:
            asic_db_values[oid] = values
    return asic_db_values


def get_wred_objects(duthost, cli_namespace_prefix):
    """
    Args:
        duthost: DUT host object

    Returns:
        A list of WRED profile objects in ASIC DB.
    """
    wred_objects = duthost.shell('sonic-db-cli {} ASIC_DB keys *WRED*'.format(cli_namespace_prefix))["stdout"]
    wred_objects = wred_objects.split("\n")
    return wred_objects


def dict_compare(fields):
    """
    Compares two dictionaries for equality based on a subset of keys.

    Args:
        fields: The keys to compare.

    Returns:
        A function that compares two dictionaries.
    """
    def compare(dict1, dict2):
        for field in fields:
            if dict1.get(field, 0) < dict2.get(field, 0):
                return -1
            elif dict1.get(field, 0) > dict2.get(field, 0):
                return 1
        # If all compared fields are equal, return 0
        return 0

    return compare


def ensure_application_of_updated_config(duthost, fields, new_values, cli_namespace_prefix):
    """
    Ensures application of the JSON patch config update

    Args:
        duthost: DUT host object
        fields: config db field(s) under test
        new_values: expected value(s) of fields. It is a dictionary where keys are WRED profile names
                    and values are dictionaries of field-value pairs for all fields in fields.
        cli_namespace_prefix: CLI ASIC namespace for sonic-db-cli commands
    """
    # Since there is no direct way to obtain the WRED profile name to oid mapping, we will just make sure
    # that the set of values in ASIC DB matches the set of values in CONFIG DB.
    def validate_wred_objects_in_asic_db():
        asic_db_values = get_asic_db_values(duthost, fields, cli_namespace_prefix)
        asic_db_values_list = sorted(list(asic_db_values.values()), key=cmp_to_key(dict_compare(fields)))
        new_values_list = sorted(list(new_values.values()), key=cmp_to_key(dict_compare(fields)))
        return asic_db_values_list == new_values_list

    logger.info("Validating WRED objects in ASIC DB...")
    pytest_assert(
        wait_until(READ_ASICDB_TIMEOUT, READ_ASICDB_INTERVAL, 0, validate_wred_objects_in_asic_db),
        "ASIC DB does not properly reflect newly configured field(s): {} expected value(s): {}"
        .format(fields, new_values)
    )


def get_wred_profiles(duthost, cli_namespace_prefix):
    wred_profiles = duthost.shell(f"sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys \
                                  'WRED_PROFILE|*' | cut -d '|' -f 2")["stdout"]
    return [w for w in wred_profiles.split('\n') if w]


@pytest.mark.parametrize("configdb_field", ["green_min_threshold", "green_max_threshold", "green_drop_probability",
                         "green_min_threshold,green_max_threshold,green_drop_probability"])
@pytest.mark.parametrize("operation", ["replace"])
def test_ecn_config_updates(duthost, ensure_dut_readiness, configdb_field, operation,
                            enum_rand_one_frontend_asic_index, cli_namespace_prefix):
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of field: {} and operation: {}"
                .format(tmpfile, configdb_field, operation))
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_frontend_asic_index)

    fields = configdb_field.split(',')
    wred_profiles = get_wred_profiles(duthost, cli_namespace_prefix)
    if not wred_profiles:
        pytest.skip("No WRED profiles found in CONFIG_DB, skipping test.")
    json_patch = list()
    # new_values is a dictionary from WRED profile name to its field-value mapping (with new values)
    # for the fields in configdb_field.
    new_values = {}
    # Creating a JSON patch for all WRED profiles in CONFIG_DB.
    for wred_profile in wred_profiles:
        ecn_data = duthost.shell("sonic-db-cli {} CONFIG_DB hgetall 'WRED_PROFILE|{}'"
                                 .format(cli_namespace_prefix, wred_profile))['stdout']
        ecn_data = ast.literal_eval(ecn_data)
        new_values[wred_profile] = {}
        for field in fields:
            value = int(ecn_data[field])
            if "probability" in field:
                if 0 <= value < 99:
                    value += 1
                elif value >= 99:
                    value -= 1
                else:
                    raise ValueError("Invalid probability value: {}".format(value))
            elif "min" in field:
                value -= 1
            else:
                value += 1
            new_values[wred_profile][field] = value

            logger.info("value to be added to json patch: {}, operation: {}, field: {}"
                        .format(value, operation, field))

            json_patch.append(
                              {"op": "{}".format(operation),
                               "path": f"/WRED_PROFILE/{wred_profile}/{field}",
                               "value": "{}".format(value)})

    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[namespace])
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid_platform_and_version(duthost, "WRED_PROFILE", "ECN tuning", operation):
            expect_op_success(duthost, output)
            ensure_application_of_updated_config(duthost, fields, new_values, cli_namespace_prefix)
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)
