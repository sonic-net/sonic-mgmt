import ast
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
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


def ensure_application_of_updated_config(duthost, configdb_field, values):
    """
    Ensures application of the JSON patch config update

    Args:
        duthost: DUT host object
        configdb_field: config db field(s) under test
        values: expected value(s) of configdb_field
    """
    def _confirm_value_in_asic_db():
        wred_objects = duthost.shell('sonic-db-cli ASIC_DB keys *WRED*')["stdout"]
        wred_objects = wred_objects.split("\n")
        if (len(wred_objects) > 1):
            for wred_object in wred_objects:
                wred_data = duthost.shell('sonic-db-cli ASIC_DB hgetall {}'.format(wred_object))["stdout"]
                if ('NULL' in wred_data):
                    continue
                wred_data = ast.literal_eval(wred_data)
                for field, value in zip(configdb_field.split(','), values.split(',')):
                    if value != wred_data[WRED_MAPPING[field]]:
                        return False
                return True
            return False
        else:
            wred_data = duthost.shell('sonic-db-cli ASIC_DB hgetall {}'.format(wred_objects[0]))["stdout"]
            wred_data = ast.literal_eval(wred_data)
            for field, value in zip(configdb_field.split(','), values.split(',')):
                if value != wred_data[WRED_MAPPING[field]]:
                    return False
            return True

    logger.info("Validating fields in ASIC DB...")
    pytest_assert(
        wait_until(READ_ASICDB_TIMEOUT, READ_ASICDB_INTERVAL, 0, _confirm_value_in_asic_db),
        "ASIC DB does not properly reflect newly configured field(s): {} expected value(s): {}"
        .format(configdb_field, values)
    )


@pytest.mark.parametrize("configdb_field", ["green_min_threshold", "green_max_threshold", "green_drop_probability",
                         "green_min_threshold,green_max_threshold,green_drop_probability"])
@pytest.mark.parametrize("operation", ["replace"])
def test_ecn_config_updates(duthost, ensure_dut_readiness, configdb_field, operation):
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of field: {} and operation: {}"
                .format(tmpfile, configdb_field, operation))

    json_patch = list()
    values = list()
    ecn_data = duthost.shell('sonic-db-cli CONFIG_DB hgetall "WRED_PROFILE|AZURE_LOSSLESS"')['stdout']
    ecn_data = ast.literal_eval(ecn_data)
    for field in configdb_field.split(','):
        value = int(ecn_data[field]) + 1
        values.append(str(value))

        logger.info("value to be added to json patch: {}, operation: {}, field: {}"
                    .format(value, operation, field))

        json_patch.append(
                          {"op": "{}".format(operation),
                           "path": "/WRED_PROFILE/AZURE_LOSSLESS/{}".format(field),
                           "value": "{}".format(value)})

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid_platform_and_version(duthost, "WRED_PROFILE", "ECN tuning", operation):
            expect_op_success(duthost, output)
            ensure_application_of_updated_config(duthost, configdb_field, ",".join(values))
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)
