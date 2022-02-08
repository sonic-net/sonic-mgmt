import logging
import json
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox', 'barefoot')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for incremental qos config update tst

    Args:
        duthost: DUT host object
    """
    config_tmpfile = generate_tmpfile(duthost)
    logger.info("config_tmpfile {}".format(config_tmpfile))
    logger.info("Backing up config_db.json")
    duthost.shell("sudo cp /etc/sonic/config_db.json {}".format(config_tmpfile))
    verify_orchagent_running_or_assert(duthost)

    yield

    verify_orchagent_running_or_assert(duthost)
    logger.info("Restoring config_db.json")
    duthost.shell("sudo cp {} /etc/sonic/config_db.json".format(config_tmpfile))
    delete_tmpfile(duthost, config_tmpfile)
    config_reload(duthost)

    logger.info("TEARDOWN COMPLETED")


def prepare_configdb_field(duthost, configdb_field, value):
    """
    Prepares config db by setting BUFFER_POOL key and field to specified value. If value is empty string or None, delete the current entry.

    Args:
        duthost: DUT host object
        configdb_field: field in config_db BUFFER_POOL table of the form key/value
        value: BUFFER_POOL table value to be set
    """

    configdb_field_elements = configdb_field.split('/')
    pytest_assert((len(configdb_field_elements) == 2), "Configdb field not identifiable")

    key = configdb_field_elements[0]
    field = configdb_field_elements[1]
    logger.info("Setting configdb key: {} field: {} to value: {}".format(key, field, value))

    if value:
        cmd = "sonic-db-cli CONFIG_DB hset \"BUFFER_POOL|{}\" \"{}\" \"{}\" ".format(key, field, value)
    else:
        cmd = "sonic-db-cli CONFIG_DB del \"BUFFER_POOL|{}\" \"{}\" ".format(key, field)

    verify_orchagent_running_or_assert(duthost)


@pytest.mark.parametrize("configdb_field", ["ingress_lossless_pool/xoff", "ingress_lossless_pool/size", "egress_lossy_pool/size"])
@pytest.mark.parametrize("operation", ["add", "replace", "remove"])
@pytest.mark.parametrize("field_pre_status", ["existing", "nonexistent"])
def test_incremental_qos_config_updates(duthost, ensure_dut_readiness, configdb_field, operation, field_pre_status):
    operation_to_new_value_map = {"add": "678", "replace": "789", "remove": ""}
    field_pre_status_to_value_map = {"existing": "567", "nonexistent": ""}

    prepare_configdb_field(duthost, configdb_field, field_pre_status_to_value_map[field_pre_status])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of field: {} and operation: {}".format(tmpfile, configdb_field, operation))

    json_patch = [
        {
            "op": "{}".format(operation),
            "path": "/BUFFER_POOL/{}".format(configdb_field),
            "value": "{}".format(operation_to_new_value_map[operation])
        }
    ]

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    delete_tmpfile(duthost, tmpfile)
