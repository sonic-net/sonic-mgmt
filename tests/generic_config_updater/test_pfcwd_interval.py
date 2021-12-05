import logging
import json
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.asic('mellanox')
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

    yield
 
    logger.info("Restoring config_db.json")
    duthost.shell("sudo cp {} /etc/sonic/config_db.json".format(config_tmpfile))
    delete_tmpfile(duthost, config_tmpfile)
    config_reload(duthost)

    logger.info("TEARDOWN COMPLETED")


def prepare_pfcwd_interval_config(duthost, value):
    """
    Prepares config db by setting pfcwd poll interval to specified value. If value is empty string, delete the current entry. 

    Args:
        duthost: DUT host object
        value: poll interval value to be set
    """

    logger.info("Setting configdb entry pfcwd poll interval to value: {}".format(value))
   
    if value:
        cmd = "sudo pfcwd interval {}".format(value)
    else:
        cmd = "sonic-db-cli CONFIG_DB del \PFC_WD\GLOBAL\POLL_INTERVAL"


def get_detection_restoration_times(duthost):
    """
    Returns detection_time, restoration_time for an interface. Poll_interval must be greater than both in order to be valid
    
    Args:
        duthost: DUT host object
    """
     
    pfcwd_config = duthost.shell("show pfcwd config")
    pytest_assert(not pfcwd_config['rc'], "Unable to read pfcwd config")
    
    for line in pfcwd_config['stdout_lines']:
        if line.startswith('Ethernet'):
            interface = line.split()[0] #Since line starts with Ethernet, we can safely use 0 index

            cmd = "sonic-db-cli CONFIG_DB hget \"PFC_WD|{}\" \"detection_time\" ".format(interface)
            output = duthost.shell(cmd, module_ignore_errors=True)
            pytest_assert(not output['rc'], "Unable to read detection time")
            detection_time = output["stdout"]
            
            cmd = "sonic-db-cli CONFIG_DB hget \"PFC_WD|{}\" \"restoration_time\" ".format(interface)
            output = duthost.shell(cmd, module_ignore_errors=True)
            pytest_assert(not output['rc'], "Unable to read restoration time")
            restoration_time = output["stdout"]

            return int(detection_time), int(restoration_time)

    pytest_assert(True, "Failed to read detection_time and/or restoration time")
            

def get_new_interval(duthost, is_valid):
    """
    Returns new interval value for pfcwd poll interval, based on the operation being performed

    Args:
        duthost: DUT host object
        is_valid: if is_valid is true, return a valid new interval. Config update should succeed. If is_valid is false, return an invalid new interval. Config update should fail.
    """

    detection_time, restoration_time = get_detection_restoration_times(duthost)
    if is_valid:
        return max(detection_time, restoration_time) + 10
    else:
        return min(detection_time, restoration_time) - 10


@pytest.mark.parametrize("operation", ["add", "replace", "remove"])
@pytest.mark.parametrize("field_pre_status", ["existing", "nonexistent"])
@pytest.mark.parametrize("is_valid_config_update", [True, False])
def test_pfcwd_interval_config_updates(duthost, ensure_dut_readiness, operation, field_pre_status, is_valid_config_update):
    new_interval = get_new_interval(duthost, is_valid_config_update)

    operation_to_new_value_map = {"add": "{}".format(new_interval), "replace": "{}".format(new_interval), "remove": ""}
    detection_time, restoration_time = get_detection_restoration_times(duthost)
    pre_status = max(detection_time, restoration_time)
    field_pre_status_to_value_map = {"existing": "{}".format(pre_status), "nonexistent": ""}
    
    prepare_pfcwd_interval_config(duthost, field_pre_status_to_value_map[field_pre_status]) 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of pfcwd poll interval and operation: {}".format(tmpfile, operation))
    value = operation_to_new_value_map[operation]
    logger.info("value to be added to json patch: {}".format(value))

    json_patch = [
        {
            "op": "{}".format(operation), 
            "path": "/PFC_WD/GLOBAL/POLL_INTERVAL", 
            "value": "{}".format(value)
        }]
    
    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    
    if is_valid_config_update:
        expect_op_success(duthost, output)
    else:
        expect_op_failure(output)
