import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

READ_APPL_DB_TIMEOUT = 480
READ_APPL_DB_INTERVAL = 20


@pytest.fixture(scope="module")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for dynamic threshold config update test

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


def ensure_application_of_updated_config(duthost, value, pg_lossless_profiles):
    """
    Ensures application of the JSON patch config update by verifying dynamic threshold value presence in DB

    Args:
        duthost: DUT host object
        value: expected value of dynamic threshold
        pg_lossless_profiles: all pg_lossless buffer profiles stored on the device
    """
    def _confirm_value_in_appl_db_and_asic_db():

        for pg_lossless_profile in pg_lossless_profiles:
            # Retrieve dynamic_th from APPL_DB
            dynamic_th_in_appl_db = duthost.shell("sonic-db-cli APPL_DB hget BUFFER_PROFILE_"
                                                  "TABLE:{} dynamic_th".format(pg_lossless_profile))["stdout"]
            if dynamic_th_in_appl_db != value:
                return False

        # Retrieve dynamic_th from ASIC_DB
        ingress_lossless_pool_oid = duthost.shell("sonic-db-cli COUNTERS_DB hget COUNTERS_BUFFER_POOL_NAME_MAP "
                                                  "ingress_lossless_pool")["stdout"]
        buffer_pool_keys = duthost.shell("redis-cli -n 1 KEYS ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:"
                                         "oid*")["stdout_lines"]

        for buffer_pool in buffer_pool_keys:
            pool_oid = duthost.shell("sonic-db-cli ASIC_DB hget {} SAI_BUFFER_PROFILE_ATTR_"
                                     "POOL_ID".format(buffer_pool))["stdout"]

            if pool_oid == ingress_lossless_pool_oid:
                xoff_val = duthost.shell("sonic-db-cli ASIC_DB hget {} SAI_BUFFER_PROFILE_ATTR_"
                                         "XOFF_TH".format(buffer_pool))["stdout"]
                dynamic_th_in_asic_db = duthost.shell("sonic-db-cli ASIC_DB hget {} SAI_BUFFER_PROFILE_"
                                                      "ATTR_SHARED_DYNAMIC_TH".format(buffer_pool))["stdout"]
                # Dynamic threshold values are a mismatch for pg_lossless profiles
                if dynamic_th_in_asic_db != value and len(xoff_val) > 0:
                    return False

        return True

    pytest_assert(
        wait_until(READ_APPL_DB_TIMEOUT, READ_APPL_DB_INTERVAL, 0, _confirm_value_in_appl_db_and_asic_db),
        "ASIC_DB or APPL_DB does not properly reflect new dynamic threshold expected value: {}".format(value)
    )


def get_pg_lossless_profiles(duthost):
    """
    Retrieves all pg_lossless buffer profiles that are present on the device. Ex. pg_lossless_100000_40m_profile

    Args:
    duthost: DUT host object
    """
    pg_lossless_profiles_str = duthost.shell("sonic-db-cli APPL_DB KEYS *BUFFER_PROFILE_TABLE:pg_lossless*")["stdout_lines"]
    pg_lossless_profiles_lst = []

    for pg_lossless_profile_str in pg_lossless_profiles_str:
        # Regex search for pg_lossless profiles
        match = re.search(r"pg_lossless(.*)", pg_lossless_profile_str)
        if match:
            pg_lossless_profile = match.group()
        else:
            continue
        pg_lossless_profiles_lst.append(pg_lossless_profile)

    return pg_lossless_profiles_lst if len(pg_lossless_profiles_lst) > 0 else None


@pytest.mark.parametrize("operation", ["replace"])
def test_dynamic_th_config_updates(duthost, ensure_dut_readiness, operation, skip_when_buffer_is_dynamic_model):
    pg_lossless_profiles = get_pg_lossless_profiles(duthost)
    pytest_require(pg_lossless_profiles, "DUT has no pg_lossless buffer profiles")
    new_dynamic_th = "2"
    json_patch = []

    for pg_lossless_profile in pg_lossless_profiles:
        individual_patch = {
            "op": "{}".format(operation),
            "path": "/BUFFER_PROFILE/{}/dynamic_th".format(pg_lossless_profile),
            "value": new_dynamic_th
        }
        json_patch.append(individual_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of updating dynamic threshold and operation: {}"
                .format(tmpfile, operation))
    logger.info("value to be added to json patch: {}".format(new_dynamic_th))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        ensure_application_of_updated_config(duthost, new_dynamic_th, pg_lossless_profiles)
        logger.info("Config successfully updated and verified.")
    finally:
        delete_tmpfile(duthost, tmpfile)
