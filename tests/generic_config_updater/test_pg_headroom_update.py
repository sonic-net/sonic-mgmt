import ast
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import is_valid_platform_and_version, get_asic_name

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)

READ_ASICDB_TIMEOUT = 20
READ_ASICDB_INTERVAL = 5


@pytest.fixture(scope="function")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for pg headroom update test

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


def ensure_application_of_updated_config(duthost, xoff, values, cli_namespace_prefix):
    """
    Ensures application of the JSON patch config update

    Args:
        duthost: DUT host object
        values: expected value(s) for the xoff field
    """
    def _confirm_value_in_app_and_asic_db():
        for profile in xoff:
            profile_data = duthost.shell('sonic-db-cli {} APPL_DB hgetall "BUFFER_PROFILE_TABLE:{}"'
                                         .format(cli_namespace_prefix, profile))["stdout"]
            profile_data = ast.literal_eval(profile_data)
            if profile_data["xoff"] != xoff[profile]:
                return False

        count = 0
        table_name = duthost.shell('sonic-db-cli {} ASIC_DB keys *BUFFER_PROFILE*'
                                   .format(cli_namespace_prefix))["stdout_lines"]
        for table in table_name:
            profile_data = duthost.shell('sonic-db-cli {} ASIC_DB hgetall "{}"'
                                         .format(cli_namespace_prefix, table))["stdout"]
            profile_data = ast.literal_eval(profile_data)
            if "SAI_BUFFER_PROFILE_ATTR_XOFF_TH" in profile_data:
                count += 1
                if profile_data["SAI_BUFFER_PROFILE_ATTR_XOFF_TH"] not in values:
                    return False
        return count == len(values)

    logger.info("Validating fields in APPL DB and ASIC DB for namespace prefix {}...".format(cli_namespace_prefix))
    pytest_assert(
        wait_until(READ_ASICDB_TIMEOUT, READ_ASICDB_INTERVAL, 0, _confirm_value_in_app_and_asic_db),
        "APPL DB or ASIC DB does not properly reflect newly configured value(s) for xoff"
    )


@pytest.mark.parametrize("operation", ["replace"])
def test_pg_headroom_update(duthost, ensure_dut_readiness, operation, skip_when_buffer_is_dynamic_model,
                            enum_rand_one_frontend_asic_index, cli_namespace_prefix):
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_frontend_asic_index)
    asic_type = get_asic_name(duthost)
    pytest_require("td2" not in asic_type, "PG headroom should be skipped on TD2")
    tmpfile = generate_tmpfile(duthost)

    json_patch = list()
    values = list()
    xoff = dict()
    lossless_profiles = duthost.shell('sonic-db-cli {} CONFIG_DB keys *BUFFER_PROFILE\\|pg_lossless*'
                                      .format(cli_namespace_prefix))['stdout_lines']
    for profile in lossless_profiles:
        profile_name = profile.split('|')[-1]
        value = duthost.shell('sonic-db-cli {} CONFIG_DB hget "{}" "xoff"'
                              .format(cli_namespace_prefix, profile))['stdout']
        value = int(value)
        value -= 1000
        xoff[profile_name] = str(value)
        values.append(str(value))

        logger.info("xoff value to be added to json patch: {}, operation: {}"
                    .format(value, operation))

        json_patch.append(
                          {"op": "{}".format(operation),
                           "path": "/BUFFER_PROFILE/{}/xoff".format(profile_name),
                           "value": "{}".format(value)})
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[namespace])
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid_platform_and_version(duthost, "BUFFER_PROFILE", "PG headroom modification", operation):
            expect_op_success(duthost, output)
            ensure_application_of_updated_config(duthost, xoff, values, cli_namespace_prefix)
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)
