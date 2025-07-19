import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
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


def ensure_application_of_updated_config(duthost, value, pg_lossless_profiles,
                                         ip_netns_namespace_prefix,
                                         cli_namespace_prefix):
    """
    Ensures application of the JSON patch config update by verifying dynamic threshold value presence in DB

    Args:
        duthost: DUT host object
        value: expected value of dynamic threshold
        pg_lossless_profiles: all pg_lossless buffer profiles stored on the device
        ip_netns_namespace_prefix: fixture for the formatted ip netns namespace
        cli_namespace_prefix: fixture for the formatted cli namespace
    """
    def _confirm_value_in_appl_db_and_asic_db():
        for pg_lossless_profile in pg_lossless_profiles:
            # Retrieve dynamic_th from APPL_DB
            dynamic_th_in_appl_db = duthost.shell("sonic-db-cli {} APPL_DB hget BUFFER_PROFILE_"
                                                  "TABLE:{} dynamic_th"
                                                  .format(cli_namespace_prefix,
                                                          pg_lossless_profile))["stdout"]
            if dynamic_th_in_appl_db != value:
                return False

        sample_ports_with_pg_lossless_profile = []
        for pg_lossless_profile in pg_lossless_profiles:
            keys = duthost.shell('sonic-db-cli {} CONFIG_DB keys "BUFFER_PG|*"'
                                 .format(cli_namespace_prefix))["stdout_lines"]
            for key in keys:
                port_pg_profile = duthost.shell('sonic-db-cli {} CONFIG_DB hget "{}" profile'
                                                .format(cli_namespace_prefix, key))["stdout"]
                if port_pg_profile == pg_lossless_profile:
                    # Found port with pg_lossless_profile. key format - BUFFER_PG|EthernetX|X-X.
                    parts = key.split("|")
                    port_name = parts[1]
                    queue_number = parts[2].split("-")[0]

                    sample_ports_with_pg_lossless_profile.append(port_name + ":" + queue_number)
                    break

        if len(sample_ports_with_pg_lossless_profile) != len(pg_lossless_profiles):
            return False

        for port in sample_ports_with_pg_lossless_profile:
            ingress_priority_group_oid = duthost.shell('sonic-db-cli {} COUNTERS_DB hget COUNTERS_PG_NAME_MAP "{}"'
                                                       .format(cli_namespace_prefix, port))["stdout"]

            buffer_profile_oid = duthost.shell("sonic-db-cli {} ASIC_DB hget ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_"
                                               "PRIORITY_GROUP:{} SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE"
                                               .format(cli_namespace_prefix, ingress_priority_group_oid))["stdout"]

            xoff_val = duthost.shell("sonic-db-cli {} ASIC_DB hget ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_"
                                     "PROFILE:{} SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH"
                                     .format(cli_namespace_prefix, buffer_profile_oid))["stdout"]
            dynamic_th_in_asic_db = duthost.shell("sonic-db-cli {} ASIC_DB hget ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_"
                                                  "PROFILE:{} SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH"
                                                  .format(cli_namespace_prefix, buffer_profile_oid))["stdout"]
            if dynamic_th_in_asic_db != value and len(xoff_val) > 0:
                return False

        return True

    pytest_assert(
        wait_until(READ_APPL_DB_TIMEOUT, READ_APPL_DB_INTERVAL, 0, _confirm_value_in_appl_db_and_asic_db),
        "ASIC_DB or APPL_DB for namespace prefix {} does not properly reflect new dynamic threshold expected value: {}"
        .format(cli_namespace_prefix, value)
    )


def get_pg_lossless_profiles(duthost, cli_namespace_prefix):
    """
    Retrieves all pg_lossless buffer profiles that are present on the device. Ex. pg_lossless_100000_40m_profile

    Args:
    duthost: DUT host object
    cli_namespace_prefix: fixture for the formatted cli namespace
    """
    pg_lossless_profiles_str = duthost.shell("sonic-db-cli {} APPL_DB KEYS *BUFFER_PROFILE_TABLE:pg_lossless*"
                                             .format(cli_namespace_prefix))["stdout_lines"]
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
def test_dynamic_th_config_updates(duthost, ensure_dut_readiness, operation,
                                   skip_when_buffer_is_dynamic_model,
                                   enum_rand_one_frontend_asic_index,
                                   ip_netns_namespace_prefix,
                                   cli_namespace_prefix):
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_frontend_asic_index)

    pg_lossless_profiles = get_pg_lossless_profiles(duthost, cli_namespace_prefix)
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

    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {} created for json patch of updating dynamic threshold and operation: {}"
                .format(tmpfile, operation))
    logger.info("value to be added to json patch: {}".format(new_dynamic_th))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        ensure_application_of_updated_config(duthost, new_dynamic_th, pg_lossless_profiles,
                                             ip_netns_namespace_prefix, cli_namespace_prefix)
        logger.info("Config successfully updated and verified.")
    finally:
        delete_tmpfile(duthost, tmpfile)
