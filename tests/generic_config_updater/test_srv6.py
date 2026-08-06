import pytest
import logging

from tests.common.gu_utils import apply_patch, expect_op_success, create_path
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.gu_utils import format_json_patch_for_multiasic

pytestmark = [
    pytest.mark.topology('t0', 't1'),
]


logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def setup_and_cleanup(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    """
    Setup/teardown fixture for SRv6 config
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    asic_index = enum_frontend_asic_index
    asic_namespace = duthost.get_namespace_from_asic_id(asic_index)
    if duthost.is_multi_asic:
        sonic_db_cli = "sonic-db-cli" + " -n " + asic_namespace
    else:
        sonic_db_cli = "sonic-db-cli"
    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1:: func_len 0")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli +
                    " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def test_srv6_config_update(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    """
    Test adding SRv6 configuration.
    """
    duthost = duthosts[rand_one_dut_hostname]
    asic_namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    json_patch = [
        {
            "op": "add",
            "path": create_path(["SRV6_MY_LOCATORS", "loc1"]),
            "value": {
                "prefix": "fcbb:bbbb:1::"
            }
        },
        {
            "op": "add",
            "path": create_path(["SRV6_MY_SIDS", "loc1|fcbb:bbbb:1::/48"]),
            "value": {
                "action": "uN",
                "decap_dscp_mode": "uniform",
            }
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=asic_namespace)

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    try:
        if duthost.is_multi_asic:
            frr_config = duthost.command("vtysh" + f" -n {enum_frontend_asic_index}"
                                         + " -c \"show running-config\"")["stdout"]
        else:
            frr_config = duthost.command("vtysh" + " -c \"show running-config\"")["stdout"]
        # verify that FRR config is generated correctly
        assert "locator loc1" in frr_config, "Locator is missing in FRR's configuration"
        assert "sid fcbb:bbbb:1::/48 locator loc1 behavior uN" in frr_config, "SID is missing in FRR's configuration"
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_srv6_config_remove(duthosts, rand_one_dut_hostname, enum_frontend_asic_index):
    """
    Test removing SRv6 configuration.
    """
    duthost = duthosts[rand_one_dut_hostname]
    asic_index = enum_frontend_asic_index
    asic_namespace = duthost.get_namespace_from_asic_id(asic_index)
    if duthost.is_multi_asic:
        sonic_db_cli = "sonic-db-cli" + " -n " + asic_namespace
    else:
        sonic_db_cli = "sonic-db-cli"

    json_patch = [
        {
            "op": "remove",
            "path": "/SRV6_MY_SIDS"
        },
        {
            "op": "remove",
            "path": "/SRV6_MY_LOCATORS"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=asic_namespace)

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        assert len(duthost.command(sonic_db_cli + " CONFIG_DB KEYS SRV6*")['stdout']) == 0, \
            "SRv6 configuration was not cleaned up in CONFIG_DB"
    finally:
        delete_tmpfile(duthost, tmpfile)
