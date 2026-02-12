import pytest
import logging
import time

from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure, create_path
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.gu_utils import format_json_patch_for_multiasic

pytestmark = [
    pytest.mark.topology('any'),
]


logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
    Ignore expected failures logs during test execution.

    Static route tests can trigger routeCheck failures during teardown/rollback convergence
    on multi-ASIC devices, but these don't cause harm to DUT.

    Args:
        duthosts: list of DUTs
        enum_rand_one_per_hwsku_frontend_hostname: Hostname of a random chosen frontend dut
        loganalyzer: Loganalyzer utility fixture
    """
    ignoreRegex = [
        r".*ERR monit\[\d+\]: 'routeCheck' status failed \(255\) -- Failure results:.*",
        r".*ERR.*Data Loading Failed:Invalid value \"fcbb:bbbb:1::\" in \"prefix\" element.",
    ]

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if loganalyzer and loganalyzer[duthost.hostname]:
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)


@pytest.fixture(autouse=True)
def setup_and_cleanup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
    """
    Setup/teardown fixture for STATIC ROUTE config
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    create_checkpoint(duthost)

    asic_index = enum_frontend_asic_index
    asic_namespace = duthost.get_namespace_from_asic_id(asic_index)
    if duthost.is_multi_asic:
        sonic_db_cli = "sonic-db-cli" + " -n " + asic_namespace
    else:
        sonic_db_cli = "sonic-db-cli"
    # add a static route to create the STATIC_ROUTE table
    duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb::/32\
        nexthop 'fc00::1' ifname 'Ethernet0'")

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def test_static_route_add(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
    """
    Test adding static route configuration.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    json_patch = [
        {
            "op": "add",
            "path": create_path(["STATIC_ROUTE", "default|fcbb:bbbb:1::/48"]),
            "value": {
                "nexthop": "2a03:1234:5678::1",
                "ifname": "Ethernet1"
            }
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)
    time.sleep(1)  # wait for the config to be applied

    try:
        if duthost.is_multi_asic:
            frr_config = duthost.command("vtysh" + f" -n {enum_frontend_asic_index}"
                                         + " -c \"show running-config\"")["stdout"]
        else:
            frr_config = duthost.command("vtysh" + " -c \"show running-config\"")["stdout"]
        # verify that FRR config is generated correctly
        assert "ipv6 route fcbb:bbbb:1::/48" in frr_config, "Static route is missing in FRR's configuration"
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_static_route_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
    """
    Test adding static route configuration.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    json_patch = [
        {
            "op": "replace",
            "path": create_path(["STATIC_ROUTE", "default|fcbb:bbbb::/32", "ifname"]),
            "value": "Ethernet1"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)
    time.sleep(1)  # wait for the config to be applied

    try:
        if duthost.is_multi_asic:
            frr_config = duthost.command("vtysh" + f" -n {enum_frontend_asic_index}"
                                         + " -c \"show running-config\"")["stdout"]
        else:
            frr_config = duthost.command("vtysh" + " -c \"show running-config\"")["stdout"]
        # verify that FRR config is updatedd correctly
        assert "ipv6 route fcbb:bbbb::/32 fc00::1 Ethernet1" in frr_config,\
               "Static route is not updated in FRR's configuration"
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_static_route_remove(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
    """
    Test removing SRv6 configuration.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_index = enum_frontend_asic_index
    asic_namespace = duthost.get_namespace_from_asic_id(asic_index)
    if duthost.is_multi_asic:
        sonic_db_cli = "sonic-db-cli" + " -n " + asic_namespace
    else:
        sonic_db_cli = "sonic-db-cli"

    json_patch = [
        {
            "op": "remove",
            "path": "/STATIC_ROUTE"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        time.sleep(1)  # wait for the config to be applied

        assert len(duthost.command(sonic_db_cli + " CONFIG_DB KEYS STATIC*")['stdout']) == 0, \
            "STATIC ROUTE configuration was not cleaned up in CONFIG_DB"
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_static_route_add_invalid(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,
                                  loganalyzer):
    """
    Test adding an invalid static route configuration.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    json_patch = [
        {
            "op": "add",
            "path": create_path(["STATIC_ROUTE", "default|fcbb:bbbb:1::"]),
            "value": {
                "nexthop": "2a03:1234:5678::1",
                "ifname": "Ethernet1"
            }
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_failure(output)
    delete_tmpfile(duthost, tmpfile)
