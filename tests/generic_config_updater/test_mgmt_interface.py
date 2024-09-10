import ipaddress
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.generic_config_updater.gu_utils import apply_patch, create_path
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

# forced mgmt route priority hardcoded to 32764 in following j2 template:
# https://github.com/sonic-net/sonic-buildimage/blob/master/files/image_config/interfaces/interfaces.j2#L82
FORCED_MGMT_ROUTE_PRIORITY = 32764

# Wait 300 seconds because sometime 'interfaces-config' service take 45 seconds to response
# interfaces-config service issue track by: https://github.com/sonic-net/sonic-buildimage/issues/19045
FILE_CHANGE_TIMEOUT = 300


@pytest.fixture(scope="function")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for pg headroom update test

    Args:
        duthost: DUT host object
    """
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def get_file_hash(duthost, file):
    hash = duthost.command("sha1sum {}".format(file))["stdout"]
    logger.debug("file hash: {}".format(hash))

    return hash


def get_interface_reload_timestamp(duthost):
    timestamp = duthost.command("sudo systemctl show --no-pager interfaces-config"
                                " -p ExecMainExitTimestamp --value")["stdout"]
    logger.info("interfaces config timestamp {}".format(timestamp))

    return timestamp


def wait_for_file_changed(duthost, file, action, *args, **kwargs):
    original_hash = get_file_hash(duthost, file)
    last_timestamp = get_interface_reload_timestamp(duthost)

    action(*args, **kwargs)

    def hash_and_timestamp_changed(duthost, file):
        latest_hash = get_file_hash(duthost, file)
        latest_timestamp = get_interface_reload_timestamp(duthost)
        return latest_hash != original_hash and latest_timestamp != last_timestamp

    exist = wait_until(FILE_CHANGE_TIMEOUT, 1, 0, hash_and_timestamp_changed, duthost, file)
    pytest_assert(exist, "File {} does not change after {} seconds.".format(file, FILE_CHANGE_TIMEOUT))


def update_forced_mgmt_route(duthost, interface_address, interface_key, routes):
    # Escape '/' in interface key
    json_patch = [
        {
            "path": create_path(["MGMT_INTERFACE",
                                 "eth0|{}".format(interface_address),
                                 "forced_mgmt_routes"])
        }
    ]

    if len(routes) == 0:
        json_patch[0]["op"] = "remove"
    else:
        json_patch[0]["value"] = routes
        # Replace if forced_mgmt_routes already exist
        current_config = duthost.command("sonic-db-cli CONFIG_DB HGET '{}' forced_mgmt_routes@"
                                         .format(interface_key))['stdout']
        if current_config != "":
            json_patch[0]["op"] = "replace"
        else:
            json_patch[0]["op"] = "add"

    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        logging.debug("json_patch: {}".format(json_patch))
        logging.debug("apply_patch result: {}".format(output))
    finally:
        delete_tmpfile(duthost, tmpfile)


def update_and_check_forced_mgmt_routes(duthost, forced_mgmt_routes, interface_address, interface_key,
                                        ip_type, test_route, expect_exist):
    # Update forced mgmt routes with new route address
    wait_for_file_changed(
                        duthost,
                        "/etc/network/interfaces",
                        update_forced_mgmt_route,
                        duthost,
                        interface_address,
                        interface_key,
                        forced_mgmt_routes)

    # Check /etc/network/interfaces generate correct
    interfaces = duthost.command("cat /etc/network/interfaces")['stdout']
    logging.debug("interfaces: {}".format(interfaces))

    pytest_assert(("up ip {} rule add pref {} to {} table default"
                  .format(ip_type, FORCED_MGMT_ROUTE_PRIORITY, test_route) in interfaces) == expect_exist)
    pytest_assert(("pre-down ip {} rule delete pref {} to {} table default"
                  .format(ip_type, FORCED_MGMT_ROUTE_PRIORITY, test_route) in interfaces) == expect_exist)


def test_forced_mgmt_routes_update(duthost, ensure_dut_readiness):
    # Get interface and check config generate correct
    mgmt_interface_keys = duthost.command("sonic-db-cli  CONFIG_DB keys 'MGMT_INTERFACE|eth0|*'")['stdout']
    logging.debug("mgmt_interface_keys: {}".format(mgmt_interface_keys))

    for interface_key in mgmt_interface_keys.split('\n'):
        logging.debug("interface_key: {}".format(interface_key))
        interface_address = interface_key.split('|')[2]

        # Get current forced mgmt routes
        forced_mgmt_routes_config = duthost.command("sonic-db-cli CONFIG_DB HGET '{}' forced_mgmt_routes@"
                                                    .format(interface_key))['stdout']

        original_forced_mgmt_routes = []
        if forced_mgmt_routes_config != "":
            original_forced_mgmt_routes = forced_mgmt_routes_config.split(",")

        # Prepare new forced mgmt routes
        test_route = "1::2:3:4/64"
        ip_type = "-6"
        if type(ipaddress.ip_network(interface_address, False)) == ipaddress.IPv4Network:
            test_route = "1.2.3.4/24"
            ip_type = "-4"

        updated_forced_mgmt_routes = original_forced_mgmt_routes.copy()
        updated_forced_mgmt_routes.append(test_route)
        logging.debug("interface address: {}, original_forced_mgmt_routes: {}, updated_forced_mgmt_routes: {}"
                      .format(interface_address, original_forced_mgmt_routes, updated_forced_mgmt_routes))

        # Update forced mgmt routes with new route address
        update_and_check_forced_mgmt_routes(duthost,
                                            updated_forced_mgmt_routes,
                                            interface_address,
                                            interface_key,
                                            ip_type,
                                            test_route,
                                            True)

        # Revert change and check again
        update_and_check_forced_mgmt_routes(duthost,
                                            original_forced_mgmt_routes,
                                            interface_address,
                                            interface_key,
                                            ip_type,
                                            test_route,
                                            False)
