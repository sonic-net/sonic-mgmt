import ipaddress
import json
import logging
import pytest

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.override_config_table.utilities import backup_config, restore_config, \
        reload_minigraph_with_golden_config
from tests.syslog.syslog_utils import is_mgmt_vrf_enabled

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


# forced mgmt route priority hardcoded to 32764 in following j2 template:
# https://github.com/sonic-net/sonic-buildimage/blob/master/files/image_config/interfaces/interfaces.j2#L82
FORCED_MGMT_ROUTE_PRIORITY = 32764


# Wait 300 seconds because sometime 'interfaces-config' service take 45 seconds to response
# interfaces-config service issue track by: https://github.com/sonic-net/sonic-buildimage/issues/19045
FILE_CHANGE_TIMEOUT = 300


@pytest.fixture
def backup_restore_config(duthosts, enum_rand_one_per_hwsku_hostname):
    """make sure tacacs server running after UT finish"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    #  Backup config before test
    CONFIG_DB = "/etc/sonic/config_db.json"
    CONFIG_DB_BACKUP = "/etc/sonic/config_db.json_before_override"
    backup_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)

    yield

    #  Restore config after test finish
    restore_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    config_reload(duthost)


def get_interface_reload_timestamp(duthost):
    timestamp = duthost.command("sudo systemctl show --no-pager interfaces-config"
                                " -p ExecMainExitTimestamp --value")["stdout"]
    logger.info("interfaces config timestamp {}".format(timestamp))

    return timestamp


def get_file_hash(duthost, file):
    hash = duthost.command("sha1sum {}".format(file))["stdout"]
    logger.debug("file hash: {}".format(hash))

    return hash


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


def address_type(address):
    return type(ipaddress.ip_network(str(address), False))


def check_ip_rule_exist(duthost, address, check_exist):
    logging.debug("check_ip_rule_exist for ip:{} exist:{}".format(address, check_exist))
    rule_command = "ip --json rule list"
    if address_type(address) is ipaddress.IPv6Network:
        rule_command = "ip --json -6 rule list"

    ip_rules = json.loads(duthost.command(rule_command)["stdout"])
    logging.debug("ip rule list: {}".format(ip_rules))

    exist = False
    dst = address.split("/")[0]
    dstlen = address.split("/")[1]
    for ip_rule in ip_rules:
        if (ip_rule.get("priority", "") == FORCED_MGMT_ROUTE_PRIORITY and
                ip_rule.get("src", "") == 'all' and
                ip_rule.get("dst", "") == dst and
                ip_rule.get("dstlen", "") == int(dstlen) and
                ip_rule.get("table", "") == 'default'):
            exist = True

    return check_exist == exist


def test_forced_mgmt_route_add_and_remove_by_mgmt_port_status(
                                    duthosts,
                                    enum_rand_one_per_hwsku_hostname,
                                    backup_restore_config):                             # noqa: F401
    """
    Check when mgmt. port is up, then forced mgmt route added to route table.
    When mgmt. port is down (oper down), then forced mgmt route removed from route table.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # When management-vrf enabled, IPV6 route of management interface will not add to 'default' route table
    if is_mgmt_vrf_enabled(duthost):
        logging.info("Ignore IPV6 default route table test because management-vrf enabled")
        return

    # Skip multi-asic because override_config format are different.
    if duthost.is_multi_asic:
        pytest.skip("Skip test_forced_mgmt_route_add_and_remove_by_mgmt_port_status for multi-asic device")

    # get current mgmt interface data from config_db.json
    config_db_data = duthost.shell("cat /etc/sonic/config_db.json")['stdout']
    config_db_json = json.loads(config_db_data)
    config_db_mgmt_interface = config_db_json["MGMT_INTERFACE"]
    config_db_port = config_db_json["MGMT_PORT"]

    # Skip if port does not exist
    output = duthost.command("ip link show eth1", module_ignore_errors=True)
    if output["failed"]:
        pytest.skip("Skip test_forced_mgmt_route_add_and_remove_by_mgmt_port_status, port does not exist")

    # Skip if port is already in use
    if 'eth1' in config_db_port:
        pytest.skip("Skip test_forced_mgmt_route_add_and_remove_by_mgmt_port_status, port in use")

    # Add eth1 to mgmt interface and port
    ipv4_forced_mgmt_address = "172.17.1.1/24"
    ipv6_forced_mgmt_address = "fec1::fffe:afa:1/64"
    config_db_mgmt_interface["eth1|10.250.1.101/24"] = {
        "forced_mgmt_routes": [
            ipv4_forced_mgmt_address
        ],
        "gwaddr": "10.250.1.1"
    }
    config_db_mgmt_interface["eth1|fec1::ffff:afa:1/64"] = {
        "forced_mgmt_routes": [
            ipv6_forced_mgmt_address
        ],
        "gwaddr": "fec1::1"
    }
    config_db_port["eth1"] = {
        "admin_status": "up",
        "alias": "eth1"
    }

    override_config = {}
    override_config["MGMT_INTERFACE"] = config_db_mgmt_interface
    override_config["MGMT_PORT"] = config_db_port
    logging.debug("override_config: {}".format(override_config))
    wait_for_file_changed(
                        duthost,
                        "/etc/network/interfaces",
                        reload_minigraph_with_golden_config,
                        duthost,
                        override_config,
                        False)

    # for device can't config eth1, ignore this test case
    eth1_status = duthost.command("sudo ifconfig eth1")['stdout']
    if "Device not found" in eth1_status:
        pytest.skip("Skip test_forced_mgmt_route_add_and_remove_by_mgmt_port_status because hardware can't config eth1")

    # Get interface and check config generate correct
    interfaces = duthost.command("cat /etc/network/interfaces")['stdout']
    logging.debug("interfaces: {}".format(interfaces))
    pytest_assert("iface eth1 inet static" in interfaces)
    pytest_assert("up ip -4 rule add pref {} to {} table default"
                  .format(FORCED_MGMT_ROUTE_PRIORITY, ipv4_forced_mgmt_address) in interfaces)
    pytest_assert("pre-down ip -4 rule delete pref {} to {} table default"
                  .format(FORCED_MGMT_ROUTE_PRIORITY, ipv4_forced_mgmt_address) in interfaces)
    pytest_assert("iface eth1 inet6 static" in interfaces)
    pytest_assert("up ip -6 rule add pref {} to {} table default"
                  .format(FORCED_MGMT_ROUTE_PRIORITY, ipv6_forced_mgmt_address) in interfaces)
    pytest_assert("pre-down ip -6 rule delete pref {} to {} table default"
                  .format(FORCED_MGMT_ROUTE_PRIORITY, ipv6_forced_mgmt_address) in interfaces)

    # startup eth1 and check forced mgmt route exist
    duthost.command("sudo ifup eth1")
    interfaces = duthost.command("show ip interfaces")
    logging.debug("show ip interfaces: {}".format(interfaces))

    # when eth1 up, forced mgmt route on this interface should exit
    exist = wait_until(10, 1, 0, check_ip_rule_exist, duthost, ipv4_forced_mgmt_address, True)
    pytest_assert(exist, "IP rule for {} does not exist.".format(ipv4_forced_mgmt_address))

    exist = wait_until(10, 1, 0, check_ip_rule_exist, duthost, ipv6_forced_mgmt_address, True)
    pytest_assert(exist, "IP rule for {} does not exist.".format(ipv6_forced_mgmt_address))

    # shutdown eth1 and check forced mgmt route exist
    duthost.command("sudo ifdown eth1")
    interfaces = duthost.command("show ip interfaces")
    logging.debug("show ip interfaces: {}".format(interfaces))

    # when eth1 down, forced mgmt route on this interface should not exit
    exist = wait_until(10, 1, 0, check_ip_rule_exist, duthost, ipv4_forced_mgmt_address, False)
    pytest_assert(exist, "IP rule for {} should not exist.".format(ipv4_forced_mgmt_address))

    exist = wait_until(10, 1, 0, check_ip_rule_exist, duthost, ipv6_forced_mgmt_address, False)
    pytest_assert(exist, "IP rule for {} should not exist.".format(ipv6_forced_mgmt_address))


def test_update_forced_mgmt(
                        duthosts,
                        enum_rand_one_per_hwsku_hostname,
                        backup_restore_config):                             # noqa: F401
    """
    Check when update forced mgmt in CONFIG_DB, interfaces and routes will be update automatically.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Get interface and check config generate correct
    mgmt_interface_keys = duthost.command("sonic-db-cli  CONFIG_DB keys 'MGMT_INTERFACE|eth0|*'")['stdout']
    logging.debug("mgmt_interface_keys: {}".format(mgmt_interface_keys))

    for interface_key in mgmt_interface_keys.split('\n'):
        logging.debug("interface_key: {}".format(interface_key))
        interface_address = interface_key.split('|')[2]

        # Get current forced mgmt routes
        original_forced_mgmt_routes = duthost.command("sonic-db-cli CONFIG_DB HGET '{}' forced_mgmt_routes@"
                                                      .format(interface_key))['stdout']
        logging.debug("forced_mgmt_routes: {}, interface address: {}"
                      .format(original_forced_mgmt_routes, interface_address))

        # Prepare new forced mgmt routes
        test_route = "1::2:3:4/64"
        ip_type = "-6"
        if type(ipaddress.ip_network(interface_address, False)) == ipaddress.IPv4Network:
            test_route = "1.2.3.4/24"
            ip_type = "-4"

        updated_forced_mgmt_routes = original_forced_mgmt_routes
        if original_forced_mgmt_routes != "":
            updated_forced_mgmt_routes += ","
        updated_forced_mgmt_routes += test_route

        # Update current forced mgmt routes
        logging.debug("updated_forced_mgmt_routes: {}".format(updated_forced_mgmt_routes))
        command = "sonic-db-cli CONFIG_DB HSET '{}' forced_mgmt_routes@ '{}'"\
                  .format(interface_key, updated_forced_mgmt_routes)

        def update_interface_config(duthost, command):
            duthost.command(command)

        wait_for_file_changed(
                            duthost,
                            "/etc/network/interfaces",
                            update_interface_config,
                            duthost,
                            command)

        # Check /etc/network/interfaces generate correct
        interfaces = duthost.command("cat /etc/network/interfaces")['stdout']
        logging.debug("interfaces: {}".format(interfaces))

        pytest_assert("up ip {} rule add pref {} to {} table default"
                      .format(ip_type, FORCED_MGMT_ROUTE_PRIORITY, test_route) in interfaces)
        pytest_assert("pre-down ip {} rule delete pref {} to {} table default"
                      .format(ip_type, FORCED_MGMT_ROUTE_PRIORITY, test_route) in interfaces)

        # Check forced mgmt route add to route table
        exist = wait_until(10, 1, 0, check_ip_rule_exist, duthost, test_route, True)
        pytest_assert(exist, "IP rule for {} does not exist.".format(test_route))

        # Revert current forced mgmt routes
        logging.debug("updated_forced_mgmt_routes: {}".format(original_forced_mgmt_routes))
        command = "sonic-db-cli CONFIG_DB HSET '{}' forced_mgmt_routes@ '{}'"\
                  .format(interface_key, original_forced_mgmt_routes)
        wait_for_file_changed(
                            duthost,
                            "/etc/network/interfaces",
                            update_interface_config,
                            duthost,
                            command)

        # Check /etc/network/interfaces generate correct
        interfaces = duthost.command("cat /etc/network/interfaces")['stdout']
        logging.debug("interfaces: {}".format(interfaces))
        pytest_assert("up ip {} rule add pref {} to {} table default"
                      .format(ip_type, FORCED_MGMT_ROUTE_PRIORITY, test_route) not in interfaces)
        pytest_assert("pre-down ip {} rule delete pref {} to {} table default"
                      .format(ip_type, FORCED_MGMT_ROUTE_PRIORITY, test_route) not in interfaces)

        # Check forced mgmt route removed from route table
        exist = wait_until(10, 1, 0, check_ip_rule_exist, duthost, test_route, False)
        pytest_assert(exist, "IP rule for {} should not exist.".format(test_route))
