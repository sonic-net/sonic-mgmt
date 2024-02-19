import ipaddress
import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.override_config_table.utilities import backup_config, restore_config, \
        reload_minigraph_with_golden_config
from tests.syslog.syslog_utils import is_mgmt_vrf_enabled

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


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


def get_interface_reload_timestamp(duthost):
    timestamp = duthost.command("sudo systemctl show --no-pager interfaces-config"
                                " -p ExecMainExitTimestamp --value")["stdout"]
    logger.info("interfaces config timestamp {}".format(timestamp))

    return timestamp


def change_and_wait_interface_config_update(duthost, command, last_timestamp=None, timeout=10):
    if not last_timestamp:
        last_timestamp = get_interface_reload_timestamp(duthost)

    duthost.shell(command)

    # Wait interfaces-config service finish
    def log_exist(duthost):
        latest_timestamp = get_interface_reload_timestamp(duthost)
        return latest_timestamp != last_timestamp

    exist = wait_until(timeout, 1, 0, log_exist, duthost)
    pytest_assert(exist, "Not found interfaces-config update log: {}".format(command))


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

    # Skip multi-asic because override_config format are different.
    if 'eth1' in config_db_port:
        pytest.skip("Skip test_forced_mgmt_route_add_and_remove_by_mgmt_port_status for multi-mgmt device")

    # Add eth1 to mgmt interface and port
    config_db_mgmt_interface["eth1|10.250.1.101/24"] = {
        "forced_mgmt_routes": [
            "172.17.1.1/24"
        ],
        "gwaddr": "10.250.1.1"
    }
    config_db_mgmt_interface["eth1|fec1::ffff:afa:1/64"] = {
        "forced_mgmt_routes": [
            "fec1::fffe:afa:1/64"
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
    reload_minigraph_with_golden_config(duthost, override_config)

    # Get interface and check config generate correct
    interfaces = duthost.command("cat /etc/network/interfaces")['stdout']
    logging.debug("interfaces: {}".format(interfaces))
    pytest_assert("iface eth1 inet static" in interfaces)
    pytest_assert("up ip -4 rule add pref 32764 to 172.17.1.1/24 table default" in interfaces)
    pytest_assert("pre-down ip -4 rule delete pref 32764 to 172.17.1.1/24 table default" in interfaces)
    pytest_assert("iface eth1 inet6 static" in interfaces)
    pytest_assert("up ip -6 rule add pref 32764 to fec1::fffe:afa:1/64 table default" in interfaces)
    pytest_assert("pre-down ip -6 rule delete pref 32764 to fec1::fffe:afa:1/64 table default" in interfaces)

    # startup eth1 and check forced mgmt route exist
    duthost.command("sudo ifup eth1")
    interfaces = duthost.command("show ip interfaces")
    logging.debug("show ip interfaces: {}".format(interfaces))

    # when eth1 up, forced mgmt route on this interface should exit
    ipv4_rules = duthost.command("ip rule list")["stdout"]
    logging.debug("ip rule list: {}".format(ipv4_rules))
    ipv6_rules = duthost.command("ip -6 rule list")["stdout"]
    logging.debug("ip -6 rule list: {}".format(ipv6_rules))
    pytest_assert("32764:	from all to 172.17.1.1/24 lookup default" in ipv4_rules)
    pytest_assert("32764:	from all to fec1::fffe:afa:1/64 lookup default" in ipv6_rules)

    # shutdown eth1 and check forced mgmt route exist
    duthost.command("sudo ifdown eth1")
    interfaces = duthost.command("show ip interfaces")
    logging.debug("show ip interfaces: {}".format(interfaces))

    # when eth1 down, forced mgmt route on this interface should not exit
    ipv4_rules = duthost.command("ip rule list")["stdout"]
    logging.debug("ip rule list: {}".format(ipv4_rules))
    ipv6_rules = duthost.command("ip -6 rule list")["stdout"]
    logging.debug("ip -6 rule list: {}".format(ipv6_rules))
    pytest_assert("32764:	from all to 172.17.1.1/24 lookup default" not in ipv4_rules)
    pytest_assert("32764:	from all to fec1::fffe:afa:1/64 lookup default" not in ipv6_rules)


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
        change_and_wait_interface_config_update(duthost, command)

        # Check /etc/network/interfaces generate correct
        interfaces = duthost.command("cat /etc/network/interfaces")['stdout']
        logging.debug("interfaces: {}".format(interfaces))

        pytest_assert("up ip {} rule add pref 32764 to {} table default"
                      .format(ip_type, test_route) in interfaces)
        pytest_assert("pre-down ip {} rule delete pref 32764 to {} table default"
                      .format(ip_type, test_route) in interfaces)

        # Check forced mgmt route add to route table
        ip_rules = duthost.command("ip {} rule list".format(ip_type))["stdout"]
        logging.debug("ip {} rule list: {}".format(ip_type, ip_rules))
        pytest_assert("32764:	from all to {} lookup default".format(test_route) in ip_rules)

        # Revert current forced mgmt routes
        logging.debug("updated_forced_mgmt_routes: {}".format(original_forced_mgmt_routes))
        command = "sonic-db-cli CONFIG_DB HSET '{}' forced_mgmt_routes@ '{}'"\
                  .format(interface_key, original_forced_mgmt_routes)
        change_and_wait_interface_config_update(duthost, command)

        # Check /etc/network/interfaces generate correct
        interfaces = duthost.command("cat /etc/network/interfaces")['stdout']
        logging.debug("interfaces: {}".format(interfaces))
        pytest_assert("up ip {} rule add pref 32764 to {} table default"
                      .format(ip_type, test_route) not in interfaces)
        pytest_assert("pre-down ip {} rule delete pref 32764 to {} table default"
                      .format(ip_type, test_route) not in interfaces)

        # Check forced mgmt route add to route table
        ip_rules = duthost.command("ip {} rule list".format(ip_type))["stdout"]
        logging.debug("ip {} rule list: {}".format(ip_type, ip_rules))
        pytest_assert("32764:	from all to {} lookup default".format(test_route) not in ip_rules)
