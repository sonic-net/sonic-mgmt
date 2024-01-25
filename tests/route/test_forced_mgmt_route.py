import pytest
import logging
import json

from tests.common.helpers.assertions import pytest_assert
from tests.syslog.syslog_utils import is_mgmt_vrf_enabled
from tests.override_config_table.utilities import backup_config, restore_config, \
        reload_minigraph_with_golden_config


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
    logging.warning("override_config: {}".format(override_config))
    reload_minigraph_with_golden_config(duthost, override_config)

    # Get interface and check config generate correct
    interfaces = duthost.command("cat /etc/network/interfaces")['stdout']
    logging.warning("interfaces: {}".format(interfaces))
    pytest_assert("iface eth1 inet static" in interfaces)
    pytest_assert("up ip -4 rule add pref 32764 to 172.17.1.1/24 table default" in interfaces)
    pytest_assert("pre-down ip -4 rule delete pref 32764 to 172.17.1.1/24 table default" in interfaces)
    pytest_assert("iface eth1 inet6 static" in interfaces)
    pytest_assert("up ip -6 rule add pref 32764 to fec1::fffe:afa:1/64 table default" in interfaces)
    pytest_assert("pre-down ip -6 rule delete pref 32764 to fec1::fffe:afa:1/64 table default" in interfaces)

    # startup eth1 and check forced mgmt route exist
    duthost.command("sudo ifup eth1")
    interfaces = duthost.command("show ip interfaces")
    logging.warning("show ip interfaces: {}".format(interfaces))

    # when eth1 up, forced mgmt route on thsi interface should exit
    ipv4_rules = duthost.command("ip rule list")["stdout"]
    logging.warning("ip rule list: {}".format(ipv4_rules))
    ipv6_rules = duthost.command("ip -6 rule list")["stdout"]
    logging.warning("ip -6 rule list: {}".format(ipv6_rules))
    pytest_assert("32764:	from all to 172.17.1.1/24 lookup default" in ipv4_rules)
    pytest_assert("32764:	from all to fec1::fffe:afa:1/64 lookup default" in ipv6_rules)

    # shutdown eth1 and check forced mgmt route exist
    duthost.command("sudo ifdown eth1")
    interfaces = duthost.command("show ip interfaces")
    logging.warning("show ip interfaces: {}".format(interfaces))

    # when eth1 down, forced mgmt route on thsi interface should not exit
    ipv4_rules = duthost.command("ip rule list")["stdout"]
    logging.warning("ip rule list: {}".format(ipv4_rules))
    ipv6_rules = duthost.command("ip -6 rule list")["stdout"]
    logging.warning("ip -6 rule list: {}".format(ipv6_rules))
    pytest_assert("32764:	from all to 172.17.1.1/24 lookup default" not in ipv4_rules)
    pytest_assert("32764:	from all to fec1::fffe:afa:1/64 lookup default" not in ipv6_rules)
