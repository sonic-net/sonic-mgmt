import logging
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
SRC_MAC = "00:11:22:33:55"
EXP_ROOT_BRIDGE_ID = "8000000102030405"


def validate_root_bridge_id(duthost, vlan_id, stp_vlan_data):
    """
    Checks if the root_bridge_id in Redis matches the expected value for a given VLAN.
    Returns True if valid, else False.
    """
    if "root_bridge_id" not in stp_vlan_data:
        return False

    root_bridge_id = stp_vlan_data["root_bridge_id"]

    if root_bridge_id != EXP_ROOT_BRIDGE_ID:
        return False

    return True


def get_root_port(duthost, vlan_id, vlan_data):
    """
    Fetch the root port from _STP_VLAN_TABLE in Redis DB 0.

    :param duthost: The DUT host object
    :param vlan_id: VLAN ID (e.g., 100)
    :return: root_port (str)
    """
    root_port = vlan_data["root_port"]
    pytest_assert(root_port, f"Root port not found in {vlan_data}")
    return root_port


def get_port_state(duthost, vlan_id, port_name):
    """
    Fetch the port state for a given port from _STP_VLAN_PORT_TABLE in Redis DB 0.

    :param duthost: The DUT host object
    :param vlan_id: VLAN ID (e.g., 100)
    :param port_name: Name of the port (e.g., "Ethernet24")
    :return: port_state (str)
    """
    port_key = f"_STP_VLAN_PORT_TABLE:Vlan{vlan_id}:{port_name}"
    redis_cmd_port = f"redis-cli HGETALL {port_key}"
    port_output_raw = duthost.shell(redis_cmd_port, module_ignore_errors=True)

    redis_output_lines = port_output_raw.get("stdout_lines", [])
    port_data = dict(zip(redis_output_lines[::2], redis_output_lines[1::2]))

    port_state = port_data.get("port_state")

    pytest_assert(port_state, f"port_state not found in {port_key}")
    return port_state


def get_port_cost(port_name, duthost, vlan_id):
    """Get port cost from STP VLAN PORT table"""
    port_key = f"_STP_VLAN_PORT_TABLE:Vlan{vlan_id}:{port_name}"
    redis_cmd = f"redis-cli HGETALL {port_key}"
    port_output_raw = duthost.shell(redis_cmd, module_ignore_errors=True)

    redis_output_lines = port_output_raw.get("stdout_lines", [])
    port_data = dict(zip(redis_output_lines[::2], redis_output_lines[1::2]))

    port_cost = port_data.get("path_cost", "0")
    return int(port_cost)


def get_stp_vlan_data(duthost, vlan_id):
    """
    Fetch and parse STP_VLAN_TABLE from Redis APP_DB for the given VLAN ID.
    """
    redis_cmd = f"redis-cli HGETALL _STP_VLAN_TABLE:Vlan{vlan_id}"
    result = duthost.shell(redis_cmd, module_ignore_errors=True)
    output_lines = result.get("stdout_lines", [])
    return dict(zip(output_lines[::2], output_lines[1::2]))


def get_stp_bridge_priority_data(duthost, vlan_id):
    """
    Fetch and parse STP_VLAN_TABLE from Redis APP_DB for the given VLAN ID.
    """
    redis_cmd = f"redis-cli -n 4 HGETALL 'STP_VLAN|Vlan{vlan_id}'"
    result = duthost.shell(redis_cmd, module_ignore_errors=True)
    output_lines = result.get("stdout_lines", [])
    bridge_priority = dict(zip(output_lines[::2], output_lines[1::2]))
    return bridge_priority


def verify_stp_state(duthost, vlan_id, ports, expected_state, timeout=120, interval=2):
    """
    Waits for the given ports to reach the expected STP state and asserts success.

    Args:
        duthost: The DUT host.
        vlan_id: VLAN ID.
        ports: List of DUT ports to check.
        expected_state: The expected STP state ("LISTENING", "LEARNING", "FORWARDING", "BLOCKING").
        timeout: Total time to wait in seconds.
        interval: Time between each check in seconds.
    """
    for port in ports:
        success = wait_until(
            timeout, interval, 0,
            lambda p=port: get_port_state(duthost, vlan_id, p) == expected_state
        )
        current_state = get_port_state(duthost, vlan_id, port)
        pytest_assert(
            success,
            f"{port} did not enter {expected_state} state within timeout. "
            f"Current state: {current_state}"
        )


def get_port_operational_state_from_appdb(duthost, port_name):
    """Get port operational state from APP DB"""
    redis_cmd = f"redis-cli -n 0 HGET PORT_TABLE:{port_name} oper_status"
    result = duthost.shell(redis_cmd, module_ignore_errors=True)
    oper_status = result.get("stdout", "").strip()
    return oper_status


def get_port_admin_state_from_appdb(duthost, port_name):
    """Get port admin state from APP DB"""
    redis_cmd = f"redis-cli -n 0 HGET PORT_TABLE:{port_name} admin_status"
    result = duthost.shell(redis_cmd, module_ignore_errors=True)
    admin_status = result.get("stdout", "").strip()
    return admin_status


def fdb_table_has_dummy_mac_for_interface(duthost, interface, dummy_mac_prefix=""):
    res = duthost.command('fdbshow')
    for output_mac in res['stdout_lines']:
        if (interface in output_mac and (dummy_mac_prefix in output_mac or dummy_mac_prefix == "")):
            return True
    return False
