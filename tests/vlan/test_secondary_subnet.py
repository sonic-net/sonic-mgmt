import logging
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_ports import get_secondary_subnet
from tests.common.helpers.dut_ports import get_vlan_interface_list


pytestmark = [pytest.mark.topology("t0", "m0")]

logger = logging.getLogger(__name__)

SECONDARY_IP = "66.66.66.66/23"


def check_secondary_ip_interface(duthost, vlan_interface, secondary_ip):
    ip_interfaces_list = duthost.show_and_parse("show ip interface")

    # Convert the list to a more usable format
    ip_interface_dict = {}
    last_interface = None

    # Process the list to handle empty interface names
    for item in ip_interfaces_list:
        interface_name = item.get("interface", "")
        if not interface_name and last_interface:
            interface_name = last_interface
        else:
            last_interface = interface_name

        # If this is the first time we're seeing this interface, create a list for it
        if interface_name not in ip_interface_dict:
            ip_interface_dict[interface_name] = []

        # Add the ip address details
        ip_interface_dict[interface_name].append(item)

    # Check if vlan_interface exists in the processed data
    found_secondary_ip = False
    if vlan_interface in ip_interface_dict:
        for item in ip_interface_dict[vlan_interface]:
            if item["ipv4 address/mask"] == secondary_ip:
                found_secondary_ip = True
                logger.info(f"Found {secondary_ip} on {vlan_interface}")
                break
    return found_secondary_ip, ip_interface_dict


def check_secondary_subnet_exist(duthost, vlan_interface, ip_address):
    """
    Verify that a secondary IP subnet exists and is properly configured.
    This function performs multiple checks to verify that a secondary IP address is properly
    configured on a VLAN interface:
    1. Checks that the secondary IP appears in the "show ip interface" command output
    2. Verifies that the secondary IP is stored correctly in Redis database
    3. Confirms that the "secondary" property is set to "true" in Redis
    Args:
        duthost: DUT (Device Under Test) host object that provides the SSH connection
        vlan_interface (str): The name of the VLAN interface (e.g., "Vlan1000")
        ip_address (str): The secondary IP address to check for
    Raises:
        AssertionError: If any verification step fails
    """
    # Step 1: Verify secondary IP appears in "show ip interface" output
    found_secondary_ip, ip_interfaces_dict = check_secondary_ip_interface(
        duthost, vlan_interface, ip_address
    )
    pytest_assert(
        found_secondary_ip,
        f"Secondary IP {ip_address} not found for {vlan_interface} in IP interface list",
    )
    pytest_assert(
        vlan_interface in ip_interfaces_dict,
        f"Interface {vlan_interface} not found in structured output",
    )

    # Step 2: Verify secondary IP is stored in Redis
    redis_key = f"VLAN_INTERFACE|{vlan_interface}|{ip_address}"
    redis_output = duthost.command(f'sudo redis-cli -n 4 KEYS "{redis_key}"')
    pytest_assert(
        redis_key in redis_output["stdout"],
        f"Secondary IP {ip_address} not found in Redis database",
    )

    # Step 5: Verify "secondary" property is set to "true" in Redis
    redis_value = duthost.command(f'sudo redis-cli -n 4 HGETALL "{redis_key}"')
    pytest_assert(
        "secondary" in redis_value["stdout"],
        f"'secondary' field not found for {redis_key} in Redis",
    )
    pytest_assert(
        "true" in redis_value["stdout"],
        f"'secondary' field not set to 'true' for {redis_key} in Redis",
    )


def check_secondary_subnet_not_exist(duthost, vlan_interface, ip_address):
    """
    Verify that a secondary IP subnet does not exist on a VLAN interface.
    This function performs multiple checks to ensure that a secondary IP address is not
    configured on a VLAN interface:
    1. Checks that the secondary IP does not appear in the "show ip interface" command output
    2. Verifies that the secondary IP is not stored in Redis database
    Args:
        duthost: DUT (Device Under Test) host object that provides the SSH connection
        vlan_interface (str): The name of the VLAN interface (e.g., "Vlan1000")
        ip_address (str): The secondary IP address to check for
    Raises:
        AssertionError: If any verification step fails
    """
    # Step 1: Verify secondary IP is removed from show output
    found_secondary_ip, ip_interfaces_dict = check_secondary_ip_interface(
        duthost, vlan_interface, ip_address
    )
    pytest_assert(
        not found_secondary_ip,
        f"Secondary IP {ip_address} found for {vlan_interface} after removal",
    )

    # Step 2: Verify secondary IP is removed from Redis
    redis_key = f"VLAN_INTERFACE|{vlan_interface}|{ip_address}"
    redis_output = duthost.command(f'sudo redis-cli -n 4 KEYS "{redis_key}"')
    pytest_assert(
        redis_key not in redis_output["stdout"],
        f"Secondary IP {SECONDARY_IP} still found in Redis db after removal",
    )


def test_existing_secondary_subnet(duthost, tbinfo):
    """
    Test to verify existing secondary subnets on VLAN interfaces.

    1. Check if the DUT already has a secondary subnet
    2. If found, verify secondary ip address info is correct
    """
    # Step 1: Check if DUT has any secondary subnet configured
    exist_flag, vlan_interface, ip_version, int_dict = get_secondary_subnet(
        duthost, tbinfo
    )

    if not exist_flag:
        pytest.skip("No secondary subnet found on DUT, skipping test")
    if ip_version == "ipv6":
        pytest.fail(
            "Secondary subnet is IPv6, vlan interface information is not correct"
        )

    secondary_ip = int_dict["addr"] + "/" + str(int_dict["prefixlen"])

    check_secondary_subnet_exist(duthost, vlan_interface, secondary_ip)


def test_secondary_subnet(duthost):
    """
    Test secondary subnet functionality on a VLAN interface.

    1. Add a secondary IP to a VLAN interface
    2. Verify it appears in "show ip interface" output
    3. Verify it's stored in Redis
    4. Remove the secondary IP
    5. Verify it's removed from both CLI output and Redis
    """
    # Step 1: Add secondary IP to VLAN interface
    vlan_interfaces = get_vlan_interface_list(duthost)
    # pick up the first vlan to test
    vlan_interface = vlan_interfaces[0]

    duthost.command(
        f"sudo config interface ip add {vlan_interface} {SECONDARY_IP} --secondary"
    )
    time.sleep(2)
    # Step 2: Verify secondary subnet info is added
    check_secondary_subnet_exist(duthost, vlan_interface, SECONDARY_IP)

    # Step 3: Remove the secondary IP
    duthost.command(f"sudo config interface ip remove {vlan_interface} {SECONDARY_IP}")
    time.sleep(2)

    # Step 4: Verify secondary subnet info is removed
    check_secondary_subnet_not_exist(duthost, vlan_interface, SECONDARY_IP)
