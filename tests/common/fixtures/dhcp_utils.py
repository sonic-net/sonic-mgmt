import re
import pytest
from tests.dhcp_relay.dhcp_relay_utils import restart_dhcp_service
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
import logging
logger = logging.getLogger(__name__)

@pytest.fixture()
def enable_sonic_dhcpv4_relay_agent(duthost, request):
    """
    Fixture to enable the DHCP relay feature flag and restart the service.
    """
    try:
        if request.getfixturevalue("relay_agent") == "sonic-relay-agent":
            match = re.search(r'(\d{8})', duthost.os_version)
            version_number = match.group()
            if version_number < "202511":
                pytest.skip(
                    f"Test skipped: sonic dhcpv4 is not supported in DUT image version: {duthost.os_version}"
                )

            duthost.shell('sonic-db-cli CONFIG_DB hset "FEATURE|dhcp_relay" "has_sonic_dhcpv4_relay" "True"', module_ignore_errors=True)
            duthost.shell('sudo config save -y', module_ignore_errors=True)
            restart_dhcp_service(duthost)
            # Checking DHCPV4 relay Process on DUT
            if "dut_dhcp_relay_data" in request.fixturenames:
                dut_dhcp_relay_data = request.getfixturevalue("dut_dhcp_relay_data")
                if dut_dhcp_relay_data:
                    pytest_assert(wait_until(40, 5, 0, check_process_and_socket_status, duthost, dut_dhcp_relay_data,
                                  "sonic_dhcpv4_process_check"))
        yield
    finally:
        # Cleanup: disable the feature flag
        if request.getfixturevalue("relay_agent") == "sonic-relay-agent":
            duthost.shell('sonic-db-cli CONFIG_DB hdel "FEATURE|dhcp_relay" "has_sonic_dhcpv4_relay"', module_ignore_errors=True)
            duthost.shell('sudo config save -y', module_ignore_errors=True)
            restart_dhcp_service(duthost)
            # Checking DHCP relay Process on DUT
            if "dut_dhcp_relay_data" in request.fixturenames:
                dut_dhcp_relay_data = request.getfixturevalue("dut_dhcp_relay_data")
                if dut_dhcp_relay_data:
                    pytest_assert(wait_until(40, 5, 0, check_process_and_socket_status, duthost, dut_dhcp_relay_data, "isc_dhcp_process_check"))
                    pytest_assert(wait_until(40, 5, 0, check_process_and_socket_status, duthost, dut_dhcp_relay_data, "sonic_dhcpv4_socket_check"))

def check_process_and_socket_status(duthost, dut_dhcp_relay_data=None, process_and_socket_check=None):
    """
    Check if the DHCP relay agent is running and listening on expected sockets.
    Works for dhcp4relay.

    """
    if process_and_socket_check == "sonic_dhcpv4_process_check":
        result = duthost.shell("docker exec -t dhcp_relay ps -aef | grep dhcp4relay", module_ignore_errors=True)
        output = result["stdout"]
        return "/usr/sbin/dhcp4relay" in output
    elif process_and_socket_check == "isc_dhcp_process_check":
        result = duthost.shell("docker exec -t dhcp_relay ps -aef | grep dhcrelay", module_ignore_errors=True)
        output = result["stdout"]
        return "/usr/sbin/dhcrelay" in output

    # If checking for socket bindings
    cmd = "docker exec -t dhcp_relay ss -nlp | grep dhcp4relay"
    result = duthost.shell(cmd, module_ignore_errors=True)
    output = result.get("stdout", "")

    if process_and_socket_check == "sonic_dhcpv4_socket_check":
        return output == ""

    # Basic static checks
    expected_static_patterns = [
        r"p_raw\s+UNCONN.*dhcp4relay",
        r"udp\s+UNCONN.*0\.0\.0\.0:67.*dhcp4relay"
    ]

    for pattern in expected_static_patterns:
        if not re.search(pattern, output):
            logger.error("Missing expected socket match: %s", pattern)
            return False

    # Validate presence of DHCPv4 socket for each downlink VLAN interface from test data
    if dut_dhcp_relay_data is None:
        logger.error("Missing dut_dhcp_relay_data for VLAN check")
        return False

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = dhcp_relay['downlink_vlan_iface']['name']
        vlan_pattern = r"%{}:67.*dhcp4relay".format(re.escape(vlan_iface))
        if not re.search(vlan_pattern, output):
            logger.error("Missing expected DHCPv4 VLAN socket for %s:67", vlan_iface)
            return False

    return True
