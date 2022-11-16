import pytest
import ipaddress
import sys
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from conftest import create_vlan, remove_vlan

pytestmark = [
    pytest.mark.topology('mx'),
]

if sys.version_info.major == 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode


@pytest.fixture(scope="module")
def dhcp_common_setup_teardown(ptfhost, creds):
    # PTF setup, install dhcp client
    http_proxy = creds.get("proxy_env", {}).get("http_proxy", "")
    http_param = "-o Acquire::http::proxy='{}'".format(http_proxy) if http_proxy != "" else ""
    ptfhost.shell("apt-get {} update".format(http_param), module_ignore_errors=True)
    ptfhost.shell("apt-get {} install isc-dhcp-client -y".format(http_param))

    yield

    ptfhost.shell("apt-get remove isc-dhcp-client -y", module_ignore_errors=True)


def send_dhcp_request(ptfhost, sleep_time=15):
    ptfhost.shell("dhclient")
    time.sleep(sleep_time)


def send_dhcp_release(ptfhost):
    ptfhost.shell("dhclient -r")


def refresh_dut_mac_table(ptfhost, vlan_config, ptf_index_port):
    """
    ping from peer interface of DUT on ptf to refresh DUT mac table
    """
    for _, config in vlan_config.items():
        vlan_member = config["members"]
        vlan_ip = config["prefix"].split("/")[0]
        for member in vlan_member:
            ptf_port_index = ptf_index_port[member]
            ptfhost.shell("timeout 1 ping -c 1 -w 1 -I eth{} {}".format(ptf_port_index, vlan_ip), module_ignore_errors=True)


def dhcp_ip_assign_test(ptfhost, vlan_config, ptf_index_port):
    try:
        # Prepare
        send_dhcp_request(ptfhost)
        send_dhcp_release(ptfhost)

        send_dhcp_request(ptfhost, 30)
        ip_base = ipaddress.ip_address(UNICODE_TYPE("172.17.0.0"))
        for _, config in vlan_config.items():
            member_number = len(config["members"])
            # No need to verify single interface in a vlan
            if member_number == 1:
                continue

            vlan_members = config["members"]
            for port_index in vlan_members:
                ip = ip_base + port_index * 4 + 1
                ptf_port_name = "eth{}".format(ptf_index_port[port_index])

                output = ptfhost.shell("ip address show {}".format(ptf_port_name))['stdout']
                pytest_assert(str(ip) in output, "Can't get correct dhcp ip for {}".format(ptf_port_name))

    finally:
        send_dhcp_release(ptfhost)


def check_dnsmasq(duthost, intf_count):
    """
    Check whether dhcp ip pool is OK
    """
    command_output = duthost.shell("docker exec -i dhcp_relay wc -l /etc/dnsmasq.hosts", module_ignore_errors=True)
    if command_output['rc'] != 0:
        return False

    dnsmasq_count = int("".join([i for i in command_output['stdout'] if i.isdigit()]))
    return dnsmasq_count >= intf_count


def test_dhcp_server_tc1_ip_assign(duthost, ptfhost, mx_common_setup_teardown, dhcp_common_setup_teardown):
    dut_index_port, ptf_index_port, vlan_configs = mx_common_setup_teardown

    for config in vlan_configs:
        intf_count = create_vlan(duthost, config, dut_index_port)
        duthost.shell("sonic-clear fdb all")
        # Frequent restarts dhcp_relay service may cause start-limit-hit error, use this command to ignore and restart
        duthost.shell("systemctl reset-failed dhcp_relay", module_ignore_errors=True)
        duthost.restart_service("dhcp_relay")

        pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "dhcp_relay"),
                      "dhcp_relay not started")
        duthost.shell("docker exec -i dhcp_relay cat /dev/null > /etc/dnsmasq.hosts", module_ignore_errors=True)
        refresh_dut_mac_table(ptfhost, config, ptf_index_port)
        wait_until(600, 3, 0, check_dnsmasq, duthost, intf_count)

        dhcp_ip_assign_test(ptfhost, config, ptf_index_port)
        remove_vlan(duthost, config, dut_index_port)
