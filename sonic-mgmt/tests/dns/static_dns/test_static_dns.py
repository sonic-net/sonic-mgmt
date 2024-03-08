import pytest
import logging
import random
import re

from tests.common.reboot import reboot
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from .static_dns_util import RESOLV_CONF_FILE, verify_nameserver_in_config_db, verify_nameserver_in_conf_file, \
    get_nameserver_from_resolvconf, config_mgmt_ip, add_dns_nameserver, del_dns_nameserver, get_mgmt_port_ip_info, \
    get_nameserver_from_config_db, clear_nameserver_from_resolvconf


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)
allure.logger = logger

IPV4_UNICAST_ADDRESS = "1.1.1.1"
IPV6_UNICAST_ADDRESS = "fe80:1000:2000:3000::1"
IPV4_LOOPBACK_ADDRESS = "172.0.0.1"
IPV6_LOOPBACK_ADDRESS = "::1"

IPV4_UNICAST_ADDRESS_1 = "2.2.2.2"

# unsupported ip address in static dns
IPV4_MULTICAST_ADDRESS = "224.0.0.2"
IPV6_MULTICAST_ADDRESS = "ffx2::"

UNCONFIGURED_IP = "5.5.5.5"

INVALID_IP_ERR = r"Error: .* invalid nameserver ip address"
UNCONFIGURED_IP_ERR = r"Error: DNS nameserver .* is not configured"
EXCEED_MAX_ERR = r"Error: The maximum number \(3\) of nameservers exceeded"
DUPLICATED_IP_ERR = r"Error: .* nameserver is already configured"

MGMT_PORT = "eth0"
DHCLIENT_PID_FILE = "/run/dhclient-dns-test.pid"


def start_dhclient(duthost):
    duthost.shell(f"sudo dhclient -pf {DHCLIENT_PID_FILE} {MGMT_PORT}")


@pytest.fixture()
def stop_dhclient(duthost):
    yield

    if duthost.shell(f'ls {DHCLIENT_PID_FILE}', module_ignore_errors=True)['rc'] == 0:
        duthost.shell(f"sudo kill $(cat {DHCLIENT_PID_FILE})")
        duthost.shell(f"rm -rf {DHCLIENT_PID_FILE}")


@pytest.mark.disable_loganalyzer
def test_static_dns_basic(request, duthost, localhost, mgmt_interfaces):
    """
    Basic test for the Static DNS
    :param duthost: DUT host object
    :param localhost: localhost object
    :param mgmt_interfaces: mgmt interfaces information.
    """
    expected_nameservers = [IPV4_UNICAST_ADDRESS, IPV6_UNICAST_ADDRESS, IPV4_LOOPBACK_ADDRESS]
    with allure.step("Add DNS nameserver and verify it was added as expected"):
        for nameserver in expected_nameservers:
            add_dns_nameserver(duthost, nameserver)
        with allure.step("Verify the nameserver is configured as expected with cli show command"):
            verify_nameserver_in_config_db(duthost, expected_nameservers)
        with allure.step(f"Verify the content in {RESOLV_CONF_FILE} is as expected"):
            verify_nameserver_in_conf_file(duthost, expected_nameservers)

    with allure.step(f"Clear the {RESOLV_CONF_FILE} file and make sure that it is updated by restarting the "
                     f"resolve config service"):
        duthost.shell(f"echo > {RESOLV_CONF_FILE}")
        duthost.shell("systemctl restart resolv-config.service")
        verify_nameserver_in_conf_file(duthost, expected_nameservers)

    duthost.shell("config save -y")
    reboot_type = request.config.getoption("--static_dns_reboot_type")
    if reboot_type == "random":
        reload_types = ["reload", "cold", "fast", "warm"]
        reboot_type = random.choice(reload_types)
    with allure.step(f"Reload the system with command {reboot_type}"):
        if reboot_type == "reload":
            config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        else:
            reboot(duthost, localhost, reboot_type)
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "All critical services should be fully started!")
            pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
                          "Not all ports that are admin up on are operationally up")

    with allure.step("Verify the nameserver is persistent after reload"):
        with allure.step("Verify the nameserver in config db is persistent"):
            verify_nameserver_in_config_db(duthost, expected_nameservers)
        with allure.step(f"Verify nameserver in the {RESOLV_CONF_FILE} is persistent"):
            verify_nameserver_in_conf_file(duthost, expected_nameservers)

    pytest_assert(wait_until(180, 5, 0, duthost.is_host_service_running, "hostcfgd"), "hostcfgd is not running.")

    with allure.step("Delete nameserver"):
        for nameserver in expected_nameservers:
            del_dns_nameserver(duthost, nameserver)
        with allure.step("Verify the nameserver is configured as expected with cli show command"):
            verify_nameserver_in_config_db(duthost, [])

        with allure.step(f"Verify the content in {RESOLV_CONF_FILE} is as expected"):
            if mgmt_interfaces:
                verify_nameserver_in_conf_file(duthost, [])
            else:
                origin_dynamic_nameservers = get_nameserver_from_resolvconf(duthost, file_name=RESOLV_CONF_FILE + ".bk")
                verify_nameserver_in_conf_file(duthost, origin_dynamic_nameservers)


@pytest.mark.usefixtures('static_mgmt_ip_configured')
class TestStaticMgmtPortIP():
    def test_dynamic_dns_not_working_when_static_ip_configured(self, duthost, stop_dhclient):
        """
        Test to verify Dynamic DNS not work when static ip address is configured on the mgmt port
        :param duthost: DUT host object
        """
        with allure.step("Delete all DNS nameserver"):
            origin_nameservers = get_nameserver_from_config_db(duthost)
            for nameserver in origin_nameservers:
                del_dns_nameserver(duthost, nameserver)
        with allure.step(f"Clear all existing DNS nameserver from {RESOLV_CONF_FILE}"):
            clear_nameserver_from_resolvconf(duthost)

        with allure.step("Verify the nameservers are cleaned up"):
            verify_nameserver_in_config_db(duthost, [])
            verify_nameserver_in_conf_file(duthost, [])

        with allure.step("Renew dhcp to restore the dns configuration."):
            start_dhclient(duthost)
            verify_nameserver_in_conf_file(duthost, [])


@pytest.mark.usefixtures('static_mgmt_ip_not_configured')
class TestDynamicMgmtPortIP():
    def test_static_dns_is_not_changing_when_do_dhcp_renew(self, duthost, stop_dhclient):
        """
        Test case to verify Static DNS will not change when do dhcp renew for the mgmt port
        :param duthost: DUT host object
        """
        expected_nameservers = [IPV4_UNICAST_ADDRESS, IPV6_UNICAST_ADDRESS]

        with allure.step("Configure static DNS"):
            for nameserver in expected_nameservers:
                add_dns_nameserver(duthost, nameserver)
        with allure.step(f"Verify that {RESOLV_CONF_FILE} is updated"):
            with allure.step("Verify the nameserver is configured as expected with cli show command"):
                verify_nameserver_in_config_db(duthost, expected_nameservers)
            with allure.step(f"Verify the content in {RESOLV_CONF_FILE} is as expected"):
                verify_nameserver_in_conf_file(duthost, expected_nameservers)

        with allure.step("Renew dhcp to restore the dns configuration."):
            start_dhclient(duthost)

        with allure.step(f"Verify that {RESOLV_CONF_FILE} is not modified"):
            verify_nameserver_in_conf_file(duthost, expected_nameservers)

        with allure.step("Delete static DNS"):
            for nameserver in expected_nameservers:
                del_dns_nameserver(duthost, nameserver)

    @pytest.mark.usefixtures('static_mgmt_ip_not_configured')
    def test_dynamic_dns_working_when_no_static_ip_and_static_dns(self, duthost, stop_dhclient):
        """
        The test is to verify Dynamic DNS work as expected when no static ip configured on mgmt port and
        static DNS is configured.
        :param duthost: DUT host object
        """
        mgmt_interfaces = get_mgmt_port_ip_info(duthost)
        expected_nameservers = [IPV4_UNICAST_ADDRESS, IPV6_UNICAST_ADDRESS, IPV4_LOOPBACK_ADDRESS]
        origin_dynamic_nameservers = get_nameserver_from_resolvconf(duthost)
        with allure.step("Configure statically the same ip that was provided by dhcp."):
            config_mgmt_ip(duthost, mgmt_interfaces, "add")

        with allure.step("Add DNS nameserver and verify it was added as expected"):
            for nameserver in expected_nameservers:
                add_dns_nameserver(duthost, nameserver)

        with allure.step("Delete nameservers"):
            for nameserver in expected_nameservers:
                del_dns_nameserver(duthost, nameserver)
            with allure.step("Verify the nameserver is configured as expected with cli show command"):
                verify_nameserver_in_config_db(duthost, [])

            with allure.step(f"Verify the content in {RESOLV_CONF_FILE} is as expected"):
                verify_nameserver_in_conf_file(duthost, [])

        with allure.step("Remove the static IP"):
            config_mgmt_ip(duthost, mgmt_interfaces, "remove")

        with allure.step("Renew dhcp to restore the dns configuration."):
            start_dhclient(duthost)
            verify_nameserver_in_conf_file(duthost, origin_dynamic_nameservers)


@pytest.mark.usefixtures('static_dns_clean')
def test_static_dns_negative(duthost):
    """
    Negative test case, to verify the expected Err msg will be returned.
    :param duthost: DUT host object
    """
    with allure.step("Add DNS nameserver with ip address that not correct"):
        invalid_ip_err_msg_not_found_msg = "Err msg should be returned when dns nameserver ip is invalid"
        cmd_err = add_dns_nameserver(duthost, IPV4_MULTICAST_ADDRESS, module_ignore_errors=True)['stderr']
        assert re.search(INVALID_IP_ERR, cmd_err, re.IGNORECASE) is not None, invalid_ip_err_msg_not_found_msg
        cmd_err = add_dns_nameserver(duthost, IPV6_MULTICAST_ADDRESS, module_ignore_errors=True)['stderr']
        assert re.search(INVALID_IP_ERR, cmd_err, re.IGNORECASE) is not None, invalid_ip_err_msg_not_found_msg

    with allure.step("Delete DNS nameserver which does not exist in the config db"):
        unconfigured_ip_err_msg_not_found_msg = \
            "Err msg should be returned when try to delete dns nameserver which is not configured"
        cmd_err = del_dns_nameserver(duthost, UNCONFIGURED_IP, module_ignore_errors=True)['stderr']
        assert re.search(UNCONFIGURED_IP_ERR, cmd_err,
                         re.IGNORECASE) is not None, unconfigured_ip_err_msg_not_found_msg

    valid_nameservers = [IPV4_UNICAST_ADDRESS]
    with allure.step("Add 1 valid nameserver to config db"):
        for nameserver in valid_nameservers:
            add_dns_nameserver(duthost, nameserver)
    with allure.step("Verify the ip already added could not be added again"):
        duplicated_ip_err_msg_not_found = "Err msg should be returned when try to add dns nameserver that already added"
        cmd_err = add_dns_nameserver(duthost, IPV4_UNICAST_ADDRESS, module_ignore_errors=True)['stderr']
        assert re.search(DUPLICATED_IP_ERR, cmd_err,
                         re.IGNORECASE) is not None, duplicated_ip_err_msg_not_found

    valid_nameservers = [IPV6_UNICAST_ADDRESS, IPV4_LOOPBACK_ADDRESS]
    with allure.step("Add 2 more valid nameserver to config db"):
        for nameserver in valid_nameservers:
            add_dns_nameserver(duthost, nameserver)

    with allure.step("Verify the 4th nameserver could not be added"):
        exceed_max_err_msg_not_found = "Err msg should be returned when try to add 4th dns nameserver"
        cmd_err = add_dns_nameserver(duthost, IPV4_UNICAST_ADDRESS_1, module_ignore_errors=True)['stderr']
        assert re.search(EXCEED_MAX_ERR, cmd_err,
                         re.IGNORECASE) is not None, exceed_max_err_msg_not_found
