import pytest
import logging

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from .static_dns_util import RESOLV_CONF_FILE, get_nameserver_from_config_db, get_nameserver_from_resolvconf, \
    config_mgmt_ip, clear_nameserver_from_resolvconf

logger = logging.getLogger(__name__)
allure.logger = logger


def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the rif loopback action tests.
    """

    parser.addoption(
        "--static_dns_reboot_type",
        action="store",
        type=str,
        default="cold",
        help="reboot type such as reload, cold, fast, warm, random"
    )

    parser.addoption(
        "--both_static_dynamic_ip_supported",
        action="store",
        type=bool,
        default=False,
        help="Both dynamic and static ip are configured on the dut"
    )


@pytest.fixture(scope="module", autouse=True)
def is_static_dns_supported(duthost):
    cmd_err = duthost.shell("show dns nameserver", module_ignore_errors=True)['stderr']
    if 'Error: No such command "dns"' in cmd_err:
        pytest.skip("The static DNS is not supported by this image.")


@pytest.fixture(scope="module", autouse=True)
def static_dns_setup(duthost):
    with allure.step("Get all existing DNS nameserver from config db"):
        nameservers_db = get_nameserver_from_config_db(duthost)

        duthost.shell(f"cp {RESOLV_CONF_FILE} {RESOLV_CONF_FILE}.bk")
        if not nameservers_db:
            nameservers = get_nameserver_from_resolvconf(duthost)
        else:
            nameservers = nameservers_db

    with allure.step("Clear all existing DNS nameserver from config db"):
        for nameserver in nameservers_db:
            duthost.shell(f"config dns nameserver del {nameserver}")

    with allure.step(f"Clear all existing DNS nameserver from {RESOLV_CONF_FILE}"):
        clear_nameserver_from_resolvconf(duthost)

    yield

    with allure.step("Recover DNS nameserver in config db"):
        for nameserver in nameservers:
            duthost.shell(f"config dns nameserver add {nameserver}")


@pytest.fixture(autouse=False)
def static_dns_clean(duthost):

    yield

    with allure.step("Clean up the nameserver in config db"):
        nameservers = get_nameserver_from_config_db(duthost)
        for nameserver in nameservers:
            duthost.shell(f"config dns nameserver del {nameserver}")


@pytest.fixture(scope='class')
def static_mgmt_ip_configured(duthost, mgmt_interfaces):
    with allure.step("Check the static ip address configured on the mgmt interface"):
        if not mgmt_interfaces:
            pytest.skip("No static ip address is configured, skip the test")

    yield


@pytest.fixture(scope='class')
def static_mgmt_ip_not_configured(duthost, mgmt_interfaces, request):
    dynamic_static_ip_configured = request.config.getoption("--both_static_dynamic_ip_supported")

    with allure.step("Check the static ip address configured on the mgmt interface"):
        if mgmt_interfaces:
            if dynamic_static_ip_configured:
                with allure.step("Delete the ip address from the mgmt port"):
                    config_mgmt_ip(duthost, mgmt_interfaces, "remove")
            else:
                pytest.skip("Static ip address is configured, skip the test")

    yield

    if mgmt_interfaces and dynamic_static_ip_configured:
        with allure.step("Config the static ip on the mgmt port"):
            config_mgmt_ip(duthost, mgmt_interfaces, "add")


@pytest.fixture(scope="class")
def mgmt_interfaces(duthost, tbinfo):
    ansible_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    mgmt_interface_info = ansible_facts["MGMT_INTERFACE"] if "MGMT_INTERFACE" in ansible_facts else {}
    return mgmt_interface_info
