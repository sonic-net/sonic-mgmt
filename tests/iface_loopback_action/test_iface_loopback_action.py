import pytest
import logging
import random
from tests.common.reboot import reboot
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from .iface_loopback_action_helper import ACTION_FORWARD, ACTION_DROP, NUM_OF_TOTAL_PACKETS
from .iface_loopback_action_helper import verify_traffic
from .iface_loopback_action_helper import config_loopback_action
from .iface_loopback_action_helper import clear_rif_counter
from .iface_loopback_action_helper import verify_interface_loopback_action
from .iface_loopback_action_helper import verify_rif_tx_err_count
from .iface_loopback_action_helper import shutdown_rif_interfaces, startup_rif_interfaces
from tests.common.platform.interface_utils import check_interface_status_of_up_ports


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)
allure.logger = logger


def test_loopback_action_basic(duthost, ptfadapter, ports_configuration):
    rif_interfaces = list(ports_configuration.keys())
    intf_count = len(rif_interfaces)
    with allure.step("Verify the rif loopback action default action: loopback traffic will be forwarded"):
        verify_traffic(duthost, ptfadapter, rif_interfaces, ports_configuration, [ACTION_FORWARD] * intf_count)
    with allure.step("Configure the loopback action to {}".format(ACTION_DROP)):
        config_loopback_action(duthost, rif_interfaces, [ACTION_DROP] * intf_count)
    with allure.step("Verify the loopback action is configured to drop"):
        with allure.step("Check the looback action is configured correctly with cli command"):
            verify_interface_loopback_action(duthost, rif_interfaces, [ACTION_DROP] * intf_count)
        with allure.step("Check the loopback traffic should be dropped"):
            with allure.step("Clear the rif counter"):
                clear_rif_counter(duthost)
            with allure.step("Check the traffic can not be received on the destination"):
                verify_traffic(duthost, ptfadapter, rif_interfaces, ports_configuration, [ACTION_DROP] * intf_count)
            with allure.step("Check the TX_ERR in rif counter statistic will increase"):
                verify_rif_tx_err_count(duthost, rif_interfaces, [NUM_OF_TOTAL_PACKETS]*intf_count)
    with allure.step("Configure the loopback action to forward"):
        config_loopback_action(duthost, rif_interfaces, [ACTION_FORWARD] * intf_count)
    with allure.step("Verify the loopback action is configured to forward"):
        with allure.step("Check the looback action is configured correctly with cli command"):
            verify_interface_loopback_action(duthost, rif_interfaces, [ACTION_FORWARD] * intf_count)
        with allure.step("Check the loopback traffic should be forwarded"):
            with allure.step("Clear the rif counter"):
                clear_rif_counter(duthost)
            with allure.step("Check the traffic can be received on the destination"):
                verify_traffic(duthost, ptfadapter, rif_interfaces, ports_configuration, [ACTION_FORWARD] * intf_count)
            with allure.step("Check the TX_ERR in rif counter statistic will not increase"):
                verify_rif_tx_err_count(duthost, rif_interfaces, [0] * intf_count)


def test_loopback_action_port_flap(duthost, ptfadapter, ports_configuration):
    rif_interfaces = list(ports_configuration.keys())
    # Remove the vlan interface since vlan interface can not be shutdown or startup
    rif_interfaces = [iface for iface in rif_interfaces if not iface.startswith("Vlan")]
    intf_count = len(rif_interfaces)
    action_list = [random.choice([ACTION_FORWARD, ACTION_DROP]) for i in range(intf_count)]
    count_list = [NUM_OF_TOTAL_PACKETS if action == ACTION_DROP else 0 for action in action_list]
    with allure.step("Configure the loopback action for {} to {}".format(rif_interfaces, action_list)):
        config_loopback_action(duthost, rif_interfaces, action_list)
    with allure.step("Shutdown the interfaces"):
        shutdown_rif_interfaces(duthost, rif_interfaces)
    with allure.step("Startup the interfaces"):
        startup_rif_interfaces(duthost, rif_interfaces)
    with allure.step("Verify the loopback action is correct of port flap"):
        with allure.step("Check the looback action is configured correctly with cli command"):
            verify_interface_loopback_action(duthost, rif_interfaces, action_list)
        with allure.step("Check the loopback traffic"):
            with allure.step("Clear the rif counter"):
                clear_rif_counter(duthost)
            with allure.step("Check the traffic can be received or dropped as expected"):
                verify_traffic(duthost, ptfadapter, rif_interfaces, ports_configuration, action_list)
            with allure.step("Check the TX_ERR in rif counter statistic will increase or not as expected"):
                verify_rif_tx_err_count(duthost, rif_interfaces, count_list)


def test_loopback_action_reload(request, duthost, localhost, ptfadapter, ports_configuration):
    rif_interfaces = list(ports_configuration.keys())
    intf_count = len(rif_interfaces)
    action_list = [random.choice([ACTION_FORWARD, ACTION_DROP]) for i in range(intf_count)]
    count_list = [NUM_OF_TOTAL_PACKETS if action == ACTION_DROP else 0 for action in action_list]
    with allure.step("Configure the loopback action for {} to {}".format(rif_interfaces, action_list)):
        config_loopback_action(duthost, rif_interfaces, action_list)
    with allure.step("Save configuration"):
        duthost.shell("config save -y")
    with allure.step("System reload"):

        reboot_type = request.config.getoption("--rif_loppback_reboot_type")
        if reboot_type == "random":
            reload_types = ["reload", "cold", "fast", "warm"]
            reboot_type = random.choice(reload_types)
        if reboot_type == "reload":
            config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        else:
            reboot(duthost, localhost, reboot_type)
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "All critical services should be fully started!")
            pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
                          "Not all ports that are admin up on are operationally up")
    with allure.step("Verify the loopback action is correct after config reload"):
        with allure.step("Check the looback action is configured correctly with cli command"):
            verify_interface_loopback_action(duthost, rif_interfaces, action_list)
        with allure.step("Check the loopback traffic"):
            with allure.step("Clear the rif counter"):
                clear_rif_counter(duthost)
            with allure.step("Check the traffic can be received or dropped as expected"):
                verify_traffic(duthost, ptfadapter, rif_interfaces, ports_configuration, action_list)
            with allure.step("Check the TX_ERR in rif counter statistic will increase or not as expected"):
                verify_rif_tx_err_count(duthost, rif_interfaces, count_list)
