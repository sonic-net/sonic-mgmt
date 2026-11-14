import logging
import pytest
import random
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.device_utils import get_primary_fanout_peer
from tests.common.utilities import skip_release
from tests.common.mellanox_data import is_mellanox_device
from tests.common.utilities import wait_until
from tests.layer1.conftest import TestMACFaultMellanox, get_sfp_presence

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

SUPPORTED_PLATFORMS = ["arista_7060x6", "nvidia_sn6600_ld", "nvidia_sn5640", "nvidia_sn5600"]
WAIT_FOR_PORT_SHUTDOWN = 5
WAIT_FOR_PORT_STARTUP = 20
WAIT_FOR_PEER_RESET_PORT_SHUTDOWN = 10
WAIT_FOR_PEER_RESET_PORT_STARTUP = 120
PEER_RESET_PORT_SHUTDOWN_POLL_INTERVAL = 1
PEER_RESET_PORT_STARTUP_POLL_INTERVAL = 5
PEER_RESET_PORT_POLL_DELAY = 0
cmd_sfp_reset = "sudo sfputil reset"


@pytest.fixture(scope="session")
def vendor_specific_obj(duthost):
    if is_mellanox_device(duthost):
        return TestMACFaultMellanox()
    else:
        pytest.skip("Test is not implemented for this specific vendor")


class TestMACFault(object):
    @pytest.fixture(scope="class", autouse=True)
    def is_supported_platform(self, duthost, tbinfo, vendor_specific_obj):
        if 'ptp' not in tbinfo['topo']['name']:
            pytest.skip("Skipping test: Not applicable for non-PTP topology")

        if any(platform in duthost.facts['platform'] for platform in SUPPORTED_PLATFORMS):
            skip_release(duthost, ["201811", "201911", "202012", "202205", "202211", "202305", "202405"])
        else:
            pytest.skip("DUT has platform {}, test is not supported".format(duthost.facts['platform']))

        if not vendor_specific_obj.is_setting_support_feature(duthost):
            pytest.skip("Platform setting is not supported for this test")

    @staticmethod
    def get_mac_fault_count(dut, interface, fault_type):
        output = dut.show_and_parse("show int errors {}".format(interface))
        logging.info("Raw output for show int errors on {}: {}".format(interface, output))

        fault_count = 0
        for error_info in output:
            if error_info['port errors'] == fault_type:
                fault_count = int(error_info['count'])
                break

        logging.info("{} count on {}: {}".format(fault_type, interface, fault_count))
        return fault_count

    @staticmethod
    def get_interface_status(dut, interface):
        return dut.show_and_parse("show interfaces status {}".format(interface))[0].get("oper", "unknown")

    @pytest.fixture(scope="class", autouse=True)
    def reboot_dut(self, rand_selected_dut, localhost):
        from tests.common.reboot import reboot
        reboot(rand_selected_dut,
               localhost, safe_reboot=True, check_intf_up_ports=True)

    @pytest.fixture(scope="class")
    def available_interfaces(self, rand_selected_dut, vendor_specific_obj):
        dut = rand_selected_dut
        parsed_presence = get_sfp_presence(dut)
        test_available_ifaces, failed_api_ports = (
            vendor_specific_obj.return_available_interfaces(dut, parsed_presence)
        )

        return test_available_ifaces, failed_api_ports

    @pytest.fixture(scope="class")
    def select_random_interfaces(self, available_interfaces, collected_ports_num):
        test_available_ifaces, failed_api_ports = available_interfaces
        if not test_available_ifaces:
            pytest.skip("No interfaces available for this test were found.")

        test_ifaces = random.sample(test_available_ifaces,
                                    min(collected_ports_num, len(test_available_ifaces)))

        return test_ifaces, failed_api_ports

    @pytest.fixture(scope="class")
    def select_random_local_fault_interfaces(self, rand_selected_dut, available_interfaces,
                                             collected_ports_num, fanouthosts, vendor_specific_obj):
        dut = rand_selected_dut
        test_available_ifaces, failed_api_ports = available_interfaces
        rx_disable_supported = set(vendor_specific_obj.filter_rx_disable_supported_interfaces(
            dut, test_available_ifaces))
        peer_reset_supported = set(vendor_specific_obj.filter_fanout_resettable_interfaces(
            dut, test_available_ifaces, fanouthosts))
        test_available_ifaces = [
            intf for intf in test_available_ifaces
            if intf in rx_disable_supported or intf in peer_reset_supported
        ]
        if not test_available_ifaces:
            pytest.skip("No interfaces support RX disable or have a resettable fanout peer.")

        test_ifaces = random.sample(test_available_ifaces,
                                    min(collected_ports_num, len(test_available_ifaces)))

        return test_ifaces, failed_api_ports

    def toggle_iface(self, dut, interface):
        dut.command("sudo config interface shutdown {}".format(interface))
        pytest_assert(wait_until(10, 1, 0, lambda: self.get_interface_status(dut, interface) == "down"),
                      "Interface {} did not go down after shutdown".format(interface))

        dut.command("sudo config interface startup {}".format(interface))
        pytest_assert(wait_until(30, 1, 0, lambda: self.get_interface_status(dut, interface) == "up"),
                      "Interface {} did not come up after startup".format(interface))

    def reset_peer_module(self, dut, interface, fanout, fanout_port):
        """
        Reset the peer module instead of shutting the peer port: an admin down peer may keep its laser on
        and transmit local fault ordered sets, which the DUT counts as a remote fault.
        """
        cmd_sfp_reset_intf = "{} {}".format(cmd_sfp_reset, fanout_port)
        reset_result = fanout.host.command(cmd_sfp_reset_intf)
        pytest_assert(reset_result["rc"] == 0 and
                      "OK" in reset_result["stdout"] and
                      "Failed" not in reset_result["stdout"],
                      "'{}' failed on fanout {}: rc={}, stdout={}".format(
                          cmd_sfp_reset_intf, fanout.hostname,
                          reset_result["rc"], reset_result["stdout"]))

        pytest_assert(
            wait_until(WAIT_FOR_PEER_RESET_PORT_SHUTDOWN,
                       PEER_RESET_PORT_SHUTDOWN_POLL_INTERVAL,
                       PEER_RESET_PORT_POLL_DELAY,
                       lambda: self.get_interface_status(dut, interface) == "down"),
            "Interface {} did not go down after resetting peer port {} on fanout {}".format(
                interface, fanout_port, fanout.hostname))

        pytest_assert(
            wait_until(WAIT_FOR_PEER_RESET_PORT_STARTUP,
                       PEER_RESET_PORT_STARTUP_POLL_INTERVAL,
                       PEER_RESET_PORT_POLL_DELAY,
                       lambda: self.get_interface_status(dut, interface) == "up"),
            "Interface {} did not come up after peer port {} on fanout {} recovered from the reset".format(
                interface, fanout_port, fanout.hostname))

    def toggle_rx_output_on_iface(self, dut, interface):
        dut.shell("sudo sfputil debug rx-output {} disable".format(interface))
        time.sleep(WAIT_FOR_PORT_SHUTDOWN)
        pytest_assert(self.get_interface_status(dut, interface) == "down",
                      "Interface {iface} did not go down after 'sudo sfputil debug rx-output {iface} disable'"
                      .format(iface=interface))

        dut.shell("sudo sfputil debug rx-output {} enable".format(interface))
        time.sleep(WAIT_FOR_PORT_STARTUP)
        pytest_assert(self.get_interface_status(dut, interface) == "up",
                      "Interface {iface} did not come up after 'sudo sfputil debug rx-output {iface} enable'"
                      .format(iface=interface))

    def test_mac_local_fault_increment(self, select_random_local_fault_interfaces, rand_selected_dut,
                                       fanouthosts, vendor_specific_obj):
        dut = rand_selected_dut
        selected_ifaces, failed_api_ports = select_random_local_fault_interfaces
        rx_disable_supported = set(vendor_specific_obj.filter_rx_disable_supported_interfaces(
            dut, selected_ifaces))
        logging.info("Selected interfaces for tests: {}".format(selected_ifaces))

        for interface in selected_ifaces:
            self.toggle_iface(dut, interface)

            pytest_assert(self.get_interface_status(dut, interface) == "up",
                          "Interface {} was not up before triggering a local fault".format(interface))

            local_fault_before = self.get_mac_fault_count(dut, interface, "mac local fault")
            logging.info("Initial MAC local fault count on {}: {}".format(interface, local_fault_before))

            if interface in rx_disable_supported:
                self.toggle_rx_output_on_iface(dut, interface)
                fault_trigger = "disabling/enabling rx-output using sfputil"
            else:
                fanout, fanout_port = get_primary_fanout_peer(dut, interface, fanouthosts)
                self.reset_peer_module(dut, interface, fanout, fanout_port)
                fault_trigger = "resetting the peer module"

            local_fault_after = self.get_mac_fault_count(dut, interface, "mac local fault")
            logging.info("MAC local fault count after {} on {}: {}".format(
                fault_trigger, interface, local_fault_after))

            pytest_assert(local_fault_after > local_fault_before,
                          "MAC local fault count did not increment after {}".format(fault_trigger))

        pytest_assert(len(failed_api_ports) == 0, "Interfaces with failed API ports: {}".format(failed_api_ports))

    def test_mac_remote_fault_increment(self, select_random_interfaces, rand_selected_dut):
        dut = rand_selected_dut
        selected_ifaces, failed_api_ports = select_random_interfaces
        logging.info("Selected interfaces for tests: {}".format(selected_ifaces))

        for interface in selected_ifaces:
            self.toggle_iface(dut, interface)

            pytest_assert(self.get_interface_status(dut, interface) == "up",
                          "Interface {} was not up before disabling/enabling tx-output using sfputil".format(interface))

            remote_fault_before = self.get_mac_fault_count(dut, interface, "mac remote fault")
            logging.info("Initial MAC remote fault count on {}: {}".format(interface, remote_fault_before))

            dut.shell("sudo sfputil debug tx-output {} disable".format(interface))
            time.sleep(WAIT_FOR_PORT_SHUTDOWN)
            pytest_assert(self.get_interface_status(dut, interface) == "down",
                          "Interface {iface} did not go down after 'sudo sfputil debug tx-output {iface} disable'"
                          .format(iface=interface))

            dut.shell("sudo sfputil debug tx-output {} enable".format(interface))
            time.sleep(WAIT_FOR_PORT_STARTUP)

            pytest_assert(self.get_interface_status(dut, interface) == "up",
                          "Interface {iface} did not come up after 'sudo sfputil debug tx-output {iface} enable'"
                          .format(iface=interface))

            remote_fault_after = self.get_mac_fault_count(dut, interface, "mac remote fault")
            logging.info("MAC remote fault count after disabling/enabling tx-output using sfputil {}: {}".format(
                interface, remote_fault_after))

            pytest_assert(remote_fault_after > remote_fault_before,
                          "MAC remote fault count did not increment after disabling/enabling tx-output on the device")

        pytest_assert(len(failed_api_ports) == 0, "Interfaces with failed API ports: {}".format(failed_api_ports))
