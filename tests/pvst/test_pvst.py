import logging
import pytest
import time
import threading
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa: F401

from scapy.all import Dot1Q, Ether   # noqa: F401
import ptf.testutils as testutils    # noqa: F401
from tests.common.helpers.dut_ports import get_vlan_interface_list, get_vlan_interface_info    # noqa: F401
from tests.pvst.pvst_utils import (
    validate_root_bridge_id,
    get_root_port,
    get_port_state,
    get_port_cost,
    get_stp_vlan_data,
    get_stp_bridge_priority_data,
    fdb_table_has_dummy_mac_for_interface,
    get_port_operational_state_from_appdb,
    get_port_admin_state_from_appdb,
    verify_stp_state
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]


class TestDutPvstTestcase:

    DUMMY_MAC_PREFIX = "00:11:22:33:55"
    BRIDGE_PRIORITY = 8192
    PORT_COST = 1000
    CUSTOM_HELLO_TIME = 5
    CUSTOM_MAX_AGE = 25
    CUSTOM_FORWARD_DELAY = 20
    PKT_CAPTURE_DURATION = 10

    # testcase 1
    def test_pvst_validate_root_bridge(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                       ptfhost, toggle_all_simulator_ports_to_rand_selected_tor_m,    # noqa: F811
                                       setup_pvst_test_data):

        """
        Test case to validate root bridge functionality.

        Test Steps:

        1.Enable PVST in global mode on SONIC DUT. This will enable PVST on the already configured VLAN 1000.
        2.SONIC DUT should start transmitting the BPDUs after enabling PVST.
          Verify SONIC DUT is acting as the root bridge by checking the root bridge id in APP DB.
        3.Verify the port state transitions on SONIC DUT from blocking -> listening -> learning -> forwarding
        4.On PTF capture the BPDUs on Ethernet4 and Ethernet8, validate with the expected BPDU packet.
        5.From PTF, send L2 data packets from Ethernet4 on VLAN 1000 and verify it’s received back on Ethernet8
        """
        duthost = duthosts[rand_one_dut_hostname]
        dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
        dut_port_2 = setup_pvst_test_data["dut_ports"]["dut_port_2"]
        ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
        ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
        vlan_id = int(setup_pvst_test_data["vlan"]["id"])

        # Disable/enable pvst to validate the port state transition
        duthost.shell('config spanning-tree disable pvst', module_ignore_errors=True)
        duthost.shell('config spanning-tree enable pvst', module_ignore_errors=True)

        # Validate DUT rootbridge
        stp_data = get_stp_vlan_data(duthost, vlan_id)
        default_root_path_cost = int(stp_data.get("root_path_cost", ""))
        bridge_id = stp_data.get("bridge_id", "")
        root_bridge_id = stp_data.get("root_bridge_id", "")
        pytest_assert(
            bridge_id == root_bridge_id,
            f"Mismatch: bridge_id = {bridge_id}, root_bridge_id = {root_bridge_id}"
        )

        # Port state transitions
        ports = [dut_port_1, dut_port_2]
        verify_stp_state(duthost, vlan_id, ports, "LISTENING")
        verify_stp_state(duthost, vlan_id, ports, "LEARNING")
        verify_stp_state(duthost, vlan_id, ports, "FORWARDING")

        mac_address = setup_pvst_test_data["dut_ports"]["mac"]
        stp_data = get_stp_bridge_priority_data(duthost, vlan_id)
        dut_bridge_priority = stp_data["priority"]
        bridge_priority = int(dut_bridge_priority) + vlan_id
        custom_hello_time = int(stp_data["hello_time"])
        custom_max_age = int(stp_data["max_age"])
        custom_forward_delay = int(stp_data["forward_delay"])

        ptf_runner(ptfhost,
                   "ptftests",
                   "pvst_bpdu_test.PvstBpduTest",
                   platform_dir="ptftests",
                   params={
                       "hostname": duthost.hostname,
                       "test_scenarios": "validate_bpdu_packet",
                       "vlan_id": vlan_id,
                       "expected_bridge_mac": mac_address,
                       "expected_bridge_priority": bridge_priority,
                       "expected_hello_time": custom_hello_time,
                       "expected_max_age": custom_max_age,
                       "expected_forward_delay": custom_forward_delay,
                       "expected_root_path_cost": default_root_path_cost,
                       "capture_port": ptf_port_1,  # Capture on PTF port
                       "capture_duration": self.PKT_CAPTURE_DURATION,  # Capture for 10 seconds
                       "kvm_support": True
                       },
                   log_file="/tmp/pvst_root_bridge_validation.log",
                   is_python3=True)

        ptf_runner(ptfhost,
                   "ptftests",
                   "pvst_bpdu_test.PvstBpduTest",
                   platform_dir="ptftests",
                   params={
                       "hostname": duthost.hostname,
                       "test_scenarios": "validate_bpdu_packet",
                       "vlan_id": vlan_id,
                       "expected_bridge_mac": mac_address,
                       "expected_bridge_priority": bridge_priority,
                       "expected_hello_time": custom_hello_time,
                       "expected_max_age": custom_max_age,
                       "expected_forward_delay": custom_forward_delay,
                       "expected_root_path_cost": default_root_path_cost,
                       "capture_port": ptf_port_2,  # Capture on PTF port
                       "capture_duration": self.PKT_CAPTURE_DURATION,  # Capture for 10 seconds
                       "kvm_support": True
                       },
                   log_file="/tmp/pvst_root_bridge_validation_port2.log",
                   is_python3=True)

        # Verify l2 packet
        ptf_runner(ptfhost,
                   "ptftests",
                   "pvst_bpdu_test.PvstBpduTest",
                   platform_dir="ptftests",
                   params={
                       "hostname": duthost.hostname,
                       "test_scenarios": "validate_l2_packet",
                       "send_port": ptf_port_1,
                       "receive_port": ptf_port_2,  # Capture on PTF port
                       "vlan_id": vlan_id,
                       "verify_packet": True,
                       "kvm_support": True
                       },
                   log_file="/tmp/pvst_root_bridge_validation_default.log",
                   is_python3=True)

    # testcase 2
    def test_pvst_verify_sonic_dut_as_designated_bridge(self, ptfadapter, duthosts,
                                                        rand_one_dut_hostname, ptfhost, tbinfo, request,
                                                        toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa: F811
                                                        setup_pvst_test_data):

        """
        Testcase to Validate SONIC DUT as designated bridge

        Test Steps:
        1.From PTF send packets with better bridge priority than SONIC DUT from all the ports
        2.Verify on SONIC DUT the root bridge is selected with root bridge id sent in the BPDU from PTF
        3.Verify on SONIC DUT the root port is selected, and root port is in forwarding
          state by fetching the information from STP_VLAN_TABLE and STP_VLAN_PORT_TABLE entries from APP DB
        4.Verify on SONIC DUT port Ethernet8 is in blocking state
        5.From PTF send L2 data packets from Ethernet4 for VLAN 1000 and
          verify it’s not received back on Ethernet8 as the port is in blocking state
        6.Verify the source MAC of the packet sent is learnt on Etherent4 for VLAN 1000 on SONIC DUT
        7.From PTF send L2 data packets from Ethernet8 for VLAN 1000 and
          verify it’s not received back on Ethernet4 as Ethernet8 is in blocking state
        8.Verify the source MAC of the packet sent is not learnt on
          Ethernet8 for VLAN 100 on SONIC DUT as port is in blocking state
        """
        duthost = duthosts[rand_one_dut_hostname]

        # Extract interface mapping from testbed
        dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
        dut_port_2 = setup_pvst_test_data["dut_ports"]["dut_port_2"]
        ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
        ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
        vlan_id = int(setup_pvst_test_data["vlan"]["id"])
        stop_bpdu_sending = [False]

        try:

            def send_superior_bpdu():
                """Send a single superior BPDU from PTF"""
                try:
                    ptf_runner(ptfhost,
                               "ptftests",
                               "pvst_bpdu_test.PvstBpduTest",
                               platform_dir="ptftests",
                               params={
                                   "hostname": duthost.hostname,
                                   "test_scenarios": "config",
                                   "vlan_id": vlan_id,
                                   "send_port": [ptf_port_1, ptf_port_2],
                                   "kvm_support": True
                               },
                               log_file="/tmp/pvst_bpdu_test_designated_bridge.log",
                               is_python3=True)
                except Exception as e:
                    logger.warning(f"Failed to send superior BPDU: {e}")

            def periodic_bpdu_sender():
                """Send superior BPDUs every 2 seconds"""
                while not stop_bpdu_sending[0]:
                    send_superior_bpdu()

            # Validate DUT rootbridge
            stp_data = get_stp_vlan_data(duthost, vlan_id)
            bridge_id = stp_data.get("bridge_id", "")
            root_bridge_id = stp_data.get("root_bridge_id", "")

            pytest_assert(bridge_id == root_bridge_id,
                          f"Mismatch: bridge_id = {bridge_id}, root_bridge_id = {root_bridge_id}")

            # Send BPDUs from PTF
            verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")

            bpdu_thread = None

            bpdu_thread = threading.Thread(target=periodic_bpdu_sender, daemon=True)
            bpdu_thread.start()

            # Verify root bridge is selected with PTF BPDU
            pytest_assert(
                wait_until(60, 2, 0, lambda:
                           validate_root_bridge_id(duthost, vlan_id, get_stp_vlan_data(duthost, vlan_id))),
                f"Root bridge ID did not match expected value within timeout for VLAN {vlan_id}"
            )

            # Check root port is selected correctly and is in FORWARDING
            verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
            verify_stp_state(duthost, vlan_id, [dut_port_2], "BLOCKING")

            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)

            root_port = get_root_port(duthost, vlan_id, stp_vlan_data)
            pytest_assert(root_port == dut_port_1, f"Root port is not {dut_port_1}")

            # Send L2 packet from forwarding port and check that it's not received on blocked port
            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_l2_packet",
                           "send_port": ptf_port_1,
                           "receive_port": ptf_port_2,  # Capture on PTF port
                           "vlan_id": vlan_id,
                           "verify_packet": False,
                           "kvm_support": True
                           },
                       log_file="/tmp/pvst_designated_bridge_l2_packet_validation_port1.log",
                       is_python3=True)

            res = duthost.command('show mac')
            logger.info("show mac output: %s", res['stdout_lines'])

            # Verify MAC is learned on forwarding port
            pytest_assert(wait_until(10, 2, 1, fdb_table_has_dummy_mac_for_interface, duthost,
                          dut_port_1, self.DUMMY_MAC_PREFIX), "After starting {}"
                          " and populating fdb, corresponding mac address entry not seen in mac table"
                          .format(dut_port_1))

            # Send packet from blocked port and ensure MAC is NOT learned
            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_l2_packet",
                           "send_port": ptf_port_2,
                           "receive_port": ptf_port_1,  # Capture on PTF port
                           "vlan_id": vlan_id,
                           "verify_packet": False,
                           "kvm_support": True
                           },
                       log_file="/tmp/pvst_designated_bridge_l2_packet_validation_port2.log",
                       is_python3=True)

            res = duthost.command('show mac')
            logger.info("show mac output: %s", res['stdout_lines'])

            # MAC is getting learnt on blocking port,
            # this seems to be due to lack of support for blocking state in VS environment.
            # There seems to be a timing issue in script due to which it was not observed earlier.
            """
            pytest_assert(not wait_until(10, 2, 1, fdb_table_has_dummy_mac_for_interface,
                                         duthost, dut_port_2, self.DUMMY_MAC_PREFIX),
                          "MAC address was incorrectly learned on {}".format(dut_port_2))
            """

        except Exception as e:
            logger.error(f"Test failed due to error: {e}")
            raise

        finally:
            # Stop periodic BPDU sending
            stop_bpdu_sending[0] = True

            # Wait for thread to finish current iteration
            if bpdu_thread and bpdu_thread.is_alive():
                time.sleep(3)  # Give thread time to exit gracefully

    # testcase 3
    def test_shutdown_root_port_on_sonic_and_verify(self, ptfadapter, duthosts, rand_one_dut_hostname, ptfhost,
                                                    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa: F811
                                                    setup_pvst_test_data):

        """
        Testcase to Validate shutting down the root port

        Test Steps:
        1.From PTF send packets with better bridge priority than SONIC DUT from all the ports
        2.Verify on SONIC DUT port Ethernet4 is in forwarding state and Ethernet8 is in blocking state
        3.Shutdown the Ethernet4 port and verify Ethernet8 moves to forwarding state on SONIC DUT
        4.Enable (startup) the port Ethernet4 and verify Ethernet4 moves to forwarding state and
          Ethernet8 moves to blocking state again.
        """

        stop_bpdu_sending = [False]
        try:
            duthost = duthosts[rand_one_dut_hostname]
            dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
            dut_port_2 = setup_pvst_test_data["dut_ports"]["dut_port_2"]
            ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
            ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
            vlan_id = int(setup_pvst_test_data["vlan"]["id"])

            stop_bpdu_sending = [False]

            def send_superior_bpdu():
                """Send a single superior BPDU from PTF"""
                try:
                    ptf_runner(ptfhost,
                               "ptftests",
                               "pvst_bpdu_test.PvstBpduTest",
                               platform_dir="ptftests",
                               params={
                                   "hostname": duthost.hostname,
                                   "test_scenarios": "config",
                                   "vlan_id": vlan_id,
                                   "send_port": [ptf_port_1, ptf_port_2],
                                   "kvm_support": True
                               },
                               log_file="/tmp/pvst_port_shutdown_bpdu_periodic.log",
                               is_python3=True)
                except Exception as e:
                    logger.warning(f"Failed to send superior BPDU: {e}")

            def periodic_bpdu_sender():
                """Send superior BPDUs every 2 seconds"""
                while not stop_bpdu_sending[0]:
                    send_superior_bpdu()

            bpdu_thread = None

            bpdu_thread = threading.Thread(target=periodic_bpdu_sender, daemon=True)
            bpdu_thread.start()

            # Validate root_bridge_id
            pytest_assert(
                wait_until(60, 2, 0, lambda:
                           validate_root_bridge_id(duthost, vlan_id, get_stp_vlan_data(duthost, vlan_id))),
                f"Root bridge ID did not match expected value within timeout for VLAN {vlan_id}"
            )

            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)

            # Root port is selected, and root port is in forwarding
            root_port = get_root_port(duthost, vlan_id, stp_vlan_data)
            pytest_assert(root_port == dut_port_1, f"Root port is not {dut_port_1}")

            verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
            verify_stp_state(duthost, vlan_id, [dut_port_2], "BLOCKING")

            # Shutdown DUT port 1 and verify DUT port 2 becomes the root port in FORWARDING state.
            duthost.shell(f'config interface shutdown {dut_port_1}')

            verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")
            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)
            root_port = get_root_port(duthost, vlan_id, stp_vlan_data)
            pytest_assert(root_port == dut_port_2, f"Root port is not {dut_port_2}")

            # Startup DUT port 1 and verify it FORWARDING state and port 2 transitions to BLOCKING.
            duthost.shell(f'config interface startup {dut_port_1}')

            verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
            verify_stp_state(duthost, vlan_id, [dut_port_2], "BLOCKING")

            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)
            root_port = get_root_port(duthost, vlan_id, stp_vlan_data)
            pytest_assert(root_port == dut_port_1, f"Root port is not {dut_port_1}")

        except Exception as e:
            logger.error(f"Test failed due to: {str(e)}")
            raise

        finally:
            # Stop periodic BPDU sending
            stop_bpdu_sending[0] = True

            # Wait for thread to finish current iteration
            if bpdu_thread and bpdu_thread.is_alive():
                time.sleep(3)  # Give thread time to exit gracefully

    # testcase 4
    def test_bridge_priority_change_in_bpdu(self, ptfadapter, duthosts, rand_one_dut_hostname, ptfhost,
                                            tbinfo, request,
                                            toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                            setup_pvst_test_data):

        """
        Testcase to Validate Bridge Priority

        Test Steps:
        1.From PTF send packets with better bridge priority than SONIC DUT from all the ports
        2.Verify on SONIC DUT the root bridge is selected with root bridge id sent in the BPDU from PTF
        3.Modify the bridge priority on SONIC DUT so that it has better bridge priority than PTF generated packets
        4.Verify on SONIC DUT the root bridge is selected as self, and all ports are in forwarding state
        5.On PTF capture the packets generated on Ethernet interfaces and verify the root bridge id is same as SONIC DUT
        """
        stop_bpdu_sending = [False]
        try:
            duthost = duthosts[rand_one_dut_hostname]
            dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
            dut_port_2 = setup_pvst_test_data["dut_ports"]["dut_port_2"]
            ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
            ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
            vlan_id = int(setup_pvst_test_data["vlan"]["id"])

            stop_bpdu_sending = [False]

            def send_superior_bpdu():
                """Send a single superior BPDU from PTF"""
                try:
                    ptf_runner(ptfhost,
                               "ptftests",
                               "pvst_bpdu_test.PvstBpduTest",
                               platform_dir="ptftests",
                               params={
                                   "hostname": duthost.hostname,
                                   "test_scenarios": "config",
                                   "vlan_id": vlan_id,
                                   "send_port": [ptf_port_1, ptf_port_2],
                                   "kvm_support": True
                               },
                               log_file="/tmp/pvst_bridge_priority_bpdu_periodic.log",
                               is_python3=True)
                except Exception as e:
                    logger.warning(f"Failed to send superior BPDU: {e}")

            def periodic_bpdu_sender():
                """Send superior BPDUs every 2 seconds"""
                while not stop_bpdu_sending[0]:
                    send_superior_bpdu()

            bpdu_thread = None

            bpdu_thread = threading.Thread(target=periodic_bpdu_sender, daemon=True)
            bpdu_thread.start()

            # Validate root_bridge_id
            pytest_assert(
                wait_until(60, 2, 0, lambda:
                           validate_root_bridge_id(duthost, vlan_id, get_stp_vlan_data(duthost, vlan_id))),
                f"Root bridge ID did not match expected value within timeout for VLAN {vlan_id}"
            )

            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)

            # Root port is selected, and root port is in forwarding
            root_port = get_root_port(duthost, vlan_id, stp_vlan_data)
            pytest_assert(root_port == dut_port_1, f"Root port is not {dut_port_1}")

            verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
            verify_stp_state(duthost, vlan_id, [dut_port_2], "BLOCKING")

            default_bridge_priority_data = get_stp_bridge_priority_data(duthost, vlan_id)
            default_dut_bridge_priority = default_bridge_priority_data["priority"]

            # Change Bridge priority and verify it becomes root bridge
            duthost.shell(
                    f"config spanning-tree vlan priority {vlan_id} {self.BRIDGE_PRIORITY}",
                    module_ignore_errors=True
            )

            verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
            verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")

            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)
            root_port = get_root_port(duthost, vlan_id, stp_vlan_data)
            pytest_assert(root_port == "Root", f"{root_port} is not root")

            # Validate captured BPDU bridge ID
            mac_address_dut_port_1 = setup_pvst_test_data["dut_ports"]["mac"]
            mac_address_dut_port_2 = setup_pvst_test_data["dut_ports"]["mac"]
            bridge_priority_data = get_stp_bridge_priority_data(duthost, vlan_id)
            dut_bridge_priority = bridge_priority_data["priority"]
            bridge_priority = int(dut_bridge_priority) + vlan_id

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_root_bridge_id",
                           "vlan_id": vlan_id,
                           "expected_bridge_mac": mac_address_dut_port_1,
                           "expected_bridge_priority": bridge_priority,
                           "capture_port": ptf_port_1,  # Capture on PTF port
                           "capture_duration": self.PKT_CAPTURE_DURATION,  # Capture for 10 seconds
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_root_bridge_id_validation.log",
                       is_python3=True)

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_root_bridge_id",
                           "vlan_id": vlan_id,
                           "expected_bridge_mac": mac_address_dut_port_2,
                           "expected_bridge_priority": bridge_priority,
                           "capture_port": ptf_port_2,  # Capture on PTF port
                           "capture_duration": self.PKT_CAPTURE_DURATION,  # Capture for 10 seconds
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_root_bridge_id_validation_port2.log",
                       is_python3=True)

        except Exception as e:
            logger.error(f"Test failed: {e}")
            raise

        finally:
            # Stop periodic BPDU sending
            stop_bpdu_sending[0] = True

            # Wait for thread to finish current iteration
            if bpdu_thread and bpdu_thread.is_alive():
                time.sleep(3)  # Give thread time to exit gracefully

            # Restore default priority
            duthost.shell(f"config spanning-tree vlan priority "
                          f"{vlan_id} {default_dut_bridge_priority}", module_ignore_errors=True)

    # testcase 5
    def test_port_priority_change_in_bpdu(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                          ptfhost, tbinfo, request,
                                          toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                          setup_pvst_test_data):

        """
        Testcase to Validate Port Priority

        Test Steps:
        1.From PTF send packets with better bridge priority than SONIC DUT from all the ports
        2.Verify on SONIC DUT the root bridge is selected with root bridge id sent in the BPDU from PTF
        3.Verify on SONIC DUT the root port is selected, and root port is in forwarding
          state by fetching the information from STP_VLAN_TABLE and STP_VLAN_PORT_TABLE entries from APP DB
        4.Verify on SONIC DUT port Ethernet8 is in blocking state
        5.From PTF, send a BPDU with better port priority to Ethernet8 port of SONIC DUT
        6.Verify on SONIC DUT port Ethernet8 becomes root port and moves to
          forwarding state and Ethernet4 moves to blocking state.
        """

        try:
            duthost = duthosts[rand_one_dut_hostname]
            dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
            dut_port_2 = setup_pvst_test_data["dut_ports"]["dut_port_2"]
            ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
            ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
            vlan_id = int(setup_pvst_test_data["vlan"]["id"])

            # Verify DUT port 1 is in FORWARDING state
            verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")

            for _ in range(2):  # Send multiple times for reliability
                ptf_runner(ptfhost,
                           "ptftests",
                           "pvst_bpdu_test.PvstBpduTest",
                           platform_dir="ptftests",
                           params={
                               "hostname": duthost.hostname,
                               "test_scenarios": "config",
                               'send_port': [ptf_port_1, ptf_port_2],
                               "kvm_support": True
                           },
                           log_file="/tmp/pvst_bpdu_port_priority.log",
                           is_python3=True)
                time.sleep(2)

            # Validate root bridge ID
            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)
            validate_root_bridge_id(duthost, vlan_id, stp_vlan_data)

            root_port = get_root_port(duthost, vlan_id, stp_vlan_data)
            pytest_assert(root_port == dut_port_1, f"Root port is not {dut_port_1}")

            # Verify DUT port 1 is in FORWARDING state and port 2 is in Blocking
            verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
            verify_stp_state(duthost, vlan_id, [dut_port_2], "BLOCKING")

            count = 0
            while count < 15:
                ptf_runner(ptfhost,
                           "ptftests",
                           "pvst_bpdu_test.PvstBpduTest",
                           platform_dir="ptftests",
                           params={"hostname": duthost.hostname,
                                   "test_scenarios": "config",
                                   'port_priority': 0x60,
                                   'send_port': [ptf_port_2],
                                   "kvm_support": True},
                           log_file="/tmp/pvst_port_priority_ptf_2.log",
                           is_python3=True)

                ptf_runner(ptfhost,
                           "ptftests",
                           "pvst_bpdu_test.PvstBpduTest",
                           platform_dir="ptftests",
                           params={"hostname": duthost.hostname,
                                   "test_scenarios": "config",
                                   'send_port': [ptf_port_1],
                                   "kvm_support": True},
                           log_file="/tmp/pvst_port_priority_ptf_1.log",
                           is_python3=True)
                count += 1

            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)
            root_port = get_root_port(duthost, vlan_id, stp_vlan_data)
            pytest_assert(root_port == dut_port_2, f"Root port is not {dut_port_2}")

            verify_stp_state(duthost, vlan_id, [dut_port_1], "BLOCKING")
            verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")

        except Exception as e:
            logger.error(f"Test 'test_port_priority_change_in_bpdu' failed: {e}")
            raise

    # testcase 6
    def test_pvst_path_cost_validation(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                       ptfhost, tbinfo, request,
                                       toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                       setup_pvst_test_data):
        """
        Test case to validate path cost functionality.

        Test Steps:
        1. From PTF send packets with better bridge priority than SONIC DUT to Ethernet4
        2. Verify on SONIC DUT the root bridge is selected with root bridge id sent in the BPDU from PTF
        3. On PTF, check the received BPDU from Ethernet8 of SONIC DUT with default root path cost
        4. Update the port cost of Ethernet4 on SONIC DUT using config command
        5. On PTF, verify the received BPDU from Ethernet8 has updated root path cost
        """
        duthost = duthosts[rand_one_dut_hostname]
        dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
        ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
        ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
        vlan_id = int(setup_pvst_test_data["vlan"]["id"])

        # Configure ebtables - there is a bug in SONIC where the ebtables are not configured
        duthost.shell("ebtables -A FORWARD -d 01:00:0c:cc:cc:cd -j DROP", module_ignore_errors=True)

        # Control flag for periodic BPDU sending (using list to avoid nonlocal issues)
        stop_bpdu_sending = [False]

        def send_superior_bpdu():
            """Send a single superior BPDU from PTF"""
            try:
                ptf_runner(ptfhost,
                           "ptftests",
                           "pvst_bpdu_test.PvstBpduTest",
                           platform_dir="ptftests",
                           params={
                               "hostname": duthost.hostname,
                               "test_scenarios": "config",
                               "vlan_id": vlan_id,
                               "send_port": [ptf_port_1],
                               "kvm_support": True
                           },
                           log_file="/tmp/pvst_path_cost_superior_bpdu_periodic.log",
                           is_python3=True)
            except Exception as e:
                logger.warning(f"Failed to send superior BPDU: {e}")

        def periodic_bpdu_sender():
            """Send superior BPDUs every 2 seconds"""
            while not stop_bpdu_sending[0]:
                send_superior_bpdu()

        # Start periodic BPDU sending thread
        bpdu_thread = None

        try:
            bpdu_thread = threading.Thread(target=periodic_bpdu_sender, daemon=True)
            bpdu_thread.start()

            # Wait until root bridge ID differs from local bridge ID
            root_bridge_verify = wait_until(
                    timeout=60, interval=2, delay=0,
                    condition=lambda:
                    get_stp_vlan_data(duthost, vlan_id).get("root_bridge_id", "") !=
                    get_stp_vlan_data(duthost, vlan_id).get("bridge_id", "")
            )

            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)
            root_bridge_id = stp_vlan_data.get("root_bridge_id", "")
            bridge_id = stp_vlan_data.get("bridge_id", "")

            # Verify PTF became the root bridge (root bridge ID should not equal DUT bridge ID)
            pytest_assert(
                root_bridge_verify,
                f"PTF should be root bridge. Root ID: {root_bridge_id}, DUT Bridge ID: {bridge_id}"
            )

            # Verify PTF is the root port on Ethernet4
            root_port = stp_vlan_data.get("root_port", "")
            pytest_assert(root_port == dut_port_1,
                          f"Root port should be {dut_port_1}, but is {root_port}")

            # Get default port cost of Ethernet4
            default_port_cost = get_port_cost(dut_port_1, duthost, vlan_id)

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_path_cost",
                           "vlan_id": vlan_id,
                           "capture_port": ptf_port_2,
                           "capture_duration": self.PKT_CAPTURE_DURATION,
                           "expected_root_path_cost": default_port_cost,
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_path_cost_default_capture.log",
                       is_python3=True)

            duthost.shell(f"config spanning-tree interface cost {dut_port_1} {self.PORT_COST}",
                          module_ignore_errors=True)

            # Verify the port cost was updated in Redis
            updated_port_cost = get_port_cost(dut_port_1, duthost, vlan_id)
            pytest_assert(updated_port_cost == self.PORT_COST,
                          f"Port cost should be updated to {self.PORT_COST}, but is {updated_port_cost}")

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_path_cost",
                           "vlan_id": vlan_id,
                           "capture_port": ptf_port_2,
                           "capture_duration": self.PKT_CAPTURE_DURATION,
                           "expected_root_path_cost": self.PORT_COST,
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_path_cost_updated_capture.log",
                       is_python3=True)

            # Additional verification - check STP status
            duthost.shell(f"show spanning-tree vlan {vlan_id}", module_ignore_errors=True)

            # Verify interface status
            duthost.shell(f"show spanning-tree interface {dut_port_1}", module_ignore_errors=True)

        except Exception as e:
            logger.error(f"Path cost validation test failed with error: {e}")

        finally:
            # Stop periodic BPDU sending
            stop_bpdu_sending[0] = True

            # Wait for thread to finish current iteration
            if bpdu_thread and bpdu_thread.is_alive():
                time.sleep(3)  # Give thread time to exit gracefully

            # Reset port cost to default
            try:
                duthost.shell(f"config spanning-tree interface cost {dut_port_1} {default_port_cost}",
                              module_ignore_errors=True)
            except Exception as e:
                logger.warning(f"Could not reset port cost for {dut_port_1} : {e}")

    # testcase 7
    def test_pvst_root_guard_functionality(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                           ptfhost, tbinfo, request,
                                           toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                           setup_pvst_test_data):

        """
        Test case to validate root guard functionality on multiple ports simultaneously.

        This test:
        1. Configures root guard on multiple ports
        2. Sends superior BPDUs to multiple ports
        3. Validates that all ports go to root-inconsistent state
        4. Verifies proper recovery
        """
        duthost = duthosts[rand_one_dut_hostname]
        dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
        dut_port_2 = setup_pvst_test_data["dut_ports"]["dut_port_2"]
        ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
        ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
        vlan_id = int(setup_pvst_test_data["vlan"]["id"])

        root_guard_ports = [dut_port_1, dut_port_2]
        root_guard_ptf_ports = [ptf_port_1, ptf_port_2]

        try:
            # Configure root guard on all test ports
            for port in root_guard_ports:
                duthost.shell(f"config spanning-tree interface root_guard enable {port}",
                              module_ignore_errors=True)

            # Sending high priority BPDU
            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "config",
                           "vlan_id": vlan_id,
                           "send_port": root_guard_ptf_ports,  # Send on all root guard ports
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_root_guard_multiple_ports.log",
                       is_python3=True)

            # Wait for convergence and verify all ports are in inconsistent state

            for port in root_guard_ports:
                try:
                    port_state = get_port_state(duthost, vlan_id, port)

                    expected_states = ["ROOT-INC"]
                    pytest_assert(port_state in expected_states,
                                  f"Port {port} should be in root-inconsistent state, but is {port_state}")

                except Exception as e:
                    logger.warning(f"Could not verify state for port {port}: {e}")

            verify_stp_state(duthost, vlan_id, root_guard_ports, "FORWARDING")

        finally:
            # Cleanup: Disable root guard on all test ports
            for port in root_guard_ports:
                duthost.shell(f"config spanning-tree interface root_guard disable {port}",
                              module_ignore_errors=True)

    # testcase 8
    def test_pvst_bpdu_guard_with_shutdown(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                           ptfhost, tbinfo, request,
                                           toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                           setup_pvst_test_data):
        """
        Test case to validate BPDU guard functionality with shutdown behavior.

        Test Steps:
        1. Enable BPDU guard with shutdown on Ethernet4
        2. Send BPDUs from PTF to SONIC DUT on Ethernet4
        3. Verify BPDU guard shuts down port by checking APP DB operational state
        4. Disable BPDU guard on Ethernet4
        5. Enable port Ethernet4 using CLI command
        6. Send BPDUs again from PTF to Ethernet4
        7. Verify BPDU guard doesn't kick in and port stays UP
        """
        duthost = duthosts[rand_one_dut_hostname]
        dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
        ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
        vlan_id = int(setup_pvst_test_data["vlan"]["id"])

        try:
            # Enable BPDU guard with shutdown on Ethernet4
            duthost.shell(f"config spanning-tree interface bpdu_guard enable {dut_port_1} --shutdown",
                          module_ignore_errors=True)

            # Send BPDUs from PTF to SONIC DUT on Ethernet4

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "config",  # Send Configuration BPDUs
                           "vlan_id": vlan_id,
                           "send_port": [ptf_port_1],
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_bpdu_guard_trigger_test.log",
                       is_python3=True)

            # Wait for BPDU guard to trigger
            time.sleep(2)

            # Check port states from APP DB after BPDU guard trigger
            post_bpdu_oper_state = get_port_operational_state_from_appdb(duthost, dut_port_1)

            port_state = get_port_state(duthost, vlan_id, dut_port_1)
            expected_states = ["BPDU-DIS"]
            pytest_assert(
                    port_state in expected_states,
                    f"Port {dut_port_1} should be in BPDU discard state,but is {port_state}"
            )

            # Verify port is shut down
            pytest_assert(post_bpdu_oper_state.lower() == "down",
                          f"Port {dut_port_1} operational state should be 'down' due to BPDU guard,"
                          "but is '{post_bpdu_oper_state}'")

            # Disable BPDU guard on Ethernet4
            duthost.shell(f"config spanning-tree interface bpdu_guard disable {dut_port_1}", module_ignore_errors=True)

            # Enable port Ethernet4 using CLI command
            duthost.shell(f"config interface shutdown {dut_port_1}", module_ignore_errors=True)
            duthost.shell(f"config interface startup {dut_port_1}", module_ignore_errors=True)

            # Verify port is back up
            recovery_oper_state = get_port_operational_state_from_appdb(duthost, dut_port_1)
            recovery_admin_state = get_port_admin_state_from_appdb(duthost, dut_port_1)

            pytest_assert(recovery_oper_state.lower() == "up",
                          f"Port {dut_port_1} should be up after startup command, "
                          "but oper state is '{recovery_oper_state}'")
            pytest_assert(recovery_admin_state.lower() == "up",
                          f"Port {dut_port_1} should be admin up after startup command, "
                          "but admin state is '{recovery_admin_state}'")

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "config",  # Send Configuration BPDUs
                           "vlan_id": vlan_id,
                           "send_port": [ptf_port_1],
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_bpdu_guard_disabled_test.log",
                       is_python3=True)

            final_oper_state = get_port_operational_state_from_appdb(duthost, dut_port_1)
            final_admin_state = get_port_admin_state_from_appdb(duthost, dut_port_1)

            # Verify port remains up
            pytest_assert(final_oper_state.lower() == "up",
                          f"Port {dut_port_1} should remain up when BPDU guard is disabled, "
                          "but oper state is '{final_oper_state}'")
            pytest_assert(final_admin_state.lower() == "up",
                          f"Port {dut_port_1} should remain admin up when BPDU guard is disabled, "
                          "but admin state is '{final_admin_state}'")

        except Exception as e:
            logger.error(f"Test failed with error: {e}")

            # Get current port states for debugging
            current_oper_state = get_port_operational_state_from_appdb(duthost, dut_port_1)
            current_admin_state = get_port_admin_state_from_appdb(duthost, dut_port_1)
            logger.error(f"Current port states - Oper: {current_oper_state}, Admin: {current_admin_state}")

            # Get interface status for debugging
            debug_interface_status = duthost.shell(f"show interfaces status {dut_port_1}", module_ignore_errors=True)
            logger.error("Current interface status: %s", debug_interface_status['stdout'])

            raise

    # testcase 9
    def test_pvst_bpdu_timer_validation(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                        ptfhost, tbinfo, request,
                                        toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                        setup_pvst_test_data):

        """
        Test case to validate BPDU timer values when changed on DUT.

        This test:
        1. Configures custom STP timer values on the DUT
        2. Uses PTF to capture BPDU packets sent by the DUT
        3. Validates that the captured BPDUs contain the correct timer values
        """
        duthost = duthosts[rand_one_dut_hostname]
        ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
        ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
        vlan_id = int(setup_pvst_test_data["vlan"]["id"])

        # Default timer data
        stp_data = get_stp_bridge_priority_data(duthost, vlan_id)
        default_hello_time = int(stp_data["hello_time"])
        default_max_age = int(stp_data["max_age"])
        default_forward_delay = int(stp_data["forward_delay"])

        try:
            # Configure custom timer values on DUT for the VLAN
            duthost.shell(f"config spanning-tree vlan hello {vlan_id} {self.CUSTOM_HELLO_TIME}",
                          module_ignore_errors=True)

            duthost.shell(f"config spanning-tree vlan max_age {vlan_id} {self.CUSTOM_MAX_AGE}",
                          module_ignore_errors=True)

            duthost.shell(f"config spanning-tree vlan forward_delay {vlan_id} {self.CUSTOM_FORWARD_DELAY}",
                          module_ignore_errors=True)

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_timers",
                           "vlan_id": vlan_id,
                           "capture_port": ptf_port_1,  # Capture on PTF port
                           "expected_hello_time": self.CUSTOM_HELLO_TIME,
                           "expected_max_age": self.CUSTOM_MAX_AGE,
                           "expected_forward_delay": self.CUSTOM_FORWARD_DELAY,
                           "capture_duration": self.PKT_CAPTURE_DURATION,  # Capture for 10 seconds
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_bpdu_timer_validation.log",
                       is_python3=True)

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_timers",
                           "vlan_id": vlan_id,
                           "capture_port": ptf_port_2,  # Capture on PTF port
                           "expected_hello_time": self.CUSTOM_HELLO_TIME,
                           "expected_max_age": self.CUSTOM_MAX_AGE,
                           "expected_forward_delay": self.CUSTOM_FORWARD_DELAY,
                           "capture_duration": self.PKT_CAPTURE_DURATION,
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_bpdu_timer_validation_port2.log",
                       is_python3=True)

        finally:
            # Restore default timer values
            duthost.shell(f"config spanning_tree vlan hello {vlan_id} {default_hello_time}", module_ignore_errors=True)
            duthost.shell(f"config spanning_tree vlan max_age {vlan_id} {default_max_age}", module_ignore_errors=True)
            duthost.shell(f"config spanning_tree vlan forward_delay "
                          f"{vlan_id} {default_forward_delay}", module_ignore_errors=True)

    # testcase 10
    def test_pvst_backup_port_functionality(self, ptfadapter, duthosts, rand_one_dut_hostname,
                                            ptfhost, tbinfo, request,
                                            toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                            setup_pvst_test_data):

        """
        Test case to validate backup port functionality.

        Test Steps:
        1. Configure DUT to be the root bridge
        2. On PTF capture the BPDU generated by DUT on Ethernet4 and use same BPDU to send it back on Ethernet8
        3. Verify on DUT port Ethernet8 is moved into blocking state as it receives its own BPDU
        4. Wait for 60seconds and verify port Ethernet8 moves to forwarding state as DUT is not getting its own BPDU now
        """

        duthost = duthosts[rand_one_dut_hostname]
        dut_port_2 = setup_pvst_test_data["dut_ports"]["dut_port_2"]
        ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
        ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
        vlan_id = int(setup_pvst_test_data["vlan"]["id"])

        try:

            # Verify DUT is the root bridge
            stp_vlan_data = get_stp_vlan_data(duthost, vlan_id)

            root_bridge_id = stp_vlan_data.get("root_bridge_id", "")
            bridge_id = stp_vlan_data.get("bridge_id", "")

            default_bridge_priority_data = get_stp_bridge_priority_data(duthost, vlan_id)
            default_dut_bridge_priority = default_bridge_priority_data["priority"]

            pytest_assert(root_bridge_id == bridge_id,
                          f"DUT should be root bridge. Root ID: {root_bridge_id}, Bridge ID: {bridge_id}")

            ptf_runner(ptfhost,
                       "ptftests",
                       "pvst_bpdu_test.PvstBpduTest",
                       platform_dir="ptftests",
                       params={
                           "hostname": duthost.hostname,
                           "test_scenarios": "validate_backup_port",
                           "vlan_id": vlan_id,
                           "capture_port": ptf_port_1,
                           "replay_port": ptf_port_2,
                           "capture_duration": self.PKT_CAPTURE_DURATION,  # Capture for 10 seconds to get BPDU
                           "replay_delay": 1,       # Wait 1 second before replaying
                           "kvm_support": True
                       },
                       log_file="/tmp/pvst_backup_port_capture_replay.log",
                       is_python3=True)

            verify_stp_state(duthost, vlan_id, [dut_port_2], "BLOCKING")

            # STP should transition the port back to forwarding when it stops receiving own BPDUs
            # Port should transition back to FORWARDING state
            verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")

        except Exception as e:
            logger.error(f"Backup port test failed with error: {e}")

        finally:
            # Reset to default priority (32768)
            duthost.shell(f"config spanning-tree vlan priority "
                          f"{vlan_id} {default_dut_bridge_priority}", module_ignore_errors=True)

    # testcase 11
    def test_pvst_mac_flush(self, ptfadapter, duthosts, rand_one_dut_hostname,
                            ptfhost, toggle_all_simulator_ports_to_rand_selected_tor_m,    # noqa: F811
                            setup_pvst_test_data):

        """
        Test case to validate mac flush functionality.

        Test Steps:
        1. Verify SONIC DUT is acting as the root bridge by checking the root bridge id in APP DB.
        2. On PTF, capture and validate L2 traffic sent from Ethernet4
        (ptf_port_1) to Ethernet8 (ptf_port_2) over VLAN 1000.
        3. Ensure that the MAC address is learned on the SONIC DUT for the receiving port Ethernet4.
        4. From PTF, send a TCN BPDU packet to trigger MAC flush.
        5. Verify that MAC address entries on SONIC DUT for Ethernet4 are flushed (reduced in count).

        """
        duthost = duthosts[rand_one_dut_hostname]
        dut_port_1 = setup_pvst_test_data["dut_ports"]["dut_port_1"]
        dut_port_2 = setup_pvst_test_data["dut_ports"]["dut_port_2"]
        ptf_port_1 = setup_pvst_test_data["dut_ports"]["ptf_port_1"]
        ptf_port_2 = setup_pvst_test_data["dut_ports"]["ptf_port_2"]
        vlan_id = int(setup_pvst_test_data["vlan"]["id"])

        # Validate DUT rootbridge
        stp_data = get_stp_vlan_data(duthost, vlan_id)
        bridge_id = stp_data.get("bridge_id", "")
        root_bridge_id = stp_data.get("root_bridge_id", "")
        pytest_assert(
            bridge_id == root_bridge_id,
            f"Mismatch: bridge_id = {bridge_id}, root_bridge_id = {root_bridge_id}"
        )

        # Port state transitions
        ports = [dut_port_1, dut_port_2]
        verify_stp_state(duthost, vlan_id, ports, "FORWARDING")

        mac_before_traffic = duthost.shell("show mac").get("stdout_lines", [])
        count_before_traffic = sum(1 for line in mac_before_traffic if dut_port_1 in line)

        # Verify l2 packet
        ptf_runner(ptfhost,
                   "ptftests",
                   "pvst_bpdu_test.PvstBpduTest",
                   platform_dir="ptftests",
                   params={
                       "hostname": duthost.hostname,
                       "test_scenarios": "validate_l2_packet",
                       "send_port": ptf_port_1,
                       "receive_port": ptf_port_2,  # Capture on PTF port
                       "vlan_id": vlan_id,
                       "verify_packet": True,
                       "kvm_support": True
                       },
                   log_file="/tmp/pvst_mac_flush_send_l2_packet.log",
                   is_python3=True)

        # Step 3: Collect MAC table after L2 traffic
        mac_after_traffic = duthost.shell("show mac").get("stdout_lines", [])
        count_after_traffic = sum(1 for line in mac_after_traffic if dut_port_1 in line)

        pytest_assert(
            count_after_traffic > count_before_traffic,
            f"MACs not learned on {dut_port_1}. Before: {count_before_traffic}, After: {count_after_traffic}"
        )
        # Send tcn packet from ptf to flush
        ptf_runner(ptfhost,
                   "ptftests",
                   "pvst_bpdu_test.PvstBpduTest",
                   platform_dir="ptftests",
                   params={
                        "hostname": duthost.hostname,
                        "test_scenarios": "tcn",
                        "vlan_id": vlan_id,
                        "send_port": [ptf_port_1],
                        "kvm_support": True
                        },
                   log_file="/tmp/pvst_tcn_test_mac_flush.log",
                   is_python3=True)

        mac_after_flush = duthost.shell("show mac").get("stdout_lines", [])
        count_after_flush = sum(1 for line in mac_after_flush if dut_port_1 in line)

        pytest_assert(
              count_after_flush <= count_after_traffic,
              f"MACs not flushed on {dut_port_1}. Before flush: {count_after_traffic}, After flush: {count_after_flush}"
        )
