import pytest
import logging
import random

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, configure_packet_aging
from tests.common.mellanox_data import is_mellanox_device
from tests.packet_trimming.constants import (VALID_TRIMMING_CONFIGS_SYM, TRIM_SIZE, TRIM_DSCP, DEFAULT_PACKET_SIZE,
                                             DEFAULT_DSCP, MIN_PACKET_SIZE, TRIM_SIZE_MAX, INVALID_TRIMMING_CONFIGS_SYM,
                                             CONFIG_TOGGLE_COUNT, JUMBO_PACKET_SIZE, PORT_TOGGLE_COUNT, TRIM_QUEUE,
                                             ASYM_TC, ASYM_PORT_1_DSCP, ASYM_PORT_2_DSCP,
                                             VALID_TRIMMING_CONFIGS_ASYM, INVALID_TRIMMING_CONFIGS_ASYM,
                                             MODE_TOGGLE_COUNT, NORMAL_PACKET_DSCP)
from tests.packet_trimming.packet_trimming_helper import (configure_trimming_global, verify_packet_trimming,
                                                          verify_trimming_config, configure_trimming_action,
                                                          configure_trimming_acl, verify_srv6_packet_with_trimming,
                                                          cleanup_trimming_acl, verify_asymmetric_dscp_packet_trimming,
                                                          reboot_dut, remove_tc_to_dscp_map, configure_tc_to_dscp_map,
                                                          verify_normal_packet, check_connected_route_ready)


pytestmark = [
    pytest.mark.topology("t0", "t1")
]

logger = logging.getLogger(__name__)


class TestPacketTrimming:
    def test_trimming_configuration(self, duthost, test_params):
        """
        Test Case: Verify Trimming Configuration

        1. Verify Symmetric DSCP valid and invalid configurations
        2. Verify Asymmetric DSCP valid and invalid configurations
        """
        with allure.step("Testing Symmetric DSCP valid configurations"):
            for size, dscp, queue in VALID_TRIMMING_CONFIGS_SYM:
                logger.info(f"Testing valid config: size={size}, dscp={dscp}, queue={queue}")
                pytest_assert(configure_trimming_global(duthost, size=size, queue=queue, dscp=dscp))

        with allure.step("Testing Symmetric DSCP invalid configurations"):
            for size, dscp, queue in INVALID_TRIMMING_CONFIGS_SYM:
                logger.info(f"Testing invalid config: size={size}, dscp={dscp}, queue={queue}")
                pytest_assert(not configure_trimming_global(duthost, size=size, queue=queue, dscp=dscp))

        with allure.step("Testing Asymmetric DSCP valid configurations"):
            for size, dscp, queue, tc in VALID_TRIMMING_CONFIGS_ASYM:
                logger.info(f"Testing valid asymmetric config: size={size}, dscp={dscp}, queue={queue}, tc={tc}")
                pytest_assert(configure_trimming_global(duthost, size=size, queue=queue, dscp=dscp, tc=tc))

        with allure.step("Testing Asymmetric DSCP invalid configurations"):
            for size, dscp, queue, tc in INVALID_TRIMMING_CONFIGS_ASYM:
                logger.info(f"Testing invalid asymmetric config: size={size}, dscp={dscp}, queue={queue}, tc={tc}")
                pytest_assert(not configure_trimming_global(duthost, size=size, queue=queue, dscp=dscp, tc=tc))

    def test_packet_size_after_trimming(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify Packet Size After Trimming

        This test verifies that packet trimming correctly adjusts packet sizes according to the configured values.
        It tests both standard and maximum trimming sizes to ensure packets are properly trimmed while preserving
        headers and critical information.
        """
        with allure.step("Configure trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming in Asymmetric DSCP mode"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        with allure.step("Verify setting TC value while missing TC_TO_DSCP_MAP attached to the egress port"):
            remove_tc_to_dscp_map(duthost)
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)
            verify_trimming_config(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Verify that trimming is configured before configuring tc_to_dscp_map"):
            configure_tc_to_dscp_map(duthost, test_params['egress_ports'])
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        with allure.step("Configure trimming in Asymmetric DSCP mode and update trimming size to {TRIM_SIZE_MAX}"):
            configure_trimming_global(duthost, size=TRIM_SIZE_MAX, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Send packets and verify trimming works after config update"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=JUMBO_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE_MAX,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

    def test_dscp_remapping_after_trimming(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify DSCP Remapping After Trimming

        This test verifies that DSCP values are correctly remapped according to the trimming configuration.
        It tests two scenarios:
        1. Normal case where packets are trimmed and DSCP is remapped
        2. Special case where packet size is less than trimming size (no trimming occurs but DSCP is still remapped)
        """
        with allure.step("Configure trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming in Asymmetric DSCP mode"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        # When packet size is less than trimming size, the packet is not trimmed, but the DSCP value should be updated
        with allure.step("Verify trim packet when packets size less than trimming size"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=MIN_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=MIN_PACKET_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

    def test_symmetric_asymmetric_mode_switch(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify trimming works after switching between symmetric and asymmetric DSCP modes multiple times.
        """
        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        for i in range(MODE_TOGGLE_COUNT):
            with allure.step(f"Round {i+1}: Configure trimming in Symmetric DSCP mode"):
                configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp=TRIM_DSCP)
                for egress_port in test_params['egress_ports']:
                    verify_packet_trimming(
                        duthost=duthost,
                        ptfadapter=ptfadapter,
                        ingress_port=test_params['ingress_port'],
                        egress_port=egress_port,
                        block_queue=test_params['block_queue'],
                        send_pkt_size=DEFAULT_PACKET_SIZE,
                        send_pkt_dscp=DEFAULT_DSCP,
                        recv_pkt_size=TRIM_SIZE,
                        recv_pkt_dscp=TRIM_DSCP
                    )

            with allure.step(f"Round {i+1}: Configure trimming in Asymmetric DSCP mode"):
                configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)
                verify_asymmetric_dscp_packet_trimming(
                    duthost=duthost,
                    ptfadapter=ptfadapter,
                    ingress_port=test_params['ingress_port'],
                    egress_ports=test_params['egress_ports'],
                    block_queue=test_params['block_queue'],
                    send_pkt_size=DEFAULT_PACKET_SIZE,
                    send_pkt_dscp=DEFAULT_DSCP,
                    recv_pkt_size=TRIM_SIZE,
                    recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                    recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
                )

    def test_untrimmed_packet_in_asym_mode(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify trimming does not modify untrimmed packet DSCP
        """
        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Configure trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Verify trimming in Asymmetric DSCP mode"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        with allure.step("Verify untrimmed packet DSCP is not modified by trimming"):
            verify_normal_packet(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_port=test_params['egress_ports'][0],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=NORMAL_PACKET_DSCP,
                recv_pkt_size=DEFAULT_PACKET_SIZE,
                recv_pkt_dscp=NORMAL_PACKET_DSCP
            )

    def test_acl_action_with_trimming(self, duthost, ptfadapter, test_params, clean_trimming_acl_tables):
        """
        Test Case: Verify ACL Action Interaction with Trimming

        This test verifies the interaction between ACL rules with the DISABLE_TRIM action and packet trimming.
        It confirms that when an ACL rule with DISABLE_TRIM action is matched, packets are dropped instead
        of being trimmed, and that trimming returns to normal operation when the ACL rule is removed.
        """
        with allure.step("Configure trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming in Asymmetric DSCP mode"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        with allure.step("Config ACL rule with DISABLE_TRIM_ACTION action"):
            configure_trimming_acl(duthost, test_params['ingress_port']['name'])

        with allure.step("Verify packets are dropped directly"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP,
                expect_packets=False
            )

        with allure.step("Remove ACL table"):
            cleanup_trimming_acl(duthost)

        with allure.step("Send packets again and verify trimmed packets"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

    def test_trimming_with_srv6(self, duthost, ptfadapter, setup_srv6, test_params):
        """
        Test Case: Verify Packet Trimming with SRv6

        This test verifies that packet trimming works correctly with SRv6 (Segment Routing over IPv6) packets.
        It ensures SRv6 headers are preserved while excess payload is trimmed according to configuration.
        """
        with allure.step("Configure trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify SRv6 packets after trimming in Asymmetric DSCP mode"):
            verify_srv6_packet_with_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                config_setup=setup_srv6,
                ingress_port=test_params['ingress_port'],
                egress_port=test_params['egress_ports'][0],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp=ASYM_PORT_1_DSCP
            )

    def test_stability_during_feature_toggles(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify Stability During Feature Toggles

        This test verifies that packet trimming functionality remains stable when the trimming
        feature is repeatedly enabled and disabled. It ensures the buffer profile configuration
        can handle multiple configuration changes without impacting trimming functionality.
        """
        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Config and verify trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        with allure.step("Disable trimming"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "off")

        with allure.step("Verify no trimming action in Asymmetric DSCP mode when disable trimming"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP,
                expect_packets=False
            )

        with allure.step("Enable trimming again"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming in Asymmetric DSCP mode after enable trimming"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        with allure.step("Trimming config toggles"):
            for i in range(CONFIG_TOGGLE_COUNT):
                logger.info(f"Trimming config toggle test iteration {i + 1}")
                for buffer_profile in test_params['trim_buffer_profiles']:
                    configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "off")
                for buffer_profile in test_params['trim_buffer_profiles']:
                    configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming still works after feature toggles in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP,
                expect_packets=True
            )

    def test_trimming_during_port_admin_toggle(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify Trimming During Port Admin Status Toggle

        This test verifies that packet trimming functionality remains stable when ports are
        administratively enabled and disabled multiple times. It ensures interface flapping
        does not impact the trimming configuration or functionality.
        """
        with allure.step("Configure trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming in Asymmetric DSCP mode"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        with allure.step("Ports admin status toggles"):
            for i in range(PORT_TOGGLE_COUNT):
                for egress_port in test_params['egress_ports']:
                    logger.info(f"Ports admin status toggle test iteration {i+1}")
                    duthost.shutdown(egress_port['name'])
                    duthost.no_shutdown(egress_port['name'])
                pytest_assert(wait_until(30, 5, 0, duthost.check_intf_link_state, egress_port['name']),
                              "Interfaces are not restored to up after the flap")

        with allure.step("Verify trimming still works after admin toggles"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

    def test_trimming_with_reload_and_reboot(self, duthost, ptfadapter, test_params, localhost, request):
        """
        Test Case: Verify Trimming Persistence After Reload and Reboot

        This test verifies that packet trimming configurations persist across system reloads and reboots.
        It ensures trimming functionality continues to work normally after the system recovers from
        a configuration reload or cold reboot.
        """
        with allure.step("Configure trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=TRIM_SIZE, queue=TRIM_QUEUE, dscp='from-tc', tc=ASYM_TC)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming in Asymmetric DSCP mode"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )

        with allure.step("Randomly choose one action from reload/cold reboot"):
            duthost.shell('sudo config save -y')

            # Check if user specified the reboot type through command line
            reboot_type = request.config.getoption("--packet_trimming_reboot_type")
            if reboot_type:
                logger.info(f"Using user-specified reboot type: {reboot_type}")
            else:
                # If user didn't specify, randomly choose one from the list
                valid_reboot_types = ["reload", "cold"]
                reboot_type = random.choice(valid_reboot_types)
                logger.info(f"Randomly choose {reboot_type} from {valid_reboot_types}")

            # Perform the reboot/reload
            reboot_dut(duthost, localhost, reboot_type=reboot_type)

        with allure.step("Verify connected route is ready after reload/cold reboot"):
            for egress_port in test_params['egress_ports']:
                pytest_assert(wait_until(30, 5, 0, check_connected_route_ready, duthost, egress_port['name']),
                              "Connected route is not ready")

        if is_mellanox_device(duthost):
            with allure.step("Disable packet aging for mellanox device after config reload"):
                configure_packet_aging(duthost, disabled=True)

        with allure.step("Verify trimming function in Asymmetric DSCP mode after reload/cold reboot"):
            verify_asymmetric_dscp_packet_trimming(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=TRIM_SIZE,
                recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
                recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
            )
