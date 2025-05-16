import pytest
import logging
import random

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, configure_packet_aging
from tests.common.mellanox_data import is_mellanox_device
from tests.packet_trimming.constants import (VALID_TRIMMING_CONFIGS, TRIM_SIZE, TRIM_DSCP, DEFAULT_PACKET_SIZE,
                                             DEFAULT_DSCP, MIN_PACKET_SIZE, TRIM_SIZE_MAX, INVALID_TRIMMING_CONFIGS,
                                             CONFIG_TOGGLE_COUNT, JUMBO_PACKET_SIZE, PORT_TOGGLE_COUNT, TRIM_QUEUE,
                                             BLOCK_QUEUE_PROFILE)
from tests.packet_trimming.packet_trimming_helper import (configure_trimming_global, verify_packet_trimming,
                                                          verify_trimming_config, configure_trimming_action,
                                                          configure_trimming_acl, verify_srv6_packet_with_trimming,
                                                          cleanup_trimming_acl, reboot_dut)


pytestmark = [
    pytest.mark.topology("t0", "t1")
]

logger = logging.getLogger(__name__)


class TestPacketTrimming:
    def test_trimming_configuration(self, duthost):
        """
        Test Case: Verify Trimming Configuration

        1. Verify that valid configurations are accepted and properly applied
        2. Verify that invalid configurations are properly rejected
        """
        with allure.step("Testing valid configurations"):
            for size, dscp, queue in VALID_TRIMMING_CONFIGS:
                logger.info(f"Testing valid config: size={size}, dscp={dscp}, queue={queue}")

                try:
                    configure_trimming_global(duthost, size, dscp, queue)
                    verify_trimming_config(duthost, size, dscp, queue)

                except Exception as e:
                    pytest.fail(
                        f"Valid configuration failed unexpectedly: size={size}, dscp={dscp}, queue={queue}, error={e}")

        with allure.step("Testing invalid configurations"):
            for size, dscp, queue in INVALID_TRIMMING_CONFIGS:
                logger.info(f"Testing invalid config: size={size}, dscp={dscp}, queue={queue}")

                try:
                    configure_trimming_global(duthost, size, dscp, queue)
                    # If we reach here, configuration didn't fail as expected
                    pytest.fail(
                        f"Invalid configuration was incorrectly accepted: size={size}, dscp={dscp}, queue={queue}")

                except Exception as e:
                    logger.debug(f"Error details: {e}")

    def test_packet_size_after_trimming(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify Packet Size After Trimming

        This test verifies that packet trimming correctly adjusts packet sizes according to the configured values.
        It tests both standard and maximum trimming sizes to ensure packets are properly trimmed while preserving
        headers and critical information.
        """
        with allure.step("Configure global trimming"):
            configure_trimming_global(duthost, TRIM_SIZE, TRIM_DSCP, TRIM_QUEUE)

        with allure.step("Enable trimming in buffer profile"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Send packets from PTF to DUT and verify trimmed packets"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

        with allure.step(f"Update trimming size to {TRIM_SIZE_MAX}"):
            configure_trimming_global(duthost, TRIM_SIZE_MAX, TRIM_DSCP, TRIM_QUEUE)

        with allure.step("Send packets and verify trimming works after config update"):
            verify_packet_trimming(duthost, ptfadapter, test_params, JUMBO_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE_MAX,
                                   TRIM_DSCP, expect_packets=True)

    def test_dscp_remapping_after_trimming(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify DSCP Remapping After Trimming

        This test verifies that DSCP values are correctly remapped according to the trimming configuration.
        It tests two scenarios:
        1. Normal case where packets are trimmed and DSCP is remapped
        2. Special case where packet size is less than trimming size (no trimming occurs but DSCP is still remapped)
        """
        with allure.step("Configure global trimming"):
            configure_trimming_global(duthost, TRIM_SIZE, TRIM_DSCP, TRIM_QUEUE)

        with allure.step("Enable trimming in buffer profile"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Send packets from PTF to DUT to trigger trimming"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

        # When packet size is less than trimming size, the packet is not trimmed, but the DSCP value should be updated
        with allure.step("Send packets size less than trimming size"):
            verify_packet_trimming(duthost, ptfadapter, test_params, MIN_PACKET_SIZE, DEFAULT_DSCP, MIN_PACKET_SIZE,
                                   TRIM_DSCP, expect_packets=True)

    def test_acl_action_with_trimming(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify ACL Action Interaction with Trimming

        This test verifies the interaction between ACL rules with the DISABLE_TRIM action and packet trimming.
        It confirms that when an ACL rule with DISABLE_TRIM action is matched, packets are dropped instead
        of being trimmed, and that trimming returns to normal operation when the ACL rule is removed.
        """
        with allure.step("Configure global trimming"):
            configure_trimming_global(duthost, TRIM_SIZE, TRIM_DSCP, TRIM_QUEUE)

        with allure.step("Enable trimming in buffer profile"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Send packets from PTF to DUT and verify trimmed packets"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

        with allure.step("Config ACL rule with DISABLE_TRIM_ACTION action"):
            configure_trimming_acl(duthost, test_params['downlink_port'])

        with allure.step("Verify packets are dropped directly"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=False)

        with allure.step("Remove ACL table"):
            cleanup_trimming_acl(duthost)

        with allure.step("Send packets again and verify trimmed packets"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

    def test_trimming_with_srv6(self, duthost, ptfadapter, setup_srv6, test_params):
        """
        Test Case: Verify Packet Trimming with SRv6

        This test verifies that packet trimming works correctly with SRv6 (Segment Routing over IPv6) packets.
        It ensures SRv6 headers are preserved while excess payload is trimmed according to configuration.
        """
        with allure.step("Configure global trimming"):
            configure_trimming_global(duthost, TRIM_SIZE, TRIM_DSCP, TRIM_QUEUE)

        with allure.step("Enable trimming in buffer profile"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Verify SRv6 packets after trimming"):
            verify_srv6_packet_with_trimming(duthost, ptfadapter, setup_srv6, test_params, DEFAULT_PACKET_SIZE,
                                             DEFAULT_DSCP, TRIM_SIZE, TRIM_DSCP)

    def test_stability_during_feature_toggles(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify Stability During Feature Toggles

        This test verifies that packet trimming functionality remains stable when the trimming
        feature is repeatedly enabled and disabled. It ensures the buffer profile configuration
        can handle multiple configuration changes without impacting trimming functionality.
        """
        with allure.step("Configure global trimming"):
            configure_trimming_global(duthost, TRIM_SIZE, TRIM_DSCP, TRIM_QUEUE)

        with allure.step("Enable trimming in buffer profile"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Send packets from PTF to DUT and verify trimmed packets"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

        with allure.step("Disable trimming"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "off")

        with allure.step("Verify no trimming action and packets are dropped"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=False)

        with allure.step("Enable trimming again"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Verify trimming function works"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

        with allure.step("Trimming config toggles"):
            for i in range(CONFIG_TOGGLE_COUNT):
                logger.info(f"Trimming config toggle test iteration {i + 1}")
                configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "off")
                configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Verify trimming still works after feature toggles"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

    def test_trimming_during_port_admin_toggle(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify Trimming During Port Admin Status Toggle

        This test verifies that packet trimming functionality remains stable when ports are
        administratively enabled and disabled multiple times. It ensures interface flapping
        does not impact the trimming configuration or functionality.
        """
        with allure.step("Configure global trimming"):
            configure_trimming_global(duthost, TRIM_SIZE, TRIM_DSCP, TRIM_QUEUE)

        with allure.step("Enable trimming in buffer profile"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Send packets from PTF to DUT and verify trimmed packets"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

        with allure.step("Ports admin status toggles"):
            for i in range(PORT_TOGGLE_COUNT):
                logger.info(f"Ports admin status toggle test iteration {i+1}")
                duthost.shutdown(test_params['uplink_port'])
                duthost.no_shutdown(test_params['uplink_port'])
            pytest_assert(wait_until(30, 5, 0, duthost.check_intf_link_state, test_params['uplink_port']),
                          "Interfaces are not restored to up after the flap")

        with allure.step("Verify trimming still works after admin toggles"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

    def test_trimming_with_reload_and_reboot(self, duthost, ptfadapter, test_params, localhost, request):
        """
        Test Case: Verify Trimming Persistence After Reload and Reboot

        This test verifies that packet trimming configurations persist across system reloads and reboots.
        It ensures trimming functionality continues to work normally after the system recovers from
        a configuration reload or cold reboot.
        """
        with allure.step("Configure global trimming"):
            configure_trimming_global(duthost, TRIM_SIZE, TRIM_DSCP, TRIM_QUEUE)

        with allure.step("Enable trimming in buffer profile"):
            configure_trimming_action(duthost, BLOCK_QUEUE_PROFILE, "on")

        with allure.step("Send packets from PTF to DUT and verify trimmed packets"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)

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

        if is_mellanox_device(duthost):
            with allure.step("Disable packet aging for mellanox device after config reload"):
                configure_packet_aging(duthost, disabled=True)

        with allure.step("Verify trimming function after reload/cold reboot"):
            verify_packet_trimming(duthost, ptfadapter, test_params, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, TRIM_SIZE,
                                   TRIM_DSCP, expect_packets=True)
