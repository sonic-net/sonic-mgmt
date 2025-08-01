import logging
import random

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, configure_packet_aging
from tests.common.mellanox_data import is_mellanox_device
from tests.packet_trimming.constants import (
    TRIM_SIZE, DEFAULT_PACKET_SIZE, DEFAULT_DSCP, MIN_PACKET_SIZE, TRIM_SIZE_MAX, CONFIG_TOGGLE_COUNT,
    JUMBO_PACKET_SIZE, PORT_TOGGLE_COUNT)
from tests.packet_trimming.packet_trimming_helper import (
    configure_trimming_action, configure_trimming_acl, verify_srv6_packet_with_trimming, cleanup_trimming_acl,
    verify_trimmed_packet, reboot_dut, check_connected_route_ready)

logger = logging.getLogger(__name__)


class BasePacketTrimming:
    def configure_trimming_global_by_mode(self, duthost):
        raise NotImplementedError

    def get_srv6_recv_pkt_dscp(self):
        raise NotImplementedError

    def get_verify_trimmed_packet_kwargs(self, test_params):
        """
        Get kwargs for verify_trimmed_packet
        """
        base_kwargs = dict(
            duthost=test_params.get('duthost'),
            ptfadapter=test_params.get('ptfadapter'),
            ingress_port=test_params['ingress_port'],
            egress_ports=test_params['egress_ports'],
            block_queue=test_params['block_queue'],
            send_pkt_size=DEFAULT_PACKET_SIZE,
            send_pkt_dscp=DEFAULT_DSCP,
            recv_pkt_size=TRIM_SIZE,
            expect_packets=True
        )
        base_kwargs.update(self.get_extra_trimmed_packet_kwargs())
        return base_kwargs

    def get_extra_trimmed_packet_kwargs(self):
        """
        Get extra kwargs for verify_trimmed_packet
        """
        return {}

    def test_packet_size_after_trimming(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify Packet Size After Trimming

        This test verifies that packet trimming correctly adjusts packet sizes according to the configured values.
        It tests both standard and maximum trimming sizes to ensure packets are properly trimmed while preserving
        headers and critical information.
        """
        with allure.step(f"Configure packet trimming in global level for {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming packet"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

        with allure.step(f"Configure trimming in {self.trimming_mode} mode and update trim size to {TRIM_SIZE_MAX}"):
            self.configure_trimming_global_by_mode(duthost, TRIM_SIZE_MAX)

        with allure.step("Send packets and verify trimming works after config update"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({
                'duthost': duthost,
                'ptfadapter': ptfadapter,
                'send_pkt_size': JUMBO_PACKET_SIZE,
                'recv_pkt_size': TRIM_SIZE_MAX
            })
            verify_trimmed_packet(**kwargs)

    def test_dscp_remapping_after_trimming(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify DSCP Remapping After Trimming

        This test verifies that DSCP values are correctly remapped according to the trimming configuration.
        It tests two scenarios:
        1. Normal case where packets are trimmed and DSCP is remapped
        2. Special case where packet size is less than trimming size (no trimming occurs but DSCP is still remapped)
        """
        with allure.step(f"Configure packet trimming in global level for {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming packet"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

        # When packet size is less than trimming size, the packet is not trimmed, but the DSCP value should be updated
        with allure.step("Verify trim packet when packets size less than trimming size"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({
                'duthost': duthost,
                'ptfadapter': ptfadapter,
                'send_pkt_size': MIN_PACKET_SIZE,
                'recv_pkt_size': MIN_PACKET_SIZE
            })
            verify_trimmed_packet(**kwargs)

    def test_acl_action_with_trimming(self, duthost, ptfadapter, test_params, clean_trimming_acl_tables):
        """
        Test Case: Verify ACL Action Interaction with Trimming

        This test verifies the interaction between ACL rules with the DISABLE_TRIM action and packet trimming.
        It confirms that when an ACL rule with DISABLE_TRIM action is matched, packets are dropped instead
        of being trimmed, and that trimming returns to normal operation when the ACL rule is removed.
        """
        with allure.step(f"Configure packet trimming in global level for {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming packet"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

        with allure.step("Config ACL rule with DISABLE_TRIM_ACTION action"):
            configure_trimming_acl(duthost, test_params['ingress_port']['name'])

        with allure.step("Verify packets are dropped directly"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({
                'duthost': duthost,
                'ptfadapter': ptfadapter,
                'expect_packets': False
            })
            verify_trimmed_packet(**kwargs)

        with allure.step("Remove ACL table"):
            cleanup_trimming_acl(duthost)

        with allure.step("Send packets again and verify trimmed packets"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

    def test_trimming_with_srv6(self, duthost, ptfadapter, setup_srv6, test_params):
        """
        Test Case: Verify Packet Trimming with SRv6

        This test verifies that packet trimming works correctly with SRv6 (Segment Routing over IPv6) packets.
        It ensures SRv6 headers are preserved while excess payload is trimmed according to configuration.
        """
        with allure.step(f"Configure packet trimming in global level for {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step(f"Verify SRv6 packets after trimming in {self.trimming_mode} mode"):
            recv_pkt_dscp = self.get_srv6_recv_pkt_dscp()
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
                recv_pkt_dscp=recv_pkt_dscp
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

        with allure.step(f"Config and verify trimming in {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

        with allure.step("Disable trimming"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "off")

        with allure.step(f"Verify no trimming action in {self.trimming_mode} mode when disable trimming"):
            self.configure_trimming_global_by_mode(duthost)
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({
                'duthost': duthost,
                'ptfadapter': ptfadapter,
                'expect_packets': False
            })
            verify_trimmed_packet(**kwargs)

        with allure.step("Enable trimming again"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step(f"Verify trimming in {self.trimming_mode} mode after enable trimming"):
            self.configure_trimming_global_by_mode(duthost)
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

        with allure.step("Trimming config toggles"):
            for i in range(CONFIG_TOGGLE_COUNT):
                logger.info(f"Trimming config toggle test iteration {i + 1}")
                for buffer_profile in test_params['trim_buffer_profiles']:
                    configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "off")
                for buffer_profile in test_params['trim_buffer_profiles']:
                    configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step(f"Verify trimming still works after feature toggles in {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

    def test_trimming_during_port_admin_toggle(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify Trimming During Port Admin Status Toggle

        This test verifies that packet trimming functionality remains stable when ports are
        administratively enabled and disabled multiple times. It ensures interface flapping
        does not impact the trimming configuration or functionality.
        """
        with allure.step(f"Configure packet trimming in global level for {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming packet"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

        with allure.step("Ports admin status toggles"):
            for i in range(PORT_TOGGLE_COUNT):
                for egress_port in test_params['egress_ports']:
                    logger.info(f"Ports admin status toggle test iteration {i+1}")
                    duthost.shutdown(egress_port['name'])
                    duthost.no_shutdown(egress_port['name'])
                pytest_assert(wait_until(30, 5, 0, duthost.check_intf_link_state, egress_port['name']),
                              "Interfaces are not restored to up after the flap")

        with allure.step("Verify trimming still works after admin toggles"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

    def test_trimming_with_reload_and_reboot(self, duthost, ptfadapter, test_params, localhost, request):
        """
        Test Case: Verify Trimming Persistence After Reload and Reboot

        This test verifies that packet trimming configurations persist across system reloads and reboots.
        It ensures trimming functionality continues to work normally after the system recovers from
        a configuration reload or cold reboot.
        """
        with allure.step(f"Configure packet trimming in global level for {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step("Verify trimming packet"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)

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

        with allure.step(f"Verify trimming function in {self.trimming_mode} mode after reload/cold reboot"):
            kwargs = self.get_verify_trimmed_packet_kwargs({**test_params})
            kwargs.update({'duthost': duthost, 'ptfadapter': ptfadapter})
            verify_trimmed_packet(**kwargs)
