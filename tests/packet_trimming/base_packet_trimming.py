import logging
import random

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, configure_packet_aging
from tests.common.mellanox_data import is_mellanox_device
from tests.packet_trimming.constants import (
    DEFAULT_PACKET_SIZE, DEFAULT_DSCP, MIN_PACKET_SIZE, CONFIG_TOGGLE_COUNT,
    JUMBO_PACKET_SIZE, PORT_TOGGLE_COUNT, COUNTER_DSCP)
from tests.packet_trimming.packet_trimming_config import PacketTrimmingConfig
from tests.packet_trimming.packet_trimming_helper import (
    configure_trimming_action, configure_trimming_acl, verify_srv6_packet_with_trimming, cleanup_trimming_acl,
    verify_trimmed_packet, reboot_dut, check_connected_route_ready, get_switch_trim_counters_json,
    get_port_trim_counters_json, disable_egress_data_plane, enable_egress_data_plane,
    verify_queue_and_port_trim_counter_consistency, get_queue_trim_counters_json, compare_counters)

logger = logging.getLogger(__name__)


class BasePacketTrimming:
    def configure_trimming_global_by_mode(self, duthost):
        raise NotImplementedError

    def get_srv6_recv_pkt_dscp(self):
        raise NotImplementedError

    def get_verify_trimmed_packet_kwargs(self, duthost, ptfadapter, test_params):
        """
        Get kwargs for verify_trimmed_packet
        """
        base_kwargs = dict(
            duthost=duthost,
            ptfadapter=ptfadapter,
            ingress_port=test_params['ingress_port'],
            egress_ports=test_params['egress_ports'],
            block_queue=test_params['block_queue'],
            send_pkt_size=DEFAULT_PACKET_SIZE,
            send_pkt_dscp=DEFAULT_DSCP,
            recv_pkt_size=PacketTrimmingConfig.get_trim_size(duthost),
            expect_packets=True
        )
        base_kwargs.update(self.get_extra_trimmed_packet_kwargs())
        logger.info(f"Base kwargs: {base_kwargs}")
        return base_kwargs

    def get_verify_trimmed_counter_packet_kwargs(self, duthost, ptfadapter, trim_counter_params):
        """
        Get kwargs for verify_trimmed_packet
        """
        base_kwargs = dict(
            duthost=duthost,
            ptfadapter=ptfadapter,
            ingress_port=trim_counter_params['ingress_port'],
            egress_ports=trim_counter_params['egress_ports'],
            block_queue=trim_counter_params['block_queue'],
            send_pkt_size=DEFAULT_PACKET_SIZE,
            send_pkt_dscp=COUNTER_DSCP,
            recv_pkt_size=PacketTrimmingConfig.get_trim_size(duthost),
            expect_packets=True
        )
        base_kwargs.update(self.get_extra_trimmed_packet_kwargs())
        logger.info(f"Base kwargs: {base_kwargs}")
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
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            verify_trimmed_packet(**kwargs)

        max_trim_size = PacketTrimmingConfig.get_max_trim_size(duthost)
        with allure.step(f"Configure trimming in {self.trimming_mode} mode and update trim size to {max_trim_size}"):
            self.configure_trimming_global_by_mode(duthost, max_trim_size)

        with allure.step("Send packets and verify trimming works after config update"):
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            kwargs.update({
                'send_pkt_size': JUMBO_PACKET_SIZE,
                'recv_pkt_size': max_trim_size
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
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            verify_trimmed_packet(**kwargs)

        # When packet size is less than trimming size, the packet is not trimmed, but the DSCP value should be updated
        with allure.step("Verify trim packet when packets size less than trimming size"):
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            kwargs.update({
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
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            verify_trimmed_packet(**kwargs)

        with allure.step("Config ACL rule with DISABLE_TRIM_ACTION action"):
            configure_trimming_acl(duthost, test_params['ingress_port']['name'])

        with allure.step("Verify packets are dropped directly"):
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            kwargs.update({'expect_packets': False})
            verify_trimmed_packet(**kwargs)

        with allure.step("Remove ACL table"):
            cleanup_trimming_acl(duthost)

        with allure.step("Send packets again and verify trimmed packets"):
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
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
                recv_pkt_size=PacketTrimmingConfig.get_trim_size(duthost),
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
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            verify_trimmed_packet(**kwargs)

        with allure.step("Disable trimming"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "off")

        with allure.step(f"Verify no trimming action in {self.trimming_mode} mode when disable trimming"):
            self.configure_trimming_global_by_mode(duthost)
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            kwargs.update({'expect_packets': False})
            verify_trimmed_packet(**kwargs)

        with allure.step("Enable trimming again"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step(f"Verify trimming in {self.trimming_mode} mode after enable trimming"):
            self.configure_trimming_global_by_mode(duthost)
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            verify_trimmed_packet(**kwargs)

        with allure.step("Trimming config toggles"):
            for i in range(CONFIG_TOGGLE_COUNT):
                logger.info(f"Trimming config toggle test iteration {i + 1}")
                for buffer_profile in test_params['trim_buffer_profiles']:
                    configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "off")
                    configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        with allure.step(f"Verify trimming still works after feature toggles in {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
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
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            verify_trimmed_packet(**kwargs)

        with allure.step("Ports admin status toggles"):
            for i in range(PORT_TOGGLE_COUNT):
                for egress_port in test_params['egress_ports']:
                    logger.info(f"Ports admin status toggle test iteration {i+1}")
                    duthost.shutdown(egress_port['name'])
                    duthost.no_shutdown(egress_port['name'])
            pytest_assert(wait_until(30, 5, 0, duthost.check_intf_link_state, egress_port['name']),
                          "Interfaces are not restored to up after the flap")

        with allure.step("Verify connected route is ready after port toggles"):
            for egress_port in test_params['egress_ports']:
                pytest_assert(wait_until(30, 5, 0, check_connected_route_ready, duthost, egress_port),
                              "Connected route is not ready")

        with allure.step("Verify trimming still works after admin toggles"):
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            verify_trimmed_packet(**kwargs)

        with allure.step("Verify packet trimming counter"):
            for egress_port in test_params['egress_ports']:
                for port in egress_port['dut_members']:
                    verify_queue_and_port_trim_counter_consistency(duthost, port)

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
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
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
                pytest_assert(wait_until(30, 5, 0, check_connected_route_ready, duthost, egress_port),
                              "Connected route is not ready")

        if is_mellanox_device(duthost):
            with allure.step("Disable packet aging for mellanox device after config reload"):
                configure_packet_aging(duthost, disabled=True)

        with allure.step(f"Verify trimming function in {self.trimming_mode} mode after reload/cold reboot"):
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            verify_trimmed_packet(**kwargs)

        with allure.step("Verify packet trimming counter"):
            for egress_port in test_params['egress_ports']:
                for port in egress_port['dut_members']:
                    verify_queue_and_port_trim_counter_consistency(duthost, port)

    def test_trimming_counters(self, duthost, ptfadapter, test_params, trim_counter_params):
        """
        Test Case: Verify PacketTrimming Counters
        """
        with allure.step(f"Configure packet trimming in global level for {self.trimming_mode} mode"):
            self.configure_trimming_global_by_mode(duthost)

        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")
            for buffer_profile in trim_counter_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, trim_counter_params['trim_buffer_profiles'][buffer_profile], "on")

        # Packets are trimmed on two queues, verify trimming counters in queue and port level
        with allure.step("Verify trimming counters on two queues"):
            # Trigger trimmed packets on queue0
            counter_kwargs = self.get_verify_trimmed_counter_packet_kwargs(duthost, ptfadapter, {**trim_counter_params})
            verify_trimmed_packet(**counter_kwargs)

            # Verify the consistency of the trim counter on the queue and the port level
            for egress_port in test_params['egress_ports']:
                for port in egress_port['dut_members']:
                    verify_queue_and_port_trim_counter_consistency(duthost, port)

        with allure.step("Verify TrimSent counters on switch level"):
            switch_trim_sent_value = get_switch_trim_counters_json(duthost)['trim_sent']
            logger.info(f"switch_trim_sent_value: {switch_trim_sent_value}")

            # Verify the trim sent counter on the switch level is equal to the sum of the trim sent counter on the
            # port level
            ports_trim_sent_counters = []
            for egress_port in test_params['egress_ports']:
                for port in egress_port['dut_members']:
                    port_trim_tx_value = get_port_trim_counters_json(duthost, port)['TRIM_TX_PKTS']
                    ports_trim_sent_counters.append(port_trim_tx_value)

            # Verify the trim sent counter on the switch level is equal to the sum of the trim sent counter on the
            # port level
            pytest_assert(sum(ports_trim_sent_counters) == switch_trim_sent_value and switch_trim_sent_value != 0,
                          "Trim sent counter on switch level is not equal to the sum of trim sent counter on port "
                          "level")

        trim_queue = PacketTrimmingConfig.get_trim_queue(duthost)

        with allure.step("Verify TrimDrop counters on switch level"):
            original_schedulers = {}
            try:
                # Block the trimmed queue
                for port in trim_counter_params['egress_ports']:
                    for dut_member in port['dut_members']:
                        original_scheduler = disable_egress_data_plane(duthost, dut_member, trim_queue)
                        original_schedulers[dut_member] = original_scheduler

                # Trigger trimmed packets on queue6
                counter_kwargs = self.get_verify_trimmed_counter_packet_kwargs(duthost, ptfadapter, {**trim_counter_params})
                counter_kwargs.update({'expect_packets': False})
                verify_trimmed_packet(**counter_kwargs)

                # Get the TrimDrop counters on switch level
                switch_trim_drop_value = get_switch_trim_counters_json(duthost)['trim_drop']
                logger.info(f"switch_trim_drop_value: {switch_trim_drop_value}")
                pytest_assert(switch_trim_drop_value > 0, "Trim drop counter on switch level is not greater than 0")

            finally:
                # Enable the trimmed queue with original scheduler
                for port in trim_counter_params['egress_ports']:
                    for dut_member in port['dut_members']:
                        original_scheduler = original_schedulers.get(dut_member)
                        enable_egress_data_plane(duthost, dut_member, trim_queue, original_scheduler)

        with allure.step("Verify trimming counter when trimming feature toggles"):
            trim_queue = 'UC'+str(trim_queue)

            # Get queue level and port level counter when trimming is enabled
            port = test_params['egress_ports'][0]['dut_members'][0]
            queue_trim_counter_trim_enable = get_queue_trim_counters_json(duthost, port)[trim_queue]
            logger.info(f"Queue trim counter when trimming is enabled: {queue_trim_counter_trim_enable}")

            port_trim_counters_trim_enable = get_port_trim_counters_json(duthost, port)
            logger.info(f"Port trim counter when trimming is enabled: {port_trim_counters_trim_enable}")

            # Disable trimming
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "off")
            for buffer_profile in trim_counter_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, trim_counter_params['trim_buffer_profiles'][buffer_profile], "off")

            # Get queue level and port level counter when trimming is disabled
            queue_trim_counter_trim_disable = get_queue_trim_counters_json(duthost, port)[trim_queue]
            logger.info(f"Queue trim counter when trimming is disabled: {queue_trim_counter_trim_disable}")

            port_trim_counters_trim_disable = get_port_trim_counters_json(duthost, port)
            logger.info(f"Port trim counter when trimming is disabled: {port_trim_counters_trim_disable}")

            # Compare trim counters when trimming enable and disable
            compare_counters(queue_trim_counter_trim_enable, queue_trim_counter_trim_disable, ['trimpacket'])
            compare_counters(port_trim_counters_trim_enable, port_trim_counters_trim_disable, ['TRIM_PKTS'])

            # Enable trimming again
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")
            for buffer_profile in trim_counter_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, trim_counter_params['trim_buffer_profiles'][buffer_profile], "on")

            # Get queue level and port level counter after trimming feature toggles
            queue_trim_counter_after_toggle = get_queue_trim_counters_json(duthost, port)[trim_queue]
            logger.info(f"Queue trim counter after trimming feature toggles: {queue_trim_counter_after_toggle}")

            port_trim_counters_after_toggle = get_port_trim_counters_json(duthost, port)
            logger.info(f"Port trim counter after trimming feature toggles: {port_trim_counters_after_toggle}")

            # Compare trim counters when trimming enable and feature toggles
            compare_counters(queue_trim_counter_trim_enable, queue_trim_counter_after_toggle, ['trimpacket'])
            compare_counters(port_trim_counters_trim_enable, port_trim_counters_after_toggle,
                             ['TRIM_PKTS', 'TRIM_TX_PKTS', 'TRIM_DRP_PKTS'])
