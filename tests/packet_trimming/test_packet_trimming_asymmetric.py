import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.packet_trimming.constants import (
    DEFAULT_PACKET_SIZE, DEFAULT_DSCP, JUMBO_PACKET_SIZE,
    ASYM_PORT_1_DSCP, ASYM_PORT_2_DSCP, MODE_TOGGLE_COUNT,
    NORMAL_PACKET_DSCP, PACKET_COUNT)
from tests.packet_trimming.packet_trimming_config import PacketTrimmingConfig
from tests.packet_trimming.packet_trimming_helper import (
    configure_trimming_global, verify_trimming_config, configure_trimming_action, verify_trimmed_packet,
    remove_tc_to_dscp_map, configure_tc_to_dscp_map, verify_normal_packet, verify_packet_trimming)
from tests.packet_trimming.base_packet_trimming import BasePacketTrimming


pytestmark = [
    pytest.mark.topology("t0", "t1")
]

logger = logging.getLogger(__name__)


class TestPacketTrimmingAsymmetric(BasePacketTrimming):
    trimming_mode = "asymmetric"

    def configure_trimming_global_by_mode(self, duthost, size=None):
        """
        Configure trimming global by trimming mode
        """
        if size is None:
            size = PacketTrimmingConfig.get_trim_size(duthost)
        queue = PacketTrimmingConfig.get_trim_queue(duthost)
        asym_tc = PacketTrimmingConfig.get_asym_tc(duthost)
        configure_trimming_global(duthost, size=size, queue=queue, dscp='from-tc', tc=asym_tc)

    def get_extra_trimmed_packet_kwargs(self):
        return dict(
            recv_pkt_dscp_port1=ASYM_PORT_1_DSCP,
            recv_pkt_dscp_port2=ASYM_PORT_2_DSCP
        )

    def get_srv6_recv_pkt_dscp(self):
        return ASYM_PORT_1_DSCP

    def test_trimming_configuration(self, duthost, test_params):
        """
        Test Case: Verify Trimming Configuration
        """
        with allure.step(f"Testing {self.trimming_mode} DSCP valid configurations"):
            for size, dscp, queue, tc in PacketTrimmingConfig.get_valid_trim_configs(duthost, asymmetric=True):
                logger.info(f"Testing valid config: size={size}, dscp={dscp}, queue={queue}, tc={tc}")
                pytest_assert(configure_trimming_global(duthost, size=size, queue=queue, dscp=dscp, tc=tc))

        with allure.step(f"Testing {self.trimming_mode} DSCP invalid configurations"):
            for size, dscp, queue, tc in PacketTrimmingConfig.get_invalid_trim_configs(duthost, asymmetric=True):
                logger.info(f"Testing invalid config: size={size}, dscp={dscp}, queue={queue}, tc={tc}")
                pytest_assert(not configure_trimming_global(duthost, size=size, queue=queue, dscp=dscp, tc=tc))

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

        trim_size = PacketTrimmingConfig.get_trim_size(duthost)
        trim_queue = PacketTrimmingConfig.get_trim_queue(duthost)
        asym_tc = PacketTrimmingConfig.get_asym_tc(duthost)

        with allure.step("Verify setting TC value while missing TC_TO_DSCP_MAP attached to the egress port"):
            remove_tc_to_dscp_map(duthost)
            configure_trimming_global(duthost, size=trim_size, queue=trim_queue, dscp='from-tc', tc=asym_tc)
            verify_trimming_config(duthost, size=trim_size, queue=trim_queue, dscp='from-tc', tc=asym_tc)

        with allure.step("Verify that trimming is configured before configuring tc_to_dscp_map"):
            configure_tc_to_dscp_map(duthost, test_params['egress_ports'])
            kwargs = self.get_verify_trimmed_packet_kwargs(duthost, ptfadapter, {**test_params})
            kwargs.update({
                'send_pkt_size': DEFAULT_PACKET_SIZE,
                'recv_pkt_size': trim_size
            })
            verify_trimmed_packet(**kwargs)

    def test_symmetric_asymmetric_mode_switch(self, duthost, ptfadapter, test_params):
        """
        Test Case: Verify trimming works after switching between symmetric and asymmetric DSCP modes multiple times.
        """
        with allure.step("Enable trimming in buffer profile"):
            for buffer_profile in test_params['trim_buffer_profiles']:
                configure_trimming_action(duthost, test_params['trim_buffer_profiles'][buffer_profile], "on")

        trim_size = PacketTrimmingConfig.get_trim_size(duthost)
        trim_queue = PacketTrimmingConfig.get_trim_queue(duthost)
        asym_tc = PacketTrimmingConfig.get_asym_tc(duthost)
        trim_dscp = PacketTrimmingConfig.DSCP

        for i in range(MODE_TOGGLE_COUNT):
            with allure.step(f"Round {i+1}: Configure trimming in Symmetric DSCP mode"):
                configure_trimming_global(duthost, size=trim_size, queue=trim_queue, dscp=trim_dscp)
                for egress_port in test_params['egress_ports']:
                    verify_packet_trimming(
                        duthost=duthost,
                        ptfadapter=ptfadapter,
                        ingress_port=test_params['ingress_port'],
                        egress_port=egress_port,
                        block_queue=test_params['block_queue'],
                        send_pkt_size=DEFAULT_PACKET_SIZE,
                        send_pkt_dscp=DEFAULT_DSCP,
                        recv_pkt_size=trim_size,
                        recv_pkt_dscp=trim_dscp,
                        packet_count=PACKET_COUNT
                    )

            with allure.step(f"Round {i+1}: Configure trimming in Asymmetric DSCP mode"):
                configure_trimming_global(duthost, size=trim_size, queue=trim_queue, dscp='from-tc', tc=asym_tc)
                verify_trimmed_packet(
                    duthost=duthost,
                    ptfadapter=ptfadapter,
                    ingress_port=test_params['ingress_port'],
                    egress_ports=test_params['egress_ports'],
                    block_queue=test_params['block_queue'],
                    send_pkt_size=DEFAULT_PACKET_SIZE,
                    send_pkt_dscp=DEFAULT_DSCP,
                    recv_pkt_size=trim_size,
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

        trim_size = PacketTrimmingConfig.get_trim_size(duthost)
        trim_queue = PacketTrimmingConfig.get_trim_queue(duthost)
        asym_tc = PacketTrimmingConfig.get_asym_tc(duthost)

        with allure.step("Configure trimming in Asymmetric DSCP mode"):
            configure_trimming_global(duthost, size=trim_size, queue=trim_queue, dscp='from-tc', tc=asym_tc)

        with allure.step("Verify trimming in Asymmetric DSCP mode"):
            verify_trimmed_packet(
                duthost=duthost,
                ptfadapter=ptfadapter,
                ingress_port=test_params['ingress_port'],
                egress_ports=test_params['egress_ports'],
                block_queue=test_params['block_queue'],
                send_pkt_size=DEFAULT_PACKET_SIZE,
                send_pkt_dscp=DEFAULT_DSCP,
                recv_pkt_size=trim_size,
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
