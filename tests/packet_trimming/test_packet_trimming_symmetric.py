import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.packet_trimming.base_packet_trimming import BasePacketTrimming
from tests.packet_trimming.constants import (
    TRIM_SIZE, TRIM_DSCP, TRIM_QUEUE, VALID_TRIMMING_CONFIGS_SYM, INVALID_TRIMMING_CONFIGS_SYM)
from tests.packet_trimming.packet_trimming_helper import configure_trimming_global

pytestmark = [
    pytest.mark.topology("t0", "t1")
]

logger = logging.getLogger(__name__)


class TestPacketTrimmingSymmetric(BasePacketTrimming):
    trimming_mode = "symmetric"

    def configure_trimming_global_by_mode(self, duthost, size=TRIM_SIZE):
        """
        Configure trimming global by trimming mode
        """
        configure_trimming_global(duthost, size=size, queue=TRIM_QUEUE, dscp=TRIM_DSCP)

    def get_extra_trimmed_packet_kwargs(self):
        return dict(
            recv_pkt_dscp_port1=TRIM_DSCP,
            recv_pkt_dscp_port2=TRIM_DSCP
        )

    def get_srv6_recv_pkt_dscp(self):
        return TRIM_DSCP

    def test_trimming_configuration(self, duthost, test_params):
        """
        Test Case: Verify Trimming Configuration
        """
        with allure.step(f"Testing {self.trimming_mode} DSCP valid configurations"):
            for size, dscp, queue in VALID_TRIMMING_CONFIGS_SYM:
                logger.info(f"Testing valid config: size={size}, dscp={dscp}, queue={queue}")
                pytest_assert(configure_trimming_global(duthost, size=size, queue=queue, dscp=dscp))

        with allure.step(f"Testing {self.trimming_mode} DSCP invalid configurations"):
            for size, dscp, queue in INVALID_TRIMMING_CONFIGS_SYM:
                logger.info(f"Testing invalid config: size={size}, dscp={dscp}, queue={queue}")
                pytest_assert(not configure_trimming_global(duthost, size=size, queue=queue, dscp=dscp))
