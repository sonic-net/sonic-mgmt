"""gNMI functional tests migrated to the native PygnmiClient."""
import logging

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import StreamMode, SubscribeMode


logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]


def test_gnmi_subscribe_sample(duthosts, rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """Verify gNMI STREAM subscriptions deliver five-second SAMPLE updates."""
    duthost = duthosts[rand_one_dut_hostname]

    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    sample_count = 5
    interval_ns = 5_000_000_000

    def validate_subscribe_sample(responses):
        assert len(responses) == sample_count + 1, \
            f"Expected exactly 6 responses, got {len(responses)}: {responses}"

        initial, *samples = responses
        assert initial.get("sync_response") is True, \
            f"Initial response missing sync_response: {initial}"
        assert isinstance(initial.get("update"), dict), \
            f"Initial response missing update payload: {initial}"
        assert all(isinstance(sample.get("update"), dict) for sample in samples), \
            f"SAMPLE response missing update payload: {samples}"

        timestamps = [sample["update"].get("timestamp") for sample in samples]
        assert all(isinstance(timestamp, int) and timestamp > 0 for timestamp in timestamps), \
            f"SAMPLE response missing a valid timestamp: {samples}"

        for previous, current in zip(timestamps, timestamps[1:]):
            delta = current - previous
            assert round(delta, -8) == interval_ns, \
                f"Expected 5-second SAMPLE interval, got {delta / 1e9:.3f}s: {timestamps}"

    with allure.step("Perform gNMI subscribe sample request to state DB"):
        responses = list(gnmi_tls.pygnmi_client.subscribe(
            "/PSU_INFO",
            target="STATE_DB",
            mode=SubscribeMode.STREAM,
            stream_mode=StreamMode.SAMPLE,
            sample_interval=5,
            count=sample_count + 1,
            collect_seconds=40,
        ))
        logger.debug("gNMI subscribe STATE_DB response: %s", responses)
        validate_subscribe_sample(responses)

    with allure.step("Perform gNMI subscribe sample request to counters DB"):
        responses = list(gnmi_tls.pygnmi_client.subscribe(
            "COUNTERS",
            target="COUNTERS_DB",
            mode=SubscribeMode.STREAM,
            stream_mode=StreamMode.SAMPLE,
            sample_interval=5,
            count=sample_count + 1,
            collect_seconds=40,
        ))
        logger.debug("gNMI subscribe COUNTERS_DB response: %s", responses)
        validate_subscribe_sample(responses)
