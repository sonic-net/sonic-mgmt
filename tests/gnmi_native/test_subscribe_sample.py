"""gNMI sample subscribe test for the native gRPC fixture."""

import logging

import pytest

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import SubscribeMode, StreamMode

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
]


def test_gnmi_subscribe_sample(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    gnmi_client,
):
    """Verify gNMI sample-mode subscribe for STATE_DB and COUNTERS_DB."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    interval_s = 5
    count = 5
    collect_seconds = 40

    def validates_subscribe_responses(responses):
        updates = [r for r in responses if isinstance(r.get("update"), dict)]
        assert len(updates) >= count, (
            "Expected at least {} update responses, got {}.\n"
            "- Full response list: {}"
        ).format(count, len(updates), responses)

        assert all(r["update"].get("timestamp") is not None for r in updates), (
            "Every update response must include a timestamp.\n"
            "- Update responses: {}"
        ).format(updates)

        timestamps = [r["update"]["timestamp"] for r in updates]
        for i in range(len(timestamps) - 1):
            diff = timestamps[i + 1] - timestamps[i]
            assert diff >= (interval_s - 0.5) * 1e9, (
                "Expected consecutive timestamp diff >= {}ns, got {}ns "
                "(ts[{}]={}, ts[{}]={})"
            ).format(int((interval_s - 0.5) * 1e9), diff, i, timestamps[i], i + 1, timestamps[i + 1])

        logger.info("Successfully received %d gNMI subscribe sample responses", len(updates))

    with allure.step("Perform gNMI subscribe sample request to STATE_DB"):
        responses = list(gnmi_client.subscribe(
            paths="/PSU_INFO",
            target="STATE_DB",
            mode=SubscribeMode.STREAM,
            stream_mode=StreamMode.SAMPLE,
            sample_interval=interval_s,
            collect_seconds=collect_seconds,
            count=count,
        ))
        logger.debug("gNMI subscribe STATE_DB response: %s", responses)
        validates_subscribe_responses(responses)

    with allure.step("Perform gNMI subscribe sample request to COUNTERS_DB"):
        responses = list(gnmi_client.subscribe(
            paths="COUNTERS",
            target="COUNTERS_DB",
            mode=SubscribeMode.STREAM,
            stream_mode=StreamMode.SAMPLE,
            sample_interval=interval_s,
            collect_seconds=collect_seconds,
            count=count,
        ))
        logger.debug("gNMI subscribe COUNTERS_DB response: %s", responses)
        validates_subscribe_responses(responses)
