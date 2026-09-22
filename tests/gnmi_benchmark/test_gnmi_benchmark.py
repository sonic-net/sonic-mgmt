"""Pytest entrypoint: select a workflow, run it in the environment, then write its result."""

import json
import logging

import pytest

from tests.common.helpers.custom_msg_utils import add_custom_msg
from tests.gnmi_benchmark.benchmark_report import BenchmarkReport

logger = logging.getLogger(__name__)
pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.stress_test,
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.skip_check_dut_health,
]


def _emit_report(request, report):
    key = "gnmi_benchmark.{}".format(report["cid"])
    if request.node is request.session.items[-1]:
        add_custom_msg(request, key, report)
    else:
        request.node.user_properties.append(("CustomMsg", json.dumps({"gnmi_benchmark": {report["cid"]: report}})))


def test_gnmi_benchmark(
    benchmark_device,
    benchmark_blaster,
    benchmark_runner,
    benchmark_connection,
    pytestconfig,
    request,
):
    host, device_sku = benchmark_device
    report = BenchmarkReport(
        connection_type=benchmark_connection.transport.upper(),
        device=dict(hostname=host.hostname, os_version=host.os_version, sku=device_sku,
                    platform=host.facts.get("platform", "unknown"), asic_type=host.facts.get("asic_type", "unknown"),
                    asic_count=host.num_asics()))
    result = benchmark_runner.run(host, benchmark_connection, benchmark_blaster, report)
    path = result.write(pytestconfig.getoption("--benchmark-output-dir"))
    _emit_report(request, result.to_dict())
    logger.info("gNMI benchmark marker=%s report=%s", result.marker, path)
    if result.failed:
        pytest.fail("gNMI benchmark marker={} has RPC failures, requests over 1000ms, or dropped arrivals".format(
            result.marker))
