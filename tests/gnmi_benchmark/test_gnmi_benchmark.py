"""Pytest entrypoint: select a workflow, run it in the environment, then write its result."""

import json
import logging
from functools import partial

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.custom_msg_utils import add_custom_msg
from tests.gnmi_benchmark.benchmark_report import BenchmarkReport
from tests.gnmi_benchmark.benchmark_runner import BenchmarkRunner
from tests.gnmi_benchmark.blaster import RouteTableBlaster

logger = logging.getLogger(__name__)
pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.stress_test,
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.skip_check_dut_health,
]

# Default automation settings. Blaster constructor defaults remain available to direct callers.
BENCHMARK_CONFIG = {
    "output_dir": "/tmp/gnmi-benchmark",
    "parameters": {
        "warmup_seconds": 60,
        "duration_seconds": 60,
        "timeout_seconds": 120,
    },
    "load_modes": {"closed-loop": 0, "open-loop": 500},  # Offered iterations/s; 0 means unpaced.
    "benchmarks": {
        "route-table": {
            "runner": BenchmarkRunner,
            "blaster": RouteTableBlaster,
            "parameters": {"route_distribution": {16000: 1, 20000: 12}},
            "profiles": {
                "1000routes-10workers": {"routes_per_request": 1000, "concurrency": 10},
                "1000routes-100workers": {"routes_per_request": 1000, "concurrency": 100},
                "1000routes-200workers": {"routes_per_request": 1000, "concurrency": 200},
                "20000routes-10workers": {"routes_per_request": 20000, "concurrency": 10},
            },
        },
    },
}

BENCHMARK_CASES = [
    pytest.param(
        benchmark["runner"],
        partial(benchmark["blaster"], **{
            **BENCHMARK_CONFIG["parameters"], **benchmark["parameters"], **parameters,
            "traffic_pattern": mode, "rate": rate, "marker": "{}-{}-{}".format(name, profile, mode),
        }),
        id="{}-{}-{}".format(name, profile, mode),
    )
    for name, benchmark in BENCHMARK_CONFIG["benchmarks"].items()
    for profile, parameters in benchmark["profiles"].items()
    for mode, rate in BENCHMARK_CONFIG["load_modes"].items()
]


def _emit_report(request, report):
    key = "gnmi_benchmark.{}".format(report["cid"])
    if request.node is request.session.items[-1]:
        add_custom_msg(request, key, report)
    else:
        request.node.user_properties.append(("CustomMsg", json.dumps({"gnmi_benchmark": {report["cid"]: report}})))


@pytest.mark.parametrize("runner_factory,blaster_factory", BENCHMARK_CASES)
def test_gnmi_benchmark(
    runner_factory,
    blaster_factory,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    request,
):
    host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    blaster = blaster_factory()
    device_sku = host.facts.get("hwsku") or ""
    pytest_require(device_sku, "DUT HwSKU is unavailable")
    if blaster.hwsku_prefixes:
        pytest_require(device_sku.startswith(blaster.hwsku_prefixes), "Unsupported HwSKU: " + device_sku)
    # Resolve TLS setup only after checking the selected device.
    connection = request.getfixturevalue("gnmi_tls")
    pytest_require(connection.transport == "tls" and connection.pygnmi_client is not None,
                   "The benchmark requires the TLS transport")
    report = BenchmarkReport(
        connection_type=connection.transport.upper(),
        device=dict(hostname=host.hostname, os_version=host.os_version, sku=device_sku,
                    platform=host.facts.get("platform", "unknown"), asic_type=host.facts.get("asic_type", "unknown"),
                    asic_count=host.num_asics()))
    result = runner_factory().run(host, connection, blaster, report)
    path = result.write(BENCHMARK_CONFIG["output_dir"])
    _emit_report(request, result.to_dict())
    logger.info("gNMI benchmark marker=%s report=%s", result.marker, path)
    if result.failed:
        pytest.fail("gNMI benchmark marker={} has RPC failures, requests over 1000ms, or dropped arrivals".format(
            result.marker))
