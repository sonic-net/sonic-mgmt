"""Explicit pytest entrypoint, excluded from default test_*.py discovery."""

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
from tests.gnmi_benchmark.helpers import recover_consumer

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
    # Set only after mapping the Redis subscriber to a service with verified restart/resync behavior.
    "recovery": {"consumer_service": None, "timeout_seconds": 60},
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
            "parameters": {
                # Match sonic-gnmi pkg/bypass/bypass.go AllowedSKUPrefixes.
                "hwsku_prefixes": ("Cisco-8102", "Cisco-8101", "Cisco-8223"),
                "route_distribution": {16000: 1, 20000: 12},
            },
            "profiles": {
                "1000routes-10workers": {"routes_per_request": 1000, "concurrency": 10},
                "1000routes-100workers": {"routes_per_request": 1000, "concurrency": 100},
                "1000routes-200workers": {"routes_per_request": 1000, "concurrency": 200},
                "20000routes-10workers": {"routes_per_request": 20000, "concurrency": 10},
            },
        },
    },
}

BENCHMARK_CASES = []
for name, benchmark in BENCHMARK_CONFIG["benchmarks"].items():
    for profile, parameters in benchmark["profiles"].items():
        for mode, rate in BENCHMARK_CONFIG["load_modes"].items():
            case_id = "{}-{}-{}".format(name, profile, mode)
            params = {**BENCHMARK_CONFIG["parameters"], **benchmark["parameters"], **parameters,
                      "traffic_pattern": mode, "rate": rate, "marker": case_id}
            BENCHMARK_CASES.append(pytest.param(
                benchmark["runner"], partial(benchmark["blaster"], **params), id=case_id))


def _emit_report(request, report):
    key = "gnmi_benchmark.{}".format(report["cid"])
    if request.node is request.session.items[-1]:
        add_custom_msg(request, key, report)
    else:
        request.node.user_properties.append(("CustomMsg", json.dumps({"gnmi_benchmark": {report["cid"]: report}})))


@pytest.fixture
def benchmark_consumer_recovery(request):
    """Set up before dynamic gnmi_tls, so its finalizer runs AFTER TLS rollback."""
    host = request.node._benchmark_host
    yield
    # Finalizer exceptions are pytest teardown errors, outside report-only handling.
    recover_consumer(host, **BENCHMARK_CONFIG["recovery"])


@pytest.mark.parametrize("runner_factory,blaster_factory", BENCHMARK_CASES)
def test_gnmi_benchmark(
    runner_factory,
    blaster_factory,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    request,
):
    report = None
    try:
        host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        blaster = blaster_factory()
        device_sku = host.facts.get("hwsku") or ""
        pytest_require(device_sku, "DUT HwSKU is unavailable")
        if blaster.hwsku_prefixes:
            pytest_require(device_sku.startswith(blaster.hwsku_prefixes), "Unsupported HwSKU: " + device_sku)
        report = BenchmarkReport(
            connection_type="TLS",
            device=dict(hostname=host.hostname, os_version=host.os_version, sku=device_sku,
                        platform=host.facts.get("platform", "unknown"),
                        asic_type=host.facts.get("asic_type", "unknown"),
                        asic_count=host.num_asics()))
        request.node._benchmark_host = host
        # Register before gnmi_tls: pytest unwinds the later fixture first.
        request.getfixturevalue("benchmark_consumer_recovery")
        # Resolve TLS setup only after checking the selected device.
        connection = request.getfixturevalue("gnmi_tls")
        pytest_require(connection.transport == "tls" and connection.pygnmi_client is not None,
                       "The benchmark requires the TLS transport")
        runner_factory().run(host, connection, blaster, report)
    except (Exception, pytest.fail.Exception):
        # Runner context managers unwind before logging; skips/interrupts propagate.
        logger.info("gNMI benchmark report-only exception node=%s", request.node.nodeid, exc_info=True)
        raise
    finally:
        if report is not None and report.measurement is not None:
            path = report.write(BENCHMARK_CONFIG["output_dir"])
            _emit_report(request, report.to_dict())
            logger.info("gNMI benchmark marker=%s cid=%s report=%s", report.marker, report.cid, path)
