"""Pytest entrypoint: select a workflow, run it in the environment, then write its result."""

import json
import logging

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.custom_msg_utils import add_custom_msg
from tests.gnmi_benchmark.benchmark_runner import BenchmarkRunner
from tests.gnmi_benchmark.benchmark_report import BenchmarkReport
from tests.gnmi_benchmark.blaster import RouteTableBlaster

logger = logging.getLogger(__name__)
pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.stress_test,
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.skip_check_dut_health,
]


def _blaster_from_options(config):
    try:
        params = json.loads(config.getoption("--benchmark-blaster-params"))
        if not isinstance(params, dict):
            raise ValueError("blaster-params must be a JSON object")
        option_names = (
            ("concurrency", "concurrency"), ("logical_requests", "logical-requests"),
            ("timeout_seconds", "timeout"), ("duration_seconds", "duration"),
            ("warmup_seconds", "warmup"), ("traffic_pattern", "traffic"), ("rate", "rate"), ("marker", "marker"))
        for key, flag in option_names:
            value = config.getoption("--benchmark-" + flag)
            if value is not None:
                params[key] = value
        return RouteTableBlaster(**params)
    except (ValueError, TypeError) as error:
        raise pytest.UsageError(str(error)) from error


def _emit_report(request, report):
    key = "gnmi_benchmark.{}".format(report["cid"])
    if request.node is request.session.items[-1]:
        add_custom_msg(request, key, report)
    else:
        request.node.user_properties.append(("CustomMsg", json.dumps({"gnmi_benchmark": {report["cid"]: report}})))


def test_gnmi_benchmark(
    gnmi_tls,  # noqa: F811
    pytestconfig,
    request,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
):
    host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    blaster = _blaster_from_options(pytestconfig)
    if gnmi_tls.transport != "tls" or gnmi_tls.pygnmi_client is None:
        pytest.skip("The benchmark requires the TLS transport")
    device_sku = host.shell("sonic-db-cli CONFIG_DB HGET 'DEVICE_METADATA|localhost' hwsku")["stdout"].strip()
    report = BenchmarkReport(
        connection_type=gnmi_tls.transport.upper(),
        device=dict(hostname=host.hostname, os_version=host.os_version, sku=device_sku,
                    platform=host.facts.get("platform", "unknown"), asic_type=host.facts.get("asic_type", "unknown"),
                    asic_count=host.num_asics()))
    result = BenchmarkRunner().run(host, gnmi_tls, blaster, report)
    path = result.write(pytestconfig.getoption("--benchmark-output-dir"))
    _emit_report(request, result.to_dict())
    logger.info("gNMI benchmark marker=%s report=%s", result.marker, path)
    if result.failed:
        pytest.fail("gNMI benchmark marker={} has RPC failures, requests over 1000ms, or dropped arrivals".format(
            result.marker))
