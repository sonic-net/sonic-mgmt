"""Command-line options for the gNMI benchmark; gnmi_tls owns TLS setup/cleanup."""

import json

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_require as require
from tests.gnmi_benchmark.benchmark_runner import BenchmarkRunner
from tests.gnmi_benchmark.blaster import BLASTERS


def pytest_addoption(parser):
    group = parser.getgroup("gNMI benchmark options")
    group.addoption("--benchmark-marker", help="Label copied into logs/reports; defaults to the blaster name")
    group.addoption("--benchmark-traffic", choices=("closed-loop", "open-loop"))
    group.addoption("--benchmark-rate", type=float,
                    help="Open-loop workload iterations/s; requires open-loop")
    group.addoption("--benchmark-concurrency", type=int)
    group.addoption("--benchmark-logical-requests", type=int)
    group.addoption("--benchmark-timeout", type=int)
    group.addoption("--benchmark-output-dir", default="/tmp/gnmi-benchmark")
    group.addoption("--benchmark-blaster", choices=tuple(BLASTERS), default="route-table",
                    help="Registered benchmark workload")
    group.addoption("--benchmark-blaster-params", default="{}",
                    help="JSON keyword arguments for the selected blaster")
    group.addoption("--benchmark-duration", type=float,
                    help="Admission window in seconds; overrides logical request count")
    group.addoption("--benchmark-warmup", type=float,
                    help="Same-channel warmup admission seconds, excluded from measured RPC statistics")


@pytest.fixture
def benchmark_blaster(pytestconfig):
    """Select the workload; explicit CLI flags override JSON parameters."""
    try:
        params = json.loads(pytestconfig.getoption("--benchmark-blaster-params"))
        if not isinstance(params, dict):
            raise ValueError("blaster-params must be a JSON object")
        option_names = (
            ("concurrency", "concurrency"), ("logical_requests", "logical-requests"),
            ("timeout_seconds", "timeout"), ("duration_seconds", "duration"),
            ("warmup_seconds", "warmup"), ("traffic_pattern", "traffic"), ("rate", "rate"), ("marker", "marker"))
        for key, flag in option_names:
            value = pytestconfig.getoption("--benchmark-" + flag)
            if value is not None:
                params[key] = value
        return BLASTERS[pytestconfig.getoption("--benchmark-blaster")](**params)
    except (ValueError, TypeError) as error:
        raise pytest.UsageError(str(error)) from error


@pytest.fixture
def benchmark_device(duthosts, enum_rand_one_per_hwsku_frontend_hostname, benchmark_blaster):
    """Check workload-specific eligibility on the selected DUT before TLS setup."""
    host = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    result = host.shell(
        "sonic-db-cli CONFIG_DB HGET 'DEVICE_METADATA|localhost' hwsku", module_ignore_errors=True)
    hwsku = result.get("stdout", "").strip()
    if result.get("rc") != 0 or not hwsku:
        pytest.fail("Unable to read DUT HwSKU from CONFIG_DB")
    prefixes = benchmark_blaster.hwsku_prefixes
    require(not prefixes or hwsku.startswith(prefixes),
            "{} requires HwSKU prefix {}; got {}".format(benchmark_blaster.name, ", ".join(prefixes), hwsku))
    return host, hwsku


@pytest.fixture
def benchmark_connection(benchmark_device, request):
    """Resolve the mutating TLS fixture only after device eligibility passes."""
    connection = request.getfixturevalue("gnmi_tls")
    require(connection.transport == "tls" and connection.pygnmi_client is not None,
            "The benchmark requires the TLS transport")
    return connection


@pytest.fixture
def benchmark_runner():
    return BenchmarkRunner()
