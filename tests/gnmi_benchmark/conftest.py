"""Command-line options for the gNMI benchmark; gnmi_tls owns TLS setup/cleanup."""

from tests.gnmi_benchmark.helpers import add_benchmark_options


def pytest_addoption(parser):
    add_benchmark_options(parser)
