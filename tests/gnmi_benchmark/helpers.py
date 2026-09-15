"""Benchmark option registration and strict JSON rendering helpers."""

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined


def add_benchmark_options(parser):
    """Register the options exposed by the benchmark's pytest entry point."""
    group = parser.getgroup("gNMI benchmark options")
    group.addoption("--benchmark-operation", choices=("get", "set", "get-set"), default="get")
    group.addoption("--benchmark-concurrency", type=int, default=4)
    group.addoption("--benchmark-logical-requests", type=int, default=100)
    group.addoption("--benchmark-timeout", type=int, default=120)
    group.addoption("--benchmark-output-dir", default="/tmp/gnmi-benchmark")
    group.addoption("--benchmark-bypass", action="store_true", help="Request server-side validation bypass for Set")
    group.addoption("--benchmark-workload", choices=("empty", "port-description", "vnet-route-tunnel"),
                    help="Workload type; defaults to empty for Get, port-description for Set/Get-Set")
    group.addoption("--benchmark-workload-params", default="{}",
                    help="JSON object of workload-specific parameters (entry_count, prepare, payload_file for VNET)")
    group.addoption("--benchmark-duration", type=float, default=0,
                    help="Closed-loop admission window in seconds; overrides logical request count")
    group.addoption("--benchmark-warmup", type=float, default=0,
                    help="Same-channel warmup admission seconds, excluded from measured RPC statistics")


def render_json_template(template_name, context):
    """Render a bundled JSON template with explicit input values."""
    environment = Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        undefined=StrictUndefined,
        autoescape=False,
    )
    return json.loads(environment.get_template(template_name).render(**context))
