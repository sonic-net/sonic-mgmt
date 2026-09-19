"""Command-line options for the gNMI benchmark; gnmi_tls owns TLS setup/cleanup."""


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
    group.addoption("--benchmark-blaster", choices=("route-table",), default="route-table",
                    help="Route-table scenario (the only supported blaster)")
    group.addoption("--benchmark-blaster-params", default="{}",
                    help="JSON keyword arguments for the selected blaster")
    group.addoption("--benchmark-duration", type=float,
                    help="Admission window in seconds; overrides logical request count")
    group.addoption("--benchmark-warmup", type=float,
                    help="Same-channel warmup admission seconds, excluded from measured RPC statistics")
