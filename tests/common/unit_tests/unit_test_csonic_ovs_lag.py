"""Unit tests for the cSONiC userspace-OVS LAG helper."""

import importlib.util
import os


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
_MODULE_PATH = os.path.join(
    _REPO_ROOT, "ansible", "roles", "sonic", "files", "csonic_ovs_lag.py")
_SPEC = importlib.util.spec_from_file_location("csonic_ovs_lag", _MODULE_PATH)
csonic_ovs_lag = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(csonic_ovs_lag)


def test_missing_addresses_compares_canonical_exact_ips():
    address_output = "\n".join([
        "10: PortChannel1 inet 10.0.0.10/31 scope global PortChannel1",
        "10: PortChannel1 inet6 fc00::2/126 scope global",
        "10: PortChannel1 inet6 fc00::2a/126 scope global",
    ])
    expected = [
        "FC00::2/126",
        "fc00::2A/126",
        "10.0.0.1/31",
        "10.0.0.10/31",
        "2001:DB8::1/64",
    ]

    assert csonic_ovs_lag._missing_addresses(expected, address_output) == [
        "10.0.0.1/31",
        "2001:DB8::1/64",
    ]
