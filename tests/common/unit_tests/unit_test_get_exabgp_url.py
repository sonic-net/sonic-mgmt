"""Unit tests for get_exabgp_url() in tests/common/helpers/bgp.py.

https://github.com/sonic-net/sonic-mgmt/issues/27916

get_exabgp_url() must bracket IPv6 literals (RFC 3986) while leaving IPv4
addresses and hostnames unchanged. The function is extracted via ast so
these tests don't need the full sonic-mgmt testbed dependency chain
(paramiko, etc.) pulled in by importing tests.common.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_get_exabgp_url.py -v
"""

import ast
import ipaddress
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "common" / "helpers" / "bgp.py"


def _load_get_exabgp_url():
    tree = ast.parse(MODULE_PATH.read_text())
    func = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "get_exabgp_url"
    )
    namespace = {"ipaddress": ipaddress}
    exec(compile(ast.Module(body=[func], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["get_exabgp_url"]


get_exabgp_url = _load_get_exabgp_url()


@pytest.mark.parametrize("host,port,expected", [
    ("10.1.2.3", 5000, "http://10.1.2.3:5000"),
    ("2001:db8::1", 5000, "http://[2001:db8::1]:5000"),
    ("ptf.example.com", 5000, "http://ptf.example.com:5000"),
])
def test_get_exabgp_url(host, port, expected):
    assert get_exabgp_url(host, port) == expected
