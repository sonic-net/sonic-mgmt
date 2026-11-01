"""Unit tests for management-mode proxy selection."""

import ast
from pathlib import Path

import pytest


SOURCE_PATH = Path(__file__).resolve().parents[2] / "helpers" / "dut_utils.py"
TREE = ast.parse(SOURCE_PATH.read_text(encoding="utf-8"))
FUNCTION = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name == "select_proxy_env"
)
MODULE = ast.Module(body=[FUNCTION], type_ignores=[])
NAMESPACE = {}
exec(compile(MODULE, str(SOURCE_PATH), "exec"), NAMESPACE)
select_proxy_env = NAMESPACE["select_proxy_env"]


def test_select_proxy_env_preserves_default_mode():
    """Keep the existing proxy and object unchanged in default mode."""
    creds = {
        "proxy_env": {"http_proxy": "http://192.0.2.1:3128"},
        "proxy_env_ipv6": {"http_proxy": "http://[2001:db8::1]:3128"},
    }

    assert select_proxy_env(creds, False) is creds
    assert creds["proxy_env"]["http_proxy"] == "http://192.0.2.1:3128"


def test_select_proxy_env_uses_ipv6_proxy_when_configured():
    """Replace the effective proxy without mutating loaded credentials."""
    creds = {
        "proxy_env": {"http_proxy": "http://192.0.2.1:3128"},
        "proxy_env_ipv6": {"http_proxy": "http://[2001:db8::1]:3128"},
    }

    selected = select_proxy_env(creds, True)

    assert selected is not creds
    assert selected["proxy_env"] == creds["proxy_env_ipv6"]
    assert selected["proxy_env"] is not creds["proxy_env_ipv6"]
    assert creds["proxy_env"]["http_proxy"] == "http://192.0.2.1:3128"


def test_select_proxy_env_keeps_existing_behavior_without_ipv6_proxy():
    """Allow IPv6-only labs that do not require a separate proxy."""
    creds = {"proxy_env": {"http_proxy": "http://192.0.2.1:3128"}}

    assert select_proxy_env(creds, True) is creds


def test_select_proxy_env_rejects_malformed_ipv6_proxy():
    """Reject a configured IPv6 proxy that is not a dictionary."""
    with pytest.raises(ValueError, match="must be a dictionary"):
        select_proxy_env({"proxy_env_ipv6": "http://[2001:db8::1]:3128"}, True)
