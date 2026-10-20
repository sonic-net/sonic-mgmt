"""Unit tests for conditional mark proxy loading."""

import ast
import logging
import os
from pathlib import Path

import pytest
import yaml


SOURCE_PATH = (
    Path(__file__).resolve().parents[2]
    / "plugins"
    / "conditional_mark"
    / "__init__.py"
)
TREE = ast.parse(SOURCE_PATH.read_text(encoding="utf-8"))
FUNCTION = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name == "get_http_proxies"
)
MODULE = ast.Module(body=[FUNCTION], type_ignores=[])
NAMESPACE = {
    "os": os,
    "yaml": yaml,
    "logger": logging.getLogger(__name__),
}
exec(compile(MODULE, str(SOURCE_PATH), "exec"), NAMESPACE)
get_http_proxies = NAMESPACE["get_http_proxies"]


def _write_env(root, inventory, public_env, inventory_env):
    all_dir = root / "group_vars" / "all"
    inventory_dir = root / "group_vars" / inventory
    all_dir.mkdir(parents=True)
    inventory_dir.mkdir(parents=True)
    (all_dir / "env.yml").write_text(yaml.safe_dump(public_env), encoding="utf-8")
    (inventory_dir / "env.yml").write_text(yaml.safe_dump(inventory_env), encoding="utf-8")


def test_inventory_without_proxy_env_preserves_global_proxy(tmp_path):
    """Keep the global IPv4 proxy when inventory adds only an IPv6 proxy."""
    _write_env(
        tmp_path,
        "lab",
        {"proxy_env": {"http_proxy": "http://192.0.2.1:3128"}},
        {"proxy_env_ipv6": {"http_proxy": "http://[2001:db8::1]:3128"}},
    )
    NAMESPACE["ANSIBLE_CONFIG_PATH"] = tmp_path

    assert get_http_proxies("lab") == {
        "http": "http://192.0.2.1:3128",
        "https": "http://192.0.2.1:3128",
    }


@pytest.mark.parametrize(
    "proxy_url",
    ["http://192.0.2.2:3128", "http://[2001:db8::2]:3128"],
)
def test_inventory_proxy_env_overrides_global_proxy(tmp_path, proxy_url):
    """Honor an explicit inventory proxy for IPv4 and IPv6 proxy URLs."""
    _write_env(
        tmp_path,
        "lab",
        {"proxy_env": {"http_proxy": "http://192.0.2.1:3128"}},
        {
            "proxy_env": {"http_proxy": proxy_url},
            "proxy_env_ipv6": {"http_proxy": "http://[2001:db8::3]:3128"},
        },
    )
    NAMESPACE["ANSIBLE_CONFIG_PATH"] = tmp_path

    assert get_http_proxies("lab") == {
        "http": proxy_url,
        "https": proxy_url,
    }


def test_empty_inventory_proxy_env_explicitly_disables_proxy(tmp_path):
    """Preserve support for an explicit inventory no-proxy override."""
    _write_env(
        tmp_path,
        "lab",
        {"proxy_env": {"http_proxy": "http://192.0.2.1:3128"}},
        {"proxy_env": {}},
    )
    NAMESPACE["ANSIBLE_CONFIG_PATH"] = tmp_path

    assert get_http_proxies("lab") == {"http": "", "https": ""}
