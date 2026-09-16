"""Regression test for sonic-mgmt issue #27700.

SonicHost._gather_facts() is decorated with a facts_cache key. Before PR
#21442, that key ('basic_facts') stored a flat dict. After PR #21442 the
function returns a nested {"basic_facts": ..., "versions": ...,
"features": ...} structure, but the decorator kept the same cache key. A
leftover legacy flat pickle from an older sonic-mgmt checkout was therefore
loaded as-is by the new code, and SonicHost.__init__ raised
KeyError('num_asic').

This test avoids importing tests.common.devices.sonic directly, since that
pulls in the full ansible/pytest_ansible/paramiko stack via
tests/common/__init__.py. Instead, following the same approach as
unit_test_dhcp_relay_cleanup.py, it parses the real source with `ast`,
extracts the real _gather_facts FunctionDef (decorator intact), and executes
it against the real cached()/FactsCache implementation loaded directly from
file.
"""

import ast
import importlib.util
import json
import logging
import pickle
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
FACTS_CACHE_PATH = REPO_ROOT / "tests/common/cache/facts_cache.py"
SONIC_PATH = REPO_ROOT / "tests/common/devices/sonic.py"


def _load_real_cache_module():
    """Import facts_cache.py by file path, bypassing tests/common/__init__.py."""
    spec = importlib.util.spec_from_file_location("_facts_cache_under_test", FACTS_CACHE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_gather_facts(cached_decorator):
    """Compile the real SonicHost._gather_facts FunctionDef, decorator intact."""
    tree = ast.parse(SONIC_PATH.read_text())
    sonic_host_cls = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "SonicHost"
    )
    gather_facts_def = next(
        node for node in sonic_host_cls.body
        if isinstance(node, ast.FunctionDef) and node.name == "_gather_facts"
    )
    module = ast.Module(body=[gather_facts_def], type_ignores=[])
    ast.fix_missing_locations(module)

    namespace = {"cached": cached_decorator, "logging": logging, "json": json}
    exec(compile(module, str(SONIC_PATH), "exec"), namespace)
    return namespace["_gather_facts"]


class FakeSonicHost:
    """Minimal stand-in exposing only what _gather_facts touches."""

    def __init__(self, hostname):
        self.hostname = hostname
        self.sonic_basic_facts_calls = 0

    def sonic_basic_facts(self):
        self.sonic_basic_facts_calls += 1
        return {
            "ansible_facts": {
                "basic_facts": {"num_asic": 1, "asic_type": "vs", "hwsku": "test-hwsku"},
                "versions": {"build_version": "master.123-abc"},
                "features": {"gbsyncd": {"state": "disabled"}},
            }
        }

    def get_asics_present_from_inventory(self):
        return []


def test_gather_facts_ignores_legacy_flat_cache(tmp_path):
    cache_module = _load_real_cache_module()

    # Point the (isolated) FactsCache singleton at tmp_path before the
    # decorator below is ever invoked.
    cache_module.FactsCache(cache_location=str(tmp_path))

    # Seed a legacy, pre-PR#21442 style flat pickle under the OLD cache key.
    hostname = "vlab-01"
    zone_dir = tmp_path / hostname
    zone_dir.mkdir()
    legacy_payload = {
        "platform": "x86_64-legacy",
        "hwsku": "legacy-hwsku",
        "asic_type": "vs",
        "num_asic": 1,
        "router_mac": "00:11:22:33:44:55",
    }
    legacy_pickle = zone_dir / "basic_facts.pickle"
    with open(legacy_pickle, "wb") as f:
        pickle.dump(legacy_payload, f, pickle.HIGHEST_PROTOCOL)
    legacy_bytes_before = legacy_pickle.read_bytes()

    gather_facts = _extract_gather_facts(cache_module.cached)
    fake_host = FakeSonicHost(hostname)

    result = gather_facts(fake_host)

    # The legacy flat payload was not returned; a fresh gather happened.
    assert result != legacy_payload
    assert fake_host.sonic_basic_facts_calls == 1
    assert result["basic_facts"]["num_asic"] == 1

    # A new pickle was written under the new key; the legacy one is untouched.
    new_pickle = zone_dir / "sonic_basic_facts.pickle"
    assert new_pickle.exists()
    assert legacy_pickle.exists()
    assert legacy_pickle.read_bytes() == legacy_bytes_before
