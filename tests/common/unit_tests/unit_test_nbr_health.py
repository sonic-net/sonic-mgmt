"""
Unit tests for tests/test_nbr_health.py::test_neighbors_health.

Covers https://github.com/sonic-net/sonic-mgmt/issues/27339: on converged
multi-VRF topologies several logical neighbors (nbrhosts entries) share one
physical cEOS VM (same nbrhost.hostname, distinct EosHost objects).
test_neighbors_health() must run check_snmp/check_eos_facts/
check_eos_bgp_facts exactly once per physical hostname, not once per logical
neighbor, while still failing the test if a check reports a problem.

The real tests/test_nbr_health.py is loaded by file path via importlib, with
lightweight stub modules injected into sys.modules for its
tests.common.helpers.assertions / tests.common.devices.eos / .sonic
imports. This avoids importing the real tests.common package (which pulls
in ansible/paramiko), matching the isolation pattern used by
tests/common/unit_tests/fixtures/unit_test_conn_graph_facts.py. Runs with
only Python, pytest, and unittest.mock via:

    python3 -m pytest --noconftest tests/common/unit_tests/unit_test_nbr_health.py
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = Path(__file__).resolve().parents[2] / "test_nbr_health.py"


def _install_stub_modules():
    """Inject fakes for test_nbr_health.py's tests.common.* imports."""
    assertions_mod = types.ModuleType("tests.common.helpers.assertions")

    def pytest_assert(condition, message=""):
        if not condition:
            pytest.fail(message)

    assertions_mod.pytest_assert = pytest_assert

    eos_mod = types.ModuleType("tests.common.devices.eos")

    class EosHost:
        def __init__(self, hostname, bgp_vrf=None):
            self.hostname = hostname
            self.bgp_vrf = bgp_vrf

    eos_mod.EosHost = EosHost

    sonic_mod = types.ModuleType("tests.common.devices.sonic")

    class SonicHost:
        pass

    sonic_mod.SonicHost = SonicHost

    sys.modules.update({
        "tests": types.ModuleType("tests"),
        "tests.common": types.ModuleType("tests.common"),
        "tests.common.helpers": types.ModuleType("tests.common.helpers"),
        "tests.common.helpers.assertions": assertions_mod,
        "tests.common.devices": types.ModuleType("tests.common.devices"),
        "tests.common.devices.eos": eos_mod,
        "tests.common.devices.sonic": sonic_mod,
    })


def _load_target_module():
    _install_stub_modules()
    spec = importlib.util.spec_from_file_location("tests.test_nbr_health", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def nbr_health_module():
    return _load_target_module()


def _neighbor(mgmt_addr):
    return {"mgmt_addr": mgmt_addr, "type": "SpineRouter"}


def _run(module, nei_meta, nbrhosts, hostname="dut-1"):
    duthost = MagicMock()
    duthost.hostname = hostname
    duthost.config_facts.return_value = {
        "ansible_facts": {
            "DEVICE_NEIGHBOR_METADATA": nei_meta,
            "DEVICE_METADATA": {"localhost": {"type": "LeafRouter"}},
        }
    }
    module.test_neighbors_health(
        duthosts={hostname: duthost},
        localhost=MagicMock(),
        nbrhosts=nbrhosts,
        eos={"snmp_rocommunity": "public"},
        sonic={"snmp_rocommunity": "public"},
        enum_frontend_dut_hostname=hostname,
    )


def test_same_physical_host_checked_once(nbr_health_module):
    """Two logical VRF siblings, same hostname, different bgp_vrf: each
    health helper is called exactly once."""
    EosHost = nbr_health_module.EosHost
    host_a = EosHost("VM0104", bgp_vrf="vrf-a")
    host_b = EosHost("VM0104", bgp_vrf="vrf-b")
    assert host_a is not host_b

    nei_meta = {"vrf-a": _neighbor("10.250.0.1"), "vrf-b": _neighbor("10.250.0.1")}
    nbrhosts = {"vrf-a": {"host": host_a}, "vrf-b": {"host": host_b}}

    with patch.object(nbr_health_module, "check_snmp", return_value=None) as m_snmp, \
            patch.object(nbr_health_module, "check_eos_facts", return_value=None) as m_facts, \
            patch.object(nbr_health_module, "check_eos_bgp_facts", return_value=None) as m_bgp:
        _run(nbr_health_module, nei_meta, nbrhosts)

    assert m_snmp.call_count == 1
    assert m_facts.call_count == 1
    assert m_bgp.call_count == 1


def test_different_physical_hosts_checked_independently(nbr_health_module):
    """Two logical neighbors on two different physical hosts: each health
    helper is called exactly twice, once per physical host."""
    EosHost = nbr_health_module.EosHost
    host_a = EosHost("VM0104")
    host_b = EosHost("VM0105")

    nei_meta = {"nbr-a": _neighbor("10.250.0.1"), "nbr-b": _neighbor("10.250.0.2")}
    nbrhosts = {"nbr-a": {"host": host_a}, "nbr-b": {"host": host_b}}

    with patch.object(nbr_health_module, "check_snmp", return_value=None) as m_snmp, \
            patch.object(nbr_health_module, "check_eos_facts", return_value=None) as m_facts, \
            patch.object(nbr_health_module, "check_eos_bgp_facts", return_value=None) as m_bgp:
        _run(nbr_health_module, nei_meta, nbrhosts)

    assert m_snmp.call_count == 2
    assert m_facts.call_count == 2
    assert m_bgp.call_count == 2


def test_failure_propagates_despite_dedup(nbr_health_module):
    """A failure from the single check run against a shared physical host
    still fails test_neighbors_health(), even though the sibling VRF that
    would have repeated the check is deduplicated."""
    EosHost = nbr_health_module.EosHost
    host_a = EosHost("VM0104", bgp_vrf="vrf-a")
    host_b = EosHost("VM0104", bgp_vrf="vrf-b")

    nei_meta = {"vrf-a": _neighbor("10.250.0.1"), "vrf-b": _neighbor("10.250.0.1")}
    nbrhosts = {"vrf-a": {"host": host_a}, "vrf-b": {"host": host_b}}

    with patch.object(nbr_health_module, "check_snmp", return_value=None) as m_snmp, \
            patch.object(nbr_health_module, "check_eos_facts", return_value=None) as m_facts, \
            patch.object(nbr_health_module, "check_eos_bgp_facts",
                         return_value="vrf-a bgp not configured correctly") as m_bgp:
        with pytest.raises(pytest.fail.Exception):
            _run(nbr_health_module, nei_meta, nbrhosts)

    # The failure was detected via the single check that ran on the shared
    # physical host ...
    assert m_bgp.call_count == 1
    # ... even though the second logical sibling was deduplicated.
    assert m_snmp.call_count == 1
    assert m_facts.call_count == 1
