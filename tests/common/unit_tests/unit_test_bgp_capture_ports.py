"""Exercise the production receive-port helper without testbed dependencies."""
import ast
from pathlib import Path
from unittest.mock import Mock

import pytest


@pytest.mark.parametrize("vm,multi_vrf,expected", [
    ("VM1", False, [100, 104]),
    ("VM10", False, [108]),
    ("unknown", False, pytest.fail.Exception),
    ("VM2", False, KeyError),
    ("Vrf1", True, [100]),
])
def test_receive_ports(vm, multi_vrf, expected):
    path = Path(__file__).resolve().parents[2] / "bgp" / "bgp_helpers.py"
    node = next(n for n in ast.parse(path.read_text(encoding="utf-8")).body
                if isinstance(n, ast.FunctionDef) and n.name == "get_ptf_recv_port")
    namespace = {"pytest_assert": lambda ok, message: None if ok else pytest.fail(message)}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    host = Mock()
    host.get_extended_minigraph_facts.return_value = {
        "minigraph_neighbors": {
            "Ethernet0": {"name": "VM1"}, "Ethernet4": {"name": "VM1"},
            "Ethernet8": {"name": "VM10"}, "Ethernet12": {"name": "VM2"}},
        "minigraph_ptf_indices": {"Ethernet0": 100, "Ethernet4": 104, "Ethernet8": 108},
    }
    host.shell.return_value = {"stdout": "Ethernet0\n" if multi_vrf else "", "rc": 0}
    vrf = {"convergence_mapping": {"VMHOST": ["Vrf1"]},
           "converged_peers": {"VMHOST": {"vrf": {"Vrf1": {"Ethernet9": {}}}}}}
    tbinfo = {"topo": {"properties": {"convergence_data": vrf}}}
    lookup = namespace["get_ptf_recv_port"]
    if isinstance(expected, type):
        with pytest.raises(expected):
            lookup(host, vm, tbinfo, multi_vrf_topo=multi_vrf)
    else:
        assert lookup(host, vm, tbinfo, multi_vrf_topo=multi_vrf) == expected
    if multi_vrf:
        host.shell.assert_called_once_with(
            "show lldp table | grep -w VMHOST[[:space:]]*Ethernet9 | awk '{print $1}'")
    else:
        host.shell.assert_not_called()
