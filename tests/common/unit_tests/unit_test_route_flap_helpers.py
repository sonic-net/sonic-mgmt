"""Focused tests for converged cSONiC route-flap ExaBGP selection."""

import ast
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "route/test_route_flap.py"
TREE = ast.parse(MODULE_PATH.read_text())
NODE = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name == "get_exabgp_endpoint"
)
NAMESPACE = {"EXABGP_BASE_PORT": 5000}
exec(compile(ast.Module(body=[NODE], type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)
get_exabgp_endpoint = NAMESPACE["get_exabgp_endpoint"]


class DutHost:
    def shell(self, command):
        assert "Ethernet120" in command
        return {"stdout": "ARISTA03T1\n"}


def test_converged_csonic_endpoint_pairs_port_with_peer_backplane_nexthop():
    tbinfo = {
        "vm_type": "csonic",
        "topo": {"properties": {
            "topo_is_multi_vrf": True,
            "convergence_data": {
                "vm_offset_mapping": {"ARISTA03T1": 7},
                "ptf_backplane_addrs": {
                    "ARISTA03T1": {"ipv4": "10.10.7.2/31"},
                },
            },
        }},
    }

    assert get_exabgp_endpoint(DutHost(), tbinfo, "Ethernet120") == (
        5007, "10.10.7.2")


def test_stock_endpoint_keeps_shared_nexthop_selection():
    tbinfo = {
        "vm_type": "veos",
        "topo": {"properties": {
            "topology": {"VMs": {"ARISTA03T1": {"vm_offset": 3}}},
        }},
    }

    assert get_exabgp_endpoint(DutHost(), tbinfo, "Ethernet120") == (
        5003, None)
