import ast
from pathlib import Path

import pytest


def _load_get_peer_snappi_chassis():
    module_path = Path(__file__).resolve().parents[2] / "snappi_tests" / "common_helpers.py"
    source = module_path.read_text(encoding="utf-8")
    parsed = ast.parse(source, filename=str(module_path))

    target_fn = None
    for node in parsed.body:
        if isinstance(node, ast.FunctionDef) and node.name == "get_peer_snappi_chassis":
            target_fn = node
            break

    if target_fn is None:
        raise RuntimeError("get_peer_snappi_chassis not found in common_helpers.py")

    isolated_module = ast.Module(body=[target_fn], type_ignores=[])
    ast.fix_missing_locations(isolated_module)
    namespace = {}
    exec(compile(isolated_module, filename=str(module_path), mode="exec"), namespace)
    return namespace["get_peer_snappi_chassis"]


get_peer_snappi_chassis = _load_get_peer_snappi_chassis()


@pytest.mark.parametrize("tbinfo", [None, {"tgs": ["ixia-tg"]}])
def test_get_peer_snappi_chassis_returns_none_when_no_direct_snappi_peer(tbinfo):
    conn_data = {
        "device_conn": {
            "dut-01": {
                "Ethernet0": {
                    "peerdevice": "fanout-switch-01",
                    "peerport": "Ethernet1",
                    "speed": "100000",
                }
            }
        },
        "device_info": {
            "fanout-switch-01": {
                "Type": "FanoutLeaf",
                "HwSku": "Arista-7060CX",
            }
        },
    }

    # get_peer_snappi_chassis intentionally does not fallback to tbinfo['tgs'].
    # If there is no direct Snappi/Ixia peer in conn_data, the function must return None.
    # Even when tbinfo has a traffic-generator list (tgs), the function should not use that as a fallback.
    # Filter snappi_fanouts to only include those present in fanout_graph_facts
    # Some fanouts may be detected via tbinfo but not in the direct connection graph
    # (e.g., when Ixia is behind an L1 switch). We only want fanouts that are
    # direct peers of the DUT so we can get proper port information.
    assert get_peer_snappi_chassis(conn_data, "dut-01", tbinfo=tbinfo) is None


def test_get_peer_snappi_chassis_returns_direct_peer_with_tbinfo_none():
    conn_data = {
        "device_conn": {
            "dut-01": {
                "Ethernet0": {
                    "peerdevice": "ixia-sonic",
                    "peerport": "Card1/Port1",
                    "speed": "100000",
                }
            }
        },
        "device_info": {
            "ixia-sonic": {
                "Type": "DevIxia",
                "HwSku": "IXIA-tester",
            }
        },
    }

    assert get_peer_snappi_chassis(conn_data, "dut-01", tbinfo=None) == ["ixia-sonic"]
