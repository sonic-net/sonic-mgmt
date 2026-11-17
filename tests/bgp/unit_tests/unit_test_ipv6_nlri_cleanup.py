"""Regression tests for scoped converged-EOS restoration after NLRI tests."""

import ast
from pathlib import Path
import tempfile
from unittest.mock import Mock, call

import pytest


CONFIG = """router bgp 64512
   router-id 192.0.2.1
   vrf OTHER
      rd 64512:1
      neighbor 192.0.2.2 remote-as 64513
   !
   vrf SELECTED
      rd 64512:2
      neighbor 192.0.2.4 remote-as 64514
      address-family ipv6
         neighbor 192.0.2.4 activate
   !
   vrf LAST
      rd 64512:3
!
interface Ethernet1
   no shutdown
"""


@pytest.fixture
def cleanup():
    path = Path(__file__).resolve().parents[1] / "test_ipv6_nlri_over_ipv4.py"
    tree = ast.parse(path.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == "_eos_vrf_restore_config")
    setup = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "setup")
    yielded = next(i for i, node in enumerate(setup.body)
                   if isinstance(node, ast.Expr) and isinstance(node.value, ast.Yield))
    teardown = ast.FunctionDef(
        name="teardown",
        args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=setup.body[yielded + 1:], decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[helper, teardown], type_ignores=[]))
    host = Mock()
    dut = Mock()
    namespace = {
        "tempfile": tempfile,
        "config_reload": Mock(),
        "is_sonic_neigh": False,
        "nbrhosts": {"peer": {"host": host}},
        "neigh_name": "peer",
        "neigh_host": host,
        "neigh_eos_bgp_parents": ["router bgp 64512", "vrf SELECTED"],
        "duthost": dut,
        "EOS_NEIGH_BACKUP_CONFIG_FILE": "/tmp/backup_{}",
        "eos_vrf_restore_config": None,
        "setup_info": {
            "eos_nlri_route_map": "NLRI_UNIT", "eos_nlri_route_map_created": True,
            "eos_nlri_peer_group": "NLRI_GROUP_UNIT", "eos_nlri_peer_group_created": True,
        },
    }
    exec(compile(module, str(path), "exec"), namespace)
    return namespace


def test_scoped_payload_contains_only_selected_bgp_vrf(cleanup):
    payload = cleanup["_eos_vrf_restore_config"](CONFIG, ["router bgp 64512", "vrf SELECTED"])

    assert payload == """router bgp 64512
   no vrf SELECTED
   vrf SELECTED
      rd 64512:2
      neighbor 192.0.2.4 remote-as 64514
      address-family ipv6
         neighbor 192.0.2.4 activate
"""


@pytest.mark.parametrize("parents", [
    ["router bgp 64512", "vrf MISSING"],
    ["router bgp 64515", "vrf SELECTED"],
])
def test_missing_context_rejected_before_mutation(cleanup, parents):
    with pytest.raises(ValueError, match="absent from the backup"):
        cleanup["_eos_vrf_restore_config"](CONFIG, parents)
    cleanup["neigh_host"].eos_config.assert_not_called()


@pytest.mark.parametrize("restore_fails", [False, True])
def test_vrf_restore_merges_only_bgp_and_always_reloads_dut(cleanup, restore_fails):
    payload = cleanup["_eos_vrf_restore_config"](CONFIG, ["router bgp 64512", "vrf SELECTED"])
    cleanup["eos_vrf_restore_config"] = payload
    temporary_paths = []

    removed_maps = []

    def restore(match, replace, verbose, **kwargs):
        assert (match, replace, verbose) == ("none", "line", False)
        if "lines" in kwargs:
            if kwargs["lines"] == ["no neighbor NLRI_GROUP_UNIT peer group"]:
                assert kwargs["parents"] == ["router bgp 64512"]
            removed_maps.extend(kwargs["lines"])
            return
        path = Path(kwargs["src"])
        temporary_paths.append(path)
        assert path.read_text() == payload
        if restore_fails:
            raise RuntimeError("restore failed")

    cleanup["neigh_host"].eos_config.side_effect = restore
    if restore_fails:
        with pytest.raises(RuntimeError, match="restore failed"):
            cleanup["teardown"]()
    else:
        cleanup["teardown"]()

    assert temporary_paths and not temporary_paths[0].exists()
    assert removed_maps == ["no neighbor NLRI_GROUP_UNIT peer group", "no route-map NLRI_UNIT"]
    cleanup["neigh_host"].load_configuration.assert_not_called()
    cleanup["config_reload"].assert_called_once_with(
        cleanup["duthost"], safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True,
    )


@pytest.mark.parametrize("sonic_neighbor", [False, True])
def test_ordinary_neighbor_restoration_preserved(cleanup, sonic_neighbor):
    cleanup["is_sonic_neigh"] = sonic_neighbor
    cleanup["teardown"]()

    expected = []
    if sonic_neighbor:
        expected.append(call(cleanup["neigh_host"], wait=60, is_dut=False))
    else:
        cleanup["neigh_host"].load_configuration.assert_called_once()
    expected.append(call(cleanup["duthost"], safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True))
    assert cleanup["config_reload"].call_args_list == expected


def test_peer_group_cleanup_failure_still_removes_map_and_recovers_dut(cleanup):
    cleanup["eos_vrf_restore_config"] = "router bgp 64512\n"
    cleanup["neigh_host"].eos_config.side_effect = [None, RuntimeError("group cleanup failed"), None]

    with pytest.raises(RuntimeError, match="group cleanup failed"):
        cleanup["teardown"]()

    assert cleanup["neigh_host"].eos_config.call_args.kwargs["lines"] == ["no route-map NLRI_UNIT"]
    cleanup["config_reload"].assert_called_once()


@pytest.mark.parametrize("failure_at", [None, "route_map", "peer_group"])
def test_converged_resources_are_owned_and_registered_before_creation(failure_at):
    path = Path(__file__).resolve().parents[1] / "test_ipv6_nlri_over_ipv4.py"
    tree = ast.parse(path.read_text())
    test = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "test_nlri")
    block = next(node for node in test.body if isinstance(node, ast.If)
                 and any(isinstance(child, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == "neigh_ipv6_addr"
                                 for target in child.targets) for child in node.orelse))
    host = Mock()
    host.eos_command.return_value = {"stdout": ["router bgp 64512"]}
    setup = {
        "neighhost": host, "neigh_ip_v6": "2001:db8::1", "dut_ip_v4": "192.0.2.1",
        "dut_asn": 64512, "neigh_eos_bgp_parents": ["router bgp 64513", "vrf SELECTED"],
        "eos_nlri_route_map": "NLRI_UNIT",
        "eos_nlri_peer_group": "NLRI_GROUP_UNIT",
    }

    def configure(**kwargs):
        assert setup["eos_nlri_route_map_created"] is True
        creating_map = kwargs["parents"] == ["route-map NLRI_UNIT permit 10"]
        if not creating_map:
            assert setup["eos_nlri_peer_group_created"] is True
        if failure_at == ("route_map" if creating_map else "peer_group"):
            raise RuntimeError("create failed")

    host.eos_config.side_effect = configure
    compiled = compile(ast.Module(body=block.orelse, type_ignores=[]), str(path), "exec")
    if failure_at:
        with pytest.raises(RuntimeError, match="create failed"):
            exec(compiled, {"setup": setup, "logger": Mock()})
    else:
        exec(compiled, {"setup": setup, "logger": Mock()})
        assert "neighbor NLRI_GROUP_UNIT route-map NLRI_UNIT out" in host.eos_config.call_args.kwargs["lines"]
        assert "neighbor NLRI_GROUP_UNIT peer group" in host.eos_config.call_args_list[1].kwargs["lines"]
    assert host.eos_config.call_args_list[0].kwargs["parents"] == ["route-map NLRI_UNIT permit 10"]
