"""Local mocks only; run with pytest --noconftest on this file."""

import ast
import base64
import importlib.util
import logging
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Optional, Sequence
from unittest.mock import MagicMock

import pytest


pytestmark = [pytest.mark.topology("any")]


COMMON = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = load_module("gnoi_download", COMMON / "helpers/gnoi_download.py")
CLIENT = load_module("ptf_gnoi", COMMON / "ptf_gnoi.py")


@pytest.mark.parametrize("failure", [None, RuntimeError, pytest.skip.Exception])
@pytest.mark.parametrize("existing", [False, True])
def test_policy_restores_original_state(existing, failure):
    """Success, failure and skip restore original bytes/attributes or absence."""
    original = b'{"previous": "policy"}\n'
    host = MagicMock()
    host.stat.return_value = {"stat": {
        "exists": existing, "isreg": True, "uid": 12, "gid": 34, "mode": "0600",
    }}
    host.slurp.return_value = {"content": base64.b64encode(original).decode()}

    def run():
        with POLICY.temporary_image_policy(host, "http://192.0.2.1/image"):
            assert '"host": "192.0.2.1"' in host.copy.call_args.kwargs["content"]
            if failure:
                raise failure("test exit")
    if failure:
        with pytest.raises(failure):
            run()
    else:
        run()
    if existing:
        host.copy.assert_called_with(
            content=original.decode("utf-8"), dest=POLICY.POLICY_PATH, owner="12", group="34", mode="0600",
        )
        host.file.assert_not_called()
    else:
        host.file.assert_called_once_with(path=POLICY.POLICY_PATH, state="absent")


def test_policy_restore_after_setup_failure():
    """A partially failed policy copy still restores previous state."""
    host = MagicMock()
    host.stat.return_value = {"stat": {"exists": False}}
    host.copy.side_effect = RuntimeError("copy failed")
    with pytest.raises(RuntimeError):
        with POLICY.temporary_image_policy(host, "http://192.0.2.1/image"):
            pytest.fail("must not enter context")
    host.file.assert_called_once_with(path=POLICY.POLICY_PATH, state="absent")


def test_policy_rejects_unrestorable_bytes_before_overwrite():
    """Invalid UTF-8 must not leave the temporary allowlist installed."""
    host = MagicMock()
    host.stat.return_value = {"stat": {"exists": True, "isreg": True}}
    host.slurp.return_value = {"content": base64.b64encode(b"\xff\xfe").decode()}
    with pytest.raises(UnicodeDecodeError):
        with POLICY.temporary_image_policy(host, "http://192.0.2.1/image"):
            pytest.fail("must reject before changing policy")
    host.copy.assert_not_called()
    host.file.assert_not_called()


def test_policy_matches_actual_dpu_not_list_position():
    """DPU inventory ordering cannot send policy to another DPU or the NPU."""
    first, selected = MagicMock(), MagicMock()
    for host, ip in [(first, "192.0.2.2"), (selected, "192.0.2.3")]:
        host.show_ip_interface.return_value = {
            "ansible_facts": {"ip_interfaces": {"eth0-midplane": {"ipv4": ip}}},
        }
    hosts = POLICY.snapshot_download_hosts([first, selected])
    assert hosts["192.0.2.3"] is selected
    assert "192.0.2.4" not in hosts
    with pytest.raises(ValueError):
        POLICY.snapshot_download_hosts([selected, selected])


def test_policy_dns_pins_and_ipv6(monkeypatch):
    """Hostname pins are snapshot addresses; IPv6 literals need no DNS."""
    lookup = MagicMock(return_value=[(None, None, None, None, ("192.0.2.1", 80))])
    monkeypatch.setattr(POLICY.socket, "getaddrinfo", lookup)
    assert POLICY.image_origin_policy("http://images.example/image")["origins"][0]["addresses"] == ["192.0.2.1"]
    assert POLICY.image_origin_policy("https://[2001:db8::1]/image")["origins"][0]["port"] == 443
    assert lookup.call_count == 1
    for url in ["file:///image", "http://images.example/image#fragment"]:
        with pytest.raises(ValueError):
            POLICY.image_origin_policy(url)


def test_dpu_policy_factory_uses_preinitialized_inventory():
    """Parallel callers use captured inventory, not dynamic pytest setup."""
    source = ast.parse((COMMON / "fixtures/gnoi_download_policy.py").read_text())
    tree = ast.Module(body=[
        node for node in source.body if isinstance(node, ast.FunctionDef)
    ], type_ignores=[])
    selected, npu = MagicMock(), MagicMock()
    selected.show_ip_interface.return_value = {
        "ansible_facts": {"ip_interfaces": {"eth0-midplane": {"ipv4": "192.0.2.3"}}},
    }
    configure = MagicMock()
    scope = {
        "pytest": pytest, "snapshot_download_hosts": POLICY.snapshot_download_hosts,
        "get_dpu_ip": MagicMock(return_value="192.0.2.3"),
        "temporary_image_policy": configure,
    }
    exec(compile(tree, "gnoi_download_policy.py", "exec"), scope)
    factory = scope["gnoi_dpu_download_policy"].__wrapped__([selected])
    selected.show_ip_interface.assert_called_once()
    selected.show_ip_interface.side_effect = RuntimeError("another worker rebooted this DPU")
    target = [("x-sonic-ss-target-type", "dpu"), ("x-sonic-ss-target-index", "3")]
    factory(npu, "http://192.0.2.1/image", target)
    configure.assert_called_with(selected, "http://192.0.2.1/image")
    scope["get_dpu_ip"].assert_called_once_with(npu, 3)
    factory(npu, "http://192.0.2.1/image")
    configure.assert_called_with(npu, "http://192.0.2.1/image")
    factory(npu, "http://192.0.2.1/image", target)
    selected.show_ip_interface.assert_called_once()


def test_setpackage_wire_metadata_and_local_compatibility():
    """Remote URL/protocol and target metadata arrive in one package message."""
    grpc = MagicMock()
    grpc.call_client_streaming.return_value = {}
    client = CLIENT.PtfGnoi(grpc)
    target = [("x-sonic-ss-target-type", "dpu"), ("x-sonic-ss-target-index", "3")]
    client.system_set_package("/var/tmp/image", remote_url="https://images.example/image", metadata=target)
    grpc.call_client_streaming.assert_called_with(
        "gnoi.system.System", "SetPackage", [{"package": {
            "filename": "/var/tmp/image", "activate": True,
            "remote_download": {"path": "https://images.example/image", "protocol": "HTTPS"},
        }}], metadata=target,
    )
    client.system_set_package("/var/tmp/local", version="version", activate=False)
    assert grpc.call_client_streaming.call_args.args[2] == [{
        "package": {"filename": "/var/tmp/local", "version": "version", "activate": False},
    }]
    grpc.call_client_streaming.reset_mock()
    with pytest.raises(ValueError):
        client.system_set_package("/var/tmp/image", remote_url="https://images.example/image", protocol="HTTP")
    grpc.call_client_streaming.assert_not_called()


def upgrade_functions(events):
    """Load actual helper functions without importing device/Ansible fixtures."""
    source = ast.parse((COMMON / "helpers/upgrade_helpers.py").read_text())
    names = {
        "perform_gnoi_upgrade", "_upgrade_one_dpu_via_gnoi",
        "perform_gnoi_upgrade_smartswitch_dpus_parallel",
    }
    tree = ast.Module(body=[
        node for node in source.body if isinstance(node, ast.FunctionDef) and node.name in names
    ], type_ignores=[])

    def check(value, message):
        assert value, message

    scope = {
        "GnoiUpgradeConfig": object, "Dict": dict, "logger": logging.getLogger(__name__),
        "Optional": Optional, "Sequence": Sequence,
        "SS_TARGET_TYPE_HDR": "x-sonic-ss-target-type", "SS_TARGET_INDEX_HDR": "x-sonic-ss-target-index",
        "pytest_assert": check, "REBOOT_TYPE_COLD": "cold",
        "reboot_and_check": lambda *args, **kwargs: events.append("reboot"),
        "_get_images_from_sonic_installer_list": lambda host: {"next": "target"},
    }
    exec(compile(tree, "upgrade_helpers.py", "exec"), scope)
    return scope


@pytest.mark.parametrize("indices", [(0, 0), ("0", "00")])
def test_parallel_upgrade_rejects_duplicate_targets_before_workers(indices):
    scope = upgrade_functions([])
    scope["SafeThreadPoolExecutor"] = executor = MagicMock()
    scope["_upgrade_one_dpu_via_gnoi"] = upgrade = MagicMock()
    configs = [SimpleNamespace(metadata={
        "x-sonic-ss-target-type": "dpu", "x-sonic-ss-target-index": str(index),
    }) for index in indices]
    with pytest.raises(ValueError, match="Duplicate DPU target"):
        scope["perform_gnoi_upgrade_smartswitch_dpus_parallel"](None, None, None, configs)
    executor.assert_not_called()
    upgrade.assert_not_called()


def test_parallel_upgrade_accepts_distinct_targets():
    scope = upgrade_functions([])
    scope["SafeThreadPoolExecutor"] = executor = MagicMock()
    configs = [SimpleNamespace(metadata={
        "x-sonic-ss-target-type": "dpu", "x-sonic-ss-target-index": str(index),
    }) for index in (0, 1)]
    result = scope["perform_gnoi_upgrade_smartswitch_dpus_parallel"](None, None, None, configs)
    assert set(result) == {0, 1}
    assert executor.return_value.__enter__.return_value.submit.call_count == 2


@pytest.mark.parametrize("pattern,expected", [
    ("all", ["npu-dpu0", "npu-dpu1"]),
    ("npu-dpu1", ["npu-dpu1"]),
    (None, []),
])
def test_parallel_npu_keeps_dpu_inventory_and_nat_selection(pattern, expected):
    """The NPU target selector must not replace the DPU host list."""
    source = ast.parse((COMMON.parents[0] / "conftest.py").read_text())
    names = {
        "get_specified_device_info", "get_specified_dpus",
        "fixture_dpuhosts", "enable_nat_for_dpuhosts",
    }
    tree = ast.Module(body=[
        node for node in source.body if isinstance(node, ast.FunctionDef) and node.name in names
    ], type_ignores=[])
    request, adhoc, npu = MagicMock(), MagicMock(), MagicMock()
    request.config.getoption.return_value = pattern
    tbinfo = {"duts": ["npu", "npu-dpu0", "npu-dpu1"]}
    scope = {
        "pytest": pytest, "logging": logging, "logger": logging.getLogger(__name__),
        "get_tbinfo": lambda request: ("mock-testbed", tbinfo),
        "is_parallel_run": lambda request: True, "get_target_hostname": lambda request: "npu",
        "is_parallel_leader": lambda request: False,
        "get_duts_from_host_pattern": lambda pattern: pattern.split(","),
        "DutHosts": MagicMock(), "is_enabled_nat_for_dpu": lambda *args: False,
        "get_dpu_names_and_ssh_ports": MagicMock(return_value={}),
        "enable_nat_for_dpus": MagicMock(),
        "pt_assert": lambda value, message: pytest.fail(message) if not value else None,
    }
    exec(compile(tree, "conftest.py", "exec"), scope)
    assert scope["get_specified_dpus"](request) == expected
    assert scope["get_specified_device_info"](request, "--host-pattern") == ["npu"]
    scope["enable_nat_for_dpuhosts"].__wrapped__([npu], adhoc, request)
    if expected:
        scope["get_dpu_names_and_ssh_ports"].assert_called_once_with(npu, expected, adhoc)
        scope["enable_nat_for_dpus"].assert_called_once_with(npu, {}, request)
    else:
        scope["get_dpu_names_and_ssh_ports"].assert_not_called()
        scope["enable_nat_for_dpus"].assert_not_called()
    scope["fixture_dpuhosts"].__wrapped__(None, adhoc, tbinfo, request, None)
    scope["DutHosts"].assert_called_once_with(adhoc, tbinfo, request, expected)


@pytest.mark.parametrize("dpu,fail,skip_reboot", [
    (False, False, False), (False, True, False), (True, False, True), (True, True, True),
])
def test_upgrade_routes_setpackage_and_restores_before_reboot(dpu, fail, skip_reboot):
    """No old transfer, no reboot on failure, and skip_reboot still installs."""
    events = []
    scope = upgrade_functions(events)
    grpc = MagicMock()

    def install(**kwargs):
        events.append("install")
        assert kwargs["remote_url"] == "http://192.0.2.1/image"
        assert kwargs.get("metadata") == (target if dpu else None)
        if fail:
            raise RuntimeError("download/install failed")
        return {}
    grpc.system_set_package.side_effect = install
    target = [("x-sonic-ss-target-type", "dpu"), ("x-sonic-ss-target-index", "3")]
    cfg = SimpleNamespace(
        to_image="http://192.0.2.1/image", dut_image_path="/var/tmp/image",
        upgrade_type="cold", protocol=None, to_version="target",
        metadata=target if dpu else None, skip_reboot=skip_reboot, allow_fail=True,
    )

    @contextmanager
    def policy(host, url, metadata=None):
        assert metadata == (target if dpu else None)
        events.append("policy")
        try:
            yield
        finally:
            events.append("restore")
    fn = scope["_upgrade_one_dpu_via_gnoi" if dpu else "perform_gnoi_upgrade"]
    kwargs = dict(
        duthost=MagicMock(), tbinfo={"topo": {}}, ptf_gnoi=grpc, cfg=cfg,
        download_policy=policy,
    )
    if not dpu:
        kwargs.update(
            localhost=object(), conn_graph_facts={}, xcvr_skip_list={},
            cold_reboot_setup=lambda: events.append("base setup"),
        )
    if fail:
        with pytest.raises(RuntimeError):
            fn(**kwargs)
    else:
        fn(**kwargs)
    expected = ([] if dpu else ["base setup"]) + ["policy", "install", "restore"]
    if not dpu and not fail:
        expected.append("reboot")
    assert events == expected
    grpc.file_transfer_to_remote.assert_not_called()
