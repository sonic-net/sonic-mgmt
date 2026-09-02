import importlib.util
import inspect
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/fixtures/grpc_fixtures.py")


def _stub(name, **attributes):
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    return module


def _load_target_module():
    dummy = type("Dummy", (), {"GNMI_MODE": "gnmi"})
    tests_common = _stub("tests.common", __path__=[])
    grpc_config = SimpleNamespace(
        DEFAULT_TLS_PORT=50052, DEFAULT_PLAINTEXT_PORT=8080,
        CA_CERT="gnmiCA.pem", CLIENT_CERT="gnmicert.pem", CLIENT_KEY="gnmikey.pem",
        get_ptf_cert_paths=lambda: {
            "ca_cert": "/ptf/ca", "client_cert": "/ptf/cert", "client_key": "/ptf/key"},
    )
    modules = {
        "tests.common": tests_common,
        "tests.common.platform": _stub("tests.common.platform", __path__=[]),
        "tests.common.helpers": _stub("tests.common.helpers", __path__=[]),
        "tests.common.cert_utils": _stub(
            "tests.common.cert_utils", create_gnmi_cert_generator=Mock()),
        "tests.common.grpc_config": _stub("tests.common.grpc_config", grpc_config=grpc_config),
        "tests.common.gu_utils": _stub(
            "tests.common.gu_utils", create_checkpoint=Mock(), rollback=Mock()),
        "tests.common.platform.processes_utils": _stub(
            "tests.common.platform.processes_utils", wait_critical_processes=Mock()),
        "tests.common.helpers.gnmi_utils": _stub(
            "tests.common.helpers.gnmi_utils", GNMIEnvironment=dummy),
        "tests.common.ptf_grpc": _stub("tests.common.ptf_grpc", PtfGrpc=dummy),
        "tests.common.ptf_gnoi": _stub("tests.common.ptf_gnoi", PtfGnoi=dummy),
        "tests.common.pygnmi_client": _stub("tests.common.pygnmi_client", PygnmiClient=dummy),
        "tests.common.dut_grpc": _stub("tests.common.dut_grpc", DutGrpc=dummy),
        "tests.common.dut_gnoi": _stub("tests.common.dut_gnoi", DutGnoi=dummy),
        "tests.common.utilities": _stub("tests.common.utilities", wait_until=Mock()),
    }
    spec = importlib.util.spec_from_file_location("unit_target_grpc_fixtures", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    modules[spec.name] = module
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


@pytest.fixture
def grpc_fixtures():
    return _load_target_module()


def test_target_module_loader_restores_import_stubs():
    names = ("tests.common", "tests.common.grpc_config", "unit_target_grpc_fixtures")
    before = {name: sys.modules.get(name) for name in names}

    _load_target_module()

    assert {name: sys.modules.get(name) for name in names} == before


def test_fixture_scopes_and_signatures(grpc_fixtures):
    def scope(fixture):
        marker = getattr(fixture, "_fixture_function_marker", None)
        return (marker or fixture._pytestfixturefunction).scope

    assert scope(grpc_fixtures.gnmi_tls) == "function"
    assert list(inspect.signature(grpc_fixtures.gnmi_tls).parameters) == [
        "request", "duthosts", "ptfhost"]
    assert not hasattr(grpc_fixtures, "gnmi_tls_module")


def test_gnmi_tls_delegates_to_lifecycle_for_selected_dut(grpc_fixtures, monkeypatch):
    selected = SimpleNamespace(hostname="selected")
    ptfhost = object()
    calls = []

    def lifecycle(duthost, ptf):
        calls.append((duthost, ptf))
        yield "fixture"

    request = SimpleNamespace(
        fixturenames=["rand_one_dut_hostname"],
        getfixturevalue=Mock(return_value="selected"))
    duthosts = {0: object(), "selected": selected}
    monkeypatch.setattr(grpc_fixtures, "_gnmi_tls_lifecycle", lifecycle)

    assert list(grpc_fixtures.gnmi_tls.__wrapped__(
        request, duthosts, ptfhost)) == ["fixture"]
    assert calls == [(selected, ptfhost)]
    request.getfixturevalue.assert_called_once_with("rand_one_dut_hostname")


def test_function_fixture_preserves_uds_path(grpc_fixtures, monkeypatch):
    selected = SimpleNamespace(hostname="selected")
    uds_flow = Mock(return_value=iter(["uds fixture"]))
    request = SimpleNamespace(
        param="uds", fixturenames=["rand_one_dut_hostname"],
        getfixturevalue=Mock(return_value="selected"))
    monkeypatch.setattr(grpc_fixtures, "_gnmi_uds_flow", uds_flow)
    monkeypatch.setattr(
        grpc_fixtures, "_gnmi_tls_lifecycle",
        Mock(side_effect=AssertionError("TLS lifecycle should not run")))

    assert list(grpc_fixtures.gnmi_tls.__wrapped__(
        request, {"selected": selected}, object())) == ["uds fixture"]
    uds_flow.assert_called_once_with(selected)


@pytest.mark.parametrize("failure_stage", ["setup", "consumer"])
def test_lifecycle_cleans_up_after_failure(grpc_fixtures, monkeypatch, failure_stage):
    events = []

    def record(event, result=None):
        return lambda *args, **kwargs: events.append(event) or result

    def establish(*args, **kwargs):
        if failure_stage == "setup":
            raise RuntimeError("setup failed")

    client = Mock()
    client.close.side_effect = record("close")
    monkeypatch.setattr(grpc_fixtures, "create_checkpoint", Mock())
    monkeypatch.setattr(grpc_fixtures, "_establish_gnoi_tls_handshake", establish)
    monkeypatch.setattr(grpc_fixtures, "PtfGrpc", Mock())
    monkeypatch.setattr(grpc_fixtures, "PtfGnoi", Mock())
    monkeypatch.setattr(grpc_fixtures, "PygnmiClient", Mock(return_value=client))
    monkeypatch.setattr(grpc_fixtures, "rollback", record(
        "rollback", {"rc": 0, "stdout": "Config rolled back successfully"}))
    monkeypatch.setattr(grpc_fixtures, "wait_critical_processes", record("wait"))
    monkeypatch.setattr(grpc_fixtures, "_delete_gnoi_certs", record("delete"))
    lifecycle = grpc_fixtures._gnmi_tls_lifecycle(
        SimpleNamespace(mgmt_ip="192.0.2.1"), object())

    with pytest.raises(RuntimeError, match="{} failed".format(failure_stage)):
        if failure_stage == "setup":
            next(lifecycle)
        else:
            next(lifecycle)
            lifecycle.throw(RuntimeError("consumer failed"))

    cleanup = ["rollback", "wait", "delete"]
    assert events == (["close"] + cleanup if failure_stage == "consumer" else cleanup)
