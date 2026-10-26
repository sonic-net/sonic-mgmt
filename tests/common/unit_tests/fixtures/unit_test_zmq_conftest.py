"""Offline ZMQ TLS fixture regressions; run with pytest --noconftest."""

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[3] / "zmq" / "conftest.py"
TLS_DIR = "/etc/sonic/telemetry/zmq-gnmi-test"


@pytest.fixture
def fixture_state():
    tables = {"GNMI|gnmi": {}, "GNMI|certs": {}}
    dut = Mock()
    dut.tempfile.return_value = {"path": TLS_DIR}

    def hset(host, database, table, **fields):
        assert host is dut
        tables[table].update(fields)

    def hdel(host, database, table, *fields):
        assert host is dut
        for field in fields:
            tables[table].pop(field, None)

    namespace = {
        "pytest": pytest,
        "gnmi_container": lambda host: "gnmi",
        "CONFIG_DB": "CONFIG_DB",
        "redis_hgetall": lambda host, database, table: dict(tables[table]),
        "redis_hset": hset,
        "redis_hdel": hdel,
    }
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "setup_gnmi_tls"
    ]
    assert len(nodes) == 1
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    generator = namespace["setup_gnmi_tls"].__wrapped__({"dut": dut}, "dut", None)
    return SimpleNamespace(tables=tables, dut=dut, generator=generator)


@pytest.mark.parametrize("original", [
    {"GNMI|gnmi": {}, "GNMI|certs": {}},
    {
        "GNMI|gnmi": {"port": "50052", "client_auth": "true", "user_auth": "password"},
        "GNMI|certs": {"server_crt": "/original.crt", "ca_crt": "/original-ca.crt", "other": "keep"},
    },
])
def test_explicit_tls_and_exact_config_restore(fixture_state, original):
    state = fixture_state
    state.tables.update({table: dict(fields) for table, fields in original.items()})
    next(state.generator)
    assert state.tables["GNMI|certs"]["server_crt"] == TLS_DIR + "/server.crt"
    assert state.tables["GNMI|certs"]["server_key"] == TLS_DIR + "/server.key"
    assert state.tables["GNMI|certs"]["ca_crt"] == ""
    assert state.tables["GNMI|gnmi"]["client_auth"] == "false"
    argv = state.dut.command.call_args.kwargs["argv"]
    assert argv[:3] == ["openssl", "req", "-x509"]
    assert argv[argv.index("-keyout") + 1] == TLS_DIR + "/server.key"
    assert argv[argv.index("-out") + 1] == TLS_DIR + "/server.crt"
    state.dut.wait_for.assert_called_once_with(port=8080, state="started", timeout=60)
    state.dut.file.assert_not_called()
    with pytest.raises(StopIteration):
        next(state.generator)
    assert state.tables == original
    assert state.dut.service.call_count == 2
    state.dut.file.assert_called_once_with(path=TLS_DIR, state="absent")


@pytest.mark.parametrize("failure_point", ["command", "service", "wait_for"])
def test_setup_failure_restores_config_and_removes_credentials(fixture_state, failure_point):
    state = fixture_state
    getattr(state.dut, failure_point).side_effect = [RuntimeError("setup failed"), None]
    with pytest.raises(RuntimeError, match="setup failed"):
        next(state.generator)
    assert state.tables == {"GNMI|gnmi": {}, "GNMI|certs": {}}
    state.dut.file.assert_called_once_with(path=TLS_DIR, state="absent")


def test_test_body_failure_restores_config(fixture_state):
    state = fixture_state
    next(state.generator)
    with pytest.raises(RuntimeError, match="test failed"):
        state.generator.throw(RuntimeError("test failed"))
    assert state.tables == {"GNMI|gnmi": {}, "GNMI|certs": {}}
    state.dut.file.assert_called_once_with(path=TLS_DIR, state="absent")


@pytest.mark.parametrize("setup_also_fails", [False, True])
def test_restart_failure_does_not_skip_credential_cleanup(fixture_state, setup_also_fails):
    state = fixture_state
    if not setup_also_fails:
        next(state.generator)
    state.dut.service.side_effect = RuntimeError("restart failed")
    with pytest.raises(RuntimeError, match="restart failed"):
        next(state.generator)
    assert state.tables == {"GNMI|gnmi": {}, "GNMI|certs": {}}
    assert state.dut.service.call_count == 2
    state.dut.file.assert_called_once_with(path=TLS_DIR, state="absent")
