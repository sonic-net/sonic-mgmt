"""Offline AAA reuse regressions; no device connections or testbed imports."""

import ast
from copy import deepcopy
import json
import shlex
from pathlib import Path
import subprocess
import sys
import textwrap
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

TESTS = Path(__file__).resolve().parents[3]
AAA = TESTS / "common/fixtures/gnmi_aaa.py"
GRPC = TESTS / "common/fixtures/grpc_fixtures.py"


def _source(path, names=None):
    tree = ast.parse(path.read_text())
    tree.body = [node for node in tree.body
                 if not isinstance(node, (ast.Import, ast.ImportFrom))
                 and (names is None or getattr(node, "name", None) in names)]
    return ast.unparse(tree)


def _load():
    from contextlib import contextmanager
    import logging
    import time
    ns = dict(contextmanager=contextmanager, json=json, shlex=shlex, logging=logging, time=time,
              pytest=pytest, CONFIG_DB="CONFIG_DB")
    exec(compile(_source(AAA), str(AAA), "exec"), ns)
    # Integration pytest.ini uses a custom LogRecord field supplied by its
    # conftest. The offline harness intentionally does not load that plugin.
    ns["logger"] = Mock()
    return ns


@pytest.fixture
def environment():
    ns = _load()
    initial = {
        "GNMI_CLIENT_CERT": {ns["PRINCIPAL"]: {"role@": "admin", "extra": "preserve"}},
        "DEVICE_METADATA": {"localhost": {"cloudtype": "", "hostname": "dut"}},
    }
    state = deepcopy(initial)
    events = []
    dut = SimpleNamespace()

    def read(command, **kwargs):
        if " EVAL " in command:
            raw = state.get("GNMI_CLIENT_CERT", {}).get(ns["PRINCIPAL"], {})
            value = [item for pair in raw.items() for item in pair] if raw else {}
        else:
            # Model ConfigDBConnector.raw_to_typed, independently of raw Redis.
            value = deepcopy(state)
            value["GNMI_CLIENT_CERT"] = {
                key: {(field[:-1] if field.endswith("@") else field):
                      (data.split(",") if field.endswith("@") else data)
                      for field, data in mapping.items() if field != "NULL"}
                for key, mapping in state.get("GNMI_CLIENT_CERT", {}).items()
            }
        return {"rc": 0, "stdout": json.dumps(value)}

    dut.shell = Mock(side_effect=read)
    client = SimpleNamespace(close=Mock())
    fixture = SimpleNamespace(duthost=dut, pygnmi_client=client)

    def flow(*args, **kwargs):
        events.append("start")
        try:
            yield fixture
        finally:
            events.append("stop")
            state.clear()
            state.update(deepcopy(initial))

    def mutate(key, fields=None, delete=False):
        table, entry = key.split("|", 1)
        if delete:
            state.setdefault(table, {}).pop(entry, None)
        elif fields is not None:
            state.setdefault(table, {}).setdefault(entry, {}).update(fields)
        return {"rc": 0}

    ns.update(
        _gnmi_tls_flow=flow, _get_target_duthost=lambda *args: dut,
        redis_del=lambda host, db, key: [mutate(key, delete=True)],
        redis_hset=lambda host, db, key, **fields: mutate(key, fields),
    )

    def hdel(host, db, key, field):
        table, entry = key.split("|", 1)
        state[table][entry].pop(field, None)
        return {"rc": 0}

    ns["redis_hdel"] = hdel
    return SimpleNamespace(ns=ns, state=state, initial=initial, events=events,
                           dut=dut, client=client, owner=ns["_RoleTlsOwner"]())


@pytest.mark.parametrize("cloud", [None, "", "Private"])
@pytest.mark.parametrize("role", [None, "", "readonly", "readwrite"])
def test_repeated_reuse_restores_exact_state(environment, cloud, role):
    env = environment
    metadata = env.initial["DEVICE_METADATA"]["localhost"]
    if cloud is None:
        metadata.pop("cloudtype")
    else:
        metadata["cloudtype"] = cloud
    env.state.clear()
    env.state.update(deepcopy(env.initial))
    for _ in range(3):
        with env.owner.case(None, None, None):
            if role is None:
                env.state["GNMI_CLIENT_CERT"].clear()
            else:
                env.state["GNMI_CLIENT_CERT"][env.ns["PRINCIPAL"]]["role@"] = role
            env.state["DEVICE_METADATA"]["localhost"]["cloudtype"] = "Public"
        assert env.state == env.initial
    assert env.events == ["start"]
    assert env.client.close.call_count == 6
    env.owner.close()
    assert env.events == ["start", "stop"]


def test_context_exception_restores_and_closes(environment):
    env = environment
    with pytest.raises(ValueError, match="body"):
        with env.owner.case(None, None, None):
            env.state["GNMI_CLIENT_CERT"].clear()
            raise ValueError("body")
    assert env.state == env.initial
    assert env.events == ["start", "stop"]
    with env.owner.case(None, None, None):
        pass
    assert env.events == ["start", "stop", "start"]
    env.owner.close()


def test_unrelated_leak_fails_before_rollback(environment):
    env = environment
    with pytest.raises(AssertionError, match="Unrelated configuration leak"):
        with env.owner.case(None, None, None):
            env.state["OTHER"] = {"key": {"field": "leak"}}
    assert env.events == ["start", "stop"]
    assert env.owner.broken
    with pytest.raises(RuntimeError, match="refusing further reuse"):
        env.owner.acquire(None, None, None)


def test_dirty_start_rejected(environment):
    env = environment
    with env.owner.case(None, None, None):
        pass
    env.state["OTHER"] = {}
    with pytest.raises(AssertionError, match="before shared"):
        with env.owner.case(None, None, None):
            pytest.fail("must not run")
    assert env.events == ["start", "stop"]
    assert env.owner.broken


def test_read_failure_not_treated_as_absence(environment):
    env = environment
    env.dut.shell.return_value = {"rc": 1, "stdout": ""}
    env.dut.shell.side_effect = None
    with pytest.raises(RuntimeError, match="Cannot snapshot"):
        with env.owner.case(None, None, None):
            pytest.fail("must not run")
    assert env.events == ["start", "stop"]


def test_restore_failure_attempts_other_field(environment):
    env = environment
    env.ns["redis_del"] = lambda *args: [{"rc": 1}]
    hdel = Mock(return_value={"rc": 0})
    before = deepcopy(env.initial)
    before["DEVICE_METADATA"]["localhost"].pop("cloudtype")
    env.ns["redis_hdel"] = hdel
    with pytest.raises(RuntimeError, match="case cleanup"):
        env.ns["_restore_case"](env.dut, before, env.initial["GNMI_CLIENT_CERT"][env.ns["PRINCIPAL"]])
    hdel.assert_called_once()


def test_client_close_failure_still_restores(environment):
    env = environment
    env.client.close.side_effect = [None, ValueError("close")]
    with pytest.raises(ValueError, match="close"):
        with env.owner.case(None, None, None):
            env.state["GNMI_CLIENT_CERT"].clear()
    assert env.state == env.initial
    assert env.events == ["start", "stop"]
    assert env.owner.broken


def test_setup_failure_cleanup_and_teardown_failure_blocks_reuse(environment):
    env = environment

    def failed_flow(*args, **kwargs):
        try:
            raise ValueError("setup")
            yield
        finally:
            env.events.append("setup-cleanup")

    env.ns["_gnmi_tls_flow"] = failed_flow
    with pytest.raises(ValueError, match="setup"):
        env.owner.acquire(None, None, None)
    assert env.events == ["setup-cleanup"]

    def failed_cleanup(*args, **kwargs):
        yield SimpleNamespace(duthost=env.dut, pygnmi_client=env.client)
        raise ValueError("cleanup")

    assert env.owner.broken
    env.owner = env.ns["_RoleTlsOwner"]()
    env.ns["_gnmi_tls_flow"] = failed_cleanup
    env.owner.acquire(None, None, None)
    with pytest.raises(ValueError, match="cleanup"):
        env.owner.close()
    with pytest.raises(RuntimeError, match="refusing further reuse"):
        env.owner.acquire(None, None, None)


def test_raw_mapping_and_decoded_config_are_distinct(environment):
    env = environment
    raw = {"role@": "admin,operator", "extra@": "", "NULL": "NULL",
           "quoted": "'\\\"\n,", "extra": "preserve"}
    env.initial["GNMI_CLIENT_CERT"][env.ns["PRINCIPAL"]] = raw
    env.state.clear()
    env.state.update(deepcopy(env.initial))
    for _ in range(2):
        with env.owner.case(None, None, None):
            decoded = env.owner.expected["GNMI_CLIENT_CERT"][env.ns["PRINCIPAL"]]
            assert decoded["role"] == ["admin", "operator"]
            assert decoded["extra"] == "preserve"
            assert "role@" not in decoded and "NULL" not in decoded
            assert env.owner.mapping == raw
            env.state["GNMI_CLIENT_CERT"].clear()
        assert env.state == env.initial
    env.owner.close()


@pytest.mark.parametrize("raw", [{}, {"role@": ""}, {"NULL": "NULL"}])
def test_raw_restore_preserves_absence_empty_and_sentinel(environment, raw):
    env = environment
    before = env.ns["_running_config"](env.dut)
    env.ns["_restore_case"](env.dut, before, raw)
    assert env.state["GNMI_CLIENT_CERT"].get(env.ns["PRINCIPAL"], {}) == raw
    assert env.ns["_principal_mapping"](env.dut) == raw


@pytest.mark.parametrize("payload", ['["role@"]', '["role@", 1]', 'null', '"x"',
                                     '{"role@": "admin"}', '["a", "1", "a", "2"]', 'not json'])
def test_invalid_raw_snapshot_fails_closed(environment, payload):
    env = environment
    env.dut.shell.side_effect = None
    env.dut.shell.return_value = {"rc": 0, "stdout": payload}
    with pytest.raises(ValueError):
        env.ns["_principal_mapping"](env.dut)


def test_raw_read_error_fails_closed(environment):
    env = environment
    env.dut.shell.side_effect = None
    env.dut.shell.return_value = {"rc": 1, "stdout": '{}'}
    with pytest.raises(RuntimeError, match="Cannot snapshot AAA principal"):
        env.ns["_principal_mapping"](env.dut)


def test_hidden_raw_mapping_leak_detected(environment):
    env = environment
    with env.owner.case(None, None, None):
        pass
    # NULL is omitted by cfggen, but a raw snapshot still detects the leak.
    env.state["GNMI_CLIENT_CERT"][env.ns["PRINCIPAL"]]["NULL"] = "leak"
    with pytest.raises(AssertionError, match="before shared"):
        with env.owner.case(None, None, None):
            pytest.fail("must not run")
    assert env.owner.broken


def test_setup_cleanup_failure_poisoned(environment):
    env = environment

    def failed_flow(*args, **kwargs):
        try:
            raise ValueError("setup")
            yield
        finally:
            raise RuntimeError("cleanup")

    env.ns["_gnmi_tls_flow"] = failed_flow
    with pytest.raises(RuntimeError, match="cleanup"):
        env.owner.acquire(None, None, None)
    assert env.owner.broken and env.owner.flow is None
    with pytest.raises(RuntimeError, match="refusing further reuse"):
        env.owner.acquire(None, None, None)


@pytest.mark.parametrize("strict", [False, True])
def test_certificate_removal_propagates_only_in_strict_mode(strict):
    ns = dict(os=SimpleNamespace(path=SimpleNamespace(exists=lambda path: True)),
              shutil=SimpleNamespace(rmtree=Mock()), logger=Mock())
    exec(compile(_source(GRPC, {"_delete_gnoi_certs"}), str(GRPC), "exec"), ns)

    def remove(path, ignore_errors):
        if not ignore_errors:
            raise OSError("cannot remove certificates")

    ns["shutil"].rmtree.side_effect = remove
    if strict:
        with pytest.raises(OSError, match="cannot remove"):
            ns["_delete_gnoi_certs"]("/fake", strict=True)
    else:
        ns["_delete_gnoi_certs"]("/fake")
    ns["shutil"].rmtree.assert_called_once_with("/fake", ignore_errors=not strict)


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("failure", ["setup", "close", "rollback", "health", "certs", "health-pytest"])
def test_actual_tls_flow_cleanup(strict, failure):
    """Exercise the extracted production generator, not a copied lifecycle."""
    ns = _load()
    client = Mock()
    cfg = SimpleNamespace(DEFAULT_TLS_PORT=50052, CA_CERT="ca", CLIENT_CERT="cert", CLIENT_KEY="key",
                          get_ptf_cert_paths=lambda: dict(ca_cert="ca", client_cert="cert", client_key="key"))
    ns.update(grpc_config=cfg, create_checkpoint=Mock(), _establish_gnoi_tls_handshake=Mock(),
              PtfGrpc=Mock(), PtfGnoi=Mock(), PygnmiClient=Mock(return_value=client),
              CertPaths=SimpleNamespace, GnmiFixture=SimpleNamespace,
              rollback=Mock(return_value={"rc": 0, "stdout": "Config rolled back successfully"}),
              wait_critical_processes=Mock(), _delete_gnoi_certs=Mock())
    failing = {"setup": ns["_establish_gnoi_tls_handshake"], "close": client.close,
               "rollback": ns["rollback"], "health": ns["wait_critical_processes"],
               "certs": ns["_delete_gnoi_certs"],
               "health-pytest": ns["wait_critical_processes"]}[failure]
    failing.side_effect = pytest.fail.Exception(failure) if failure == "health-pytest" else ValueError(failure)
    exec(compile(_source(GRPC, {"_gnmi_tls_flow"}), str(GRPC), "exec"), ns)
    flow = ns["_gnmi_tls_flow"](SimpleNamespace(mgmt_ip="::1"), Mock(), strict_cleanup=strict)
    if failure == "setup":
        with pytest.raises(ValueError, match="setup"):
            next(flow)
    else:
        next(flow)
        expected = pytest.fail.Exception if failure == "health-pytest" else (RuntimeError if strict else StopIteration)
        with pytest.raises(expected):
            next(flow)
    ns["rollback"].assert_called_once()
    ns["wait_critical_processes"].assert_called_once()
    ns["_delete_gnoi_certs"].assert_called_once()


def test_public_fixture_scope_and_aaa_case_selection():
    tree = ast.parse(GRPC.read_text())
    fixture = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "gnmi_tls")
    assert ast.unparse(fixture.decorator_list[0]) == "pytest.fixture(scope='function')"
    tree = ast.parse((TESTS / "gnmi/test_gnmi_aaa.py").read_text())
    tests = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]
    for test in tests:
        args = [arg.arg for arg in test.args.args]
        if test.name == "test_cn_role_access":
            assert "gnmi_aaa_role_tls" in args and "gnmi_tls" not in args
        else:
            assert "gnmi_tls" in args and "gnmi_aaa_role_tls" not in args


@pytest.mark.parametrize("order", ["roles-first", "fresh-first", "interleaved"])
@pytest.mark.parametrize("body_failure", [False, True])
def test_real_pytest_scope_ordering(tmp_path, order, body_failure):
    """Real pytest fixtures prove nonoverlap and cleanup before config check."""
    production = _source(AAA)
    prelude = textwrap.dedent('''
        from contextlib import contextmanager
        import json, logging, shlex, time
        from types import SimpleNamespace
        import pytest
        CONFIG_DB = 'CONFIG_DB'
        events = []
        state = {'DEVICE_METADATA': {'localhost': {}},
                 'GNMI_CLIENT_CERT': {'test.client.gnmi.sonic': {'role': ['admin']}}}
        dut = SimpleNamespace(shell=lambda command, **k: {'rc': 0, 'stdout': json.dumps(
            ['role@', 'admin'] if ' EVAL ' in command else state)})
        _get_target_duthost = lambda *args: dut
        def _gnmi_tls_flow(*args, **kwargs):
            events.append('shared-start')
            yield SimpleNamespace(duthost=dut, pygnmi_client=SimpleNamespace(close=lambda: None))
            events.append('shared-stop')
        def redis_del(*args):
            return [{'rc': 0}]
        def redis_hset(*args, **kwargs):
            return {'rc': 0}
        def redis_hdel(*args):
            return {'rc': 0}
    ''')
    fixtures = textwrap.dedent('''
        @pytest.fixture(scope='session')
        def duthosts(): return [dut]
        @pytest.fixture(scope='session')
        def ptfhost(): return object()
        @pytest.fixture(scope='module', autouse=True)
        def core_dump_and_config_check():
            events.append('config-start')
            yield
            events.append('config-stop')
            with open('events.json', 'w') as stream: json.dump(events, stream)
        # Same local autouse wrapper as the real AAA module. The fresh fixture
        # deliberately has NO dependency on the boundary: autouse must order it.
        _boundary = gnmi_aaa_case_boundary
        @pytest.fixture
        def gnmi_tls():
            events.append('fresh-start')
            yield
            events.append('fresh-stop')
    ''')
    (tmp_path / "conftest.py").write_text(prelude + production + fixtures)
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    actual_boundary = _source(TESTS / "gnmi/test_gnmi_aaa.py", {"gnmi_aaa_case_boundary"})
    (tmp_path / "test_cases.py").write_text(
        "import pytest\nfrom conftest import _boundary as _gnmi_aaa_case_boundary\n" + actual_boundary +
        textwrap.dedent('''
        @pytest.mark.parametrize('n', [0, 1, 2])
        def test_role(gnmi_aaa_role_tls, n): pass
        def test_fresh(gnmi_tls): pass
    '''))
    role = "test_cases.py::test_role"
    fresh = "test_cases.py::test_fresh"
    selections = {"roles-first": [role, fresh], "fresh-first": [fresh, role],
                  "interleaved": [role + "[0]", fresh, role + "[1]", role + "[2]"]}[order]
    if body_failure:
        test_path = tmp_path / "test_cases.py"
        test_path.write_text(test_path.read_text().replace(
            "def test_role(gnmi_aaa_role_tls, n): pass",
            "def test_role(gnmi_aaa_role_tls, n): assert n != 1"))
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", *selections],
                            cwd=tmp_path, text=True, capture_output=True)
    assert result.returncode == (1 if body_failure else 0), result.stdout + result.stderr
    events = json.loads((tmp_path / "events.json").read_text())
    assert events[0] == "config-start" and events[-1] == "config-stop"
    active = None
    for event in events[1:-1]:
        kind, phase = event.split("-")
        if phase == "start":
            assert active is None, events
            active = kind
        else:
            assert active == kind, events
            active = None
    assert active is None
    # Real pytest body failures are not thrown into yield fixtures. Sharing
    # continues only after exact per-case restoration succeeds. The failed body
    # remains a failure; cleanup/setup failures separately poison the owner.
    assert events.count("shared-start") == (2 if order == "interleaved" else 1)


@pytest.mark.parametrize("method", ["get", "set", "capabilities"])
@pytest.mark.parametrize("fail", [False, True])
def test_production_public_rpcs_refresh_channels(method, fail):
    """Role cases use public RPCs: each gets a new channel even after failure."""
    path = TESTS / "common/pygnmi_client.py"
    tree = ast.parse(path.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PygnmiClient")
    names = {"_ensure_client", "close", method}
    cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in names]
    for node in cls.body:
        node.returns = None
        for arg in node.args.args:
            arg.annotation = None
    ns = dict(GetDataType=SimpleNamespace(ALL="all"), Encoding=SimpleNamespace(JSON_IETF="json_ietf"),
              _normalize_paths=lambda path: [path],
              grpc=SimpleNamespace(RpcError=ValueError, FutureTimeoutError=TimeoutError),
              gNMIException=ValueError, PygnmiClientError=ValueError, PygnmiClientCallError=ValueError)
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(path), "exec"), ns)
    client = ns["PygnmiClient"]()
    client._client = None
    channels = [Mock(), Mock()]
    client._build_client = Mock(side_effect=channels)
    client._map_error = lambda error, operation: error
    args = {"get": {"paths": "path"}, "set": {"update": [("path", "value")]}, "capabilities": {}}[method]
    for channel in channels:
        if fail:
            getattr(channel, method).side_effect = ValueError("RPC failed")
            with pytest.raises(ValueError, match="RPC failed"):
                getattr(client, method)(**args)
        else:
            getattr(client, method)(**args)
        channel.connect.assert_called_once()
        channel.close.assert_called_once()
        assert client._client is None
    assert client._build_client.call_count == 2
