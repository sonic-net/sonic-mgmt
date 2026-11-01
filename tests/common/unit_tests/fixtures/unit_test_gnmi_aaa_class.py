"""Offline scope/state regressions; no Ansible, device, or TLS execution.

Run with --noconftest --confcutdir=tests/common/unit_tests.
"""
import ast
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

TESTS = Path(__file__).resolve().parents[3]
AAA = TESTS / "gnmi/test_gnmi_aaa.py"
GRPC = TESTS / "common/fixtures/grpc_fixtures.py"


def source(path, names):
    tree = ast.parse(path.read_text())
    tree.body = [node for node in tree.body if getattr(node, "name", None) in names]
    return ast.unparse(tree)


def test_collection_contract():
    tree = ast.parse(AAA.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]
    assert {node.name for node in functions} == {
        "test_gnmi_audit_log", "test_gnmi_audit_rate_limit",
        "test_gnmi_audit_log_remote_forwarding", "test_gnmi_default_cert_auth",
    }
    assert all("gnmi_tls" in [arg.arg for arg in node.args.args] for node in functions)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    assert cls.name == "TestCnRoleAccess"
    ids = [kw.value.value for node in ast.walk(tree) if isinstance(node, ast.Call)
           for kw in node.keywords if kw.arg == "id"]
    assert len(ids) == len(set(ids)) == 14  # 12 role + 2 reused audit parameter IDs.


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("failure", ["close", "rollback", "health", "health-pytest", "certs"])
def test_cleanup_contract(strict, failure):
    client = Mock()
    ns = dict(
        logger=Mock(), create_checkpoint=Mock(), _establish_gnoi_tls_handshake=Mock(),
        grpc_config=SimpleNamespace(
            DEFAULT_TLS_PORT=50052, CA_CERT="ca", CLIENT_CERT="cert", CLIENT_KEY="key",
            get_ptf_cert_paths=lambda: dict(ca_cert="ca", client_cert="cert", client_key="key")),
        CertPaths=SimpleNamespace, GnmiFixture=SimpleNamespace, PtfGrpc=Mock(), PtfGnoi=Mock(),
        PygnmiClient=Mock(return_value=client),
        rollback=Mock(return_value={"rc": 0, "stdout": "Config rolled back successfully"}),
        wait_critical_processes=Mock(), _delete_gnoi_certs=Mock(),
    )
    target = {"close": client.close, "rollback": ns["rollback"], "health": ns["wait_critical_processes"],
              "health-pytest": ns["wait_critical_processes"], "certs": ns["_delete_gnoi_certs"]}[failure]
    target.side_effect = pytest.fail.Exception(failure) if failure == "health-pytest" else ValueError(failure)
    exec(source(GRPC, {"_gnmi_tls_flow"}), ns)
    flow = ns["_gnmi_tls_flow"](SimpleNamespace(mgmt_ip="::1"), Mock(), strict_cleanup=strict)
    env = next(flow)
    assert env.port == 50052 and env.tls
    expected = pytest.fail.Exception if failure == "health-pytest" else (RuntimeError if strict else StopIteration)
    with pytest.raises(expected):
        next(flow)
    ns["rollback"].assert_called_once()
    ns["wait_critical_processes"].assert_called_once()
    if strict:
        ns["_delete_gnoi_certs"].assert_called_once_with("/tmp/gnoi_certs", strict=True)
    elif failure == "health-pytest":
        ns["_delete_gnoi_certs"].assert_not_called()  # Public behavior is unchanged.
    else:
        ns["_delete_gnoi_certs"].assert_called_once_with("/tmp/gnoi_certs")


@pytest.mark.parametrize("disabled", [None, "option", "marker"])
@pytest.mark.parametrize("ignore_failure", [False, True])
def test_log_window_uses_existing_policy(disabled, ignore_failure):
    # Real LogAnalyzer policy/context methods; fake only its transport/config IO.
    path = TESTS / "common/plugins/loganalyzer/loganalyzer.py"
    tree = ast.parse(path.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LogAnalyzer")
    cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef)
                and node.name in {"__init__", "__enter__", "__exit__", "load_common_config"}]
    ns = dict(contextmanager=contextmanager, os=os, join=lambda *parts: "/".join(parts),
              COMMON_MATCH="match", COMMON_IGNORE="ignore", COMMON_EXPECT="expect", logging=Mock(),
              BugHandler=Mock(), get_bughandler_instance=Mock(),
              ansible_loganalyzer=Mock(return_value=Mock(
                  create_msg_regex=lambda paths: (None, list(paths)))))
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(path), "exec"), ns)
    analyzer_class = ns["LogAnalyzer"]
    analyzer_class.init = Mock(return_value="marker")
    analyzer_class.analyze = Mock()
    exec(source(AAA, {"_role_tls_logs"}), ns)
    options = {"--disable_loganalyzer": disabled == "option", "--ignore_la_failure": ignore_failure,
               "--store_la_logs": True}
    request = SimpleNamespace(
        config=SimpleNamespace(getoption=options.__getitem__),
        keywords={"disable_loganalyzer": True} if disabled == "marker" else {},
        session=SimpleNamespace(config=SimpleNamespace(cache=SimpleNamespace(get=lambda *args: ["extended"]))),
    )
    dut = SimpleNamespace(hostname="dut")
    with ns["_role_tls_logs"](dut, request, "setup"):
        pass
    if disabled:
        analyzer_class.init.assert_not_called()
    else:
        analyzer_class.analyze.assert_called_once_with("marker", fail=not ignore_failure)
        assert dut.loganalyzer.store_la_logs
        assert dut.loganalyzer.ignore_regex == ["ignore", "extended"]
        assert dut.loganalyzer.expect_regex == ["expect"]  # Common config only, no per-case patterns.


@pytest.mark.parametrize("cloudtype", [False, "", "Private"])
@pytest.mark.parametrize("mapping", [{}, {"role@": ""}, {"role@": "admin", "extra": "", "NULL": "NULL"}])
@pytest.mark.parametrize("order", ["together", "interleaved", "reverse"])
def test_real_scope_and_exact_restoration(tmp_path, cloudtype, mapping, order):
    result, events = run_cases(tmp_path, cloudtype, mapping, order)
    assert result.returncode == 0, result.stdout + result.stderr
    starts = [event for event in events if event == "tls-start"]
    assert len(starts) == (2 if order == "interleaved" else 1)
    assert events.count("tls-stop") == len(starts)
    assert events[0] == "config-start" and events[-1] == "config-stop"
    active = False
    for event in events:
        if event == "tls-start":
            assert not active
            active = True
        elif event == "tls-stop":
            assert active
            active = False
        elif event == "fresh":
            assert not active
    assert not active
    for i, event in enumerate(events):
        if event in ("tls-start", "tls-stop"):
            assert events[i - 1].endswith("-log-start"), events
            assert events[i + 1].endswith("-log-stop"), events
        if event == "restore":
            assert events[i + 1] == "function-log-stop", events


@pytest.mark.parametrize("failure", ["setup", "body", "restore", "final", "setup-log", "final-log", "analyze"])
def test_failure_is_visible_and_cleanup_runs(tmp_path, failure):
    result, events = run_cases(tmp_path, False, {"role@": "admin"}, "together", failure)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "injected-" + failure in result.stdout
    assert events.count("tls-stop") == events.count("tls-start")
    assert events[-1] == "config-stop"
    if failure == "restore":
        assert "AAA owned state was not restored before this case" in result.stdout
    if failure in ("body", "final", "final-log", "analyze"):
        assert "restore" in events


def run_cases(tmp_path, cloudtype, mapping, order, failure=None):
    # Execute the actual production fixtures and actual parallel-barrier plugin
    # under pytest. Only device commands, TLS flow and log transport are fakes.
    prelude = textwrap.dedent('''
        from contextlib import ExitStack, contextmanager
        import json, shlex, pytest
        from types import SimpleNamespace
        events = []
        CLIENT_PRINCIPAL = "test.client.gnmi.sonic"
        CONFIG_DB = "CONFIG_DB"
        state = INITIAL
        original = json.loads(json.dumps(state))
        failure = FAILURE
        @pytest.hookimpl(optionalhook=True)
        def pytest_assert(value, message):
            assert value, message
        def read(command, **kwargs):
            fields = [x for pair in state["mapping"].items() for x in pair]
            return {"rc": 0, "stdout": json.dumps({"principal": fields or {}, "cloudtype": state["cloudtype"]})}
        dut = SimpleNamespace(shell=read)
        _get_target_duthost = lambda *args: dut
        def redis_del(*args):
            state["mapping"] = {}
            return [{"rc": 0}]
        def redis_hset(host, db, key, **fields):
            if key.startswith("GNMI_CLIENT_CERT"):
                if failure == "restore": raise ValueError("injected-restore")
                state["mapping"].update(fields)
            else:
                state["cloudtype"] = fields["cloudtype"]
            return {"rc": 0}
        def redis_hdel(*args):
            state["cloudtype"] = False
            return {"rc": 0}
        def _gnmi_tls_flow(*args, **kwargs):
            assert kwargs == {"strict_cleanup": True}
            events.append("tls-start")
            try:
                if failure == "setup": raise ValueError("injected-setup")
                yield SimpleNamespace(duthost=dut)
            finally:
                events.append("tls-stop")
                state.update(json.loads(json.dumps(original)))
                if failure == "final": raise ValueError("injected-final")
        class LogAnalyzer:
            def __init__(self, host, prefix, request):
                self.phase = "setup" if prefix.endswith("setup") else "final"
                self.expect_regex = []
            def load_common_config(self): pass
            def __enter__(self):
                if failure == self.phase + "-log": raise ValueError("injected-" + failure)
                events.append(self.phase + "-log-start")
            def __exit__(self, *args):
                events.append(self.phase + "-log-stop")
                if failure == "analyze": raise ValueError("injected-analyze")
        def pytest_addoption(parser):
            parser.addoption("--disable_loganalyzer", action="store_true")
        @pytest.fixture(scope="session")
        def tbinfo(): return {"duts": ["dut"]}
        @pytest.fixture(scope="session")
        def duthosts(): return [dut]
        @pytest.fixture(scope="session")
        def ptfhost(): return object()
        @pytest.fixture(scope="module", autouse=True)
        def core_dump_and_config_check():
            events.append("config-start")
            yield
            events.append("config-stop")
            with open("events.json", "w") as stream: json.dump(events, stream)
        @pytest.fixture(autouse=True)
        def loganalyzer():
            events.append("function-log-start")
            yield
            if state == original: events.append("restore")
            events.append("function-log-stop")
    ''').replace("INITIAL", repr({"mapping": mapping, "cloudtype": cloudtype})).replace("FAILURE", repr(failure))
    fixtures = source(AAA, {"_role_tls_logs", "_role_state", "_restore_role_state", "role_tls", "role_case_tls"})
    plugin = (TESTS / "common/plugins/parallel_fixture/__init__.py").read_text()
    (tmp_path / "conftest.py").write_text(plugin + "\n" + prelude + fixtures)
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_cases.py").write_text(textwrap.dedent('''
        import pytest
        from conftest import events, state, failure
        class TestCnRoleAccess:
            @pytest.mark.parametrize("role", ["", None], ids=["empty", "unmapped"])
            def test_cn_role_access(self, role_case_tls, role):
                state["mapping"] = {} if role is None else {"role@": role}
                state["cloudtype"] = "Public"
                if failure == "body": raise ValueError("injected-body")
        def test_fresh():
            events.append("fresh")
    '''))
    role = "test_cases.py::TestCnRoleAccess::test_cn_role_access"
    fresh = "test_cases.py::test_fresh"
    selected = {
        "together": [role, fresh],
        "interleaved": [role + "[empty]", fresh, role + "[unmapped]"],
        "reverse": [fresh, role + "[unmapped]", role + "[empty]"],
    }[order]
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", *selected],
                            cwd=tmp_path, capture_output=True, text=True, timeout=45)
    assert (tmp_path / "events.json").exists(), result.stdout + result.stderr
    return result, json.loads((tmp_path / "events.json").read_text())
