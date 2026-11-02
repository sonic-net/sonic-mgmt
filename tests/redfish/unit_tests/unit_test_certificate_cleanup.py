"""Focused offline SOURCES; execute only via the designated test owner.

python3 -m pytest --noconftest --confcutdir=tests/redfish/unit_tests \
    tests/redfish/unit_tests/unit_test_certificate_cleanup.py -v
"""
import ast
from contextlib import contextmanager
import hashlib
import http.client
import json
import logging
import os
from pathlib import Path
import shlex
import ssl
import stat
import tempfile
import time
from types import MappingProxyType, SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("certificates", "watcher", "configuration", "container")
WRAPPERS = ("good_certs_after_test", "healthy_watcher_after_test",
            "provisioned_on_session_port", "provisioned_after_test")
SENTINEL = "PRIVATE-KEY-OR-REMOTE-PAYLOAD-SENTINEL"


def load(path, ns, names=None):
    tree = ast.parse(path.read_text())
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.Assign))
             and (names is None or isinstance(n, ast.FunctionDef) and n.name in names)]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), ns)


@pytest.fixture
def api():
    ns = dict(hashlib=hashlib, http=http, json=json, Path=Path, shlex=shlex,
              ssl=ssl, time=time, MappingProxyType=MappingProxyType, os=os, stat=stat, tempfile=tempfile)
    # Constants from the actual utility source, in dependency order. Do not
    # execute unrelated module initialization such as logger construction.
    tree = ast.parse((ROOT / "redfish_utils.py").read_text())
    for node in tree.body:
        if (isinstance(node, ast.Assign) and
                all(isinstance(target, ast.Name) and target.id.isupper() for target in node.targets)):
            exec(compile(ast.Module(body=[node], type_ignores=[]), "constants", "exec"), ns)
    load(ROOT / "certificate_cleanup.py", ns)
    return ns


@pytest.fixture
def expected(api, tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    names = (api["SERVER_CERT_NAME"], api["SERVER_KEY_NAME"], api["CA_CERT_NAME"],
             api["CLIENT_CERT_NAME"], api["CLIENT_KEY_NAME"])
    for index, name in enumerate(names):
        (source / name).write_bytes(("artifact-{}".format(index)).encode())
        (source / name).chmod(0o600)
    # Only PEM parsing is substituted; freeze/copy/hash production code runs.
    api["ssl"] = SimpleNamespace(PEM_cert_to_DER_cert=lambda value: b"server-DER")
    api["_inspect"] = Mock(return_value={"port": None})
    result = api["freeze_expected"]({"dir": source, "port": 443}, tmp_path / "frozen", None)
    return result


def metrics():
    return {"checks": 0, "inspection_calls": 0, "auth_calls": 0, "check_seconds": 0.0}


def test_frozen_sources_not_dirty_baseline(api, expected, tmp_path):
    remote = json.loads(expected["remote"])
    content = [b"artifact-0", b"artifact-1", b"artifact-2"]
    assert remote["fingerprint"] == hashlib.sha256(b"".join(content)).hexdigest()
    assert remote["fingerprint"] != hashlib.sha256("".join(remote["files"]).encode()).hexdigest()
    (tmp_path / "source" / api["SERVER_CERT_NAME"]).write_bytes(b"rotated")
    assert api["_local_intact"](expected)
    with pytest.raises(TypeError):
        expected["remote"] = "dirty"
    for path in expected["dir"].iterdir():
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("port", [None, "", "bad", "0", "65536", "443", "8443", "00443"])
def test_exact_port_representation_restore(api, port):
    config = {"server_crt": "/crt", "server_key": "/key", "ca_crt": "/ca", "client_crt_cname": "bmcweb"}
    dut = Mock()
    dut.shell.return_value = {"rc": 0}
    api["restore_expected_config"](dut, {"remote": json.dumps({"config": config, "port": port})})
    words = shlex.split(dut.shell.call_args_list[-1].args[0])
    assert words[2:] == (["hdel", "REDFISH|config", "port"] if port is None else
                         ["hset", "REDFISH|config", "port", port])
    assert dut.shell.call_count == 5


@pytest.mark.parametrize("result", [{}, {"rc": 1}, {"rc": 0, "failed": True},
                                    {"rc": 0, "stderr": SENTINEL}, {"rc": 0, "stdout": SENTINEL}])
def test_unknown_inspection_never_clean(api, expected, result, caplog):
    # Restore the real parser after the provisioning stub.
    load(ROOT / "certificate_cleanup.py", api, {"_inspect"})
    dut = Mock(mgmt_ip="192.0.2.1")
    dut.shell.return_value = result
    api["privileged_ready"] = Mock(return_value=True)
    assert not api["expected_ready"](dut, expected, metrics())
    api["privileged_ready"].assert_not_called()
    assert SENTINEL not in caplog.text
    assert dut.shell.call_args.kwargs["verbose"] is False


@pytest.mark.parametrize("leaf", ["SERVER_CERT_NAME", "SERVER_KEY_NAME", "CA_CERT_NAME", "CLIENT_KEY_NAME"])
def test_frozen_artifact_tamper_cannot_become_expected(api, expected, leaf):
    (expected["dir"] / api[leaf]).write_bytes(b"different")
    api["_inspect"] = Mock(return_value=True)
    assert not api["expected_ready"](Mock(), expected, metrics())
    api["_inspect"].assert_not_called()


def orchestration(api, ready):
    api.update(pytest=pytest, pytest_assert=lambda ok, msg: require(ok, msg),
               contextmanager=contextmanager, logger=logging.getLogger("cleanup-test"), WATCHER="credentials-watcher")
    api["expected_ready"] = Mock(side_effect=ready)
    for name in ("restore_delivered_certs", "restore_expected_config", "supervisor", "recreate_container"):
        api[name] = Mock()
    api["program_state"] = Mock(return_value="RUNNING")
    api["wait_for_program"] = Mock(return_value=True)
    api["restart_service"] = Mock(return_value=True)
    api["wait_until"] = lambda timeout, poll, delay, fn, *args: fn(*args)
    load(ROOT / "test_redfish_certificates.py", api,
         set(WRAPPERS) | {"_restore_certificate_profile", "_profile_certificate_cleanup"})
    return api


def require(ok, msg):
    if not ok:
        raise AssertionError(msg)


@pytest.mark.parametrize("profile", PROFILES)
def test_clean_zero_mutations(api, expected, profile):
    ns = orchestration(api, [True])
    ns["_restore_certificate_profile"](Mock(), {"cleanup_expected": expected}, profile)
    for name in ("restore_delivered_certs", "restore_expected_config", "supervisor",
                 "recreate_container", "restart_service"):
        ns[name].assert_not_called()


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("verified", [True, False])
def test_fallback_requires_full_verification(api, expected, profile, verified):
    ns = orchestration(api, [False, verified])
    if verified:
        ns["_restore_certificate_profile"](Mock(), {"cleanup_expected": expected}, profile)
    else:
        with pytest.raises(AssertionError, match="cleanup failed"):
            ns["_restore_certificate_profile"](Mock(), {"cleanup_expected": expected}, profile)
    assert ns["restore_delivered_certs"].call_args.args[1] == expected["dir"]
    assert ns["restart_service"].call_count == (profile == "configuration")
    assert ns["recreate_container"].call_count == (profile == "container")
    assert ns["expected_ready"].call_args.args[-1] is False  # unknown script cannot skip, can recover


@pytest.mark.parametrize("operation,profile", [
    ("restore_delivered_certs", "certificates"), ("restore_expected_config", "configuration"),
    ("restart_service", "configuration"), ("wait_for_program", "container")])
def test_failed_fallback_is_visible_and_private(api, expected, operation, profile, caplog):
    ns = orchestration(api, [False, True])
    ns[operation].side_effect = RuntimeError(SENTINEL)
    with pytest.raises(AssertionError, match="cleanup failed") as error:
        ns["_restore_certificate_profile"](Mock(), {"cleanup_expected": expected}, profile)
    assert SENTINEL not in str(error.value) + caplog.text


@pytest.mark.parametrize("index", range(4))
def test_wrapper_cleanup_runs_after_body_failure(api, expected, index):
    ns = orchestration(api, [False, True])
    fixture = ns[WRAPPERS[index]]
    function = fixture.__wrapped__
    generator = function(Mock(), {"cleanup_expected": expected})
    next(generator)
    # Pytest resumes yield fixtures normally even when a test call fails.
    with pytest.raises(RuntimeError, match="body failure"):
        try:
            raise RuntimeError("body failure")
        finally:
            with pytest.raises(StopIteration):
                next(generator)
    assert ns["restore_delivered_certs"].call_count == 1


@pytest.mark.parametrize("status", [200, 301, 401, 403, 500])
@pytest.mark.parametrize("wire", [b"server-DER", b"old-or-rotated-DER"])
def test_same_verified_socket_certificate_and_privileged_status(api, expected, status, wire):
    conn = Mock()
    conn.sock.getpeercert.return_value = wire
    conn.getresponse.return_value.status = status
    context = Mock()
    api["ssl"] = SimpleNamespace(create_default_context=Mock(return_value=context))
    factory = Mock(return_value=conn)
    api["http"] = SimpleNamespace(client=SimpleNamespace(HTTPSConnection=factory))
    assert api["privileged_ready"]("192.0.2.1", expected) == (wire == b"server-DER" and status == 200)
    api["ssl"].create_default_context.assert_called_once_with(cafile=str(expected["dir"] / api["CA_CERT_NAME"]))
    assert factory.call_args.args[1] == 443
    conn.close.assert_called_once()
    if wire == b"server-DER":
        conn.request.assert_called_once_with("GET", "/redfish/v1/Managers")


@pytest.mark.parametrize("error", [ssl.SSLError(SENTINEL), TimeoutError(SENTINEL), OSError(SENTINEL)])
def test_tls_timeout_transport_unknown(api, expected, error, caplog):
    api["_inspect"] = Mock(return_value=True)
    api["privileged_ready"] = Mock(side_effect=error)
    assert not api["expected_ready"](Mock(), expected, metrics())
    assert SENTINEL not in caplog.text


def test_remote_predicate_each_drift_fails(api):
    """Execute the actual embedded read-only predicate, not a second model of it."""
    import re
    import sys

    content = [b"cert", b"key", b"ca"]
    fp = hashlib.sha256(b"".join(content)).hexdigest()
    config = {"server_crt": "/crt", "server_key": "/key", "ca_crt": "/ca", "client_crt_cname": "bmcweb"}
    expected = {"config": config, "port": None, "fingerprint": fp,
                "files": [hashlib.sha256(b).hexdigest() for b in content],
                "script": hashlib.sha256(b"script").hexdigest(), "require_script": True}
    good = {"/crt": b"cert", "/key": b"key", "/ca": b"ca", "/usr/bin/stage-credentials.sh": b"script",
            "/var/lib/bmcweb/.staged-credentials.stamp": (fp + "\n").encode(),
            "/var/lib/bmcweb/provisioned": b"Do not delete\nprovisioned_at=2026-11-02T00:00:00Z\n",
            "/etc/ssl/certs/https/server.pem": b"certkey", "/etc/ssl/certs/authority/CA-cert.pem": b"ca"}
    status = {"source_fingerprint": fp, "applied_fingerprint": fp, "in_sync": "true",
              "mtls_enforced": "true", "last_error": ""}
    # Extract the real try block and substitute only IO boundaries. Its helper
    # read() has separate regular-file/permission regression below.
    tree = ast.parse(api["INSPECT"])
    body = next(n for n in tree.body if isinstance(n, ast.Try))
    code = compile(ast.Module(body=[body], type_ignores=[]), "remote-inspection", "exec")
    cases = [("clean", None), ("old_alias", None), ("configured_path_alias", None)] + [("file", p) for p in good]
    cases += [("missing_file", p) for p in good]
    cases += [("status", k) for k in status] + [("missing_status", k) for k in status]
    cases += [("config", k) for k in config] + [("missing_config", k) for k in config]
    cases += [("program", p) for p in ("credentials-watcher", "bmcweb", "sonic-dbus-bridge")]
    cases += [("port", ""), ("port", "443"), ("port", "8443"), ("port", "missing"),
              ("trust", None), ("symlink", None), ("old_badlink", None), ("old_regular", None),
              ("command", None), ("read", None), ("both_wrong", None)]
    for kind, field in cases:
        files = dict(good)
        state = dict(status)
        certs = dict(config)
        ports = {}
        if kind == "file":
            files[field] = SENTINEL.encode()
        if kind == "missing_file":
            del files[field]
        if kind == "status":
            state[field] = "wrong"  # stale true plus wrong source/applied must fail
        if kind == "missing_status":
            del state[field]
        if kind == "both_wrong":
            state.update(source_fingerprint="wrong", applied_fingerprint="wrong")
        if kind == "config":
            certs[field] = "" if field == "client_crt_cname" else "/wrong"
        if kind == "missing_config":
            del certs[field]
        if kind == "port":
            if field == "missing":
                expected["port"] = "443"
            else:
                ports["port"] = field
        if kind == "configured_path_alias":
            # Alternate delivery paths, then restored configured paths: the
            # producer retains both subject hash aliases to current CA bytes.
            certs = dict(config)
        output = []

        def readlink(path):
            if kind == "old_regular" and path.endswith("89abcdef.0"):
                raise OSError("not a symlink")
            if kind == "symlink" or kind == "old_badlink" and path.endswith("89abcdef.0"):
                return "foreign-ca.pem"
            return "CA-cert.pem"

        def run(*args):
            if kind == "command":
                raise ValueError(SENTINEL)
            if args[0] == "openssl":
                return b"01234567\n"
            state = " FATAL" if kind == "program" and args[-1] == field else " RUNNING pid 1"
            return (args[-1] + state).encode()

        def read(path):
            if kind == "read":
                raise PermissionError(SENTINEL)
            return files[path]

        ns = dict(hashlib=hashlib, json=json, re=re, run=run, read=read,
                  row=lambda db, key: state if db == "STATE_DB" else ports if key.endswith("config") else certs,
                  os=SimpleNamespace(listdir=lambda path: ["CA-cert.pem", "01234567.0"] +
                                     (["old-ca.pem"] if kind == "trust" else []) +
                                     (["89abcdef.0"] if kind in ("old_alias", "configured_path_alias",
                                                                 "old_badlink", "old_regular") else []),
                                     readlink=readlink),
                  sys=SimpleNamespace(argv=["inspect", json.dumps(expected)], exit=sys.exit), print=output.append)
        if kind in ("clean", "old_alias", "configured_path_alias"):
            exec(code, ns)
            assert output == ["true"]
        else:
            with pytest.raises(SystemExit) as error:
                exec(code, ns)
            assert error.value.code == 1
            assert output == ["false"]
        expected["port"] = None


def test_remote_reader_rejects_nonregular_and_writable_files(api, tmp_path):
    import os
    import stat
    ns = {"os": os, "stat": stat}
    tree = ast.parse(api["INSPECT"])
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "read")
    exec(compile(ast.Module(body=[node], type_ignores=[]), "reader", "exec"), ns)
    path = tmp_path / "bad"
    path.write_text(SENTINEL)
    path.chmod(0o666)
    with pytest.raises(ValueError):
        ns["read"](str(path))
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        ns["read"](str(link))
    with pytest.raises(ValueError):
        ns["read"](str(tmp_path))


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("body_failed", [False, True])
@pytest.mark.parametrize("order", [("guard", "unchanged"), ("unchanged", "guard")])
def test_rotated_local_generation_cleanup_then_real_next_bodies(api, expected, profile, body_failed, order):
    ns = orchestration(api, [False, True])
    source = expected["canonical"]
    names = (api["SERVER_CERT_NAME"], api["SERVER_KEY_NAME"], api["CA_CERT_NAME"])
    original = [(source / n).read_bytes() for n in names]
    # Model the actual rotate_server_cert canonical-file overwrite (no DUT).
    (source / names[0]).write_bytes(b"rotated certificate")
    (source / names[1]).write_bytes(b"rotated key")
    device = {"content": [b"rotated certificate", b"rotated key", original[2]], "pid": 1}

    def deliver(dut, directory):
        content = [(directory / n).read_bytes() for n in names]
        if content != device["content"]:
            device["pid"] += 1
        device["content"] = content

    ns["restore_delivered_certs"] = deliver
    certs = {"cleanup_expected": expected, "dir": source, "server_crt": str(source / names[0])}
    fixture = ns[WRAPPERS[PROFILES.index(profile)]].__wrapped__(Mock(), certs)
    next(fixture)
    if body_failed:
        with pytest.raises(RuntimeError, match="body failed"):
            try:
                raise RuntimeError("body failed")
            finally:
                with pytest.raises(StopIteration):
                    next(fixture)
    else:
        with pytest.raises(StopIteration):
            next(fixture)
    assert device["content"] == [(source / n).read_bytes() for n in names] == original

    # Execute the actual next-case assertion bodies with only hardware IO
    # replaced. Wrong canonical bytes change the modeled pid/fingerprint and
    # fail the original unchanged-content assertions (the F1 counterexample).
    def fingerprint():
        return hashlib.sha256(b"".join(device["content"])).hexdigest()

    ns.update(served_serial=lambda dut: device["content"][0], local_serial=lambda path: Path(path).read_bytes(),
              corrupt_staged_cert=Mock(), syslog_line_count=lambda dut: 0, logged_since=lambda *args: True,
              mtls_get=Mock(), assert_status_ok=Mock(), bmcweb_pid=lambda dut: device["pid"],
              wait_for_staging=lambda dut: True, deliver_certs=deliver, RECONCILE_WINDOW=90,
              cert_status=lambda dut, field: fingerprint() if field == "applied_fingerprint" else "true",
              time=SimpleNamespace(sleep=Mock()))
    tree = ast.parse((ROOT / "test_redfish_certificates.py").read_text())
    methods = {n.name: n for cls in tree.body if isinstance(cls, ast.ClassDef)
               for n in cls.body if isinstance(n, ast.FunctionDef)}
    for name in ("test_guard_self_heals_damaged_staged_cert", "test_unchanged_content_does_not_bounce_bmcweb"):
        exec(compile(ast.Module(body=[methods[name]], type_ignores=[]), "next-case", "exec"), ns)
    for selection in order:
        if selection == "guard":
            ns["test_guard_self_heals_damaged_staged_cert"](None, Mock(), "192.0.2.1", certs, None)
        else:
            ns["test_unchanged_content_does_not_bounce_bmcweb"](None, Mock(), certs)
    ns["time"].sleep.assert_called_once_with(90)  # original negative window preserved


@pytest.mark.parametrize("target", ["frozen", "canonical"])
def test_local_generation_refuses_symlink_or_tampered_frozen_source(api, expected, tmp_path, target):
    name = api["SERVER_KEY_NAME"]
    path = (expected["dir"] if target == "frozen" else expected["canonical"]) / name
    other = tmp_path / "not-owned"
    other.write_bytes(b"leave untouched")
    path.unlink()
    path.symlink_to(other)
    with pytest.raises(ValueError):
        api["restore_local_generation"](expected, {"local_replacements": 0})
    assert other.read_bytes() == b"leave untouched"


@pytest.mark.parametrize("raw_port,effective", [(None, 443), ("", 443), ("invalid", 443),
                                                ("0", 443), ("65536", 443), ("00443", 443), ("8443", 8443)])
def test_freeze_retains_raw_port_without_inspection_setup_gate(api, expected, tmp_path, raw_port, effective):
    api["_inspect"] = Mock(side_effect=RuntimeError(SENTINEL))
    result = api["freeze_expected"]({"dir": expected["canonical"], "port": effective},
                                    tmp_path / "another-frozen", raw_port)
    assert json.loads(result["remote"])["port"] == raw_port
    assert result["port"] == effective
    api["_inspect"].assert_not_called()


@pytest.mark.parametrize("configured_paths", [False, True])
def test_distinct_ca_subject_hash_rotate_restore_trust_aliases(api, tmp_path, configured_paths):
    import re
    # Extract the real trust-validation block, substitute its filesystem root
    # and openssl hash observation only. Model exactly stage_certs' cp/mv plus
    # ln -sfn behavior; no alias deletion on either rotation or restoration.
    tree = ast.parse(api["INSPECT"])
    body = next(n for n in tree.body if isinstance(n, ast.Try)).body
    start = next(i for i, n in enumerate(body) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "auth" for t in n.targets))
    end = next(i for i, n in enumerate(body) if isinstance(n, ast.For) and isinstance(n.target, ast.Name)
               and n.target.id == "program")
    code = compile(ast.Module(body=body[start + 1:end], type_ignores=[]), "trust-validation", "exec")
    auth = tmp_path / "authority"
    auth.mkdir()
    dut = Mock()
    dut.shell.return_value = {"rc": 0}
    for ca_bytes, subject_hash in [(b"original CA", "01234567"), (b"different CA", "89abcdef"),
                                   (b"original CA", "01234567")]:
        if configured_paths:
            api["restore_expected_config"](dut, {"remote": json.dumps({
                "config": {"server_crt": "/crt", "server_key": "/key", "ca_crt": "/ca",
                           "client_crt_cname": "bmcweb"}, "port": None})})
        (auth / "CA-cert.pem").write_bytes(ca_bytes)
        alias = auth / (subject_hash + ".0")
        if alias.is_symlink():
            alias.unlink()
        alias.symlink_to("CA-cert.pem")
        ns = dict(auth=str(auth) + "/", content=[b"cert", b"key", ca_bytes], os=os, re=re,
                  read=lambda path: Path(path).read_bytes(), run=lambda *args: subject_hash.encode())
        exec(code, ns)
    assert {p.name for p in auth.iterdir()} == {"CA-cert.pem", "01234567.0", "89abcdef.0"}
    (auth / "foreign.pem").write_bytes(b"foreign CA")
    with pytest.raises(ValueError, match="unexpected trust anchor"):
        exec(code, ns)
    (auth / "foreign.pem").unlink()
    (auth / "89abcdef.0").unlink()
    (auth / "89abcdef.0").symlink_to("../foreign.pem")
    with pytest.raises(ValueError, match="trust link drift"):
        exec(code, ns)


def test_inspection_unavailable_still_attempts_recovery_then_fails_verification(api, expected):
    ns = orchestration(api, [])
    load(ROOT / "certificate_cleanup.py", ns, {"expected_ready"})
    ns["_inspect"] = Mock(side_effect=RuntimeError(SENTINEL))
    with pytest.raises(AssertionError, match="cleanup failed"):
        ns["_restore_certificate_profile"](Mock(), {"cleanup_expected": expected}, "container")
    ns["restore_delivered_certs"].assert_called_once()
    ns["recreate_container"].assert_called_once()
    assert ns["_inspect"].call_count == 2  # initial check and mandatory postcheck
