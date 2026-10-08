"""Controller-only coverage of the real Ansible multi-password SSH plugin."""

import hashlib
import inspect
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from ansible.errors import AnsibleAuthenticationFailure, AnsibleConnectionFailure, AnsibleError
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader, init_plugin_loader


V4, V6 = "192.0.2.10", "2001:db8::10"
P1, P2 = "test-first", "test-second"
PLUGIN_DIR = Path(__file__).resolve().parents[4] / "ansible/plugins/connection"


@pytest.fixture(scope="module")
def make_connection():
    """Load the production plugin without opening a connection."""
    init_plugin_loader()
    connection_loader.add_directory(str(PLUGIN_DIR))

    def make(primary=V4, alternate=V6, passwords=(P1, P2), no_log=False):
        context = PlayContext()
        context.remote_addr = primary
        context.remote_user = "test-user"
        context.port = 22
        context.password = passwords[0]
        context.no_log = no_log
        conn = connection_loader.get("multi_passwd_ssh", context)
        assert Path(inspect.getsourcefile(type(conn))).resolve() == PLUGIN_DIR / "multi_passwd_ssh.py"
        conn.set_options(direct={
            "host": primary, "hostv6": alternate, "password": passwords[0],
            "altpassword": passwords[1] if len(passwords) > 1 else None,
            "altpasswords": list(passwords[2:]), "reconnection_retries": 0,
        })
        return conn

    return make


def intercept(monkeypatch, conn, operation, outcome):
    attempts = []

    def execute(self, *args, **kwargs):
        pair = (self.get_option("host"), self.get_option("password"))
        assert self.host == self._play_context.remote_addr == pair[0]
        assert self._play_context.password == pair[1]
        attempts.append(pair)
        return outcome(pair)

    monkeypatch.setattr(type(conn).__mro__[1], operation, execute)
    return attempts


def invoke(conn, operation):
    args = {"exec_command": ("true",), "put_file": ("/local", "/remote"), "fetch_file": ("/remote", "/local")}
    return getattr(conn, operation)(*args[operation])


def fail(pair):
    raise AnsibleConnectionFailure("No route to host")


@pytest.mark.parametrize("operation", ["exec_command", "put_file", "fetch_file"])
def test_rotates_back_from_successful_alternate(make_connection, monkeypatch, operation):
    """Retain both supplied endpoints after a successful alternate connection."""
    conn = make_connection()
    working = [(V6, P2)]

    def execute(pair):
        if pair == working[0]:
            return 0, b"ok", b""
        return fail(pair)

    attempts = intercept(monkeypatch, conn, operation, execute)
    invoke(conn, operation)
    assert attempts == [(V4, P1), (V4, P2), (V6, P1), (V6, P2)]
    assert conn.get_option("password") == P1
    assert conn.get_option("current_password_hash") == hashlib.sha256(P2.encode()).hexdigest()
    attempts.clear()
    invoke(conn, operation)
    assert attempts == [(V6, P2)]
    attempts.clear()
    working[0] = (V4, P1)
    invoke(conn, operation)
    assert attempts == [(V6, P2), (V4, P1)]
    assert conn.get_option("host") == V4
    assert conn.get_option("current_password_hash") == hashlib.sha256(P1.encode()).hexdigest()


@pytest.mark.parametrize("operation", ["exec_command", "put_file", "fetch_file"])
@pytest.mark.parametrize("error_type", [AnsibleConnectionFailure, AnsibleAuthenticationFailure])
def test_full_cycle_stops_before_start_repeats(make_connection, monkeypatch, operation, error_type):
    """Try exactly one cycle from a remembered nonzero position and restore state."""
    conn = make_connection()
    intercept(monkeypatch, conn, operation,
              lambda pair: (0, b"", b"") if pair == (V6, P1) else fail(pair))
    invoke(conn, operation)

    def reject(pair):
        raise error_type("simulated failure")

    attempts = intercept(monkeypatch, conn, operation, reject)
    with pytest.raises(AnsibleConnectionFailure, match="All configured") as failure:
        invoke(conn, operation)
    assert attempts == [(V6, P1), (V6, P2), (V4, P1), (V4, P2)]
    assert isinstance(failure.value.__cause__, error_type)
    assert conn.host == conn.get_option("host") == conn._play_context.remote_addr == V6
    assert conn.get_option("password") == conn._play_context.password == P1
    assert conn._credential_retry_active is False


@pytest.mark.parametrize("alternate", [None, V4, V6])
def test_duplicate_and_missing_candidates(make_connection, monkeypatch, alternate):
    """Deduplicate endpoints and passwords without adding a second cycle."""
    conn = make_connection(alternate=alternate, passwords=(P1, P1, P2, P2))
    attempts = intercept(monkeypatch, conn, "exec_command", fail)
    with pytest.raises(AnsibleConnectionFailure, match="All configured"):
        conn.exec_command("true")
    expected = [(V4, P1), (V4, P2)]
    if alternate == V6:
        expected += [(V6, P1), (V6, P2)]
    assert attempts == expected
    assert conn.host == conn.get_option("host") == conn._play_context.remote_addr == V4


@pytest.mark.parametrize("no_log,message", [
    (False, "Permission denied"),
    (False, "Connection reset by peer"),
    (True, "<error censored due to no log>"),
    (True, "opaque connection error"),
])
def test_connection_error_text_does_not_control_rotation(make_connection, monkeypatch, no_log, message):
    """Retry real connection exceptions without parsing censored SSH messages."""
    conn = make_connection(no_log=no_log)

    def execute(pair):
        if pair == (V6, P2):
            return 0, b"ok", b""
        raise AnsibleConnectionFailure(message)

    attempts = intercept(monkeypatch, conn, "exec_command", execute)
    assert conn.exec_command("true")[0] == 0
    assert attempts == [(V4, P1), (V4, P2), (V6, P1), (V6, P2)]


def test_command_failure_does_not_rotate(make_connection, monkeypatch):
    """A remote command result is returned without retrying the command elsewhere."""
    conn = make_connection()
    result = (42, b"", b"application failure")
    attempts = intercept(monkeypatch, conn, "exec_command", lambda pair: result)
    assert conn.exec_command("false") == result
    assert attempts == [(V4, P1)]


def test_non_connection_exception_restores_state(make_connection, monkeypatch):
    """Do not retry programming, file or configuration errors as SSH failures."""
    conn = make_connection()

    def execute(pair):
        if pair == (V4, P1):
            return fail(pair)
        raise AnsibleError("invalid operation")

    attempts = intercept(monkeypatch, conn, "exec_command", execute)
    with pytest.raises(AnsibleError, match="invalid operation"):
        conn.exec_command("true")
    assert attempts == [(V4, P1), (V4, P2)]
    assert conn.get_option("password") == conn._play_context.password == P1
    assert conn.host == conn.get_option("host") == conn._play_context.remote_addr == V4
    assert conn._credential_retry_active is False


def test_new_options_reset_candidates_and_cursor(make_connection, monkeypatch):
    """New inventory/task options replace stale endpoints and password preferences."""
    conn = make_connection()
    intercept(monkeypatch, conn, "exec_command",
              lambda pair: (0, b"", b"") if pair == (V6, P2) else fail(pair))
    conn.exec_command("true")
    conn.set_options(direct={"host": "192.0.2.20", "hostv6": None, "password": "replacement",
                             "altpassword": None, "altpasswords": []})
    attempts = intercept(monkeypatch, conn, "exec_command", lambda pair: (0, b"", b""))
    conn.exec_command("true")
    assert attempts == [("192.0.2.20", "replacement")]


def test_unchanged_options_preserve_successful_candidate(make_connection, monkeypatch):
    """Unchanged inputs preserve the working pair and the endpoint reset must close."""
    conn = make_connection()
    attempts = intercept(monkeypatch, conn, "exec_command",
                         lambda pair: (0, b"", b"") if pair == (V6, P2) else fail(pair))
    conn.exec_command("true")
    conn.set_options(direct={
        "host": V4, "hostv6": V6, "password": P1, "altpassword": P2,
        "altpasswords": [], "reconnection_retries": 0,
    })
    assert conn.host == conn.get_option("host") == conn._play_context.remote_addr == V6
    base = type(conn).__mro__[1]
    monkeypatch.setattr(base, "_build_command", lambda self, binary, subsystem, *args: [binary] + list(args))
    resets = []

    def reset_process(command, **kwargs):
        resets.append(command)
        return SimpleNamespace(communicate=lambda: (b"", b""), wait=lambda: 0)

    monkeypatch.setattr(base.reset.__globals__["subprocess"], "Popen", reset_process)
    conn.reset()
    assert [command[-3:] for command in resets] == [["-O", "check", V6], ["-O", "stop", V6]]
    attempts.clear()
    conn.exec_command("true")
    assert attempts == [(V6, P2)]


def test_key_authentication_has_no_password_hash(make_connection, monkeypatch):
    """Permit a key-authenticated candidate without trying to hash None."""
    conn = make_connection(passwords=(None,))
    attempts = intercept(monkeypatch, conn, "exec_command", lambda pair: (0, b"", b""))
    conn.exec_command("true")
    assert attempts == [(V4, None)]
    assert conn.get_option("current_password_hash") is None


@pytest.mark.parametrize("operation,method", [
    ("exec_command", "sftp"),
    ("put_file", "sftp"), ("put_file", "scp"), ("put_file", "piped"),
    ("fetch_file", "sftp"), ("fetch_file", "scp"), ("fetch_file", "piped"),
])
@pytest.mark.parametrize("no_log", [False, True])
def test_real_ssh_paths_rebuild_endpoint_and_pipes(make_connection, monkeypatch, tmp_path, operation, method, no_log):
    """Exercise real command/transfer builders with only SSH process execution mocked."""
    conn = make_connection(passwords=(P1,), no_log=no_log)
    conn.set_option("password_mechanism", "sshpass")
    conn.set_option("ssh_transfer_method", method)
    conn.set_option("ssh_args", "-o ControlMaster=auto -o ControlPersist=60s")
    conn.set_option("control_path_dir", str(tmp_path / "control"))
    monkeypatch.setattr(type(conn).__mro__[1], "_sshpass_available", staticmethod(lambda: True))
    local = tmp_path / "payload"
    local.write_bytes(b"payload")
    attempts, commands = [], []
    working = [V6]

    def execute(self, command, in_data, sudoable=True, checkrc=True):
        endpoint = self.get_option("host")
        attempts.append(endpoint)
        commands.append([part.decode() if isinstance(part, bytes) else part for part in command])
        if self.sshpass_pipe is not None:
            for descriptor in self.sshpass_pipe:
                os.close(descriptor)
            self.sshpass_pipe = None
        if endpoint != working[0]:
            return 255, b"", b"No route to host"
        return 0, b"payload", b""

    monkeypatch.setattr(type(conn).__mro__[1], "_bare_run", execute)

    def transfer():
        if operation == "exec_command":
            conn.exec_command("true", sudoable=False)
        elif operation == "put_file":
            conn.put_file(str(local), "/remote/payload")
        else:
            conn.fetch_file("/remote/payload", str(local))

    transfer()
    assert attempts == [V4, V6]
    assert any(V4 in part for part in commands[0])
    assert not any(V4 in part for part in commands[1])
    assert any(V6 in part for part in commands[1])
    paths = [[part for part in command if part.startswith("ControlPath=")] for command in commands]
    assert paths[0] and paths[1] and paths[0] != paths[1]
    working[0] = V4
    transfer()
    assert attempts == [V4, V6, V6, V4]
    assert any(V4 in part for part in commands[-1])
    assert not any(V6 in part for part in commands[-1])
    assert conn.get_option("password") == P1
    assert conn._credential_retry_active is False
