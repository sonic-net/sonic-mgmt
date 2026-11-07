"""Password Get/Set tests with fixed accounts in a dedicated, serial test environment.

The legacy setup helper replaces a same-named host user. Password initialization
uses task-level no_log and stdin; real SSH/become pipelining must be qualified
before device execution to avoid remote temporary plaintext files.
"""
import json
import os
import re
import secrets
import subprocess
from contextlib import ExitStack
from functools import partial

import grpc
import pytest
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import gnmi_tls, _restart_gnoi_server  # noqa: F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db  # noqa: F401
from tests.common.helpers.gnmi_connection import gnmi_connection, build_native_set_request
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hset, redis_hdel
from tests.common.helpers.tacacs.tacacs_helper import setup_local_user
from tests.common.utilities import get_inventory_files

pytestmark = [pytest.mark.topology("any")]
DB_KEY = "DEVICE_METADATA|localhost"
PARTS = ("CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost", "cloudtype")


@pytest.fixture(autouse=True)
def restore_startup_config(backup_and_restore_config_db):  # noqa: F811
    """Back up before TLS setup and restore after TLS teardown, including failures."""
    yield


def _set_password(request, duthost, username, password):
    """Use a no_log task; adhoc module kwargs cannot set task-level no_log."""
    __tracebackhide__ = True
    inventories = get_inventory_files(request)
    assert inventories and all(os.path.isfile(path) for path in inventories), "Require actual inventory files"
    assert re.fullmatch(r"[A-Za-z0-9_.-]+", duthost.hostname), "Require one literal DUT hostname"
    assert not request.config.getoption("ansible_extra_inventory", default=None), "Extra inventory not supported"
    cmd = ["ansible-playbook"]
    for path in inventories:
        cmd.extend(["-i", os.path.abspath(path)])
    cmd.extend(["--limit", duthost.hostname, "/dev/stdin"])
    play = [{
        "hosts": duthost.hostname, "gather_facts": False, "become": True,
        "vars": {"ansible_ssh_pipelining": True, "ansible_pipelining": True},
        "tasks": [{"name": "Set test password", "no_log": True,
                   "ansible.builtin.command": {"argv": ["chpasswd"], "stdin": username + ":" + password}}],
    }]
    env = dict(os.environ, ANSIBLE_PIPELINING="True", ANSIBLE_KEEP_REMOTE_FILES="False", ANSIBLE_DEBUG="False")
    try:
        result = subprocess.run(cmd, input=json.dumps(play), text=True, capture_output=True, timeout=60, env=env)
    except subprocess.TimeoutExpired:
        raise pytest.fail.Exception(
            "Password initialization timed out; remote process/cleanup state unknown", pytrace=False) from None
    except OSError:
        raise pytest.fail.Exception("Password initialization could not start", pytrace=False) from None
    if result.returncode:
        pytest.fail("Password initialization failed, rc={}".format(result.returncode), pytrace=False)


def _delete_user(duthost, prefix, username):
    result = duthost.command(argv=prefix + ["userdel", username], module_ignore_errors=True)
    assert result["rc"] in (0, 6), "Test user cleanup failed"  # 6: absent after failed setup


def _cloudtype(duthost):
    # HEXISTS distinguishes an absent field from an existing empty string.
    exists = duthost.command(argv=["sonic-db-cli", CONFIG_DB, "HEXISTS", DB_KEY, "cloudtype"])
    assert exists["stdout"].strip() in ("0", "1"), "Invalid sentinel existence result"
    value = duthost.command(argv=["sonic-db-cli", CONFIG_DB, "HGET", DB_KEY, "cloudtype"])
    return exists["stdout"].strip() == "1", value["stdout"].rstrip("\n")


def _restore_cloudtype(duthost, original):
    exists, value = original
    result = (redis_hset(duthost, CONFIG_DB, DB_KEY, cloudtype=value) if exists
              else redis_hdel(duthost, CONFIG_DB, DB_KEY, "cloudtype"))
    assert result["rc"] == 0 and _cloudtype(duthost) == original, "Sentinel restoration failed"


@pytest.fixture
def password_identity(request, gnmi_tls, role):  # noqa: F811
    """Reuse a fixed test name sequentially; clean up before TLS rollback."""
    __tracebackhide__ = True
    duthost = gnmi_tls.duthost
    container = ["docker", "exec", "gnmi"]
    info = json.loads(duthost.command(argv=["docker", "inspect", "gnmi"])["stdout"])[0]
    assert info["HostConfig"]["NetworkMode"] == "host", "Password authentication requires host sshd"
    files = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow")
    for mount in info["Mounts"]:
        destination = mount["Destination"].rstrip("/")
        assert not any(path == destination or path.startswith(destination + "/") for path in files), \
            "Container account files must not be shared mounts"
    for prefix in ([], container):
        for path in files:
            actual = duthost.command(argv=prefix + ["readlink", "-f", path])["stdout"].strip()
            assert actual == path, "Account file symlinks are unsupported"
    username = "gnmi_test_" + role.rsplit("_", 1)[1]
    original = _cloudtype(duthost)
    with ExitStack() as cleanup:
        cleanup.callback(_restore_cloudtype, duthost, original)
        group = duthost.command(argv=container + ["getent", "group", role], module_ignore_errors=True)
        assert group["rc"] in (0, 2), "Role group lookup failed"
        if group["rc"] == 2:
            duthost.command(argv=container + ["groupadd", role])
            cleanup.callback(duthost.command, argv=container + ["groupdel", role])
        cleanup.callback(_delete_user, duthost, [], username)
        cleanup.callback(_delete_user, duthost, container, username)
        password = "Gnmi!9_" + secrets.token_hex(20)
        useradd_args = ["--no-create-home", "--no-user-group", "--gid", "nogroup", "--no-log-init",
                        "-K", "CREATE_MAIL_SPOOL=no", "--shell", "/bin/bash"]
        setup_local_user(duthost, {"local_user": username, "local_user_passwd": password},
                         useradd_args=useradd_args, password_setter=partial(_set_password, request))
        duthost.command(argv=container + ["useradd"] + useradd_args + ["--groups", role, username])
        result = redis_hset(duthost, CONFIG_DB, "GNMI|gnmi", user_auth="password")
        assert result["rc"] == 0, "Could not select password-only authentication"
        _restart_gnoi_server(duthost)
        cmdline = duthost.command(argv=container + ["sh", "-c", "ps -eo args | grep '^/usr/sbin/telemetry '"])["stdout"]
        assert re.search(r"--?client_auth(?:=|\s+)password(?:\s|$)", cmdline), "Password-only mode not active"
        assert "config_table_name" not in cmdline, "Unexpected certificate role mapping"
        # Keep the test password out of pytest fixture-value reprs and --showlocals.
        yield gnmi_tls, username, lambda: password


@pytest.mark.parametrize("role", ["gnmi_config_db_readonly", "gnmi_config_db_readwrite"], ids=["readonly", "readwrite"])
def test_password_access(password_identity, role):
    __tracebackhide__ = True
    fixture, username, get_password = password_identity
    duthost = fixture.duthost
    assert redis_hset(duthost, CONFIG_DB, DB_KEY, cloudtype="Private")["rc"] == 0
    assert _cloudtype(duthost) == (True, "Private"), "Sentinel setup failed"
    metadata = (("username", username), ("password", get_password()))
    write = build_native_set_request(PARTS, "Public")
    with gnmi_connection(fixture) as (_, stub):
        if role.endswith("readonly"):
            read = gnmi_pb2.GetRequest(encoding=gnmi_pb2.JSON_IETF)
            path = read.path.add(origin="sonic-db")
            for part in PARTS:
                path.elem.add(name=part)
            try:
                response = stub.Get(read, metadata=metadata, timeout=30)
            except grpc.RpcError:
                raise pytest.fail.Exception("Password Get failed", pytrace=False) from None
            values = [json.loads(update.val.json_ietf_val) for notification in response.notification
                      for update in notification.update]
            assert values == ["Private"], "Password Get did not return the sentinel"
            try:
                stub.Set(write, metadata=metadata, timeout=30)
            except grpc.RpcError as error:
                if error.code() != grpc.StatusCode.PERMISSION_DENIED or role not in error.details():
                    raise pytest.fail.Exception(
                        "Password Set did not return the target readonly denial", pytrace=False) from None
            else:
                pytest.fail("Password readonly Set unexpectedly succeeded", pytrace=False)
            assert _cloudtype(duthost) == (True, "Private"), "Denied Set changed Redis"
        else:
            try:
                stub.Set(write, metadata=metadata, timeout=30)
            except grpc.RpcError:
                raise pytest.fail.Exception("Password readwrite Set failed", pytrace=False) from None
            assert _cloudtype(duthost) == (True, "Public"), "Authorized Set did not change Redis"
