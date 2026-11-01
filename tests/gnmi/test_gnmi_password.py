"""Password-authenticated native Get/Set access using owned local identities.

Before device execution, qualify SSH/become pipelining (including failure and
timeout cleanup) for the selected inventory. no_log does not prevent remote
temporary plaintext files; a configured pipelining flag alone is not evidence.
"""
import json
import os
import re
import secrets
import subprocess

import grpc
import pytest
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import gnmi_tls, _restart_gnoi_server  # noqa: F401
from tests.common.helpers.gnmi_connection import gnmi_connection, build_native_set_request
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hset, redis_hdel
from tests.common.utilities import get_inventory_files

pytestmark = [pytest.mark.topology("any")]
DB_KEY = "DEVICE_METADATA|localhost"
PARTS = ("CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost", "cloudtype")


def _set_password(request, duthost, username, password):
    """Only this password task needs a playbook: adhoc kwargs cannot set no_log."""
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
        "tasks": [{
            "name": "Set owned password-test credential", "no_log": True,
            "ansible.builtin.command": {"argv": ["chpasswd"], "stdin": username + ":" + password},
        }],
    }]
    env = dict(os.environ, ANSIBLE_PIPELINING="True", ANSIBLE_KEEP_REMOTE_FILES="False", ANSIBLE_DEBUG="False")
    try:
        result = subprocess.run(cmd, input=json.dumps(play), text=True, capture_output=True,
                                timeout=60, env=env)
    except subprocess.TimeoutExpired:
        raise pytest.fail.Exception(
            "Password initialization timed out; remote process/cleanup state unknown", pytrace=False) from None
    except OSError:
        raise pytest.fail.Exception("Password initialization could not start", pytrace=False) from None
    if result.returncode:
        pytest.fail("Password initialization failed, rc={}".format(result.returncode), pytrace=False)


def _account_record(duthost, prefix, database, name):
    result = duthost.command(argv=prefix + ["getent", database, str(name)], module_ignore_errors=True)
    assert result["rc"] in (0, 2), "Account lookup failed"
    return result["stdout"].strip().split(":") if result["rc"] == 0 else None


def _remove_owned(duthost, prefix, database, name, identity):
    record = _account_record(duthost, prefix, database, name)
    if record is None:
        return
    assert int(record[2]) == identity, "Owned identity changed; refusing deletion"
    if database == "group":
        assert not record[3], "Owned group acquired other members; refusing deletion"
    command = "userdel" if database == "passwd" else "groupdel"
    duthost.command(argv=prefix + [command, name])
    assert _account_record(duthost, prefix, database, name) is None, "Owned identity survived cleanup"


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
    """One new username per instance; identity finalizers run before TLS rollback."""
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
    username = "gnmipw_" + secrets.token_hex(5)
    uid = 50000 + secrets.randbelow(10000)
    for prefix in ([], container):
        assert _account_record(duthost, prefix, "passwd", username) is None, "Test name already exists"
        assert _account_record(duthost, prefix, "passwd", uid) is None, "Test UID already exists"
        assert _account_record(duthost, prefix, "group", username) is None, "Test group name already exists"
        assert _account_record(duthost, prefix, "group", "nogroup") is not None, "Missing unprivileged base group"

    original = _cloudtype(duthost)
    request.addfinalizer(lambda: _restore_cloudtype(duthost, original))
    existing_group = _account_record(duthost, container, "group", role)
    if existing_group is None:
        gid = 60000 + secrets.randbelow(5000)
        assert _account_record(duthost, container, "group", gid) is None, "Test GID already exists"
        request.addfinalizer(lambda: _remove_owned(duthost, container, "group", role, gid))
        duthost.command(argv=container + ["groupadd", "--gid", str(gid), role])
    else:
        def check_existing_group():
            assert _account_record(duthost, container, "group", role) == existing_group, \
                "Preexisting role group was not restored"
        request.addfinalizer(check_existing_group)

    for prefix in ([], container):
        request.addfinalizer(lambda prefix=prefix: _remove_owned(duthost, prefix, "passwd", username, uid))
        args = ["useradd", "--uid", str(uid), "--no-create-home", "--no-user-group", "--gid", "nogroup",
                "--no-log-init", "-K", "CREATE_MAIL_SPOOL=no", "--shell", "/bin/bash"]
        if prefix:
            args.extend(["--groups", role])
        duthost.command(argv=prefix + args + [username])
        record = _account_record(duthost, prefix, "passwd", username)
        assert record and int(record[2]) == uid, "Owned account was not created"

    password = "Gnmi!9_" + secrets.token_hex(20)
    _set_password(request, duthost, username, password)
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
