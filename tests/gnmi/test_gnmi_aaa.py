"""gNMI audit, authentication, and authorization tests."""

import base64
import json
import logging
import shlex
import time
import uuid
from contextlib import ExitStack

import pytest
from pygnmi.client import gNMIException

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    _restart_gnoi_server,
    gnmi_tls,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_audit import (
    RPC_COMPLETION_PREFIX,
    get_audit_log_offset,
    parse_audit_records,
    wait_for_audit_record,
    wait_for_audit_records,
)
from tests.common.helpers.sonic_db import (
    CONFIG_DB,
    redis_del,
    redis_hdel,
    redis_hget,
    redis_hset,
    redis_keys,
)
from tests.common.helpers.syslog_helpers import (
    capture_remote_syslog,
    is_mgmt_vrf_enabled,
    read_syslog_payloads,
)
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.ptf_grpc import PtfGrpcError
from tests.common.pygnmi_client import GetDataType, PygnmiClientError

pytestmark = [
    pytest.mark.topology("any"),
]
logger = logging.getLogger(__name__)
allure.logger = logger
CLIENT_PRINCIPAL = "test.client.gnmi.sonic"
GENERIC_NOACCESS_ROLE = "gnmi_noaccess"
GENERIC_READONLY_ROLE = "gnmi_readonly"
GENERIC_READWRITE_ROLE = "gnmi_readwrite"
CONFIG_DB_NOACCESS_ROLE = "gnmi_config_db_noaccess"
CONFIG_DB_READONLY_ROLE = "gnmi_config_db_readonly"
CONFIG_DB_READWRITE_ROLE = "gnmi_config_db_readwrite"
UNMAPPED_CN_ERROR = "Unauthenticated|unauthenticated|Invalid cert cname|" "not a trusted|common name mapping"
GET_METHOD = "/gnmi.gNMI/Get"
SET_METHOD = "/gnmi.gNMI/Set"
RATE_LIMIT_BURST = 60
RATE_LIMIT_REFILL_SECONDS = 60
CONFIG_DB_GET_PATH = "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"
CONFIG_DB_SET_PATH = "{}/cloudtype".format(CONFIG_DB_GET_PATH)
AUDIT_GET_PATH = "/CONFIG_DB/localhost/DEVICE_METADATA/localhost"
AUDIT_SET_PATH = "{}/cloudtype".format(AUDIT_GET_PATH)


def _set_configdb(env, metadata=None):
    env.grpc.call_unary("gnmi.gNMI", "Set", {
        "prefix": {"origin": "sonic-db"},
        "update": [{
            "path": {"elem": [{"name": name} for name in (
                "CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost", "cloudtype",
            )]},
            "val": {"jsonIetfVal": base64.b64encode(b'"Public"').decode()},
        }],
    }, metadata=metadata)


def _get_configdb(env):
    env.grpc.call_unary("gnmi.gNMI", "Get", {
        "prefix": {"origin": "sonic-db"},
        "path": [{"elem": [{"name": name} for name in (
            "CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost",
        )]}],
        "type": "ALL",
        "encoding": "JSON_IETF",
    })


def _get_countersdb(env):
    env.grpc.call_unary("gnmi.gNMI", "Get", {
        "prefix": {"target": "COUNTERS_DB"},
        "path": [{"elem": [{"name": "COUNTERS_PORT_NAME_MAP"}]}],
        "type": "ALL",
        "encoding": "JSON_IETF",
    })


def _get_capabilities(env):
    result = env.pygnmi_client.capabilities()
    models = result.get("supported_models", [])
    encodings = result.get("supported_encodings", [])
    pytest_assert(
        any(model.get("name") == "sonic-db" for model in models),
        "sonic-db not found in gNMI capabilities: {}".format(models),
    )
    pytest_assert(
        "json_ietf" in encodings,
        "json_ietf not found in gNMI capabilities: {}".format(encodings),
    )


def _set_client_cert_role(duthost, role):
    role_key = "GNMI_CLIENT_CERT|{}".format(CLIENT_PRINCIPAL)
    if role is None:
        result = redis_del(duthost, CONFIG_DB, role_key)[0]
        pytest_assert(
            result["rc"] == 0 and result["stdout"].strip() == "1",
            "Failed to remove client certificate mapping: {}".format(result),
        )
        return

    result = redis_hset(duthost, CONFIG_DB, role_key, **{"role@": role})
    pytest_assert(
        result["rc"] == 0,
        "Failed to set role {!r}: {}".format(role, result),
    )
    pytest_assert(
        redis_hget(duthost, CONFIG_DB, role_key, "role@") == role,
        "Client certificate role was not set to {!r}".format(role),
    )


AUDIT_ACTIVITIES = [
    pytest.param(_get_countersdb, GET_METHOD, id="get"),
    pytest.param(_set_configdb, SET_METHOD, id="set"),
]


@pytest.mark.parametrize("operation,method", AUDIT_ACTIVITIES)
def test_gnmi_audit_log(gnmi_tls, operation, method):  # noqa: F811
    duthost = gnmi_tls.duthost
    offset = get_audit_log_offset(duthost)

    operation(gnmi_tls)
    wait_for_audit_record(duthost, offset, method, CLIENT_PRINCIPAL)


def test_gnmi_audit_rate_limit(gnmi_tls):  # noqa: F811
    """Verify Get outcome buckets are limited and Set remains unlimited."""
    duthost = gnmi_tls.duthost
    offset = get_audit_log_offset(duthost)

    burst_started = time.monotonic()
    with gnmi_tls.pygnmi_client._build_client() as client:
        for _ in range(RATE_LIMIT_BURST + 1):
            client.get(
                path=[CONFIG_DB_GET_PATH],
                encoding="json_ietf",
            )

        get_burst_seconds = time.monotonic() - burst_started
        pytest_assert(
            get_burst_seconds < RATE_LIMIT_REFILL_SECONDS,
            "Get burst took {:.1f}s; requests crossed the 60s refill " "boundary".format(get_burst_seconds),
        )

        with pytest.raises(gNMIException, match="unsupported request type"):
            client.get(
                path=[CONFIG_DB_GET_PATH],
                datatype=str(GetDataType.STATE),
                encoding="json_ietf",
            )

    get_records = wait_for_audit_records(
        duthost,
        offset,
        GET_METHOD,
        CLIENT_PRINCIPAL,
        expected_count=RATE_LIMIT_BURST,
        code="OK",
        path=AUDIT_GET_PATH,
    )
    pytest_assert(
        all(record["suppressed"] == 0 for record in get_records),
        "In-limit Get records unexpectedly reported suppression",
    )

    unimplemented_records = wait_for_audit_records(
        duthost,
        offset,
        GET_METHOD,
        CLIENT_PRINCIPAL,
        expected_count=1,
        code="Unimplemented",
        path=AUDIT_GET_PATH,
    )
    pytest_assert(
        unimplemented_records[0]["suppressed"] == 0,
        "Get/Unimplemented did not use an independent outcome bucket",
    )

    _set_client_cert_role(duthost, CONFIG_DB_READONLY_ROLE)
    with gnmi_tls.pygnmi_client._build_client() as client:
        for _ in range(RATE_LIMIT_BURST + 1):
            with pytest.raises(gNMIException, match=CONFIG_DB_READONLY_ROLE):
                client.set(
                    update=[(CONFIG_DB_SET_PATH, '"Public"')],
                    encoding="json_ietf",
                )

    set_records = wait_for_audit_records(
        duthost,
        offset,
        SET_METHOD,
        CLIENT_PRINCIPAL,
        expected_count=RATE_LIMIT_BURST + 1,
        code="Unknown",
        path=AUDIT_SET_PATH,
    )
    pytest_assert(
        all(record["suppressed"] == 0 for record in set_records),
        "Set records were unexpectedly rate-limited",
    )

    refill_wait = max(
        0,
        RATE_LIMIT_REFILL_SECONDS + 1 - (time.monotonic() - burst_started),
    )
    time.sleep(refill_wait)
    gnmi_tls.pygnmi_client.get(CONFIG_DB_GET_PATH)

    get_records = wait_for_audit_records(
        duthost,
        offset,
        GET_METHOD,
        CLIENT_PRINCIPAL,
        expected_count=RATE_LIMIT_BURST + 1,
        code="OK",
        path=AUDIT_GET_PATH,
    )
    pytest_assert(
        get_records[-1]["suppressed"] == 1,
        "First refilled Get record did not report one suppressed request: {}".format(get_records[-1]),
    )


@pytest.mark.parametrize("operation,method", AUDIT_ACTIVITIES)
def test_gnmi_audit_log_remote_forwarding(gnmi_tls, ptfhost, operation, method):  # noqa: F811
    duthost = gnmi_tls.duthost
    syslog_vrf = "mgmt" if is_mgmt_vrf_enabled(duthost) else None

    with capture_remote_syslog(duthost, ptfhost.mgmt_ip, vrf=syslog_vrf) as (capture_result, capture_file):
        offset = get_audit_log_offset(duthost)
        with allure.step("Generate a {} audit record".format(method)):
            operation(gnmi_tls)

        with allure.step("Verify the remotely forwarded audit record"):
            local_records = wait_for_audit_record(duthost, offset, method, CLIENT_PRINCIPAL)
            forwarded_payloads = read_syslog_payloads(duthost, capture_result, capture_file)
            pytest_assert(
                any(RPC_COMPLETION_PREFIX in payload for payload in forwarded_payloads),
                "No RPC_COMPLETION marker found in forwarded UDP packets",
            )
            streamed_records = [
                record
                for payload in forwarded_payloads
                for record in parse_audit_records(payload, method, CLIENT_PRINCIPAL)
            ]
            pytest_assert(
                streamed_records == local_records,
                "Streamed audit records differ from local gNMI records: "
                "local={}, streamed={}".format(
                    local_records,
                    streamed_records,
                ),
            )


@pytest.mark.parametrize("operation,method", AUDIT_ACTIVITIES)
def test_gnmi_default_cert_auth(gnmi_tls, operation, method):  # noqa: F811
    duthost = gnmi_tls.duthost
    if method == SET_METHOD:
        redis_hset(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", cloudtype="Private")
        pytest_assert(
            redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == "Private",
            "Failed to seed the Set authorization sentinel",
        )
    delete_result = redis_hdel(duthost, CONFIG_DB, "GNMI|gnmi", "user_auth")
    pytest_assert(
        delete_result["rc"] == 0 and delete_result["stdout"].strip() == "1",
        "Failed to delete GNMI|gnmi.user_auth: {}".format(delete_result),
    )
    pytest_assert(
        not redis_hget(duthost, CONFIG_DB, "GNMI|gnmi", "user_auth"),
        "GNMI|gnmi.user_auth is still configured after HDEL",
    )
    _restart_gnoi_server(duthost)

    redis_del(
        duthost,
        CONFIG_DB,
        *redis_keys(duthost, CONFIG_DB, "GNMI_CLIENT_CERT|*"),
    )
    with pytest.raises(
        PtfGrpcError,
        match="Unauthenticated",
    ):
        operation(gnmi_tls)
    if method == SET_METHOD:
        pytest_assert(
            redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == "Private",
            "Unauthenticated Set changed CONFIG_DB",
        )


CAPABILITIES_ROLE_CASES = [
    pytest.param(
        GENERIC_NOACCESS_ROLE,
        _get_capabilities,
        r"does not have access.*role gnmi_noaccess\b",
        id="generic-noaccess-capabilities",
    ),
    pytest.param(
        GENERIC_READONLY_ROLE,
        _get_capabilities,
        None,
        id="generic-readonly-capabilities",
    ),
    pytest.param(
        GENERIC_READWRITE_ROLE,
        _get_capabilities,
        None,
        id="generic-readwrite-capabilities",
    ),
    pytest.param(
        "",
        _get_capabilities,
        None,
        id="empty-role-capabilities",
    ),
]

CONFIG_DB_ROLE_CASES = [
    pytest.param(
        CONFIG_DB_NOACCESS_ROLE,
        _get_configdb,
        r"does not have access.*role gnmi_config_db_noaccess\b",
        id="configdb-noaccess-get",
    ),
    pytest.param(
        CONFIG_DB_NOACCESS_ROLE,
        _set_configdb,
        r"does not have access.*role gnmi_config_db_noaccess\b",
        id="configdb-noaccess-set",
    ),
    pytest.param(
        CONFIG_DB_READONLY_ROLE,
        _get_configdb,
        None,
        id="configdb-readonly-get",
    ),
    pytest.param(
        CONFIG_DB_READONLY_ROLE,
        _set_configdb,
        r"does not have access.*role gnmi_config_db_readonly\b",
        id="configdb-readonly-set",
    ),
    pytest.param(
        CONFIG_DB_READWRITE_ROLE,
        _get_configdb,
        None,
        id="configdb-readwrite-get",
    ),
    pytest.param(
        CONFIG_DB_READWRITE_ROLE,
        _set_configdb,
        None,
        id="configdb-readwrite-set",
    ),
]

UNMAPPED_CN_ROLE_CASES = [
    pytest.param(
        None,
        _get_configdb,
        UNMAPPED_CN_ERROR,
        id="unmapped-get",
    ),
    pytest.param(
        None,
        _set_configdb,
        UNMAPPED_CN_ERROR,
        id="unmapped-set",
    ),
]


@pytest.mark.parametrize(
    "role,operation,error_pattern",
    CAPABILITIES_ROLE_CASES + CONFIG_DB_ROLE_CASES + UNMAPPED_CN_ROLE_CASES,
)
def test_cn_role_access(gnmi_tls, role, operation, error_pattern):  # noqa: F811
    """Verify generic and target-specific role authorization."""
    duthost = gnmi_tls.duthost
    if operation is _set_configdb:
        redis_hset(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", cloudtype="Private")
        pytest_assert(
            redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == "Private",
            "Failed to seed the Set authorization sentinel",
        )
    # gnmi_tls owns restoration of both the mapping and the sentinel.
    _set_client_cert_role(duthost, role)
    if error_pattern:
        error_type = PygnmiClientError if operation is _get_capabilities else PtfGrpcError
        with pytest.raises(error_type, match=error_pattern):
            operation(gnmi_tls)
    else:
        operation(gnmi_tls)
    if operation is _set_configdb:
        expected = "Private" if error_pattern else "Public"
        pytest_assert(
            redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == expected,
            "CONFIG_DB state does not match the Set authorization outcome",
        )


@pytest.mark.disable_loganalyzer
def test_mixed_auth_local_cert_role_access(gnmi_tls):  # noqa: F811
    """Rejected password must not grant writes to a local readonly certificate identity.

    Requires the role-enforcing server including sonic-gnmi #824 and #807.
    Mixed auth uses the launcher's empty config_table_name, so certificate roles
    come from container-local users/groups, not GNMI_CLIENT_CERT. This verifies
    the external fallback/role contract, not an internal identity-reset hook.
    """
    duthost = gnmi_tls.duthost
    gnmi_tls.grpc.configure_max_time(30)
    password_user = "gnmi_auth_" + uuid.uuid4().hex[:12]
    groups = [CONFIG_DB_READONLY_ROLE, CONFIG_DB_READWRITE_ROLE]
    mounts = json.loads(duthost.command(argv=["docker", "inspect", "gnmi"])["stdout"])[0]["Mounts"]
    protected = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow")
    pytest_assert(not any(
        path == mount["Destination"].rstrip("/") or
        path.startswith(mount["Destination"].rstrip("/") + "/")
        for mount in mounts for path in protected
    ), "Mixed-auth test requires container-local account files, not bind-mounted identities")

    # Refuse existing identities/groups: CONFIG_DB rollback does not own these.
    for database, names in (("passwd", [CLIENT_PRINCIPAL, password_user]), ("group", groups)):
        for name in names:
            result = duthost.command(
                argv=["docker", "exec", "gnmi", "getent", database, name], module_ignore_errors=True,
            )
            pytest_assert(result["rc"] == 2, "Account/group already exists or lookup failed: " + name)
    result = duthost.command(argv=["getent", "passwd", password_user], module_ignore_errors=True)
    # getent returns 2 for an absent key (1 means invalid arguments/database).
    pytest_assert(result["rc"] == 2, "Password probe must not name an existing host user")

    def account_command(*args):
        duthost.command(argv=["docker", "exec", "gnmi"] + list(args))

    def configure_auth(mode):
        result = redis_hset(duthost, CONFIG_DB, "GNMI|gnmi", user_auth=mode)
        pytest_assert(result["rc"] == 0, "Failed to configure authentication mode")
        _restart_gnoi_server(duthost)
        output = duthost.command(argv=["docker", "exec", "gnmi", "pgrep", "-a", "-x", "telemetry"])
        pytest_assert(len(output["stdout_lines"]) == 1, "Expected one native telemetry process")
        argv = shlex.split(output["stdout_lines"][0])[1:]
        pytest_assert("--client_auth" in argv and argv[argv.index("--client_auth") + 1] == mode,
                      "Running server does not use the requested authentication mode")
        pytest_assert(not any(arg.startswith("--config_table_name") for arg in argv),
                      "Mixed-auth regression requires the launcher's empty config_table_name")

    with ExitStack() as cleanup:
        for group in groups:
            account_command("groupadd", group)
            cleanup.callback(account_command, "groupdel", group)
        for name, group in ((password_user, CONFIG_DB_READWRITE_ROLE),
                            (CLIENT_PRINCIPAL, CONFIG_DB_READONLY_ROLE)):
            account_command("useradd", "-M", "-N", "-g", group, "-s", "/usr/sbin/nologin", "-p", "!", name)
            cleanup.callback(account_command, "userdel", name)

        metadata = [("username", password_user), ("password", "invalid-" + uuid.uuid4().hex)]
        redis_hset(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", cloudtype="Private")
        pytest_assert(redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == "Private",
                      "Failed to seed the Set authorization sentinel")
        # Password-only control proves this identity cannot authenticate at host sshd.
        configure_auth("password")
        with pytest.raises(PtfGrpcError, match=r"Code: Unauthenticated\b"):
            _set_configdb(gnmi_tls, metadata=metadata)
        pytest_assert(redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == "Private",
                      "Rejected password changed CONFIG_DB")

        configure_auth("password,cert")
        with pytest.raises(PtfGrpcError, match=r"(?s)Code: PermissionDenied\b.*role gnmi_config_db_readonly\b"):
            _set_configdb(gnmi_tls, metadata=metadata)
        pytest_assert(redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == "Private",
                      "Readonly certificate fallback changed CONFIG_DB")

        # Same identity, route, and rejected password; only our owned CN role changes.
        account_command("usermod", "-g", CONFIG_DB_READWRITE_ROLE, CLIENT_PRINCIPAL)
        _set_configdb(gnmi_tls, metadata=metadata)
        pytest_assert(redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == "Public",
                      "Readwrite certificate fallback did not update CONFIG_DB")
    # ExitStack deletes only the accounts/groups created above; gnmi_tls restores CONFIG_DB.
