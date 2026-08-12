"""gNMI audit, authentication, and authorization tests."""

import json

import pytest

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    _restart_gnoi_server,
    gnmi_tls,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import (
    CONFIG_DB,
    redis_del,
    redis_hdel,
    redis_hset,
    redis_keys,
)
from tests.common.pygnmi_client import PygnmiClientError
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("any"),
]
RPC_COMPLETION_PREFIX = "RPC_COMPLETION "
CLIENT_PRINCIPAL = "test.client.gnmi.sonic"
READWRITE_CLIENT_PRINCIPAL = "test.client.readwrite.gnmi.sonic"
READONLY_ROLE = "gnmi_config_db_readonly"
READWRITE_ROLE = "gnmi_config_db_readwrite"


def _get_completions(log_text):
    records = []
    decoder = json.JSONDecoder()
    for line in log_text.splitlines():
        _, separator, payload = line.partition(RPC_COMPLETION_PREFIX)
        if not separator:
            continue
        try:
            record, _ = decoder.raw_decode(payload)
        except json.JSONDecodeError:
            continue
        if (record.get("method") == "/gnmi.gNMI/Get"
                and record.get("path") == ["/COUNTERS_PORT_NAME_MAP"]
                and record.get("principal") == CLIENT_PRINCIPAL):
            records.append(record)
    return records


def test_gnmi_get_audit_log(gnmi_tls):  # noqa: F811
    duthost = gnmi_tls.duthost
    offset = int(
        duthost.shell(
            "sudo stat -c %s /var/log/gnmi.log"
        )["stdout"].strip()
    )

    gnmi_tls.pygnmi_client.get(
        "COUNTERS_PORT_NAME_MAP",
        target="COUNTERS_DB",
    )

    def audit_record_written():
        new_log = duthost.shell(
            "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1),
            module_ignore_errors=True,
        )["stdout"]
        return bool(_get_completions(new_log))

    pytest_assert(
        wait_until(30, 1, 0, audit_record_written),
        "No new Get completion record in /var/log/gnmi.log",
    )
    new_log = duthost.shell(
        "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1)
    )["stdout"]
    pytest_assert(
        len(_get_completions(new_log)) == 1,
        "Expected exactly one new Get completion record",
    )


def _set_configdb(client):
    client.set(
        update=[(
            "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost/cloudtype",
            "Public",
        )],
    )


def _get_configdb(client):
    client.get(
        "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"
    )


def _get_countersdb(client):
    client.get(
        "COUNTERS_PORT_NAME_MAP",
        target="COUNTERS_DB",
    )


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(_get_countersdb, id="get"),
        pytest.param(_set_configdb, id="set"),
    ],
)
def test_gnmi_default_cert_auth(gnmi_tls, operation):  # noqa: F811
    duthost = gnmi_tls.duthost
    redis_hdel(duthost, CONFIG_DB, "GNMI|gnmi", "user_auth")
    _restart_gnoi_server(duthost)

    redis_del(
        duthost,
        CONFIG_DB,
        *redis_keys(duthost, CONFIG_DB, "GNMI_CLIENT_CERT|*"),
    )
    with pytest.raises(
        PygnmiClientError,
        match="Unauthenticated|unauthenticated|common name mapping",
    ):
        operation(gnmi_tls.pygnmi_client)


@pytest.mark.parametrize(
    "cn_roles,error_pattern",
    [
        pytest.param(
            {
                CLIENT_PRINCIPAL: READONLY_ROLE,
                READWRITE_CLIENT_PRINCIPAL: READWRITE_ROLE,
            },
            READONLY_ROLE,
            id="readonly",
        ),
        pytest.param(
            {READWRITE_CLIENT_PRINCIPAL: READWRITE_ROLE},
            "Unauthenticated|Invalid cert cname|not a trusted",
            id="unmapped",
        ),
    ],
)
def test_cn_insufficient_access(gnmi_tls, cn_roles, error_pattern):  # noqa: F811
    duthost = gnmi_tls.duthost
    redis_del(
        duthost,
        CONFIG_DB,
        *redis_keys(duthost, CONFIG_DB, "GNMI_CLIENT_CERT|*"),
    )
    for cname, role in cn_roles.items():
        redis_hset(
            duthost,
            CONFIG_DB,
            "GNMI_CLIENT_CERT|{}".format(cname),
            **{"role@": role}
        )

    with pytest.raises(
        PygnmiClientError,
        match=error_pattern,
    ):
        _set_configdb(gnmi_tls.pygnmi_client)


@pytest.mark.parametrize(
    "role,operation",
    [
        pytest.param(READONLY_ROLE, _get_configdb, id="readonly-get"),
        pytest.param(READWRITE_ROLE, _get_configdb, id="readwrite-get"),
        pytest.param(READWRITE_ROLE, _set_configdb, id="readwrite-set"),
    ],
)
def test_cn_allowed_access(gnmi_tls, role, operation):  # noqa: F811
    """Verify a mapped CN can perform the requested CONFIG_DB operation."""
    duthost = gnmi_tls.duthost
    redis_hset(
        duthost,
        CONFIG_DB,
        "GNMI_CLIENT_CERT|{}".format(CLIENT_PRINCIPAL),
        **{"role@": role}
    )

    operation(gnmi_tls.pygnmi_client)
