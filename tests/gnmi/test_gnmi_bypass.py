"""Native Set bypass must allow writers and deny identities without write access."""

import base64
import json
import re
import uuid

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_audit import get_audit_log_offset
from tests.common.helpers.sonic_db import CONFIG_DB, redis_del, redis_hget, redis_hgetall, redis_hset
from tests.common.ptf_grpc import PtfGrpcError
from tests.common.utilities import wait_until


pytestmark = [pytest.mark.topology("any"), pytest.mark.disable_loganalyzer]
BYPASS_HEADER = {"x-sonic-ss-bypass-validation": "true"}
BYPASS_SKUS = ("Cisco-8101", "Cisco-8102", "Cisco-8223")
CLIENT_KEY = "GNMI_CLIENT_CERT|test.client.gnmi.sonic"


@pytest.fixture
def bypass_env(gnmi_tls):  # noqa: F811
    """Bound RPC deadlines and restore the certificate role after each case."""
    duthost = gnmi_tls.duthost
    hwsku = redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "hwsku")
    if not hwsku.startswith(BYPASS_SKUS):
        pytest.skip("Native Set bypass requires Cisco-8101/8102/8223; DUT SKU is {}".format(hwsku))
    original_role = redis_hget(duthost, CONFIG_DB, CLIENT_KEY, "role@")
    pytest_assert(original_role, "TLS fixture did not install a certificate role")
    gnmi_tls.grpc.configure_max_time(30)
    try:
        yield gnmi_tls
    finally:
        _set_role(duthost, original_role)


def _set_role(duthost, role):
    result = redis_hset(duthost, CONFIG_DB, CLIENT_KEY, **{"role@": role})
    pytest_assert(result["rc"] == 0, "Failed to configure certificate role")
    pytest_assert(redis_hget(duthost, CONFIG_DB, CLIENT_KEY, "role@") == role,
                  "Certificate role was not applied")


@pytest.mark.parametrize("has_access", [True, False], ids=["with-access", "without-access"])
@pytest.mark.parametrize("wire_form", ["prefix-target", "database-in-path"])
@pytest.mark.parametrize("operation", ["update", "replace", "delete"])
def test_native_set_bypass_authorization(bypass_env, has_access, wire_form, operation):
    """Regress sonic-gnmi PR 791: bypass metadata must not grant write access.

    Requires a bypass-enabled SKU and checks the fast-path log in addition to
    CONFIG_DB state, so ordinary native Set success cannot mask a bypass skip.
    """
    env = bypass_env
    duthost = env.duthost
    # PrefixListMgr ignores keys without a '|' separated prefix. This isolated
    # name exercises an allowed table without creating an FRR prefix-list or
    # changing a live route. The log assertion below proves bypass selection.
    name = "gnmi_authz_" + uuid.uuid4().hex[:12]
    key = "PREFIX_LIST|" + name
    original = {"action": "permit"}
    updated = {"action": "deny"}
    pytest_assert(not redis_hgetall(duthost, CONFIG_DB, key), "Test key already exists")
    prefix = {"origin": "sonic-db"}
    elements = ["PREFIX_LIST", name]
    if wire_form == "prefix-target":
        prefix["target"] = "CONFIG_DB"
    else:
        elements = ["CONFIG_DB", "localhost"] + elements
    path = {"elem": [{"name": element} for element in elements]}
    request = {"prefix": prefix}
    if operation == "delete":
        request[operation] = [path]
    else:
        value = json.dumps(updated).encode()
        request[operation] = [{"path": path, "val": {"jsonIetfVal": base64.b64encode(value).decode()}}]

    try:
        result = redis_hset(duthost, CONFIG_DB, key, **original)
        pytest_assert(result["rc"] == 0 and redis_hgetall(duthost, CONFIG_DB, key) == original,
                      "Failed to seed CONFIG_DB sentinel")
        # Prove this exact request reaches the bypass before testing a denied
        # identity, even when pytest selects only a single negative case.
        _set_role(duthost, "gnmi_config_db_readwrite")
        offset = get_audit_log_offset(duthost)

        def invoke():
            return env.grpc.call_unary("gnmi.gNMI", "Set", request, metadata=BYPASS_HEADER)

        response = invoke()
        pytest_assert(response.get("response"), "Set returned no operation results")
        expected = {} if operation == "delete" else updated
        pytest_assert(redis_hgetall(duthost, CONFIG_DB, key) == expected, "Authorized Set state mismatch")

        def bypass_logged():
            log = duthost.shell("sudo tail -c +{} /var/log/gnmi.log".format(offset + 1))["stdout"]
            return "Bypass fast path: direct ConfigDB operations" in log

        pytest_assert(wait_until(10, 1, 0, bypass_logged), "Set succeeded without exercising the bypass path")
        if not has_access:
            result = redis_hset(duthost, CONFIG_DB, key, **original)
            pytest_assert(result["rc"] == 0 and redis_hgetall(duthost, CONFIG_DB, key) == original,
                          "Failed to restore sentinel before denial check")
            role = "gnmi_config_db_readonly"
            _set_role(duthost, role)
            with pytest.raises(PtfGrpcError) as caught:
                invoke()
            message = str(caught.value)
            # checkRoleAccess currently returns a plain Go error (gRPC Unknown).
            pytest_assert(re.search(r"Code:\s*(Unknown|PermissionDenied)\b", message), message)
            pytest_assert("does not have access" in message and role in message, message)
            pytest_assert(redis_hgetall(duthost, CONFIG_DB, key) == original,
                          "Denied bypass Set changed CONFIG_DB")
    finally:
        result = redis_del(duthost, CONFIG_DB, key)[0]
        pytest_assert(result["rc"] == 0, "Failed to remove CONFIG_DB sentinel")
        pytest_assert(not redis_hgetall(duthost, CONFIG_DB, key), "CONFIG_DB sentinel still exists")
