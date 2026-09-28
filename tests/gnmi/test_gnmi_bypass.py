"""Native Set bypass must allow writers and deny identities without write access."""

from contextlib import contextmanager
import uuid

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_audit import get_audit_log_offset
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hget, redis_hgetall, redis_hset
from tests.common.pygnmi_client import PygnmiClientError
from tests.common.utilities import wait_until


pytestmark = [pytest.mark.topology("any"), pytest.mark.disable_loganalyzer]
BYPASS_METADATA = [("x-sonic-ss-bypass-validation", "true")]
BYPASS_SKUS = ("Cisco-8101", "Cisco-8102", "Cisco-8223")
CLIENT_KEY = "GNMI_CLIENT_CERT|test.client.gnmi.sonic"
ORIGINAL = {"action": "permit"}
UPDATED = {"action": "deny"}


@contextmanager
def _expect_write(duthost):
    """An allowed request must complete through the actual bypass path."""
    offset = get_audit_log_offset(duthost)
    yield

    def bypass_logged():
        log = duthost.shell("sudo tail -c +{} /var/log/gnmi.log".format(offset + 1))["stdout"]
        return "Bypass fast path: direct ConfigDB operations" in log

    pytest_assert(wait_until(10, 1, 0, bypass_logged), "Set succeeded without exercising the bypass path")


def _expect_denial(duthost):
    # Transport errors and ordinary request-validation failures cannot match.
    return pytest.raises(PygnmiClientError, match=r"does not have access.*gnmi_config_db_readonly")


@pytest.mark.parametrize("role,expectation,expected_state", [
    pytest.param("gnmi_config_db_readwrite", _expect_write, "written", id="with-access"),
    pytest.param("gnmi_config_db_readonly", _expect_denial, "original", id="without-access"),
])
@pytest.mark.parametrize("prefix,target", [
    pytest.param("sonic-db:", "CONFIG_DB", id="prefix-target"),
    pytest.param("sonic-db:CONFIG_DB/localhost", None, id="database-in-path"),
])
@pytest.mark.parametrize("request_args,written_state", [
    pytest.param(lambda path: {"update": [(path, UPDATED)]}, UPDATED, id="update"),
    pytest.param(lambda path: {"replace": [(path, UPDATED)]}, UPDATED, id="replace"),
    pytest.param(lambda path: {"delete": [path]}, {}, id="delete"),
])
def test_native_set_bypass_authorization(
    gnmi_tls, role, expectation, expected_state, prefix, target, request_args, written_state  # noqa: F811
):
    """Use the same Set call with parameterized role, outcome and state assertions."""
    duthost = gnmi_tls.duthost
    hwsku = redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "hwsku")
    if not hwsku.startswith(BYPASS_SKUS):
        pytest.skip("Native Set bypass requires Cisco-8101/8102/8223; DUT SKU is {}".format(hwsku))

    # PrefixListMgr ignores keys without a '|' separated prefix, so this entry
    # does not configure an FRR prefix-list. gnmi_tls rolls back CONFIG_DB.
    name = "gnmi_authz_" + uuid.uuid4().hex[:12]
    key = "PREFIX_LIST|" + name
    pytest_assert(not redis_hgetall(duthost, CONFIG_DB, key), "Test key already exists")
    result = redis_hset(duthost, CONFIG_DB, key, **ORIGINAL)
    pytest_assert(result["rc"] == 0 and redis_hgetall(duthost, CONFIG_DB, key) == ORIGINAL,
                  "Failed to seed CONFIG_DB sentinel")
    result = redis_hset(duthost, CONFIG_DB, CLIENT_KEY, **{"role@": role})
    pytest_assert(result["rc"] == 0 and redis_hget(duthost, CONFIG_DB, CLIENT_KEY, "role@") == role,
                  "Certificate role was not applied")

    with expectation(duthost):
        gnmi_tls.pygnmi_client.set(
            prefix=prefix, target=target, metadata=BYPASS_METADATA,
            **request_args("PREFIX_LIST/" + name),
        )
    expected = {"original": ORIGINAL, "written": written_state}[expected_state]
    pytest_assert(redis_hgetall(duthost, CONFIG_DB, key) == expected,
                  "CONFIG_DB state does not match the authorization outcome")
