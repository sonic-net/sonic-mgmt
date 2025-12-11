"""
Testcases for YANG leaf:
    drop_monitor_limit (0 | 1..500)

Validates:
    - RESTCONF range enforcement
    - CONFIG_DB update
    - CLI behavior (if supported)
"""

import pytest
import logging

LOGGER = logging.getLogger(__name__)

REST_URL = "/restconf/data/sonic-sflow:SYSTEM_SFLOW/SYSTEM_SFLOW_LIST=default"


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def patch_drop_limit(rest_client, value):
    payload = {
        "sonic-sflow:SYSTEM_SFLOW_LIST": [
            {
                "drop_monitor_limit": value
            }
        ]
    }
    return rest_client.patch(REST_URL, payload)


def get_drop_limit_from_db(duthost):
    out = duthost.shell(
        "redis-cli -n 4 hgetall 'SYSTEM_SFLOW|default'"
    )["stdout"].splitlines()
    kv = dict(zip(out[0::2], out[1::2]))
    return int(kv.get("drop_monitor_limit", -999))


# ------------------------------------------------------------------------------
# Valid tests
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("value", [0, 1, 250, 500])
def test_sflow_drop_monitor_limit_valid(rest_client, duthost, value):
    """
    Must accept values in valid range:
        0 → disable
        1..500 allowed
    """
    LOGGER.info(f"Testing valid value: {value}")

    resp = patch_drop_limit(rest_client, value)
    assert resp.status_code == 204, f"Unexpected RESTCONF response: {resp.text}"

    # DB verification
    db_value = get_drop_limit_from_db(duthost)
    assert db_value == value, f"CONFIG_DB mismatch: expected={value}, got={db_value}"


# ------------------------------------------------------------------------------
# Invalid tests
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("value", [-1, -10, 501, 999, "abc"])
def test_sflow_drop_monitor_limit_invalid(rest_client, value):
    """
    Must reject values outside range:
        <0, >500, non-numeric
    """
    LOGGER.info(f"Testing invalid value: {value}")

    resp = patch_drop_limit(rest_client, value)

    assert resp.status_code == 400, \
        f"Expected 400 Bad Request, got {resp.status_code}"

    assert "must be 0 or in range 1-500" in resp.text, \
        "Expected YANG range error message missing"


# ------------------------------------------------------------------------------
# Boundary tests
# ------------------------------------------------------------------------------

def test_sflow_drop_monitor_limit_lower_bound(rest_client, duthost):
    resp = patch_drop_limit(rest_client, 0)
    assert resp.status_code == 204
    assert get_drop_limit_from_db(duthost) == 0


def test_sflow_drop_monitor_limit_upper_bound(rest_client, duthost):
    resp = patch_drop_limit(rest_client, 500)
    assert resp.status_code == 204
    assert get_drop_limit_from_db(duthost) == 500


# ------------------------------------------------------------------------------
# Optional CLI tests (if SONiC CLI supports this leaf)
# ------------------------------------------------------------------------------

@pytest.mark.skip(reason="Enable only if CLI `config sflow drop` is implemented")
def test_sflow_drop_monitor_limit_cli_valid(duthost):
    duthost.shell("config sflow drop monitor-limit 100")
    out = duthost.shell(
        "show runningconfiguration all | grep drop_monitor_limit"
    )["stdout"]
    assert "100" in out


@pytest.mark.skip(reason="Enable only if CLI `config sflow drop` is implemented")
def test_sflow_drop_monitor_limit_cli_invalid(duthost):
    res = duthost.shell("config sflow drop monitor-limit 700", module_ignore_errors=True)
    assert res["rc"] != 0
