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

pytestmark = [
    pytest.mark.topology("t0", "t1"),
]

REST_URL = "/restconf/data/sonic-sflow:SYSTEM_SFLOW/SYSTEM_SFLOW_LIST=default"
DROP_LIMIT_FIELD = "drop_monitor_limit"


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
    LOGGER.info("Testing valid value: %s", value)
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
    LOGGER.info("Testing invalid value: %s", value)
    resp = patch_drop_limit(rest_client, value)

    assert resp.status_code == 400, \
        f"Expected 400 Bad Request, got {resp.status_code}"

    body = resp.text.lower()
    assert any(tok in body for tok in (DROP_LIMIT_FIELD, "range", "error")), \
        f"validation error: {resp.text}"


def test_sflow_drop_monitor_limit_cli_valid(cli_drop_supported, duthost):
    duthost.shell("config sflow drop-monitor-limit 100")
    out = duthost.shell(
        "show runningconfiguration all | grep drop_monitor_limit"
    )["stdout"]
    assert "100" in out


def test_sflow_drop_monitor_limit_cli_invalid(cli_drop_supported, duthost):
    res = duthost.shell(
        "config sflow drop-monitor-limit 700", module_ignore_errors=True
    )
    assert res["rc"] != 0
