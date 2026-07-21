"""Read-only tracer tests for the direct native gNMI fixture."""

import pytest

pytestmark = [pytest.mark.topology("any")]


def _updates(result):
    for notification in result.get("notification", []):
        for update in notification.get("update", []):
            yield update


def _find_leaf(value, suffix):
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(nested, (dict, list)):
                found = _find_leaf(nested, suffix)
                if found is not None:
                    return found
            elif key.endswith(suffix):
                return nested
    elif isinstance(value, list):
        for nested in value:
            found = _find_leaf(nested, suffix)
            if found is not None:
                return found
    return None


def _as_int(value):
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def test_capabilities(gnmi_client):
    """The direct native client reaches the managed gNMI server."""
    result = gnmi_client.capabilities()

    assert result.get("supported_models")
    assert "json_ietf" in result.get("supported_encodings", [])


def test_interface_mtu(duthosts, enum_rand_one_per_hwsku_frontend_hostname, gnmi_client):
    """The client and expected-value check use the same selected DUT."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    port_key = duthost.shell(
        "sonic-db-cli CONFIG_DB keys 'PORT|*' | sort | head -n 1"
    )["stdout"].strip()
    assert port_key, "Selected frontend DUT has no CONFIG_DB PORT entries"
    port = port_key.split("|", 1)[1]
    expected = int(
        duthost.shell(
            "sonic-db-cli CONFIG_DB hget '{}' mtu".format(port_key)
        )["stdout"].strip()
    )

    result = gnmi_client.get(
        "/openconfig-interfaces:interfaces/interface[name={}]/config/mtu".format(port)
    )
    updates = list(_updates(result))

    assert updates
    assert any(
        "mtu" in str(update.get("path", ""))
        and (_as_int(update.get("val")) == expected
             or _as_int(_find_leaf(update.get("val"), "mtu")) == expected)
        for update in updates
    )
