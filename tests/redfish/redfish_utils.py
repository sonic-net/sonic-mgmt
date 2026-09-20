"""
Shared Redfish test utilities for SONiC BMC Redfish API tests.
"""
import requests

from tests.common.helpers.assertions import pytest_assert


BMC_TEST_CA_NAME = "SONiC BMC Test CA"


def redfish_url(bmc_ip, path):
    """Build a full https URL for a Redfish path on the BMC."""
    return "https://{}{}".format(bmc_ip, path)


class RedfishClient:
    """HTTP client for Redfish API calls using mTLS client-certificate auth."""

    def __init__(self, bmc_ip, cert, key, ca, timeout=30):
        self.base_url = "https://{}".format(bmc_ip)
        self.cert = (cert, key)
        self.verify = ca
        self.timeout = timeout

    def _request(self, method, path, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return requests.request(
            method, self.base_url + path,
            cert=self.cert, verify=self.verify,
            **kwargs,
        )

    def get(self, path, **kwargs):
        return self._request("GET", path, **kwargs)

    def post(self, path, json=None, **kwargs):
        return self._request("POST", path, json=json, **kwargs)

    def patch(self, path, json=None, **kwargs):
        return self._request("PATCH", path, json=json, **kwargs)

    def delete(self, path, **kwargs):
        return self._request("DELETE", path, **kwargs)


def assert_field_equals(body, field, expected):
    """Assert a top-level field equals an expected value."""
    actual = body.get(field, "")
    pytest_assert(
        actual == expected,
        "Field '{}' must be {!r}, got: {!r}".format(field, expected, actual)
    )


def assert_field_contains(body, field, substring):
    """Assert a top-level field contains a substring."""
    actual = body.get(field, "")
    pytest_assert(
        substring in actual,
        "Field '{}' must contain {!r}, got: {!r}".format(field, substring, actual)
    )


def assert_field_nonempty(body, field):
    """Assert a top-level field is a non-empty string."""
    actual = body.get(field, "")
    pytest_assert(
        isinstance(actual, str) and len(actual) > 0,
        "Field '{}' must be a non-empty string, got: {!r}".format(field, actual)
    )


def assert_field_in(body, field, valid_values):
    """Assert a top-level field is one of the valid values."""
    actual = body.get(field, "")
    pytest_assert(
        actual in valid_values,
        "Field '{}' must be one of {}, got: {!r}".format(field, valid_values, actual)
    )


def assert_status_ok(response, path):
    """Assert HTTP 200 from a given path."""
    pytest_assert(
        response.status_code == 200,
        "Expected HTTP 200 from {}, got: {}".format(path, response.status_code)
    )


def assert_member_count(body, minimum=1):
    """Assert Members@odata.count >= minimum and Members array has entries."""
    count = body.get("Members@odata.count", 0)
    pytest_assert(
        count >= minimum,
        "Members@odata.count must be >= {}, got: {}".format(minimum, count)
    )


def assert_no_content(response, path):
    """Assert HTTP 204 with an empty body from a given path."""
    pytest_assert(
        response.status_code == 204,
        "Expected HTTP 204 from {}, got: {} body={!r}".format(
            path, response.status_code, response.text[:500])
    )
    pytest_assert(
        not response.content,
        "Expected empty body with HTTP 204 from {}, got: {!r}".format(path, response.text[:500])
    )


def assert_redfish_error(response, status, message, message_args=None, prop=None):
    """Assert a Redfish error response carrying the given registry message.

    bmcweb reports some errors under body["error"] ("code" plus
    "@Message.ExtendedInfo") and property-scoped ones under
    "<prop>@Message.ExtendedInfo". With prop given only that annotation is
    searched; without it every ExtendedInfo list in the body is. MessageId is
    matched on its ".<message>" suffix so a Base registry version bump does
    not break callers.
    """
    pytest_assert(
        response.status_code == status,
        "Expected HTTP {}, got: {} body={!r}".format(status, response.status_code, response.text[:500])
    )
    try:
        body = response.json()
    except ValueError:
        pytest_assert(False, "Expected a Redfish error body, got non-JSON: {!r}".format(response.text[:300]))
    suffix = ".{}".format(message)
    if prop:
        infos = body.get("{}@Message.ExtendedInfo".format(prop), [])
    else:
        infos = list(body.get("error", {}).get("@Message.ExtendedInfo", []))
        for key, value in body.items():
            if key.endswith("@Message.ExtendedInfo") and isinstance(value, list):
                infos.extend(value)
    matched = [i for i in infos if i.get("MessageId", "").endswith(suffix)]
    pytest_assert(
        matched,
        "No ExtendedInfo entry with MessageId ending {!r} in: {!r}".format(suffix, body)
    )
    if message_args is not None:
        pytest_assert(
            any(i.get("MessageArgs") == message_args for i in matched),
            "MessageArgs must be {!r}, got: {!r}".format(
                message_args, [i.get("MessageArgs") for i in matched])
        )
