"""
Shared Redfish test utilities for SONiC BMC Redfish API tests.
"""
import requests
import urllib3

from tests.common.helpers.assertions import pytest_assert

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RedfishClient:
    """HTTP client for Redfish API calls with Basic Auth and TLS verification disabled."""

    def __init__(self, bmc_ip, user, password, timeout=30):
        self.base_url = "https://{}".format(bmc_ip)
        self.auth = (user, password)
        self.timeout = timeout

    def get(self, path, auth=True, **kwargs):
        url = self.base_url + path
        auth_arg = self.auth if auth else None
        return requests.get(url, auth=auth_arg, verify=False, timeout=self.timeout, **kwargs)

    def post(self, path, json=None, **kwargs):
        url = self.base_url + path
        return requests.post(url, auth=self.auth, verify=False, timeout=self.timeout,
                             json=json, **kwargs)

    def delete(self, path, **kwargs):
        url = self.base_url + path
        return requests.delete(url, auth=self.auth, verify=False, timeout=self.timeout, **kwargs)


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
