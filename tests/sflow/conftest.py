"""
    Pytest configuration used by the sFlow tests.
"""
import json
import logging
import os

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGGER = logging.getLogger(__name__)

REST_PORT = int(os.getenv("SONIC_REST_PORT", "443"))
SFLOW_TABLE = "SYSTEM_SFLOW|default"
DROP_LIMIT_FIELD = "drop_monitor_limit"


class RestconfClient:
    """ wrapper returning the raw requests.Response."""

    def __init__(self, host, port=REST_PORT, cert=None, auth=None, verify=False):
        self.base_url = f"https://{host}:{port}"
        self.cert = cert        # (client_cert_path, client_key_path) for mTLS
        self.auth = auth        # (user, password) for basic auth
        self.verify = verify
        self.headers = {
            "Content-Type": "application/yang-data+json",
            "Accept": "application/yang-data+json",
        }

    def _request(self, method, path, payload=None):
        url = self.base_url + path
        data = json.dumps(payload) if payload is not None else None
        LOGGER.info("RESTCONF %s %s payload=%s", method, url, data)
        resp = requests.request(
            method, url,
            headers=self.headers,
            data=data,
            cert=self.cert,
            auth=self.auth,
            verify=self.verify,
            timeout=30,
        )
        LOGGER.info("RESTCONF <- %s %s", resp.status_code, resp.text)
        return resp

    def get(self, path):
        return self._request("GET", path)

    def patch(self, path, payload):
        return self._request("PATCH", path, payload)

    def delete(self, path):
        return self._request("DELETE", path)


@pytest.fixture(scope="module")
def duthost(duthosts, rand_one_dut_hostname):
    """Single DUT under test (standard sonic-mgmt selection)."""
    return duthosts[rand_one_dut_hostname]


@pytest.fixture(scope="module")
def rest_client(duthost, creds):
    """
    RESTCONF client bound to the DUT management IP.

    Defaults to basic auth using the standard testbed creds.
    """
    client = RestconfClient(
        duthost.mgmt_ip,
        auth=(creds["sonicadmin_user"], creds["sonicadmin_password"]),
    )
    return client


@pytest.fixture(autouse=True)
def preserve_sflow_drop_limit(duthost):
    """
    Restores via a direct CONFIG_DB write (which notifies subscribers). If you
    prefer a stronger guarantee, replace the teardown body with config_reload:
        from tests.common.config_reload import config_reload
        config_reload(duthost, wait=120)
    """
    orig = duthost.shell(
        f"redis-cli -n 4 hget '{SFLOW_TABLE}' {DROP_LIMIT_FIELD}",
        module_ignore_errors=True,
    )["stdout"].strip()
    LOGGER.info("Snapshot %s = %r", DROP_LIMIT_FIELD, orig or "<absent>")

    yield

    if orig:
        duthost.shell(f"redis-cli -n 4 hset '{SFLOW_TABLE}' {DROP_LIMIT_FIELD} {orig}")
    else:
        duthost.shell(
            f"redis-cli -n 4 hdel '{SFLOW_TABLE}' {DROP_LIMIT_FIELD}",
            module_ignore_errors=True,
        )
    LOGGER.info("Restored %s to %r", DROP_LIMIT_FIELD, orig or "<absent>")
