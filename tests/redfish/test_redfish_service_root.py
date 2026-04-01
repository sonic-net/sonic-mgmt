"""
Test for Redfish Service Root endpoint: GET /redfish/v1

Validates that the BMC Redfish service root returns a well-formed response
as defined by the DMTF Redfish specification.
"""
import logging
import pytest
import requests
import urllib3

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('bmc-dual-mgmt', 'bmc-shared-mgmt'),
]

# Required fields per DMTF Redfish spec
REQUIRED_FIELDS = ["@odata.type", "@odata.id", "RedfishVersion", "UUID", "Links"]


class TestRedfishServiceRoot:

    def test_service_root(self, bmc_ip, bmc_creds):
        """
        GET /redfish/v1 and validate the response.

        What this test does:
        1. Makes an HTTP GET request to https://<bmc_ip>/redfish/v1
           using Basic Auth (username/password from creds.yml).
           TLS verification is disabled (verify=False) because the BMC
           uses a self-signed certificate.

        2. Asserts HTTP 200 — the BMC is reachable and Redfish is running.

        3. Parses the response as JSON — confirms the body is not garbage.

        4. Checks all DMTF-required fields are present:
           @odata.type, @odata.id, RedfishVersion, UUID, Links.

        5. Checks RedfishVersion is a non-empty string (e.g. "1.17.0").

        6. Checks @odata.id equals "/redfish/v1" — the resource correctly
           identifies itself.

        7. Checks Links.Sessions exists — tells clients where to authenticate.
        """
        url = "https://{}/redfish/v1".format(bmc_ip)
        logger.info("GET {}".format(url))

        response = requests.get(
            url,
            auth=(bmc_creds["user"], bmc_creds["password"]),
            verify=False,
            timeout=30,
        )

        logger.info("HTTP status: {}".format(response.status_code))
        logger.info("Response body: {}".format(response.text))

        # 1. Must return HTTP 200
        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 from /redfish/v1, got: {}".format(response.status_code)
        )

        # 2. Body must be valid JSON
        try:
            body = response.json()
        except ValueError:
            pytest_assert(False, "Response body is not valid JSON: {}".format(response.text))

        # 3. All DMTF-required fields must be present
        for field in REQUIRED_FIELDS:
            pytest_assert(
                field in body,
                "Required field '{}' missing from /redfish/v1 response".format(field)
            )

        # 4. RedfishVersion must be a non-empty string
        version = body.get("RedfishVersion", "")
        pytest_assert(
            isinstance(version, str) and len(version) > 0,
            "RedfishVersion must be a non-empty string, got: {!r}".format(version)
        )
        logger.info("BMC RedfishVersion: {}".format(version))

        # 5. @odata.id must equal /redfish/v1
        odata_id = body.get("@odata.id", "")
        pytest_assert(
            odata_id.rstrip("/") == "/redfish/v1",
            "@odata.id must be '/redfish/v1', got: {!r}".format(odata_id)
        )

        # 6. Links.Sessions must exist
        links = body.get("Links", {})
        pytest_assert(
            "Sessions" in links,
            "Links.Sessions is missing from /redfish/v1 response"
        )
