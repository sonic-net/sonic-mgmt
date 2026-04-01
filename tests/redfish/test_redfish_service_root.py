"""
Test for Redfish Service Root endpoint: GET /redfish/v1

Section 1: Service Root Discovery (Test Cases #1, #2, #3)
Validates that the BMC Redfish service root returns a well-formed response
as defined by the DMTF Redfish specification.
"""
import logging
import pytest
import urllib3

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('bmc-dual-mgmt', 'bmc-shared-mgmt'),
]

REQUIRED_FIELDS = ["@odata.type", "@odata.id", "RedfishVersion", "UUID", "Links"]


class TestRedfishServiceRoot:

    def test_service_root_accessible(self, redfish_client):
        """
        Test Case #1 — Service root is accessible.

        GET /redfish/v1, validate HTTP 200 and Content-Type is application/json.
        """
        response = redfish_client.get("/redfish/v1")
        logger.info("HTTP status: {}".format(response.status_code))

        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 from /redfish/v1, got: {}".format(response.status_code)
        )
        content_type = response.headers.get("Content-Type", "")
        pytest_assert(
            "application/json" in content_type,
            "Expected Content-Type to contain 'application/json', got: {!r}".format(content_type)
        )

    def test_service_root_fields(self, redfish_client):
        """
        Test Case #2 — Service root contains required fields.

        Validates DMTF-required fields and SONiC-specific navigation links.
        """
        response = redfish_client.get("/redfish/v1")
        pytest_assert(response.status_code == 200,
                      "Expected HTTP 200 from /redfish/v1, got: {}".format(response.status_code))

        try:
            body = response.json()
        except ValueError:
            pytest_assert(False, "Response body is not valid JSON: {}".format(response.text))

        # All DMTF-required fields must be present
        for field in REQUIRED_FIELDS:
            pytest_assert(
                field in body,
                "Required field '{}' missing from /redfish/v1 response".format(field)
            )

        # @odata.id must equal /redfish/v1
        odata_id = body.get("@odata.id", "")
        pytest_assert(
            odata_id.rstrip("/") == "/redfish/v1",
            "@odata.id must be '/redfish/v1', got: {!r}".format(odata_id)
        )

        # @odata.type must contain ServiceRoot
        odata_type = body.get("@odata.type", "")
        pytest_assert(
            "ServiceRoot" in odata_type,
            "@odata.type must contain 'ServiceRoot', got: {!r}".format(odata_type)
        )

        # RedfishVersion must be a non-empty string
        version = body.get("RedfishVersion", "")
        pytest_assert(
            isinstance(version, str) and len(version) > 0,
            "RedfishVersion must be a non-empty string, got: {!r}".format(version)
        )
        logger.info("BMC RedfishVersion: {}".format(version))

        # UUID must be a non-empty string
        uuid = body.get("UUID", "")
        pytest_assert(
            isinstance(uuid, str) and len(uuid) > 0,
            "UUID must be a non-empty string, got: {!r}".format(uuid)
        )

        # Product must equal SONiCBMC
        product = body.get("Product", "")
        pytest_assert(
            product == "SONiCBMC",
            "Product must be 'SONiCBMC', got: {!r}".format(product)
        )

        # Navigation links: Chassis and Systems
        chassis_link = body.get("Chassis", {}).get("@odata.id", "")
        pytest_assert(
            chassis_link == "/redfish/v1/Chassis",
            "Chassis.@odata.id must be '/redfish/v1/Chassis', got: {!r}".format(chassis_link)
        )

        systems_link = body.get("Systems", {}).get("@odata.id", "")
        pytest_assert(
            systems_link == "/redfish/v1/Systems",
            "Systems.@odata.id must be '/redfish/v1/Systems', got: {!r}".format(systems_link)
        )

        # Links.Sessions must exist
        links = body.get("Links", {})
        pytest_assert(
            "Sessions" in links,
            "Links.Sessions is missing from /redfish/v1 response"
        )

    def test_service_root_no_auth(self, redfish_client):
        """
        Test Case #3 — Unauthenticated access is not rejected.

        GET /redfish/v1 without credentials must still return HTTP 200.
        The service root is a public discovery endpoint per the Redfish spec.
        """
        response = redfish_client.get("/redfish/v1", auth=False)
        logger.info("HTTP status (no auth): {}".format(response.status_code))

        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 from unauthenticated /redfish/v1, got: {}".format(
                response.status_code)
        )
        content_type = response.headers.get("Content-Type", "")
        pytest_assert(
            "application/json" in content_type,
            "Expected Content-Type to contain 'application/json', got: {!r}".format(content_type)
        )
