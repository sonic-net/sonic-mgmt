"""
Test for Redfish Service Root endpoint: GET /redfish/v1

Section 1: Service Root Discovery (Test Cases #1, #2, #3)
Validates that the BMC Redfish service root returns a well-formed response
as defined by the DMTF Redfish specification.
"""
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.redfish.redfish_utils import (
    assert_field_equals, assert_field_contains, assert_field_nonempty, assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('bmc-dual-mgmt', 'bmc-shared-mgmt'),
]

REQUIRED_FIELDS = ["@odata.type", "@odata.id", "RedfishVersion", "UUID", "Links"]
SERVICE_ROOT = "/redfish/v1"


class TestRedfishServiceRoot:

    def test_service_root_accessible(self, redfish_client):
        """
        Test Case #1 — Service root is accessible.

        GET /redfish/v1, validate HTTP 200 and Content-Type is application/json.
        """
        response = redfish_client.get(SERVICE_ROOT)
        logger.info("HTTP status: {}".format(response.status_code))

        assert_status_ok(response, SERVICE_ROOT)
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
        response = redfish_client.get(SERVICE_ROOT)
        assert_status_ok(response, SERVICE_ROOT)

        body = response.json()

        for field in REQUIRED_FIELDS:
            pytest_assert(
                field in body,
                "Required field '{}' missing from {} response".format(field, SERVICE_ROOT)
            )

        assert_field_equals(body, "@odata.id", SERVICE_ROOT)
        assert_field_contains(body, "@odata.type", "ServiceRoot")
        assert_field_nonempty(body, "RedfishVersion")
        assert_field_nonempty(body, "UUID")
        assert_field_equals(body, "Product", "SONiCBMC")

        # Navigation links
        update_service_link = body.get("UpdateService", {}).get("@odata.id", "")
        pytest_assert(
            update_service_link == "/redfish/v1/UpdateService",
            "UpdateService.@odata.id must be '/redfish/v1/UpdateService', got: {!r}".format(
                update_service_link)
        )

        systems_link = body.get("Systems", {}).get("@odata.id", "")
        pytest_assert(
            systems_link == "/redfish/v1/Systems",
            "Systems.@odata.id must be '/redfish/v1/Systems', got: {!r}".format(systems_link)
        )

        links = body.get("Links", {})
        pytest_assert("Sessions" in links, "Links.Sessions is missing from {} response".format(SERVICE_ROOT))
