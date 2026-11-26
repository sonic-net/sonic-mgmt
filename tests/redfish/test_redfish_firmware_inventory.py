"""
Tests for Redfish Firmware Inventory endpoints.
"""
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.redfish.redfish_utils import (
    assert_field_contains, assert_field_equals, assert_field_nonempty,
    assert_member_count, assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

FIRMWARE_COLLECTION_PATH = "/redfish/v1/UpdateService/FirmwareInventory"
BMC_FIRMWARE_PATH = "{}/bmc".format(FIRMWARE_COLLECTION_PATH)
BIOS_FIRMWARE_PATH = "{}/bios".format(FIRMWARE_COLLECTION_PATH)
SWITCH_FIRMWARE_PATH = "{}/switch".format(FIRMWARE_COLLECTION_PATH)

EXPECTED_MEMBERS = {"bmc", "bios", "switch"}


def _assert_software_inventory_shape(body, component_id):
    """Schema invariants shared by every SoftwareInventory entry."""
    assert_field_equals(body, "Id", component_id)
    assert_field_contains(body, "@odata.type", "SoftwareInventory")
    assert_field_equals(body, "Name", "Software Inventory")

    status = body.get("Status", {})
    pytest_assert(
        status.get("State") == "Enabled",
        "Status.State must be 'Enabled', got: {!r}".format(status.get("State"))
    )
    pytest_assert(
        status.get("Health") == "OK",
        "Status.Health must be 'OK', got: {!r}".format(status.get("Health"))
    )
    pytest_assert(
        status.get("HealthRollup") == "OK",
        "Status.HealthRollup must be 'OK', got: {!r}".format(status.get("HealthRollup"))
    )

    pytest_assert(
        isinstance(body.get("Updateable"), bool),
        "Updateable must be a boolean, got: {!r}".format(body.get("Updateable"))
    )
    assert_field_nonempty(body, "Version")


class TestRedfishFirmwareInventory:

    def test_firmware_inventory_collection(self, redfish_client):
        """
        Firmware inventory collection.

        GET /redfish/v1/UpdateService/FirmwareInventory must return HTTP 200
        with at least one member and expected firmware components.
        """
        response = redfish_client.get(FIRMWARE_COLLECTION_PATH)
        logger.info("GET {} -> {}".format(FIRMWARE_COLLECTION_PATH, response.status_code))

        assert_status_ok(response, FIRMWARE_COLLECTION_PATH)

        body = response.json()
        assert_member_count(body)

        members = body.get("Members", [])
        member_ids = {m.get("@odata.id", "").split("/")[-1] for m in members}
        logger.info("Firmware members: {}".format(member_ids))

        missing = EXPECTED_MEMBERS - member_ids
        pytest_assert(
            not missing,
            "Expected firmware members {} not found in collection. Present: {}".format(
                missing, member_ids)
        )

    def test_firmware_bmc(self, redfish_client):
        """
        BMC firmware inventory entry.

        GET /redfish/v1/UpdateService/FirmwareInventory/bmc — validates the BMC
        SoftwareInventory entry has a real build version and links back to
        /redfish/v1/Managers/bmc via RelatedItem.
        """
        response = redfish_client.get(BMC_FIRMWARE_PATH)
        logger.info("GET {} -> {}".format(BMC_FIRMWARE_PATH, response.status_code))
        assert_status_ok(response, BMC_FIRMWARE_PATH)

        body = response.json()
        assert_field_equals(body, "@odata.id", BMC_FIRMWARE_PATH)
        _assert_software_inventory_shape(body, "bmc")
        assert_field_equals(body, "Description", "BMC image")

        # BMC must report a real build string, not the "N/A" placeholder.
        version = body.get("Version")
        pytest_assert(
            version != "N/A",
            "BMC Version must be a real build string, got: {!r}".format(version)
        )
        logger.info("BMC Version: {!r}".format(version))

        related_ids = [r.get("@odata.id") for r in body.get("RelatedItem", [])]
        pytest_assert(
            "/redfish/v1/Managers/bmc" in related_ids,
            "BMC RelatedItem must contain '/redfish/v1/Managers/bmc', got: {}".format(
                related_ids)
        )

    def test_firmware_bios(self, redfish_client):
        """
        BIOS firmware inventory entry.

        GET /redfish/v1/UpdateService/FirmwareInventory/bios — validates the BIOS
        SoftwareInventory entry. Version is currently "N/A" and there is no
        RelatedItem in this BMC build, so only schema shape is asserted.
        """
        response = redfish_client.get(BIOS_FIRMWARE_PATH)
        logger.info("GET {} -> {}".format(BIOS_FIRMWARE_PATH, response.status_code))
        assert_status_ok(response, BIOS_FIRMWARE_PATH)

        body = response.json()
        assert_field_equals(body, "@odata.id", BIOS_FIRMWARE_PATH)
        _assert_software_inventory_shape(body, "bios")
        assert_field_equals(body, "Description", "Other image")
        logger.info("BIOS Version: {!r}".format(body.get("Version")))

    def test_firmware_switch(self, redfish_client):
        """
        Switch (host) firmware inventory entry.

        GET /redfish/v1/UpdateService/FirmwareInventory/switch — validates the
        switch SoftwareInventory entry links back to /redfish/v1/Systems/system/Bios
        via RelatedItem.
        """
        response = redfish_client.get(SWITCH_FIRMWARE_PATH)
        logger.info("GET {} -> {}".format(SWITCH_FIRMWARE_PATH, response.status_code))
        assert_status_ok(response, SWITCH_FIRMWARE_PATH)

        body = response.json()
        assert_field_equals(body, "@odata.id", SWITCH_FIRMWARE_PATH)
        _assert_software_inventory_shape(body, "switch")
        assert_field_equals(body, "Description", "Host image")
        logger.info("Switch Version: {!r}".format(body.get("Version")))

        related_ids = [r.get("@odata.id") for r in body.get("RelatedItem", [])]
        pytest_assert(
            "/redfish/v1/Systems/system/Bios" in related_ids,
            "Switch RelatedItem must contain '/redfish/v1/Systems/system/Bios', got: {}".format(
                related_ids)
        )
