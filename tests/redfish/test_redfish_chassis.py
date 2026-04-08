"""
Tests for Redfish Chassis and Systems inventory endpoints.

Section 2: Chassis Inventory (Test Cases #4, #5, #6)
Section 3: Systems Inventory (Test Cases #7, #8)
"""
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.redfish.redfish_utils import (
    assert_field_contains, assert_field_in, assert_field_nonempty,
    assert_member_count, assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('bmc-dual-mgmt', 'bmc-shared-mgmt'),
]

CHASSIS_COLLECTION_PATH = "/redfish/v1/Chassis"
CHASSIS_PATH = "/redfish/v1/Chassis/chassis"
SYSTEMS_COLLECTION_PATH = "/redfish/v1/Systems"
SYSTEM_PATH = "/redfish/v1/Systems/system"

VALID_POWER_STATES = {"On", "Off", "PoweringOn", "PoweringOff"}
CHASSIS_IDENTITY_FIELDS = ["SerialNumber", "Manufacturer", "Model", "PartNumber"]


class TestRedfishChassis:

    def test_chassis_collection(self, redfish_client):
        """
        Test Case #4 — Chassis collection is accessible.

        GET /redfish/v1/Chassis must return HTTP 200 with at least one member.
        """
        response = redfish_client.get(CHASSIS_COLLECTION_PATH)
        logger.info("GET {} -> {}".format(CHASSIS_COLLECTION_PATH, response.status_code))

        assert_status_ok(response, CHASSIS_COLLECTION_PATH)

        body = response.json()
        assert_member_count(body)

        members = body.get("Members", [])
        pytest_assert(
            len(members) >= 1 and "@odata.id" in members[0],
            "Members must have at least one entry with '@odata.id', got: {}".format(members)
        )

    def test_chassis_identity(self, redfish_client):
        """
        Test Case #5 — Chassis identity fields are populated.

        GET /redfish/v1/Chassis/chassis and validate identity fields.
        """
        response = redfish_client.get(CHASSIS_PATH)
        logger.info("GET {} -> {}".format(CHASSIS_PATH, response.status_code))

        assert_status_ok(response, CHASSIS_PATH)

        body = response.json()
        for field in CHASSIS_IDENTITY_FIELDS:
            assert_field_nonempty(body, field)
            logger.info("Chassis {}: {}".format(field, body.get(field)))

    def test_chassis_dbus_consistency(self, redfish_client, bmc_duthost):
        """
        Test Case #6 — Chassis D-Bus objects match Redfish output.

        Cross-validates SerialNumber, Manufacturer, Model, PartNumber between D-Bus and Redfish.
        """
        chassis_dbus_path = "/xyz/openbmc_project/inventory/system/chassis"
        asset_iface = "xyz.openbmc_project.Inventory.Decorator.Asset"

        response = redfish_client.get(CHASSIS_PATH)
        assert_status_ok(response, CHASSIS_PATH)
        redfish_body = response.json()

        for field in CHASSIS_IDENTITY_FIELDS:
            cmd = ("busctl get-property xyz.openbmc_project.Inventory "
                   "{} {} {}".format(chassis_dbus_path, asset_iface, field))
            result = bmc_duthost.command(cmd, module_ignore_errors=True)
            if result["rc"] != 0:
                logger.warning("D-Bus query failed for {}: {}".format(field, result["stderr"]))
                continue

            # busctl output format: 's "value"' — strip type prefix and quotes
            raw = result["stdout"].strip()
            dbus_value = raw.split(" ", 1)[-1].strip('"') if " " in raw else raw.strip('"')
            redfish_value = redfish_body.get(field, "")

            pytest_assert(
                dbus_value == redfish_value,
                "D-Bus {} ({!r}) does not match Redfish ({!r})".format(
                    field, dbus_value, redfish_value)
            )
            logger.info("D-Bus/Redfish {} match: {!r}".format(field, dbus_value))


class TestRedfishSystems:

    def test_systems_collection(self, redfish_client):
        """
        Test Case #7 — Systems collection is accessible.

        GET /redfish/v1/Systems must return HTTP 200 with at least one member.
        """
        response = redfish_client.get(SYSTEMS_COLLECTION_PATH)
        logger.info("GET {} -> {}".format(SYSTEMS_COLLECTION_PATH, response.status_code))

        assert_status_ok(response, SYSTEMS_COLLECTION_PATH)
        assert_member_count(response.json())

    def test_system_identity(self, redfish_client):
        """
        Test Case #8 — System identity and power state.

        GET /redfish/v1/Systems/system and validate PowerState and @odata.type.
        """
        response = redfish_client.get(SYSTEM_PATH)
        logger.info("GET {} -> {}".format(SYSTEM_PATH, response.status_code))

        assert_status_ok(response, SYSTEM_PATH)

        body = response.json()
        assert_field_in(body, "PowerState", VALID_POWER_STATES)
        assert_field_contains(body, "@odata.type", "ComputerSystem")
        logger.info("System PowerState: {}".format(body.get("PowerState")))
