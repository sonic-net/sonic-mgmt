"""
Tests for Redfish Chassis and Systems inventory endpoints.

Section 2: Chassis Inventory (Test Cases #4, #5, #6)
Section 3: Systems Inventory (Test Cases #7, #8)
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

CHASSIS_COLLECTION_PATH = "/redfish/v1/Chassis"
CHASSIS_PATH = "/redfish/v1/Chassis/chassis"
SYSTEMS_COLLECTION_PATH = "/redfish/v1/Systems"
SYSTEM_PATH = "/redfish/v1/Systems/system"

VALID_POWER_STATES = {"On", "Off", "PoweringOn", "PoweringOff"}


class TestRedfishChassis:

    def test_chassis_collection(self, redfish_client):
        """
        Test Case #4 — Chassis collection is accessible.

        GET /redfish/v1/Chassis must return HTTP 200 with at least one member.
        """
        response = redfish_client.get(CHASSIS_COLLECTION_PATH)
        logger.info("GET {} -> {}".format(CHASSIS_COLLECTION_PATH, response.status_code))

        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 from {}, got: {}".format(CHASSIS_COLLECTION_PATH,
                                                        response.status_code)
        )

        body = response.json()
        count = body.get("Members@odata.count", 0)
        pytest_assert(
            count >= 1,
            "Members@odata.count must be >= 1, got: {}".format(count)
        )

        members = body.get("Members", [])
        pytest_assert(
            len(members) >= 1,
            "Members array must have at least one entry, got: {}".format(members)
        )
        pytest_assert(
            "@odata.id" in members[0],
            "Members[0] must contain '@odata.id', got: {}".format(members[0])
        )

    def test_chassis_identity(self, redfish_client):
        """
        Test Case #5 — Chassis identity fields are populated.

        GET /redfish/v1/Chassis/chassis and validate identity fields.
        """
        response = redfish_client.get(CHASSIS_PATH)
        logger.info("GET {} -> {}".format(CHASSIS_PATH, response.status_code))

        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 from {}, got: {}".format(CHASSIS_PATH, response.status_code)
        )

        body = response.json()
        identity_fields = ["SerialNumber", "Manufacturer", "Model", "PartNumber"]
        for field in identity_fields:
            value = body.get(field, "")
            pytest_assert(
                isinstance(value, str) and len(value) > 0,
                "Field '{}' must be a non-empty string, got: {!r}".format(field, value)
            )
            logger.info("Chassis {}: {}".format(field, value))

    def test_chassis_dbus_consistency(self, redfish_client, bmc_duthost):
        """
        Test Case #6 — Chassis D-Bus objects match Redfish output.

        Cross-validates SerialNumber, Manufacturer, Model, PartNumber between D-Bus and Redfish.
        """
        chassis_dbus_path = "/xyz/openbmc_project/inventory/system/chassis"
        asset_iface = "xyz.openbmc_project.Inventory.Decorator.Asset"
        dbus_fields = {
            "SerialNumber": "SerialNumber",
            "Manufacturer": "Manufacturer",
            "Model": "Model",
            "PartNumber": "PartNumber",
        }

        # Get Redfish data
        response = redfish_client.get(CHASSIS_PATH)
        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 from {}, got: {}".format(CHASSIS_PATH, response.status_code)
        )
        redfish_body = response.json()

        # Cross-validate each field via D-Bus
        for dbus_prop, redfish_field in dbus_fields.items():
            cmd = ("busctl get-property xyz.openbmc_project.Inventory "
                   "{} {} {}".format(chassis_dbus_path, asset_iface, dbus_prop))
            result = bmc_duthost.command(cmd, module_ignore_errors=True)
            if result["rc"] != 0:
                logger.warning("D-Bus query failed for {}: {}".format(dbus_prop, result["stderr"]))
                continue

            # busctl output format: 's "value"' — strip type prefix and quotes
            raw = result["stdout"].strip()
            dbus_value = raw.split(" ", 1)[-1].strip('"') if " " in raw else raw.strip('"')
            redfish_value = redfish_body.get(redfish_field, "")

            pytest_assert(
                dbus_value == redfish_value,
                "D-Bus {} ({!r}) does not match Redfish {} ({!r})".format(
                    dbus_prop, dbus_value, redfish_field, redfish_value)
            )
            logger.info("D-Bus/Redfish {} match: {!r}".format(dbus_prop, dbus_value))


class TestRedfishSystems:

    def test_systems_collection(self, redfish_client):
        """
        Test Case #7 — Systems collection is accessible.

        GET /redfish/v1/Systems must return HTTP 200 with at least one member.
        """
        response = redfish_client.get(SYSTEMS_COLLECTION_PATH)
        logger.info("GET {} -> {}".format(SYSTEMS_COLLECTION_PATH, response.status_code))

        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 from {}, got: {}".format(SYSTEMS_COLLECTION_PATH,
                                                        response.status_code)
        )

        body = response.json()
        count = body.get("Members@odata.count", 0)
        pytest_assert(
            count >= 1,
            "Members@odata.count must be >= 1, got: {}".format(count)
        )

    def test_system_identity(self, redfish_client):
        """
        Test Case #8 — System identity and power state.

        GET /redfish/v1/Systems/system and validate PowerState and @odata.type.
        """
        response = redfish_client.get(SYSTEM_PATH)
        logger.info("GET {} -> {}".format(SYSTEM_PATH, response.status_code))

        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 from {}, got: {}".format(SYSTEM_PATH, response.status_code)
        )

        body = response.json()

        power_state = body.get("PowerState", "")
        pytest_assert(
            power_state in VALID_POWER_STATES,
            "PowerState must be one of {}, got: {!r}".format(VALID_POWER_STATES, power_state)
        )
        logger.info("System PowerState: {}".format(power_state))

        odata_type = body.get("@odata.type", "")
        pytest_assert(
            "ComputerSystem" in odata_type,
            "@odata.type must contain 'ComputerSystem', got: {!r}".format(odata_type)
        )
