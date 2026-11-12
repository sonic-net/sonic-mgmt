# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Nexthop AI
# Copyright (C) 2026 SONiC Project
# Author: Chinmoy Dey <chinmoy@nexthop.ai>
"""
Tests for the Redfish Chassis resource and the leak detection tree beneath it.

    GET /redfish/v1/Chassis
    GET /redfish/v1/Chassis/chassis
    GET /redfish/v1/Chassis/chassis/ThermalSubsystem
    GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection
    GET /redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors
    GET /redfish/v1/Chassis/chassis/LeakDetectors

On the SONiC BMC the single Chassis is the switch, built by bmcweb from the
/xyz/openbmc_project/inventory/system/chassis object sonic-dbus-bridge
exports. Its identity comes from CONFIG_DB DEVICE_METADATA|localhost first
and the FRU EEPROM second, so the Redfish fields are checked against CONFIG_DB
wherever it provides them.

Leak detectors (pmon-bmc-design.md section 2.1.2 item 6) hang off the chassis
at the DMTF canonical Chassis/<id>/LeakDetectors collection and at the
deprecated ThermalSubsystem/LeakDetection/LeakDetectors one, which is the form
the leak events name as OriginOfCondition. Both are served from the same D-Bus
objects and must list the same detectors, each in its own URI form. The tests
work with whatever detectors the platform exposes; a detector's own resource
is covered with a known sensor in test_redfish_event_subscription.py.
"""
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hgetall
from tests.redfish.redfish_utils import (
    assert_field_contains,
    assert_field_equals,
    assert_field_nonempty,
    assert_member_count,
    assert_redfish_error,
    assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

CHASSIS_COLLECTION_PATH = "/redfish/v1/Chassis"
CHASSIS_ID = "chassis"
UNKNOWN_CHASSIS_ID = "nochassis"
UNKNOWN_DETECTOR_ID = "DoesNotExist"

CANONICAL_LEAK_DETECTORS_TEMPLATE = "/redfish/v1/Chassis/{}/LeakDetectors"
LEAK_DETECTION_TEMPLATE = "/redfish/v1/Chassis/{}/ThermalSubsystem/LeakDetection"
DEPRECATED_LEAK_DETECTORS_TEMPLATE = LEAK_DETECTION_TEMPLATE + "/LeakDetectors"

CHASSIS_PATH = "{}/{}".format(CHASSIS_COLLECTION_PATH, CHASSIS_ID)
THERMAL_SUBSYSTEM_PATH = "{}/ThermalSubsystem".format(CHASSIS_PATH)
LEAK_DETECTION_PATH = LEAK_DETECTION_TEMPLATE.format(CHASSIS_ID)
CANONICAL_LEAK_DETECTORS_PATH = CANONICAL_LEAK_DETECTORS_TEMPLATE.format(CHASSIS_ID)
DEPRECATED_LEAK_DETECTORS_PATH = DEPRECATED_LEAK_DETECTORS_TEMPLATE.format(CHASSIS_ID)
LEAK_DETECTOR_COLLECTIONS = [CANONICAL_LEAK_DETECTORS_PATH, DEPRECATED_LEAK_DETECTORS_PATH]

DEVICE_METADATA_KEY = "DEVICE_METADATA|localhost"
# Redfish identity field -> DEVICE_METADATA fields sonic-dbus-bridge reads for it, in precedence order.
IDENTITY_SOURCES = {
    "SerialNumber": ["serial_number"],
    "Manufacturer": ["manufacturer"],
    "Model": ["model", "platform"],
    "PartNumber": ["part_number"],
}

# Paths on the leak detection tree with an id bmcweb cannot resolve, and the
# ResourceNotFound MessageArgs each must answer with.
UNKNOWN_ID_CASES = {
    "unknown_chassis_canonical_collection": (
        CANONICAL_LEAK_DETECTORS_TEMPLATE.format(UNKNOWN_CHASSIS_ID), ["Chassis", UNKNOWN_CHASSIS_ID]),
    "unknown_chassis_deprecated_collection": (
        DEPRECATED_LEAK_DETECTORS_TEMPLATE.format(UNKNOWN_CHASSIS_ID), ["Chassis", UNKNOWN_CHASSIS_ID]),
    "unknown_chassis_leak_detection": (
        LEAK_DETECTION_TEMPLATE.format(UNKNOWN_CHASSIS_ID), ["Chassis", UNKNOWN_CHASSIS_ID]),
    "unknown_detector_canonical": (
        "{}/{}".format(CANONICAL_LEAK_DETECTORS_PATH, UNKNOWN_DETECTOR_ID), ["LeakDetector", UNKNOWN_DETECTOR_ID]),
    "unknown_detector_deprecated": (
        "{}/{}".format(DEPRECATED_LEAK_DETECTORS_PATH, UNKNOWN_DETECTOR_ID), ["LeakDetector", UNKNOWN_DETECTOR_ID]),
}


def _link(body, field):
    return body.get(field, {}).get("@odata.id")


def _assert_link(body, path, field, expected):
    pytest_assert(
        _link(body, field) == expected,
        "{} {}.@odata.id must be {!r}, got: {!r}".format(path, field, expected, _link(body, field))
    )


class TestRedfishChassis:

    def test_chassis_collection_lists_chassis(self, redfish_client):
        """
        The Chassis collection lists the switch as /redfish/v1/Chassis/chassis.

        That is the chassis the leak events name in OriginOfCondition, so a
        rack manager must reach it from the collection.
        """
        response = redfish_client.get(CHASSIS_COLLECTION_PATH)
        assert_status_ok(response, CHASSIS_COLLECTION_PATH)
        body = response.json()
        assert_field_equals(body, "@odata.id", CHASSIS_COLLECTION_PATH)
        assert_field_contains(body, "@odata.type", "ChassisCollection")
        assert_member_count(body)
        members = [m.get("@odata.id") for m in body.get("Members", [])]
        pytest_assert(
            CHASSIS_PATH in members,
            "{} must list {}, got: {}".format(CHASSIS_COLLECTION_PATH, CHASSIS_PATH, members)
        )
        logger.info("Verified %s lists %s", CHASSIS_COLLECTION_PATH, members)

    def test_chassis_identity_matches_config_db(self, redfish_client, bmc_duthost):
        """
        Chassis identity fields are populated and agree with CONFIG_DB.

        sonic-dbus-bridge takes SerialNumber, Manufacturer, Model and
        PartNumber from DEVICE_METADATA|localhost when the field is there
        (Model falls back to platform) and from the FRU EEPROM or platform
        data otherwise, so each Redfish field must equal the CONFIG_DB value
        where one exists and be a non-empty string regardless.
        """
        response = redfish_client.get(CHASSIS_PATH)
        assert_status_ok(response, CHASSIS_PATH)
        body = response.json()
        assert_field_equals(body, "@odata.id", CHASSIS_PATH)
        assert_field_equals(body, "Id", CHASSIS_ID)
        assert_field_contains(body, "@odata.type", "#Chassis.")
        assert_field_nonempty(body, "ChassisType")

        metadata = redis_hgetall(bmc_duthost, CONFIG_DB, DEVICE_METADATA_KEY)
        for field, sources in IDENTITY_SOURCES.items():
            assert_field_nonempty(body, field)
            source = next((s for s in sources if metadata.get(s)), None)
            if source is None:
                logger.info("%s=%r (no %s source in %s, served from the FRU EEPROM or platform data)",
                            field, body[field], "/".join(sources), DEVICE_METADATA_KEY)
                continue
            pytest_assert(
                body[field] == metadata[source],
                "{} must equal {} {}={!r}, got: {!r}".format(field, DEVICE_METADATA_KEY, source,
                                                             metadata[source], body[field])
            )
            logger.info("%s=%r matches %s %s", field, body[field], DEVICE_METADATA_KEY, source)
        logger.info("Verified %s identity: ChassisType=%s", CHASSIS_PATH, body["ChassisType"])

    def test_chassis_links_leak_detection(self, redfish_client):
        """
        The chassis advertises both ways into its leak detectors.

        Chassis.LeakDetectors must point at the canonical Chassis/<id>/LeakDetectors
        collection (Chassis schema v1.26.0) and Chassis.ThermalSubsystem at a
        ThermalSubsystem that links the LeakDetection resource, so a rack
        manager reaches the detectors by navigation down either tree.
        """
        response = redfish_client.get(CHASSIS_PATH)
        assert_status_ok(response, CHASSIS_PATH)
        body = response.json()
        _assert_link(body, CHASSIS_PATH, "LeakDetectors", CANONICAL_LEAK_DETECTORS_PATH)
        _assert_link(body, CHASSIS_PATH, "ThermalSubsystem", THERMAL_SUBSYSTEM_PATH)

        response = redfish_client.get(THERMAL_SUBSYSTEM_PATH)
        assert_status_ok(response, THERMAL_SUBSYSTEM_PATH)
        _assert_link(response.json(), THERMAL_SUBSYSTEM_PATH, "LeakDetection", LEAK_DETECTION_PATH)
        logger.info("Verified %s links %s and, through %s, %s", CHASSIS_PATH, CANONICAL_LEAK_DETECTORS_PATH,
                    THERMAL_SUBSYSTEM_PATH, LEAK_DETECTION_PATH)

    def test_leak_detection_resource(self, redfish_client):
        """
        ThermalSubsystem/LeakDetection groups the detectors and reports an aggregate Status.

        It must identify itself as LeakDetection, link the deprecated
        LeakDetectors collection beneath it and read Enabled and OK.
        """
        response = redfish_client.get(LEAK_DETECTION_PATH)
        assert_status_ok(response, LEAK_DETECTION_PATH)
        body = response.json()
        assert_field_equals(body, "@odata.id", LEAK_DETECTION_PATH)
        assert_field_contains(body, "@odata.type", "#LeakDetection.")
        assert_field_equals(body, "Id", "LeakDetection")
        assert_field_equals(body, "Name", "Leak Detection")
        _assert_link(body, LEAK_DETECTION_PATH, "LeakDetectors", DEPRECATED_LEAK_DETECTORS_PATH)
        status = body.get("Status", {})
        pytest_assert(
            status.get("State") == "Enabled" and status.get("Health") == "OK",
            "{} Status must be Enabled/OK, got: {!r}".format(LEAK_DETECTION_PATH, status)
        )
        logger.info("Verified %s: %s", LEAK_DETECTION_PATH, body)

    def test_leak_detector_collections_serve_same_detectors(self, redfish_client):
        """
        Both LeakDetectors collection forms list the platform's detectors, each in its own URI form.

        The canonical and the deprecated collection are built from the same
        D-Bus objects: each must answer with a LeakDetectorCollection whose
        @odata.id is the URI it was asked for, whose members live under that
        URI and whose count matches, and the two must name the same detectors.
        """
        detector_ids = {}
        for collection in LEAK_DETECTOR_COLLECTIONS:
            response = redfish_client.get(collection)
            assert_status_ok(response, collection)
            body = response.json()
            assert_field_equals(body, "@odata.id", collection)
            assert_field_contains(body, "@odata.type", "LeakDetectorCollection")
            assert_field_equals(body, "Name", "Leak Detector Collection")
            members = [m.get("@odata.id", "") for m in body.get("Members", [])]
            pytest_assert(
                body.get("Members@odata.count") == len(members),
                "{} Members@odata.count must be {}, got: {!r}".format(
                    collection, len(members), body.get("Members@odata.count"))
            )
            misplaced = [m for m in members if not m.startswith(collection + "/")]
            pytest_assert(not misplaced, "{} members must live under it, got: {}".format(collection, misplaced))
            detector_ids[collection] = sorted(m.rsplit("/", 1)[1] for m in members)
            logger.info("%s lists %d detector(s): %s", collection, len(members), members)

        pytest_assert(
            detector_ids[CANONICAL_LEAK_DETECTORS_PATH] == detector_ids[DEPRECATED_LEAK_DETECTORS_PATH],
            "The two LeakDetectors collections must list the same detectors, got: {}".format(detector_ids)
        )
        logger.info("Verified both LeakDetectors collections serve %s", detector_ids[CANONICAL_LEAK_DETECTORS_PATH])

    @pytest.mark.parametrize("case", list(UNKNOWN_ID_CASES))
    def test_leak_detection_unknown_ids_rejected(self, redfish_client, case):
        """
        An unknown chassis or detector id on the leak detection tree answers 404 ResourceNotFound.

        The error must name the segment that failed to resolve (Chassis or
        LeakDetector) and the id that was asked for, on both URI forms.
        """
        path, message_args = UNKNOWN_ID_CASES[case]
        response = redfish_client.get(path)
        logger.info("[{}] GET {} -> {} {!r}".format(case, path, response.status_code, response.text[:300]))
        assert_redfish_error(response, 404, "ResourceNotFound", message_args=message_args)
        logger.info("[%s] Verified 404 ResourceNotFound %s", case, message_args)
