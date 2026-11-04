"""
Tests for the SONiC OEM Rack Manager telemetry action:

    POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitTelemetry

In production a rack manager pushes coolant telemetry (inlet liquid temperature,
flow rate, pressure, rack-level leak) into the switch BMC at a fixed cadence.
Here the sonic-mgmt container plays the rack manager over mTLS. The BMC path is

    bmcweb (auth, manager id, 64 KiB cap, JSON parse, "*Alarms*" envelope)
      -> D-Bus com.sonic.RackManager.SubmitTelemetry
      -> sonic-dbus-bridge (field-rule classification, worker thread)
      -> STATE_DB  RACK_MANAGER_DATA|<sensor>

Nothing on the BMC consumes RACK_MANAGER_DATA and no Redfish GET returns it, so
STATE_DB is the observable boundary: every test that expects persistence polls
the table on the BMC host and checks the record against the platform DB schema
(pmon-bmc-design.md, section 2.1.2.1). Telemetry does not drive bmcctld power
actions (only RACK_MANAGER_ALERT does), so these tests are safe on a live BMC.
"""
import json
import logging
import time
from datetime import datetime

import pytest
import requests

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.sonic_db import (
    STATE_DB,
    redis_del,
    redis_hgetall,
    redis_hset,
    redis_keys,
)
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    assert_field_equals,
    assert_field_nonempty,
    assert_no_content,
    assert_redfish_error,
    assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

MANAGER_PATH = "/redfish/v1/Managers/bmc"
RACK_MANAGER_PATH = "{}/Oem/SONiC/RackManager".format(MANAGER_PATH)
SUBMIT_TELEMETRY_ACTION = "#SONiC.SubmitTelemetry"
SUBMIT_ALERT_ACTION = "#SONiC.SubmitAlert"
SUBMIT_TELEMETRY_TARGET = "{}/Actions/SONiC.SubmitTelemetry".format(RACK_MANAGER_PATH)
SUBMIT_ALERT_TARGET = "{}/Actions/SONiC.SubmitAlert".format(RACK_MANAGER_PATH)
RACK_MANAGER_ODATA_TYPE = "#SonicManager.v1_0_0.RackManager"

DATA_TABLE = "RACK_MANAGER_DATA"
TEMPERATURE_KEY = "{}|Inlet_liquid_temperature".format(DATA_TABLE)
FLOW_RATE_KEY = "{}|Inlet_liquid_flow_rate".format(DATA_TABLE)
PRESSURE_KEY = "{}|Inlet_liquid_pressure".format(DATA_TABLE)
LEAK_KEY = "{}|Rack_level_leak".format(DATA_TABLE)

# The bridge writes STATE_DB from a worker thread after bmcweb has already
# answered 204, so persistence is observed by polling (each poll is one
# sonic-db-cli call per key over SSH, hence the generous timeout).
PERSIST_TIMEOUT = 20
PERSIST_POLL = 1
# Settle time before asserting that a rejected request wrote nothing.
NO_WRITE_SETTLE = 3
BRIDGE_STATE_TIMEOUT = 30
BRIDGE_RECOVERY_TIMEOUT = 60
# bmcweb rejects OEM action bodies above this size before forwarding them.
MAX_BODY_BYTES = 64 * 1024
# isoUtcNow() in the bridge: ISO 8601 UTC with microseconds.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

BMCWEB_CONTAINER = "redfish"
BRIDGE_PROGRAM = "sonic-dbus-bridge"
# Acceptable answers while the bridge is down; see test_submit_telemetry_bridge_unavailable.
BRIDGE_DOWN_STATUSES = (401, 500, 503)

# Documented reference payload (oem-extension/README.md, section 4.3).
TELEMETRY_PAYLOAD = {
    "Alarms": {
        "InletTempDeviation": {"InletTemperature": 16.87, "Severity": "Normal"},
        "FlowRateDeviation": {"FlowRate": 28, "Severity": "Normal"},
        "LiquidPressureDeviation": {"LiquidPressure": 2, "Severity": "Critical"},
        "LeakDetected": {"Severity": "Critical"},
    }
}
TELEMETRY_EXPECTED = {
    TEMPERATURE_KEY: {"InletTemperature": 16.87, "unit": "C", "severity": "NORMAL"},
    FLOW_RATE_KEY: {"value": 28, "unit": "gallons_per_min", "severity": "NORMAL"},
    PRESSURE_KEY: {"value": 2, "unit": "psi", "severity": "CRITICAL"},
    LEAK_KEY: {"leak": "CRITICAL"},
}

# Follow-up sample in which every condition has returned to normal.
CLEARED_PAYLOAD = {
    "Alarms": {
        "InletTempDeviation": {"InletTemperature": 18.5, "Severity": "Normal"},
        "FlowRateDeviation": {"FlowRate": 30, "Severity": "Normal"},
        "LiquidPressureDeviation": {"LiquidPressure": 5.25, "Severity": "Normal"},
        "LeakDetected": {"Severity": "Normal"},
    }
}
CLEARED_EXPECTED = {
    TEMPERATURE_KEY: {"InletTemperature": 18.5, "unit": "C", "severity": "NORMAL"},
    FLOW_RATE_KEY: {"value": 30, "unit": "gallons_per_min", "severity": "NORMAL"},
    PRESSURE_KEY: {"value": 5.25, "unit": "psi", "severity": "NORMAL"},
    LEAK_KEY: {"leak": "NORMAL"},
}

# (payload, expected STATE_DB records) pairs exercising the bridge's
# classification rules: envelope pattern, severity inheritance/default/casing,
# unknown-field dropping and multi-envelope merging.
PAYLOAD_SHAPE_CASES = {
    "alternate_envelope_name": (
        {"SystemAlarms": {"FlowRateDeviation": {"FlowRate": 31, "Severity": "Minor"}}},
        {FLOW_RATE_KEY: {"value": 31, "unit": "gallons_per_min", "severity": "MINOR"}},
    ),
    "wrapper_severity_inherited": (
        {"Alarms": {"ShutdownAlert": {
            "Severity": "Major",
            "TempDeviation": {"InletTemperature": 40},
            "LiquidPressureDeviation": {"LiquidPressure": 90},
            "LeakDetected": {"Severity": "Critical"},
        }}},
        {
            TEMPERATURE_KEY: {"InletTemperature": 40, "unit": "C", "severity": "MAJOR"},
            PRESSURE_KEY: {"value": 90, "unit": "psi", "severity": "MAJOR"},
            LEAK_KEY: {"leak": "CRITICAL"},
        },
    ),
    "missing_severity_defaults_normal": (
        {"Alarms": {"FlowRateDeviation": {"FlowRate": 27}}},
        {FLOW_RATE_KEY: {"value": 27, "unit": "gallons_per_min", "severity": "NORMAL"}},
    ),
    "severity_case_normalised": (
        {"Alarms": {"LiquidPressureDeviation": {"LiquidPressure": 1, "Severity": "critical"}}},
        {PRESSURE_KEY: {"value": 1, "unit": "psi", "severity": "CRITICAL"}},
    ),
    "unknown_fields_dropped": (
        {"Alarms": {
            "EnergyValveActive": True,
            "PumpSpeedDeviation": {"Rpm": 1200, "Severity": "Major"},
            "InletTempDeviation": {"InletTemperature": 21, "Severity": "Normal", "RscmPosition": 3},
        }},
        {TEMPERATURE_KEY: {"InletTemperature": 21, "unit": "C", "severity": "NORMAL"}},
    ),
    "multiple_envelopes_merged": (
        {
            "Alarms": {"InletTempDeviation": {"InletTemperature": 19, "Severity": "Normal"}},
            "RackAlarms": {"FlowRateDeviation": {"FlowRate": 33, "Severity": "Minor"}},
        },
        {
            TEMPERATURE_KEY: {"InletTemperature": 19, "unit": "C", "severity": "NORMAL"},
            FLOW_RATE_KEY: {"value": 33, "unit": "gallons_per_min", "severity": "MINOR"},
        },
    ),
    "unrecognised_only_persists_nothing": (
        {"Alarms": {"PumpSpeedDeviation": {"Rpm": 1200, "Severity": "Major"}}},
        {},
    ),
}

# Requests bmcweb must reject before anything reaches the bridge. Each entry:
# (method, path resolver, request kwargs, expected status, error spec or None).
BAD_REQUEST_CASES = {
    "empty_body_malformed_json": (
        "POST", lambda target: target,
        {"data": "", "headers": {"Content-Type": "application/json"}},
        400, {"message": "MalformedJSON"},
    ),
    "missing_alarms_envelope": (
        "POST", lambda target: target,
        {"json": {"NotPresent": {}}},
        400, {"message": "PropertyMissing", "message_args": ["Alarms"], "prop": "Alarms"},
    ),
    "unknown_manager_id": (
        "POST", lambda target: target.replace("/Managers/bmc/", "/Managers/notbmc/"),
        {"json": TELEMETRY_PAYLOAD},
        404, {"message": "ResourceNotFound", "message_args": ["Manager", "notbmc"]},
    ),
    # bmcweb answers the Base.PayloadTooLarge message with 400, not 413.
    "oversized_body": (
        "POST", lambda target: target,
        {"data": json.dumps({"Alarms": {"Padding": "x" * MAX_BODY_BYTES}}),
         "headers": {"Content-Type": "application/json"}},
        400, {"message": "PayloadTooLarge"},
    ),
    "get_method_not_allowed": (
        "GET", lambda target: target,
        {},
        405, None,
    ),
}


def _data_keys(bmc_duthost):
    return set(redis_keys(bmc_duthost, STATE_DB, "{}|*".format(DATA_TABLE)))


def _records_present(bmc_duthost, keys):
    """wait_until condition: every key exists with its timestamp field.

    The bridge pipelines the HSETs for a record in order with timestamp last,
    so a visible timestamp means the whole record for that key has landed.
    """
    return all(redis_hgetall(bmc_duthost, STATE_DB, key).get("timestamp") for key in keys)


def _records_newer_than(bmc_duthost, previous):
    """wait_until condition: every key's timestamp is later than in `previous`.

    Plain string comparison is deliberate: the fixed-width ISO-8601 format
    orders lexically, and wait_until swallows exceptions from conditions, so
    parsing here would only hide a format error. Format is asserted separately
    by _assert_record.
    """
    for key, before in previous.items():
        current = redis_hgetall(bmc_duthost, STATE_DB, key).get("timestamp", "")
        if not current or current <= before["timestamp"]:
            return False
    return True


def _wait_for_records(bmc_duthost, keys):
    pytest_assert(
        wait_until(PERSIST_TIMEOUT, PERSIST_POLL, 0, _records_present, bmc_duthost, keys),
        "Telemetry not persisted to STATE_DB within {}s; present: {}".format(
            PERSIST_TIMEOUT, sorted(_data_keys(bmc_duthost)))
    )
    return {key: redis_hgetall(bmc_duthost, STATE_DB, key) for key in keys}


def _parse_timestamp(value):
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError as e:
        raise AssertionError(
            "timestamp {!r} is not in bridge format {!r}".format(value, TIMESTAMP_FORMAT)) from e


def _assert_record(key, actual, expected):
    """Assert a RACK_MANAGER_DATA hash holds exactly the expected fields plus timestamp.

    Numeric expectations are compared as floats: the bridge renders doubles
    with std::to_string (16.87 -> "16.870000") and integers verbatim.
    """
    expected_fields = set(expected) | {"timestamp"}
    pytest_assert(
        set(actual) == expected_fields,
        "{}: fields {} != expected {}".format(key, sorted(actual), sorted(expected_fields))
    )
    for field, want in expected.items():
        got = actual[field]
        if isinstance(want, (int, float)):
            pytest_assert(
                abs(float(got) - want) < 1e-6,
                "{}.{} must be {}, got: {!r}".format(key, field, want, got)
            )
        else:
            pytest_assert(got == want, "{}.{} must be {!r}, got: {!r}".format(key, field, want, got))
    _parse_timestamp(actual["timestamp"])


def _assert_records(bmc_duthost, expected):
    """Wait for and validate every expected record, and that nothing else was written."""
    records = _wait_for_records(bmc_duthost, list(expected))
    for key, fields in expected.items():
        logger.info("{} -> {}".format(key, records[key]))
        _assert_record(key, records[key], fields)
    stray = _data_keys(bmc_duthost) - set(expected)
    pytest_assert(not stray, "Unexpected {} keys written: {}".format(DATA_TABLE, sorted(stray)))
    return records


def _assert_nothing_persisted(bmc_duthost):
    time.sleep(NO_WRITE_SETTLE)
    keys = _data_keys(bmc_duthost)
    pytest_assert(not keys, "{} must stay empty, found: {}".format(DATA_TABLE, sorted(keys)))


def _bridge_in_state(bmc_duthost, state):
    res = bmc_duthost.shell(
        "docker exec {} supervisorctl status {}".format(BMCWEB_CONTAINER, BRIDGE_PROGRAM),
        module_ignore_errors=True,
    )
    return state in res["stdout"]


@pytest.fixture(scope="module")
def telemetry_target(redfish_client):
    """Resolve the SubmitTelemetry action target from the Manager resource.

    A rack manager discovers the target this way rather than hardcoding it;
    resolving it once here also turns "image has no OEM extension" into a
    single clear skip instead of a failure per test.
    """
    response = redfish_client.get(MANAGER_PATH)
    assert_status_ok(response, MANAGER_PATH)
    actions = response.json().get("Oem", {}).get("SONiC", {}).get("RackManager", {}).get("Actions", {})
    target = actions.get(SUBMIT_TELEMETRY_ACTION, {}).get("target", "")
    pyrequire(target, "{} does not advertise {}; image lacks the SONiC OEM RackManager extension".format(
        MANAGER_PATH, SUBMIT_TELEMETRY_ACTION))
    logger.info("SubmitTelemetry target: {}".format(target))
    return target


@pytest.fixture(scope="function")
def clean_rack_manager_data(bmc_duthost):
    """Start from an empty RACK_MANAGER_DATA table; restore the prior contents afterwards.

    HSET never removes stale fields, so an empty table is what makes the
    exact-field-set assertions meaningful.
    """
    keys = redis_keys(bmc_duthost, STATE_DB, "{}|*".format(DATA_TABLE))
    snapshot = {key: redis_hgetall(bmc_duthost, STATE_DB, key) for key in keys}
    if keys:
        logger.info("Snapshotting and clearing existing {} keys: {}".format(DATA_TABLE, keys))
        redis_del(bmc_duthost, STATE_DB, *keys)

    yield

    leftover = redis_keys(bmc_duthost, STATE_DB, "{}|*".format(DATA_TABLE))
    if leftover:
        redis_del(bmc_duthost, STATE_DB, *leftover)
    for key, fields in snapshot.items():
        if fields:
            redis_hset(bmc_duthost, STATE_DB, key, **fields)


class TestRedfishRackManagerTelemetry:

    def test_manager_advertises_telemetry_action(self, redfish_client):
        """
        The BMC advertises the SONiC OEM RackManager interface.

        GET /redfish/v1/Managers/bmc must embed Oem.SONiC.RackManager with both
        action targets, and the standalone Oem/SONiC/RackManager resource must
        identify itself with the SonicManager schema type and fixed identity
        fields. This is how a rack manager finds the endpoint to push to.
        """
        response = redfish_client.get(MANAGER_PATH)
        assert_status_ok(response, MANAGER_PATH)
        rack_manager = response.json().get("Oem", {}).get("SONiC", {}).get("RackManager", {})
        pytest_assert(rack_manager, "Oem.SONiC.RackManager missing from {}".format(MANAGER_PATH))
        assert_field_equals(rack_manager, "@odata.id", RACK_MANAGER_PATH)
        assert_field_equals(rack_manager, "@odata.type", RACK_MANAGER_ODATA_TYPE)

        actions = rack_manager.get("Actions", {})
        for action, target in ((SUBMIT_TELEMETRY_ACTION, SUBMIT_TELEMETRY_TARGET),
                               (SUBMIT_ALERT_ACTION, SUBMIT_ALERT_TARGET)):
            pytest_assert(
                actions.get(action, {}).get("target") == target,
                "Actions[{}].target must be {!r}, got: {!r}".format(
                    action, target, actions.get(action, {}).get("target"))
            )

        response = redfish_client.get(RACK_MANAGER_PATH)
        assert_status_ok(response, RACK_MANAGER_PATH)
        body = response.json()
        assert_field_equals(body, "@odata.id", RACK_MANAGER_PATH)
        assert_field_equals(body, "@odata.type", RACK_MANAGER_ODATA_TYPE)
        assert_field_equals(body, "Id", "RackManager")
        assert_field_equals(body, "Name", "SONiC Rack Manager Interface")
        assert_field_nonempty(body, "Description")
        pytest_assert(
            body.get("Actions", {}).get(SUBMIT_TELEMETRY_ACTION, {}).get("target") == SUBMIT_TELEMETRY_TARGET,
            "Standalone resource must advertise {}, got: {!r}".format(
                SUBMIT_TELEMETRY_ACTION, body.get("Actions"))
        )

    def test_submit_telemetry_persists_to_state_db(self, redfish_client, bmc_duthost,
                                                   telemetry_target, clean_rack_manager_data):
        """
        Valid telemetry is accepted and persisted per the platform DB schema.

        POST the documented reference payload (all four sensors, mixed
        severities, a float temperature). bmcweb must answer 204 with an
        empty body, and each sensor must appear under RACK_MANAGER_DATA with
        exactly the schema fields: the temperature value under
        "InletTemperature", flow/pressure under "value", fixed units,
        upper-cased severity, an ISO-8601 UTC timestamp, and a leak record
        carrying only leak + timestamp. No other keys may be written.
        """
        response = redfish_client.post(telemetry_target, json=TELEMETRY_PAYLOAD)
        logger.info("POST {} -> {}".format(telemetry_target, response.status_code))
        assert_no_content(response, telemetry_target)

        _assert_records(bmc_duthost, TELEMETRY_EXPECTED)

    def test_submit_telemetry_updates_existing_record(self, redfish_client, bmc_duthost,
                                                      telemetry_target, clean_rack_manager_data):
        """
        A later sample overwrites the previous one, so alert clearing is visible.

        The design intent of telemetry is to let the BMC see when a Critical
        condition reported earlier has cleared. Push the Critical reference
        payload, then an all-Normal sample: every record must show the new
        value and NORMAL severity/leak state, with a strictly later timestamp.
        """
        response = redfish_client.post(telemetry_target, json=TELEMETRY_PAYLOAD)
        assert_no_content(response, telemetry_target)
        first = _assert_records(bmc_duthost, TELEMETRY_EXPECTED)

        response = redfish_client.post(telemetry_target, json=CLEARED_PAYLOAD)
        assert_no_content(response, telemetry_target)
        pytest_assert(
            wait_until(PERSIST_TIMEOUT, PERSIST_POLL, 0, _records_newer_than, bmc_duthost, first),
            "Second telemetry sample did not refresh every {} record within {}s".format(
                DATA_TABLE, PERSIST_TIMEOUT)
        )
        _assert_records(bmc_duthost, CLEARED_EXPECTED)

    @pytest.mark.parametrize("case", list(PAYLOAD_SHAPE_CASES))
    def test_submit_telemetry_payload_shapes(self, redfish_client, bmc_duthost,
                                             telemetry_target, clean_rack_manager_data, case):
        """
        The bridge's classification rules hold for the payload shapes a rack manager may send.

        Every case must be accepted with 204. Where records are expected they
        must match exactly; where none are expected the table must stay empty:
          - any top-level key matching "*Alarms*" is a valid envelope;
          - Severity is inherited from the enclosing wrapper, defaults to
            NORMAL when absent, and is upper-cased regardless of input case;
          - fields without a sensor rule (and RscmPosition) are dropped;
          - several envelopes in one body merge into one write batch;
          - a body with only unrecognised fields is accepted but persists nothing.
        """
        payload, expected = PAYLOAD_SHAPE_CASES[case]
        response = redfish_client.post(telemetry_target, json=payload)
        logger.info("[{}] POST {} -> {}".format(case, telemetry_target, response.status_code))
        assert_no_content(response, telemetry_target)

        if expected:
            _assert_records(bmc_duthost, expected)
        else:
            _assert_nothing_persisted(bmc_duthost)

    @pytest.mark.parametrize("case", list(BAD_REQUEST_CASES))
    def test_submit_telemetry_rejects_bad_requests(self, redfish_client, bmc_duthost,
                                                   telemetry_target, clean_rack_manager_data, case):
        """
        bmcweb rejects malformed requests with the right Redfish error and writes nothing.

          - empty body                 -> 400 MalformedJSON
          - no "*Alarms*" envelope key -> 400 PropertyMissing (Alarms)
          - unknown manager id         -> 404 ResourceNotFound (Manager, notbmc)
          - body above 64 KiB          -> 400 PayloadTooLarge
          - GET on the action target   -> 405
        After each rejection RACK_MANAGER_DATA must remain empty.
        """
        method, resolve_path, kwargs, status, error = BAD_REQUEST_CASES[case]
        path = resolve_path(telemetry_target)
        if method == "GET":
            response = redfish_client.get(path, **kwargs)
        else:
            response = redfish_client.post(path, **kwargs)
        logger.info("[{}] {} {} -> {} {!r}".format(case, method, path, response.status_code, response.text[:200]))

        if error:
            assert_redfish_error(response, status, **error)
        else:
            pytest_assert(
                response.status_code == status,
                "[{}] expected HTTP {}, got: {} body={!r}".format(case, status, response.status_code,
                                                                  response.text[:500])
            )
        _assert_nothing_persisted(bmc_duthost)

    def test_submit_telemetry_bridge_unavailable(self, redfish_client, bmc_duthost,
                                                 telemetry_target, clean_rack_manager_data):
        """
        With sonic-dbus-bridge stopped, telemetry is refused, not silently lost, and service recovers.

        bmcweb depends on the bridge over D-Bus for both the mTLS user lookup
        and the telemetry forward, so which call fails first decides the
        status: 503 ServiceTemporarilyUnavailable (forward), or 500/401 if
        the user lookup fails first. Either way bmcweb must answer promptly
        with no 2xx, and nothing may reach STATE_DB. After the bridge is
        restarted the next POST must succeed and persist.
        """
        bmc_duthost.shell("docker exec {} supervisorctl stop {}".format(BMCWEB_CONTAINER, BRIDGE_PROGRAM))
        try:
            pytest_assert(
                wait_until(BRIDGE_STATE_TIMEOUT, 2, 0, _bridge_in_state, bmc_duthost, "STOPPED"),
                "{} did not reach STOPPED within {}s".format(BRIDGE_PROGRAM, BRIDGE_STATE_TIMEOUT)
            )
            try:
                response = redfish_client.post(telemetry_target, json=TELEMETRY_PAYLOAD)
            except requests.exceptions.RequestException as e:
                raise AssertionError("bmcweb did not answer SubmitTelemetry while {} was stopped: {}".format(
                    BRIDGE_PROGRAM, e)) from e
            logger.info("POST with bridge stopped -> {} {!r}".format(response.status_code, response.text[:300]))
            pytest_assert(
                response.status_code in BRIDGE_DOWN_STATUSES,
                "Expected one of {} with {} stopped, got: {}".format(
                    BRIDGE_DOWN_STATUSES, BRIDGE_PROGRAM, response.status_code)
            )
            _assert_nothing_persisted(bmc_duthost)
        finally:
            bmc_duthost.shell(
                "docker exec {} supervisorctl start {}".format(BMCWEB_CONTAINER, BRIDGE_PROGRAM),
                module_ignore_errors=True,
            )

        pytest_assert(
            wait_until(BRIDGE_STATE_TIMEOUT, 2, 0, _bridge_in_state, bmc_duthost, "RUNNING"),
            "{} did not return to RUNNING within {}s".format(BRIDGE_PROGRAM, BRIDGE_STATE_TIMEOUT)
        )

        def _telemetry_accepted():
            return redfish_client.post(telemetry_target, json=TELEMETRY_PAYLOAD).status_code == 204

        pytest_assert(
            wait_until(BRIDGE_RECOVERY_TIMEOUT, 2, 0, _telemetry_accepted),
            "SubmitTelemetry did not recover within {}s of restarting {}".format(
                BRIDGE_RECOVERY_TIMEOUT, BRIDGE_PROGRAM)
        )
        _assert_records(bmc_duthost, TELEMETRY_EXPECTED)
