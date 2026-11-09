"""
Tests for the SONiC OEM Rack Manager alert action:

    POST /redfish/v1/Managers/bmc/Oem/SONiC/RackManager/Actions/SONiC.SubmitAlert

pmon-bmc-design.md section 2.1.2 item 4: the rack manager sends an alert when
there is a deviation in inlet liquid temperature, flow rate, pressure or a
rack-level leak. The BMC path is

    bmcweb (auth, manager id, 64 KiB cap, JSON parse, "redfish*" envelope)
      -> D-Bus com.sonic.RackManager.SubmitAlert
      -> sonic-dbus-bridge (field-rule classification, worker thread)
      -> STATE_DB  RACK_MANAGER_ALERT|<sensor>

STATE_DB is the observable boundary and the records are checked against the
schema in section 2.1.2.1: a measurement alert stores severity + timestamp,
the leak alert stores leak + timestamp.

Unlike telemetry, RACK_MANAGER_ALERT is consumed by bmcctld: a CRITICAL entry
blocks POWER_ON and dispatches rack_mgr_critical_alert_action from
LEAK_CONTROL_POLICY (default syslog_only). The tests therefore only inject
CRITICAL when that action cannot power the switch host off, and always clear
the table and restore its previous contents afterwards.
"""
import json
import logging
import time
from datetime import datetime

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.sonic_db import (
    CONFIG_DB,
    STATE_DB,
    redis_del,
    redis_hgetall,
    redis_hset,
    redis_keys,
)
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    assert_no_content,
    assert_redfish_error,
    assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

MANAGER_PATH = "/redfish/v1/Managers/bmc"
SUBMIT_ALERT_ACTION = "#SONiC.SubmitAlert"

ALERT_TABLE = "RACK_MANAGER_ALERT"
TEMPERATURE_KEY = "{}|Inlet_liquid_temperature".format(ALERT_TABLE)
FLOW_RATE_KEY = "{}|Inlet_liquid_flow_rate".format(ALERT_TABLE)
PRESSURE_KEY = "{}|Inlet_liquid_pressure".format(ALERT_TABLE)
LEAK_KEY = "{}|Rack_level_leak".format(ALERT_TABLE)

LEAK_CONTROL_POLICY_KEY = "LEAK_CONTROL_POLICY"
# bmcctld defaults when LEAK_CONTROL_POLICY is absent (pmon-bmc-design.md 2.3.1).
DEFAULT_RACK_MGR_LEAK_POLICY = "enabled"
DEFAULT_RACK_MGR_CRITICAL_ALERT_ACTION = "syslog_only"
DEFAULT_RACK_MGR_MINOR_ALERT_ACTION = "syslog_only"

PERSIST_TIMEOUT = 20
PERSIST_POLL = 1
NO_WRITE_SETTLE = 3
MAX_BODY_BYTES = 64 * 1024
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Flat form (oem-extension/README.md, section 4.1): one block per alert type,
# measurement leaves inherit Severity from the enclosing "Alerts" wrapper.
FLAT_ALERT_PAYLOAD = {
    "redfish_alert_data": {
        "Alerts": {"InletTemperature": 18, "FlowRate": 58, "Severity": "Minor"},
        "LiquidPressureDeviation": {"LiquidPressure": 68, "Severity": "Major"},
        "LeakDetected": {"Severity": "Critical"},
    }
}
FLAT_ALERT_EXPECTED = {
    TEMPERATURE_KEY: {"severity": "MINOR"},
    FLOW_RATE_KEY: {"severity": "MINOR"},
    PRESSURE_KEY: {"severity": "MAJOR"},
    LEAK_KEY: {"leak": "CRITICAL"},
}

# ShutdownAlert wrapped form (README section 4.2): the wrapper owns one
# Severity that every leaf without its own inherits.
WRAPPED_ALERT_PAYLOAD = {
    "redfish_alert_data": {
        "ShutdownAlert": {
            "FlowRateDeviation": {"FlowRate": 58},
            "TempDeviation": {"InletTemperature": 17},
            "LiquidPressureDeviation": {"LiquidPressure": 68},
            "LeakDetected": {"Severity": "Critical"},
            "Severity": "Major",
        }
    }
}
WRAPPED_ALERT_EXPECTED = {
    TEMPERATURE_KEY: {"severity": "MAJOR"},
    FLOW_RATE_KEY: {"severity": "MAJOR"},
    PRESSURE_KEY: {"severity": "MAJOR"},
    LEAK_KEY: {"leak": "CRITICAL"},
}

# Every condition back to normal, the shape a rack manager sends on clear.
CLEARED_ALERT_PAYLOAD = {
    "redfish_alert_data": {
        "Alerts": {"InletTemperature": 20, "FlowRate": 60, "Severity": "Normal"},
        "LiquidPressureDeviation": {"LiquidPressure": 70, "Severity": "Normal"},
        "LeakDetected": {"Severity": "Normal"},
    }
}
CLEARED_ALERT_EXPECTED = {
    TEMPERATURE_KEY: {"severity": "NORMAL"},
    FLOW_RATE_KEY: {"severity": "NORMAL"},
    PRESSURE_KEY: {"severity": "NORMAL"},
    LEAK_KEY: {"leak": "NORMAL"},
}

# Payloads that never carry CRITICAL, so they are safe under any policy.
MINOR_ONLY_PAYLOAD = {
    "redfish_alert_data": {"FlowRateDeviation": {"FlowRate": 40, "Severity": "Minor"}}
}
MINOR_ONLY_EXPECTED = {FLOW_RATE_KEY: {"severity": "MINOR"}}

# Requests bmcweb must reject before anything reaches the bridge. Each entry:
# (method, path resolver, request kwargs, expected status, error spec or None).
BAD_REQUEST_CASES = {
    "empty_body_malformed_json": (
        "POST", lambda target: target,
        {"data": "", "headers": {"Content-Type": "application/json"}},
        400, {"message": "MalformedJSON"},
    ),
    # A telemetry-style "Alarms" envelope is not an alert envelope.
    "missing_redfish_envelope": (
        "POST", lambda target: target,
        {"json": {"Alarms": {"LeakDetected": {"Severity": "Minor"}}}},
        400, {"message": "PropertyMissing", "message_args": ["redfish"], "prop": "redfish"},
    ),
    # The envelope pattern is case-sensitive.
    "envelope_wrong_case": (
        "POST", lambda target: target,
        {"json": {"Redfish_alert_data": {"LeakDetected": {"Severity": "Minor"}}}},
        400, {"message": "PropertyMissing", "message_args": ["redfish"], "prop": "redfish"},
    ),
    "unknown_manager_id": (
        "POST", lambda target: target.replace("/Managers/bmc/", "/Managers/notbmc/"),
        {"json": MINOR_ONLY_PAYLOAD},
        404, {"message": "ResourceNotFound", "message_args": ["Manager", "notbmc"]},
    ),
    "oversized_body": (
        "POST", lambda target: target,
        {"data": json.dumps({"redfish_alert_data": {"Padding": "x" * MAX_BODY_BYTES}}),
         "headers": {"Content-Type": "application/json"}},
        400, {"message": "PayloadTooLarge"},
    ),
    "get_method_not_allowed": (
        "GET", lambda target: target,
        {},
        405, None,
    ),
}


def _alert_keys(bmc_duthost):
    return set(redis_keys(bmc_duthost, STATE_DB, "{}|*".format(ALERT_TABLE)))


def _records_present(bmc_duthost, keys):
    """wait_until condition: every key exists with its timestamp field (written last)."""
    return all(redis_hgetall(bmc_duthost, STATE_DB, key).get("timestamp") for key in keys)


def _records_newer_than(bmc_duthost, previous):
    """wait_until condition: every key's timestamp is lexically later than in `previous`."""
    for key, before in previous.items():
        current = redis_hgetall(bmc_duthost, STATE_DB, key).get("timestamp", "")
        if not current or current <= before["timestamp"]:
            return False
    return True


def _assert_record(key, actual, expected):
    """Assert a RACK_MANAGER_ALERT hash holds exactly the schema fields plus timestamp."""
    expected_fields = set(expected) | {"timestamp"}
    pytest_assert(
        set(actual) == expected_fields,
        "{}: fields {} != expected {}".format(key, sorted(actual), sorted(expected_fields))
    )
    for field, want in expected.items():
        pytest_assert(actual[field] == want, "{}.{} must be {!r}, got: {!r}".format(key, field, want, actual[field]))
    try:
        datetime.strptime(actual["timestamp"], TIMESTAMP_FORMAT)
    except ValueError:
        pytest.fail("{} timestamp {!r} is not in bridge format {!r}".format(key, actual["timestamp"], TIMESTAMP_FORMAT))


def _assert_records(bmc_duthost, expected):
    """Wait for and validate every expected record, and that nothing else was written."""
    pytest_assert(
        wait_until(PERSIST_TIMEOUT, PERSIST_POLL, 0, _records_present, bmc_duthost, list(expected)),
        "Alerts not persisted to STATE_DB within {}s; present: {}".format(
            PERSIST_TIMEOUT, sorted(_alert_keys(bmc_duthost)))
    )
    records = {key: redis_hgetall(bmc_duthost, STATE_DB, key) for key in expected}
    for key, fields in expected.items():
        logger.info("{} -> {}".format(key, records[key]))
        _assert_record(key, records[key], fields)
    stray = _alert_keys(bmc_duthost) - set(expected)
    pytest_assert(not stray, "Unexpected {} keys written: {}".format(ALERT_TABLE, sorted(stray)))
    return records


def _assert_nothing_persisted(bmc_duthost):
    time.sleep(NO_WRITE_SETTLE)
    keys = _alert_keys(bmc_duthost)
    pytest_assert(not keys, "{} must stay empty, found: {}".format(ALERT_TABLE, sorted(keys)))


def _rack_mgr_policy(bmc_duthost):
    """Effective rack manager alert policy: CONFIG_DB LEAK_CONTROL_POLICY over bmcctld defaults."""
    policy = {
        "rack_mgr_leak_policy": DEFAULT_RACK_MGR_LEAK_POLICY,
        "rack_mgr_critical_alert_action": DEFAULT_RACK_MGR_CRITICAL_ALERT_ACTION,
        "rack_mgr_minor_alert_action": DEFAULT_RACK_MGR_MINOR_ALERT_ACTION,
    }
    policy.update(redis_hgetall(bmc_duthost, CONFIG_DB, LEAK_CONTROL_POLICY_KEY))
    return policy


@pytest.fixture(scope="module")
def alert_target(redfish_client):
    """Resolve the SubmitAlert action target from the Manager resource, as a rack manager would."""
    response = redfish_client.get(MANAGER_PATH)
    assert_status_ok(response, MANAGER_PATH)
    actions = response.json().get("Oem", {}).get("SONiC", {}).get("RackManager", {}).get("Actions", {})
    target = actions.get(SUBMIT_ALERT_ACTION, {}).get("target", "")
    pyrequire(target, "{} does not advertise {}; image lacks the SONiC OEM RackManager extension".format(
        MANAGER_PATH, SUBMIT_ALERT_ACTION))
    logger.info("SubmitAlert target: {}".format(target))
    return target


@pytest.fixture(scope="function")
def clean_rack_manager_alerts(bmc_duthost):
    """Start from an empty RACK_MANAGER_ALERT table and restore the prior contents afterwards.

    The restore matters more than for telemetry: a CRITICAL entry left behind
    would make bmcctld refuse every later POWER_ON.
    """
    keys = redis_keys(bmc_duthost, STATE_DB, "{}|*".format(ALERT_TABLE))
    snapshot = {key: redis_hgetall(bmc_duthost, STATE_DB, key) for key in keys}
    if keys:
        logger.info("Snapshotting and clearing existing {} keys: {}".format(ALERT_TABLE, keys))
        redis_del(bmc_duthost, STATE_DB, *keys)

    yield

    leftover = redis_keys(bmc_duthost, STATE_DB, "{}|*".format(ALERT_TABLE))
    if leftover:
        redis_del(bmc_duthost, STATE_DB, *leftover)
    for key, fields in snapshot.items():
        if fields:
            redis_hset(bmc_duthost, STATE_DB, key, **fields)


@pytest.fixture(scope="function")
def critical_alert_is_safe(bmc_duthost):
    """Skip unless a CRITICAL rack manager alert cannot power the switch host off.

    bmcctld dispatches rack_mgr_critical_alert_action on a CRITICAL alert when
    rack_mgr_leak_policy is enabled. Only syslog_only leaves the host running.
    """
    policy = _rack_mgr_policy(bmc_duthost)
    logger.info("Effective rack manager alert policy: {}".format(policy))
    pyrequire(
        policy["rack_mgr_leak_policy"] == "disabled" or policy["rack_mgr_critical_alert_action"] == "syslog_only",
        "LEAK_CONTROL_POLICY rack_mgr_critical_alert_action={!r} would act on the switch host; "
        "refusing to inject a CRITICAL rack manager alert".format(policy["rack_mgr_critical_alert_action"])
    )


class TestRedfishRackManagerAlert:

    def test_submit_alert_persists_to_state_db(self, redfish_client, bmc_duthost, alert_target,
                                               clean_rack_manager_alerts, critical_alert_is_safe):
        """
        A flat-form alert is accepted and persisted per the platform DB schema.

        POST the documented flat payload. bmcweb must answer 204 with an empty
        body and each sensor must appear under RACK_MANAGER_ALERT with exactly
        the schema fields: upper-cased severity + timestamp for the three
        measurements, leak + timestamp for the rack-level leak. Measurement
        leaves inherit Severity from their wrapper. No other keys may be written.
        """
        response = redfish_client.post(alert_target, json=FLAT_ALERT_PAYLOAD)
        logger.info("POST {} -> {}".format(alert_target, response.status_code))
        assert_no_content(response, alert_target)

        _assert_records(bmc_duthost, FLAT_ALERT_EXPECTED)

    def test_submit_alert_wrapped_form_inherits_severity(self, redfish_client, bmc_duthost, alert_target,
                                                         clean_rack_manager_alerts, critical_alert_is_safe):
        """
        The ShutdownAlert wrapped form resolves to the same canonical records.

        Leaves without their own Severity take the wrapper's (Major), the
        LeakDetected leaf keeps its own Critical, and the wrapper name is not
        encoded in the STATE_DB key.
        """
        response = redfish_client.post(alert_target, json=WRAPPED_ALERT_PAYLOAD)
        assert_no_content(response, alert_target)

        _assert_records(bmc_duthost, WRAPPED_ALERT_EXPECTED)

    def test_submit_alert_clear_overwrites_critical(self, redfish_client, bmc_duthost, alert_target,
                                                    clean_rack_manager_alerts, critical_alert_is_safe):
        """
        A follow-up Normal alert clears an earlier Critical in place.

        bmcctld keys its power-on gate on RACK_MANAGER_ALERT severity, so the
        clear must land on the same keys with NORMAL and a later timestamp.
        """
        response = redfish_client.post(alert_target, json=FLAT_ALERT_PAYLOAD)
        assert_no_content(response, alert_target)
        first = _assert_records(bmc_duthost, FLAT_ALERT_EXPECTED)

        response = redfish_client.post(alert_target, json=CLEARED_ALERT_PAYLOAD)
        assert_no_content(response, alert_target)
        pytest_assert(
            wait_until(PERSIST_TIMEOUT, PERSIST_POLL, 0, _records_newer_than, bmc_duthost, first),
            "Clearing alert did not refresh every {} record within {}s".format(ALERT_TABLE, PERSIST_TIMEOUT)
        )
        _assert_records(bmc_duthost, CLEARED_ALERT_EXPECTED)

    def test_submit_alert_minor_only(self, redfish_client, bmc_duthost, alert_target, clean_rack_manager_alerts):
        """
        A single Minor measurement alert writes only that sensor's record.

        Runs under any LEAK_CONTROL_POLICY since nothing CRITICAL is injected.
        """
        response = redfish_client.post(alert_target, json=MINOR_ONLY_PAYLOAD)
        assert_no_content(response, alert_target)

        _assert_records(bmc_duthost, MINOR_ONLY_EXPECTED)

    @pytest.mark.parametrize("case", list(BAD_REQUEST_CASES))
    def test_submit_alert_rejects_bad_requests(self, redfish_client, bmc_duthost, alert_target,
                                               clean_rack_manager_alerts, case):
        """
        bmcweb rejects malformed alert requests with the right Redfish error and writes nothing.

          - empty body                       -> 400 MalformedJSON
          - no "redfish*" envelope key       -> 400 PropertyMissing (redfish)
          - envelope with the wrong case     -> 400 PropertyMissing (redfish)
          - unknown manager id               -> 404 ResourceNotFound (Manager, notbmc)
          - body above 64 KiB                -> 400 PayloadTooLarge
          - GET on the action target         -> 405
        After each rejection RACK_MANAGER_ALERT must remain empty.
        """
        method, resolve_path, kwargs, status, error = BAD_REQUEST_CASES[case]
        path = resolve_path(alert_target)
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
