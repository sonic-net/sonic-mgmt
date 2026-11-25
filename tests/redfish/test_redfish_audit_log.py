# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Nexthop AI
# Copyright (C) 2026 SONiC Project
# Author: Chinmoy Dey <chinmoy@nexthop.ai>
"""
Tests for the Redfish audit trail on the SONiC BMC.

bmcweb writes one JSON record to syslog, under the identifier
``redfish-audit`` and facility ``authpriv``, for every POST, PATCH, PUT or
DELETE, for every request answered with 401 or 403, and for every Redfish
event the BMC raises itself. A GET is recorded only while the log level in
CONFIG_DB ``LOGGER|sonic-dbus-bridge`` is ``DEBUG`` (sonic-redfish README
section 7.3).

Here the sonic-mgmt test plays the rack manager: it makes a request, or
raises a leak event the way thermalctld would, and reads back the record that
request added to the BMC's auth log. A record says who changed what and with
what result, and never carries what the caller sent beyond the fields listed
for the route, so the tests also check what must be absent.
"""
import json
import logging
import re
import time

import pytest
import requests

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.sonic_db import CONFIG_DB, STATE_DB, redis_del, redis_hgetall, redis_hset
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    assert_no_content,
    assert_status_ok,
    BMCWEB_CONTAINER,
    BRIDGE_SERVICE,
    BRIDGE_STATE_TIMEOUT,
    CLIENT_CN,
    command_keys,
    host_is_settled_on,
    PRIVILEGED_PATH,
    redfish_url,
    remove_new_commands,
    supervisor,
    wait_for_new_commands_done,
    wait_for_program,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

# rsyslog on the BMC files the authpriv facility here.
AUDIT_LOG = "/var/log/auth.log"
# A record as rsyslog files it: the identifier and pid, then the JSON object. The
# sudo line this module's own grep leaves in the same log does not match it.
AUDIT_LINE_GREP = r"redfish-audit\[[0-9]+\]: \{"
AUDIT_LINE_PATTERN = re.compile(r"redfish-audit\[\d+\]: (\{.*\})\s*$")
RECORD_TIMEOUT = 20
RECORD_POLL = 2
# Settle time before asserting that a request added no record.
NO_RECORD_SETTLE = 5
TIMESTAMP_PATTERN = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z"

SYSTEM_PATH = "/redfish/v1/Systems/system"
SYSTEM_RULE = "/redfish/v1/Systems/<str>"
RESET_PATH = "{}/Actions/ComputerSystem.Reset".format(SYSTEM_PATH)
RESET_RULE = "{}/Actions/ComputerSystem.Reset".format(SYSTEM_RULE)
RESET_ACTION = "ComputerSystem.Reset"
SUBSCRIPTIONS_PATH = "/redfish/v1/EventService/Subscriptions"
SUBSCRIPTION_RULE = "{}/<str>".format(SUBSCRIPTIONS_PATH)
HOST_STATE_KEY = "HOST_STATE|switch-host"

# The log level sonic-dbus-bridge follows, and publishes on D-Bus for bmcweb.
LOG_LEVEL_KEY = "LOGGER|sonic-dbus-bridge"
LOG_LEVEL_FIELD = "LOGLEVEL"
LOG_LEVEL_DBUS = ("com.sonic.RackManager", "/com/sonic/Redfish/Logging", "com.sonic.Redfish.Logging", "LogLevel")
LOG_LEVEL_TIMEOUT = 30

# A subscription whose destination and context must stay out of the record.
# 192.0.2.0/24 is reserved for documentation, so nothing is ever delivered.
UNRECORDED_DESTINATION_HOST = "192.0.2.77"
UNRECORDED_DESTINATION_PATH = "rmc-audit-secret-path"
UNRECORDED_CONTEXT = "rmc-audit-secret-context"
UNROUTED_MARKER = "rmc-audit-xyzzy"
UNROUTED_PATH = "/redfish/v1/No/Such/Route-{}".format(UNROUTED_MARKER)

# Synthetic leak sensor the test plays thermalctld for.
LEAK_SENSOR = "rmc_audit_leak"
LEAK_SENSOR_KEY = "LIQUID_COOLING_INFO|{}".format(LEAK_SENSOR)
LEAK_DETECTOR_PATH = "/redfish/v1/Chassis/chassis/LeakDetectors/{}".format(LEAK_SENSOR)
LEAK_STATES = {
    "OK": {"leaking": "No", "leak_status": "No", "leak_severity": "None", "leak_sensor_status": "Good"},
    "Critical": {"leaking": "Yes", "leak_status": "Yes", "leak_severity": "CRITICAL", "leak_sensor_status": "Good"},
}
# MessageId suffix and Severity of the event each detector state raises.
LEAK_EVENTS = {
    "Critical": ("LeakDetectedCritical", "Critical"),
    "OK": ("LeakDetectedNormal", "OK"),
}
DETECTOR_TIMEOUT = 60


class AuditLog:
    """The audit records in the BMC's auth log, read back over SSH."""

    def __init__(self, duthost):
        self.duthost = duthost

    def lines(self):
        """Every audit line in the log, oldest first."""
        res = self.duthost.shell(
            "sudo grep -a -E -- '{}' {}".format(AUDIT_LINE_GREP, AUDIT_LOG), module_ignore_errors=True, verbose=False)
        return [line for line in res["stdout"].splitlines() if AUDIT_LINE_PATTERN.search(line)]

    def mark(self):
        """The number of audit lines so far, once it has stopped moving.

        A record of an earlier request can still be on its way through
        rsyslog, and must not be taken for one the next request added.
        """
        count = len(self.lines())
        while True:
            time.sleep(1)
            later = len(self.lines())
            if later == count:
                return count
            count = later

    def added(self, since):
        """(record, line) for every audit line written after mark(). A line that is not JSON fails the test."""
        found = []
        for line in self.lines()[since:]:
            try:
                found.append((json.loads(AUDIT_LINE_PATTERN.search(line).group(1)), line))
            except ValueError as e:
                raise AssertionError("Audit line is not a JSON record: {!r}".format(line)) from e
        return found

    def wait_for(self, since, description, **fields):
        """The first (record, line) after mark() whose fields equal `fields`."""
        last = {}

        def _matching():
            last["added"] = self.added(since)
            return [(record, line) for record, line in last["added"]
                    if all(record.get(name) == value for name, value in fields.items())]

        pytest_assert(
            wait_until(RECORD_TIMEOUT, RECORD_POLL, 0, _matching),
            "No audit record for {} ({}) within {}s, records added: {}".format(
                description, fields, RECORD_TIMEOUT, [record for record, _ in last.get("added", [])])
        )
        record, line = _matching()[0]
        logger.info("Audit record for %s: %s", description, record)
        return record, line


def _log_level(duthost):
    """The level sonic-dbus-bridge publishes for bmcweb, or None when it publishes none."""
    bus, path, interface, prop = LOG_LEVEL_DBUS
    res = duthost.shell(
        "docker exec {} dbus-send --system --print-reply --dest={} {} org.freedesktop.DBus.Properties.Get "
        "string:{} string:{}".format(BMCWEB_CONTAINER, bus, path, interface, prop),
        module_ignore_errors=True)
    if res["rc"] != 0:
        return None
    match = re.search(r'string "([^"]*)"', res["stdout"])
    return match.group(1) if match else None


def _assert_record_envelope(record):
    """Check the fields every record carries: version, source, UTC timestamp and sequence number."""
    pytest_assert(record.get("v") == 1, "Record version must be 1, got: {}".format(record))
    pytest_assert(record.get("src") == "bmcweb", "Record src must be bmcweb, got: {}".format(record))
    pytest_assert(
        isinstance(record.get("ts"), str) and re.fullmatch(TIMESTAMP_PATTERN, record["ts"]),
        "Record ts must be a UTC timestamp with milliseconds, got: {}".format(record)
    )
    pytest_assert(
        isinstance(record.get("seq"), int) and record["seq"] > 0,
        "Record seq must be a positive sequence number, got: {}".format(record)
    )


def _assert_absent(line, values):
    leaked = [value for value in values if value in line]
    pytest_assert(not leaked, "The audit record must not carry {}, got: {}".format(leaked, line))


@pytest.fixture(scope="module")
def audit_log(bmc_duthost, redfish_client):
    """The audit trail of a BMC whose bmcweb was built with redfish-audit.

    Skips unless sonic-dbus-bridge publishes the LogLevel property bmcweb
    follows, which exists only together with the audit trail. Depends on
    redfish_client so the certificates are provisioned first.
    """
    level = _log_level(bmc_duthost)
    pyrequire(
        level is not None,
        "{} does not publish {} on D-Bus; this image was built without the Redfish audit trail".format(
            BRIDGE_SERVICE, ".".join(LOG_LEVEL_DBUS[2:]))
    )
    logger.info("%s publishes log level %s", BRIDGE_SERVICE, level)
    return AuditLog(bmc_duthost)


@pytest.fixture(scope="function")
def log_level(bmc_duthost):
    """Return a callable that sets the CONFIG_DB log level, and put the entry back as it was afterwards."""
    before = redis_hgetall(bmc_duthost, CONFIG_DB, LOG_LEVEL_KEY)
    level_before = _log_level(bmc_duthost)

    def _set(level):
        redis_hset(bmc_duthost, CONFIG_DB, LOG_LEVEL_KEY, **{LOG_LEVEL_FIELD: level})
        pytest_assert(
            wait_until(LOG_LEVEL_TIMEOUT, 1, 0, lambda: _log_level(bmc_duthost) == level),
            "{} did not apply log level {} within {}s of CONFIG_DB {} changing, it publishes: {}".format(
                BRIDGE_SERVICE, level, LOG_LEVEL_TIMEOUT, LOG_LEVEL_KEY, _log_level(bmc_duthost))
        )
        logger.info("%s applied log level %s", BRIDGE_SERVICE, level)

    yield _set

    redis_del(bmc_duthost, CONFIG_DB, LOG_LEVEL_KEY)
    if before:
        redis_hset(bmc_duthost, CONFIG_DB, LOG_LEVEL_KEY, **before)
    pytest_assert(
        wait_until(LOG_LEVEL_TIMEOUT, 1, 0, lambda: _log_level(bmc_duthost) == level_before),
        "{} did not return to log level {} within {}s, it publishes: {}".format(
            BRIDGE_SERVICE, level_before, LOG_LEVEL_TIMEOUT, _log_level(bmc_duthost))
    )


@pytest.fixture(scope="function")
def leak_sensor(bmc_duthost, redfish_client):
    """A synthetic leak sensor at OK that the bridge exports; returns a state injector.

    Removes the row afterwards and restarts the bridge so it no longer exports it.
    """
    def _set_state(state):
        redis_hset(bmc_duthost, STATE_DB, LEAK_SENSOR_KEY, **LEAK_STATES[state])
        logger.info("BMC leak sensor %s set to %s via STATE_DB %s", LEAK_SENSOR, state, LEAK_STATES[state])

    def _detector_ok():
        try:
            response = redfish_client.get(LEAK_DETECTOR_PATH)
        except requests.exceptions.RequestException:
            return False
        return response.status_code == 200 and response.json().get("DetectorState") == "OK"

    try:
        redis_hset(bmc_duthost, STATE_DB, LEAK_SENSOR_KEY, type="leak", location="rmc-test", **LEAK_STATES["OK"])
        pytest_assert(
            wait_until(DETECTOR_TIMEOUT, 3, 0, _detector_ok),
            "{} did not report DetectorState OK within {}s of {} being written".format(
                LEAK_DETECTOR_PATH, DETECTOR_TIMEOUT, LEAK_SENSOR_KEY)
        )
        yield _set_state
    finally:
        redis_del(bmc_duthost, STATE_DB, LEAK_SENSOR_KEY)
        supervisor(bmc_duthost, "restart", BRIDGE_SERVICE)
        pytest_assert(wait_for_program(bmc_duthost, BRIDGE_SERVICE, "RUNNING", BRIDGE_STATE_TIMEOUT),
                      "{} did not return to RUNNING within {}s".format(BRIDGE_SERVICE, BRIDGE_STATE_TIMEOUT))


class TestRedfishAuditLog:

    def test_state_changing_request_recorded(self, redfish_client, bmc_duthost, audit_log):
        """
        A request that changes state is recorded with who made it, what it asked for and the result.

        ResetType=On against a switch host that is on is accepted with 204 and
        is a no-op for the host. Its record is a `request` naming the client
        certificate's common name as the user, the method, the route pattern
        rather than the path sent, the action, the ResetType asked for and the
        status answered, with a UTC timestamp and a sequence number.
        """
        host_state = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)
        pyrequire(host_is_settled_on(host_state),
                  "{} must show the switch host settled on, got: {}".format(HOST_STATE_KEY, host_state))
        keys_before = command_keys(bmc_duthost)
        since = audit_log.mark()

        try:
            response = redfish_client.post(RESET_PATH, json={"ResetType": "On"})
            assert_no_content(response, RESET_PATH)
            record, _ = audit_log.wait_for(since, "ResetType=On", ev="request", uri=RESET_RULE)
        finally:
            wait_for_new_commands_done(bmc_duthost, keys_before)
            remove_new_commands(bmc_duthost, keys_before)

        _assert_record_envelope(record)
        expected = {
            "user": CLIENT_CN,
            "method": "POST",
            "action": RESET_ACTION,
            "detail": {"ResetType": "On"},
            "status": 204,
        }
        actual = {name: record.get(name) for name in expected}
        pytest_assert(actual == expected, "The reset record must carry {}, got: {}".format(expected, record))
        logger.info("Verified the reset was recorded as %s", record)

    def test_refused_request_recorded(self, redfish_client, audit_log):
        """
        A state-changing request the BMC rejects is recorded with the status it was answered with.

        ResetType=InvalidType is refused with 400 and changes nothing. A
        `request` record is written for any status, so the refusal is on
        record with status 400 and a later sequence number than the record
        before it.
        """
        since = audit_log.mark()
        first = redfish_client.post(RESET_PATH, json={"ResetType": "InvalidType"})
        pytest_assert(first.status_code == 400,
                      "Expected HTTP 400 for ResetType=InvalidType, got: {}".format(first.status_code))
        record, _ = audit_log.wait_for(since, "ResetType=InvalidType", ev="request", uri=RESET_RULE, status=400)
        _assert_record_envelope(record)
        pytest_assert(record.get("method") == "POST" and record.get("action") == RESET_ACTION,
                      "The refused reset must be recorded as POST {}, got: {}".format(RESET_ACTION, record))

        since = audit_log.mark()
        redfish_client.post(RESET_PATH, json={"ResetType": "InvalidType"})
        later, _ = audit_log.wait_for(since, "a second ResetType=InvalidType", ev="request", uri=RESET_RULE)
        pytest_assert(later["seq"] > record["seq"],
                      "Sequence numbers must increase, got {} then {}".format(record["seq"], later["seq"]))
        logger.info("Verified a refused reset was recorded with status 400, seq %s then %s",
                    record["seq"], later["seq"])

    def test_denied_request_recorded(self, bmc_ip, bmc_tls_certs, audit_log):
        """
        A request refused for lack of a credential is recorded as denied, with no user.

        A GET on a privileged resource without a client certificate is
        answered 401 or 403. Its record is `denied` with that status and the
        method, names no user, and does not carry the path that was asked for.
        """
        since = audit_log.mark()
        response = requests.get(
            redfish_url(bmc_ip, PRIVILEGED_PATH, bmc_tls_certs["port"]), verify=bmc_tls_certs["ca"], timeout=30)
        pytest_assert(
            response.status_code in (401, 403),
            "Expected 401 or 403 on {} without a client certificate, got: {}".format(
                PRIVILEGED_PATH, response.status_code))

        record, line = audit_log.wait_for(since, "a request without a certificate", ev="denied")
        _assert_record_envelope(record)
        pytest_assert(
            record.get("status") == response.status_code and record.get("method") == "GET",
            "The denied record must carry GET and status {}, got: {}".format(response.status_code, record)
        )
        pytest_assert("user" not in record, "A denied request has no user to name, got: {}".format(record))
        _assert_absent(line, [PRIVILEGED_PATH])
        logger.info("Verified the request without a certificate was recorded as %s", record)

    def test_read_recorded_only_at_debug(self, redfish_client, audit_log, log_level):
        """
        A GET is recorded only while the log level is DEBUG.

        At the level the BMC runs with, a successful GET adds no record. With
        CONFIG_DB LOGGER|sonic-dbus-bridge LOGLEVEL set to DEBUG, which the
        bridge applies without a restart, the same GET is recorded as `read`
        with the route pattern and status 200. Once the entry is put back the
        GET is no longer recorded.
        """
        def _get_adds_no_record(description):
            since = audit_log.mark()
            assert_status_ok(redfish_client.get(SYSTEM_PATH), SYSTEM_PATH)
            time.sleep(NO_RECORD_SETTLE)
            reads = [record for record, _ in audit_log.added(since) if record.get("ev") == "read"]
            pytest_assert(not reads, "A GET {} must add no read record, got: {}".format(description, reads))

        _get_adds_no_record("at the default log level")

        log_level("DEBUG")
        since = audit_log.mark()
        assert_status_ok(redfish_client.get(SYSTEM_PATH), SYSTEM_PATH)
        record, _ = audit_log.wait_for(since, "a GET at DEBUG", ev="read", uri=SYSTEM_RULE)
        _assert_record_envelope(record)
        pytest_assert(
            record.get("method") == "GET" and record.get("status") == 200 and record.get("user") == CLIENT_CN,
            "The read record must carry GET, status 200 and user {}, got: {}".format(CLIENT_CN, record)
        )

        log_level("INFO")
        _get_adds_no_record("after the log level left DEBUG")
        logger.info("Verified a GET is recorded at DEBUG only: %s", record)

    def test_leak_event_recorded_without_subscriber(self, redfish_client, audit_log, leak_sensor):
        """
        A leak the BMC detects is on record even with nobody subscribed.

        A leak is not a request, so no `request` record covers it. Flipping
        the test sensor to a CRITICAL leak must add an `event` record whose
        msg is the LeakDetectedCritical MessageId and whose detail names the
        sensor, the Severity and the number of subscribers. Clearing the leak
        adds the LeakDetectedNormal record.
        """
        subscriptions = redfish_client.get(SUBSCRIPTIONS_PATH)
        assert_status_ok(subscriptions, SUBSCRIPTIONS_PATH)
        subscribers = subscriptions.json().get("Members@odata.count")

        for state in ("Critical", "OK"):
            message, severity = LEAK_EVENTS[state]
            since = audit_log.mark()
            leak_sensor(state)

            last = {}

            def _event():
                last["added"] = [record for record, _ in audit_log.added(since)]
                return [record for record in last["added"]
                        if record.get("ev") == "event" and str(record.get("msg", "")).endswith("." + message)]

            pytest_assert(
                wait_until(RECORD_TIMEOUT, RECORD_POLL, 0, _event),
                "No event record for {} within {}s of the sensor going {}, records added: {}".format(
                    message, RECORD_TIMEOUT, state, last.get("added"))
            )
            events = _event()
            pytest_assert(len(events) == 1, "One {} must add one event record, got: {}".format(message, events))
            record = events[0]
            _assert_record_envelope(record)
            detail = record.get("detail", {})
            pytest_assert(
                detail.get("resource") == LEAK_SENSOR and detail.get("Severity") == severity
                and detail.get("subscribers") == subscribers,
                "The {} record must name resource {}, Severity {} and {} subscriber(s), got: {}".format(
                    message, LEAK_SENSOR, severity, subscribers, record)
            )
            logger.info("Verified the sensor going %s was recorded as %s", state, record)

    def test_subscription_destination_not_recorded(self, redfish_client, audit_log):
        """
        Creating and deleting a subscription is recorded without the address or context sent.

        Addresses and request bodies are never logged. The POST is recorded
        against the Subscriptions route with status 201 and the DELETE against
        the route pattern of a subscription, and neither line carries the
        Destination host, its path or the Context.
        """
        unrecorded = [UNRECORDED_DESTINATION_HOST, UNRECORDED_DESTINATION_PATH, UNRECORDED_CONTEXT]
        since = audit_log.mark()
        response = redfish_client.post(SUBSCRIPTIONS_PATH, json={
            "Destination": "http://{}:8080/{}".format(UNRECORDED_DESTINATION_HOST, UNRECORDED_DESTINATION_PATH),
            "Protocol": "Redfish",
            "Context": UNRECORDED_CONTEXT,
        })
        pytest_assert(response.status_code == 201,
                      "Expected HTTP 201 from {}, got: {} body={!r}".format(
                          SUBSCRIPTIONS_PATH, response.status_code, response.text[:300]))
        location = response.headers.get("Location", "")
        try:
            created, line = audit_log.wait_for(since, "the subscription POST", ev="request", method="POST",
                                               uri=SUBSCRIPTIONS_PATH)
            pytest_assert(created.get("status") == 201 and created.get("user") == CLIENT_CN,
                          "The subscription record must carry status 201 and user {}, got: {}".format(
                              CLIENT_CN, created))
            _assert_absent(line, unrecorded)
        finally:
            since = audit_log.mark()
            deleted_response = redfish_client.delete(location)

        pytest_assert(deleted_response.status_code in (200, 204),
                      "DELETE {} expected 200/204, got: {}".format(location, deleted_response.status_code))
        deleted, line = audit_log.wait_for(since, "the subscription DELETE", ev="request", method="DELETE",
                                           uri=SUBSCRIPTION_RULE)
        pytest_assert(deleted.get("status") == deleted_response.status_code,
                      "The DELETE record must carry status {}, got: {}".format(
                          deleted_response.status_code, deleted))
        pytest_assert(deleted["seq"] > created["seq"],
                      "Sequence numbers must increase, got {} then {}".format(created["seq"], deleted["seq"]))
        _assert_absent(line, unrecorded)
        logger.info("Verified the subscription was recorded without %s: %s then %s", unrecorded, created, deleted)

    def test_unrouted_path_not_recorded(self, redfish_client, audit_log):
        """
        A request to a path the BMC does not serve is recorded without the path sent.

        The uri of a record is the route pattern, never the caller's text. A
        POST to an unknown path is answered 404 or 405 and recorded with that
        status, and the path does not appear in the line.
        """
        since = audit_log.mark()
        response = redfish_client.post(UNROUTED_PATH, json={})
        pytest_assert(response.status_code in (404, 405),
                      "Expected 404 or 405 from {}, got: {}".format(UNROUTED_PATH, response.status_code))
        record, line = audit_log.wait_for(since, "a POST to an unknown path", ev="request", method="POST",
                                          status=response.status_code)
        _assert_record_envelope(record)
        _assert_absent(line, [UNROUTED_MARKER])
        logger.info("Verified the unknown path was recorded as %s", record)
