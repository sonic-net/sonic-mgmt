"""
Tests for Redfish EventService push subscriptions on the SONiC BMC.

A rack manager subscribes for events by POSTing an EventDestination with its
webhook URL; when the BMC raises an event, bmcweb POSTs an
``#Event.v1_4_0.Event`` payload to that URL. Here the sonic-mgmt test plays
the rack manager: it creates the subscriptions, raises events on the BMC and
verifies what its webhook endpoint received.

Events are raised through the SONiC-BMC leak detection path (sonic-redfish):
a platform daemon writes ``LIQUID_COOLING_INFO|<sensor>`` to STATE_DB,
``sonic-dbus-bridge`` mirrors it as
``xyz.openbmc_project.Inventory.Item.LeakDetector`` on D-Bus, and bmcweb's
rmc-events leak monitor turns each ``DetectorState`` change into an
``Environmental.1.1.LeakDetected{Critical,Warning,Normal}`` event with
resource type ``LeakDetector``. The test stands in for the platform daemon by
seeding a synthetic sensor row and flipping its state.

The tests cover what a rack manager uses: POST EventService/Subscriptions,
the leak and switch-host power events it then receives, and the resources
those events point at. Other EventService features (SubmitTestEvent, SSE,
PATCH, retry policies) are not exercised here.

Switch-host power events come from bmcctld's HOST_STATE|switch-host row:
``sonic-dbus-bridge`` mirrors device_power_state/device_status into
``xyz.openbmc_project.State.Host`` CurrentHostState and bmcweb's host state
monitor turns each change into a ``ResourceEvent.1.3.ResourcePower*``
event on the ComputerSystem. The power tests drive real transitions through
ComputerSystem.Reset, so bmcctld writes the row and the events come out of
the live chain. Only the leak sensor is simulated, standing in for thermalctld.

The webhook endpoint is ``redfish_event_listener.py`` running on the PTF
host, the test infrastructure sitting on the BMC's management subnet. That
keeps the rack manager outside the BMC (neither in the redfish container nor
on the BMC host) while remaining reachable from a BMC that has no route to
the test runner. Reachability is confirmed with a probe POST issued from
inside the redfish container, the exact network path bmcweb uses.
"""
import json
import logging
import os
import shlex
import time

import pytest
import requests

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.sonic_db import STATE_DB, redis_del, redis_hgetall, redis_hset, redis_keys
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    assert_field_contains,
    assert_field_equals,
    assert_field_nonempty,
    assert_no_content,
    assert_redfish_error,
    assert_status_ok,
    BMCCTLD,
    BMCCTLD_TIMEOUT,
    BRIDGE_SERVICE,
    COMMAND_DONE_TIMEOUT,
    command_done,
    command_keys,
    host_is_settled_on,
    is_bmcctld_running,
    remove_new_commands,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

EVENT_SERVICE_PATH = "/redfish/v1/EventService"
SUBSCRIPTIONS_PATH = "{}/Subscriptions".format(EVENT_SERVICE_PATH)
SERVICE_ROOT = "/redfish/v1"

REDFISH_CONTAINER = "redfish"

RECEIVER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "redfish_event_listener.py")
PTF_RECEIVER_SCRIPT = "/tmp/redfish_event_listener.py"
PTF_RECEIVER_OUTPUT = "/tmp/redfish_events.jsonl"
PTF_RECEIVER_LOG = "/tmp/redfish_event_listener.log"
# Fixed so the "closed port next to the receiver" used by the retry test is predictable.
RECEIVER_PORT = 18081
# pkill pattern that matches the receiver but not the shell issuing the pkill.
PTF_RECEIVER_PKILL = "pkill -f '[p]ython3 {}' || true".format(PTF_RECEIVER_SCRIPT)

# bmcweb delivers asynchronously and the PTF receiver's output is read over SSH per poll.
DELIVERY_TIMEOUT = 30
DELIVERY_POLL = 2
NO_DELIVERY_SETTLE = 8
BMCWEB_READY_TIMEOUT = 90
BRIDGE_READY_TIMEOUT = 60

EVENT_ODATA_TYPE = "#Event.v1_4_0.Event"

# Synthetic leak sensor the test plays platform daemon for. The row is seeded
# once per module while the bridge is running, as thermalctld publishes one.
LEAK_SENSOR = "rmc_test_leak"
LEAK_SENSOR_KEY = "LIQUID_COOLING_INFO|{}".format(LEAK_SENSOR)
LEAK_SENSOR_DBUS_PATH = "/xyz/openbmc_project/sensors/leak/{}".format(LEAK_SENSOR)
LEAK_DETECTOR_IFACE = "xyz.openbmc_project.Inventory.Item.LeakDetector"
BRIDGE_BUS_NAME = "xyz.openbmc_project.Inventory.Manager"
# OriginOfCondition of the test sensor's leak events, under the Chassis named "chassis"
# as in pmon-bmc-design.md section 2.1.2.
LEAK_ORIGIN = "/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors/{}".format(LEAK_SENSOR)
# The same detector at the canonical Chassis-level collection (Chassis schema v1.26.0) the Chassis links.
LEAK_ORIGIN_CANONICAL = "/redfish/v1/Chassis/chassis/LeakDetectors/{}".format(LEAK_SENSOR)
LEAK_REGISTRY = "Environmental"
LEAK_RESOURCE_TYPE = "LeakDetector"
# STATE_DB fields per detector state, as thermalctld writes them and
# sonic-dbus-bridge's LeakSensor::detectorState() maps them. Unavailable is
# a faulted sensor whose leak state cannot be read (sonic-redfish design section 7.6).
LEAK_STATES = {
    "OK": {"leaking": "No", "leak_status": "No", "leak_severity": "None", "leak_sensor_status": "Good"},
    "Warning": {"leaking": "Yes", "leak_status": "Yes", "leak_severity": "MINOR", "leak_sensor_status": "Good"},
    "Critical": {"leaking": "Yes", "leak_status": "Yes", "leak_severity": "CRITICAL", "leak_sensor_status": "Good"},
    "Unavailable": {"leaking": "N/A", "leak_status": "N/A", "leak_severity": "None", "leak_sensor_status": "Fault"},
    # thermalctld writes a fault with leaking N/A. A faulted sensor still reading No
    # cannot vouch for it, so the bridge maps this to Unavailable as well.
    "FaultNotLeaking": {"leaking": "No", "leak_status": "No", "leak_severity": "None", "leak_sensor_status": "Fault"},
}
# A sensor that faults while it still reads a leak. The leak is kept as the DetectorState.
LEAKING_FAULT_STATES = {
    leak: dict(LEAK_STATES[leak], leak_sensor_status="Fault") for leak in ("Critical", "Warning")
}
# The two STATE_DB forms of a faulted sensor. Both are DetectorState Unavailable.
LEAK_FAULT_STATES = ("Unavailable", "FaultNotLeaking")
# Event raised as a detector enters Unavailable (Warning) or leaves it with the
# health it comes back with (OK, Critical): (MessageId, Severity).
LEAK_STATUS_EVENTS = {
    "Warning": ("ResourceEvent.1.3.ResourceStatusChangedWarning", "Warning"),
    "OK": ("ResourceEvent.1.3.ResourceStatusChangedOK", "OK"),
    "Critical": ("ResourceEvent.1.3.ResourceStatusChangedCritical", "Critical"),
}
LEAK_SENSOR_KEY_GLOB = "LIQUID_COOLING_INFO|*"
# A second synthetic sensor, written while the bridge is already running.
LATE_LEAK_SENSOR = "rmc_test_leak_late"
LATE_LEAK_SENSOR_KEY = "LIQUID_COOLING_INFO|{}".format(LATE_LEAK_SENSOR)
LATE_LEAK_ORIGIN = "/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors/{}".format(
    LATE_LEAK_SENSOR)
LATE_LEAK_ORIGIN_CANONICAL = "/redfish/v1/Chassis/chassis/LeakDetectors/{}".format(LATE_LEAK_SENSOR)
# Event bmcweb's leak monitor emits for each detector state: (MessageId, Severity, Message).
LEAK_EVENTS = {
    "Critical": ("Environmental.1.1.LeakDetectedCritical", "Critical",
                 "Leak detector '{}' reports a critical level leak.".format(LEAK_SENSOR)),
    "Warning": ("Environmental.1.1.LeakDetectedWarning", "Warning",
                "Leak detector '{}' reports a warning level leak.".format(LEAK_SENSOR)),
    "OK": ("Environmental.1.1.LeakDetectedNormal", "OK",
           "Leak detector '{}' has returned to normal.".format(LEAK_SENSOR)),
}

# Switch-host power state as bmcctld publishes it and the event each value produces.
HOST_STATE_KEY = "HOST_STATE|switch-host"
HOST_REGISTRY = "ResourceEvent"
HOST_RESOURCE_TYPE = "ComputerSystem"
SYSTEM_ORIGIN = "/redfish/v1/Systems/system"
RESET_PATH = "{}/Actions/ComputerSystem.Reset".format(SYSTEM_ORIGIN)
# Events the host state monitor raises as the switch host goes off and comes back, in delivery order.
HOST_POWER_EVENTS = {
    "PoweringOff": ("ResourceEvent.1.3.ResourcePoweringOff", "The resource `system` is powering off."),
    "PoweredOff": ("ResourceEvent.1.3.ResourcePoweredOff", "The resource `system` has powered off."),
    "PoweringOn": ("ResourceEvent.1.3.ResourcePoweringOn", "The resource `system` is powering on."),
    "PoweredOn": ("ResourceEvent.1.3.ResourcePoweredOn", "The resource `system` has powered on."),
}
EVENT_NAME_BY_MESSAGE_ID = {message_id: name for name, (message_id, _) in HOST_POWER_EVENTS.items()}
POWER_OFF_ON_SEQUENCE = ("PoweringOff", "PoweredOff", "PoweringOn", "PoweredOn")
# A GracefulShutdown gives the host graceful_shutdown_timeout to go down on its own before power is removed.
HOST_OFF_TIMEOUT = 240
HOST_ON_TIMEOUT = 120
HOST_STATE_POLL = 5
CHASSIS_PATH = "/redfish/v1/Chassis/chassis"
# A HOST_STATE row neither of whose fields maps to a host state.
UNRECOGNISED_HOST_STATE = {"device_power_state": "RMC_TEST_UNRECOGNISED", "device_status": "RMC_TEST_UNRECOGNISED"}

# Runs a POST from inside the redfish container: exactly the network path bmcweb uses.
PROBE_SNIPPET = ("import sys, urllib.request; "
                 "r = urllib.request.urlopen(urllib.request.Request(sys.argv[1], data=b'{}', method='POST'), "
                 "timeout=5); print(r.status)")


def _container_shell(bmc_duthost, cmd, **kwargs):
    return bmc_duthost.shell("docker exec {} sh -c {}".format(REDFISH_CONTAINER, shlex.quote(cmd)), **kwargs)


def _compact(text, limit=700):
    """One-line, truncated rendering of a response body for the run log."""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "...(truncated)"


def _redfish(redfish_client, method, path, **kwargs):
    """Issue a Redfish call and log request and response so the run log reads as a transcript."""
    body = kwargs.get("json")
    logger.info("RMC --> %s %s%s", method, path,
                " body=" + json.dumps(body, sort_keys=True) if body is not None else "")
    response = getattr(redfish_client, method.lower())(path, **kwargs)
    extras = ""
    if "Location" in response.headers:
        extras += " Location=" + response.headers["Location"]
    if response.text.strip():
        extras += " body=" + _compact(response.text)
    logger.info("BMC <-- %s %s HTTP %s%s", method, path, response.status_code, extras)
    return response


def _reachable_from_redfish_container(bmc_duthost, url):
    """True iff a POST from inside the redfish container reaches `url` and gets 204 back."""
    res = bmc_duthost.shell(
        "docker exec {} python3 -c {} {}".format(REDFISH_CONTAINER, shlex.quote(PROBE_SNIPPET), shlex.quote(url)),
        module_ignore_errors=True,
    )
    return res["rc"] == 0 and res["stdout"].strip() == "204"


def _subscription_ids(redfish_client):
    response = redfish_client.get(SUBSCRIPTIONS_PATH)
    assert_status_ok(response, SUBSCRIPTIONS_PATH)
    return [m["@odata.id"].rsplit("/", 1)[1] for m in response.json().get("Members", [])]


def _delete_all_subscriptions(redfish_client):
    leftovers = _subscription_ids(redfish_client)
    if leftovers:
        logger.info("Removing existing subscriptions: %s", leftovers)
    for sub_id in leftovers:
        _redfish(redfish_client, "DELETE", "{}/{}".format(SUBSCRIPTIONS_PATH, sub_id))


def _subscribe(redfish_client, destination, context, **extra):
    """POST a RedfishEvent push subscription; return (id, path)."""
    body = {"Destination": destination, "Protocol": "Redfish", "Context": context}
    body.update(extra)
    response = _redfish(redfish_client, "POST", SUBSCRIPTIONS_PATH, json=body)
    pytest_assert(
        response.status_code == 201,
        "Subscribe {} expected HTTP 201, got: {} body={!r}".format(body, response.status_code, response.text[:500])
    )
    location = response.headers.get("Location", "")
    pytest_assert(
        location.startswith(SUBSCRIPTIONS_PATH + "/"),
        "Location must point under {}, got: {!r}".format(SUBSCRIPTIONS_PATH, location)
    )
    sub_id = location.rsplit("/", 1)[1]
    logger.info("Subscription %s created: Destination=%s Context=%s", sub_id, destination, context)
    return sub_id, location


def _wait_for_deliveries(receiver, name, count, timeout=DELIVERY_TIMEOUT):
    """Return the payloads POSTed to receiver path `name` once at least `count` arrived."""
    pytest_assert(
        wait_until(timeout, DELIVERY_POLL, 0, lambda: len(receiver.deliveries(name)) >= count),
        "Expected {} event delivery(ies) at {} within {}s, got: {}".format(
            count, receiver.url(name), timeout, receiver.deliveries(name))
    )
    payloads = receiver.deliveries(name)
    logger.info("RMC endpoint %s has received %d POST(s); latest payload: %s",
                receiver.url(name), len(payloads), _compact(json.dumps(payloads[-1], sort_keys=True)))
    return payloads


def _assert_event_envelope(payload):
    assert_field_equals(payload, "@odata.type", EVENT_ODATA_TYPE)
    pytest_assert(
        str(payload.get("Id", "")).isdigit(),
        "Event payload Id must be a numeric string, got: {!r}".format(payload.get("Id"))
    )
    events = payload.get("Events")
    pytest_assert(
        isinstance(events, list) and events,
        "Event payload must carry a non-empty Events array, got: {!r}".format(events)
    )
    return events


def _assert_leak_event(event, state):
    """Check an event record is the leak monitor's event for `state` on the test sensor."""
    message_id, severity, message = LEAK_EVENTS[state]
    assert_field_equals(event, "MessageId", message_id)
    assert_field_equals(event, "Severity", severity)
    assert_field_equals(event, "Message", message)
    assert_field_equals(event, "MessageArgs", [LEAK_SENSOR])
    assert_field_equals(event, "MemberId", "0")
    pytest_assert(
        event.get("OriginOfCondition", {}).get("@odata.id") == LEAK_ORIGIN,
        "OriginOfCondition must be {!r}, got: {!r}".format(LEAK_ORIGIN, event.get("OriginOfCondition"))
    )
    pytest_assert(
        isinstance(event.get("EventTimestamp"), str) and event["EventTimestamp"],
        "EventTimestamp must be a non-empty string, got: {!r}".format(event.get("EventTimestamp"))
    )
    pytest_assert(
        str(event.get("EventId", "")).isdigit(),
        "EventId must be numeric, got: {!r}".format(event.get("EventId"))
    )


def _host_state(bmc_duthost):
    return redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)


def _host_is_settled_on(bmc_duthost):
    return host_is_settled_on(_host_state(bmc_duthost))


def _reset(redfish_client, reset_type):
    response = _redfish(redfish_client, "POST", RESET_PATH, json={"ResetType": reset_type})
    assert_no_content(response, RESET_PATH)


def _delivered_message_ids(payloads, collapse_repeats=False, only=None):
    """MessageId of every event delivered, in order, limited to those in `only` when given.

    bmcctld writes two transitional values on the way down (GRACEFUL_SHUTTING_DOWN,
    then POWERING_OFF) that the bridge maps to the same CurrentHostState, so the
    same event can be raised twice in a row. collapse_repeats folds those.
    """
    ids = []
    for payload in payloads:
        for event in payload.get("Events", []):
            message_id = event.get("MessageId")
            if only is not None and message_id not in only:
                continue
            if not (collapse_repeats and ids and ids[-1] == message_id):
                ids.append(message_id)
    return ids


def _wait_for_power_event(receiver, name, event_name, timeout):
    """Return every payload delivered to receiver path `name` once the `event_name` power event is among them."""
    message_id = HOST_POWER_EVENTS[event_name][0]
    pytest_assert(
        wait_until(timeout, DELIVERY_POLL, 0, lambda: message_id in _delivered_message_ids(receiver.deliveries(name))),
        "{} did not reach {} within {}s, deliveries so far: {}".format(
            message_id, receiver.url(name), timeout, _delivered_message_ids(receiver.deliveries(name)))
    )
    payloads = receiver.deliveries(name)
    logger.info("RMC endpoint %s has %s after %d delivery(ies)", receiver.url(name), message_id, len(payloads))
    return payloads


def _power_event(payloads, event_name):
    """The event record for `event_name` among delivered payloads, envelope checked."""
    return _event_with_id(payloads, HOST_POWER_EVENTS[event_name][0])


def _assert_host_power_event(event, event_name):
    """Check an event record is the host state monitor's `event_name` event."""
    message_id, message = HOST_POWER_EVENTS[event_name]
    assert_field_equals(event, "MessageId", message_id)
    assert_field_equals(event, "Severity", "OK")
    assert_field_equals(event, "Message", message)
    assert_field_equals(event, "MessageArgs", ["system"])
    assert_field_equals(event, "MemberId", "0")
    pytest_assert(
        event.get("OriginOfCondition", {}).get("@odata.id") == SYSTEM_ORIGIN,
        "OriginOfCondition must be {!r}, got: {!r}".format(SYSTEM_ORIGIN, event.get("OriginOfCondition"))
    )
    pytest_assert(
        isinstance(event.get("EventTimestamp"), str) and event["EventTimestamp"],
        "EventTimestamp must be a non-empty string, got: {!r}".format(event.get("EventTimestamp"))
    )


def _assert_leak_status_event(event, health):
    """Check an event record is the ResourceStatusChanged<health> event for the test sensor."""
    message_id, severity = LEAK_STATUS_EVENTS[health]
    assert_field_equals(event, "MessageId", message_id)
    assert_field_equals(event, "Severity", severity)
    assert_field_equals(event, "MessageArgs", [LEAK_SENSOR, health])
    pytest_assert(
        event.get("OriginOfCondition", {}).get("@odata.id") == LEAK_ORIGIN,
        "OriginOfCondition must be {!r}, got: {!r}".format(LEAK_ORIGIN, event.get("OriginOfCondition"))
    )
    pytest_assert(
        isinstance(event.get("EventTimestamp"), str) and event["EventTimestamp"],
        "EventTimestamp must be a non-empty string, got: {!r}".format(event.get("EventTimestamp"))
    )


def _event_with_id(payloads, message_id):
    """The first event record carrying `message_id` among delivered payloads, envelope checked."""
    event = next(
        (record for payload in payloads for record in _assert_event_envelope(payload)
         if record.get("MessageId") == message_id),
        None)
    pytest_assert(event is not None,
                  "{} not found in deliveries: {}".format(message_id, _delivered_message_ids(payloads)))
    return event


def _events_for(payloads, sensor):
    """Every delivered event record whose first MessageArg is `sensor`, in order."""
    return [event for payload in payloads for event in payload.get("Events", [])
            if (event.get("MessageArgs") or [None])[0] == sensor]


def _seed_late_sensor(bmc_duthost, state):
    """Write the late sensor's row in `state` while the bridge is running."""
    fields = dict(LEAK_STATES[state], type="leak", location="rmc-test")
    redis_hset(bmc_duthost, STATE_DB, LATE_LEAK_SENSOR_KEY, **fields)
    logger.info("Seeded STATE_DB %s with %s while %s is running", LATE_LEAK_SENSOR_KEY, fields, BRIDGE_SERVICE)


def _get_body(redfish_client, path):
    """JSON body of a 200 GET on `path`, or {} while the BMC cannot answer it."""
    try:
        response = redfish_client.get(path)
    except requests.exceptions.RequestException:
        return {}
    return response.json() if response.status_code == 200 else {}


def _wait_for_body(redfish_client, path, predicate, timeout, poll=DELIVERY_POLL):
    """Poll GET `path` until `predicate(body)` holds. Returns (held, the last body read)."""
    last = {}

    def _check():
        last["body"] = _get_body(redfish_client, path)
        return predicate(last["body"])

    held = wait_until(timeout, poll, 0, _check)
    return held, last.get("body", {})


def _wait_for_message_ids(receiver, name, wanted, timeout=DELIVERY_TIMEOUT):
    """Poll receiver path `name` until every MessageId in `wanted` arrived.

    Returns (arrived, the last payloads read).
    """
    last = {}

    def _check():
        last["payloads"] = receiver.deliveries(name)
        return set(wanted) <= set(_delivered_message_ids(last["payloads"]))

    arrived = wait_until(timeout, DELIVERY_POLL, 0, _check)
    return arrived, last.get("payloads", [])


def _host_state_published(bmc_duthost):
    """True once HOST_STATE|switch-host holds a row other than the unrecognised one a test wrote."""
    state = _host_state(bmc_duthost)
    return bool(state) and any(state.get(field) != value for field, value in UNRECOGNISED_HOST_STATE.items())


def _reports_unknown_power(body):
    return bool(body) and "PowerState" not in body and body.get("Status", {}).get("State") == "UnavailableOffline"


def _wait_for_bmcweb(redfish_client, bmc_duthost):
    def _up():
        res = _container_shell(bmc_duthost, "supervisorctl status bmcweb", module_ignore_errors=True)
        if "RUNNING" not in res["stdout"]:
            return False
        try:
            return redfish_client.get(SERVICE_ROOT).status_code == 200
        except requests.exceptions.RequestException:
            return False
    pytest_assert(
        wait_until(BMCWEB_READY_TIMEOUT, 3, 0, _up),
        "bmcweb did not come back within {}s".format(BMCWEB_READY_TIMEOUT)
    )


def _leak_detector_state(bmc_duthost):
    """DetectorState of the test sensor as exported by sonic-dbus-bridge, or None if absent."""
    res = _container_shell(
        bmc_duthost,
        "dbus-send --system --print-reply --dest={} {} org.freedesktop.DBus.Properties.Get "
        "string:{} string:DetectorState".format(BRIDGE_BUS_NAME, LEAK_SENSOR_DBUS_PATH, LEAK_DETECTOR_IFACE),
        module_ignore_errors=True,
    )
    if res["rc"] != 0:
        return None
    marker = "{}.DetectorState.".format(LEAK_DETECTOR_IFACE)
    for token in res["stdout"].replace('"', " ").split():
        if token.startswith(marker):
            return token[len(marker):]
    return None


def _restart_bridge(bmc_duthost, **kwargs):
    logger.info("Restarting %s in the %s container", BRIDGE_SERVICE, REDFISH_CONTAINER)
    _container_shell(bmc_duthost, "supervisorctl restart {}".format(BRIDGE_SERVICE), **kwargs)


class RmcReceiver:
    """The rack manager's webhook endpoint as seen by the tests."""

    def __init__(self, base_url, fetch):
        self.base_url = base_url
        self._fetch = fetch

    def url(self, name):
        return "{}/{}".format(self.base_url, name)

    def deliveries(self, name):
        return [r["body"] for r in self._fetch() if r["path"] == "/{}".format(name)]


@pytest.fixture(scope="module")
def rmc_receiver(bmc_duthost, ptfhost, redfish_feature_enabled):
    """Start the rack manager's webhook endpoint on the PTF host.

    The standalone listener runs on the PTF and is addressed by the PTF's
    management IP. Reachability is confirmed with a POST issued from inside
    the redfish container, i.e. the exact network path bmcweb will use for
    deliveries.
    """
    pyrequire(ptfhost is not None, "This topology has no PTF host to run the rack manager's webhook endpoint on")
    base_url = "http://{}:{}".format(ptfhost.mgmt_ip, RECEIVER_PORT)

    ptfhost.copy(src=RECEIVER_SCRIPT, dest=PTF_RECEIVER_SCRIPT)
    ptfhost.shell("{}; rm -f {}".format(PTF_RECEIVER_PKILL, PTF_RECEIVER_OUTPUT))
    ptfhost.shell(
        "nohup python3 {} --port {} --output {} </dev/null >{} 2>&1 &".format(
            PTF_RECEIVER_SCRIPT, RECEIVER_PORT, PTF_RECEIVER_OUTPUT, PTF_RECEIVER_LOG))
    pyrequire(
        wait_until(20, 2, 0, _reachable_from_redfish_container, bmc_duthost, base_url + "/probe"),
        "redfish container cannot reach the RMC receiver on the PTF at {}; receiver log: {}".format(
            base_url, ptfhost.shell("cat {}".format(PTF_RECEIVER_LOG), module_ignore_errors=True)["stdout"])
    )
    logger.info("RMC receiver running on PTF %s at %s", ptfhost.hostname, base_url)

    def _fetch():
        out = ptfhost.shell("cat {}".format(PTF_RECEIVER_OUTPUT), module_ignore_errors=True)["stdout"]
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    yield RmcReceiver(base_url, _fetch)

    ptfhost.shell("{}; rm -f {} {} {}".format(
        PTF_RECEIVER_PKILL, PTF_RECEIVER_SCRIPT, PTF_RECEIVER_OUTPUT, PTF_RECEIVER_LOG),
        module_ignore_errors=True)


@pytest.fixture(scope="function")
def clean_subscriptions(redfish_client):
    """No subscriptions before or after a test.

    bmcweb persists subscriptions across restarts, so leftovers from an
    aborted run would otherwise receive (and count as) deliveries here.
    """
    _delete_all_subscriptions(redfish_client)
    yield
    _delete_all_subscriptions(redfish_client)


@pytest.fixture(scope="module")
def leak_sensor(bmc_duthost, redfish_client, redfish_feature_enabled):
    """A synthetic leak sensor exported by sonic-dbus-bridge; returns a state injector.

    Skips unless bmcweb advertises the Environmental registry and the
    LeakDetector resource type, i.e. was built with sonic-redfish rmc-events.
    Seeds LIQUID_COOLING_INFO|<sensor> in STATE_DB the way thermalctld would
    and waits until the running bridge answers for the LeakDetector object on
    D-Bus. The injector rewrites the row's leak fields, which the bridge
    turns into a DetectorState change.
    """
    body = redfish_client.get(EVENT_SERVICE_PATH).json()
    pyrequire(
        LEAK_REGISTRY in body.get("RegistryPrefixes", []) and LEAK_RESOURCE_TYPE in body.get("ResourceTypes", []),
        "EventService does not advertise the {} registry and {} resource type (RegistryPrefixes={} "
        "ResourceTypes={}); this bmcweb was built without sonic-redfish rmc-events".format(
            LEAK_REGISTRY, LEAK_RESOURCE_TYPE, body.get("RegistryPrefixes"), body.get("ResourceTypes"))
    )

    def _hset(fields):
        redis_hset(bmc_duthost, STATE_DB, LEAK_SENSOR_KEY, **fields)

    seed = dict(LEAK_STATES["OK"], type="leak", location="rmc-test")
    _hset(seed)
    logger.info("Seeded STATE_DB %s with %s", LEAK_SENSOR_KEY, seed)
    pytest_assert(
        wait_until(BRIDGE_READY_TIMEOUT, 3, 0, lambda: _leak_detector_state(bmc_duthost) == "OK"),
        "{} did not export {} with DetectorState OK within {}s of the row being written".format(
            BRIDGE_SERVICE, LEAK_SENSOR_DBUS_PATH, BRIDGE_READY_TIMEOUT)
    )
    logger.info("%s exports %s on D-Bus (DetectorState=OK)", BRIDGE_SERVICE, LEAK_SENSOR_DBUS_PATH)

    def _set_state(state, fields=None):
        fields = fields or LEAK_STATES[state]
        _hset(fields)
        logger.info("BMC leak sensor %s set to %s via STATE_DB %s", LEAK_SENSOR, state, fields)

    yield _set_state

    bmc_duthost.shell("sonic-db-cli STATE_DB DEL {}".format(shlex.quote(LEAK_SENSOR_KEY)), module_ignore_errors=True)
    _restart_bridge(bmc_duthost, module_ignore_errors=True)


@pytest.fixture(scope="function")
def leak_event(bmc_duthost, leak_sensor, clean_subscriptions):
    """Leak sensor back at OK with no subscriptions, so each test starts from a quiet BMC.

    Resetting to OK before any subscription exists means the LeakDetectedNormal
    a previous test's Critical would produce has nobody to be delivered to.
    """
    leak_sensor("OK")
    pytest_assert(
        wait_until(15, 1, 0, lambda: _leak_detector_state(bmc_duthost) == "OK"),
        "{} did not return {} to DetectorState OK".format(BRIDGE_SERVICE, LEAK_SENSOR_DBUS_PATH)
    )
    yield leak_sensor


@pytest.fixture(scope="function")
def host_power_restored(redfish_client, bmc_duthost):
    """Require the switch host settled on before a power test and power it back on if the test leaves it off.

    The power tests take the host down for real through ComputerSystem.Reset,
    so a failure part-way must not leave it off for the rest of the run.
    """
    before = _host_state(bmc_duthost)
    pyrequire(host_is_settled_on(before),
              "{} must show the switch host settled on before a power test, got: {}".format(HOST_STATE_KEY, before))

    yield

    if _host_is_settled_on(bmc_duthost):
        return
    logger.warning("%s is %s after the test, powering the switch host back on",
                   HOST_STATE_KEY, _host_state(bmc_duthost))
    _reset(redfish_client, "On")
    pytest_assert(wait_until(HOST_ON_TIMEOUT, HOST_STATE_POLL, 0, _host_is_settled_on, bmc_duthost),
                  "{} did not settle on within {}s of ResetType=On: {}".format(
                      HOST_STATE_KEY, HOST_ON_TIMEOUT, _host_state(bmc_duthost)))


@pytest.fixture(scope="function")
def late_leak_sensor(bmc_duthost, leak_event):
    """Remove the late sensor row afterwards and restart the bridge so it no longer exports it.

    Depends on leak_event so the main sensor is at OK, which the teardown waits for again.
    """
    yield LATE_LEAK_SENSOR_KEY
    redis_del(bmc_duthost, STATE_DB, LATE_LEAK_SENSOR_KEY)
    _restart_bridge(bmc_duthost, module_ignore_errors=True)
    pytest_assert(
        wait_until(BRIDGE_READY_TIMEOUT, 3, 0, lambda: _leak_detector_state(bmc_duthost) == "OK"),
        "{} did not export {} again within {}s of restarting".format(
            BRIDGE_SERVICE, LEAK_SENSOR_DBUS_PATH, BRIDGE_READY_TIMEOUT)
    )


@pytest.fixture(scope="function")
def bmcctld_stopped(bmc_duthost):
    """Stop bmcctld so HOST_STATE|switch-host stays absent, and start it again afterwards.

    bmcctld republishes HOST_STATE from the live oper status when it starts,
    so starting it is also how the test ends the unknown state. The yielded
    callable starts it and reports whether it is RUNNING and has republished
    the row. Every RACK_MANAGER_COMMAND row the test created is removed
    afterwards, before bmcctld is started if the test did not get that far, so
    a failed test cannot leave it a command to execute.
    """
    pyrequire(is_bmcctld_running(bmc_duthost), "{} is not RUNNING in the pmon container".format(BMCCTLD))
    keys_before = command_keys(bmc_duthost)

    def _start():
        logger.info("Starting %s in the pmon container", BMCCTLD)
        bmc_duthost.start_pmon_daemon(BMCCTLD)
        return (wait_until(BMCCTLD_TIMEOUT, HOST_STATE_POLL, 0, is_bmcctld_running, bmc_duthost)
                and wait_until(BMCCTLD_TIMEOUT, HOST_STATE_POLL, 0, _host_state_published, bmc_duthost))

    try:
        logger.info("Stopping %s in the pmon container", BMCCTLD)
        bmc_duthost.stop_pmon_daemon_service(BMCCTLD)
        yield _start
    finally:
        running = is_bmcctld_running(bmc_duthost)
        if running:
            # bmcctld writes a status to a command it took, which would bring a deleted row back.
            wait_until(COMMAND_DONE_TIMEOUT, DELIVERY_POLL, 0, lambda: all(
                command_done(bmc_duthost, key) for key in command_keys(bmc_duthost) - keys_before))
        remove_new_commands(bmc_duthost, keys_before)
        if not running:
            pytest_assert(_start(), "{} did not start and republish {} within {}s".format(
                BMCCTLD, HOST_STATE_KEY, BMCCTLD_TIMEOUT))


class TestRedfishEventSubscription:

    def test_event_service_advertised(self, redfish_client):
        """
        EventService is enabled and advertises what a rack manager needs to subscribe.

        GET /redfish/v1/EventService: ServiceEnabled, the Subscriptions
        collection link and the registry prefixes the BMC can filter on (Base
        and OpenBMC at least). Whether the Environmental registry and
        LeakDetector resource type are advertised is logged, and gates the
        leak-event tests below.
        """
        response = redfish_client.get(EVENT_SERVICE_PATH)
        assert_status_ok(response, EVENT_SERVICE_PATH)
        body = response.json()
        logger.info("EventService: {}".format(body))

        assert_field_equals(body, "@odata.id", EVENT_SERVICE_PATH)
        assert_field_equals(body, "ServiceEnabled", True)
        pytest_assert(
            body.get("Status", {}).get("State") == "Enabled",
            "Status.State must be 'Enabled', got: {!r}".format(body.get("Status"))
        )
        pytest_assert(
            body.get("Subscriptions", {}).get("@odata.id") == SUBSCRIPTIONS_PATH,
            "Subscriptions link must be {!r}, got: {!r}".format(SUBSCRIPTIONS_PATH, body.get("Subscriptions"))
        )
        prefixes = set(body.get("RegistryPrefixes", []))
        pytest_assert(
            {"Base", "OpenBMC"} <= prefixes,
            "RegistryPrefixes must include Base and OpenBMC, got: {}".format(sorted(prefixes))
        )
        logger.info("Leak events advertised: %s registry=%s, %s resource type=%s", LEAK_REGISTRY,
                    LEAK_REGISTRY in prefixes, LEAK_RESOURCE_TYPE, LEAK_RESOURCE_TYPE in body.get("ResourceTypes", []))

    def test_event_service_advertises_rack_manager_filters(self, redfish_client):
        """
        EventService advertises the filters the rack manager's subscriptions use.

        Leak events come from the Environmental registry on LeakDetector
        resources and switch-host power events from the ResourceEvent registry
        on the ComputerSystem. bmcweb refuses a subscription that filters on a
        RegistryPrefix or ResourceType it does not list, so all four must be
        advertised.
        """
        response = redfish_client.get(EVENT_SERVICE_PATH)
        assert_status_ok(response, EVENT_SERVICE_PATH)
        body = response.json()
        prefixes = set(body.get("RegistryPrefixes", []))
        resource_types = set(body.get("ResourceTypes", []))
        pytest_assert(
            {LEAK_REGISTRY, HOST_REGISTRY} <= prefixes,
            "RegistryPrefixes must include {} and {}, got: {}".format(LEAK_REGISTRY, HOST_REGISTRY, sorted(prefixes))
        )
        pytest_assert(
            {LEAK_RESOURCE_TYPE, HOST_RESOURCE_TYPE} <= resource_types,
            "ResourceTypes must include {} and {}, got: {}".format(
                LEAK_RESOURCE_TYPE, HOST_RESOURCE_TYPE, sorted(resource_types))
        )
        logger.info("Verified EventService advertises RegistryPrefixes %s and ResourceTypes %s",
                    sorted(prefixes), sorted(resource_types))

    def test_subscription_lifecycle(self, redfish_client, rmc_receiver, clean_subscriptions):
        """
        A push subscription can be created, read back and removed.

        POST -> 201 with Location; GET echoes the destination, context and the
        defaults bmcweb applies (Protocol Redfish, SubscriptionType
        RedfishEvent, EventFormatType Event); the collection lists it; DELETE
        removes it and a further GET is 404.
        """
        destination = rmc_receiver.url("lifecycle")
        sub_id, path = _subscribe(redfish_client, destination, "ctx-lifecycle")

        response = _redfish(redfish_client, "GET", path)
        assert_status_ok(response, path)
        body = response.json()
        assert_field_equals(body, "@odata.id", path)
        assert_field_equals(body, "Id", sub_id)
        assert_field_equals(body, "Destination", destination)
        assert_field_equals(body, "Context", "ctx-lifecycle")
        assert_field_equals(body, "Protocol", "Redfish")
        assert_field_equals(body, "SubscriptionType", "RedfishEvent")
        assert_field_equals(body, "EventFormatType", "Event")
        assert_field_equals(body, "RegistryPrefixes", [])
        assert_field_equals(body, "MessageIds", [])
        pytest_assert(
            sub_id in _subscription_ids(redfish_client),
            "Subscription {} missing from {}".format(sub_id, SUBSCRIPTIONS_PATH)
        )

        logger.info("Verified GET shows the subscribed Destination/Context and bmcweb defaults")

        response = _redfish(redfish_client, "DELETE", path)
        pytest_assert(
            response.status_code in (200, 204),
            "DELETE {} expected 200/204, got: {}".format(path, response.status_code)
        )
        # bmcweb answers GET on a missing subscription with a bare 404 (no error body).
        response = _redfish(redfish_client, "GET", path)
        pytest_assert(
            response.status_code == 404,
            "GET {} after DELETE expected 404, got: {}".format(path, response.status_code)
        )
        pytest_assert(
            sub_id not in _subscription_ids(redfish_client),
            "Subscription {} still listed after DELETE".format(sub_id)
        )
        logger.info("Verified DELETE removed subscription %s (GET -> 404, not listed)", sub_id)

    @pytest.mark.parametrize("case", [
        "missing_destination", "unsupported_protocol", "malformed_destination", "userinfo_in_destination",
        "unknown_registry_prefix", "message_ids_with_registry_prefixes", "unknown_retry_policy",
    ])
    def test_subscription_rejects_bad_requests(self, redfish_client, rmc_receiver, clean_subscriptions, case):
        """
        Invalid subscription requests are refused with a Redfish error and create nothing.
        """
        good = rmc_receiver.url("bad-{}".format(case))
        bodies = {
            "missing_destination": ({"Protocol": "Redfish"}, "PropertyMissing"),
            "unsupported_protocol": ({"Destination": good, "Protocol": "Kafka"}, "PropertyValueNotInList"),
            "malformed_destination": ({"Destination": "not a url", "Protocol": "Redfish"},
                                      "PropertyValueFormatError"),
            "userinfo_in_destination": ({"Destination": "http://rmc:secret@10.0.0.1/", "Protocol": "Redfish"},
                                        "PropertyValueFormatError"),
            "unknown_registry_prefix": ({"Destination": good, "Protocol": "Redfish",
                                         "RegistryPrefixes": ["NoSuchRegistry"]}, "PropertyValueNotInList"),
            "message_ids_with_registry_prefixes": ({"Destination": good, "Protocol": "Redfish",
                                                    "RegistryPrefixes": ["OpenBMC"],
                                                    "MessageIds": ["PowerSupplyFailed"]}, "PropertyValueConflict"),
            "unknown_retry_policy": ({"Destination": good, "Protocol": "Redfish",
                                      "DeliveryRetryPolicy": "Never"}, "PropertyValueNotInList"),
        }
        body, message = bodies[case]
        response = _redfish(redfish_client, "POST", SUBSCRIPTIONS_PATH, json=body)
        assert_redfish_error(response, 400, message)
        logger.info("[%s] Verified HTTP 400 with %s and no subscription created", case, message)
        pytest_assert(
            not _subscription_ids(redfish_client),
            "[{}] rejected request must not create a subscription".format(case)
        )

    def test_leak_event_delivered(self, redfish_client, rmc_receiver, leak_event):
        """
        A leak detected on the BMC is pushed to the subscribed rack manager.

        The rack manager subscribes; the test sensor's STATE_DB row flips to
        leaking/CRITICAL; sonic-dbus-bridge changes DetectorState on D-Bus and
        bmcweb must POST one Event payload to the subscribed URL carrying
        Environmental.1.1.LeakDetectedCritical, Severity Critical, the
        sensor name as MessageArgs and an OriginOfCondition pointing at the
        sensor's LeakDetector resource. Clearing the leak arrives as a second
        POST (LeakDetectedNormal, Severity OK) with a higher Id.
        """
        _subscribe(redfish_client, rmc_receiver.url("events"), "ctx-events")

        leak_event("Critical")
        payload = _wait_for_deliveries(rmc_receiver, "events", 1)[0]

        events = _assert_event_envelope(payload)
        pytest_assert(len(events) == 1, "Expected exactly one event record, got: {}".format(events))
        _assert_leak_event(events[0], "Critical")
        logger.info("Verified RMC received leak event: MessageId=%s Severity=%s MessageArgs=%s "
                    "OriginOfCondition=%s EventTimestamp=%s", events[0]["MessageId"], events[0]["Severity"],
                    events[0]["MessageArgs"], events[0]["OriginOfCondition"], events[0]["EventTimestamp"])

        leak_event("OK")
        payloads = _wait_for_deliveries(rmc_receiver, "events", 2)
        pytest_assert(len(payloads) == 2, "Expected exactly two deliveries, got: {}".format(payloads))
        _assert_leak_event(_assert_event_envelope(payloads[1])[0], "OK")
        pytest_assert(
            int(payloads[1]["Id"]) > int(payloads[0]["Id"]),
            "Event payload Ids must increase: {} then {}".format(payloads[0]["Id"], payloads[1]["Id"])
        )
        logger.info("Verified leak cleared event %s delivered as a separate POST (Id %s > %s)",
                    LEAK_EVENTS["OK"][0], payloads[1]["Id"], payloads[0]["Id"])

    def test_leak_warning_event_delivered(self, redfish_client, rmc_receiver, leak_event):
        """
        A MINOR leak is reported as LeakDetectedWarning with Severity Warning.
        """
        _subscribe(redfish_client, rmc_receiver.url("warning"), "ctx-warning")
        leak_event("Warning")
        event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, "warning", 1)[0])[0]
        _assert_leak_event(event, "Warning")
        logger.info("Verified MINOR leak delivered as %s Severity=%s", event["MessageId"], event["Severity"])

    def test_resource_type_filter(self, redfish_client, rmc_receiver, leak_event):
        """
        ResourceTypes and RegistryPrefixes limit what a subscriber is sent.

        Five rack-manager subscriptions: unfiltered, ResourceTypes=[LeakDetector],
        RegistryPrefixes=[Environmental], ResourceTypes=[Task] and
        RegistryPrefixes=[Base]. After a leak event the first three have it
        and the other two have nothing.
        """
        _subscribe(redfish_client, rmc_receiver.url("all"), "ctx-all")
        _subscribe(redfish_client, rmc_receiver.url("leak"), "ctx-leak", ResourceTypes=[LEAK_RESOURCE_TYPE])
        _subscribe(redfish_client, rmc_receiver.url("environmental"), "ctx-environmental",
                   RegistryPrefixes=[LEAK_REGISTRY])
        _subscribe(redfish_client, rmc_receiver.url("task"), "ctx-task", ResourceTypes=["Task"])
        _subscribe(redfish_client, rmc_receiver.url("base"), "ctx-base", RegistryPrefixes=["Base"])

        leak_event("Critical")

        for name in ("all", "leak", "environmental"):
            event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, name, 1)[0])[0]
            _assert_leak_event(event, "Critical")
        # Give a wrongly forwarded leak event time to show up before counting.
        time.sleep(NO_DELIVERY_SETTLE)
        for name in ("task", "base"):
            got = rmc_receiver.deliveries(name)
            pytest_assert(
                not got,
                "Subscriber {!r} must not receive the leak event, got: {}".format(name, got)
            )
        logger.info("Verified leak event reached the unfiltered, ResourceTypes=[%s] and RegistryPrefixes=[%s] "
                    "subscribers only", LEAK_RESOURCE_TYPE, LEAK_REGISTRY)

    def test_subscription_persists_across_bmcweb_restart(
            self, redfish_client, bmc_duthost, rmc_receiver, leak_event):
        """
        A subscription survives a bmcweb restart and keeps delivering.

        bmcweb persists subscriptions to disk; after `supervisorctl restart
        bmcweb` the subscription is still listed with the same Destination and
        Context, and the restarted bmcweb's leak monitor (re-attached to the
        bridge's D-Bus objects) delivers a new leak event to it.
        """
        sub_id, path = _subscribe(redfish_client, rmc_receiver.url("persist"), "ctx-persist")

        logger.info("Restarting bmcweb in the %s container", REDFISH_CONTAINER)
        _container_shell(bmc_duthost, "supervisorctl restart bmcweb")
        _wait_for_bmcweb(redfish_client, bmc_duthost)
        logger.info("bmcweb back; subscriptions now: %s", _subscription_ids(redfish_client))

        pytest_assert(
            sub_id in _subscription_ids(redfish_client),
            "Subscription {} not listed after bmcweb restart".format(sub_id)
        )
        body = _redfish(redfish_client, "GET", path).json()
        assert_field_equals(body, "Destination", rmc_receiver.url("persist"))
        assert_field_equals(body, "Context", "ctx-persist")
        logger.info("Verified subscription %s survived the restart with the same Destination/Context", sub_id)

        leak_event("Critical")
        event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, "persist", 1)[0])[0]
        _assert_leak_event(event, "Critical")
        logger.info("Verified delivery still works after the bmcweb restart")

    def test_leak_detector_resource_tracks_state(self, redfish_client, leak_event):
        """
        The LeakDetector resource a leak event points at reflects the live sensor state.

        pmon-bmc-design.md section 2.1.2 item 6 models BMC leak sensors under
        Chassis/<id>/ThermalSubsystem/LeakDetection. A rack manager that
        follows OriginOfCondition from a leak event must find the detector
        listed in the LeakDetectors collection, and GET on it must report
        DetectorState and Status.Health moving OK -> Critical -> OK with the
        STATE_DB row.
        """
        collection = LEAK_ORIGIN.rsplit("/", 1)[0]

        response = redfish_client.get(collection)
        assert_status_ok(response, collection)
        members = [m.get("@odata.id") for m in response.json().get("Members", [])]
        pytest_assert(LEAK_ORIGIN in members, "{} must list {}, got: {}".format(collection, LEAK_ORIGIN, members))

        def _detector_reports(state):
            body = redfish_client.get(LEAK_ORIGIN).json()
            logger.info("%s DetectorState=%s Health=%s (waiting for %s)", LEAK_ORIGIN,
                        body.get("DetectorState"), body.get("Status", {}).get("Health"), state)
            return body.get("DetectorState") == state and body.get("Status", {}).get("Health") == state

        for state in ("Critical", "OK"):
            leak_event(state)
            pytest_assert(
                wait_until(DELIVERY_TIMEOUT, DELIVERY_POLL, 0, _detector_reports, state),
                "{} did not report DetectorState {} within {}s".format(LEAK_ORIGIN, state, DELIVERY_TIMEOUT)
            )
            body = redfish_client.get(LEAK_ORIGIN).json()
            assert_field_equals(body, "@odata.id", LEAK_ORIGIN)
            assert_field_equals(body, "Id", LEAK_SENSOR)
            logger.info("Verified %s DetectorState=%s Health=%s", LEAK_ORIGIN, state,
                        body.get("Status", {}).get("Health"))

    def test_leak_detector_resource_shape(self, redfish_client, leak_event):
        """
        The LeakDetector a leak event points at is served in full at both of its URIs.

        OriginOfCondition names the deprecated
        ThermalSubsystem/LeakDetection/LeakDetectors/<id> form and the Chassis
        links the canonical Chassis/<id>/LeakDetectors/<id> form. Each
        collection must list the test sensor and each member must serve the
        same LeakDetector under its own @odata.id: identity, a
        LeakDetectorType, DetectorState OK and an Enabled, OK Status.
        """
        for member in (LEAK_ORIGIN, LEAK_ORIGIN_CANONICAL):
            collection = member.rsplit("/", 1)[0]
            response = redfish_client.get(collection)
            assert_status_ok(response, collection)
            members = [m.get("@odata.id") for m in response.json().get("Members", [])]
            pytest_assert(member in members, "{} must list {}, got: {}".format(collection, member, members))

            response = redfish_client.get(member)
            assert_status_ok(response, member)
            body = response.json()
            assert_field_equals(body, "@odata.id", member)
            assert_field_contains(body, "@odata.type", "#LeakDetector.")
            assert_field_equals(body, "Id", LEAK_SENSOR)
            assert_field_equals(body, "Name", "Leak Detector {}".format(LEAK_SENSOR))
            assert_field_nonempty(body, "LeakDetectorType")
            assert_field_equals(body, "DetectorState", "OK")
            status = body.get("Status", {})
            pytest_assert(
                status.get("State") == "Enabled" and status.get("Health") == "OK",
                "{} Status must be Enabled/OK, got: {!r}".format(member, status)
            )
            logger.info("Verified %s: LeakDetectorType=%s DetectorState=%s Status=%s",
                        member, body["LeakDetectorType"], body["DetectorState"], status)

    def test_host_power_events_delivered(self, redfish_client, bmc_duthost, rmc_receiver, clean_subscriptions,
                                         host_power_restored):
        """
        Taking the switch host down and back up reaches a subscribed rack manager as ResourceEvents.

        A subscription filtered on ResourceTypes=[ComputerSystem] receives
        ResourcePoweringOff and ResourcePoweredOff for a ComputerSystem.Reset
        GracefulShutdown, then ResourcePoweringOn and ResourcePoweredOn for the
        ResetType=On that follows, in that order and with increasing Ids. The
        transitions are real: bmcctld shuts the host down, removes its power
        and restores it, and HOST_STATE reads a settled on value at the end.
        Each event names the ComputerSystem as its origin. A subscription
        filtered on RegistryPrefixes=[ResourceEvent] receives the same power
        events in the same order, among whatever else that registry carries,
        and one filtered on LeakDetector receives none of them.
        """
        _subscribe(redfish_client, rmc_receiver.url("power"), "ctx-power", ResourceTypes=[HOST_RESOURCE_TYPE])
        _subscribe(redfish_client, rmc_receiver.url("power-registry"), "ctx-power-registry",
                   RegistryPrefixes=[HOST_REGISTRY])
        _subscribe(redfish_client, rmc_receiver.url("leak-only"), "ctx-leak-only", ResourceTypes=[LEAK_RESOURCE_TYPE])

        _reset(redfish_client, "GracefulShutdown")
        _wait_for_power_event(rmc_receiver, "power", "PoweredOff", HOST_OFF_TIMEOUT)
        logger.info("%s after GracefulShutdown: %s", HOST_STATE_KEY, _host_state(bmc_duthost))

        _reset(redfish_client, "On")
        payloads = _wait_for_power_event(rmc_receiver, "power", "PoweredOn", HOST_ON_TIMEOUT)
        pytest_assert(wait_until(HOST_ON_TIMEOUT, HOST_STATE_POLL, 0, _host_is_settled_on, bmc_duthost),
                      "{} did not settle on after ResetType=On: {}".format(HOST_STATE_KEY, _host_state(bmc_duthost)))
        logger.info("%s after ResetType=On: %s", HOST_STATE_KEY, _host_state(bmc_duthost))

        expected = [HOST_POWER_EVENTS[name][0] for name in POWER_OFF_ON_SEQUENCE]
        delivered = _delivered_message_ids(payloads, collapse_repeats=True)
        pytest_assert(delivered == expected, "Power events must arrive as {}, got: {}".format(expected, delivered))
        for payload in payloads:
            events = _assert_event_envelope(payload)
            pytest_assert(len(events) == 1, "Expected exactly one event record per delivery, got: {}".format(events))
            _assert_host_power_event(events[0], EVENT_NAME_BY_MESSAGE_ID[events[0]["MessageId"]])

        ids = [int(p["Id"]) for p in payloads]
        pytest_assert(ids == sorted(ids) and len(set(ids)) == len(ids),
                      "Event payload Ids must increase across the transitions, got: {}".format(ids))

        # The ResourceEvent registry also carries ResourceStatusChanged for a leak sensor fault.
        registry_payloads = _wait_for_power_event(rmc_receiver, "power-registry", "PoweredOn", DELIVERY_TIMEOUT)
        by_registry = _delivered_message_ids(registry_payloads, collapse_repeats=True, only=expected)
        pytest_assert(by_registry == expected,
                      "A RegistryPrefixes=[{}] subscriber must receive {} in order, got: {}".format(
                          HOST_REGISTRY, expected, _delivered_message_ids(registry_payloads)))
        time.sleep(NO_DELIVERY_SETTLE)
        leak_only = rmc_receiver.deliveries("leak-only")
        pytest_assert(not leak_only,
                      "A LeakDetector-only subscriber must not receive power events, got: {}".format(leak_only))
        logger.info("Verified the four power events of a real shutdown and power-on, none at the LeakDetector-only "
                    "subscriber")

    def test_host_power_off_event_drives_power_on_request(
            self, redfish_client, bmc_duthost, rmc_receiver, clean_subscriptions, host_power_restored):
        """
        A rack manager learns the switch host is off from the event and powers it back on over Redfish.

        The host is powered off for real with ComputerSystem.Reset ForceOff.
        The subscriber receives ResourcePoweredOff and answers with
        ResetType=On. That request must become one new RACK_MANAGER_COMMAND
        row with command=POWER_ON that bmcctld completes with status DONE and
        result SUCCESS, bmcctld must bring the host back so HOST_STATE settles
        on, and the subscriber must then receive ResourcePoweredOn.
        """
        _subscribe(redfish_client, rmc_receiver.url("rm"), "ctx-rm", ResourceTypes=[HOST_RESOURCE_TYPE])

        _reset(redfish_client, "ForceOff")
        payloads = _wait_for_power_event(rmc_receiver, "rm", "PoweredOff", HOST_OFF_TIMEOUT)
        event = _power_event(payloads, "PoweredOff")
        _assert_host_power_event(event, "PoweredOff")
        logger.info("Rack manager received %s with %s=%s, requesting ResetType=On",
                    event["MessageId"], HOST_STATE_KEY, _host_state(bmc_duthost))
        keys_before = command_keys(bmc_duthost)

        _reset(redfish_client, "On")

        def _new_command_keys():
            return command_keys(bmc_duthost) - keys_before

        pytest_assert(wait_until(DELIVERY_TIMEOUT, DELIVERY_POLL, 0, _new_command_keys),
                      "No RACK_MANAGER_COMMAND row appeared within {}s of the reset".format(DELIVERY_TIMEOUT))
        new_keys = _new_command_keys()
        pytest_assert(len(new_keys) == 1, "One reset must create one command row, got: {}".format(sorted(new_keys)))
        key = new_keys.pop()

        pytest_assert(wait_until(COMMAND_DONE_TIMEOUT, DELIVERY_POLL, 0, command_done, bmc_duthost, key),
                      "{} was not completed by bmcctld within {}s".format(key, COMMAND_DONE_TIMEOUT))
        row = redis_hgetall(bmc_duthost, STATE_DB, key)
        pytest_assert(
            row.get("command") == "POWER_ON" and row.get("status") == "DONE" and row.get("result") == "SUCCESS",
            "{} must end command=POWER_ON status=DONE result=SUCCESS, got: {}".format(key, row)
        )
        logger.info("bmcctld completed %s: %s", key, row)

        pytest_assert(wait_until(HOST_ON_TIMEOUT, HOST_STATE_POLL, 0, _host_is_settled_on, bmc_duthost),
                      "{} did not settle on after ResetType=On: {}".format(HOST_STATE_KEY, _host_state(bmc_duthost)))
        payloads = _wait_for_power_event(rmc_receiver, "rm", "PoweredOn", HOST_ON_TIMEOUT)
        _assert_host_power_event(_power_event(payloads, "PoweredOn"), "PoweredOn")
        logger.info("Verified the rack manager saw the host go off, powered it on, and saw it on again")

    @pytest.mark.parametrize("fault", LEAK_FAULT_STATES)
    def test_leak_detector_fault_reported_unavailable(self, redfish_client, leak_event, fault):
        """
        A faulted leak sensor does not look healthy to the rack manager.

        sonic-redfish design section 7.6: thermalctld reporting leak_sensor_status=Fault with an
        unreadable leaking value maps to DetectorState Unavailable, reported
        with Status.State UnavailableOffline and Status.Health Warning at both
        LeakDetector URIs. A faulted sensor whose leaking value still reads No
        is reported the same way. Once the sensor reads again the detector
        returns to DetectorState OK with an Enabled, OK Status.
        """
        expected = {
            "Unavailable": ("UnavailableOffline", "Warning"),
            "OK": ("Enabled", "OK"),
        }
        for row, state in ((fault, "Unavailable"), ("OK", "OK")):
            leak_event(row)
            want_state, want_health = expected[state]

            def _reports(body):
                status = body.get("Status", {})
                return (body.get("DetectorState") == state and status.get("State") == want_state
                        and status.get("Health") == want_health)

            for member in (LEAK_ORIGIN, LEAK_ORIGIN_CANONICAL):
                held, body = _wait_for_body(redfish_client, member, _reports, DELIVERY_TIMEOUT)
                pytest_assert(
                    held,
                    "{} must report DetectorState {} with Status {}/{} within {}s, got: {}".format(
                        member, state, want_state, want_health, DELIVERY_TIMEOUT, body)
                )
                logger.info("Verified %s DetectorState=%s Status=%s/%s", member, state, want_state, want_health)

    @pytest.mark.parametrize("fault", LEAK_FAULT_STATES)
    def test_leak_detector_fault_events_delivered(self, redfish_client, rmc_receiver, leak_event, fault):
        """
        A leak sensor faulting and recovering reaches the rack manager as ResourceStatusChanged events.

        sonic-redfish design section 7.6: the transition into Unavailable raises
        ResourceEvent.1.3.ResourceStatusChangedWarning and the transition
        out raises ResourceStatusChangedOK, each with the detector as
        OriginOfCondition. The fault is not a leak, so no LeakDetected event
        accompanies it. Recovering into DetectorState OK also raises
        LeakDetectedNormal. An unfiltered subscription and one filtered on
        ResourceTypes=[LeakDetector] both receive the events.
        """
        unfiltered = "fault-{}".format(fault)
        by_type = "fault-leak-{}".format(fault)
        _subscribe(redfish_client, rmc_receiver.url(unfiltered), "ctx-fault")
        _subscribe(redfish_client, rmc_receiver.url(by_type), "ctx-fault-leak", ResourceTypes=[LEAK_RESOURCE_TYPE])

        leak_event(fault)
        for name in (unfiltered, by_type):
            payloads = _wait_for_deliveries(rmc_receiver, name, 1)
            events = _assert_event_envelope(payloads[0])
            pytest_assert(len(events) == 1, "Expected exactly one event record, got: {}".format(events))
            _assert_leak_status_event(events[0], "Warning")
        time.sleep(NO_DELIVERY_SETTLE)
        delivered = _delivered_message_ids(rmc_receiver.deliveries(unfiltered))
        pytest_assert(delivered == [LEAK_STATUS_EVENTS["Warning"][0]],
                      "A sensor fault must raise only {}, got: {}".format(LEAK_STATUS_EVENTS["Warning"][0], delivered))
        logger.info("Verified the sensor fault was delivered as %s", LEAK_STATUS_EVENTS["Warning"][0])

        leak_event("OK")
        recovered = (LEAK_STATUS_EVENTS["OK"][0], LEAK_EVENTS["OK"][0])
        for name in (unfiltered, by_type):
            arrived, payloads = _wait_for_message_ids(rmc_receiver, name, recovered)
            pytest_assert(
                arrived,
                "{} must receive {} within {}s, got: {}".format(
                    rmc_receiver.url(name), recovered, DELIVERY_TIMEOUT, _delivered_message_ids(payloads))
            )
            _assert_leak_status_event(_event_with_id(payloads, LEAK_STATUS_EVENTS["OK"][0]), "OK")
            _assert_leak_event(_event_with_id(payloads, LEAK_EVENTS["OK"][0]), "OK")
        logger.info("Verified the sensor recovery was delivered as %s and %s", *recovered)

    @pytest.mark.parametrize("leak", ["Critical", "Warning"])
    def test_leak_detector_fault_recovery_into_leak(self, redfish_client, rmc_receiver, leak_event, leak):
        """
        A sensor that comes back from a fault already leaking is never reported healthy.

        sonic-redfish design section 7.6: leaving Unavailable raises the
        ResourceStatusChanged event for the health the detector comes back
        with, then the leak event. Back into a CRITICAL leak that is
        ResourceStatusChangedCritical and LeakDetectedCritical. Unavailable is
        already reported as Warning, so back into a MINOR leak the health did
        not change and only LeakDetectedWarning is sent. Neither case may
        raise ResourceStatusChangedOK, and the detector reports the leak with
        an Enabled Status.
        """
        name = "fault-into-{}".format(leak)
        _subscribe(redfish_client, rmc_receiver.url(name), "ctx-fault-into-leak")

        leak_event("Unavailable")
        fault_event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, name, 1)[0])[0]
        _assert_leak_status_event(fault_event, "Warning")

        leak_event(leak)
        expected = [LEAK_STATUS_EVENTS["Warning"][0], LEAK_EVENTS[leak][0]]
        if leak == "Critical":
            expected.append(LEAK_STATUS_EVENTS["Critical"][0])
        arrived, payloads = _wait_for_message_ids(rmc_receiver, name, expected)
        pytest_assert(
            arrived,
            "{} must receive {} within {}s, got: {}".format(
                rmc_receiver.url(name), expected, DELIVERY_TIMEOUT, _delivered_message_ids(payloads))
        )
        time.sleep(NO_DELIVERY_SETTLE)
        payloads = rmc_receiver.deliveries(name)
        delivered = _delivered_message_ids(payloads)
        pytest_assert(
            sorted(delivered) == sorted(expected),
            "Recovering from a fault into a {} leak must raise exactly {}, got: {}".format(leak, expected, delivered)
        )
        _assert_leak_event(_event_with_id(payloads, LEAK_EVENTS[leak][0]), leak)
        if leak == "Critical":
            _assert_leak_status_event(_event_with_id(payloads, LEAK_STATUS_EVENTS["Critical"][0]), "Critical")

        for member in (LEAK_ORIGIN, LEAK_ORIGIN_CANONICAL):
            body = _get_body(redfish_client, member)
            status = body.get("Status", {})
            pytest_assert(
                body.get("DetectorState") == leak and status.get("State") == "Enabled"
                and status.get("Health") == leak,
                "{} must report DetectorState {} with Status Enabled/{}, got: {}".format(member, leak, leak, body)
            )
        logger.info("Verified recovery from a fault into a %s leak was delivered as %s", leak, delivered)

    @pytest.mark.parametrize("leak", ["Critical", "Warning"])
    def test_leaking_detector_fault_keeps_the_leak(self, redfish_client, rmc_receiver, leak_event, leak):
        """
        A sensor that faults while it reports a leak keeps reporting the leak.

        sonic-redfish design section 7.6: a faulted sensor that still reads a
        leak keeps the leak as its DetectorState and health, and is reported
        with Status.State UnavailableOffline at both LeakDetector URIs until
        the sensor is good again. The leak never cleared, so neither the fault
        nor the recovery may raise LeakDetectedNormal or
        ResourceStatusChangedOK.
        """
        name = "leaking-fault-{}".format(leak)
        _subscribe(redfish_client, rmc_receiver.url(name), "ctx-leaking-fault")

        leak_event(leak)
        _wait_for_deliveries(rmc_receiver, name, 1)

        def _assert_status(want_state):
            def _reports(body):
                status = body.get("Status", {})
                return (body.get("DetectorState") == leak and status.get("State") == want_state
                        and status.get("Health") == leak)

            for member in (LEAK_ORIGIN, LEAK_ORIGIN_CANONICAL):
                held, body = _wait_for_body(redfish_client, member, _reports, DELIVERY_TIMEOUT)
                pytest_assert(
                    held,
                    "{} must report DetectorState {} with Status {}/{} within {}s, got: {}".format(
                        member, leak, want_state, leak, DELIVERY_TIMEOUT, body)
                )
                logger.info("Verified %s DetectorState=%s Status=%s/%s", member, leak, want_state, leak)

        _assert_status("Enabled")
        leak_event("{} with a faulted sensor".format(leak), LEAKING_FAULT_STATES[leak])
        _assert_status("UnavailableOffline")
        leak_event(leak)
        _assert_status("Enabled")

        time.sleep(NO_DELIVERY_SETTLE)
        delivered = _delivered_message_ids(rmc_receiver.deliveries(name))
        healthy = {LEAK_EVENTS["OK"][0], LEAK_STATUS_EVENTS["OK"][0]}
        pytest_assert(
            delivered[0] == LEAK_EVENTS[leak][0] and not healthy & set(delivered),
            "A {} leak whose sensor faults and recovers must be announced as {} and never as {}, got: {}".format(
                leak, LEAK_EVENTS[leak][0], sorted(healthy), delivered)
        )
        logger.info("Verified a %s leak stayed reported through a sensor fault: %s", leak, delivered)

    def test_leak_detector_published_after_bridge_start(self, redfish_client, bmc_duthost, late_leak_sensor):
        """
        A leak sensor thermalctld publishes after the bridge started gets its LeakDetector.

        sonic-redfish design section 2.1: one LeakDetector per LIQUID_COOLING_INFO|* sensor. A
        sensor row written while sonic-dbus-bridge is running, as after a cold
        boot where thermalctld starts later, must appear in both LeakDetectors
        collections without a bridge or container restart, and the canonical
        collection must then list exactly the sensors in STATE_DB.
        """
        _seed_late_sensor(bmc_duthost, "OK")

        for member in (LEAK_ORIGIN, LEAK_ORIGIN_CANONICAL):
            collection = member.rsplit("/", 1)[0]
            late_member = "{}/{}".format(collection, LATE_LEAK_SENSOR)

            def _listed():
                members = [m.get("@odata.id") for m in _get_body(redfish_client, collection).get("Members", [])]
                return late_member in members

            pytest_assert(
                wait_until(BRIDGE_READY_TIMEOUT, 3, 0, _listed),
                "{} did not list {} within {}s of the row being written".format(
                    collection, late_member, BRIDGE_READY_TIMEOUT)
            )
            body = _get_body(redfish_client, late_member)
            assert_field_equals(body, "@odata.id", late_member)
            assert_field_equals(body, "Id", LATE_LEAK_SENSOR)
            assert_field_equals(body, "DetectorState", "OK")
            status = body.get("Status", {})
            pytest_assert(status.get("State") == "Enabled" and status.get("Health") == "OK",
                          "{} Status must be Enabled/OK, got: {!r}".format(late_member, status))
            logger.info("Verified %s is served with DetectorState OK", late_member)

        collection = LEAK_ORIGIN_CANONICAL.rsplit("/", 1)[0]
        sensors = sorted(key.split("|", 1)[1] for key in redis_keys(bmc_duthost, STATE_DB, LEAK_SENSOR_KEY_GLOB))
        detectors = sorted(m.get("@odata.id", "").rsplit("/", 1)[-1]
                           for m in _get_body(redfish_client, collection).get("Members", []))
        pytest_assert(detectors == sensors,
                      "{} must list one detector per {} row: detectors={} sensors={}".format(
                          collection, LEAK_SENSOR_KEY_GLOB, detectors, sensors))
        logger.info("Verified %s lists one detector per STATE_DB sensor: %s", collection, detectors)

    @pytest.mark.parametrize("state", ["Critical", "OK"])
    def test_late_leak_detector_first_state_announced_once(
            self, redfish_client, bmc_duthost, rmc_receiver, clean_subscriptions, late_leak_sensor, state):
        """
        A leak sensor published after the bridge started tells the rack manager its first state once.

        sonic-redfish design section 2.1: the detector of a sensor first seen
        leaking is created in that state rather than changed to it, and the
        rack manager must still receive one LeakDetectedCritical for it. A
        sensor first seen OK never leaked, so it is listed without any event.
        """
        name = "late-{}".format(state)
        _subscribe(redfish_client, rmc_receiver.url(name), "ctx-late")
        _seed_late_sensor(bmc_duthost, state)

        served, body = _wait_for_body(redfish_client, LATE_LEAK_ORIGIN_CANONICAL,
                                      lambda b: b.get("DetectorState") == state, BRIDGE_READY_TIMEOUT, poll=3)
        pytest_assert(
            served,
            "{} did not report DetectorState {} within {}s of the row being written, got: {}".format(
                LATE_LEAK_ORIGIN_CANONICAL, state, BRIDGE_READY_TIMEOUT, body)
        )

        if state != "OK":
            pytest_assert(
                wait_until(DELIVERY_TIMEOUT, DELIVERY_POLL, 0,
                           lambda: _events_for(rmc_receiver.deliveries(name), LATE_LEAK_SENSOR)),
                "No event for {} reached {} within {}s".format(
                    LATE_LEAK_SENSOR, rmc_receiver.url(name), DELIVERY_TIMEOUT)
            )
        time.sleep(NO_DELIVERY_SETTLE)
        events = _events_for(rmc_receiver.deliveries(name), LATE_LEAK_SENSOR)
        if state == "OK":
            pytest_assert(not events, "A sensor first seen OK must raise no event, got: {}".format(events))
            logger.info("Verified %s first seen OK raised no event", LATE_LEAK_SENSOR)
            return

        pytest_assert(len(events) == 1,
                      "The first state of {} must be announced exactly once, got: {}".format(LATE_LEAK_SENSOR, events))
        message_id, severity, _ = LEAK_EVENTS[state]
        assert_field_equals(events[0], "MessageId", message_id)
        assert_field_equals(events[0], "Severity", severity)
        pytest_assert(
            events[0].get("OriginOfCondition", {}).get("@odata.id") == LATE_LEAK_ORIGIN,
            "OriginOfCondition must be {!r}, got: {!r}".format(LATE_LEAK_ORIGIN, events[0].get("OriginOfCondition"))
        )
        logger.info("Verified %s first seen %s was announced once as %s", LATE_LEAK_SENSOR, state, message_id)

    @pytest.mark.parametrize("row", ["absent", "unrecognised"])
    def test_host_state_unknown_until_bmcctld_publishes(
            self, redfish_client, bmc_duthost, rmc_receiver, clean_subscriptions, host_power_restored,
            bmcctld_stopped, row):
        """
        The switch-host power state is reported unknown until bmcctld publishes HOST_STATE.

        sonic-redfish design section 7.7: with HOST_STATE|switch-host absent when
        sonic-dbus-bridge starts, or present with no field the bridge
        recognises, Systems/system and Chassis/chassis omit
        PowerState and report Status.State UnavailableOffline, and no
        event is raised for the ComputerSystem. A ComputerSystem.Reset received
        meanwhile is still forwarded as a RACK_MANAGER_COMMAND row. bmcctld's
        first HOST_STATE row then sets the real state on both resources and
        raises the matching event, ResourcePoweredOn for a host that is on.

        bmcctld is stopped for the duration so it cannot republish the row,
        and the reset is ResetType=On against a host that is on, which bmcctld
        resolves as a no-op.
        """
        name = "unknown-{}".format(row)
        _subscribe(redfish_client, rmc_receiver.url(name), "ctx-unknown", ResourceTypes=[HOST_RESOURCE_TYPE])

        logger.info("Removing %s (%s) and restarting %s", HOST_STATE_KEY, _host_state(bmc_duthost), BRIDGE_SERVICE)
        redis_del(bmc_duthost, STATE_DB, HOST_STATE_KEY)
        if row == "unrecognised":
            redis_hset(bmc_duthost, STATE_DB, HOST_STATE_KEY, **UNRECOGNISED_HOST_STATE)
            logger.info("Wrote %s as %s", HOST_STATE_KEY, UNRECOGNISED_HOST_STATE)
        _restart_bridge(bmc_duthost)

        for path in (SYSTEM_ORIGIN, CHASSIS_PATH):
            unknown, body = _wait_for_body(redfish_client, path, _reports_unknown_power, BRIDGE_READY_TIMEOUT, poll=3)
            pytest_assert(
                unknown,
                "{} must omit PowerState and report Status.State UnavailableOffline within {}s, got: {}".format(
                    path, BRIDGE_READY_TIMEOUT, body)
            )
            logger.info("Verified %s reports an unknown power state: %s", path, body.get("Status"))

        keys_before = command_keys(bmc_duthost)
        _reset(redfish_client, "On")
        pytest_assert(
            wait_until(DELIVERY_TIMEOUT, DELIVERY_POLL, 0, lambda: command_keys(bmc_duthost) - keys_before),
            "ResetType=On in the unknown state created no RACK_MANAGER_COMMAND row within {}s".format(DELIVERY_TIMEOUT)
        )
        new_keys = command_keys(bmc_duthost) - keys_before
        pytest_assert(len(new_keys) == 1, "One reset must create one command row, got: {}".format(sorted(new_keys)))
        command_key = new_keys.pop()
        command = redis_hgetall(bmc_duthost, STATE_DB, command_key)
        pytest_assert(command.get("command") == "POWER_ON",
                      "{} must carry command=POWER_ON, got: {}".format(command_key, command))
        logger.info("Verified ResetType=On in the unknown state was forwarded as %s: %s", command_key, command)

        time.sleep(NO_DELIVERY_SETTLE)
        early = _delivered_message_ids(rmc_receiver.deliveries(name))
        pytest_assert(not early, "The unknown state must raise no event, got: {}".format(early))

        pytest_assert(bmcctld_stopped(), "{} did not start and republish {} within {}s".format(
            BMCCTLD, HOST_STATE_KEY, BMCCTLD_TIMEOUT))
        pytest_assert(wait_until(HOST_ON_TIMEOUT, HOST_STATE_POLL, 0, _host_is_settled_on, bmc_duthost),
                      "{} did not settle on after {} started: {}".format(
                          HOST_STATE_KEY, BMCCTLD, _host_state(bmc_duthost)))
        logger.info("%s republished %s: %s", BMCCTLD, HOST_STATE_KEY, _host_state(bmc_duthost))

        for path in (SYSTEM_ORIGIN, CHASSIS_PATH):
            powered_on, body = _wait_for_body(
                redfish_client, path,
                lambda b: b.get("PowerState") == "On" and b.get("Status", {}).get("State") == "Enabled",
                DELIVERY_TIMEOUT)
            pytest_assert(
                powered_on,
                "{} must report PowerState On with Status.State Enabled once {} is published, got: {}".format(
                    path, HOST_STATE_KEY, body)
            )
            logger.info("Verified %s reports PowerState On, Status %s", path, body.get("Status"))

        payloads = _wait_for_power_event(rmc_receiver, name, "PoweredOn", HOST_ON_TIMEOUT)
        _assert_host_power_event(_power_event(payloads, "PoweredOn"), "PoweredOn")
        logger.info("Verified the first published %s raised %s", HOST_STATE_KEY, HOST_POWER_EVENTS["PoweredOn"][0])
