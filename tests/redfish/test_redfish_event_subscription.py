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
``Environmental.1.1.0.LeakDetected{Critical,Warning,Normal}`` event with
resource type ``LeakDetector``. The test stands in for the platform daemon by
seeding a synthetic sensor row and flipping its state.

The tests cover what a rack manager uses: POST EventService/Subscriptions,
the leak and switch-host power events it then receives, and the resources
those events point at. Other EventService features (SubmitTestEvent, SSE,
PATCH, retry policies) are not exercised here.

Switch-host power events come from bmcctld's HOST_STATE|switch-host row:
``sonic-dbus-bridge`` mirrors device_power_state/device_status into
``xyz.openbmc_project.State.Host`` CurrentHostState and bmcweb's host state
monitor turns each change into a ``ResourceEvent.1.3.0.ResourcePower*``
event on the ComputerSystem. The tests stand in for bmcctld by writing that
row, the same way they stand in for thermalctld on the leak sensor.

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
from tests.common.helpers.sonic_db import STATE_DB, redis_hgetall, redis_hset, redis_keys
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    assert_field_equals,
    assert_redfish_error,
    assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

EVENT_SERVICE_PATH = "/redfish/v1/EventService"
SUBSCRIPTIONS_PATH = "{}/Subscriptions".format(EVENT_SERVICE_PATH)
SERVICE_ROOT = "/redfish/v1"

REDFISH_CONTAINER = "redfish"
BRIDGE_SERVICE = "sonic-dbus-bridge"

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

# Synthetic leak sensor the test plays platform daemon for. sonic-dbus-bridge
# discovers LIQUID_COOLING_INFO|* rows only at startup, so the row is seeded
# and the bridge restarted once per module.
LEAK_SENSOR = "rmc_test_leak"
LEAK_SENSOR_KEY = "LIQUID_COOLING_INFO|{}".format(LEAK_SENSOR)
LEAK_SENSOR_DBUS_PATH = "/xyz/openbmc_project/sensors/leak/{}".format(LEAK_SENSOR)
LEAK_DETECTOR_IFACE = "xyz.openbmc_project.Inventory.Item.LeakDetector"
BRIDGE_BUS_NAME = "xyz.openbmc_project.Inventory.Manager"
# OriginOfCondition of the test sensor's leak events, under the Chassis named "chassis"
# as in pmon-bmc-design.md section 2.1.2.
LEAK_ORIGIN = "/redfish/v1/Chassis/chassis/ThermalSubsystem/LeakDetection/LeakDetectors/{}".format(LEAK_SENSOR)
LEAK_REGISTRY = "Environmental"
LEAK_RESOURCE_TYPE = "LeakDetector"
# STATE_DB fields per detector state, as thermalctld writes them and
# sonic-dbus-bridge's LeakSensor::detectorState() maps them.
LEAK_STATES = {
    "OK": {"leaking": "No", "leak_status": "No", "leak_severity": "None"},
    "Warning": {"leaking": "Yes", "leak_status": "Yes", "leak_severity": "MINOR"},
    "Critical": {"leaking": "Yes", "leak_status": "Yes", "leak_severity": "CRITICAL"},
}
# Event bmcweb's leak monitor emits for each detector state: (MessageId, Severity, Message).
LEAK_EVENTS = {
    "Critical": ("Environmental.1.1.0.LeakDetectedCritical", "Critical",
                 "Leak detector '{}' reports a critical level leak.".format(LEAK_SENSOR)),
    "Warning": ("Environmental.1.1.0.LeakDetectedWarning", "Warning",
                "Leak detector '{}' reports a warning level leak.".format(LEAK_SENSOR)),
    "OK": ("Environmental.1.1.0.LeakDetectedNormal", "OK",
           "Leak detector '{}' has returned to normal.".format(LEAK_SENSOR)),
}

# Switch-host power state as bmcctld publishes it and the event each value produces.
HOST_STATE_KEY = "HOST_STATE|switch-host"
HOST_RESOURCE_TYPE = "ComputerSystem"
SYSTEM_ORIGIN = "/redfish/v1/Systems/system"
RESET_PATH = "{}/Actions/ComputerSystem.Reset".format(SYSTEM_ORIGIN)
COMMAND_KEY_GLOB = "RACK_MANAGER_COMMAND|*"
COMMAND_DONE_TIMEOUT = 60
# device_power_state -> (device_status bmcctld writes with it, MessageId, Message)
HOST_POWER_EVENTS = {
    "POWERING_OFF": ("ONLINE", "ResourceEvent.1.3.0.ResourcePoweringOff", "The resource `system` is powering off."),
    "POWERED_OFF": ("OFFLINE", "ResourceEvent.1.3.0.ResourcePoweredOff", "The resource `system` has powered off."),
    "POWERING_ON": ("OFFLINE", "ResourceEvent.1.3.0.ResourcePoweringOn", "The resource `system` is powering on."),
    "POWERED_ON": ("ONLINE", "ResourceEvent.1.3.0.ResourcePoweredOn", "The resource `system` has powered on."),
}

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


def _assert_host_power_event(event, power_state):
    """Check an event record is the host state monitor's event for `power_state`."""
    _, message_id, message = HOST_POWER_EVENTS[power_state]
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
    Seeds LIQUID_COOLING_INFO|<sensor> in STATE_DB the way thermalctld would,
    restarts the bridge so it discovers the row, and waits until the
    LeakDetector object answers on D-Bus. The injector rewrites the row's
    leak fields, which the bridge turns into a DetectorState change.
    """
    body = redfish_client.get(EVENT_SERVICE_PATH).json()
    pyrequire(
        LEAK_REGISTRY in body.get("RegistryPrefixes", []) and LEAK_RESOURCE_TYPE in body.get("ResourceTypes", []),
        "EventService does not advertise the {} registry and {} resource type (RegistryPrefixes={} "
        "ResourceTypes={}); this bmcweb was built without sonic-redfish rmc-events".format(
            LEAK_REGISTRY, LEAK_RESOURCE_TYPE, body.get("RegistryPrefixes"), body.get("ResourceTypes"))
    )

    def _hset(fields):
        pairs = " ".join("{} {}".format(k, shlex.quote(v)) for k, v in fields.items())
        bmc_duthost.shell("sonic-db-cli STATE_DB HSET {} {}".format(shlex.quote(LEAK_SENSOR_KEY), pairs))

    seed = dict(LEAK_STATES["OK"], leak_sensor_status="Good", type="leak", location="rmc-test")
    _hset(seed)
    logger.info("Seeded STATE_DB %s with %s", LEAK_SENSOR_KEY, seed)
    _restart_bridge(bmc_duthost)
    pyrequire(
        wait_until(BRIDGE_READY_TIMEOUT, 3, 0, lambda: _leak_detector_state(bmc_duthost) == "OK"),
        "{} did not export {} with DetectorState OK within {}s of restarting".format(
            BRIDGE_SERVICE, LEAK_SENSOR_DBUS_PATH, BRIDGE_READY_TIMEOUT)
    )
    logger.info("%s exports %s on D-Bus (DetectorState=OK)", BRIDGE_SERVICE, LEAK_SENSOR_DBUS_PATH)

    def _set_state(state):
        _hset(LEAK_STATES[state])
        logger.info("BMC leak sensor %s set to %s via STATE_DB %s", LEAK_SENSOR, state, LEAK_STATES[state])

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
def host_power_state(bmc_duthost):
    """Write HOST_STATE|switch-host as bmcctld would; returns a setter and restores the row afterwards.

    Only the STATE_DB row is written, never the switch host: bmcctld rewrites
    the row on a real transition and leaves it alone otherwise, so a
    simulated value stays until this fixture restores the snapshot. Requires
    the host to be settled POWERED_ON/ONLINE so nothing real is in flight.
    """
    before = redis_hgetall(bmc_duthost, STATE_DB, HOST_STATE_KEY)
    pyrequire(
        before.get("device_power_state") == "POWERED_ON" and before.get("device_status") == "ONLINE",
        "{} must read POWERED_ON/ONLINE to simulate power events, got: {}".format(HOST_STATE_KEY, before)
    )

    def _write(power_state, device_status):
        redis_hset(bmc_duthost, STATE_DB, HOST_STATE_KEY, device_power_state=power_state, device_status=device_status,
                   last_change_timestamp=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
        logger.info("%s set to device_power_state=%s device_status=%s", HOST_STATE_KEY, power_state, device_status)

    yield lambda power_state: _write(power_state, HOST_POWER_EVENTS[power_state][0])

    _write(before["device_power_state"], before["device_status"])


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
        Environmental.1.1.0.LeakDetectedCritical, Severity Critical, the
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

        Four rack-manager subscriptions: unfiltered, ResourceTypes=[LeakDetector],
        ResourceTypes=[Task] and RegistryPrefixes=[Base]. After a leak event
        the first two have it and the other two have nothing.
        """
        _subscribe(redfish_client, rmc_receiver.url("all"), "ctx-all")
        _subscribe(redfish_client, rmc_receiver.url("leak"), "ctx-leak", ResourceTypes=[LEAK_RESOURCE_TYPE])
        _subscribe(redfish_client, rmc_receiver.url("task"), "ctx-task", ResourceTypes=["Task"])
        _subscribe(redfish_client, rmc_receiver.url("base"), "ctx-base", RegistryPrefixes=["Base"])

        leak_event("Critical")

        for name in ("all", "leak"):
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
        logger.info("Verified leak event reached the unfiltered and ResourceTypes=[%s] subscribers only",
                    LEAK_RESOURCE_TYPE)

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

    def test_host_power_events_delivered(self, redfish_client, rmc_receiver, clean_subscriptions, host_power_state):
        """
        Each switch-host power transition reaches a subscribed rack manager as a ResourceEvent.

        A subscription filtered on ResourceTypes=[ComputerSystem] receives
        ResourcePoweringOff, ResourcePoweredOff, ResourcePoweringOn and
        ResourcePoweredOn, in order and with increasing Ids, as HOST_STATE
        moves through POWERING_OFF, POWERED_OFF, POWERING_ON, POWERED_ON.
        Each event names the ComputerSystem as its origin. A subscription
        filtered on LeakDetector receives none of them.
        """
        _subscribe(redfish_client, rmc_receiver.url("power"), "ctx-power", ResourceTypes=[HOST_RESOURCE_TYPE])
        _subscribe(redfish_client, rmc_receiver.url("leak-only"), "ctx-leak-only", ResourceTypes=[LEAK_RESOURCE_TYPE])

        payloads = []
        for count, power_state in enumerate(("POWERING_OFF", "POWERED_OFF", "POWERING_ON", "POWERED_ON"), 1):
            host_power_state(power_state)
            payloads = _wait_for_deliveries(rmc_receiver, "power", count)
            events = _assert_event_envelope(payloads[-1])
            pytest_assert(len(events) == 1, "Expected exactly one event record, got: {}".format(events))
            _assert_host_power_event(events[0], power_state)
            logger.info("Verified %s delivered for device_power_state=%s", events[0]["MessageId"], power_state)

        ids = [int(p["Id"]) for p in payloads]
        pytest_assert(ids == sorted(ids) and len(set(ids)) == len(ids),
                      "Event payload Ids must increase across the transitions, got: {}".format(ids))
        time.sleep(NO_DELIVERY_SETTLE)
        leak_only = rmc_receiver.deliveries("leak-only")
        pytest_assert(not leak_only,
                      "A LeakDetector-only subscriber must not receive power events, got: {}".format(leak_only))
        logger.info("Verified four power events in order and none at the LeakDetector-only subscriber")

    def test_host_power_off_event_drives_power_on_request(
            self, redfish_client, bmc_duthost, rmc_receiver, clean_subscriptions, host_power_state):
        """
        A rack manager learns the switch host is off from the event and powers it back on over Redfish.

        HOST_STATE reports POWERED_OFF, the subscriber receives
        ResourcePoweredOff, and answers with ComputerSystem.Reset ResetType=On.
        That request must become one RACK_MANAGER_COMMAND row with
        command=POWER_ON that bmcctld completes with status DONE and result
        SUCCESS. bmcctld finds the host already on and so does not rewrite
        HOST_STATE itself, so the row is set back to POWERED_ON here, standing
        in for the write a real power-on would make, and the subscriber must
        then receive ResourcePoweredOn.
        """
        _subscribe(redfish_client, rmc_receiver.url("rm"), "ctx-rm", ResourceTypes=[HOST_RESOURCE_TYPE])
        keys_before = set(redis_keys(bmc_duthost, STATE_DB, COMMAND_KEY_GLOB))

        host_power_state("POWERED_OFF")
        event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, "rm", 1)[0])[0]
        _assert_host_power_event(event, "POWERED_OFF")
        logger.info("Rack manager received %s, requesting ResetType=On", event["MessageId"])

        response = _redfish(redfish_client, "POST", RESET_PATH, json={"ResetType": "On"})
        pytest_assert(response.status_code in (200, 204),
                      "ResetType=On must be accepted with HTTP 200 or 204, got: {}".format(response.status_code))

        def _new_command_keys():
            return set(redis_keys(bmc_duthost, STATE_DB, COMMAND_KEY_GLOB)) - keys_before

        pytest_assert(wait_until(DELIVERY_TIMEOUT, DELIVERY_POLL, 0, _new_command_keys),
                      "No RACK_MANAGER_COMMAND row appeared within {}s of the reset".format(DELIVERY_TIMEOUT))
        new_keys = _new_command_keys()
        pytest_assert(len(new_keys) == 1, "One reset must create one command row, got: {}".format(sorted(new_keys)))
        key = new_keys.pop()

        def _command_done():
            return redis_hgetall(bmc_duthost, STATE_DB, key).get("status") in ("DONE", "FAILED")

        pytest_assert(wait_until(COMMAND_DONE_TIMEOUT, DELIVERY_POLL, 0, _command_done),
                      "{} was not completed by bmcctld within {}s".format(key, COMMAND_DONE_TIMEOUT))
        row = redis_hgetall(bmc_duthost, STATE_DB, key)
        pytest_assert(
            row.get("command") == "POWER_ON" and row.get("status") == "DONE" and row.get("result") == "SUCCESS",
            "{} must end command=POWER_ON status=DONE result=SUCCESS, got: {}".format(key, row)
        )
        logger.info("bmcctld completed %s: %s", key, row)

        host_power_state("POWERED_ON")
        event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, "rm", 2)[1])[0]
        _assert_host_power_event(event, "POWERED_ON")
        logger.info("Verified the rack manager saw the host off, powered it on, and saw it on again")
