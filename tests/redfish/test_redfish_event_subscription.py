"""
Tests for Redfish EventService push subscriptions on the SONiC BMC.

A rack manager subscribes for events by POSTing an EventDestination with its
webhook URL; when the BMC raises an event, bmcweb POSTs an
``#Event.v1_4_0.Event`` payload to that URL. Here the sonic-mgmt test plays
the rack manager: it creates the subscriptions, raises events on the BMC and
verifies what its webhook endpoint received.

Events are raised two ways, both landing in bmcweb's EventServiceManager:

* the SONiC-BMC leak detection path (sonic-redfish): a platform daemon
  writes ``LIQUID_COOLING_INFO|<sensor>`` to STATE_DB, ``sonic-dbus-bridge``
  mirrors it as ``xyz.openbmc_project.Inventory.Item.LeakDetector`` on D-Bus,
  and bmcweb's rmc-events leak monitor turns each ``DetectorState`` change
  into an ``Environmental.1.1.0.LeakDetected{Critical,Warning,Normal}`` event
  with resource type ``LeakDetector``. The test stands in for the platform
  daemon by seeding a synthetic sensor row and flipping its state;
* ``EventService.SubmitTestEvent``, the DMTF-standard test action, which
  bmcweb fans out verbatim to every subscriber, bypassing filters.

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
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    assert_field_equals,
    assert_no_content,
    assert_redfish_error,
    assert_status_ok,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

EVENT_SERVICE_PATH = "/redfish/v1/EventService"
SUBSCRIPTIONS_PATH = "{}/Subscriptions".format(EVENT_SERVICE_PATH)
SUBMIT_TEST_EVENT_PATH = "{}/Actions/EventService.SubmitTestEvent".format(EVENT_SERVICE_PATH)
SSE_PATH = "{}/SSE".format(EVENT_SERVICE_PATH)
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
# EventService on the image retries 3 times at 30 s; connect timeouts add to that.
RETRY_TERMINATION_TIMEOUT = 240
SSE_READ_TIMEOUT = 30

EVENT_ODATA_TYPE = "#Event.v1_4_0.Event"
TEST_EVENT_MESSAGE_ID = "OpenBMC.0.1.TestEventLog"

# Synthetic leak sensor the test plays platform daemon for. sonic-dbus-bridge
# discovers LIQUID_COOLING_INFO|* rows only at startup, so the row is seeded
# and the bridge restarted once per module.
LEAK_SENSOR = "rmc_test_leak"
LEAK_SENSOR_KEY = "LIQUID_COOLING_INFO|{}".format(LEAK_SENSOR)
LEAK_SENSOR_DBUS_PATH = "/xyz/openbmc_project/sensors/leak/{}".format(LEAK_SENSOR)
LEAK_DETECTOR_IFACE = "xyz.openbmc_project.Inventory.Item.LeakDetector"
BRIDGE_BUS_NAME = "xyz.openbmc_project.Inventory.Manager"
LEAK_ORIGIN = "/redfish/v1/Chassis/BMC/ThermalSubsystem/LeakDetection/LeakDetectors/{}".format(LEAK_SENSOR)
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


class TestRedfishEventSubscription:

    def test_event_service_advertised(self, redfish_client):
        """
        EventService is enabled and advertises what a rack manager needs.

        GET /redfish/v1/EventService: ServiceEnabled, the Subscriptions
        collection link, the SubmitTestEvent action target, the SSE URI and
        the registry prefixes the BMC can filter on (Base and OpenBMC at least).
        Whether the Environmental registry and LeakDetector resource type are
        advertised is logged, and gates the leak-event tests below.
        """
        response = redfish_client.get(EVENT_SERVICE_PATH)
        assert_status_ok(response, EVENT_SERVICE_PATH)
        body = response.json()
        logger.info("EventService: {}".format(body))

        assert_field_equals(body, "@odata.id", EVENT_SERVICE_PATH)
        assert_field_equals(body, "ServiceEnabled", True)
        assert_field_equals(body, "ServerSentEventUri", SSE_PATH)
        pytest_assert(
            body.get("Status", {}).get("State") == "Enabled",
            "Status.State must be 'Enabled', got: {!r}".format(body.get("Status"))
        )
        pytest_assert(
            body.get("Subscriptions", {}).get("@odata.id") == SUBSCRIPTIONS_PATH,
            "Subscriptions link must be {!r}, got: {!r}".format(SUBSCRIPTIONS_PATH, body.get("Subscriptions"))
        )
        target = body.get("Actions", {}).get("#EventService.SubmitTestEvent", {}).get("target")
        pytest_assert(
            target == SUBMIT_TEST_EVENT_PATH,
            "SubmitTestEvent target must be {!r}, got: {!r}".format(SUBMIT_TEST_EVENT_PATH, target)
        )
        prefixes = set(body.get("RegistryPrefixes", []))
        pytest_assert(
            {"Base", "OpenBMC"} <= prefixes,
            "RegistryPrefixes must include Base and OpenBMC, got: {}".format(sorted(prefixes))
        )
        pytest_assert(
            isinstance(body.get("DeliveryRetryAttempts"), int) and body["DeliveryRetryAttempts"] >= 1,
            "DeliveryRetryAttempts must be a positive integer, got: {!r}".format(body.get("DeliveryRetryAttempts"))
        )
        logger.info("Leak events advertised: %s registry=%s, %s resource type=%s", LEAK_REGISTRY,
                    LEAK_REGISTRY in prefixes, LEAK_RESOURCE_TYPE, LEAK_RESOURCE_TYPE in body.get("ResourceTypes", []))

    def test_subscription_lifecycle(self, redfish_client, rmc_receiver, clean_subscriptions):
        """
        A push subscription can be created, read back, updated and removed.

        POST -> 201 with Location; GET echoes the destination, context and the
        defaults bmcweb applies (Protocol Redfish, SubscriptionType
        RedfishEvent, EventFormatType Event, DeliveryRetryPolicy
        TerminateAfterRetries); the collection lists it; PATCH changes the
        Context; DELETE removes it and a further GET is 404.
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
        assert_field_equals(body, "DeliveryRetryPolicy", "TerminateAfterRetries")
        assert_field_equals(body, "RegistryPrefixes", [])
        assert_field_equals(body, "MessageIds", [])
        pytest_assert(
            sub_id in _subscription_ids(redfish_client),
            "Subscription {} missing from {}".format(sub_id, SUBSCRIPTIONS_PATH)
        )

        logger.info("Verified GET shows the subscribed Destination/Context and bmcweb defaults")
        response = _redfish(redfish_client, "PATCH", path, json={"Context": "ctx-updated"})
        pytest_assert(
            response.status_code in (200, 204),
            "PATCH {} expected 200/204, got: {} body={!r}".format(path, response.status_code, response.text[:300])
        )
        assert_field_equals(_redfish(redfish_client, "GET", path).json(), "Context", "ctx-updated")
        logger.info("Verified PATCH updated Context to 'ctx-updated'")

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

    def test_delete_unknown_subscription(self, redfish_client, clean_subscriptions):
        """DELETE of a subscription id that does not exist is 404 ResourceNotFound."""
        path = "{}/424242".format(SUBSCRIPTIONS_PATH)
        assert_redfish_error(_redfish(redfish_client, "DELETE", path), 404, "ResourceNotFound",
                             message_args=["EventDestination", "424242"])
        logger.info("Verified DELETE of unknown subscription -> 404 ResourceNotFound")

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
            _assert_leak_event(_assert_event_envelope(_wait_for_deliveries(rmc_receiver, name, 1)[0])[0], "Critical")
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

    def test_submit_test_event_delivered(self, redfish_client, rmc_receiver, clean_subscriptions):
        """
        EventService.SubmitTestEvent reaches every subscriber with the fields passed through.

        bmcweb fans a test event out to all subscriptions regardless of their
        filters, so a RegistryPrefixes=[Base] subscriber receives an OpenBMC
        test event too. MessageId, MessageArgs, Severity, Message,
        OriginOfCondition and EventTimestamp are forwarded as submitted.
        """
        _subscribe(redfish_client, rmc_receiver.url("test-all"), "ctx-test-all")
        _subscribe(redfish_client, rmc_receiver.url("test-base"), "ctx-test-base", RegistryPrefixes=["Base"])

        submitted = {
            "MessageId": TEST_EVENT_MESSAGE_ID,
            "MessageArgs": [],
            "Severity": "OK",
            "Message": "rack manager delivery check",
            "OriginOfCondition": "/redfish/v1/Chassis/chassis",
            "EventTimestamp": "2026-01-01T00:00:00+00:00",
        }
        response = _redfish(redfish_client, "POST", SUBMIT_TEST_EVENT_PATH, json=submitted)
        assert_no_content(response, SUBMIT_TEST_EVENT_PATH)

        for name in ("test-all", "test-base"):
            payload = _wait_for_deliveries(rmc_receiver, name, 1)[0]
            event = _assert_event_envelope(payload)[0]
            for field in ("MessageId", "MessageArgs", "Severity", "Message", "EventTimestamp"):
                assert_field_equals(event, field, submitted[field])
            pytest_assert(
                event.get("OriginOfCondition", {}).get("@odata.id") == submitted["OriginOfCondition"],
                "[{}] OriginOfCondition must be {!r}, got: {!r}".format(
                    name, submitted["OriginOfCondition"], event.get("OriginOfCondition"))
            )
            assert_field_equals(event, "MemberId", "0")
            logger.info("[%s] Verified test event delivered with all submitted fields", name)

    def test_delete_stops_delivery(self, redfish_client, rmc_receiver, leak_event):
        """
        Once a rack manager unsubscribes it receives nothing more; other subscribers still do.
        """
        _, path_a = _subscribe(redfish_client, rmc_receiver.url("keep"), "ctx-keep")
        _, path_b = _subscribe(redfish_client, rmc_receiver.url("gone"), "ctx-gone")

        leak_event("Critical")
        _wait_for_deliveries(rmc_receiver, "keep", 1)
        _wait_for_deliveries(rmc_receiver, "gone", 1)

        response = _redfish(redfish_client, "DELETE", path_b)
        pytest_assert(response.status_code in (200, 204), "DELETE {} -> {}".format(path_b, response.status_code))

        leak_event("OK")
        _wait_for_deliveries(rmc_receiver, "keep", 2)
        time.sleep(NO_DELIVERY_SETTLE)
        gone = rmc_receiver.deliveries("gone")
        pytest_assert(
            len(gone) == 1,
            "Unsubscribed endpoint must not receive further events, got {} deliveries: {}".format(len(gone), gone)
        )
        logger.info("Verified after unsubscribe: 'keep' received the second event, 'gone' still has %d", len(gone))

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

    def test_sse_stream_receives_events(self, redfish_client, leak_event):
        """
        The rack manager can also pull events over Server-Sent Events.

        GET /redfish/v1/EventService/SSE (HTTP/1.1, Accept: text/event-stream)
        opens a stream, which shows up as an SSE-type subscription while open.
        An event raised on the BMC arrives as an SSE frame whose data is the
        same #Event payload the push path uses. Closing the stream removes the
        subscription.
        """
        logger.info("RMC --> GET %s (HTTP/1.1, Accept: text/event-stream, streaming)", SSE_PATH)
        response = redfish_client.get(
            SSE_PATH, stream=True, headers={"Accept": "text/event-stream"}, timeout=(10, SSE_READ_TIMEOUT))
        try:
            logger.info("BMC <-- GET %s HTTP %s Content-Type=%s", SSE_PATH, response.status_code,
                        response.headers.get("Content-Type"))
            assert_status_ok(response, SSE_PATH)
            content_type = response.headers.get("Content-Type", "")
            pytest_assert(
                "text/event-stream" in content_type,
                "SSE Content-Type must be text/event-stream, got: {!r}".format(content_type)
            )
            pytest_assert(
                wait_until(10, 1, 0, lambda: len(_subscription_ids(redfish_client)) == 1),
                "Open SSE stream must appear as one subscription, got: {}".format(_subscription_ids(redfish_client))
            )
            sub = _redfish(redfish_client, "GET",
                           "{}/{}".format(SUBSCRIPTIONS_PATH, _subscription_ids(redfish_client)[0])).json()
            assert_field_equals(sub, "SubscriptionType", "SSE")
            logger.info("Verified open SSE stream is listed as subscription %s (SubscriptionType=SSE)", sub["Id"])

            leak_event("Critical")

            # Byte-sized reads: the SSE response has no Content-Length, so
            # iter_lines() (512-byte chunks) and chunk_size=None (read to EOF)
            # both sit on a small frame until the read timeout.
            data_lines = []
            payload = None
            buffered = b""
            try:
                for chunk in response.iter_content(chunk_size=1):
                    buffered += chunk
                    while b"\n" in buffered and payload is None:
                        raw_line, buffered = buffered.split(b"\n", 1)
                        line = raw_line.decode("utf-8", "replace").rstrip("\r")
                        if line.startswith("data:"):
                            data_lines.append(line[len("data:"):].strip())
                        elif line == "" and data_lines:
                            payload = json.loads("".join(data_lines))
                    if payload is not None:
                        break
            except requests.exceptions.RequestException as e:
                pytest.fail("SSE stream ended before an event frame arrived: {}".format(e))
            pytest_assert(payload is not None, "No complete SSE event frame received")
            logger.info("RMC received SSE frame: %s", _compact(json.dumps(payload, sort_keys=True)))
            event = _assert_event_envelope(payload)[0]
            _assert_leak_event(event, "Critical")
            logger.info("Verified SSE frame carries the leak event %s", event["MessageId"])
        finally:
            response.close()
            logger.info("RMC closed the SSE stream")

        pytest_assert(
            wait_until(20, 2, 0, lambda: not _subscription_ids(redfish_client)),
            "SSE subscription must disappear once the stream is closed, got: {}".format(
                _subscription_ids(redfish_client))
        )
        logger.info("Verified SSE subscription removed after the stream closed")

    def test_unreachable_destination_terminates(self, redfish_client, rmc_receiver, clean_subscriptions):
        """
        Delivery retries are bounded by DeliveryRetryPolicy.

        Two subscriptions point at a closed port next to the receiver:
        TerminateAfterRetries (the default) must be removed by bmcweb once the
        configured DeliveryRetryAttempts are exhausted; RetryForever must stay.
        The reachable receiver keeps its subscription throughout.
        """
        host, port = rmc_receiver.base_url.rsplit(":", 1)
        dead = "{}:{}/dead".format(host, int(port) + 1)
        _, terminate_path = _subscribe(redfish_client, dead, "ctx-terminate")
        _, forever_path = _subscribe(redfish_client, dead, "ctx-forever", DeliveryRetryPolicy="RetryForever")
        _, live_path = _subscribe(redfish_client, rmc_receiver.url("live"), "ctx-live")

        response = _redfish(redfish_client, "POST", SUBMIT_TEST_EVENT_PATH, json={"MessageId": TEST_EVENT_MESSAGE_ID})
        assert_no_content(response, SUBMIT_TEST_EVENT_PATH)
        _wait_for_deliveries(rmc_receiver, "live", 1)

        logger.info("Waiting up to %ds for bmcweb to prune the TerminateAfterRetries subscription %s "
                    "(deliveries to %s fail; EventService retries 3 x 30s)", RETRY_TERMINATION_TIMEOUT,
                    terminate_path, dead)
        start = time.time()
        pytest_assert(
            wait_until(RETRY_TERMINATION_TIMEOUT, 10, 0,
                       lambda: redfish_client.get(terminate_path).status_code == 404),
            "TerminateAfterRetries subscription still present after {}s of failed deliveries".format(
                RETRY_TERMINATION_TIMEOUT)
        )
        logger.info("TerminateAfterRetries subscription removed after ~{:.0f}s".format(time.time() - start))
        assert_status_ok(_redfish(redfish_client, "GET", forever_path), forever_path)
        assert_status_ok(_redfish(redfish_client, "GET", live_path), live_path)
        logger.info("Verified RetryForever and reachable subscriptions are still present")

    @pytest.mark.xfail(strict=True, reason=(
        "bmcweb's eventMatchesFilter splits MessageId on '.' and only recognises the 4-field "
        "'Registry.Major.Minor.Key' form, so the 5-field Environmental.1.1.0.* leak MessageIds "
        "resolve to an empty registry and a RegistryPrefixes=[Environmental] subscriber never receives them"))
    def test_registry_prefix_filter_environmental(self, redfish_client, rmc_receiver, leak_event):
        """
        RegistryPrefixes=[Environmental] should pass the leak events (DMTF EventDestination).

        bmcweb advertises Environmental in EventService.RegistryPrefixes and
        accepts the subscription, so a rack manager filtering on it expects
        the leak events. Marked strict xfail while bmcweb's delivery-side
        filter cannot match them; a fixed bmcweb turns this into a failure to
        be removed.
        """
        _subscribe(redfish_client, rmc_receiver.url("env"), "ctx-env", RegistryPrefixes=[LEAK_REGISTRY])
        leak_event("Critical")
        logger.info("Expecting the RegistryPrefixes=[%s] subscriber to receive the leak event (known bmcweb gap: "
                    "it currently never does, hence xfail)", LEAK_REGISTRY)
        event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, "env", 1)[0])[0]
        _assert_leak_event(event, "Critical")

    def test_leak_detector_resource_tracks_state(self, redfish_client, leak_event):
        """
        The LeakDetector resource a leak event points at reflects the live sensor state.

        pmon-bmc-design.md section 2.1.2 item 6 models BMC leak sensors under
        Chassis/<id>/ThermalSubsystem/LeakDetection. A rack manager that
        follows OriginOfCondition from a leak event must find the detector
        listed in the LeakDetectors collection, and GET on it must report
        DetectorState and Status.Health moving OK -> Critical -> OK with the
        STATE_DB row, while the LeakDetection resource aggregates the worst
        detector into its own Status.Health.
        """
        leak_detection = LEAK_ORIGIN.rsplit("/LeakDetectors/", 1)[0]
        collection = "{}/LeakDetectors".format(leak_detection)

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
            health = redfish_client.get(leak_detection).json().get("Status", {}).get("Health")
            if state == "Critical":
                pytest_assert(health == "Critical",
                              "{} Status.Health must aggregate to Critical, got: {!r}".format(leak_detection, health))
            logger.info("Verified %s DetectorState=%s, %s Health=%s", LEAK_ORIGIN, state, leak_detection, health)
