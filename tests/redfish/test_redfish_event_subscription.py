"""
Tests for Redfish EventService push subscriptions on the SONiC BMC.

A rack manager subscribes for events by POSTing an EventDestination with its
webhook URL; when the BMC raises an event, bmcweb POSTs an
``#Event.v1_4_0.Event`` payload to that URL. Here the sonic-mgmt test plays
the rack manager: it creates the subscriptions, raises events on the BMC and
verifies what its webhook endpoint received.

Events are raised two ways, both landing in bmcweb's EventServiceManager:

* appending a ``"<RFC3339> <Registry.M.m.Key>,<args>"`` line to the BMC's
  Redfish event log (``/var/log/redfish`` inside the redfish container),
  which bmcweb's inotify watcher formats via the message registries and
  runs through each subscription's filters -- the same path a platform
  daemon logging an event would take;
* ``EventService.SubmitTestEvent``, the DMTF-standard test action, which
  bmcweb fans out verbatim to every subscriber, bypassing filters.

Redis-driven events (leak detection) are not raised by the bridge on this
image, so they are not covered here.

The webhook endpoint is ``redfish_event_listener.py``. It runs in-process in
the test runner when the BMC can reach it, so the flow is a real rack
manager's: bmcweb POSTs over the management network to the subscriber. Where
the BMC cannot initiate connections toward the runner (for example, a
firewall between the two), the listener instead runs on the BMC host and is
addressed by the docker gateway IP -- the one host address bmcweb's
bridge-networked redfish container can reach. Which one is in use is decided
per module by a probe POST from inside that container and stated in the run
log.
"""
import json
import logging
import os
import shlex
import socket
import time
from datetime import datetime, timezone

import pytest
import requests

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.utilities import wait_until
from tests.redfish.redfish_event_listener import EventReceiver
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
# bmcweb's file-backed Redfish event log, watched with inotify inside the container.
EVENT_LOG_FILE = "/var/log/redfish"

RECEIVER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "redfish_event_listener.py")
BMC_RECEIVER_SCRIPT = "/tmp/redfish_event_listener.py"
BMC_RECEIVER_OUTPUT = "/tmp/redfish_events.jsonl"
BMC_RECEIVER_LOG = "/tmp/redfish_event_listener.log"
# Fixed so the "closed port next to the receiver" used by the retry test is predictable.
RECEIVER_PORT = 18081
# pkill pattern that matches the receiver but not the shell issuing the pkill.
BMC_RECEIVER_PKILL = "pkill -f '[p]ython3 {}' || true".format(BMC_RECEIVER_SCRIPT)

# bmcweb delivers asynchronously; the BMC-host receiver is read over SSH per poll.
DELIVERY_TIMEOUT = 30
DELIVERY_POLL = 2
NO_DELIVERY_SETTLE = 8
BMCWEB_READY_TIMEOUT = 90
# EventService on the image retries 3 times at 30 s; connect timeouts add to that.
RETRY_TERMINATION_TIMEOUT = 240
SSE_READ_TIMEOUT = 30

EVENT_ODATA_TYPE = "#Event.v1_4_0.Event"

# Registry messages used as manually raised events. The version in an event
# log line is not checked by bmcweb (the registry's own version is emitted),
# so lines carry a placeholder and assertions match registry + key only.
PSU_FAILED = ("OpenBMC", "PowerSupplyFailed")     # 1 arg, Severity Warning
BASE_SUCCESS = ("Base", "Success")                # 0 args, Severity OK
TEST_EVENT_MESSAGE_ID = "OpenBMC.0.1.TestEventLog"

# Runs a POST from inside the redfish container: exactly the network path bmcweb uses.
PROBE_SNIPPET = ("import sys, urllib.request; "
                 "r = urllib.request.urlopen(urllib.request.Request(sys.argv[1], data=b'{}', method='POST'), "
                 "timeout=5); print(r.status)")


def _message_id_matches(message_id, registry, key):
    return message_id.startswith("{}.".format(registry)) and message_id.endswith(".{}".format(key))


def _event_log_line(registry, key, args, now):
    """Format one bmcweb event-log line; bmcweb strips the fractional seconds on output."""
    line = "{} {}.0.0.{}".format(now.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"), registry, key)
    if args:
        line += "," + ",".join(args)
    return line


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


class RmcReceiver:
    """The rack manager's webhook endpoint as seen by the tests."""

    def __init__(self, base_url, fetch):
        self.base_url = base_url
        self._fetch = fetch

    def url(self, name):
        return "{}/{}".format(self.base_url, name)

    def deliveries(self, name):
        return [r["body"] for r in self._fetch() if r["path"] == "/{}".format(name)]


def _runner_address_facing(bmc_ip):
    """The test runner's own address on the path to the BMC (no packet is sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((bmc_ip, 9))
        return sock.getsockname()[0]
    finally:
        sock.close()


@pytest.fixture(scope="module")
def rmc_receiver(bmc_duthost, bmc_ip, redfish_client):
    """Start the rack manager's webhook endpoint where bmcweb can deliver to it.

    Preferred: in-process in the test runner, addressed by the runner's IP
    facing the BMC. Fallback: the standalone listener on the BMC host,
    addressed by the redfish container's docker gateway. Either way,
    reachability is confirmed with a POST issued from inside the redfish
    container, i.e. the exact network path bmcweb will use for deliveries.
    Depends on redfish_client so the redfish container is up and bmcweb is
    running (bmc_tls_certs) before the probe is issued inside it.
    """
    local = EventReceiver("0.0.0.0", RECEIVER_PORT).start()
    base_url = "http://{}:{}".format(_runner_address_facing(bmc_ip), local.port)
    if wait_until(10, 2, 0, _reachable_from_redfish_container, bmc_duthost, base_url + "/probe"):
        logger.info("RMC receiver running in the test runner at {}".format(base_url))
        yield RmcReceiver(base_url, local.events)
        local.stop()
        return
    local.stop()
    logger.warning("redfish container cannot reach the test runner at %s (management network drops "
                   "BMC-initiated connections); running the RMC receiver on the BMC host instead", base_url)

    gateway = _container_shell(bmc_duthost, "ip -4 route show default")["stdout"].split()[2]
    base_url = "http://{}:{}".format(gateway, RECEIVER_PORT)

    bmc_duthost.copy(src=RECEIVER_SCRIPT, dest=BMC_RECEIVER_SCRIPT)
    bmc_duthost.shell("{}; rm -f {}".format(BMC_RECEIVER_PKILL, BMC_RECEIVER_OUTPUT))
    bmc_duthost.shell(
        "nohup python3 {} --port {} --output {} </dev/null >{} 2>&1 &".format(
            BMC_RECEIVER_SCRIPT, RECEIVER_PORT, BMC_RECEIVER_OUTPUT, BMC_RECEIVER_LOG))
    pyrequire(
        wait_until(20, 2, 0, _reachable_from_redfish_container, bmc_duthost, base_url + "/probe"),
        "redfish container cannot reach the RMC receiver at {}; receiver log: {}".format(
            base_url, bmc_duthost.shell("cat {}".format(BMC_RECEIVER_LOG), module_ignore_errors=True)["stdout"])
    )
    logger.info("RMC receiver running on the BMC host at {}".format(base_url))

    def _fetch():
        out = bmc_duthost.shell("cat {}".format(BMC_RECEIVER_OUTPUT), module_ignore_errors=True)["stdout"]
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    yield RmcReceiver(base_url, _fetch)

    bmc_duthost.shell("{}; rm -f {} {} {}".format(
        BMC_RECEIVER_PKILL, BMC_RECEIVER_SCRIPT, BMC_RECEIVER_OUTPUT, BMC_RECEIVER_LOG),
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


@pytest.fixture(scope="function")
def event_log(bmc_duthost, clean_subscriptions):
    """Fresh, empty Redfish event log in the redfish container; returns an injector.

    Created before any subscription exists: bmcweb only starts watching the
    file once there is a subscriber, and a file that appears after the watch
    is set up gets its first line replayed twice (create + modify).
    """
    _container_shell(bmc_duthost, "rm -f {f}; : > {f}".format(f=EVENT_LOG_FILE))
    logger.info("BMC event log %s reset to empty in the %s container", EVENT_LOG_FILE, REDFISH_CONTAINER)

    def _inject(registry, key, *args):
        now = datetime.now(timezone.utc)
        line = _event_log_line(registry, key, args, now)
        _container_shell(bmc_duthost, "echo {} >> {}".format(shlex.quote(line), EVENT_LOG_FILE))
        logger.info("BMC event raised: appended to %s: %s", EVENT_LOG_FILE, line)
        return now.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    yield _inject

    _container_shell(bmc_duthost, "rm -f {}".format(EVENT_LOG_FILE), module_ignore_errors=True)


class TestRedfishEventSubscription:

    def test_event_service_advertised(self, redfish_client):
        """
        EventService is enabled and advertises what a rack manager needs.

        GET /redfish/v1/EventService: ServiceEnabled, the Subscriptions
        collection link, the SubmitTestEvent action target, the SSE URI and
        the registry prefixes the BMC can filter on (Base and OpenBMC at least).
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

    def test_event_log_event_delivered(self, redfish_client, rmc_receiver, event_log):
        """
        An event raised on the BMC is pushed to the subscribed rack manager.

        The rack manager subscribes; an OpenBMC PowerSupplyFailed line is
        written to the BMC event log; bmcweb must POST one Event payload to
        the subscribed URL carrying the registry-formatted message, the
        MessageArgs, Severity Warning, the subscription Context and the log
        timestamp. A second event (Base.Success) arrives as a second POST
        with a higher Id.
        """
        _subscribe(redfish_client, rmc_receiver.url("events"), "ctx-events")

        stamp = event_log(PSU_FAILED[0], PSU_FAILED[1], "PS1")
        payload = _wait_for_deliveries(rmc_receiver, "events", 1)[0]

        events = _assert_event_envelope(payload)
        pytest_assert(len(events) == 1, "Expected exactly one event record, got: {}".format(events))
        event = events[0]
        pytest_assert(
            _message_id_matches(event.get("MessageId", ""), *PSU_FAILED),
            "MessageId must be {}.<ver>.{}, got: {!r}".format(PSU_FAILED[0], PSU_FAILED[1], event.get("MessageId"))
        )
        assert_field_equals(event, "MessageArgs", ["PS1"])
        assert_field_equals(event, "Severity", "Warning")
        assert_field_equals(event, "Message", "Power supply PS1 failed.")
        assert_field_equals(event, "Context", "ctx-events")
        assert_field_equals(event, "EventTimestamp", stamp)
        pytest_assert(
            str(event.get("EventId", "")).isdigit(),
            "EventId must be a numeric string, got: {!r}".format(event.get("EventId"))
        )
        logger.info("Verified RMC received event: MessageId=%s Severity=%s MessageArgs=%s Context=%s "
                    "EventTimestamp=%s Message=%r", event["MessageId"], event["Severity"], event["MessageArgs"],
                    event["Context"], event["EventTimestamp"], event["Message"])

        event_log(BASE_SUCCESS[0], BASE_SUCCESS[1])
        payloads = _wait_for_deliveries(rmc_receiver, "events", 2)
        pytest_assert(len(payloads) == 2, "Expected exactly two deliveries, got: {}".format(payloads))
        second = _assert_event_envelope(payloads[1])[0]
        pytest_assert(
            _message_id_matches(second.get("MessageId", ""), *BASE_SUCCESS),
            "Second event must be Base.<ver>.Success, got: {!r}".format(second.get("MessageId"))
        )
        assert_field_equals(second, "Severity", "OK")
        pytest_assert(
            int(payloads[1]["Id"]) > int(payloads[0]["Id"]),
            "Event payload Ids must increase: {} then {}".format(payloads[0]["Id"], payloads[1]["Id"])
        )
        logger.info("Verified second event %s delivered as a separate POST (Id %s > %s)",
                    second["MessageId"], payloads[1]["Id"], payloads[0]["Id"])

    def test_registry_prefix_filter(self, redfish_client, rmc_receiver, event_log):
        """
        RegistryPrefixes limits what a subscriber is sent.

        Two rack-manager subscriptions: unfiltered, and RegistryPrefixes=[Base].
        After an OpenBMC event and a Base event, the unfiltered endpoint has
        both while the Base-only endpoint has exactly the Base event.
        """
        _subscribe(redfish_client, rmc_receiver.url("all"), "ctx-all")
        _subscribe(redfish_client, rmc_receiver.url("base"), "ctx-base", RegistryPrefixes=["Base"])

        event_log(PSU_FAILED[0], PSU_FAILED[1], "PS1")
        event_log(BASE_SUCCESS[0], BASE_SUCCESS[1])

        everything = _wait_for_deliveries(rmc_receiver, "all", 2)
        _wait_for_deliveries(rmc_receiver, "base", 1)
        # Give a wrongly forwarded OpenBMC event time to show up before counting.
        time.sleep(NO_DELIVERY_SETTLE)
        base_only = rmc_receiver.deliveries("base")

        ids_all = [e["MessageId"] for p in everything for e in p["Events"]]
        ids_base = [e["MessageId"] for p in base_only for e in p["Events"]]
        logger.info("RMC endpoints received: all=%s base=%s", ids_all, ids_base)
        pytest_assert(
            len(ids_base) == 1 and _message_id_matches(ids_base[0], *BASE_SUCCESS),
            "Base-only subscriber must receive exactly the Base event, got: {}".format(ids_base)
        )
        pytest_assert(
            any(_message_id_matches(i, *PSU_FAILED) for i in ids_all)
            and any(_message_id_matches(i, *BASE_SUCCESS) for i in ids_all),
            "Unfiltered subscriber must receive both events, got: {}".format(ids_all)
        )
        logger.info("Verified RegistryPrefixes=[Base] delivered only the Base event; unfiltered got both")

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

    def test_delete_stops_delivery(self, redfish_client, rmc_receiver, event_log):
        """
        Once a rack manager unsubscribes it receives nothing more; other subscribers still do.
        """
        _, path_a = _subscribe(redfish_client, rmc_receiver.url("keep"), "ctx-keep")
        _, path_b = _subscribe(redfish_client, rmc_receiver.url("gone"), "ctx-gone")

        event_log(PSU_FAILED[0], PSU_FAILED[1], "PS1")
        _wait_for_deliveries(rmc_receiver, "keep", 1)
        _wait_for_deliveries(rmc_receiver, "gone", 1)

        response = _redfish(redfish_client, "DELETE", path_b)
        pytest_assert(response.status_code in (200, 204), "DELETE {} -> {}".format(path_b, response.status_code))

        event_log(PSU_FAILED[0], PSU_FAILED[1], "PS2")
        _wait_for_deliveries(rmc_receiver, "keep", 2)
        time.sleep(NO_DELIVERY_SETTLE)
        gone = rmc_receiver.deliveries("gone")
        pytest_assert(
            len(gone) == 1,
            "Unsubscribed endpoint must not receive further events, got {} deliveries: {}".format(len(gone), gone)
        )
        logger.info("Verified after unsubscribe: 'keep' received the second event, 'gone' still has %d", len(gone))

    def test_subscription_persists_across_bmcweb_restart(
            self, redfish_client, bmc_duthost, rmc_receiver, event_log):
        """
        A subscription survives a bmcweb restart and keeps delivering.

        bmcweb persists subscriptions to disk; after `supervisorctl restart
        bmcweb` the subscription is still listed with the same Destination and
        Context, and a new event is delivered to it.
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

        event_log(PSU_FAILED[0], PSU_FAILED[1], "PS1")
        event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, "persist", 1)[0])[0]
        pytest_assert(
            _message_id_matches(event.get("MessageId", ""), *PSU_FAILED),
            "Post-restart delivery must be the injected event, got: {!r}".format(event.get("MessageId"))
        )
        logger.info("Verified delivery still works after the bmcweb restart")

    def test_sse_stream_receives_events(self, redfish_client, event_log):
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

            event_log(PSU_FAILED[0], PSU_FAILED[1], "PS1")

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
            pytest_assert(
                _message_id_matches(event.get("MessageId", ""), *PSU_FAILED),
                "SSE event must be the injected event, got: {!r}".format(event.get("MessageId"))
            )
            assert_field_equals(event, "MessageArgs", ["PS1"])
            logger.info("Verified SSE frame carries the raised event %s", event["MessageId"])
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
        "bmcweb validates MessageIds against bare registry keys on POST but matches "
        "'<Registry>.<Key>' at delivery, so a MessageIds-filtered subscriber never receives anything"))
    def test_message_id_filter(self, redfish_client, rmc_receiver, event_log):
        """
        MessageIds limits a subscriber to the listed messages (DMTF EventDestination).

        Expected: a MessageIds=["PowerSupplyFailed"] subscriber receives the
        PowerSupplyFailed event. Marked strict xfail while bmcweb's filter
        cannot match; a fixed bmcweb turns this into a failure to be removed.
        """
        _subscribe(redfish_client, rmc_receiver.url("psu"), "ctx-psu", MessageIds=[PSU_FAILED[1]])
        event_log(PSU_FAILED[0], PSU_FAILED[1], "PS1")
        logger.info("Expecting the MessageIds=[%s] subscriber to receive the event (known bmcweb gap: "
                    "it currently never does, hence xfail)", PSU_FAILED[1])
        event = _assert_event_envelope(_wait_for_deliveries(rmc_receiver, "psu", 1)[0])[0]
        pytest_assert(
            _message_id_matches(event.get("MessageId", ""), *PSU_FAILED),
            "MessageIds subscriber must receive PowerSupplyFailed, got: {!r}".format(event.get("MessageId"))
        )
