"""
Tests for Redfish behaviour under concurrent rack manager requests.

A rack manager polls inventory continuously and issues actions and
subscription changes from other threads at the same time. bmcweb serves
every request from one event loop and, on the SONiC BMC, resolves inventory
through synchronous-looking D-Bus calls into ``sonic-dbus-bridge``. A reset
request travels Redfish -> bmcweb -> D-Bus ``RequestedHostTransition`` ->
the bridge's action queue -> a ``RACK_MANAGER_COMMAND|<id>`` row in STATE_DB.

Two situations are exercised:

* reset requests while several pollers walk the inventory: every request
  must be answered, the inventory must not change shape mid-poll, every
  reset must reach STATE_DB and nothing may restart underneath
* the same subscription created and deleted by several callers at once:
  each accepted create must be an independent subscription, each id may be
  deleted exactly once and the collection must be empty again at the end
"""
import json
import logging
import re
import shlex
import threading
import time

import pytest
import requests

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import assert_status_ok, host_is_settled_on

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

SYSTEM_PATH = "/redfish/v1/Systems/system"
RESET_PATH = SYSTEM_PATH + "/Actions/ComputerSystem.Reset"
SUBSCRIPTIONS_PATH = "/redfish/v1/EventService/Subscriptions"
# Resources the rack manager interface touches: leak detectors live under
# Chassis, the OEM actions under Managers, and the firmware inventory.
INVENTORY_COLLECTIONS = [
    "/redfish/v1/Chassis",
    "/redfish/v1/Managers",
    "/redfish/v1/UpdateService/FirmwareInventory",
]
REDFISH_CONTAINER = "redfish"

HOST_STATE_BUS = "xyz.openbmc_project.State.Host"
HOST_STATE_PATH = "/xyz/openbmc_project/state/host0"
HOST_STATE_IFACE = "xyz.openbmc_project.State.Host"
TRANSITION_ON = "xyz.openbmc_project.State.Host.Transition.On"
# STATE_DB row the bridge writes per accepted transition, and the row the
# host side keeps for the switch host's power state.
COMMAND_KEY_GLOB = "RACK_MANAGER_COMMAND|*"
HOST_STATE_KEY = "HOST_STATE|switch-host"
STATE_DB_INDEX = 6

POLLERS = 4
RESET_REQUESTS = 5
RESET_SPACING = 1.0
POLL_TAIL = 5.0
REQUEST_TIMEOUT = 30
COMMAND_ROW_TIMEOUT = 30

CREATORS = 8
DELETERS_PER_ID = 3
CHURN_WORKERS = 4
CHURN_ITERATIONS = 5
# RFC 5737 documentation address, never delivered to. bmcweb stores a
# Destination with its port made explicit, so give it one to read back exactly.
DUPLICATE_DESTINATION = "http://192.0.2.1:80/concurrency"
DUPLICATE_CONTEXT = "concurrency-duplicate"


def _container_shell(bmc_duthost, cmd, **kwargs):
    return bmc_duthost.shell("docker exec {} sh -c {}".format(REDFISH_CONTAINER, shlex.quote(cmd)), **kwargs)


def _supervisor_pids(bmc_duthost):
    """{program: pid} for every RUNNING supervisord program in the redfish container."""
    res = _container_shell(bmc_duthost, "supervisorctl status", module_ignore_errors=True)
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"^(\S+)\s+RUNNING\s+pid (\d+)", res["stdout"], re.M)}


def _requested_host_transition(bmc_duthost):
    res = _container_shell(
        bmc_duthost,
        "dbus-send --system --print-reply --dest={} {} org.freedesktop.DBus.Properties.Get "
        "string:{} string:RequestedHostTransition".format(HOST_STATE_BUS, HOST_STATE_PATH, HOST_STATE_IFACE),
        module_ignore_errors=True,
    )
    match = re.search(r'string "([^"]+)"', res["stdout"])
    return match.group(1) if match else None


def _state_db_hgetall(bmc_duthost, key):
    res = bmc_duthost.shell("redis-cli -n {} hgetall {}".format(STATE_DB_INDEX, shlex.quote(key)),
                            module_ignore_errors=True)
    lines = res["stdout"].splitlines()
    return dict(zip(lines[0::2], lines[1::2]))


def _run_threads(workers):
    """Start every callable in `workers` on its own thread, release them together and join them."""
    barrier = threading.Barrier(len(workers))
    errors = []

    def _wrap(fn):
        def _run():
            barrier.wait()
            try:
                fn()
            except Exception as e:
                logger.exception("worker failed")
                errors.append("{}: {}".format(type(e).__name__, e))
        return _run

    threads = [threading.Thread(target=_wrap(fn), daemon=True) for fn in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    pytest_assert(not errors, "Worker threads raised: {}".format(errors))


def _member_ids(body):
    return sorted(m.get("@odata.id", "") for m in body.get("Members", []))


def _subscription_ids(redfish_client):
    response = redfish_client.get(SUBSCRIPTIONS_PATH)
    assert_status_ok(response, SUBSCRIPTIONS_PATH)
    return [m["@odata.id"].rsplit("/", 1)[1] for m in response.json().get("Members", [])]


def _delete_all_subscriptions(redfish_client):
    leftovers = _subscription_ids(redfish_client)
    if leftovers:
        logger.info("Removing existing subscriptions: %s", leftovers)
    for sub_id in leftovers:
        redfish_client.delete("{}/{}".format(SUBSCRIPTIONS_PATH, sub_id))


@pytest.fixture
def clean_subscriptions(redfish_client):
    """No subscriptions before or after a test, so counts start from and return to zero."""
    _delete_all_subscriptions(redfish_client)
    yield
    _delete_all_subscriptions(redfish_client)


def _command_keys(bmc_duthost):
    res = bmc_duthost.shell("redis-cli -n {} keys {}".format(STATE_DB_INDEX, shlex.quote(COMMAND_KEY_GLOB)),
                            module_ignore_errors=True)
    return {line.strip() for line in res["stdout"].splitlines() if line.strip()}


@pytest.fixture
def command_rows(bmc_duthost):
    """RACK_MANAGER_COMMAND rows added to STATE_DB since the test started.

    bmcctld leaves completed rows in place (pmon-bmc-design.md 2.1.2.1), so
    the keys present before the test are snapshotted and the callable returns
    the sorted keys that appeared since.
    """
    before = _command_keys(bmc_duthost)
    yield lambda: sorted(_command_keys(bmc_duthost) - before)


def _assert_nothing_restarted(bmc_duthost, pids_before):
    pids_after = _supervisor_pids(bmc_duthost)
    pytest_assert(
        pids_after == pids_before,
        "A redfish container program restarted or died during the test: before={} after={}".format(
            pids_before, pids_after)
    )


def _running_pids(bmc_duthost):
    pids = _supervisor_pids(bmc_duthost)
    for program in ("bmcweb", "sonic-dbus-bridge"):
        pytest_assert(program in pids, "{} is not RUNNING before the test".format(program))
    return pids


class TestRedfishConcurrency:

    def test_reset_concurrent_with_inventory_poll(self, redfish_client, bmc_duthost, command_rows):
        """
        ResetType=On requests while several pollers walk the inventory.

        HOST_STATE must already show the switch host settled on so the
        resets are no-ops for it and only exercise the request path. Every
        poll must be answered 200 with the same members as before, every
        reset must be accepted and turn into a RequestedHostTransition on
        D-Bus and a RACK_MANAGER_COMMAND row in STATE_DB, HOST_STATE must
        show the host on and unchanged afterwards and neither bmcweb nor the
        bridge may restart.
        """
        host_state_before = _state_db_hgetall(bmc_duthost, HOST_STATE_KEY)
        logger.info("%s before: %s", HOST_STATE_KEY, host_state_before)
        if not host_is_settled_on(host_state_before):
            pytest.skip("{} is {}, ResetType=On would change the switch host".format(
                HOST_STATE_KEY, host_state_before))
        pids_before = _running_pids(bmc_duthost)

        baseline = {}
        paths = []
        for collection in INVENTORY_COLLECTIONS:
            response = redfish_client.get(collection)
            assert_status_ok(response, collection)
            baseline[collection] = _member_ids(response.json())
            paths.append(collection)
            paths.extend(baseline[collection])
        logger.info("Polling %d paths from %d threads: %s", len(paths), POLLERS, json.dumps(baseline, sort_keys=True))

        stop = threading.Event()
        polls = []
        resets = []

        def _poller():
            while not stop.is_set():
                for path in paths:
                    started = time.time()
                    record = {"path": path, "elapsed": None, "status": None}
                    try:
                        response = redfish_client.get(path, timeout=REQUEST_TIMEOUT)
                        record["status"] = response.status_code
                        if response.status_code == 200:
                            body = response.json()
                            if path in baseline:
                                record["members"] = _member_ids(body)
                    except requests.exceptions.RequestException as e:
                        record["status"] = type(e).__name__
                    record["elapsed"] = time.time() - started
                    polls.append(record)
                    if stop.is_set():
                        break

        def _resetter():
            for _ in range(RESET_REQUESTS):
                started = time.time()
                response = redfish_client.post(RESET_PATH, json={"ResetType": "On"}, timeout=REQUEST_TIMEOUT)
                resets.append((response.status_code, time.time() - started))
                logger.info("POST %s ResetType=On -> HTTP %s in %.2fs", RESET_PATH, response.status_code, resets[-1][1])
                time.sleep(RESET_SPACING)
            time.sleep(POLL_TAIL)
            stop.set()

        _run_threads([_resetter] + [_poller] * POLLERS)

        pytest_assert(
            len(resets) == RESET_REQUESTS and all(status == 204 for status, _ in resets),
            "Every reset must be accepted with HTTP 204 under load, got: {}".format(resets)
        )
        failed = [(r["path"], r["status"]) for r in polls if r["status"] != 200]
        pytest_assert(
            not failed,
            "{} of {} inventory polls were not answered 200 while resets were in flight, e.g. {}".format(
                len(failed), len(polls), failed[:10])
        )
        drifted = [(r["path"], r["members"]) for r in polls if "members" in r and r["members"] != baseline[r["path"]]]
        pytest_assert(
            not drifted,
            "Collection membership changed while resets were in flight, e.g. {}".format(drifted[:5])
        )
        slowest = max(polls, key=lambda r: r["elapsed"])
        logger.info("%d polls answered 200, slowest %s in %.2fs, slowest reset %.2fs",
                    len(polls), slowest["path"], slowest["elapsed"], max(t for _, t in resets))

        requested = _requested_host_transition(bmc_duthost)
        pytest_assert(
            requested == TRANSITION_ON,
            "D-Bus {} RequestedHostTransition must be {} after the resets, got: {!r}".format(
                HOST_STATE_PATH, TRANSITION_ON, requested)
        )
        pytest_assert(
            wait_until(COMMAND_ROW_TIMEOUT, 2, 0, lambda: len(command_rows()) >= RESET_REQUESTS),
            "Only {} RACK_MANAGER_COMMAND rows reached STATE_DB for {} accepted resets within {}s".format(
                len(command_rows()), RESET_REQUESTS, COMMAND_ROW_TIMEOUT)
        )
        rows = command_rows()
        pytest_assert(
            len(rows) == RESET_REQUESTS,
            "Expected exactly one RACK_MANAGER_COMMAND row per reset ({}), got {}: {}".format(
                RESET_REQUESTS, len(rows), rows)
        )
        logger.info("STATE_DB received %d RACK_MANAGER_COMMAND rows: %s", len(rows), rows)

        def _host_settled_on():
            return host_is_settled_on(_state_db_hgetall(bmc_duthost, HOST_STATE_KEY))

        pytest_assert(wait_until(COMMAND_ROW_TIMEOUT, 2, 0, _host_settled_on),
                      "{} did not show the switch host settled on again within {}s".format(
                          HOST_STATE_KEY, COMMAND_ROW_TIMEOUT))
        host_state_after = _state_db_hgetall(bmc_duthost, HOST_STATE_KEY)
        logger.info("%s after: %s", HOST_STATE_KEY, host_state_after)
        if host_state_before:
            pytest_assert(
                host_state_after.get("device_power_state") == host_state_before.get("device_power_state"),
                "{} device_power_state changed across ResetType=On requests: {} -> {}".format(
                    HOST_STATE_KEY, host_state_before, host_state_after)
            )
        _assert_nothing_restarted(bmc_duthost, pids_before)
        logger.info("Verified %d resets and %d concurrent inventory polls were all served", len(resets), len(polls))

    def test_duplicate_subscription_create_and_delete(self, redfish_client, bmc_duthost, clean_subscriptions):
        """
        The same subscription body POSTed by several callers at once, then
        every resulting id DELETEd by several callers at once.

        bmcweb does not reject a repeated Destination, so each POST must be
        answered 201 with its own id and the collection must list exactly
        those ids. Concurrent DELETEs of each id must all be answered promptly
        with 2xx or 404, never a 5xx or a hang, and the collection must be
        empty afterwards.
        """
        pids_before = _running_pids(bmc_duthost)
        body = {"Destination": DUPLICATE_DESTINATION, "Protocol": "Redfish", "Context": DUPLICATE_CONTEXT}
        creates = []

        def _create():
            response = redfish_client.post(SUBSCRIPTIONS_PATH, json=body, timeout=REQUEST_TIMEOUT)
            creates.append((response.status_code, response.headers.get("Location", ""), response.text[:300]))

        _run_threads([_create] * CREATORS)
        logger.info("%d concurrent creates: %s", CREATORS, [(s, loc) for s, loc, _ in creates])
        pytest_assert(
            len(creates) == CREATORS and all(status == 201 for status, _, _ in creates),
            "Every concurrent create must be answered 201, got: {}".format(creates)
        )
        ids = [location.rsplit("/", 1)[1] for _, location, _ in creates]
        pytest_assert(len(set(ids)) == len(ids),
                      "Two concurrent creates were given the same subscription id: {}".format(ids))
        listed = sorted(_subscription_ids(redfish_client))
        pytest_assert(
            listed == sorted(ids),
            "Collection must list exactly the {} created subscriptions, got: {}".format(sorted(ids), listed)
        )
        for _, location, _ in creates:
            response = redfish_client.get(location)
            assert_status_ok(response, location)
            pytest_assert(
                response.json().get("Destination") == DUPLICATE_DESTINATION,
                "{} Destination is {!r}".format(location, response.json().get("Destination"))
            )

        deletes = []

        def _delete(sub_id):
            path = "{}/{}".format(SUBSCRIPTIONS_PATH, sub_id)
            response = redfish_client.delete(path, timeout=REQUEST_TIMEOUT)
            deletes.append((sub_id, response))

        _run_threads([lambda sub_id=sub_id: _delete(sub_id) for sub_id in ids for _ in range(DELETERS_PER_ID)])
        for sub_id in ids:
            responses = [r for i, r in deletes if i == sub_id]
            statuses = [r.status_code for r in responses]
            logger.info("Subscription %s: %d concurrent deletes -> %s", sub_id, len(responses), statuses)
            pytest_assert(
                all(status in (200, 204, 404) for status in statuses),
                "{} concurrent deletes of subscription {} must each be answered 2xx or 404, got: {}".format(
                    DELETERS_PER_ID, sub_id, statuses)
            )
        pytest_assert(_subscription_ids(redfish_client) == [], "Collection must be empty after the deletes")
        _assert_nothing_restarted(bmc_duthost, pids_before)
        logger.info("Verified %d duplicate creates and %d duplicate deletes were handled consistently",
                    CREATORS, len(deletes))

    def test_interleaved_create_delete_churn(self, redfish_client, bmc_duthost, clean_subscriptions):
        """
        Several callers each create, read and delete their own subscription
        repeatedly at the same time.

        Every step must succeed for every caller, so no caller's create is
        lost or deleted by another's DELETE, and the collection must be
        empty again once they finish.
        """
        pids_before = _running_pids(bmc_duthost)
        outcomes = []

        def _churn(worker):
            for iteration in range(CHURN_ITERATIONS):
                context = "churn-{}-{}".format(worker, iteration)
                body = {"Destination": DUPLICATE_DESTINATION, "Protocol": "Redfish", "Context": context}
                response = redfish_client.post(SUBSCRIPTIONS_PATH, json=body, timeout=REQUEST_TIMEOUT)
                if response.status_code != 201:
                    outcomes.append((context, "POST", response.status_code))
                    continue
                location = response.headers.get("Location", "")
                response = redfish_client.get(location, timeout=REQUEST_TIMEOUT)
                if response.status_code != 200 or response.json().get("Context") != context:
                    outcomes.append((context, "GET", response.status_code))
                response = redfish_client.delete(location, timeout=REQUEST_TIMEOUT)
                if response.status_code not in (200, 204):
                    outcomes.append((context, "DELETE", response.status_code))

        _run_threads([lambda worker=worker: _churn(worker) for worker in range(CHURN_WORKERS)])
        pytest_assert(
            not outcomes,
            "{} of {} create/read/delete steps failed under concurrency: {}".format(
                len(outcomes), CHURN_WORKERS * CHURN_ITERATIONS * 3, outcomes)
        )
        pytest_assert(_subscription_ids(redfish_client) == [], "Collection must be empty after the churn")
        _assert_nothing_restarted(bmc_duthost, pids_before)
        logger.info("Verified %d workers x %d create/read/delete cycles completed cleanly",
                    CHURN_WORKERS, CHURN_ITERATIONS)
