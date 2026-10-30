"""
Tests for Redfish recovery after restarting the services that back it.

On the SONiC BMC (sonic-redfish) bmcweb owns no inventory of its own. Every
resource under Chassis, Systems, UpdateService/FirmwareInventory,
AccountService/Accounts and the leak detectors is assembled per request from
D-Bus objects that ``sonic-dbus-bridge`` exports and registers with the
``xyz.openbmc_project.ObjectMapper`` it also hosts (bmcweb finds them with
GetSubTree, GetSubTreePaths and GetObject). Restarting the bridge therefore
drops and re-creates both the objects and the mapper underneath a running
bmcweb, and restarting the redfish container drops bmcweb as well.

Each test takes two snapshots before the restart, one of what a rack manager
sees through Redfish and one of what bmcweb sees through the ObjectMapper,
performs the restart and checks both come back identical.
"""
import json
import logging
import re
import shlex

import pytest
import requests

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

SERVICE_ROOT = "/redfish/v1"
SUBSCRIPTIONS_PATH = "/redfish/v1/EventService/Subscriptions"
REDFISH_CONTAINER = "redfish"
REDFISH_SERVICE = "redfish"
BRIDGE_SERVICE = "sonic-dbus-bridge"

# Collections bmcweb fills from ObjectMapper lookups against sonic-dbus-bridge
# that the rack manager interface touches: leak detectors under Chassis, the OEM actions
# under Managers, and FirmwareInventory (pmon-bmc-design.md 2.1.2).
INVENTORY_COLLECTIONS = [
    "/redfish/v1/Chassis",
    "/redfish/v1/Managers",
    "/redfish/v1/UpdateService/FirmwareInventory",
]
LEAK_DETECTORS_SUFFIX = "/ThermalSubsystem/LeakDetection/LeakDetectors"
# Identity and state fields of a member that a restart must not change.
# Clock-derived fields such as DateTime are deliberately left out.
STABLE_FIELDS = (
    "@odata.id", "@odata.type", "Id", "Name", "Manufacturer", "Model", "SerialNumber",
    "PartNumber", "Version", "PowerState", "DetectorState", "UserName", "RoleId", "Enabled", "Status",
)

MAPPER_BUS = "xyz.openbmc_project.ObjectMapper"
MAPPER_PATH = "/xyz/openbmc_project/object_mapper"
MAPPER_IFACE = "xyz.openbmc_project.ObjectMapper"
HOST_STATE_BUS = "xyz.openbmc_project.State.Host"
HOST_STATE_PATH = "/xyz/openbmc_project/state/host0"
# Interfaces sonic-dbus-bridge registers with its ObjectMapper for bmcweb to find.
MAPPER_INTERFACES = [
    "xyz.openbmc_project.Inventory.Item.Chassis",
    "xyz.openbmc_project.Inventory.Item.System",
    "xyz.openbmc_project.State.Chassis",
    "xyz.openbmc_project.State.Host",
    "xyz.openbmc_project.Software.Version",
    "xyz.openbmc_project.Inventory.Item.LeakDetector",
]
# Without these the Chassis and Systems resources cannot be built at all.
MAPPER_REQUIRED_INTERFACES = [
    "xyz.openbmc_project.Inventory.Item.Chassis",
    "xyz.openbmc_project.State.Host",
]

BRIDGE_READY_TIMEOUT = 60
CONTAINER_READY_TIMEOUT = 180
RECOVERY_TIMEOUT = 90
RECOVERY_POLL = 3
# RFC 5737 documentation address: the subscription only has to survive the
# restart, no event is raised at it. bmcweb stores a Destination with its
# port made explicit, so give it one to read back exactly.
PERSISTED_DESTINATION = "http://192.0.2.1:80/restart-recovery"
PERSISTED_CONTEXT = "restart-recovery"


def _container_shell(bmc_duthost, cmd, **kwargs):
    return bmc_duthost.shell("docker exec {} sh -c {}".format(REDFISH_CONTAINER, shlex.quote(cmd)), **kwargs)


def _diff(before, after):
    """Human-readable list of keys whose values differ between two snapshots."""
    keys = sorted(set(before) | set(after))
    return ["{}: {!r} -> {!r}".format(k, before.get(k), after.get(k)) for k in keys if before.get(k) != after.get(k)]


def _stable_fields(body):
    return {field: body[field] for field in STABLE_FIELDS if field in body}


def _get_json(redfish_client, path, problems, **kwargs):
    """GET `path`, returning its JSON body or None with the failure recorded in `problems`."""
    try:
        response = redfish_client.get(path, **kwargs)
    except requests.exceptions.RequestException as e:
        problems.append("{}: {}".format(path, type(e).__name__))
        return None
    if response.status_code != 200:
        problems.append("{}: HTTP {}".format(path, response.status_code))
        return None
    try:
        return response.json()
    except ValueError:
        problems.append("{}: non-JSON body".format(path))
        return None


def _member_ids(body):
    return sorted(m.get("@odata.id", "") for m in body.get("Members", []))


def _snapshot_collection(redfish_client, collection, snapshot, problems):
    """Record a collection's member ids and each member's stable fields. Returns the member ids."""
    body = _get_json(redfish_client, collection, problems)
    if body is None:
        return []
    members = _member_ids(body)
    snapshot[collection] = members
    for member in members:
        member_body = _get_json(redfish_client, member, problems)
        if member_body is not None:
            snapshot[member] = _stable_fields(member_body)
    return members


def _redfish_snapshot(redfish_client):
    """Walk the inventory collections as a rack manager would.

    Returns (snapshot, problems). The snapshot maps each collection path to its
    sorted member ids and each member path to its stable fields. Any GET that
    is not a 200 with a JSON body is listed in problems instead of raising, so
    the snapshot can be polled for during recovery. A chassis' leak detector
    collection is included when the chassis exposes one.
    """
    snapshot = {}
    problems = []
    for collection in INVENTORY_COLLECTIONS:
        members = _snapshot_collection(redfish_client, collection, snapshot, problems)
        if collection != "/redfish/v1/Chassis":
            continue
        for chassis in members:
            leak_collection = chassis + LEAK_DETECTORS_SUFFIX
            if _get_json(redfish_client, leak_collection, []) is not None:
                _snapshot_collection(redfish_client, leak_collection, snapshot, problems)
    return snapshot, problems


def _log_snapshot(label, snapshot):
    collections = {k: v for k, v in snapshot.items() if isinstance(v, list)}
    logger.info("%s: %d collections, %d members: %s", label, len(collections),
                len(snapshot) - len(collections), json.dumps(collections, sort_keys=True))


def _mapper_snapshot(bmc_duthost):
    """{interface: sorted object paths} as answered by the bridge's ObjectMapper.

    Returns None while the mapper is not answering (ServiceUnknown, no reply),
    which is distinct from an interface legitimately having no objects.
    """
    script = "; ".join(
        'echo "== {iface}"; dbus-send --system --print-reply --dest={bus} {path} {mapper}.GetSubTreePaths '
        'string:/ int32:0 array:string:{iface} 2>&1'.format(
            iface=iface, bus=MAPPER_BUS, path=MAPPER_PATH, mapper=MAPPER_IFACE)
        for iface in MAPPER_INTERFACES
    )
    res = _container_shell(bmc_duthost, script, module_ignore_errors=True)
    snapshot = {}
    current = None
    for line in res["stdout"].splitlines():
        if line.startswith("== "):
            current = line[3:].strip()
            snapshot[current] = []
        elif line.startswith("Error "):
            return None
        elif current is not None:
            match = re.search(r'string "([^"]+)"', line)
            if match:
                snapshot[current].append(match.group(1))
    if len(snapshot) != len(MAPPER_INTERFACES):
        return None
    return {iface: sorted(paths) for iface, paths in snapshot.items()}


def _mapper_object(bmc_duthost, path):
    """Bus names the ObjectMapper's GetObject reports for `path`, or [] if unknown."""
    res = _container_shell(
        bmc_duthost,
        "dbus-send --system --print-reply --dest={} {} {}.GetObject string:{} array:string:".format(
            MAPPER_BUS, MAPPER_PATH, MAPPER_IFACE, path),
        module_ignore_errors=True,
    )
    if res["rc"] != 0:
        return []
    return [s for s in re.findall(r'string "([^"]+)"', res["stdout"]) if not s.startswith("/")]


def _supervisor_pid(bmc_duthost, program):
    """PID supervisord reports for `program` in the redfish container, or None if not RUNNING."""
    res = _container_shell(bmc_duthost, "supervisorctl status {}".format(program), module_ignore_errors=True)
    match = re.search(r"RUNNING\s+pid (\d+)", res["stdout"])
    return int(match.group(1)) if match else None


def _service_root_ok(redfish_client):
    try:
        return redfish_client.get(SERVICE_ROOT).status_code == 200
    except requests.exceptions.RequestException:
        return False


def _take_baseline(redfish_client, bmc_duthost):
    """Snapshot Redfish and the ObjectMapper, asserting both are healthy and non-trivial."""
    redfish_before, problems = _redfish_snapshot(redfish_client)
    pytest_assert(not problems, "Inventory is not fully readable before the restart: {}".format(problems))
    pytest_assert(redfish_before.get("/redfish/v1/Chassis"),
                  "/redfish/v1/Chassis has no members before the restart, nothing to recover")
    _log_snapshot("Redfish before restart", redfish_before)

    mapper_before = _mapper_snapshot(bmc_duthost)
    pytest_assert(mapper_before is not None, "ObjectMapper is not answering before the restart")
    for iface in MAPPER_REQUIRED_INTERFACES:
        pytest_assert(mapper_before.get(iface),
                      "ObjectMapper lists no object for {} before the restart".format(iface))
    logger.info("ObjectMapper before restart: %s", json.dumps(mapper_before, sort_keys=True))
    return redfish_before, mapper_before


def _wait_for_recovery(redfish_client, bmc_duthost, redfish_before, mapper_before, timeout):
    """Wait until the mapper and Redfish views match the baseline again, then assert they do."""
    state = {}

    def _mapper_back():
        state["mapper"] = _mapper_snapshot(bmc_duthost)
        return state["mapper"] == mapper_before

    wait_until(timeout, RECOVERY_POLL, 0, _mapper_back)
    pytest_assert(
        state["mapper"] is not None,
        "ObjectMapper did not answer within {}s of the restart".format(timeout)
    )
    pytest_assert(
        state["mapper"] == mapper_before,
        "ObjectMapper tree differs after the restart: {}".format(_diff(mapper_before, state["mapper"]))
    )
    logger.info("ObjectMapper again lists %d object paths across %d interfaces",
                sum(len(v) for v in state["mapper"].values()), len(state["mapper"]))

    def _redfish_back():
        state["redfish"], state["problems"] = _redfish_snapshot(redfish_client)
        return not state["problems"] and state["redfish"] == redfish_before

    wait_until(timeout, RECOVERY_POLL, 0, _redfish_back)
    pytest_assert(
        not state["problems"],
        "Redfish inventory still not fully readable {}s after the restart: {}".format(timeout, state["problems"])
    )
    pytest_assert(
        state["redfish"] == redfish_before,
        "Redfish inventory differs after the restart: {}".format(_diff(redfish_before, state["redfish"]))
    )
    _log_snapshot("Redfish after restart", state["redfish"])


def _wait_for_bridge(bmc_duthost):
    pytest_assert(
        wait_until(BRIDGE_READY_TIMEOUT, 2, 0, lambda: _supervisor_pid(bmc_duthost, BRIDGE_SERVICE) is not None),
        "{} did not reach RUNNING within {}s".format(BRIDGE_SERVICE, BRIDGE_READY_TIMEOUT)
    )


class TestRedfishRestartRecovery:

    def test_bridge_restart_rediscovered_by_running_bmcweb(self, redfish_client, bmc_duthost):
        """
        Restart sonic-dbus-bridge under a running bmcweb.

        The bridge re-creates its D-Bus objects and re-registers them with a
        fresh ObjectMapper. bmcweb, which is not restarted (its supervisord
        PID is checked), must pick them up again and serve the same
        inventory as before.
        """
        redfish_before, mapper_before = _take_baseline(redfish_client, bmc_duthost)
        bmcweb_pid = _supervisor_pid(bmc_duthost, "bmcweb")
        pytest_assert(bmcweb_pid is not None, "bmcweb is not RUNNING before the restart")

        logger.info("Restarting %s (bmcweb pid %d stays up)", BRIDGE_SERVICE, bmcweb_pid)
        _container_shell(bmc_duthost, "supervisorctl restart {}".format(BRIDGE_SERVICE))
        _wait_for_bridge(bmc_duthost)

        _wait_for_recovery(redfish_client, bmc_duthost, redfish_before, mapper_before, RECOVERY_TIMEOUT)

        owners = _mapper_object(bmc_duthost, HOST_STATE_PATH)
        pytest_assert(
            HOST_STATE_BUS in owners,
            "ObjectMapper GetObject({}) must name {} after the restart, got: {}".format(
                HOST_STATE_PATH, HOST_STATE_BUS, owners)
        )
        pytest_assert(
            _supervisor_pid(bmc_duthost, "bmcweb") == bmcweb_pid,
            "bmcweb was restarted (pid changed from {}), so re-discovery by the running bmcweb was not "
            "exercised".format(bmcweb_pid)
        )
        logger.info("Verified running bmcweb (pid %d) re-discovered the bridge objects after restart", bmcweb_pid)

    def test_redfish_container_restart(self, redfish_client, bmc_duthost):
        """
        Restart the whole redfish container (bmcweb and sonic-dbus-bridge).

        After `systemctl restart redfish` the mTLS configuration must still
        be in force (the client's certificate is accepted), the bridge must
        re-register its objects, bmcweb must serve the same inventory, and a
        push subscription created before the restart must still exist,
        since bmcweb persists subscriptions in the container.
        """
        redfish_before, mapper_before = _take_baseline(redfish_client, bmc_duthost)

        body = {"Destination": PERSISTED_DESTINATION, "Protocol": "Redfish", "Context": PERSISTED_CONTEXT}
        response = redfish_client.post(SUBSCRIPTIONS_PATH, json=body)
        pytest_assert(
            response.status_code == 201,
            "Subscribe expected HTTP 201, got: {} body={!r}".format(response.status_code, response.text[:500])
        )
        location = response.headers.get("Location", "")
        pytest_assert(location.startswith(SUBSCRIPTIONS_PATH + "/"), "Unexpected Location: {!r}".format(location))
        logger.info("Created subscription %s before the container restart", location)

        try:
            logger.info("Restarting the %s service", REDFISH_SERVICE)
            bmc_duthost.shell("sudo systemctl restart {}".format(REDFISH_SERVICE))
            pytest_assert(
                wait_until(CONTAINER_READY_TIMEOUT, RECOVERY_POLL, 0,
                           bmc_duthost.is_service_fully_started, REDFISH_SERVICE),
                "{} container did not come back within {}s".format(REDFISH_CONTAINER, CONTAINER_READY_TIMEOUT)
            )

            def _bmcweb_serving():
                return _supervisor_pid(bmc_duthost, "bmcweb") is not None and _service_root_ok(redfish_client)

            pytest_assert(
                wait_until(CONTAINER_READY_TIMEOUT, RECOVERY_POLL, 0, _bmcweb_serving),
                "bmcweb did not accept the mTLS client within {}s of the container restart".format(
                    CONTAINER_READY_TIMEOUT)
            )
            _wait_for_recovery(redfish_client, bmc_duthost, redfish_before, mapper_before, RECOVERY_TIMEOUT)

            response = redfish_client.get(location)
            pytest_assert(
                response.status_code == 200,
                "Subscription {} did not survive the container restart: HTTP {}".format(
                    location, response.status_code)
            )
            for field, expected in (("Destination", PERSISTED_DESTINATION), ("Context", PERSISTED_CONTEXT)):
                pytest_assert(
                    response.json().get(field) == expected,
                    "Subscription {} {} must be {!r} after the restart, got: {!r}".format(
                        location, field, expected, response.json().get(field))
                )
            logger.info("Verified inventory and subscription %s survived the container restart", location)
        finally:
            response = redfish_client.delete(location)
            if response.status_code not in (200, 204):
                logger.warning("Could not remove subscription %s: HTTP %s", location, response.status_code)
