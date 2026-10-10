"""Qualify installed Healthz RPCs and telemetry using controlled producers.

The lifecycle cases require explicit command-line selection as described in
healthz_qualification.md. They skip before changing TLS configuration when
that selection is absent. No test installs rules or injects a hardware fault.
"""

import base64
import hashlib
import json
import logging
import shlex
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from urllib.parse import quote, unquote

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.ptf_grpc import PtfGrpcError
from tests.common.pygnmi_client import PygnmiClient, PygnmiClientCallError, StreamMode
from tests.common.utilities import compose_dict_from_cli


logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("any")]
SERVICE = "gnoi.healthz.Healthz"
HEALTH_PREFIX = "COMPONENT_HEALTH_INFO|"
STATE_FIELDS = {"status", "last-unhealthy", "unhealthy-count"}


def _path(component):
    return {"elem": [
        {"name": "components"},
        {"name": "component", "key": {"name": component}},
    ]}


def _state_path(component):
    return "openconfig://components/component[name={}]/healthz/state".format(component)


def _rpc(client, method, component, **fields):
    return client.grpc.call_unary(SERVICE, method, {"path": _path(component), **fields})


def _events(client, component, acknowledged=True):
    return _rpc(client, "List", component, includeAcknowledged=acknowledged).get("statuses", [])


def _state_values(response):
    """Accept subtree and leaf updates in the native pygnmi response shapes."""
    result = {}

    def leaves(value):
        if isinstance(value, dict):
            for key, child in value.items():
                name = key.split(":")[-1]
                if name in STATE_FIELDS:
                    result[name] = child
                else:
                    leaves(child)

    notifications = response.get("notification", [response.get("update", {})])
    for notification in notifications:
        for update in notification.get("update", []):
            value = update.get("val")
            name = update.get("path", "").rsplit("/", 1)[-1].split(":")[-1]
            if name in STATE_FIELDS:
                result[name] = value
            else:
                leaves(value)
    if "status" in result:
        result["status"] = result["status"].split(":")[-1]
    for name in ("last-unhealthy", "unhealthy-count"):
        if name in result:
            result[name] = int(result[name])
    return result


def _state(client, component):
    return _state_values(client.pygnmi_client.get(_state_path(component)))


def _wait_for_state(client, component, expected):
    deadline = time.monotonic() + 60
    while True:
        try:
            state = _state(client, component)
        except PygnmiClientCallError as error:
            if "NotFound" not in str(error):
                raise
            state = {}
        if all(state.get(name) == value for name, value in expected.items()):
            return state
        assert time.monotonic() < deadline, "Healthz projection did not reach {}: {}".format(expected, state)
        time.sleep(1)


def _wait_for_event(client, component, status, previous_id):
    deadline = time.monotonic() + 60
    while True:
        try:
            event = _rpc(client, "Get", component)["component"]
        except PtfGrpcError as error:
            if "NotFound" not in str(error):
                raise
            event = {}
        if event.get("status") == "STATUS_" + status and event.get("id") != previous_id:
            return event
        assert time.monotonic() < deadline, "Healthz did not publish {}: {}".format(status, event)
        time.sleep(1)


def _artifact(client, artifact_id):
    frames = client.grpc.call_server_streaming(SERVICE, "Artifact", {"id": artifact_id})
    assert len(frames) >= 3, "Artifact must contain header, content, and trailer"
    assert set(frames[0]) == {"header"} and set(frames[-1]) == {"trailer"}
    assert all(set(frame) == {"bytes"} for frame in frames[1:-1])
    content = b"".join(base64.b64decode(frame["bytes"], validate=True) for frame in frames[1:-1])
    header = frames[0]["header"]
    assert header["id"] == artifact_id
    file_info = header["file"]
    assert file_info["name"] == artifact_id.rsplit("/", 1)[-1]
    assert file_info["mimetype"] == "application/gzip"
    assert int(file_info.get("size", 0)) == len(content)
    assert file_info["hash"]["method"] == "SHA256"
    assert base64.b64decode(file_info["hash"]["hash"], validate=True) == hashlib.sha256(content).digest()
    return content


class _Episode:
    """A unique generic producer, or the explicitly selected installed demo."""

    def __init__(self, duthost, kind, component="", signal=""):
        self.duthost, self.kind, self.signal = duthost, kind, signal
        self.component = component or "HEALTHZ_QUALIFICATION_" + uuid.uuid4().hex
        self.producer = "dldd" if signal else "healthz-qualification"
        self.source_key = "qualification/" + uuid.uuid4().hex
        self.payload = "/var/tmp/healthz-qualification-" + uuid.uuid4().hex
        self.artifact_sha256 = None
        self.artifact_id = None
        self.active = False
        self.signal_content = None

    def _run(self, command):
        result = self.duthost.shell(command, module_ignore_errors=True)
        assert result["rc"] == 0, "{} failed: {}".format(command, result.get("stderr", result))
        return result["stdout"].strip()

    def _call(self, method, request):
        code = (
            "import dbus,json; p=dbus.SystemBus().get_object('org.SONiC.HostService.healthz',"
            "'/org/SONiC/HostService/healthz'); c,r=getattr(p,{!r})({!r},"
            "dbus_interface='org.SONiC.HostService.healthz',timeout=60); "
            "assert int(c)==0,(c,r); print(str(r))"
        ).format(method, json.dumps(request))
        return json.loads(self._run("sudo python3 -c " + shlex.quote(code)))

    def _publish(self, active, artifact_id="", observation=False):
        observed_at = int(self._run("date +%s"))
        values = {"producer": self.producer, "source_key": self.source_key,
                  "component": self.component, "observed_at": str(observed_at)}
        if observation:
            values["kind"] = "observation"
        else:
            values.update(active=str(int(active)), transition_id=uuid.uuid4().hex,
                          component_type="SERVICE", symptom="SYMPTOM_COMM_ERROR")
            if artifact_id:
                values["artifact_id"] = artifact_id
        arguments = [item for pair in values.items() for item in pair]
        self._run("sonic-db-cli STATE_DB XADD HEALTHZ_TRANSITIONS MAXLEN '=' 10000 '*' "
                  + " ".join(shlex.quote(item) for item in arguments))
        return observed_at

    def prepare(self):
        if self.signal:
            assert self.signal.startswith("/var/tmp/"), "Demo signal must be under /var/tmp"
            info = self.duthost.stat(path=self.signal)["stat"]
            assert info.get("isreg") and not info.get("islnk"), "Demo signal must be an existing regular file"
            self.signal_attributes = {"mode": info["mode"], "owner": info["pw_name"], "group": info["gr_name"]}
            self.signal_content = base64.b64decode(self.duthost.slurp(src=self.signal)["content"]).decode("utf-8")
            assert self.signal_content.strip() == "HEALTHY"
        else:
            self._publish(False)

    def _signal(self, value):
        self.duthost.copy(content=value + "\n", dest=self.signal, **self.signal_attributes)

    def activate(self):
        self.active = True  # Ensure teardown clears even a partially failed activation.
        if self.signal:
            self._signal("FAULT")
            deadline = time.monotonic() + 60
            pattern = "FAULT_INFO|{}|*".format(self.component)
            while True:
                keys = self._run("sonic-db-cli STATE_DB KEYS " + shlex.quote(pattern)).splitlines()
                for key in keys:
                    row = compose_dict_from_cli(self._run(
                        "sonic-db-cli STATE_DB HGETALL " + shlex.quote(key)))
                    if row.get("status") == "ACTIVE":
                        self.fault_key = key
                        artifact_id = row.get("healthz_artifact_id")
                        assert artifact_id and {name for name in row if name.startswith("healthz_")} == {
                            "healthz_artifact_id"}, "DLDD must publish only its scalar artifact ID"
                        break
                else:
                    assert time.monotonic() < deadline, "Installed demo did not create an archived DLDD fault"
                    time.sleep(1)
                    continue
                break
        elif self.kind == "archive":
            artifact_id = self._call("reserve_artifact", {})["artifact_id"]
            self.artifact_id = artifact_id
            self._publish(True, artifact_id)
            self.duthost.copy(content="Healthz qualification payload\n", dest=self.payload, mode="0600")
            self._call("submit_artifact", {"artifact_id": artifact_id,
                       "paths": [{"path": self.payload, "name": "qualification.txt"}]})
        else:
            self._publish(True)
            return None
        archive = "/var/lib/sonic/healthz/artifacts/" + artifact_id
        deadline = time.monotonic() + 60
        while self._call("artifact_status", {"artifact_id": artifact_id})["state"] == "PENDING":
            assert time.monotonic() < deadline, "Archive did not complete"
            time.sleep(1)
        self.artifact_sha256 = self._run("sudo sha256sum -- " + shlex.quote(archive)).split()[0]
        return artifact_id

    def observe(self):
        # An asserted observation must be later than activation's second.
        time.sleep(2)
        if self.signal:
            return int(self._run("date +%s"))
        return self._publish(True, observation=True)

    def recover(self):
        if self.signal:
            self._signal("HEALTHY")
        else:
            self._publish(False)
        self.active = False

    def close(self):
        try:
            if self.active:
                self.recover()
                key = "COMPONENT_HEALTH_INFO|" + quote(self.component, safe="")
                deadline = time.monotonic() + 60
                while self._run("sonic-db-cli STATE_DB HGET " + shlex.quote(key) + " status") != "HEALTHY":
                    assert time.monotonic() < deadline, "Controlled source failed to recover during teardown"
                    time.sleep(1)
        finally:
            if self.artifact_id and self._call("artifact_status", {"artifact_id": self.artifact_id})["state"] == "PENDING":
                self._call("fail_artifact", {"artifact_id": self.artifact_id})
            if self.signal_content is not None:
                self.duthost.copy(content=self.signal_content, dest=self.signal, **self.signal_attributes)
                assert base64.b64decode(self.duthost.slurp(src=self.signal)["content"]).decode("utf-8") == self.signal_content
            elif not self.signal:
                self._run("sudo rm -f -- " + shlex.quote(self.payload))


def test_healthz_installed_baseline(healthz_tls):
    """Stored component state maps to GET; missing state never becomes healthy."""
    gnmi_tls = healthz_tls
    duthost = gnmi_tls.duthost
    keys = duthost.shell("sonic-db-cli STATE_DB KEYS 'COMPONENT_HEALTH_INFO|*'")["stdout_lines"]
    for key in keys:
        row = compose_dict_from_cli(duthost.shell(
            "sonic-db-cli STATE_DB HGETALL {}".format(shlex.quote(key)),
        )["stdout"])
        component = unquote(key[len(HEALTH_PREFIX):])
        state = _state(gnmi_tls, component)
        assert state["status"] == row["status"]
        assert state["unhealthy-count"] == int(row["unhealthy_count"])
        if "last_unhealthy" in row:
            assert state["last-unhealthy"] == int(row["last_unhealthy"])
        else:
            assert "last-unhealthy" not in state
        retained = _events(gnmi_tls, component)
        latest = _rpc(gnmi_tls, "Get", component)["component"]
        assert latest["id"] in {event["id"] for event in retained}
        assert latest["status"] == "STATUS_" + row["status"]
        visible = _events(gnmi_tls, component, acknowledged=False)
        assert {event["id"] for event in visible} == {
            event["id"] for event in retained if not event.get("acknowledged", False)
        }
        logger.info("Healthz baseline component=%s latest=%s state=%s", component, latest, state)

    missing = "healthz-qualification-missing-" + uuid.uuid4().hex
    with pytest.raises(PtfGrpcError, match="NotFound"):
        _rpc(gnmi_tls, "Get", missing)
    with pytest.raises(PygnmiClientCallError, match="NotFound"):
        _state(gnmi_tls, missing)


@pytest.fixture(params=["archive", "no_archive", "dldd"])
def healthz_episode(request):
    if not request.config.getoption("--healthz-controlled-episodes", default=False):
        pytest.skip("Controlled {} episode requires --healthz-controlled-episodes on an exclusive lab DUT".format(
            request.param))
    component = request.config.getoption("--healthz-dldd-component", default="")
    signal = request.config.getoption("--healthz-dldd-signal", default="")
    if request.param == "dldd" and not (component and signal):
        pytest.skip("DLDD episode requires --healthz-dldd-component and --healthz-dldd-signal for an installed demo rule")
    client = request.getfixturevalue("healthz_tls")
    client.grpc.configure_max_time(60)
    if request.param != "no_archive":
        count = int(client.duthost.shell(
            "sudo find /var/lib/sonic/healthz/artifacts -maxdepth 1 -type f "
            "\\( -name 'healthz-*.tar.gz' -o -name '*.pending' \\) | wc -l"
        )["stdout"])
        assert count < 20, "Archive store has no free slot; qualification must not prune retained artifacts"
    episode = _Episode(client.duthost, request.param,
                       component if request.param == "dldd" else "",
                       signal if request.param == "dldd" else "")
    try:
        episode.prepare()
        _wait_for_event(client, episode.component, "HEALTHY", "")
        _wait_for_state(client, episode.component, {"status": "HEALTHY"})
        yield episode, client
    finally:
        episode.close()


def test_healthz_controlled_episode(healthz_episode):
    """One episode covers RPC lifecycle, archive identity, and post-sync updates."""
    episode, client = healthz_episode
    component = episode.component
    baseline = _state(client, component)
    assert baseline["status"] == "HEALTHY", "Controlled component must start assessed and healthy"
    before_events = _events(client, component)
    before_ids = {event["id"] for event in before_events}
    expected_count = baseline["unhealthy-count"] + 1
    base = client.pygnmi_client
    subscriber = PygnmiClient(
        base.host, base.port, plaintext=base.plaintext,
        ca_cert=base.ca_cert, client_cert=base.client_cert, client_key=base.client_key,
        timeout=base.timeout, connect=False,
    )
    synced, stop, unhealthy_received, recovery_started, healthy_received = (Event() for _ in range(5))
    notifications = []

    def collect():
        current = dict(baseline)
        for message in subscriber.subscribe(
            _state_path(component), stream_mode=StreamMode.ON_CHANGE, collect_seconds=120,
        ):
            notifications.append(message)
            if message.get("sync_response"):
                synced.set()
            elif synced.is_set():
                current.update(_state_values(message))
                if current.get("status") == "UNHEALTHY" and current.get("unhealthy-count") == expected_count:
                    unhealthy_received.set()
                if recovery_started.is_set() and current.get("status") == "HEALTHY":
                    healthy_received.set()
                    break
            if stop.is_set():
                break

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(collect)
        try:
            assert synced.wait(30), "Healthz ON_CHANGE did not synchronize"
            artifact_id = episode.activate()
            active = _wait_for_event(client, component, "UNHEALTHY", "")
            assert active["id"] not in before_ids
            _wait_for_state(client, component, {"status": "UNHEALTHY", "unhealthy-count": expected_count})
            assert unhealthy_received.wait(30), "Missing post-sync UNHEALTHY update"
            if artifact_id:
                assert active["id"] == artifact_id
                content = _artifact(client, artifact_id)
                assert hashlib.sha256(content).hexdigest() == episode.artifact_sha256
                completed = _rpc(client, "Get", component)["component"]
                assert completed["artifacts"][0]["id"] == artifact_id
            else:
                assert not active.get("artifacts") and active["id"].startswith("hz-")
            for _ in range(2):
                acknowledged = _rpc(client, "Acknowledge", component, id=active["id"])["status"]
                assert acknowledged["id"] == active["id"] and acknowledged["acknowledged"]
            assert active["id"] not in {event["id"] for event in _events(client, component, False)}
            assert active["id"] in {event["id"] for event in _events(client, component)}
            if artifact_id:
                assert _artifact(client, artifact_id) == content

            observed_at = episode.observe()
            deadline = time.monotonic() + 60
            while _state(client, component).get("last-unhealthy", 0) < observed_at * 1_000_000_000:
                assert time.monotonic() < deadline, "Asserted observation did not update last-unhealthy"
                time.sleep(1)
            assert {event["id"] for event in _events(client, component)} == before_ids | {active["id"]}
            state = _state(client, component)
            assert state["unhealthy-count"] == expected_count
            last_unhealthy = state["last-unhealthy"]
            recovery_started.set()
            episode.recover()
            recovery = _wait_for_event(client, component, "HEALTHY", active["id"])
            assert recovery["id"] not in before_ids | {active["id"]}
            assert recovery["id"].startswith("hz-") and not recovery.get("artifacts")
            _wait_for_state(client, component, {"status": "HEALTHY", "unhealthy-count": expected_count})
            state = _state(client, component)
            if episode.producer == "dldd":
                detection = int(episode._run("sonic-db-cli STATE_DB HGET "
                                            + shlex.quote(episode.fault_key) + " last_detection_time"))
                assert state["last-unhealthy"] == detection * 1_000_000_000
            else:
                assert state["last-unhealthy"] == last_unhealthy
            last_unhealthy = state["last-unhealthy"]
            assert {event["id"] for event in _events(client, component)} == before_ids | {
                active["id"], recovery["id"],
            }
            if episode.producer == "dldd":
                for fields in ({}, {"eventId": active["id"]}):
                    with pytest.raises(PtfGrpcError, match="Unimplemented"):
                        _rpc(client, "Check", component, **fields)
            assert healthy_received.wait(30), "Missing post-sync HEALTHY recovery update"
        finally:
            stop.set()
        pending.result(timeout=125)

    sync_index = next(index for index, message in enumerate(notifications) if message.get("sync_response"))
    accumulated = dict(baseline)
    post_sync_states = []
    for message in notifications[sync_index + 1:]:
        values = _state_values(message)
        if values:
            accumulated.update(values)
            post_sync_states.append(dict(accumulated))
    assert any(state["status"] == "UNHEALTHY" and state["unhealthy-count"] == expected_count
               for state in post_sync_states), "Missing post-sync UNHEALTHY update"
    assert any(state == {"status": "HEALTHY", "unhealthy-count": expected_count,
                         "last-unhealthy": last_unhealthy}
               for state in post_sync_states), "Missing post-sync HEALTHY recovery update"
    logger.info("Healthz episode component=%s active=%s recovery=%s notifications=%s",
                component, active, recovery, notifications)
