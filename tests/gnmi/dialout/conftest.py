import base64
import itertools
import json
import logging
import shlex

import pytest
from pygnmi.spec.v080.gnmi_pb2 import SubscribeResponse

from tests.common.cert_utils import TlsCertificateGenerator
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

COLLECTOR_SRC = "gnmi/dialout/dialout_collector.py"
COLLECTOR_DST = "/root/dialout_collector.py"
CERT_DST = "/root/dialout_collector.crt"
KEY_DST = "/root/dialout_collector.key"
# Below the default net.ipv4.ip_local_port_range (32768-60999) so the kernel
# can never hand a collector port to an outbound connection first.
BASE_PORT = 20075

# The keys this suite writes; cleanup must touch nothing else.
OWNED_KEYS = ("Global", "DestinationGroup_TEST", "Subscription_TEST")


# ---------------------------------------------------------------------------
# tests/gnmi/conftest.py defines a module-scoped autouse fixture,
# setup_vrf_configuration, which drags the vrf_config parametrization into
# every test id; dial-out does not touch the gNMI server VRF binding, so
# shadow it with a no-op. download_gnmi_client (in-tree it currently lives
# in tests/gnmi/test_gnmi_configdb.py; some sonic-mgmt forks define it as a
# package-level autouse fixture) docker-cps gNMI client binaries out of the
# gnmi container with no error tolerance and picks its DUT via
# rand_one_dut_hostname, which need not match this suite's
# enum_rand_one_per_hwsku_hostname selection; its shadow keeps this suite
# independent of it wherever it is package-level.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module", autouse=True)
def download_gnmi_client():
    yield


@pytest.fixture(scope="module", autouse=True)
def setup_vrf_configuration():
    yield


# supervisorctl status prints one of these for a program that exists; a
# missing program prints "dialout: ERROR (no such process)", which must not
# match. Note: single-asic container names only — on multi-asic DUTs the
# per-asic containers (gnmi0, telemetry0, ...) are not probed, so the module
# skips there.
SUPERVISOR_PROGRAM_STATES = ("RUNNING", "STARTING", "STOPPING", "STOPPED",
                             "EXITED", "FATAL", "BACKOFF", "UNKNOWN")


def dialout_program_status(duthost, container, timeout=30):
    """Return supervisorctl's status line for the dialout program, or None.

    Right after a container starts, supervisord's control socket does not
    exist yet and supervisorctl fails with a socket error; poll until it
    answers authoritatively: rc 0 (all programs running), rc 3 (a program in
    a non-running state), or an explicit "no such process" for a program
    that does not exist in this container.
    """
    result = {"out": None}

    def _answered():
        res = duthost.shell("docker exec %s supervisorctl status dialout" % container,
                            module_ignore_errors=True)
        out = (res["stdout"] or "") + (res["stderr"] or "")
        if res["rc"] in (0, 3) or "no such process" in out:
            result["out"] = res["stdout"]
            return True
        return False

    if not wait_until(timeout, 5, 0, _answered):
        return None
    return result["out"]


def find_dialout_container(duthost):
    """Find the container hosting the dialout program.

    Returns (container, status_line) — the status line is captured before
    anything restarts the program, so callers can assert on the state the
    image booted into. Returns (None, None) if no container has the program.
    """
    for container in ("gnmi", "telemetry"):
        res = duthost.shell("docker ps --filter name=%s --format '{{.Names}}'" % container,
                            module_ignore_errors=True)
        # The docker name filter is a substring match ("gnmi" also matches a
        # multi-asic "gnmi0"), so require an exact name before docker exec.
        if res["rc"] != 0 or container not in [ln.strip() for ln in res["stdout_lines"]]:
            continue
        status = dialout_program_status(duthost, container)
        if status and any(state in status for state in SUPERVISOR_PROGRAM_STATES):
            return container, status
    return None, None


def dump_telemetry_client_rows(duthost):
    """Snapshot all TELEMETRY_CLIENT rows as {key: {field: value}}.

    Uses redis-dump because it emits real JSON: values containing quotes or
    newlines survive the snapshot/restore round-trip exactly, where parsing
    sonic-db-cli HGETALL's pseudo-dict output would not. Fails the module
    (before anything is deleted) rather than silently dropping a row it
    cannot snapshot.
    """
    res = duthost.shell("redis-dump -d 4 -k 'TELEMETRY_CLIENT|*'",
                        module_ignore_errors=True)
    pt_assert(res["rc"] == 0,
              "could not snapshot TELEMETRY_CLIENT rows: %s" % res["stderr"])
    dump = json.loads(res["stdout"].strip() or "{}")
    return {key: entry["value"] for key, entry in dump.items()}


def hset_row(duthost, key, fields, ignore_errors=False):
    pairs = " ".join("%s %s" % (shlex.quote(str(k)), shlex.quote(str(v)))
                     for k, v in sorted(fields.items()))
    res = duthost.shell("sonic-db-cli CONFIG_DB HSET %s %s" % (shlex.quote(key), pairs),
                        module_ignore_errors=ignore_errors)
    if ignore_errors and res["rc"] != 0:
        logger.error("HSET %s failed: %s", key, res["stderr"])
    return res


@pytest.fixture(scope="module")
def dialout_setup(request, duthosts, enum_rand_one_per_hwsku_hostname, ptfhost):
    """Locate the dialout program, quiesce pre-existing config, restart clean.

    Pre-existing TELEMETRY_CLIENT rows are snapshotted and restored on module
    teardown; they must be absent while the suite runs (they would create
    competing publish streams after the restart below).
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Retry the whole discovery: right after an image install / config
    # reload the gnmi/telemetry containers come up late in the boot
    # sequence, so a single docker-ps probe can miss a container that is
    # seconds away from existing. Only a stable absence means "skip".
    found = {}

    def _discover():
        container, status = find_dialout_container(duthost)
        if container is None:
            return False
        found["container"] = container
        found["status"] = status
        return True

    if not wait_until(180, 15, 0, _discover):
        pytest.skip("No single-asic gnmi/telemetry container with a dialout program on %s "
                    "(multi-asic DUTs are not covered by this suite)" % duthost.hostname)
    container, initial_status = found["container"], found["status"]

    # The program is autostart=false and brought up via dependent_startup
    # once gnmi-native is running, so right after boot the authoritative
    # answer can legitimately still be STOPPED/STARTING. Give that wiring a
    # bounded window to reach RUNNING before freezing the snapshot that
    # test_dialout_process_running asserts on.
    if "RUNNING" not in (initial_status or ""):
        def _booted():
            status = dialout_program_status(duthost, container, timeout=5)
            if status:
                found["status"] = status
            return status is not None and "RUNNING" in status

        wait_until(60, 5, 0, _booted)
        initial_status = found["status"]

    saved_rows = dump_telemetry_client_rows(duthost)
    if saved_rows:
        logger.info("snapshotting %d pre-existing TELEMETRY_CLIENT rows: %s",
                    len(saved_rows), sorted(saved_rows))

    # Registered before the first delete so the restore runs even if this
    # fixture fails between the delete and its yield (a generator fixture
    # that raises before yielding never reaches code after it).
    def _restore():
        TelemetryClientConfig(duthost).cleanup()
        for key, fields in saved_rows.items():
            hset_row(duthost, key, fields, ignore_errors=True)
        if saved_rows:
            logger.info("restored %d pre-existing TELEMETRY_CLIENT rows", len(saved_rows))
        # Restoring rows in redis does not reset the client's in-memory
        # state (e.g. the retry interval from this suite's Global row), so
        # restart the program once the original configuration is back.
        duthost.shell("docker exec %s supervisorctl restart dialout" % container,
                      module_ignore_errors=True)
        if not wait_until(30, 3, 0, lambda: "RUNNING" in
                          (dialout_program_status(duthost, container, timeout=5) or "")):
            logger.warning("dialout did not reach RUNNING after config restore")

    request.addfinalizer(_restore)
    for key in saved_rows:
        duthost.shell("sonic-db-cli CONFIG_DB DEL %s" % shlex.quote(key),
                      module_ignore_errors=True)

    def dialout_running():
        status = dialout_program_status(duthost, container, timeout=5)
        return status is not None and "RUNNING" in status

    # Restart the client so no publish/retry state from earlier sessions
    # survives: a subscription deleted while its goroutine was still dialing
    # can keep retrying and connect to a later collector on the same port.
    duthost.shell("docker exec %s supervisorctl restart dialout" % container,
                  module_ignore_errors=True)
    pt_assert(wait_until(30, 3, 0, dialout_running),
              "dialout program did not reach RUNNING in %s" % container)

    yield {"duthost": duthost, "container": container, "ptfhost": ptfhost,
           "initial_dialout_status": initial_status}


class TelemetryClientConfig(object):
    """Writes TELEMETRY_CLIENT rows the dialout client watches via keyspace events.

    Keys use the underscore form (DestinationGroup_<name> / Subscription_<name>);
    the YANG pipe form is only accepted by recent sonic-gnmi versions,
    so tests stick to the spelling every release understands.

    cleanup() deletes only the keys this suite owns (OWNED_KEYS); rows that
    predate the run are handled by dialout_setup's snapshot/restore.
    """

    def __init__(self, duthost):
        self.duthost = duthost

    def hset(self, key, **fields):
        hset_row(self.duthost, "TELEMETRY_CLIENT|%s" % key, fields)

    def delete(self, key):
        self.duthost.shell("sonic-db-cli CONFIG_DB DEL 'TELEMETRY_CLIENT|%s'" % key,
                           module_ignore_errors=True)

    def cleanup(self):
        for key in OWNED_KEYS:
            self.delete(key)


@pytest.fixture(scope="function", autouse=True)
def telemetry_client_config(dialout_setup):
    """Per-test TELEMETRY_CLIENT config writer with guaranteed cleanup.

    Also re-checks the dialout program before each test: it runs with
    autorestart=false, so a crash mid-module would otherwise surface as a
    cascade of misleading "no updates received" failures in later tests.
    """
    duthost = dialout_setup["duthost"]
    container = dialout_setup["container"]
    status = dialout_program_status(duthost, container, timeout=5)
    pt_assert(status is not None and "RUNNING" in status,
              "dialout program is not RUNNING before test (status: %s) — it may have "
              "crashed during an earlier test (autorestart=false)" % (status or "unknown"))
    config = TelemetryClientConfig(duthost)
    config.cleanup()
    yield config
    config.cleanup()


def _decode_update(update):
    """Return (path, payload) for one gNMI Update.

    path is the slash-joined element names; payload is the decoded JSON
    value (a dict for SONiC DB table content) or the TypedValue's string
    form when it is not JSON.
    """
    path = "/".join(elem.name for elem in update.path.elem)
    val_kind = update.val.WhichOneof("value")
    if val_kind in ("json_ietf_val", "json_val"):
        raw_val = getattr(update.val, val_kind)
        try:
            return path, json.loads(raw_val)
        except ValueError:
            return path, raw_val.decode("utf-8", "replace")
    return path, str(update.val)


def decode_record(record):
    """Decode a collector record's raw SubscribeResponse bytes in place.

    The collector stores raw base64 bytes (docker-ptf has no pygnmi, and
    keeping it proto-free avoids stub codegen there entirely); decoding
    happens here with pygnmi's bundled gnmi_pb2. raw_b64 is kept only when
    the decoded fields cannot tell the tests what the message was.
    """
    raw = base64.b64decode(record["raw_b64"])
    try:
        resp = SubscribeResponse()
        resp.ParseFromString(raw)
    except Exception as exc:  # noqa: BLE001 - classify and keep going
        record["kind"] = "decode_error"
        record["error"] = str(exc)
        return record
    if resp.HasField("sync_response"):
        record["kind"] = "sync"
        record["sync_response"] = resp.sync_response
        del record["raw_b64"]
    elif resp.HasField("update"):
        record["kind"] = "update"
        record["target"] = resp.update.prefix.target
        record["update_count"] = len(resp.update.update)
        record["notification_timestamp"] = resp.update.timestamp
        record["updates"] = [_decode_update(u) for u in resp.update.update]
        del record["raw_b64"]
    else:
        record["kind"] = "other"
    return record


class CollectorHandle(object):
    def __init__(self, ptfhost, port):
        self.ptfhost = ptfhost
        self.port = port
        self.pid = None
        self.data_file = "/tmp/dialout_collector_%d.jsonl" % port
        self.log_file = "/tmp/dialout_collector_%d.log" % port

    @property
    def address(self):
        host = str(self.ptfhost.mgmt_ip)
        if ":" in host:
            # An unbracketed IPv6 host:port fails net.SplitHostPort in the
            # Go dialout client (--ipv6_only_mgmt testbeds).
            host = "[%s]" % host
        return "%s:%d" % (host, self.port)

    def records(self):
        res = self.ptfhost.shell("cat %s" % self.data_file, module_ignore_errors=True)
        if res["rc"] != 0:
            return []
        records = []
        for line in res["stdout_lines"]:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(decode_record(json.loads(line)))
            except ValueError:
                # The file is read while the collector appends; the final
                # line can be torn mid-write. Skip it — it will be complete
                # on the next read.
                logger.debug("skipping partial JSONL line (%d bytes)", len(line))
        return records

    def count(self, kind=None):
        records = self.records()
        if kind is None:
            return len(records)
        return len([r for r in records if r.get("kind") == kind])

    def stop(self):
        # Kill only this collector's own PID: on a PTF shared by two
        # sessions, a pattern-based pkill could stop the other session's
        # collector.
        if self.pid is not None:
            self.ptfhost.shell("kill -9 %d" % self.pid, module_ignore_errors=True)


@pytest.fixture(scope="module")
def copy_collector(ptfhost):
    """Deploy the collector and its TLS server cert pair to the PTF.

    The collector's only dependency is grpcio — no proto stubs, no pygnmi.
    The SONiC client dials with server verification disabled but always over
    TLS, so a throwaway pair from the shared generator is deployed alongside.
    """
    ptfhost.copy(src=COLLECTOR_SRC, dest=COLLECTOR_DST)
    certs = TlsCertificateGenerator(server_ip=str(ptfhost.mgmt_ip)).get_cert_bytes()
    ptfhost.copy(content=certs["server_cert"].decode("ascii"), dest=CERT_DST)
    ptfhost.copy(content=certs["server_key"].decode("ascii"), dest=KEY_DST)


_port_counter = itertools.count(BASE_PORT)


@pytest.fixture(scope="function")
def start_collector(ptfhost, copy_collector):
    """Factory starting a collector on the PTF; all instances stopped on teardown.

    Ports are never reused within a session so a stale publish stream aimed
    at an earlier test's collector can not pollute a later test's data.
    """
    handles = []

    def _start():
        port = next(_port_counter)
        handle = CollectorHandle(ptfhost, port)
        ptfhost.shell("rm -f %s %s" % (handle.data_file, handle.log_file))
        res = ptfhost.shell("nohup python3 %s --port %d --data %s --cert %s --key %s > %s 2>&1 "
                            "& echo $!"
                            % (COLLECTOR_DST, port, handle.data_file, CERT_DST, KEY_DST,
                               handle.log_file))
        handle.pid = int(res["stdout_lines"][-1].strip())
        # Registered before the readiness wait so teardown also stops a
        # collector that launched but never became ready. A process that
        # survives an aborted run holds its port, and the next bind on it
        # fails loudly (SO_REUSEPORT is disabled in the collector) — never
        # silently killed, since it may belong to another session.
        handles.append(handle)

        def ready():
            res = ptfhost.shell("grep -c 'Ready to serve' %s" % handle.log_file,
                                module_ignore_errors=True)
            return res["rc"] == 0 and int(res["stdout"].strip()) > 0

        if not wait_until(30, 1, 0, ready):
            log_tail = ptfhost.shell("tail -20 %s" % handle.log_file,
                                     module_ignore_errors=True)["stdout"]
            pt_assert(False, "dialout collector on port %d did not become ready; "
                             "collector log:\n%s" % (port, log_tail))
        return handle

    yield _start

    for handle in handles:
        handle.stop()
