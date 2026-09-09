"""gNMI dial-out tests.

SONiC telemetry dial-out: the DUT's dialout client watches the
TELEMETRY_CLIENT table in CONFIG_DB and pushes gNMI SubscribeResponse
messages over the gnmi.sonic.gNMIDialOut/Publish gRPC stream to a
configured collector. These tests run a collector on the PTF host and
verify the full path: config ingestion via redis keyspace events, the
periodic/stream/once report types, multi-destination failover, and
unconfiguration.
"""
import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]

REPORT_INTERVAL_MS = 2000
RETRY_INTERVAL_S = 5


def configure_dialout(config, dst_addrs, report_type, paths="COUNTERS_PORT_NAME_MAP",
                      report_interval=REPORT_INTERVAL_MS):
    """Write a full Global + DestinationGroup + Subscription config set.

    report_interval is always set explicitly: the client's fallback for an
    omitted field is currently a microseconds-scale busy loop, not the 5s
    its code comment intends.
    """
    config.hset("Global", retry_interval=RETRY_INTERVAL_S)
    config.hset("DestinationGroup_TEST", dst_addr=",".join(dst_addrs))
    fields = {
        "dst_group": "TEST",
        "path_target": "COUNTERS_DB",
        "paths": paths,
        "report_type": report_type,
        "report_interval": report_interval,
    }
    config.hset("Subscription_TEST", **fields)


def wait_for_updates(collector, minimum, timeout=90):
    return wait_until(timeout, 3, 0, lambda: collector.count(kind="update") >= minimum)


def updates_contain(records, path, key, value):
    """True when some decoded update matches `path` exactly and its JSON
    payload carries key=value. Anything else — another path, another value,
    a non-dict payload — does not satisfy it."""
    for record in records:
        for upd_path, payload in record.get("updates", []):
            if upd_path == path and isinstance(payload, dict) and payload.get(key) == value:
                return True
    return False


def counters_port_map_entry(duthost):
    """One (port, oid) entry read live from the DUT's COUNTERS_PORT_NAME_MAP."""
    port = duthost.shell(
        "sonic-db-cli COUNTERS_DB HKEYS COUNTERS_PORT_NAME_MAP")["stdout_lines"][0].strip()
    oid = duthost.shell(
        "sonic-db-cli COUNTERS_DB HGET COUNTERS_PORT_NAME_MAP '%s'" % port)["stdout"].strip()
    return port, oid


def test_dialout_process_running(dialout_setup):
    """The dialout client program comes up by default in the gnmi/telemetry container.

    Asserts on the supervisorctl status captured before dialout_setup's own
    restart, so what is verified is the state the image booted into — i.e.
    the dependent_startup wiring (the program is autostart=false and started
    only via dependent_startup_wait_for), not this suite's restart.
    """
    initial = dialout_setup["initial_dialout_status"]
    pytest_assert(initial is not None and "RUNNING" in initial,
                  "dialout was not RUNNING in %s before this suite restarted it "
                  "(initial status: %s)" % (dialout_setup["container"], initial))


def test_dialout_periodic(dialout_setup, telemetry_client_config, start_collector):
    """Periodic report: collector receives COUNTERS_DB snapshots, not a busy loop."""
    collector = start_collector()
    configure_dialout(telemetry_client_config, [collector.address], "periodic")

    pytest_assert(wait_for_updates(collector, 3),
                  "collector received %d update messages, want >= 3" % collector.count(kind="update"))

    updates = [r for r in collector.records() if r.get("kind") == "update"]
    pytest_assert(updates, "no update records readable from the collector on re-read "
                           "(records: %d)" % collector.count())
    for record in updates:
        pytest_assert(record.get("target") == "COUNTERS_DB",
                      "unexpected notification target: %s" % record)
        pytest_assert(record.get("update_count", 0) >= 1,
                      "notification carries no updates: %s" % record)

    # Payload check against the DUT's own table content: the requested path
    # must arrive carrying a real COUNTERS_PORT_NAME_MAP entry, so an
    # unrelated update with the right target can not satisfy this test.
    port, oid = counters_port_map_entry(dialout_setup["duthost"])
    pytest_assert(updates_contain(updates, "COUNTERS_PORT_NAME_MAP", port, oid),
                  "no update carried %s=%s at path COUNTERS_PORT_NAME_MAP; got: %s"
                  % (port, oid, [r.get("updates") for r in updates[:3]]))
    # Validator self-check: records with the correct target and update
    # count but a wrong path, or a wrong value, must be rejected.
    base = {"kind": "update", "target": "COUNTERS_DB", "update_count": 1}
    wrong_path = [dict(base, updates=[("NOT_THE_REQUESTED_PATH", {port: oid})])]
    wrong_value = [dict(base, updates=[("COUNTERS_PORT_NAME_MAP", {port: "oid:0xbad"})])]
    pytest_assert(not updates_contain(wrong_path, "COUNTERS_PORT_NAME_MAP", port, oid),
                  "payload validation accepted an update with the wrong path")
    pytest_assert(not updates_contain(wrong_value, "COUNTERS_PORT_NAME_MAP", port, oid),
                  "payload validation accepted an update with the wrong value")

    # Busy-loop guard (lower bound only): within a single publish stream
    # (peer), consecutive messages must not arrive much faster than
    # report_interval. Group by peer so a reconnect (new stream) can not
    # produce a misleading small gap, and assert on the median gap: the
    # timestamps are receive-side, so a stalled read can stamp one message
    # late and the next on time, shortening a single gap on a healthy
    # client — while the busy-loop bug compresses every gap to microseconds.
    by_peer = {}
    for r in updates:
        by_peer.setdefault(r.get("peer"), []).append(r["ts"])
    peer, timestamps = max(by_peer.items(), key=lambda kv: len(kv[1]))
    gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
    pytest_assert(len(gaps) >= 1,
                  "not enough same-stream samples to measure cadence "
                  "(peers: %s)" % {p: len(t) for p, t in by_peer.items()})
    median_gap = sorted(gaps)[len(gaps) // 2]
    pytest_assert(median_gap > REPORT_INTERVAL_MS / 1000.0 * 0.5,
                  "updates from %s arrived too fast (median gap %.3fs, gaps %s); "
                  "busy loop?" % (peer, median_gap, gaps))


def test_dialout_stream(dialout_setup, telemetry_client_config, start_collector):
    """Stream report: update notifications and a sync_response arrive at the collector."""
    collector = start_collector()
    configure_dialout(telemetry_client_config, [collector.address], "stream",
                      paths="COUNTERS/Ethernet*")

    pytest_assert(wait_until(90, 3, 0, lambda: collector.count(kind="sync") >= 1),
                  "no sync_response received; records: %d" % collector.count())
    pytest_assert(collector.count(kind="update") >= 1,
                  "no update notifications received")

    # Payload check: the client publishes the path as requested — the
    # wildcard stays unexpanded (COUNTERS/Ethernet*) with a payload keyed
    # by the DUT's real port names; a later on-change update can also
    # arrive per port (COUNTERS/<port>). Either way the counters must be
    # for ports this DUT actually has, and non-empty.
    duthost = dialout_setup["duthost"]
    ports = {ln.strip() for ln in duthost.shell(
        "sonic-db-cli COUNTERS_DB HKEYS COUNTERS_PORT_NAME_MAP")["stdout_lines"] if ln.strip()}
    matched = 0
    for record in collector.records():
        for path, payload in record.get("updates", []):
            if not path.startswith("COUNTERS/"):
                continue
            pytest_assert(isinstance(payload, dict) and payload,
                          "counters update %s carries no payload: %r" % (path, payload))
            tail = path.split("/", 1)[1]
            per_port = {tail: payload} if tail in ports else payload
            known = {p: c for p, c in per_port.items() if p in ports}
            pytest_assert(known,
                          "update %s carries no data for any port this DUT has "
                          "(payload keys: %s)" % (path, sorted(per_port)[:5]))
            for port, counters in known.items():
                pytest_assert(isinstance(counters, dict) and counters,
                              "empty counters for %s in update %s" % (port, path))
            matched += 1
    pytest_assert(matched >= 1,
                  "no update matched the requested COUNTERS/Ethernet* paths")


@pytest.mark.xfail(strict=True,
                   reason="report_type 'once' is accepted by TELEMETRY_CLIENT config but "
                          "unimplemented in the dialout client: publishRun has no Once arm, "
                          "so the subscription is silently ignored")
def test_dialout_once(dialout_setup, telemetry_client_config, start_collector):
    """Once report: a single snapshot should arrive after configuration."""
    collector = start_collector()
    configure_dialout(telemetry_client_config, [collector.address], "once")
    pytest_assert(wait_for_updates(collector, 1, timeout=60),
                  "no snapshot received for report_type=once")


def test_dialout_failover(dialout_setup, telemetry_client_config, start_collector):
    """With two destinations, killing the active collector moves the stream to the other."""
    first = start_collector()
    second = start_collector()
    configure_dialout(telemetry_client_config, [first.address, second.address], "periodic")

    # The client connects to one destination (round-robin from the first).
    pytest_assert(wait_until(90, 3, 0,
                             lambda: first.count(kind="update") + second.count(kind="update") >= 2),
                  "no updates on either collector")

    def last_update_ts(collector):
        stamps = [r["ts"] for r in collector.records() if r.get("kind") == "update"]
        return max(stamps) if stamps else 0.0

    # The live stream is wherever the most recent update landed — a
    # reconnect during the initial wait can leave old updates on both.
    active, standby = ((first, second) if last_update_ts(first) >= last_update_ts(second)
                       else (second, first))

    # Confirm the standby really is idle before the kill, so the rise
    # asserted below can only mean failover (not a mislabelled active).
    standby_before = standby.count(kind="update")
    time.sleep(1.5 * REPORT_INTERVAL_MS / 1000.0)
    pytest_assert(standby.count(kind="update") == standby_before,
                  "standby collector received updates before failover — "
                  "active/standby misidentified")

    active.stop()
    pytest_assert(wait_until(120, 5, 0,
                             lambda: standby.count(kind="update") > standby_before),
                  "no updates on standby collector after killing the active one")


def test_dialout_unconfigure_stops_publishing(dialout_setup, telemetry_client_config,
                                              start_collector):
    """Deleting the Subscription row stops the publish stream."""
    collector = start_collector()
    configure_dialout(telemetry_client_config, [collector.address], "periodic")
    pytest_assert(wait_for_updates(collector, 2), "dial-out stream never started")

    telemetry_client_config.delete("Subscription_TEST")

    # Wait for the stream to quiesce first: the deletion propagates via
    # keyspace events and a message already in flight may still land, so a
    # fixed grace period would make the equality check below flaky.
    def quiesced():
        n = collector.count(kind="update")
        time.sleep(REPORT_INTERVAL_MS / 1000.0)
        return collector.count(kind="update") == n

    pytest_assert(wait_until(30, 1, 0, quiesced),
                  "updates never stopped arriving after Subscription was deleted")

    before = collector.count(kind="update")
    time.sleep(3 * REPORT_INTERVAL_MS / 1000.0)
    after = collector.count(kind="update")
    pytest_assert(after == before,
                  "updates kept arriving after Subscription was deleted (%d -> %d)"
                  % (before, after))
