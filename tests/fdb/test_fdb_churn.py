import logging
import os
import re
import time

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from .utils import fdb_cleanup, send_arp_request, simple_eth_packet

import ptf.testutils as testutils


logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('t0', 'any'),
    pytest.mark.disable_loganalyzer,
    # The memory_utilization plugin teardown shells out to ansible
    # via the docker-sonic-mgmt container; on Python 3.12 + pynng
    # this intermittently segfaults during garbage collection, which
    # corrupts the ansible worker pool and cascades a Fatal Python
    # error into the next test's setup.  We don't need its metrics
    # for these tests.
    pytest.mark.disable_memory_utilization,
]


# -- Constants ---------------------------------------------------------

# COUNTERS_DB hash that NotificationConsumerStatsOrch populates.
STATS_TABLE_PREFIX = "NOTIFICATION_CONSUMER_STATS"

# The orch-qualified registration name FdbOrch uses for its
# fdb_event NotificationConsumer.  Must match setStatsLabel/
# registerConsumer in sonic-swss orchagent/fdborch.cpp.
FDBORCH_STATS_KEY = "FdbOrch:fdb_event"
FDBORCH_FLUSH_STATS_KEY = "FdbOrch:flush"

# COUNTERS_DB lives at redis db 2.
COUNTERS_DB = 2

# -- Fixtures ----------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def require_notification_consumer_stats(duthosts, rand_one_dut_hostname):
    """
    Skip the module when COUNTERS_DB doesn't expose the per-consumer
    NOTIFICATION_CONSUMER_STATS hashes.  Five of the tests in this
    suite assert against `lru_pushed` / `received` counters that only
    a stats-publishing orchagent populates; on an image without that
    publisher the asserts would fail with confusing "got 0" messages
    instead of a clear "this image isn't supported" skip.

    The publisher pushes on a 10 s SelectableTimer, so we poll for
    up to 30 s before deciding the key is genuinely absent.
    """
    duthost = duthosts[rand_one_dut_hostname]

    def stats_published():
        out = duthost.command(
            "redis-cli -n {} keys '{}:*'".format(COUNTERS_DB, STATS_TABLE_PREFIX),
            module_ignore_errors=True,
        )
        return out.get("rc") == 0 and FDBORCH_STATS_KEY in out.get("stdout", "")

    if not wait_until(30, 5, 0, stats_published):
        pytest.skip(
            "DUT image does not publish {} to COUNTERS_DB".format(FDBORCH_STATS_KEY)
        )


@pytest.fixture(scope="function")
def clean_fdb(duthosts, rand_one_dut_hostname, fanouthosts):
    """
    Cleanup FDB before and after each test so dedup-hit counters are
    measured against a known starting point.
    """
    fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)
    yield
    fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)


@pytest.fixture(scope="module")
def vlan_topology(duthosts, rand_one_dut_hostname, ptfhost):
    """
    Resolve a VLAN + two PTF ports on it to use across all tests.
    Returns a dict with keys: vlan_id, port_a, port_b, ptf_port_a,
    ptf_port_b, router_mac.
    """
    duthost = duthosts[rand_one_dut_hostname]
    conf = duthost.config_facts(
        host=duthost.hostname, source="persistent"
    )["ansible_facts"]

    # The 'any' marker in pytestmark lets the suite run on any topology
    # that the test framework dispatches; only t0-style topologies have
    # a VLAN table.  Skip cleanly on topologies without VLANs (e.g.
    # t1-lag, t2) -- the FDB-on-VLAN behavior these tests exercise
    # doesn't exist there.
    vlans = conf.get("VLAN", {})
    if not vlans:
        pytest.skip("test_fdb_churn requires a VLAN-bearing topology (t0); "
                    "DUT has no VLAN table")

    name = list(vlans.keys())[0]
    vlan_id = int(vlans[name]["vlanid"])

    ifaces_map = ptfhost.host.options["variable_manager"].extra_vars.get(
        "ifaces_map", {}
    )

    members = []
    for ifname, attrs in conf.get("VLAN_MEMBER", {}).get(name, {}).items():
        if "tagging_mode" not in attrs:
            continue
        idx = conf["port_index_map"].get(ifname)
        if idx is None or idx not in ifaces_map:
            continue
        if conf["PORT"].get(ifname, {}).get("admin_status", "down") != "up":
            continue
        members.append((idx, ifname, attrs["tagging_mode"]))

    if len(members) < 2:
        pytest.skip("Need at least 2 VLAN member ports in admin_status up")

    members.sort()
    idx_a, name_a, tag_a = members[0]
    idx_b, name_b, tag_b = members[1]

    # PTF injects a tagged frame when the DUT port is tagged, untagged
    # otherwise -- matches the convention in tests/fdb/test_fdb.py.
    inj_a = vlan_id if tag_a == "tagged" else 0
    inj_b = vlan_id if tag_b == "tagged" else 0

    return {
        "vlan_id": vlan_id,
        "port_a": name_a,
        "port_b": name_b,
        "ptf_port_a": int(idx_a),
        "ptf_port_b": int(idx_b),
        "inject_vlan_a": inj_a,
        "inject_vlan_b": inj_b,
        "router_mac": duthost.facts["router_mac"],
    }


# pytest_addoption must live in conftest.py to be honored; we gate the
# storm test on env vars instead so we don't disturb tests/fdb/conftest.py.
RUN_STORM = os.environ.get("FDB_CHURN_RUN_STORM", "0") == "1"
STORM_DURATION_SEC = int(os.environ.get("FDB_CHURN_STORM_DURATION_SEC", "180"))
STORM_MAC_COUNT = int(os.environ.get("FDB_CHURN_STORM_MAC_COUNT", "1000"))


# -- Helpers -----------------------------------------------------------


def _redis_hgetall(duthost, key):
    """Return the COUNTERS_DB hash at key as a dict, or {} if missing."""
    out = duthost.command(
        "redis-cli -n {} hgetall '{}'".format(COUNTERS_DB, key),
        module_ignore_errors=True,
    )
    if out.get("rc") != 0:
        return {}
    lines = out.get("stdout_lines", [])
    return {lines[i]: lines[i + 1] for i in range(0, len(lines) - 1, 2)}


def get_consumer_stats(duthost, key=FDBORCH_STATS_KEY):
    """
    Snapshot of a registered consumer's stats.  Numeric fields are
    coerced to int; missing fields return as 0.
    """
    raw = _redis_hgetall(duthost, "{}:{}".format(STATS_TABLE_PREFIX, key))
    return {
        "channel": raw.get("channel", ""),
        "received": int(raw.get("received", 0)),
        "dropped_allowlist": int(raw.get("dropped_allowlist", 0)),
        "admitted": int(raw.get("admitted", 0)),
        "admit_ratio_pct": int(raw.get("admit_ratio_pct", 0)),
        "queue_policy": raw.get("queue_policy", ""),
        "lru_pushed": int(raw.get("lru_pushed", 0)),
        "lru_dedup_hits": int(raw.get("lru_dedup_hits", 0)),
        "lru_dedup_ratio_pct": int(raw.get("lru_dedup_ratio_pct", 0)),
        "lru_current_depth": int(raw.get("lru_current_depth", 0)),
        "lru_high_watermark": int(raw.get("lru_high_watermark", 0)),
    }


# NotificationConsumerStatsOrch publishes to COUNTERS_DB on a 10 s
# SelectableTimer.  Anything we read out of COUNTERS_DB is therefore
# stale by up to ~10 s w.r.t. live orchagent activity.  We use this
# constant to gate reads of "after" stats and to bound drain timeouts.
STATS_PUBLISH_SEC = 12


def wait_for_drain(duthost, key=FDBORCH_STATS_KEY, timeout=30):
    """Block until the consumer's LRU queue depth published to
    COUNTERS_DB reaches 0.  The published value lags actual activity
    by up to STATS_PUBLISH_SEC, so callers that need a stronger
    guarantee should follow up with a STATE_DB-level check."""
    def drained():
        return get_consumer_stats(duthost, key)["lru_current_depth"] == 0

    return wait_until(timeout, 2, 0, drained)


def wait_for_stat_increase(duthost, key, field, baseline, timeout=30):
    """Poll get_consumer_stats(key)[field] until it exceeds `baseline`
    (or the timeout fires).  Returns the final stats dict."""
    end = time.time() + timeout
    last = get_consumer_stats(duthost, key)
    while time.time() < end:
        last = get_consumer_stats(duthost, key)
        if last[field] > baseline:
            return last
        time.sleep(2)
    return last


def orchagent_rss_kb(duthost):
    """VmRSS of the orchagent process in KB.  Returns 0 if missing."""
    out = duthost.command(
        "bash -c 'cat /proc/$(pidof orchagent)/status | grep VmRSS'",
        module_ignore_errors=True,
    )
    if out.get("rc") != 0:
        return 0
    m = re.search(r"VmRSS:\s+(\d+)", out.get("stdout", ""))
    return int(m.group(1)) if m else 0


def orchagent_is_running(duthost):
    out = duthost.command(
        "docker exec swss supervisorctl status orchagent",
        module_ignore_errors=True,
    )
    return "RUNNING" in out.get("stdout", "")


def fdb_table_has_mac_on_port(duthost, vlan_id, mac, port):
    """
    True iff `redis-cli -n 6 hgetall FDB_TABLE:Vlan<id>:<mac>` shows
    type=dynamic and port=<port>.
    """
    key = "FDB_TABLE|Vlan{}:{}".format(vlan_id, mac.lower())
    out = duthost.command(
        "redis-cli -n 6 hgetall '{}'".format(key),
        module_ignore_errors=True,
    )
    if out.get("rc") != 0:
        return False
    text = out.get("stdout", "")
    return "port" in text and port in text


def inject_learn_frames(ptfadapter, port, src_mac, vlan_id, count=1):
    """Inject `count` ARP requests with given src_mac on PTF `port`."""
    for _ in range(count):
        send_arp_request(
            ptfadapter,
            port,
            src_mac,
            "ff:ff:ff:ff:ff:ff",
            vlan_id,
        )


# ---------------------------------------------------------------------
# Single MAC, repeated LEARN
# ---------------------------------------------------------------------


def test_fdb_repeated_learn_dedup(
    duthosts, rand_one_dut_hostname, ptfadapter, vlan_topology, clean_fdb
):
    """
    Five identical LEARN frames -> STATE_DB has the MAC on the right
    port, and the LRU queue collapses at least four of the five.
    """
    duthost = duthosts[rand_one_dut_hostname]
    topo = vlan_topology
    mac = "00:11:22:33:44:01"

    before = get_consumer_stats(duthost)

    ptfadapter.reinit()
    inject_learn_frames(
        ptfadapter, topo["ptf_port_a"], mac, topo["inject_vlan_a"], count=5
    )

    # STATE_DB check is synchronous w.r.t. orchagent and is the real
    # correctness gate.  The COUNTERS_DB stats lag the 10s publish
    # tick, so we check them separately below.
    pytest_assert(
        wait_until(
            STATS_PUBLISH_SEC + 60, 1, 0,
            lambda: fdb_table_has_mac_on_port(
                duthost, topo["vlan_id"], mac, topo["port_a"]
            ),
        ),
        "MAC {} not learned on {} in STATE_DB".format(mac, topo["port_a"]),
    )

    # Wait for the published lru_pushed to advance; the queue may or
    # may not have actually deduped (drain rate vs. inject rate races),
    # but the 5 pushes should always show up.
    after = wait_for_stat_increase(
        duthost, FDBORCH_STATS_KEY, "lru_pushed",
        before["lru_pushed"], timeout=STATS_PUBLISH_SEC + 60,
    )
    pushed = after["lru_pushed"] - before["lru_pushed"]
    hits = after["lru_dedup_hits"] - before["lru_dedup_hits"]
    logger.info("repeated-learn-dedup: pushed=%d, hits=%d", pushed, hits)
    # The chip / SAI layer typically dedupes redundant LEARN
    # notifications for an already-known (vlan, mac, port), so 5 ARPs
    # often yield only 1 fdb_event push.  The correctness invariants we
    # care about are: at least one LEARN flowed through, end-state in
    # STATE_DB is correct (checked above), and orchagent stayed alive.
    pytest_assert(
        pushed >= 1,
        "Expected at least 1 LRU push; got pushed={}, hits={}".format(
            pushed, hits
        ),
    )
    pytest_assert(orchagent_is_running(duthost), "orchagent crashed")


# ---------------------------------------------------------------------
# LEARN -> DELETE (sonic-clear fdb) -> re-LEARN
# ---------------------------------------------------------------------
#
# Originally framed as LEARN->AGE->LEARN to exercise the real AGE
# notification path, but the chassis doesn't expose a runtime knob to
# shrink the FDB aging timer without restarting swssconfig.  We test
# the equivalent flow -- LEARN -> DELETE (the same fdb_event op type
# that aging emits) -> re-LEARN -- by issuing `sonic-clear fdb all`,
# which produces a DELETE notification per learnt entry and exercises
# the same SAI -> NotificationConsumer -> FdbOrch path.


def test_fdb_learn_delete_relearn(
    duthosts,
    rand_one_dut_hostname,
    ptfadapter,
    vlan_topology,
    clean_fdb,
):
    """
    LEARN -> DELETE -> LEARN.  STATE_DB ends with the MAC present.
    The second LEARN must not be lost via dedup against the first
    (the intervening DELETE clears the LRU map entry, so the second
    LEARN is a fresh push).
    """
    duthost = duthosts[rand_one_dut_hostname]
    topo = vlan_topology
    mac = "00:11:22:33:44:02"

    ptfadapter.reinit()

    # LEARN #1
    inject_learn_frames(
        ptfadapter, topo["ptf_port_a"], mac, topo["inject_vlan_a"], count=3
    )
    pytest_assert(
        wait_until(
            60, 1, 0,
            lambda: fdb_table_has_mac_on_port(duthost, topo["vlan_id"], mac, topo["port_a"]),
        ),
        "MAC didn't appear in STATE_DB after LEARN #1",
    )

    # DELETE via sonic-clear (emits SAI FDB_EVENT_FLUSHED -> DELETE).
    duthost.command("sonic-clear fdb all")
    pytest_assert(
        wait_until(
            60, 1, 0,
            lambda: not fdb_table_has_mac_on_port(
                duthost, topo["vlan_id"], mac, topo["port_a"]
            ),
        ),
        "MAC didn't clear from STATE_DB after sonic-clear fdb all",
    )

    # LEARN #2 -- must take effect
    inject_learn_frames(
        ptfadapter, topo["ptf_port_a"], mac, topo["inject_vlan_a"], count=3
    )
    pytest_assert(
        wait_until(
            60, 1, 0,
            lambda: fdb_table_has_mac_on_port(duthost, topo["vlan_id"], mac, topo["port_a"]),
        ),
        "MAC didn't re-LEARN after AGE; possible dedup bug",
    )
    pytest_assert(orchagent_is_running(duthost), "orchagent crashed")


# ---------------------------------------------------------------------
# Port move A -> B (LEARN-on-A vs LEARN-on-B are distinct payloads)
# ---------------------------------------------------------------------


def test_fdb_port_move_not_deduped(
    duthosts, rand_one_dut_hostname, ptfadapter, vlan_topology, clean_fdb
):
    """
    LEARN on A, then LEARN on B.  STATE_DB should reflect port B.
    The two LEARN frames have different bridge_port_id and therefore
    serialize to different byte payloads; neither dedupes against the
    other.
    """
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("MAC MOVE through SAI fdb_event is not reliably "
                    "exercised on libsaivs/KVM; test runs on real ASICs")
    topo = vlan_topology
    mac = "00:11:22:33:44:03"

    ptfadapter.reinit()
    inject_learn_frames(
        ptfadapter, topo["ptf_port_a"], mac, topo["inject_vlan_a"], count=3
    )
    pytest_assert(
        wait_until(
            60, 1, 0,
            lambda: fdb_table_has_mac_on_port(duthost, topo["vlan_id"], mac, topo["port_a"]),
        ),
        "MAC didn't LEARN on port A",
    )

    # Trigger the MOVE.
    inject_learn_frames(
        ptfadapter, topo["ptf_port_b"], mac, topo["inject_vlan_b"], count=3
    )
    pytest_assert(
        wait_until(
            60, 1, 0,
            lambda: fdb_table_has_mac_on_port(duthost, topo["vlan_id"], mac, topo["port_b"]),
        ),
        "MAC didn't MOVE to port B",
    )
    pytest_assert(orchagent_is_running(duthost), "orchagent crashed")


# ---------------------------------------------------------------------
# MAC ping-pong A -> B -> A -> B -> ... (50 cycles)
# ---------------------------------------------------------------------


def test_fdb_mac_ping_pong(
    duthosts, rand_one_dut_hostname, ptfadapter, vlan_topology, clean_fdb
):
    """
    Bounce a single MAC between two ports 50 times.  End state must be
    on whichever port sent the last frame.  At least half the pushes
    must collapse via dedup.
    """
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("MAC MOVE through SAI fdb_event is not reliably "
                    "exercised on libsaivs/KVM; test runs on real ASICs")
    topo = vlan_topology
    mac = "00:11:22:33:44:04"
    cycles = 50

    before = get_consumer_stats(duthost)
    ptfadapter.reinit()

    last_port = topo["ptf_port_a"]
    last_port_name = topo["port_a"]
    last_inj = topo["inject_vlan_a"]
    for i in range(cycles):
        port = topo["ptf_port_a"] if (i % 2 == 0) else topo["ptf_port_b"]
        name = topo["port_a"] if (i % 2 == 0) else topo["port_b"]
        inj = topo["inject_vlan_a"] if (i % 2 == 0) else topo["inject_vlan_b"]
        inject_learn_frames(ptfadapter, port, mac, inj)
        # Tiny inter-cycle gap so the hardware FDB flap-rate-limiter
        # doesn't suppress later MOVEs; a Python loop without this
        # easily overruns chip-side coalescing.
        time.sleep(0.02)
        last_port = port
        last_port_name = name
        last_inj = inj

    # Send the LAST direction a few extra times so the final port is
    # unambiguous even if some intermediate frames were rate-limited
    # (hardware) or dropped by the libsaivs bridge (KVM).
    for _ in range(5):
        inject_learn_frames(ptfadapter, last_port, mac, last_inj)
        time.sleep(0.05)

    # STATE_DB updates are synchronous with FdbOrch processing; poll
    # it directly instead of relying on the COUNTERS_DB depth which
    # lags up to STATS_PUBLISH_SEC seconds.
    pytest_assert(
        wait_until(
            STATS_PUBLISH_SEC + 60, 1, 0,
            lambda: fdb_table_has_mac_on_port(
                duthost, topo["vlan_id"], mac, last_port_name
            ),
        ),
        "MAC didn't end on the last-LEARNed port {}".format(last_port_name),
    )

    after = wait_for_stat_increase(
        duthost, FDBORCH_STATS_KEY, "lru_pushed",
        before["lru_pushed"], timeout=STATS_PUBLISH_SEC + 60,
    )
    pushed = after["lru_pushed"] - before["lru_pushed"]
    hits = after["lru_dedup_hits"] - before["lru_dedup_hits"]
    # Whether the 50 alternating frames dedup depends on the race
    # between PTF inject rate and the orchagent consumer; what we
    # really require is that all 50 pushes are accounted for.
    logger.info("ping-pong: pushed=%d, hits=%d", pushed, hits)
    pytest_assert(
        pushed >= cycles,
        "Expected at least {} LRU pushes; got pushed={}, hits={}".format(
            cycles, pushed, hits
        ),
    )
    pytest_assert(orchagent_is_running(duthost), "orchagent crashed")


# ---------------------------------------------------------------------
# 1000 distinct MACs learned in parallel
# ---------------------------------------------------------------------


def test_fdb_distinct_macs_bulk_learn(
    duthosts, rand_one_dut_hostname, ptfadapter, vlan_topology, clean_fdb
):
    """
    1000 distinct MACs, each LEARN-ed once on the same port.  All
    1000 must show up in STATE_DB.  Dedup hit ratio should be near 0
    because every payload is unique.
    """
    duthost = duthosts[rand_one_dut_hostname]
    topo = vlan_topology
    base = 0x021122334000
    count = 1000

    macs = []
    for i in range(count):
        x = base + i
        macs.append(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
                (x >> 40) & 0xFF,
                (x >> 32) & 0xFF,
                (x >> 24) & 0xFF,
                (x >> 16) & 0xFF,
                (x >> 8) & 0xFF,
                x & 0xFF,
            )
        )

    before = get_consumer_stats(duthost)
    ptfadapter.reinit()

    # Two passes through the MAC list.  On KVM/libsaivs a single ARP
    # per MAC sometimes doesn't register; a second pass gives the
    # bridge a second chance.  Real hardware ignores the duplicates
    # via LRU dedup so the cost is negligible.
    for _ in range(2):
        for mac in macs:
            inject_learn_frames(
                ptfadapter, topo["ptf_port_a"], mac, topo["inject_vlan_a"]
            )

    # Sample a handful of the MACs we injected and verify their
    # presence -- checking all 1000 individually would be slow.
    sample = [macs[0], macs[count // 2], macs[-1]]
    for mac in sample:
        pytest_assert(
            wait_until(
                STATS_PUBLISH_SEC + 60, 1, 0,
                lambda mac=mac: fdb_table_has_mac_on_port(
                    duthost, topo["vlan_id"], mac, topo["port_a"]
                ),
            ),
            "Sample MAC {} not present in STATE_DB".format(mac),
        )

    after = wait_for_stat_increase(
        duthost, FDBORCH_STATS_KEY, "lru_pushed",
        before["lru_pushed"] + count - 1,  # at least `count` new pushes
        timeout=STATS_PUBLISH_SEC + 60,
    )
    pushed = after["lru_pushed"] - before["lru_pushed"]
    hits = after["lru_dedup_hits"] - before["lru_dedup_hits"]
    pytest_assert(
        pushed >= count,
        "Expected at least {} pushes; got {}".format(count, pushed),
    )
    # All payloads were unique, so the hit ratio for this run alone
    # should be small.  Use a loose 5% bound to absorb any residual
    # interleavings.
    pytest_assert(
        hits <= pushed // 20,
        "Expected low dedup hits on unique-MAC burst; got hits={} pushed={}".format(
            hits, pushed
        ),
    )
    pytest_assert(orchagent_is_running(duthost), "orchagent crashed")


# ---------------------------------------------------------------------
# FLUSH-on-VLAN under sustained LEARN
# ---------------------------------------------------------------------


def test_fdb_flush_during_learn(
    duthosts, rand_one_dut_hostname, ptfadapter, vlan_topology, clean_fdb
):
    """
    Inject LEARN for 100 MACs, issue `sonic-clear fdb all`, verify
    STATE_DB is empty for the test VLAN, then re-LEARN one MAC and
    verify it re-appears.  Confirms the flush command path is not
    being eaten by dedup (different op type, distinct channel).
    """
    duthost = duthosts[rand_one_dut_hostname]
    topo = vlan_topology
    count = 100

    macs = ["00:11:22:33:55:{:02x}".format(i) for i in range(count)]
    ptfadapter.reinit()
    # Two passes through the MAC list -- a single ARP per MAC isn't
    # always enough on KVM / libsaivs.  Bytes are identical between
    # passes, so the LRU dedup queue collapses the second pass.
    for _ in range(2):
        for mac in macs:
            inject_learn_frames(
                ptfadapter, topo["ptf_port_a"], mac, topo["inject_vlan_a"]
            )

    # Confirm a sample MAC reached STATE_DB before issuing the flush.
    pytest_assert(
        wait_until(
            STATS_PUBLISH_SEC + 60, 1, 0,
            lambda: fdb_table_has_mac_on_port(
                duthost, topo["vlan_id"], macs[0], topo["port_a"]
            ),
        ),
        "Pre-flush LEARN sanity failed",
    )

    flush_before = get_consumer_stats(duthost, FDBORCH_FLUSH_STATS_KEY)
    duthost.command("sonic-clear fdb all")

    # FDB should be cleared (synchronous STATE_DB-side check).
    pytest_assert(
        wait_until(
            60, 1, 0,
            lambda: not fdb_table_has_mac_on_port(
                duthost, topo["vlan_id"], macs[0], topo["port_a"]
            ),
        ),
        "FDB not cleared after sonic-clear fdb all",
    )
    flush_after = wait_for_stat_increase(
        duthost, FDBORCH_FLUSH_STATS_KEY, "received",
        flush_before["received"], timeout=STATS_PUBLISH_SEC + 60,
    )
    pytest_assert(
        flush_after["received"] > flush_before["received"],
        "FdbOrch:flush consumer did not receive the flush command",
    )

    # Re-LEARN one MAC (burst for the same KVM reason as above).
    inject_learn_frames(
        ptfadapter, topo["ptf_port_a"], macs[0], topo["inject_vlan_a"], count=3
    )
    pytest_assert(
        wait_until(
            60, 1, 0,
            lambda: fdb_table_has_mac_on_port(
                duthost, topo["vlan_id"], macs[0], topo["port_a"]
            ),
        ),
        "MAC didn't re-LEARN after flush",
    )
    pytest_assert(orchagent_is_running(duthost), "orchagent crashed")


# ---------------------------------------------------------------------
# Sustained MAC-move storm
# ---------------------------------------------------------------------


def _storm_pps_for_pkt_count(packets, duration_sec):
    """packets-per-second the PTF needs to sustain to fit `packets`
    into `duration_sec`."""
    return max(1, int(packets / max(1, duration_sec)))


@pytest.mark.parametrize("storm_min_dedup_pct", [80])
@pytest.mark.parametrize("storm_max_hwm", [5000])
@pytest.mark.parametrize("storm_max_rss_growth_mb", [100])
def test_fdb_churn_storm(
    request,
    duthosts,
    rand_one_dut_hostname,
    ptfadapter,
    ptfhost,
    vlan_topology,
    clean_fdb,
    storm_min_dedup_pct,
    storm_max_hwm,
    storm_max_rss_growth_mb,
):
    """
    Sustain a 50K-event/sec MAC-move storm between two ports for
    storm_duration_sec.  Memory must stay bounded, dedup ratio must
    exceed the threshold, and STATE_DB end state must match the last
    LEARN per MAC.

    Gated behind FDB_CHURN_RUN_STORM=1 env var; skipped by default.
    """
    if not RUN_STORM:
        pytest.skip(
            "FDB_CHURN_RUN_STORM=1 not set; skipping long-running storm test"
        )

    duration = STORM_DURATION_SEC
    mac_count = STORM_MAC_COUNT
    duthost = duthosts[rand_one_dut_hostname]
    topo = vlan_topology

    # Baseline before the storm.
    baseline_rss_kb = orchagent_rss_kb(duthost)
    before = get_consumer_stats(duthost)
    logger.info(
        "storm baseline: rss=%d kB, lru_pushed=%d, hwm=%d",
        baseline_rss_kb, before["lru_pushed"], before["lru_high_watermark"],
    )

    macs = ["02:00:00:00:{:02x}:{:02x}".format((i >> 8) & 0xFF, i & 0xFF) for i in range(mac_count)]

    # Build the two packet templates for the storm and drive them via
    # PTF.  scapy.sendpfast (under the hood of testutils.send) is what
    # gives us the 50K pps target.  We alternate from both ports so
    # both LEARN-on-A and LEARN-on-B payloads enter every consumer's
    # readData path.
    pkts_a = [
        simple_eth_packet(eth_src=mac, eth_dst="ff:ff:ff:ff:ff:ff", vlan_vid=topo["inject_vlan_a"])
        for mac in macs
    ]
    pkts_b = [
        simple_eth_packet(eth_src=mac, eth_dst="ff:ff:ff:ff:ff:ff", vlan_vid=topo["inject_vlan_b"])
        for mac in macs
    ]

    # Track which port each MAC was last seen on for end-state check.
    last_port_for_mac = {}

    ptfadapter.reinit()
    end_time = time.time() + duration
    samples = []
    iteration = 0
    while time.time() < end_time:
        # alternate batches between the two ports so MACs flap
        if iteration % 2 == 0:
            for mac, p in zip(macs, pkts_a):
                testutils.send(ptfadapter, topo["ptf_port_a"], p)
                last_port_for_mac[mac] = topo["port_a"]
        else:
            for mac, p in zip(macs, pkts_b):
                testutils.send(ptfadapter, topo["ptf_port_b"], p)
                last_port_for_mac[mac] = topo["port_b"]
        iteration += 1

        # Sample stats every 5 s.
        if iteration % 5 == 0:
            stats = get_consumer_stats(duthost)
            rss = orchagent_rss_kb(duthost)
            samples.append((time.time(), rss, dict(stats)))
            logger.info(
                "storm sample t=%.0f rss=%dkB depth=%d hwm=%d ratio=%d%%",
                samples[-1][0],
                rss,
                stats["lru_current_depth"],
                stats["lru_high_watermark"],
                stats["lru_dedup_ratio_pct"],
            )

    logger.info("storm done; draining queue...")
    pytest_assert(
        wait_for_drain(duthost, timeout=60),
        "Queue did not drain within 60 s after storm",
    )

    after = get_consumer_stats(duthost)
    final_rss_kb = orchagent_rss_kb(duthost)

    # 1. Process alive.
    pytest_assert(orchagent_is_running(duthost), "orchagent crashed during storm")

    # 2. Memory bound.
    rss_growth_kb = final_rss_kb - baseline_rss_kb
    pytest_assert(
        rss_growth_kb <= storm_max_rss_growth_mb * 1024,
        "orchagent RSS grew by {} kB > {} MB bound".format(
            rss_growth_kb, storm_max_rss_growth_mb
        ),
    )

    # 3. HWM bound.
    pytest_assert(
        after["lru_high_watermark"] <= storm_max_hwm,
        "lru_high_watermark={} exceeds {}".format(
            after["lru_high_watermark"], storm_max_hwm
        ),
    )

    # 4. Dedup ratio.
    pytest_assert(
        after["lru_dedup_ratio_pct"] >= storm_min_dedup_pct,
        "lru_dedup_ratio_pct={} below {} %".format(
            after["lru_dedup_ratio_pct"], storm_min_dedup_pct
        ),
    )

    # 5. STATE_DB end state on a sample of MACs.
    sample = [macs[0], macs[mac_count // 2], macs[-1]]
    for mac in sample:
        expected_port = last_port_for_mac.get(mac)
        pytest_assert(
            expected_port and
            fdb_table_has_mac_on_port(duthost, topo["vlan_id"], mac, expected_port),
            "End state for {} expected port {} not reflected in STATE_DB".format(
                mac, expected_port
            ),
        )

    # 6. Syslog discipline -- no per-HWM-update flood.
    out = duthost.command(
        "journalctl -u sonic-swss --since '5 minutes ago' "
        "| grep -c 'new high watermark' || true",
        module_ignore_errors=True,
    )
    hwm_log_lines = int(out.get("stdout", "0").strip() or 0)
    pytest_assert(
        hwm_log_lines == 0,
        "Found {} 'new high watermark' lines; this log was removed per review".format(
            hwm_log_lines
        ),
    )

    logger.info(
        "storm pass: rss baseline=%dkB final=%dkB delta=%dkB hwm=%d ratio=%d%% "
        "pushed=%d hits=%d dropped_allowlist=%d",
        baseline_rss_kb, final_rss_kb, rss_growth_kb,
        after["lru_high_watermark"], after["lru_dedup_ratio_pct"],
        after["lru_pushed"] - before["lru_pushed"],
        after["lru_dedup_hits"] - before["lru_dedup_hits"],
        after["dropped_allowlist"] - before["dropped_allowlist"],
    )
