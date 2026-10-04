import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.platform_tests.link_flap.link_flap_utils import check_orch_cpu_utilization

logger = logging.getLogger(__name__)


# Disable route_check because both tests briefly flap DUT-facing links
# (synthetic: fake port_state_change events; paused: real shut/noshut) which
# transiently flaps BGP sessions.
pytestmark = [
    pytest.mark.disable_route_check,
    pytest.mark.topology('any'),
]


# Number of (down, up) pairs - 2x this many PUBLISH messages.
LINK_FLAP_COUNT = 150000

# Number of shut/noshut iterations per port for the functional end-state test.
FUNCTIONAL_FLAP_ITERATIONS = 10

# Wait for orchagent CPU to settle after the burst (proxy for drain).
ORCHAGENT_DRAIN_TIMEOUT = 120
ORCHAGENT_DRAIN_POLL_INTERVAL = 2

# Seconds to wait for APPL_DB oper_status to converge.
OPER_STATUS_TIMEOUT = 60

# CPU threshold used to declare orchagent caught up with the burst.
ORCHAGENT_IDLE_CPU_THRESHOLD = 10

# Fake SAI port OID used in synthetic injection. PortsOrch logs "port does not
# exist, possibly outdated event" and skips state mutation, so we exercise the
# NotificationConsumer path without flipping real ports through BFD/neighbors.
FAKE_PORT_OID = "oid:0x10000deadbead"

# COUNTERS_DB hash that NotificationConsumerStatsOrch populates.
COUNTERS_DB = 2
STATS_TABLE_PREFIX = "NOTIFICATION_CONSUMER_STATS"
PORTSORCH_STATS_KEY = "PortsOrch:port_state_change"

# NotificationConsumerStatsOrch publishes on a 10 s SelectableTimer.
STATS_PUBLISH_SEC = 12


def _ns_arg(asic_id):
    return "" if asic_id == '' else "-n asic{}".format(asic_id)


def _counters_db_cmd(asic_id):
    if asic_id == '':
        return "redis-cli -n {}".format(COUNTERS_DB)
    return "redis-cli -s /var/run/redis{}/redis.sock -n {}".format(asic_id, COUNTERS_DB)


def orchagent_is_running(duthost, asic_id=''):
    out = duthost.command(
        "docker exec swss{} supervisorctl status orchagent".format(asic_id),
        module_ignore_errors=True,
    )
    return "RUNNING" in out.get("stdout", "")


def _redis_hgetall(duthost, key, asic_id=''):
    out = duthost.command(
        "{} hgetall '{}'".format(_counters_db_cmd(asic_id), key),
        module_ignore_errors=True,
    )
    if out.get("rc") != 0:
        return {}
    lines = out.get("stdout_lines", [])
    return {lines[i]: lines[i + 1] for i in range(0, len(lines) - 1, 2)}


def get_consumer_stats(duthost, key=PORTSORCH_STATS_KEY, asic_id=''):
    raw = _redis_hgetall(duthost, "{}:{}".format(STATS_TABLE_PREFIX, key), asic_id=asic_id)
    return {
        "queue_policy": raw.get("queue_policy", ""),
        "received": int(raw.get("received", 0)),
        "lru_pushed": int(raw.get("lru_pushed", 0)),
        "lru_dedup_hits": int(raw.get("lru_dedup_hits", 0)),
        "lru_current_depth": int(raw.get("lru_current_depth", 0)),
    }


def stats_available(duthost, key=PORTSORCH_STATS_KEY, asic_id=''):
    out = duthost.command(
        "{} exists '{}:{}'".format(_counters_db_cmd(asic_id), STATS_TABLE_PREFIX, key),
        module_ignore_errors=True,
    )
    rc = out.get("rc")
    stdout = out.get("stdout", "").strip()
    # Log the raw result whenever it's not a clean "key exists". Absent
    # publisher and transient redis-cli failure both cause skip-the-module
    # via the require_notification_consumer_stats fixture, so leave a
    # breadcrumb to distinguish them when triaging a skipped run.
    if rc != 0 or stdout != "1":
        logger.debug(
            "stats_available(%s:%s asic=%r): rc=%s stdout=%r stderr=%r",
            STATS_TABLE_PREFIX, key, asic_id, rc, stdout,
            out.get("stderr", "")[:200],
        )
    return rc == 0 and stdout == "1"


def _appl_db_admin(duthost, port, asic_id):
    cmd = "sonic-db-cli {} APPL_DB HGET 'PORT_TABLE:{}' admin_status".format(_ns_arg(asic_id), port)
    return duthost.shell(cmd)["stdout"].strip().lower()


def _appl_db_oper(duthost, port, asic_id):
    cmd = "sonic-db-cli {} APPL_DB HGET 'PORT_TABLE:{}' oper_status".format(_ns_arg(asic_id), port)
    return duthost.shell(cmd)["stdout"].strip().lower()


def _pick_two_ports(duthost, tbinfo, asic_id):
    """Return two admin-up minigraph ports. Skip ports that are already down
    so the later `admin=='up'` sanity check yields a specific "not enough
    admin-up ports" failure instead of a generic per-port assertion.
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    all_ports = sorted(mg_facts["minigraph_ports"].keys())
    up_ports = [p for p in all_ports if _appl_db_admin(duthost, p, asic_id) == "up"]
    pytest_assert(
        len(up_ports) >= 2,
        "Need at least 2 admin-up minigraph ports; found {} up out of {}".format(
            len(up_ports), len(all_ports),
        ),
    )
    return up_ports[0], up_ports[1]


def _wait_for_orchagent_idle(duthost):
    pytest_assert(
        wait_until(
            ORCHAGENT_DRAIN_TIMEOUT, ORCHAGENT_DRAIN_POLL_INTERVAL, 0,
            check_orch_cpu_utilization, duthost, ORCHAGENT_IDLE_CPU_THRESHOLD,
        ),
        "orchagent CPU did not settle below {}% within {}s".format(
            ORCHAGENT_IDLE_CPU_THRESHOLD, ORCHAGENT_DRAIN_TIMEOUT,
        ),
    )


@pytest.fixture
def asic_id(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if duthost.sonichost.is_multi_asic:
        return enum_rand_one_frontend_asic_index
    return ''


@pytest.fixture(autouse=True)
def require_notification_consumer_stats(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, asic_id,
):
    """
    Skip the test when COUNTERS_DB doesn't expose the
    NOTIFICATION_CONSUMER_STATS:PortsOrch:port_state_change hash on the
    ASIC we're about to test.

    The publisher pushes on a 10 s SelectableTimer, so we poll for up to
    30 s before deciding the key is genuinely absent.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if not wait_until(30, 5, 0, lambda: stats_available(duthost, asic_id=asic_id)):
        pytest.skip(
            "DUT image does not publish {}:{} to COUNTERS_DB on asic {!r} - "
            "LRU dedup fix not present".format(
                STATS_TABLE_PREFIX, PORTSORCH_STATS_KEY, asic_id,
            )
        )


# Injection script copied onto the DUT and executed there. Uses redis-py against
# the per-asic unix socket so injection rate is bounded only by redis pipelining.
_INJECT_SCRIPT = r'''
import sys
import json
import redis

oid = sys.argv[1]
n = int(sys.argv[2])
sock = sys.argv[3]

DOWN = (
    r'["port_state_change","[{\"port_error_status\":\"SAI_PORT_ERROR_STATUS_CLEAR\",'
    r'\"port_id\":\"' + oid + r'\",'
    r'\"port_state\":\"SAI_PORT_OPER_STATUS_DOWN\"}]"]'
)
UP = (
    r'["port_state_change","[{\"port_error_status\":\"SAI_PORT_ERROR_STATUS_CLEAR\",'
    r'\"port_id\":\"' + oid + r'\",'
    r'\"port_state\":\"SAI_PORT_OPER_STATUS_UP\"}]"]'
)

r = redis.Redis(unix_socket_path=sock)
p = r.pipeline(transaction=False)
for _ in range(n):
    p.publish('NOTIFICATIONS', DOWN)
    p.publish('NOTIFICATIONS', UP)
p.execute()
'''


def _redis_socket(asic_id):
    if asic_id == '':
        return "/var/run/redis/redis.sock"
    return "/var/run/redis{}/redis.sock".format(asic_id)


def test_link_flap_dedup_synthetic(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, asic_id, loganalyzer,
):
    """
    Publish 2 * LINK_FLAP_COUNT byte-identical port_state_change
    messages on ASIC_DB NOTIFICATIONS with orchagent running. Verify
    from NOTIFICATION_CONSUMER_STATS that the LRU-dedup queue collapsed
    most of the burst and orchagent stayed alive.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Ignore the SWSS_LOG_NOTICE that PortsOrch emits for our synthetic OID
    # (see FAKE_PORT_OID comment); every non-deduped burst message triggers
    # one, and we do not want loganalyzer flagging those as unexpected.
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.append(
            r".*Got port state change for port id 0x10000deadbead.*does not exist.*",
        )

    # Skip if the DUT image doesn't have the redis-py dependency the inject
    # script needs. Cleaner than erroring inside the shell step.
    if duthost.shell(
        "python3 -c 'import redis'", module_ignore_errors=True,
    )["rc"] != 0:
        pytest.skip("python3-redis not installed on DUT; skipping synthetic inject test")

    sock = _redis_socket(asic_id)
    burst_msgs = 2 * LINK_FLAP_COUNT

    _wait_for_orchagent_idle(duthost)
    stats_before = get_consumer_stats(duthost, asic_id=asic_id)

    # Fail fast on wrong queue policy: we do not want to spend ~minutes
    # injecting 300 K messages against a Fifo consumer only to fail the
    # policy check afterwards.
    pytest_assert(
        stats_before["queue_policy"] == "LruDedup",
        "PortsOrch:port_state_change queue_policy is {!r} before burst; expected 'LruDedup'".format(
            stats_before["queue_policy"],
        ),
    )

    script_path = "/tmp/notif_dedup_inject.py"
    duthost.copy(content=_INJECT_SCRIPT, dest=script_path)
    try:
        duthost.shell(
            "python3 {script} {oid} {n} {sock}".format(
                script=script_path, oid=FAKE_PORT_OID, n=LINK_FLAP_COUNT, sock=sock,
            ),
        )

        _wait_for_orchagent_idle(duthost)

        pytest_assert(orchagent_is_running(duthost, asic_id=asic_id), "orchagent crashed during burst")

        # Poll the actual counter delta instead of sleeping one full publish
        # cycle unconditionally. On a healthy DUT the counters usually land
        # inside 10-15 s (10 s SelectableTimer + jitter); allow up to
        # 2 * STATS_PUBLISH_SEC before declaring the consumer wedged.
        received_target = int(burst_msgs * 0.9)

        def _received_reached_target():
            got = get_consumer_stats(duthost, asic_id=asic_id)
            return got["received"] - stats_before["received"] >= received_target

        pytest_assert(
            wait_until(2 * STATS_PUBLISH_SEC, 2, 0, _received_reached_target),
            "PortsOrch:port_state_change received did not advance by >= {} within {}s "
            "of the burst".format(received_target, 2 * STATS_PUBLISH_SEC),
        )

        stats_after = get_consumer_stats(duthost, asic_id=asic_id)
        received_delta = stats_after["received"] - stats_before["received"]
        pushed_delta = stats_after["lru_pushed"] - stats_before["lru_pushed"]
        hits_delta = stats_after["lru_dedup_hits"] - stats_before["lru_dedup_hits"]
        logger.info(
            "dedup stats: policy=%s received_delta=%d lru_pushed_delta=%d lru_dedup_hits_delta=%d",
            stats_after["queue_policy"], received_delta, pushed_delta, hits_delta,
        )
        # Burst has 2 distinct payloads, so > 50 % of messages must dedup.
        pytest_assert(
            hits_delta > burst_msgs * 0.5,
            "LruDedup consumer collapsed only {} of {} messages".format(hits_delta, burst_msgs),
        )
    finally:
        # Don't leave the inject script sitting on the DUT across runs.
        duthost.shell("rm -f {}".format(script_path), module_ignore_errors=True)


@pytest.mark.sanity_check(skip_sanity=True)
def test_link_flap_dedup_paused_orchagent(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, asic_id, tbinfo, bring_up_dut_interfaces,
):
    """
    Functional end-state verification.

    Pick two ports. Pause orchagent. Drive FUNCTIONAL_FLAP_ITERATIONS rounds
    of shut/noshut on both ports interleaved, then issue one final shutdown
    on port_a so its target end state is DOWN while port_b's target end
    state is UP. Resume orchagent and verify each port reaches its target
    in APPL_DB admin and oper status.

    This test is a functional smoke that the overall pipeline still reaches
    the correct end state across a long backlog of admin churn.

    ``sanity_check(skip_sanity=True)`` because port_a is transiently down
    across large parts of the test and BGP peers take a few seconds to
    reconverge after teardown restores it - the inter-test sanity_check
    would otherwise race that reconvergence window.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    port_a, port_b = _pick_two_ports(duthost, tbinfo, asic_id)
    ns_arg = _ns_arg(asic_id)

    pytest_assert(_appl_db_admin(duthost, port_a, asic_id) == "up",
                  "{} is not initially admin up".format(port_a))
    pytest_assert(_appl_db_admin(duthost, port_b, asic_id) == "up",
                  "{} is not initially admin up".format(port_b))

    duthost.control_process('orchagent', pause=True, namespace=asic_id)
    try:
        # Build and run the batched flap commands while orchagent is paused.
        cmds = []
        for _ in range(FUNCTIONAL_FLAP_ITERATIONS):
            cmds.append("sudo config interface {ns} shutdown {p}".format(ns=ns_arg, p=port_a))
            cmds.append("sudo config interface {ns} shutdown {p}".format(ns=ns_arg, p=port_b))
            cmds.append("sudo config interface {ns} startup {p}".format(ns=ns_arg, p=port_a))
            cmds.append("sudo config interface {ns} startup {p}".format(ns=ns_arg, p=port_b))
        # Final write: take port_a back DOWN. port_b stays UP from the loop's last 'startup'.
        cmds.append("sudo config interface {ns} shutdown {p}".format(ns=ns_arg, p=port_a))
        duthost.shell(" && ".join(cmds))

        # Resume orchagent and let it drain the paused-flap backlog.
        duthost.control_process('orchagent', pause=False, namespace=asic_id)
        _wait_for_orchagent_idle(duthost)

        # End-state assertions.
        admin_a = _appl_db_admin(duthost, port_a, asic_id)
        admin_b = _appl_db_admin(duthost, port_b, asic_id)
        pytest_assert(admin_a == "down",
                      "{} expected APPL_DB admin=down, got {!r}".format(port_a, admin_a))
        pytest_assert(admin_b == "up",
                      "{} expected APPL_DB admin=up,   got {!r}".format(port_b, admin_b))

        pytest_assert(
            wait_until(OPER_STATUS_TIMEOUT, 2, 0,
                       lambda: _appl_db_oper(duthost, port_a, asic_id) == "down"),
            "{} APPL_DB oper_status did not settle to down within {}s".format(port_a, OPER_STATUS_TIMEOUT),
        )
        pytest_assert(
            wait_until(OPER_STATUS_TIMEOUT, 2, 0,
                       lambda: _appl_db_oper(duthost, port_b, asic_id) == "up"),
            "{} APPL_DB oper_status did not settle to up within {}s".format(port_b, OPER_STATUS_TIMEOUT),
        )
        pytest_assert(orchagent_is_running(duthost, asic_id=asic_id), "orchagent crashed")
    finally:
        # Always resume orchagent and bring both ports back up, regardless of
        # which step failed. Both operations are idempotent - SIGCONT to a
        # running process is a no-op; `config interface startup` on an
        # already-admin-up port is a no-op - so cleanup is safe even if the
        # try block failed before or after these transitions.
        duthost.control_process('orchagent', pause=False, namespace=asic_id)
        duthost.shell(
            "sudo config interface {ns} startup {p}".format(ns=ns_arg, p=port_a),
            module_ignore_errors=True,
        )
        duthost.shell(
            "sudo config interface {ns} startup {p}".format(ns=ns_arg, p=port_b),
            module_ignore_errors=True,
        )
