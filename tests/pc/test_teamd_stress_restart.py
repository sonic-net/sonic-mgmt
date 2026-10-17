"""
Test: teamsyncd does not crash (segfault) during swss container restart
with multiple PortChannels configured.

Background:
    teamsyncd processes netlink events (RTM_NEWLINK, RTM_DELLINK) for LAG
    interfaces. A race condition exists where deferred RTM_DELLINK events
    leave stale TeamPortSync objects with active team file descriptors in
    the select loop. When the kernel sends port-change events on these
    dead interfaces, team_handle_events() calls rtnl_link_get_name() on
    a NULL netlink link object, causing a segfault.

    The fix processes RTM_DELLINK immediately (removeLag is cheap and safe)
    while still deferring RTM_NEWLINK (addLag needs validation).

Test Strategy:
    1. Create single-member PortChannels from freed VLAN member ports to
       maximize the number of team devices and netlink events
    2. Restart the swss container (which brings down both orchagent and
       teamd together, then brings them back up cleanly). This avoids
       orchagent crashes that occur when only teamd is restarted, because
       restarting teamd alone leaves orchagent with stale port state.
    3. Verify no new teamsyncd segfaults or core dumps appear after restart

    The number of restart iterations scales with the --completeness_level
    pytest option: debug=1, basic/confident=3, thorough=10.

Topology: t0
"""

import json
import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.common.plugins.test_completeness import CompletenessLevel

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.supported_completeness_level(
        CompletenessLevel.debug,
        CompletenessLevel.basic,
        CompletenessLevel.thorough,
    ),
]

# Number of swss restart iterations by completeness level.
# More iterations increase the chance of triggering the race condition.
RESTART_ITERATIONS_BY_LEVEL = {
    'debug': 1,       # Quick smoke test
    'basic': 3,       # Default CI level
    'confident': 3,   # Same as basic
    'thorough': 10,   # Extended stress for high confidence
}
DEFAULT_RESTART_ITERATIONS = 3

# Timeout (seconds) to wait for swss container + teamsyncd to come back
# after systemctl restart. swss takes longer than teamd alone because it
# includes orchagent, portsyncd, neighsyncd, etc.
SWSS_RESTART_TIMEOUT = 120

# PortChannel numbering starts at 200 to avoid conflict with existing
# uplink PortChannels (typically PortChannel101-104 in T0 topology).
PORT_CHANNEL_BASE = 200

# Maximum extra PortChannels to create. More LAGs = more netlink events
# during restart = higher chance of triggering the race. With swss restart
# (orchagent + teamd together), VS can handle at least 24 extra PCs.
MAX_EXTRA_PORTCHANNELS = 24


def get_free_ports(duthost):
    """Get ports eligible for PortChannel creation.

    Returns ports that are VLAN members but NOT already in a PortChannel
    and NOT used as routed uplinks. These can be safely removed from the
    VLAN and assigned to new PortChannels.

    Returns:
        tuple: (sorted list of free port names, full config dict)
    """
    cfg = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])

    # Ports already in a PortChannel — can't reuse these
    pc_member_ports = set()
    for member_key in cfg.get("PORTCHANNEL_MEMBER", {}):
        parts = member_key.split("|")
        if len(parts) == 2:
            pc_member_ports.add(parts[1])

    # VLAN member ports — these are our candidates
    vlan_member_ports = set()
    for member_key in cfg.get("VLAN_MEMBER", {}):
        parts = member_key.split("|")
        if len(parts) == 2:
            vlan_member_ports.add(parts[1])

    # Routed/uplink ports (have IP addresses) — must not touch these
    uplink_ports = set()
    for intf_key in cfg.get("INTERFACE", {}):
        port = intf_key.split("|")[0]
        if port.startswith("Ethernet"):
            uplink_ports.add(port)

    free_ports = vlan_member_ports - pc_member_ports - uplink_ports
    return sorted(free_ports), cfg


def is_swss_ready(duthost):
    """Check if swss and teamd containers are running and teamsyncd is alive.

    Despite the confusing naming, teamsyncd runs inside the **teamd**
    container (not swss). We need both swss (for orchagent) and teamd
    (for teamsyncd) to be up before declaring readiness.
    """
    # Check swss container is running (orchagent lives here)
    result = duthost.shell("docker ps -q -f name=swss -f status=running",
                           module_ignore_errors=True)
    if not result['stdout'].strip():
        return False
    # Check teamd container is running (teamsyncd lives here)
    result = duthost.shell("docker ps -q -f name=teamd -f status=running",
                           module_ignore_errors=True)
    if not result['stdout'].strip():
        return False
    # Verify teamsyncd process is alive inside the teamd container
    result = duthost.shell("docker exec teamd pgrep -x teamsyncd",
                           module_ignore_errors=True)
    return result['rc'] == 0


def get_teamsyncd_crash_count(duthost):
    """Count teamsyncd segfault entries in syslog.

    Searches for kernel segfault messages, SIGSEGV signals, and signal 11
    references associated with the teamsyncd process.
    """
    result = duthost.shell(
        "grep -c 'teamsyncd.*segfault\\|teamsyncd.*SIGSEGV\\|teamsyncd.*signal 11' "
        "/var/log/syslog 2>/dev/null || echo 0",
        module_ignore_errors=True
    )
    return int(result['stdout'].strip())


def get_core_files(duthost, pattern="core.teamsyncd.*"):
    """List core dump files matching the given glob pattern."""
    result = duthost.shell(
        "ls /var/core/{} 2>/dev/null".format(pattern),
        module_ignore_errors=True
    )
    if result['rc'] != 0 or not result['stdout'].strip():
        return []
    return result['stdout'].strip().split('\n')


@pytest.fixture(scope="module")
def backup_and_restore_config(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Save config_db.json before test and restore it after.

    The test modifies VLAN membership, ACL tables, and PortChannel config.
    This fixture ensures the DUT is returned to its original state via
    config reload regardless of test outcome.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.teamd_test_backup")
    logger.info("Backed up config_db.json")

    yield duthost

    logger.info("Waiting for critical processes before config restore")
    wait_critical_processes(duthost)
    logger.info("Restoring original config_db.json")
    duthost.shell("cp /etc/sonic/config_db.json.teamd_test_backup /etc/sonic/config_db.json")
    config_reload(duthost, config_source='config_db', safe_reload=True, wait=120)
    duthost.shell("rm -f /etc/sonic/config_db.json.teamd_test_backup")


def test_teamd_stress_restart(backup_and_restore_config, request,
                              completeness_level=None):
    """Verify teamsyncd survives repeated swss restarts without crashing.

    This test targets a specific race condition in teamsyncd's netlink event
    handling. The crash occurs when:
      1. RTM_DELLINK for a LAG is deferred (queued for later processing)
      2. The TeamPortSync object remains alive with its team fd in select()
      3. The kernel sends port-change events on the now-dead interface
      4. team_handle_events() dereferences a NULL link pointer → SIGSEGV

    We restart swss (not just teamd) to avoid a secondary issue where
    orchagent crashes from stale port state when teamd restarts independently.
    Restarting swss brings down orchagent + teamd together, so they
    reinitialize cleanly in sync.
    """
    duthost = backup_and_restore_config

    # --- Determine iteration count from completeness level ---
    level = completeness_level or 'basic'
    if hasattr(request, 'config'):
        specified = request.config.getoption("--completeness_level", default=None)
        if specified:
            level = specified
    restart_iterations = RESTART_ITERATIONS_BY_LEVEL.get(level, DEFAULT_RESTART_ITERATIONS)
    logger.info("Completeness level: %s, restart iterations: %d", level, restart_iterations)

    # --- Record baseline crash state ---
    # We compare against this after the test to detect NEW crashes only,
    # ignoring any pre-existing segfault entries from prior test runs.
    pre_segfault_count = get_teamsyncd_crash_count(duthost)
    pre_cores = get_core_files(duthost)
    logger.info("Pre-test baseline: %d segfaults in syslog, %d teamsyncd cores",
                pre_segfault_count, len(pre_cores))

    # --- Step 1: Identify free ports for PortChannel creation ---
    free_ports, cfg = get_free_ports(duthost)
    logger.info("Found %d free ports (showing first 5): %s", len(free_ports), free_ports[:5])
    pytest_assert(len(free_ports) >= 4,
                  "Need at least 4 free ports for meaningful test, found {}".format(len(free_ports)))
    # Cap the number of PCs to avoid overwhelming orchagent on VS
    free_ports = free_ports[:MAX_EXTRA_PORTCHANNELS]

    # --- Step 2: Remove VLAN membership for ports we'll use ---
    # Ports must be removed from VLANs before they can join a PortChannel.
    for member_key in cfg.get("VLAN_MEMBER", {}):
        parts = member_key.split("|")
        if len(parts) == 2:
            vlan_name, port = parts
            if port in free_ports:
                vid = vlan_name.replace("Vlan", "")
                duthost.shell("config vlan member del {} {}".format(vid, port),
                              module_ignore_errors=True)
    logger.info("Removed VLAN members for %d ports", len(free_ports))

    # --- Step 3: Remove ACL tables that bind to our ports ---
    # ACL tables like EVERFLOW/EVERFLOWV6 bind to all Ethernet ports.
    # Ports bound to an ACL table cannot be added to a PortChannel.
    # We remove the conflicting tables; they'll be restored by config
    # reload in teardown.
    for tbl_key, tbl_val in cfg.get("ACL_TABLE", {}).items():
        if isinstance(tbl_val, dict):
            acl_ports = tbl_val.get("ports", [])
            if isinstance(acl_ports, list) and any(p in free_ports for p in acl_ports):
                duthost.shell("sudo config acl remove table {}".format(tbl_key),
                              module_ignore_errors=True)
                logger.info("Removed ACL table %s (bound to test ports)", tbl_key)

    # --- Step 4: Create single-member PortChannels ---
    # Each PortChannel creates a team device + TeamPortSync object in teamsyncd.
    # More team devices = more netlink events during restart = higher chance
    # of hitting the race condition.
    created_pcs = []
    for i, port in enumerate(free_ports):
        pc_id = PORT_CHANNEL_BASE + i
        pc_name = "PortChannel{}".format(pc_id)
        duthost.shell("config portchannel add {}".format(pc_name))
        duthost.shell("config portchannel member add {} {}".format(pc_name, port))
        created_pcs.append(pc_name)
    logger.info("Created %d PortChannels: %s", len(created_pcs), created_pcs)

    # Save config so swss picks up the new PortChannels on restart
    duthost.shell("config save -y")
    # Allow orchagent to finish processing the new PortChannel config
    time.sleep(10)

    pytest_assert(is_swss_ready(duthost),
                  "swss/teamsyncd not running after PortChannel creation — "
                  "cannot proceed with restart test")

    # --- Step 5: Restart swss and check for teamsyncd crashes ---
    # Each restart triggers:
    #   - RTM_DELLINK for all team devices (PortChannels being torn down)
    #   - RTM_NEWLINK for all team devices (PortChannels being recreated)
    # The bug causes a segfault when DELLINKs are deferred but the team
    # fd is still in the select loop.
    logger.info("Starting %d swss restart iterations", restart_iterations)
    for iteration in range(restart_iterations):
        logger.info("=== Restart iteration %d/%d ===", iteration + 1, restart_iterations)

        # Clear any systemd failure state from previous iterations.
        # Without this, systemd's StartLimitBurst rate-limiter can refuse
        # to start swss after repeated crash-restarts, masking the actual
        # segfault we're trying to detect.
        duthost.shell("sudo systemctl reset-failed swss.service",
                      module_ignore_errors=True)

        # Restart swss container. This cleanly shuts down orchagent + teamd
        # + teamsyncd together, then brings them all back up.
        duthost.shell("sudo systemctl restart swss")

        # Wait for swss to come back up with teamsyncd running
        if not wait_until(SWSS_RESTART_TIMEOUT, 5, 10, is_swss_ready, duthost):
            # If swss didn't come back, check if teamsyncd crashed
            post_segfaults = get_teamsyncd_crash_count(duthost)
            post_cores = get_core_files(duthost)
            pytest.fail(
                "swss/teamsyncd failed to restart on iteration {}. "
                "Segfaults: {} (was {}). New cores: {}".format(
                    iteration + 1,
                    post_segfaults, pre_segfault_count,
                    [c for c in post_cores if c not in pre_cores]
                )
            )

        # Wait for ALL critical services (containers) to be running.
        # Restarting swss cascades to teamd, syncd, bgp, etc.
        # We must wait for all of them, not just swss+teamd.
        pytest_assert(
            wait_until(SWSS_RESTART_TIMEOUT, 10, 0, duthost.critical_services_fully_started),
            "Not all critical services came back on iteration {}".format(iteration + 1)
        )
        # Then wait for all critical processes inside those containers
        wait_critical_processes(duthost)

    # --- Step 6: Verify no new teamsyncd crashes ---
    post_segfault_count = get_teamsyncd_crash_count(duthost)
    post_cores = get_core_files(duthost)
    new_segfaults = post_segfault_count - pre_segfault_count
    new_cores = [c for c in post_cores if c not in pre_cores]

    logger.info("Post-test results: %d new segfaults, new cores: %s",
                new_segfaults, new_cores)

    pytest_assert(new_segfaults == 0,
                  "teamsyncd crashed {} time(s) during {} swss restart iterations. "
                  "New core dumps: {}".format(new_segfaults, restart_iterations, new_cores))

    logger.info("PASSED: teamsyncd survived %d swss restart iterations with %d extra PortChannels",
                restart_iterations, len(created_pcs))
