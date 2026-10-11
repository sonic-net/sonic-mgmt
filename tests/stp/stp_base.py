# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Shared STP helpers, mode-parameterized on `stp_mode` ("pvst" | "mst").

Per the refactor goal, all common logic lives here as module-level functions
that take `mode` as a parameter, so both the test classes and `conftest.py`
fixtures reuse them. `StpTestBase` is a thin convenience wrapper that binds
`mode = self.STP_MODE`; `test_pvst.py` / `test_mstp.py` subclass it.
"""
import contextlib
import logging
import shlex
import threading

import pytest

from tests.common.devices.ptf import PTFHost
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner
from tests.stp import stp_utils

logger = logging.getLogger(__name__)

PVST = "pvst"
MST = "mst"

PTF_CLASS = {
    PVST: "pvst_bpdu_test.PvstBpduTest",
    MST: "mstp_bpdu_test.MstpBpduTest",
}


# ============================ module-level helpers ==========================
# ---- STP feature / container ----
def stp_container_up(duthost):
    # NOTE: use is_container_running() (docker ps -f name=stp), not
    # `docker ps --format '{{.Names}}'` -- ansible renders the un-escaped
    # `{{.Names}}` as an (empty) Jinja2 expression, so that form always reports
    # the container as down even when it is up.
    return duthost.is_container_running("stp")


def wait_featured_ready(duthost, timeout=90):
    """`featured` is the daemon that actually starts/stops feature containers in
    response to FEATURE|<name> state changes. `config reload` stops
    featured.timer and SIGTERMs featured (and hostcfgd), then it is restarted via
    its timer -- a `config feature state stp enabled` issued while it is down is a
    no-op until it returns, so the container never starts. Gate on featured being
    active before toggling feature state."""
    return wait_until(timeout, 2, 0, lambda: duthost.shell(
        "systemctl is-active featured.service",
        module_ignore_errors=True).get("stdout", "").strip() == "active")


def ensure_stp_feature_up(duthost, timeout=120):
    """Enable the STP feature and make sure its container is running, resilient to
    the post-`config reload` window. A reload restores FEATURE|stp to the image
    default (disabled), masks/stops the stp container, and bounces featured; a
    plain enable during that window is dropped. So wait for featured, enable, and
    if the container still has not come up, force it with an explicit
    unmask + start. Returns True once the container is up."""
    wait_featured_ready(duthost)
    duthost.shell("sudo config feature state stp enabled", module_ignore_errors=True)
    if wait_until(timeout, 3, 0, lambda: stp_container_up(duthost)):
        return True
    # featured did not bring it up (masked / still bouncing): drive it directly.
    duthost.shell("sudo systemctl unmask stp.service", module_ignore_errors=True)
    duthost.shell("sudo systemctl start stp.service", module_ignore_errors=True)
    return wait_until(timeout, 3, 0, lambda: stp_container_up(duthost))


# ---- leave CONFIG_DB as the module found it ----
# A disable keeps the STP configuration, so turning spanning tree off at the end
# of a test is not enough to put CONFIG_DB back. These are the keys the suite
# can create or change.
STP_CONFIG_PATTERNS = ("STP|*", "STP_*", "FEATURE|stp", "LOGGER|stpmgrd")


def snapshot_stp_config(duthost):
    """Every STP-owned CONFIG_DB row, as {key: {field: value}}."""
    keys = set()
    for pattern in STP_CONFIG_PATTERNS:
        out = duthost.shell("redis-cli -n 4 --raw keys '{}'".format(pattern),
                            module_ignore_errors=True).get("stdout_lines", [])
        keys.update(k for k in out if k)
    return {k: stp_utils._hgetall(duthost, k, dbnum=4) for k in keys}


def restore_stp_config(duthost, snapshot):
    """Put the STP rows, the feature state and the stpmgrd logger row back as they were."""
    duthost.shell("config spanning-tree disable mst", module_ignore_errors=True)
    duthost.shell("config spanning-tree disable pvst", module_ignore_errors=True)
    state = snapshot.get("FEATURE|stp", {}).get("state")
    if state:
        duthost.shell("sudo config feature state stp {}".format(state), module_ignore_errors=True)
    now = snapshot_stp_config(duthost)
    cmds = []
    for key in now:
        if key not in snapshot or now[key] != snapshot[key]:
            cmds.append("redis-cli -n 4 del {} >/dev/null".format(shlex.quote(key)))
    for key, fields in snapshot.items():
        if fields and now.get(key) != fields:
            args = " ".join("{} {}".format(shlex.quote(f), shlex.quote(v)) for f, v in fields.items())
            cmds.append("redis-cli -n 4 hset {} {} >/dev/null".format(shlex.quote(key), args))
    if cmds:
        duthost.shell("; ".join(cmds))
    after = snapshot_stp_config(duthost)
    return sorted(k for k in set(after) | set(snapshot) if after.get(k) != snapshot.get(k))


# ---- global mode ----
def enable_stp(duthost, mode):
    duthost.shell("config spanning-tree enable {}".format(mode), module_ignore_errors=True)


def disable_stp(duthost, mode):
    duthost.shell("config spanning-tree disable {}".format(mode), module_ignore_errors=True)


def bounce_stp(duthost, mode):
    disable_stp(duthost, mode)
    enable_stp(duthost, mode)


# The daemon's operational tables in APPL_DB, per mode. A disable must leave
# none of them behind, whatever mode was running.
TREE_KEY_PATTERNS = {
    PVST: ("_STP_VLAN_TABLE:*", "_STP_VLAN_PORT_TABLE:*"),
    MST: ("_STP_MST_INST_TABLE:*", "_STP_MST_PORT_TABLE:*"),
}


def tree_keys(duthost, mode=None):
    """APPL_DB keys the daemon holds for `mode`, or for both modes when None."""
    modes = (mode,) if mode else (PVST, MST)
    keys = []
    for m in modes:
        for pattern in TREE_KEY_PATTERNS[m]:
            out = duthost.shell("redis-cli -n 0 keys '{}'".format(pattern),
                                module_ignore_errors=True).get("stdout", "")
            keys += [k.strip() for k in out.splitlines() if k.strip()]
    return keys


def wait_tree_cleared(duthost, mode=None, timeout=30):
    return wait_until(timeout, 2, 0, lambda: not tree_keys(duthost, mode))


def config_validates(duthost):
    """Run the running config through the YANG validation every generic config
    update performs, by applying an empty patch. Returns (ok, output)."""
    patch = "/tmp/stp_empty_patch.json"
    duthost.shell("echo '[]' > {}".format(patch), module_ignore_errors=True)
    res = duthost.shell("config apply-patch {}".format(patch), module_ignore_errors=True)
    out = (res.get("stdout", "") + res.get("stderr", "")).strip()
    return res.get("rc", 1) == 0, out


# ---- MST region / instance mapping (no-op for PVST) ----
def _region_config(duthost):
    """(name, revision) as CONFIG_DB currently holds them."""
    out = duthost.shell("redis-cli -n 4 hmget 'STP_MST|GLOBAL' name revision",
                        module_ignore_errors=True).get("stdout_lines", [])
    vals = [v.strip() for v in out] + ["", ""]
    return vals[0], vals[1]


def _region_applied(duthost, region_name, revision):
    name, rev = _region_config(duthost)
    return name == str(region_name) and rev == str(revision)


def setup_region(duthost, mode, region_name, revision, instance_vlan_map):
    """`instance_vlan_map`: {instance_id: [vids]}."""
    if mode != MST:
        return
    # A dropped region write leaves the DUT in a different region from the BPDUs
    # the PTF sends. That looks like a protocol bug, not a setup failure, so let
    # these raise and confirm they landed.
    duthost.shell("config spanning-tree mst region-name {}".format(region_name))
    duthost.shell("config spanning-tree mst revision {}".format(revision))
    pytest_assert(
        wait_until(15, 2, 0, lambda: _region_applied(duthost, region_name, revision)),
        "MST region did not apply: wanted {}/{}, CONFIG_DB has {}/{}".format(
            region_name, revision, *_region_config(duthost)))
    # Instances beyond the CIST are not supported on every build; a failure here
    # must not abort the CIST tests.
    for inst, vids in instance_vlan_map.items():
        for vid in vids:
            duthost.shell("config spanning-tree mst instance {} vlan add {}".format(inst, vid),
                          module_ignore_errors=True)


def delete_mst_instance(duthost, instance):
    """`config spanning-tree mst instance <id> delete` where the image has it;
    on an older image, drop the CONFIG_DB row directly."""
    res = duthost.shell("config spanning-tree mst instance {} delete".format(instance),
                        module_ignore_errors=True)
    if res.get("rc", 1) != 0:
        duthost.shell("redis-cli -n 4 del 'STP_MST_INST|{}'".format(instance), module_ignore_errors=True)


def teardown_region(duthost, mode, instance_vlan_map):
    if mode != MST:
        return
    for inst, vids in instance_vlan_map.items():
        for vid in vids:
            duthost.shell("config spanning-tree mst instance {} vlan del {}".format(inst, vid),
                          module_ignore_errors=True)


# ---- per-scope tunables (PVST scope=vlan_id, MST scope=instance_id) ----
def set_bridge_priority(duthost, mode, scope, priority):
    if mode == MST:
        duthost.shell("config spanning-tree mst instance {} priority {}".format(scope, priority),
                      module_ignore_errors=True)
    else:
        duthost.shell("config spanning-tree vlan priority {} {}".format(scope, priority),
                      module_ignore_errors=True)


def set_port_cost(duthost, mode, scope, port, cost):
    if mode == MST:
        duthost.shell("config spanning-tree mst instance {} interface {} cost {}".format(scope, port, cost),
                      module_ignore_errors=True)
    else:
        duthost.shell("config spanning-tree interface cost {} {}".format(port, cost),
                      module_ignore_errors=True)


def set_port_priority(duthost, mode, scope, port, priority):
    if mode == MST:
        duthost.shell("config spanning-tree mst instance {} interface {} priority {}".format(scope, port, priority),
                      module_ignore_errors=True)
    else:
        duthost.shell("config spanning-tree vlan interface priority {} {} {}".format(scope, port, priority),
                      module_ignore_errors=True)


def set_timers(duthost, mode, scope, hello=None, max_age=None, fwd_delay=None):
    """PVST timers are per-VLAN (`... vlan hello <vid> <v>`); MST timers are
    global to the switch (`... hello <v>`). `scope` is the VLAN id for PVST and
    is ignored for MST."""
    def _set(pvst_cmd, mst_cmd, val):
        if val is None:
            return
        duthost.shell((mst_cmd if mode == MST else pvst_cmd).format(scope=scope, v=val),
                      module_ignore_errors=True)
    _set("config spanning-tree vlan hello {scope} {v}", "config spanning-tree hello {v}", hello)
    _set("config spanning-tree vlan max_age {scope} {v}", "config spanning-tree max_age {v}", max_age)
    _set("config spanning-tree vlan forward_delay {scope} {v}",
         "config spanning-tree forward_delay {v}", fwd_delay)


# ---- PTF ----
def run_bpdu(ptfhost, duthost, mode, scenario, params, log_file):
    """Invoke the mode's PTF BPDU test with `scenario`/`params`. Fills in the
    common hostname/test_scenarios/kvm_support keys."""
    merged = {"hostname": duthost.hostname, "test_scenarios": scenario, "kvm_support": True}
    merged.update(params)
    ptf_runner(ptfhost, "ptftests", PTF_CLASS[mode], platform_dir="ptftests",
               params=merged, log_file=log_file, is_python3=True)


# ================================ class wrapper =============================
class StpTestBase:
    """Convenience wrapper binding `mode = self.STP_MODE`. Subclasses set STP_MODE."""

    STP_MODE = None

    @pytest.fixture(autouse=True)
    def _ptf_senders(self, ansible_adhoc, ptfhost):
        """A background sender needs its own PTF host object. The ansible
        dispatcher behind `ptfhost` resolves a module name and then runs it
        in two steps with shared state, so two threads using one object can
        run each other's module with their own arguments; that surfaced as a
        log-collection `archive` call being run as `fetch`."""
        self._new_ptfhost = lambda: PTFHost(ansible_adhoc, ptfhost.hostname,
                                            ptfhost.duthost, ptfhost.tbinfo)

    # Shared tunables (mirror the original PVST test).
    BRIDGE_PRIORITY = 8192
    PORT_COST = 1000
    CUSTOM_HELLO_TIME = 5
    CUSTOM_MAX_AGE = 25
    CUSTOM_FORWARD_DELAY = 20
    PKT_CAPTURE_DURATION = 10

    # global mode
    def enable_stp(self, duthost):
        enable_stp(duthost, self.STP_MODE)

    def disable_stp(self, duthost):
        disable_stp(duthost, self.STP_MODE)

    def bounce_stp(self, duthost):
        bounce_stp(duthost, self.STP_MODE)

    # region / tunables
    def setup_region(self, duthost, region_name, revision, instance_vlan_map):
        setup_region(duthost, self.STP_MODE, region_name, revision, instance_vlan_map)

    def set_bridge_priority(self, duthost, scope, priority):
        set_bridge_priority(duthost, self.STP_MODE, scope, priority)

    def set_port_cost(self, duthost, scope, port, cost):
        set_port_cost(duthost, self.STP_MODE, scope, port, cost)

    def set_port_priority(self, duthost, scope, port, priority):
        set_port_priority(duthost, self.STP_MODE, scope, port, priority)

    def set_timers(self, duthost, scope, hello=None, max_age=None, fwd_delay=None):
        set_timers(duthost, self.STP_MODE, scope, hello, max_age, fwd_delay)

    # DB verify
    def get_bridge_data(self, duthost, scope):
        return stp_utils.get_bridge_data(duthost, self.STP_MODE, scope)

    def get_port_state(self, duthost, scope, port):
        return stp_utils.get_port_state(duthost, self.STP_MODE, scope, port)

    def get_port_cost(self, duthost, scope, port):
        return stp_utils.get_port_cost(duthost, self.STP_MODE, scope, port)

    def get_root_port(self, duthost, scope):
        return stp_utils.get_root_port(duthost, self.STP_MODE, scope)

    def verify_stp_state(self, duthost, scope, ports, expected_state, **kw):
        stp_utils.verify_stp_state(duthost, self.STP_MODE, scope, ports, expected_state, **kw)

    def is_self_root(self, duthost, scope):
        return stp_utils.is_self_root(duthost, self.STP_MODE, scope)

    def wait_self_root(self, duthost, scope, timeout=60):
        return wait_until(timeout, 2, 0, lambda: self.is_self_root(duthost, scope))

    def wait_root_port(self, duthost, scope, expected, timeout=60):
        """Wait for the elected root port to settle on `expected`.

        Losing self-root and electing the new root port are not atomic:
        `is_self_root` goes false the instant `root_port` stops reading "Root",
        but the final port may not be recorded yet. A one-shot read straight
        after `wait_until(... not is_self_root ...)` races that window and fails
        intermittently with "root port is not <X>".

        Reads the bridge row directly rather than via `get_root_port()`, whose
        internal assert would fire inside the poll before the row is populated.
        """
        return wait_until(
            timeout, 2, 0,
            lambda: stp_utils.get_bridge_data(
                duthost, self.STP_MODE, scope).get("root_port") == expected)

    # --- config / enrolment-test helpers (shared by test_*_config.py) --------
    # `scope` is CIST instance 0 for MST and the VLAN id for PVST.
    @staticmethod
    def stp_container_up(duthost):
        return stp_container_up(duthost)

    def ensure_stp_up(self, duthost):
        """Guard against the stp.service flakiness: if the container has exited
        (it does not reliably auto-restart after config/feature churn), unmask +
        start it and wait, so the APPL_DB enrolment rows are authoritative."""
        if not stp_container_up(duthost):
            duthost.shell("sudo systemctl unmask stp.service", module_ignore_errors=True)
            duthost.shell("sudo systemctl start stp.service", module_ignore_errors=True)
            wait_until(60, 3, 0, lambda: stp_container_up(duthost))

    def is_enrolled(self, duthost, scope, intf):
        """True once `intf` has an STP port row for `scope` (STP is running on it)."""
        return stp_utils.get_port_data(duthost, self.STP_MODE, scope, intf) != {}

    def wait_enrolled(self, duthost, scope, intf, timeout=90):
        self.ensure_stp_up(duthost)
        return wait_until(timeout, 3, 0, lambda: self.is_enrolled(duthost, scope, intf))

    def wait_unenrolled(self, duthost, scope, intf, timeout=60):
        self.ensure_stp_up(duthost)
        return wait_until(timeout, 2, 0, lambda: not self.is_enrolled(duthost, scope, intf))

    def assert_forwarding_if_up(self, duthost, scope, intf):
        """Verify FORWARDING for an enrolled interface, but only when it is
        oper-up (a down link legitimately sits in the mode's non-forwarding
        state)."""
        if stp_utils.get_port_oper_state(duthost, intf).lower() != "up":
            state = stp_utils.get_port_data(duthost, self.STP_MODE, scope, intf).get("port_state")
            logger.info("%s is not oper-up; state=%r (skipping FORWARDING check)", intf, state)
            return
        self.verify_stp_state(duthost, scope, [intf], "FORWARDING")

    def stp_feature(self, duthost, state):
        duthost.shell("config feature state stp {}".format(state), module_ignore_errors=True)

    def enable_feature_and_wait(self, duthost):
        pytest_assert(ensure_stp_feature_up(duthost),
                      "stp container did not come up after enabling the feature")

    def disable_feature_and_wait(self, duthost):
        self.stp_feature(duthost, "disabled")
        pytest_assert(wait_until(60, 3, 0, lambda: not self.stp_container_up(duthost)),
                      "stp container did not go down after disabling the feature")

    def assert_mode_cleared(self, duthost, timeout=30):
        """After disabling STP, STP|GLOBAL mode clears in CONFIG_DB."""
        pytest_assert(
            wait_until(timeout, 2, 0, lambda: duthost.shell(
                "redis-cli -n 4 hget 'STP|GLOBAL' mode",
                module_ignore_errors=True).get("stdout", "").strip() != self.STP_MODE),
            "STP|GLOBAL mode still '{}' after disabling STP".format(self.STP_MODE))

    def assert_tree_cleared(self, duthost, timeout=30):
        """After disabling STP the daemon has torn its tree down: no APPL_DB
        row of either mode is left, so nothing reads a stale FORWARDING."""
        pytest_assert(wait_tree_cleared(duthost, timeout=timeout),
                      "APPL_DB still holds STP rows {}s after the disable: {}".format(
                          timeout, tree_keys(duthost)))

    def assert_config_validates(self, duthost):
        ok, out = config_validates(duthost)
        pytest_assert(ok, "the running config no longer passes YANG validation: {}".format(out))

    def bpdu_guard_tripped(self, duthost, scope, port):
        """A bpdu-guard-tripped port is out of forwarding -- reported as BPDU-DIS
        / DISCARDING / BLOCKING -- or err-disabled (oper-down)."""
        state = stp_utils.get_port_data(duthost, self.STP_MODE, scope, port).get("port_state", "")
        return (state in ("BPDU-DIS", "DISCARDING", "BLOCKING")
                or stp_utils.get_port_oper_state(duthost, port).lower() == "down")

    # PTF
    def run_bpdu(self, ptfhost, duthost, scenario, params, log_file):
        run_bpdu(ptfhost, duthost, self.STP_MODE, scenario, params, log_file)

    # One PTF invocation of a sender stream: 30 BPDUs at the 2 s default hello
    # is a minute of steady neighbour, longer than any wait in these tests, so
    # the DUT never sees the gap between two PTF runs.
    STREAM_COUNT = 30
    STREAM_INTERVAL = 2

    @contextlib.contextmanager
    def bpdu_streams(self, ptfhost, duthost, streams, scenario="config"):
        """Run several BPDU senders at once, one thread per (params, log_file)
        in `streams`, each sending at hello cadence until the block exits.

        Two neighbours that must both be heard, such as one per port when the
        test is about which port wins, cannot share a thread: a single sender
        alternating between them leaves each port silent for a whole PTF run,
        longer than the daemon holds a neighbour's information, so the roles
        flap and age out instead of settling.
        """
        stop = [False]

        def _loop(host, params, log_file):
            merged = dict(params, send_count=self.STREAM_COUNT, send_interval=self.STREAM_INTERVAL)
            while not stop[0]:
                try:
                    self.run_bpdu(host, duthost, scenario, merged, log_file)
                except Exception as e:   # noqa: BLE001 -- a dropped send must not kill the test
                    logger.warning("BPDU stream %s failed: %s", log_file, e)

        threads = [threading.Thread(target=_loop, args=(self._new_ptfhost(), p, lf), daemon=True)
                   for p, lf in streams]
        for t in threads:
            t.start()
        try:
            yield
        finally:
            stop[0] = True
            for t in threads:
                t.join(timeout=self.STREAM_COUNT * self.STREAM_INTERVAL + 30)
                if t.is_alive():
                    logger.warning("BPDU stream still alive after its send window; "
                                   "its last frames may leak into the next test")

    @contextlib.contextmanager
    def periodic_superior_sender(self, ptfhost, duthost, params, log_file, scenario="config"):
        """Background thread that repeatedly injects a superior BPDU (scenario
        `config`) until the `with` block exits — mirrors the PVST tests' periodic
        sender so the DUT keeps yielding root while assertions run."""
        stop = [False]
        host = self._new_ptfhost()

        def _loop():
            while not stop[0]:
                try:
                    self.run_bpdu(host, duthost, scenario, params, log_file)
                except Exception as e:   # noqa: BLE001 — a dropped send must not kill the test
                    logger.warning("periodic superior BPDU send failed: %s", e)

        thread = threading.Thread(target=_loop, daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop[0] = True
            # Each loop iteration is a blocking PTF invocation that can run for
            # tens of seconds; a short join lets the thread outlive its test and
            # keep injecting into the next one, which shows up as order-dependent
            # failures. Wait the send out.
            thread.join(timeout=60)
            if thread.is_alive():
                logger.warning("periodic superior sender still alive after 60s; "
                               "its last send may leak into the next test")
