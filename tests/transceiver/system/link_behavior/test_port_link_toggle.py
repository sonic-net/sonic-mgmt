"""System / Link Behavior - grouped per-lane shutdown + startup validation.

Implements TC1 (Port Shutdown Validation) and TC2 (Port Startup Validation)
from ``docs/testplan/transceiver/system_test_plan.md``.

Rather than toggling all 96 ports one-by-one (slow), the front ports are
split into two groups - ``local_group`` and ``remote_group`` - using LLDP,
and each group is toggled one *lane* (subport index) at a time across every
cage in the group simultaneously::

    for group in (local_group, remote_group):
        for lane i in 0 .. (subports_per_cage - 1):
            # the i-th subport of every cage, e.g. Ethernet0,Ethernet64,...
            ONE `config interface shutdown <comma-list>`  (per ASIC namespace)
            ONE `show interface description` poll -> all oper-down within 5s
            ONE `config interface startup  <comma-list>`  (per ASIC namespace)
            ONE `show interface description` poll -> all oper-up within 60s
            Standard Port Recovery and Verification for the lane's ports
                (LLDP / CMIS / SI / health)

So an 8x100G fabric needs 8 shut/no-shut rounds per group (16 total) instead
of 96 sequential single-port cycles, and each round is a single shutdown
command + single poll + single startup command + single poll (not one per
port).

Why split into local / remote groups (LLDP-driven)
--------------------------------------------------
Every front port has an LLDP neighbor. Using each port's
``APPL_DB LLDP_ENTRY_TABLE:<port>``:

  * ``lldp_rem_chassis_id == LLDP_LOC_CHASSIS.lldp_loc_chassis_id``
    -> the neighbor is on THIS switch (a self-loop). The two ends of that
    link are paired; the lower-numbered cage goes to ``local_group`` and its
    partner to ``remote_group``. Toggling one group leaves every link's
    partner admin-up, so the link re-converges cleanly (and the LLDP step of
    Standard Recovery stays meaningful) instead of both ends going down at
    once.
  * a different ``lldp_rem_chassis_id`` -> the neighbor is on a DIFFERENT
    switch. We do not touch the other switch; that cage's local side is
    tested under ``local_group`` and its off-switch partner is left alone.

Requirements enforced
----------------------
  1. All front ports must be the same breakout mode (e.g. all 8x100G, or all
     2x400G, or all 1x800G). A mixed fabric is a hard ``pytest.fail``.
  2. Ports are split into ``local_group`` / ``remote_group`` as above; an
     off-switch partner is never toggled.

Failure handling: failures are collected across every (port, step) pair and
reported in a single ``pytest.fail`` at the end, so one run surfaces every
misbehaving port. ``startup`` is always issued after ``shutdown`` so a port is
never left admin-down because a verification step failed mid-loop.
"""
import logging

import pytest

from tests.common.platform.interface_utils import get_physical_port_indices
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers, db_helpers
from tests.transceiver.common.verification import (
    list_core_files,
    standard_port_recovery_and_verification,
    wait_for_ports_oper_state,
)

logger = logging.getLogger(__name__)


def _eth_index(port):
    """Numeric sort key for an ``EthernetN`` name (``"Ethernet80"`` -> 80)."""
    digits = "".join(c for c in port if c.isdigit())
    return int(digits) if digits else 0


def _sys_attr(port_attrs, name, default):
    return port_attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get(name, default)


def _port_namespace(duthost, port):
    """Return the ASIC network namespace owning ``port``.

    Resolved the same way as the EEPROM tests
    (``tests/transceiver/eeprom/test_eeprom_content.py``): map the port to its
    ASIC instance, then to that ASIC's namespace.  On a single-ASIC DUT this is
    ``""``, so ``cli_helpers`` emits no ``-n`` flag and the command stays
    ``config interface shutdown <port>``.
    """
    return duthost.get_namespace_from_asic_id(
        duthost.get_port_asic_instance(port).asic_index
    )


def _startup_port(duthost, port):
    """Single-port startup, used only by the module teardown safety net."""
    err = cli_helpers.config_interface_startup(
        duthost, port, namespace=_port_namespace(duthost, port)
    )
    if err:
        logger.warning("config interface startup %s reported: %s", port, err)


def _group_by_namespace(ports, port_ns):
    """Return ``{namespace: [ports]}`` using the precomputed ``port_ns`` map.

    On a single-ASIC DUT every port maps to ``""``, so the whole batch lands in
    one group and is toggled with a single ``config interface`` command. On a
    multi-ASIC DUT a lane spanning ASICs becomes one command per namespace.
    """
    groups = {}
    for port in ports:
        groups.setdefault(port_ns[port], []).append(port)
    return groups


def _toggle_ports(duthost, ports, port_ns, action):
    """Issue ``config interface <action>`` for ``ports`` in one command per ASIC
    namespace (comma-separated list), so an entire lane is shut/started at once.
    """
    fn = (cli_helpers.config_interface_shutdown if action == "shutdown"
          else cli_helpers.config_interface_startup)
    for namespace, ns_ports in _group_by_namespace(ports, port_ns).items():
        err = fn(duthost, ns_ports, namespace=namespace)
        if err:
            logger.warning("config interface %s %s reported: %s",
                           action, ",".join(ns_ports), err)


# ──────────────────────────────────────────────────────────────────────
# Cage discovery, breakout-mode uniformity, and LLDP-driven grouping
# ──────────────────────────────────────────────────────────────────────


def _build_cages(duthost, ports):
    """Group ``ports`` into cages by physical port index.

    Returns ``(cages, port_to_cage)`` where ``cages`` maps a physical-port
    index to its list of subport names (sorted by Ethernet number, so element
    ``[0]`` is the cage's parent / first subport) and ``port_to_cage`` maps each
    port to its cage index. The physical-port index is the CONFIG_DB ``PORT``
    ``index`` field (every subport of a breakout cage shares it).
    """
    phys = get_physical_port_indices(duthost)
    cages = {}
    port_to_cage = {}
    for port in ports:
        idx = phys.get(port)
        if idx is None:
            logger.warning("Port %s has no physical port index; treating as its own cage", port)
            idx = f"_solo_{port}"
        port_to_cage[port] = idx
        cages.setdefault(idx, []).append(port)
    for idx in cages:
        cages[idx].sort(key=_eth_index)
    return cages, port_to_cage


def _validate_uniform_mode(port_attributes_dict, cages, port_to_cage):
    """Enforce that every front port is the same breakout mode (req #1).

    A port's mode is ``(subports_per_cage, speed_gbps)`` - e.g. ``(8, 100)`` is
    8x100G, ``(2, 400)`` is 2x400G, ``(1, 800)`` is 1x800G. A mixed fabric is a
    hard ``pytest.fail``.

    Returns ``(subports_per_cage, mode_label)`` for the single uniform mode.
    """
    modes = {}
    for port, cage_idx in port_to_cage.items():
        subport_count = len(cages[cage_idx])
        speed = port_attributes_dict[port].get(BASE_ATTRIBUTES_KEY, {}).get("speed_gbps")
        modes.setdefault((subport_count, speed), []).append(port)

    if len(modes) != 1:
        parts = []
        for (n, speed), plist in sorted(modes.items(), key=lambda kv: str(kv[0])):
            label = f"{n}x{speed}G" if speed else f"{n} subport(s)/cage"
            parts.append(f"{label}: {len(plist)} port(s) (e.g. {sorted(plist, key=_eth_index)[0]})")
        pytest.fail(
            "Front ports are not a uniform breakout mode (req: all 8x100G, all "
            "2x400G, or all 1x800G): " + "; ".join(parts)
        )

    (subport_count, speed) = next(iter(modes))
    mode_label = f"{subport_count}x{speed}G" if speed else f"{subport_count} subport(s)/cage"
    return subport_count, mode_label


def _split_groups(duthost, cages, port_to_cage):
    """Split cages into ``(local_cages, remote_cages)`` using LLDP (req #2).

    For each cage, the parent port's LLDP neighbor decides:

      * neighbor on THIS switch (``lldp_rem_chassis_id`` == local chassis id):
        the cage and its partner cage are a self-loop pair - the lower-numbered
        parent goes to ``local_cages``, the higher to ``remote_cages``.
      * neighbor on a DIFFERENT switch (or no resolvable on-switch partner):
        the cage goes to ``local_cages`` and its off-switch partner is left
        untouched.

    Returns two lists of cage indices.

    All LLDP reads are scoped to the owning ASIC's namespace (multi-ASIC). On a
    single-ASIC DUT the namespace resolves to ``""`` and no ``-n`` flag is
    emitted. The local chassis id is read per namespace (each ASIC has its own
    LLDP database) and cached.
    """
    loc_chassis_by_ns = {}

    def _local_chassis(namespace):
        if namespace not in loc_chassis_by_ns:
            loc = db_helpers.hgetall_dict(
                duthost, "APPL_DB", "LLDP_LOC_CHASSIS", namespace=namespace
            )
            chassis_id = (loc or {}).get("lldp_loc_chassis_id")
            if not chassis_id:
                logger.warning(
                    "LLDP_LOC_CHASSIS.lldp_loc_chassis_id not found (namespace=%r); "
                    "neighbors in this namespace will be treated as off-switch",
                    namespace,
                )
            loc_chassis_by_ns[namespace] = chassis_id
        return loc_chassis_by_ns[namespace]

    local_cages = []
    remote_cages = []
    assigned = set()

    for cage_idx in sorted(cages, key=lambda ci: _eth_index(cages[ci][0])):
        if cage_idx in assigned:
            continue
        parent = cages[cage_idx][0]
        namespace = _port_namespace(duthost, parent)
        local_chassis_id = _local_chassis(namespace)
        entry = db_helpers.hgetall_dict(
            duthost, "APPL_DB", f"LLDP_ENTRY_TABLE:{parent}", namespace=namespace
        )
        partner_port = entry.get("lldp_rem_port_desc")
        rem_chassis_id = entry.get("lldp_rem_chassis_id")
        same_switch = bool(rem_chassis_id) and rem_chassis_id == local_chassis_id
        partner_cage = port_to_cage.get(partner_port) if partner_port else None

        if (same_switch and partner_cage is not None
                and partner_cage != cage_idx and partner_cage not in assigned):
            lo_cage, hi_cage = sorted(
                [cage_idx, partner_cage], key=lambda ci: _eth_index(cages[ci][0])
            )
            local_cages.append(lo_cage)
            remote_cages.append(hi_cage)
            assigned.update([lo_cage, hi_cage])
            logger.debug(
                "Self-loop pair (same switch): %s <-> %s  =>  local=%s, remote=%s",
                parent, partner_port, cages[lo_cage][0], cages[hi_cage][0],
            )
        else:
            local_cages.append(cage_idx)
            assigned.add(cage_idx)
            if partner_port and not same_switch:
                reason = f"partner {partner_port} on a different switch (chassis {rem_chassis_id})"
            elif not partner_port:
                reason = "no LLDP neighbor"
            else:
                reason = f"partner {partner_port} not under test"
            logger.debug("Cage parent %s => local_group only (%s)", parent, reason)

    return local_cages, remote_cages


def _group_ports(group_cages, cages):
    """Flatten a list of cage indices into a flat, Ethernet-sorted port list."""
    ports = [p for ci in group_cages for p in cages[ci]]
    return sorted(ports, key=_eth_index)


# ──────────────────────────────────────────────────────────────────────
# Module-scoped safety net.
# A hard test abort (fixture error, infra exception) could leave a port
# admin-down. This teardown re-issues startup for every port in scope
# regardless of whether the test passed.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True, scope="module")
def _restore_ports_after_module(duthost, port_attributes_dict):
    yield
    ports = sorted(port_attributes_dict.keys(), key=_eth_index)
    if not ports:
        return
    logger.info("Link-behavior teardown: ensuring %d port(s) are admin-up", len(ports))
    for port in ports:
        _startup_port(duthost, port)


# ──────────────────────────────────────────────────────────────────────
# Grouped shut/no-shut runner
# ──────────────────────────────────────────────────────────────────────


def _run_group(
    duthost, group_name, group_cages, cages, subports_per_cage,
    port_attributes_dict, port_ns, shared_state, failures,
):
    """Toggle one group, one lane (subport index) at a time, then verify.

    For each lane ``i`` in ``0 .. subports_per_cage-1`` the lane's ports
    (one subport per cage, e.g. ``Ethernet0,Ethernet64,Ethernet128,...``) are
    handled in batch:

      1. ONE ``config interface shutdown <comma-list>`` command (per ASIC
         namespace) shuts the whole lane,
      2. ONE ``show interface description`` poll verifies every port is
         oper-down within ``port_shutdown_wait_sec``,
      3. ONE ``config interface startup <comma-list>`` command starts the lane,
      4. ONE ``show interface description`` poll verifies every port is oper-up
         within ``port_startup_wait_sec``,
      5. the Standard Port Recovery and Verification Procedure runs for each of
         the lane's ports (LLDP / CMIS / SI / health).

    Startup (step 3) is always issued even if the down-check missed, so a port
    is never left admin-down because a verification step failed.
    """
    ordered_cages = sorted(group_cages, key=lambda ci: _eth_index(cages[ci][0]))
    if not ordered_cages:
        logger.info("%s group is empty - nothing to toggle", group_name)
        return

    for lane in range(subports_per_cage):
        batch = [cages[ci][lane] for ci in ordered_cages]

        # ── 1-2. shut the whole lane in one command, verify down in one poll ──
        shutdown_wait = max(
            _sys_attr(port_attributes_dict[p], "port_shutdown_wait_sec", 5) for p in batch
        )
        logger.info("[%s] lane %d: shutdown (one command) %s; poll oper-down up to %ds",
                    group_name, lane, batch, shutdown_wait)
        _toggle_ports(duthost, batch, port_ns, "shutdown")
        down = wait_for_ports_oper_state(duthost, batch, "down", shutdown_wait)
        for port in batch:
            if not down[port]["passed"]:
                failures.append(f"[{group_name} shutdown] {down[port]['details']}")
                logger.warning("[%s] shutdown FAILED: %s", group_name, down[port]["details"])

        # ── 3-4. start the whole lane in one command, verify up in one poll ──
        startup_wait = max(
            _sys_attr(port_attributes_dict[p], "port_startup_wait_sec", 60) for p in batch
        )
        logger.info("[%s] lane %d: startup (one command) %s; poll oper-up up to %ds",
                    group_name, lane, batch, startup_wait)
        _toggle_ports(duthost, batch, port_ns, "startup")
        up = wait_for_ports_oper_state(duthost, batch, "up", startup_wait)
        for port in batch:
            if not up[port]["passed"]:
                failures.append(f"[{group_name} startup] {up[port]['details']}")
                logger.warning("[%s] startup FAILED: %s", group_name, up[port]["details"])

        # ── 5. Standard Port Recovery for the lane's ports ──
        for port in batch:
            result = standard_port_recovery_and_verification(
                duthost, port, port_attributes_dict[port],
                link_up_timeout_sec=startup_wait,
                shared_state=shared_state,
            )
            if not result["passed"]:
                failures.append(f"[{group_name} recovery] {result['details']}")
                logger.warning("[%s] recovery FAILED on %s: %s",
                               group_name, port, result["details"])


# ──────────────────────────────────────────────────────────────────────
# TC1 + TC2 combined - grouped per-lane shutdown + startup validation
# ──────────────────────────────────────────────────────────────────────


def test_system_port_sns_validation(duthost, port_attributes_dict):
    """Group front ports by LLDP, then toggle each group one lane at a time.

    See the module docstring for the full design. In short:
      * enforce a uniform breakout mode across all front ports (req #1),
      * split into ``local_group`` / ``remote_group`` via LLDP so a link's two
        ends are never both shut at once and off-switch partners are untouched
        (req #2),
      * per group, one lane at a time: ONE shutdown command -> ONE poll for
        oper-down -> ONE startup command -> ONE poll for oper-up -> Standard
        Port Recovery for the lane's ports.

    All (port, step) failures are accumulated and reported in a single
    ``pytest.fail`` so one run surfaces every issue.
    """
    ports = sorted(port_attributes_dict.keys(), key=_eth_index)
    assert ports, "port_attributes_dict is empty - nothing to validate"

    cages, port_to_cage = _build_cages(duthost, ports)
    subports_per_cage, mode_label = _validate_uniform_mode(
        port_attributes_dict, cages, port_to_cage
    )
    local_cages, remote_cages = _split_groups(duthost, cages, port_to_cage)

    # Resolve each port's ASIC namespace once, reused for every batched
    # ``config interface`` command (single-ASIC -> "" -> no ``-n`` flag).
    port_ns = {port: _port_namespace(duthost, port) for port in ports}

    local_group = _group_ports(local_cages, cages)
    remote_group = _group_ports(remote_cages, cages)
    logger.debug("Breakout mode: %s (%d subport(s)/cage), %d cage(s) total",
                 mode_label, subports_per_cage, len(cages))
    logger.debug("local_group (%d ports): %s", len(local_group), local_group)
    logger.debug("remote_group (%d ports): %s", len(remote_group), remote_group)

    # Capture pre-existing cores BEFORE any toggle so the recovery health check
    # flags only cores created during this test, not stale ones already present
    # in /var/core (e.g. old zebra/orchagent cores from earlier crashes).
    shared_state = {"core_baseline": list_core_files(duthost)}
    failures = []

    _run_group(duthost, "local", local_cages, cages, subports_per_cage,
               port_attributes_dict, port_ns, shared_state, failures)
    _run_group(duthost, "remote", remote_cages, cages, subports_per_cage,
               port_attributes_dict, port_ns, shared_state, failures)

    if failures:
        pytest.fail(
            f"Grouped port shutdown+startup validation FAILED on {len(failures)} "
            f"step(s) across {len(ports)} port(s) "
            f"(local={len(local_group)}, remote={len(remote_group)}):\n  - "
            + "\n  - ".join(failures)
        )
