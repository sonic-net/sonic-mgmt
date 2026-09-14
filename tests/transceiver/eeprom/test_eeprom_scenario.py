"""EEPROM Scenario Coverage (S1-S7).

Implements the EEPROM scenario-coverage test cases from
``docs/testplan/transceiver/eeprom_test_plan.md`` on the shared model
(``scenario_ops`` operations + feature verifiers):

  * S1    — DataPath field clear/restore on shut/no-shut (CMIS active-optical).
  * S2-S4 — EEPROM recovery (static content + CMIS active-optical DataPath) after cold/warm/fast reboot.
  * S5    — after config reload.
  * S6    — after xcvrd / pmon / swss / syncd restart.
  * S7    — after sfputil reset.

Static content is scored by ``verify_eeprom_static_recovered`` (link-independent);
the dynamic DataPath fields (CMIS active-optical) by ``verify_datapath_recovered``;
and the firmware versions by ``verify_firmware_info_recovered`` (republished by
xcvrd's DOM thread on a slower, delayed cycle) as a separate line item.

S2-S7 drive those three verifiers through the shared
``eeprom/recovery.py::verify_transceiver_recovery`` orchestration, which the
physical OIR and firmware suites reuse; S1 and the S7 post-reset checks call the
individual verifiers directly because they score a different subset.
"""
import logging

import pytest

from tests.common.platform.interface_utils import is_first_subport
from tests.transceiver.attribute_parser.attribute_keys import DOM_ATTRIBUTES_KEY, SYSTEM_ATTRIBUTES_KEY
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.health_checks import DEFAULT_MONITORED_PROCESSES
from tests.transceiver.eeprom import datapath, recovery
from tests.transceiver.eeprom.eeprom_content import (
    verify_eeprom_static_recovered,
    verify_firmware_info_recovered,
)

logger = logging.getLogger(__name__)


# Full-system disruptions (reboot / config reload) may restart every
# framework-monitored process, so their PID changes are all expected.
_ALL_MONITORED_PROCESSES = set(DEFAULT_MONITORED_PROCESSES)
_DAEMON_EXPECTED_PID_CHANGES = {
    # xcvrd (supervisor process) and its pmon container restart xcvrd only.
    "xcvrd": {"xcvrd"},
    "pmon": {"xcvrd"},
    # swss/syncd are tightly coupled. The platform attribute separately
    # controls whether xcvrd is also expected to restart inside pmon.
    "swss": {"syncd", "orchagent"},
    "syncd": {"syncd", "orchagent"},
}


def _representative_attribute(port_attributes_dict, scope_key, attribute):
    """Read an operation-scoped attribute (uniform across ports) from a
    representative port's ``scope_key`` shard."""
    return next(iter(port_attributes_dict.values()))[scope_key][attribute]


def _system_attribute(port_attributes_dict, attribute):
    return _representative_attribute(port_attributes_dict, SYSTEM_ATTRIBUTES_KEY, attribute)


def _verify_recovery(
    duthost,
    port_attributes_dict,
    lport_to_first_subport_mapping,
    wait_sec,
    scenario,
):
    """Verify EEPROM static content + CMIS active-optical DataPath + firmware recovery.

    Thin scenario-suite wrapper over the shared
    :func:`tests.transceiver.eeprom.recovery.verify_transceiver_recovery`
    orchestration, aggregating its line-item failures into one ``pytest.fail``.
    """
    failures = recovery.verify_transceiver_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        wait_sec,
        scenario,
        # The scenario suite sizes the firmware budget from a representative
        # port because these disruptions are DUT-wide and every port shares the
        # same settle characteristics.
        firmware_wait_sec=wait_sec + _representative_attribute(
            port_attributes_dict, DOM_ATTRIBUTES_KEY, "dom_info_recover_sec"),
    )
    if failures:
        pytest.fail(
            "EEPROM recovery verification failed {}:\n{}".format(scenario, "\n".join(failures))
        )


def test_datapath_clear_restore_on_shut_noshut(duthost, port_attributes_dict):
    """S1: DataPath fields clear to ``N/A`` on shut and restore on startup (bulk).

    Follows the scenario-coverage skeleton: pre-check → bulk shut → verify
    cleared → bulk startup → verify recovered → teardown. Per-port failures
    aggregate into one ``pytest.fail``.
    """
    ports = datapath.cmis_active_optical_ports(port_attributes_dict)
    if not ports:
        pytest.skip("No CMIS active-optical ports to exercise for S1")

    # Per-port settle waits scaled to fleet size (bulk settles slower — see
    # scenario_ops.scale_bulk_wait); read directly so a missing key fails loudly.
    target_attrs = [port_attributes_dict[port] for port in ports]
    shutdown_wait = scenario_ops.scale_bulk_wait(
        max(a.get(SYSTEM_ATTRIBUTES_KEY, {})["port_shutdown_wait_sec"] for a in target_attrs),
        len(ports))
    # Unscaled per-port oper-up budget: used for the datapath republish poll (a
    # per-port latency); scaled for the bulk oper-up waits.
    port_startup_wait = max(
        a.get(SYSTEM_ATTRIBUTES_KEY, {})["port_startup_wait_sec"] for a in target_attrs)
    startup_wait = scenario_ops.scale_bulk_wait(port_startup_wait, len(ports))

    all_failures = []
    # 1. Pre-check: DataPath at steady state (snapshot, wait_sec=0) so a post-op
    #    failure is attributable to the shut/no-shut.
    all_failures += datapath.verify_datapath_recovered(
        duthost, port_attributes_dict, 0, ports=ports)

    logger.info("S1: exercising DataPath clear/restore on %d port(s) "
                "(shutdown_wait=%ss startup_wait=%ss)",
                len(ports), shutdown_wait, startup_wait)
    try:
        # 2. Bulk shut, then verify DataPath cleared: xcvrd clears the fields
        #    after link-drop, so oper-down doesn't imply cleared — poll shutdown_wait.
        all_failures += scenario_ops.perform_ports_shutdown(
            duthost, ports, shutdown_wait)
        all_failures += datapath.verify_datapath_cleared(
            duthost, port_attributes_dict, shutdown_wait, ports=ports)

        # 3. Bulk startup, then verify DataPath recovered: xcvrd's republish can
        #    lag oper-up (per-port latency) — poll the unscaled port_startup_wait.
        all_failures += scenario_ops.perform_ports_startup(
            duthost, ports, startup_wait)
        all_failures += datapath.verify_datapath_recovered(
            duthost, port_attributes_dict, port_startup_wait, ports=ports)
    finally:
        # Teardown: restore every exercised port and surface any that don't come
        # back up, so a broken testbed fails this test rather than later ones.
        all_failures += scenario_ops.perform_ports_startup(duthost, ports, startup_wait)

    if all_failures:
        pytest.fail(
            "DataPath clear/restore on shut/no-shut (S1) failures:\n"
            + "\n".join(all_failures)
        )


@pytest.mark.disable_loganalyzer
@pytest.mark.disable_memory_utilization
@pytest.mark.parametrize("reboot_type", ["cold", "warm", "fast"])
def test_eeprom_recovery_after_reboot(
    duthost,
    localhost,
    port_attributes_dict,
    lport_to_first_subport_mapping,
    expected_pid_changes,
    reboot_type,
):
    """S2-S4: Verify EEPROM static content + DataPath recovery after cold, warm, and fast reboot."""
    if not port_attributes_dict:
        pytest.skip("No transceiver ports to verify")
    # Cold reboot is always supported; warm/fast are gated by a platform attr.
    if reboot_type != "cold":
        gate = "{}_reboot_supported".format(reboot_type)
        if not _system_attribute(port_attributes_dict, gate):
            pytest.skip("{} is false".format(gate))

    _verify_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        0,
        "before {} reboot".format(reboot_type),
    )

    expected_pid_changes.update(_ALL_MONITORED_PROCESSES)
    operation = getattr(scenario_ops, "perform_{}_reboot".format(reboot_type))
    operation(duthost, localhost)

    _verify_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        _system_attribute(port_attributes_dict, "{}_reboot_settle_sec".format(reboot_type)),
        "after {} reboot".format(reboot_type),
    )


@pytest.mark.disable_loganalyzer
@pytest.mark.disable_memory_utilization
def test_eeprom_recovery_after_config_reload(
    duthost,
    port_attributes_dict,
    lport_to_first_subport_mapping,
    expected_pid_changes,
):
    """S5: Verify EEPROM static content + DataPath recovery after a CONFIG_DB reload."""
    if not port_attributes_dict:
        pytest.skip("No transceiver ports to verify")

    _verify_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        0,
        "before config reload",
    )

    expected_pid_changes.update(_ALL_MONITORED_PROCESSES)
    scenario_ops.perform_config_reload(duthost)

    _verify_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        _system_attribute(port_attributes_dict, "config_reload_settle_sec"),
        "after config reload",
    )


@pytest.mark.disable_loganalyzer
@pytest.mark.disable_memory_utilization
@pytest.mark.parametrize("daemon", ["xcvrd", "pmon", "swss", "syncd"])
def test_eeprom_recovery_after_daemon_restart(
    duthost,
    port_attributes_dict,
    lport_to_first_subport_mapping,
    expected_pid_changes,
    daemon,
):
    """S6: Verify EEPROM static content + DataPath recovery after each related daemon restart."""
    if not port_attributes_dict:
        pytest.skip("No transceiver ports to verify")
    # syncd-alone restart runs by default (most platforms recover cleanly); opt
    # out where it does not recover cleanly (syncd crash/core on a lane-map
    # mismatch, "helperCheckLaneMap: lanes map size differ", before systemd
    # self-heals it) — a functional gate, not just log noise.
    if daemon == "syncd" and not _system_attribute(port_attributes_dict, "syncd_restart_supported"):
        pytest.skip("syncd_restart_supported is false")

    _verify_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        0,
        "before {} restart".format(daemon),
    )

    expected_pid_changes.update(_DAEMON_EXPECTED_PID_CHANGES[daemon])
    if daemon in ("swss", "syncd") and _system_attribute(
        port_attributes_dict, "expect_xcvrd_restart_with_swss_or_syncd"
    ):
        expected_pid_changes.add("xcvrd")
    scenario_ops.perform_daemon_restart(duthost, daemon)

    _verify_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        _system_attribute(
            port_attributes_dict, "{}_restart_settle_sec".format(daemon)
        ),
        "after {} restart".format(daemon),
    )


def test_eeprom_recovery_after_sfputil_reset(
    duthost,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """S7: Verify static EEPROM and active DataPath state after module reset."""
    if not port_attributes_dict:
        pytest.skip("No transceiver ports to verify")

    _verify_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        0,
        "before sfputil reset",
    )
    # _verify_recovery already snapshots static content + DataPath as the pre-check.
    active_optical_ports = datapath.cmis_active_optical_ports(port_attributes_dict)

    # Reset support varies by optic, so gate each module on its own attribute
    # rather than on a representative port.
    reset_ports = [
        port
        for port in port_attributes_dict
        if is_first_subport(port, lport_to_first_subport_mapping)
        and port_attributes_dict[port][SYSTEM_ATTRIBUTES_KEY]["transceiver_reset_supported"]
    ]
    if not reset_ports:
        pytest.skip("No ports with transceiver_reset_supported")
    # A reset drops the datapath on every subport of the module, so the toggle
    # (and the verification) covers all subports of the reset modules only.
    reset_modules = set(reset_ports)
    toggle_ports = [
        port
        for port in port_attributes_dict
        if lport_to_first_subport_mapping.get(port) in reset_modules
    ]
    active_ports = [port for port in toggle_ports if port in active_optical_ports]

    # All modules reset in one bulk shut -> reset -> startup cycle (not one cycle
    # per connector); settle budgets come from the (uniform) system attrs, scaled
    # from per-port to the full toggled-port count.
    system_attrs = port_attributes_dict[reset_ports[0]][SYSTEM_ATTRIBUTES_KEY]
    shutdown_wait = scenario_ops.scale_bulk_wait(
        system_attrs["port_shutdown_wait_sec"], len(toggle_ports))
    startup_wait = scenario_ops.scale_bulk_wait(
        system_attrs["port_startup_wait_sec"], len(toggle_ports))
    # EEPROM may be briefly inaccessible over I2C after a reset, so the recovery
    # poll budget adds that window on top of the oper-up wait.
    recover_wait = startup_wait + system_attrs["transceiver_reset_i2c_recover_sec"]
    logger.info("S7: bulk sfputil reset of %d module(s) across %d port(s), wait=%ss",
                len(reset_ports), len(toggle_ports), recover_wait)

    all_failures = scenario_ops.perform_sfputil_reset(
        duthost,
        reset_ports,
        toggle_ports,
        shutdown_wait,
        startup_wait,
    )
    all_failures += verify_eeprom_static_recovered(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        recover_wait,
        ports=toggle_ports,
        enforce_timeout=True,
    )
    all_failures += datapath.verify_datapath_recovered(
        duthost,
        port_attributes_dict,
        recover_wait,
        ports=active_ports,
    )
    # Firmware is republished on xcvrd's slower DOM cycle, so it gets the reset
    # recovery budget plus that delay (same split as ``_verify_recovery``).
    all_failures += verify_firmware_info_recovered(
        duthost,
        port_attributes_dict,
        recover_wait + _representative_attribute(
            port_attributes_dict, DOM_ATTRIBUTES_KEY, "dom_info_recover_sec"),
        ports=toggle_ports,
    )

    if all_failures:
        pytest.fail(
            "EEPROM recovery after sfputil reset failures:\n"
            + "\n".join(all_failures)
        )
