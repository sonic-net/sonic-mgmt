"""State Preservation and Restoration helpers for transceiver System tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for the
"State Preservation and Restoration helpers".

Implements the post-session / post-test restoration described in
``docs/testplan/transceiver/system_test_plan.md`` (§ State Preservation and
Restoration): bring every port back to admin-up and high power mode (low-power
off), then bounce any remaining admin-up/oper-down links once. Operational state
is checked after restoration by the caller.

This is the restorative counterpart to
:mod:`tests.transceiver.common.verification` (which is diagnostic): it issues
port startup through :mod:`tests.transceiver.common.cli_helpers`. The caller
performs final link verification after all post-session checks.
"""
import json
import logging

from tests.common.platform.interface_utils import get_dut_interfaces_status
from tests.transceiver.attribute_parser.attribute_keys import SYSTEM_ATTRIBUTES_KEY
from tests.transceiver.common import cli_helpers, scenario_ops

logger = logging.getLogger(__name__)

_PMON_DAEMON_CONTROL_BACKUP_PATH = "/tmp/pmon_daemon_control.json.bak"


def post_state_restoration(duthost, port_attributes_dict):
    """Restore every port in ``port_attributes_dict`` to known-good state.

    Per ``system_test_plan.md`` post-session State Restoration:
            * high power mode (low-power off),
            * admin-up,
            * one shut/startup recovery attempt for admin-up/oper-down links.

    The function is restorative, not diagnostic - it does the minimum
    needed to bring each port back, then reports which ports it touched
    and which ones still failed to recover.

    Returns:
        dict: ``{
            'admin_up_restored': [str],     # ports we issued 'startup' on
            'lpmode_high_restored': [str],  # ports we toggled out of LPMode
            'link_bounced': [str],          # oper-down ports we shut/start
            'still_failing': [str],         # toggle/wait failure details
        }``
    """
    summary = {
        "admin_up_restored": [],
        "lpmode_high_restored": [],
        "link_bounced": [],
        "still_failing": [],
    }
    if not port_attributes_dict:
        return summary

    # Pass 1: turn off low-power mode on anything still in LPMode.
    lpmode_by_port, err = cli_helpers.sfputil_show_lpmode(duthost)
    if err:
        logger.warning("Restoration: failed to read LPMode state: %s", err)
    else:
        low_power_ports = [
            port for port in sorted(port_attributes_dict)
            if lpmode_by_port.get(port, "").lower() == "on"
        ]
        for port in low_power_ports:
            logger.info("Restoration: turning off LPMode on %s", port)
            _, err = cli_helpers.sfputil_set_lpmode(duthost, port, low_power=False)
            if err:
                logger.warning("Restoration: failed to turn off LPMode on %s: %s", port, err)
                summary["still_failing"].append(err)
            else:
                summary["lpmode_high_restored"].append(port)

    # Pass 2: admin-up everything that's down after power-state restoration.
    intf_status = get_dut_interfaces_status(duthost)
    admin_down_ports = [
        port for port in sorted(port_attributes_dict)
        if (intf_status.get(port) or {}).get("admin") == "down"
    ]
    if admin_down_ports:
        startup_wait = scenario_ops.scale_bulk_wait(
            max(
                port_attributes_dict[port][SYSTEM_ATTRIBUTES_KEY]["port_startup_wait_sec"]
                for port in admin_down_ports
            ),
            len(admin_down_ports),
        )
        scenario_ops.perform_ports_startup(duthost, admin_down_ports, startup_wait)
        summary["admin_up_restored"].extend(admin_down_ports)

    # Pass 3: bounce links that remain admin-up but operationally down.
    intf_status = get_dut_interfaces_status(duthost)
    oper_down_ports = [
        port for port in sorted(port_attributes_dict)
        if (intf_status.get(port) or {}).get("admin") == "up"
        and (intf_status.get(port) or {}).get("oper") == "down"
    ]
    if oper_down_ports:
        shutdown_wait = scenario_ops.scale_bulk_wait(
            max(
                port_attributes_dict[port][SYSTEM_ATTRIBUTES_KEY]["port_shutdown_wait_sec"]
                for port in oper_down_ports
            ),
            len(oper_down_ports),
        )
        startup_wait = scenario_ops.scale_bulk_wait(
            max(
                port_attributes_dict[port][SYSTEM_ATTRIBUTES_KEY]["port_startup_wait_sec"]
                for port in oper_down_ports
            ),
            len(oper_down_ports),
        )
        summary["link_bounced"].extend(oper_down_ports)
        scenario_ops.perform_ports_shutdown(duthost, oper_down_ports, shutdown_wait)
        scenario_ops.perform_ports_startup(duthost, oper_down_ports, startup_wait)

    final_status = get_dut_interfaces_status(duthost)
    summary["still_failing"].extend(
        "{}: admin={}, oper={}".format(
            port,
            (final_status.get(port) or {}).get("admin", "missing"),
            (final_status.get(port) or {}).get("oper", "missing"),
        )
        for port in sorted(port_attributes_dict)
        if (final_status.get(port) or {}).get("admin") != "up"
        or (final_status.get(port) or {}).get("oper") != "up"
    )

    return summary


def enable_pmon_skip_xcvrd(duthost):
    """Back up ``pmon_daemon_control.json`` and set ``"skip_xcvrd": true`` in it.

    Used by the System Event Handling "CMIS boot-up low power mode" test:
    disabling xcvrd before a reboot lets a freshly-booted CMIS module's
    default (low) power state be observed before xcvrd's init sequence would
    otherwise bring it up. :func:`restore_pmon_daemon_control` reverts this.

    Returns an error string, or ``None`` on success.
    """
    config_path = "/usr/share/sonic/device/{}/pmon_daemon_control.json".format(
        duthost.facts["platform"]
    )
    backup_result = duthost.shell(
        "cp {src} {dst} 2>/dev/null || echo '{{}}' > {dst}".format(
            src=config_path, dst=_PMON_DAEMON_CONTROL_BACKUP_PATH,
        ),
        module_ignore_errors=True,
    )
    if backup_result.get("rc", 1) != 0:
        return "failed to back up {}: {}".format(
            config_path, (backup_result.get("stderr") or "").strip()
        )

    read_result = duthost.shell(
        f"cat {_PMON_DAEMON_CONTROL_BACKUP_PATH}", module_ignore_errors=True
    )
    try:
        daemon_dict = json.loads(read_result.get("stdout") or "{}")
    except ValueError:
        daemon_dict = {}
    daemon_dict["skip_xcvrd"] = True

    write_result = duthost.copy(
        content=json.dumps(daemon_dict, indent=4) + "\n", dest=config_path,
    )
    if write_result.get("failed"):
        return f"failed to write {config_path} with skip_xcvrd=true"
    return None


def restore_pmon_daemon_control(duthost):
    """Revert ``pmon_daemon_control.json`` to the backup :func:`enable_pmon_skip_xcvrd` made.

    Returns an error string, or ``None`` on success.
    """
    config_path = "/usr/share/sonic/device/{}/pmon_daemon_control.json".format(
        duthost.facts["platform"]
    )
    result = duthost.shell(
        f"cp {_PMON_DAEMON_CONTROL_BACKUP_PATH} {config_path}",
        module_ignore_errors=True,
    )
    if result.get("rc", 1) != 0:
        return "failed to restore {}: {}".format(
            config_path, (result.get("stderr") or "").strip()
        )
    return None
