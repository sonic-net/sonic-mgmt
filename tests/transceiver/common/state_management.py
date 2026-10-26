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


def _pmon_daemon_control_path(duthost):
    """Return the ``pmon_daemon_control.json`` that pmon actually reads.

    Mirrors pmon's ``docker_init.sh``: the hwsku copy takes precedence over the
    platform copy. When neither exists, the platform copy is returned so a
    newly created file is picked up.

    Args:
        duthost: DUT host object.

    Returns:
        tuple: ``(dut_path, pmon_path)``.
            dut_path: absolute path of the file on the DUT host.
            pmon_path: the same file as mounted inside the pmon container.
    """
    platform_dir = "/usr/share/sonic/device/{}".format(duthost.facts["platform"])
    hwsku_path = "{}/{}/pmon_daemon_control.json".format(platform_dir, duthost.facts["hwsku"])
    if duthost.stat(path=hwsku_path)["stat"]["exists"]:
        return hwsku_path, "/usr/share/sonic/hwsku/pmon_daemon_control.json"
    return (
        "{}/pmon_daemon_control.json".format(platform_dir),
        "/usr/share/sonic/platform/pmon_daemon_control.json",
    )


def enable_pmon_skip_xcvrd(duthost):
    """Set ``"skip_xcvrd": true`` in ``pmon_daemon_control.json``.

    Used by the System Event Handling "CMIS boot-up low power mode" test:
    disabling xcvrd before a reboot lets a freshly-booted CMIS module's
    default (low) power state be observed before xcvrd's init sequence would
    otherwise bring it up. :func:`restore_pmon_daemon_control` reverts this.

    The original contents are returned to the caller rather than backed up on
    the DUT, because ``/tmp`` is wiped by the cold reboot that follows.

    Args:
        duthost: DUT host object.

    Returns:
        tuple: ``(original_text, error)``.
            original_text: original file contents, or ``None`` if the file did not exist.
            error: error string, or ``None`` on success.
    """
    config_path, _ = _pmon_daemon_control_path(duthost)
    if duthost.stat(path=config_path)["stat"]["exists"]:
        read_result = duthost.shell(f"cat {config_path}", module_ignore_errors=True)
        if read_result.get("rc", 1) != 0:
            return None, "failed to read {}: {}".format(
                config_path, (read_result.get("stderr") or "").strip()
            )
        original_text = read_result["stdout"]
    else:
        original_text = None

    try:
        daemon_dict = json.loads(original_text or "{}")
    except ValueError:
        daemon_dict = {}
    daemon_dict["skip_xcvrd"] = True

    write_result = duthost.copy(
        content=json.dumps(daemon_dict, indent=4) + "\n", dest=config_path,
    )
    if write_result.get("failed"):
        return original_text, f"failed to write {config_path} with skip_xcvrd=true"
    return original_text, None


_PMON_SUPERVISOR_TEMPLATE = "/usr/share/sonic/templates/docker-pmon.supervisord.conf.j2"
_PMON_CRITICAL_PROCESSES_FILE = "/etc/supervisor/critical_processes"


def check_skip_xcvrd_critical_mismatch(duthost):
    """Detect, before rebooting, a boot with ``skip_xcvrd`` that cannot come up healthy.

    pmon's ``critical_processes`` file is static, while its ``supervisord.conf``
    is rendered at container start from ``pmon_daemon_control.json`` (the file
    :func:`_pmon_daemon_control_path` resolves). If xcvrd is
    a critical process and the rendered config still defines ``[program:xcvrd]``,
    xcvrd is either started anyway or reported not running, so neither the
    boot-up LPMode check nor the post-reboot critical-process wait can pass.

    Call after :func:`enable_pmon_skip_xcvrd`, while pmon is still running. Only
    a confirmed mismatch is reported: if either file cannot be read or rendered,
    this returns ``None`` and the reboot proceeds as normal.

    Args:
        duthost: DUT host object.

    Returns:
        str or None: description of the mismatch, or ``None`` if none was found.
    """
    critical = duthost.shell(
        f"docker exec pmon cat {_PMON_CRITICAL_PROCESSES_FILE}", module_ignore_errors=True,
    )
    if critical.get("rc", 1) != 0:
        logger.info("Could not read pmon %s; skipping skip_xcvrd consistency check",
                    _PMON_CRITICAL_PROCESSES_FILE)
        return None
    if "program:xcvrd" not in (line.strip() for line in critical["stdout_lines"]):
        return None

    config_path, pmon_config_path = _pmon_daemon_control_path(duthost)
    rendered = duthost.shell(
        f"docker exec pmon sonic-cfggen -d -j {pmon_config_path} -t {_PMON_SUPERVISOR_TEMPLATE}",
        module_ignore_errors=True,
    )
    if rendered.get("rc", 1) != 0:
        logger.info("Could not render pmon supervisord.conf; skipping skip_xcvrd consistency check: %s",
                    (rendered.get("stderr") or "").strip())
        return None
    if "[program:xcvrd]" not in (line.strip() for line in rendered["stdout_lines"]):
        return None
    return (
        f"xcvrd is a pmon critical process ({_PMON_CRITICAL_PROCESSES_FILE}) but pmon's "
        f"supervisord.conf rendered from {config_path} still defines [program:xcvrd] with "
        "skip_xcvrd set, so a boot with xcvrd disabled cannot come up healthy"
    )


def restore_pmon_daemon_control(duthost, original_text):
    """Revert ``pmon_daemon_control.json`` to what :func:`enable_pmon_skip_xcvrd` found.

    Args:
        duthost: DUT host object.
        original_text: original file contents returned by
            :func:`enable_pmon_skip_xcvrd`; ``None`` means the file did not
            exist and is removed.

    Returns:
        str or None: error string, or ``None`` on success.
    """
    config_path, _ = _pmon_daemon_control_path(duthost)
    if original_text is None:
        result = duthost.file(path=config_path, state="absent", module_ignore_errors=True)
    else:
        result = duthost.copy(
            content=original_text + "\n", dest=config_path, module_ignore_errors=True,
        )
    if result.get("failed"):
        return "failed to restore {}: {}".format(config_path, result.get("msg", ""))
    return None


def verify_pmon_daemon_control_restored(duthost, original_text):
    """Check that ``pmon_daemon_control.json`` and xcvrd are back to their pre-test state.

    The file must match what :func:`enable_pmon_skip_xcvrd` found (absent if it
    was absent). xcvrd must be RUNNING unless the original file already set
    ``skip_xcvrd``, in which case it is intentionally disabled and left so.

    Args:
        duthost: DUT host object.
        original_text: original file contents returned by
            :func:`enable_pmon_skip_xcvrd`; ``None`` means the file did not exist.

    Returns:
        str or None: description of what differs from the pre-test state, or
        ``None`` if it was restored.
    """
    config_path, _ = _pmon_daemon_control_path(duthost)
    read_result = duthost.shell(f"cat {config_path}", module_ignore_errors=True)
    current_text = read_result["stdout"] if read_result.get("rc", 1) == 0 else None
    if original_text is None:
        if current_text is not None:
            return f"{config_path} still exists but did not exist before the test"
    elif current_text is None:
        return f"{config_path} is missing but existed before the test"
    elif current_text.strip() != original_text.strip():
        return f"{config_path} does not match its pre-test contents"

    try:
        xcvrd_skipped = bool(json.loads(original_text or "{}").get("skip_xcvrd"))
    except ValueError:
        xcvrd_skipped = False
    if xcvrd_skipped:
        logger.info("skip_xcvrd was set before the test; leaving xcvrd disabled")
        return None

    status, _ = duthost.get_pmon_daemon_status("xcvrd")
    if status != "RUNNING":
        return f"xcvrd is {status or 'missing'} in pmon, expected RUNNING"
    return None
