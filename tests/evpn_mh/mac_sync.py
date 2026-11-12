"""Optional MAC-over-FPM operating-mode helpers for EVPN-MH tests."""

import shlex

from .operations import wait_until


MAC_SYNC_KEY = "FDB_SYNC|global"
MAC_SYNC_FIELD = "mac_sync_mode"
KERNEL_MODE = "kernel"
FPM_MODE = "fpm"
EXPECTED_DUT_ROLES = ("mh_leaf0", "mh_leaf1")


class MacSyncModeError(RuntimeError):
    """Raised when a requested MAC synchronization mode is not operational."""


def _result_detail(result):
    return "\n".join(
        str(result.get(field, "")) for field in ("stderr", "stdout", "msg")
        if result.get(field)
    ).strip()


def _checked_stdout(dut, command):
    result = dut.shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise MacSyncModeError(
            "{} failed on {}: {}".format(
                command, dut.hostname, _result_detail(result)))
    return result.get("stdout", "")


def _db_hget(dut, database, key, field):
    value = _checked_stdout(
        dut,
        "sonic-db-cli {} HGET {} {}".format(
            database, shlex.quote(key), shlex.quote(field)),
    ).strip()
    return None if value in ("", "(nil)") else value.lower()


def configured_mac_sync_mode(dut):
    """Return the configured mode, applying SONiC's absent-row default."""
    mode = _db_hget(dut, "CONFIG_DB", MAC_SYNC_KEY, MAC_SYNC_FIELD)
    if mode is None:
        return KERNEL_MODE
    if mode not in (KERNEL_MODE, FPM_MODE):
        raise MacSyncModeError(
            "{} has unsupported configured MAC sync mode {!r}".format(
                dut.hostname, mode))
    return mode


def _device_subtype(dut):
    return _db_hget(
        dut, "CONFIG_DB", "DEVICE_METADATA|localhost", "subtype") or ""


def _supervisor_states(dut, container):
    output = _checked_stdout(
        dut, "docker exec {} supervisorctl status".format(container))
    states = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            states[fields[0].rsplit(":", 1)[-1]] = fields[1]
    if not states:
        raise MacSyncModeError(
            "{} {} supervisor state is empty".format(
                dut.hostname, container))
    return states


def _zebra_arguments(dut):
    return _checked_stdout(
        dut, "docker exec bgp sh -c \"ps -eo args | grep '[z]ebra'\"")


def _fpm_socket_connected(dut):
    output = _checked_stdout(dut, "sudo ss -tupn | grep 2620").lower()
    return "fpmsyncd" in output and "zebra" in output


def current_mac_sync_mode(dut):
    """Resolve the running mode without changing device state."""
    configured = configured_mac_sync_mode(dut)
    subtype = _device_subtype(dut).lower()
    zebra_arguments = _zebra_arguments(dut)
    if (configured == FPM_MODE or subtype == "l3evpnmh"
            or "--kernel-mac-ext-learn" in zebra_arguments):
        return FPM_MODE
    return KERNEL_MODE


def mac_sync_mode_ready(dut, expected_mode):
    """Pollable proof that configuration and running processes agree."""
    try:
        configured = configured_mac_sync_mode(dut)
        subtype = _device_subtype(dut).lower()
        zebra_arguments = _zebra_arguments(dut)
        bgp_states = _supervisor_states(dut, "bgp")
        swss_states = _supervisor_states(dut, "swss")
    except MacSyncModeError:
        return False

    if expected_mode == KERNEL_MODE:
        return (
            configured == KERNEL_MODE
            and subtype != "l3evpnmh"
            and "--kernel-mac-ext-learn" not in zebra_arguments
            and bgp_states.get("zebra") == "RUNNING"
            and swss_states.get("fdbsyncd") == "RUNNING"
        )
    if expected_mode != FPM_MODE:
        return False

    try:
        connected = _fpm_socket_connected(dut)
    except MacSyncModeError:
        return False
    service_ready = getattr(
        dut, "is_service_fully_started_per_asic_or_host", None)
    if callable(service_ready):
        try:
            if not service_ready("bgp"):
                return False
        except Exception:
            return False
    return (
        (configured == FPM_MODE or subtype == "l3evpnmh")
        and bgp_states.get("zebra") == "RUNNING"
        and bgp_states.get("fpmsyncd") == "RUNNING"
        and swss_states.get("fdbsyncd") == "RUNNING"
        and "-M dplane_fpm_sonic" in zebra_arguments
        and "--kernel-mac-ext-learn" in zebra_arguments
        and connected
    )


def assert_mac_sync_mode(dut, expected_mode):
    if not mac_sync_mode_ready(dut, expected_mode):
        raise MacSyncModeError(
            "{} is not operational in requested MAC sync mode {}".format(
                dut.hostname, expected_mode))


def probe_mac_over_fpm_capabilities(dut):
    """Return non-mutating image capability failures for an explicit request."""
    checks = (
        (
            "configuration CLI",
            "config fdb mac-sync-mode --help",
        ),
        (
            "Zebra external-MAC option and SONiC dataplane module",
            "docker exec bgp /usr/lib/frr/zebra -M dplane_fpm_sonic "
            "--help 2>&1 | grep -F -- '--kernel-mac-ext-learn'",
        ),
        (
            "BGP supervisor processes",
            "docker exec bgp supervisorctl status zebra fpmsyncd",
        ),
        (
            "SWSS fdbsyncd process",
            "docker exec swss supervisorctl status fdbsyncd",
        ),
        (
            "FPM socket inspection",
            "sudo ss -tupn",
        ),
    )
    failures = []
    for label, command in checks:
        result = dut.shell(command, module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            failures.append("{}: {}".format(label, _result_detail(result)))
    return failures


def restart_bgp_for_mac_sync(dut, timeout=180):
    """Restart the BGP service so Zebra receives freshly rendered arguments."""
    try:
        dut.reset_service("bgp")
        dut.restart_service("bgp")
    except Exception as error:
        raise MacSyncModeError(
            "BGP restart failed on {}: {}".format(
                dut.hostname, error)) from error
    ready = getattr(dut, "is_service_fully_started_per_asic_or_host", None)
    if not callable(ready):
        raise MacSyncModeError(
            "{} lacks the sonic-mgmt BGP service readiness API".format(
                dut.hostname))
    if not wait_until(timeout, 5, 0, ready, "bgp"):
        raise MacSyncModeError(
            "BGP did not return fully started on {}".format(dut.hostname))


def enable_mac_over_fpm(duts, timeout=180):
    """Enable and prove FPM mode on exactly the two local EVPN-MH ToRs."""
    if tuple(sorted(duts)) != EXPECTED_DUT_ROLES:
        raise MacSyncModeError(
            "MAC-over-FPM requires exactly {}".format(
                ", ".join(EXPECTED_DUT_ROLES)))

    # Configure both peers before restarting either peer.  A failure at any
    # point is restored by the already-active EVPN-MH checkpoint fixture.
    for role in EXPECTED_DUT_ROLES:
        _checked_stdout(
            duts[role], "sudo config fdb mac-sync-mode fpm")
    for role in EXPECTED_DUT_ROLES:
        if configured_mac_sync_mode(duts[role]) != FPM_MODE:
            raise MacSyncModeError(
                "{} did not retain mac_sync_mode=fpm".format(role))
    for role in EXPECTED_DUT_ROLES:
        _checked_stdout(duts[role], "sudo config save -y")
    for role in EXPECTED_DUT_ROLES:
        restart_bgp_for_mac_sync(duts[role], timeout=timeout)
    for role in EXPECTED_DUT_ROLES:
        if not wait_until(
                timeout, 5, 0, mac_sync_mode_ready,
                duts[role], FPM_MODE):
            raise MacSyncModeError(
                "{} did not become operational in MAC-over-FPM mode".format(
                    role))
