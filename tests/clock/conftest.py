import json
import shlex
import time
import uuid
from contextlib import contextmanager

import pytest
import logging

from ansible.errors import AnsibleConnectionFailure
from pytest_ansible.errors import AnsibleConnectionFailure as PytestAnsibleConnectionFailure
from tests.clock.ntp_utils import (
    get_ntp_one_shot_command,
    get_ntp_service_name,
    prepare_ntp_one_shot_config,
    setup_ntp_server_context
)
from tests.clock.test_clock import ClockConsts, ClockUtils
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.ntp_helper import get_ntp_daemon_in_use
from tests.common.utilities import wait_until


CLOCK_RECOVERY_TIMEOUT = 660
CLOCK_RECOVERY_COMMAND_TIMEOUT = 420
CLOCK_RECOVERY_KILL_AFTER = 150
CLOCK_RECOVERY_LEASE = 1800
CLOCK_RECOVERY_RETRY_INTERVAL = 60
CLOCK_RECOVERY_LOCK_TIMEOUT = 30
CLOCK_OFFSET_TOLERANCE = 5
CLOCK_SOURCE_MAX_OFFSET = 60
CLOCK_PTF_RECOVERY_TIMEOUT = 3600
CLOCK_POST_RESTORE_SETTLE_TIME = 20
CLOCK_TIMEZONE_SYNC_TIMEOUT = 120

RECOVERY_REFRESH_ERRORS = (
    RunAnsibleModuleFail,
    AnsibleConnectionFailure,
    PytestAnsibleConnectionFailure
)


def pytest_addoption(parser):
    parser.addoption("--ntp_server", action="store", default=None, required=False, help="IP of NTP server to use")


def _get_systemd_property(duthost, service_name, property_name):
    result = duthost.command(
        "systemctl show {} --property={} --value".format(
            shlex.quote(service_name),
            shlex.quote(property_name)
        )
    )
    value = result["stdout"].strip()
    assert value, "Empty {} for {}".format(property_name, service_name)
    return value


def _get_ntp_config(duthost):
    output = duthost.command("sonic-cfggen -d --var-json NTP_SERVER")["stdout"].strip()
    return json.loads(output or "{}")


def _get_configured_timezone(duthost):
    exists_output = duthost.command(
        'sonic-db-cli CONFIG_DB hexists "DEVICE_METADATA|localhost" "timezone"'
    )["stdout"].strip().lower()
    assert exists_output in {"0", "1", "false", "true"}, \
        "Unexpected CONFIG_DB HEXISTS output: {!r}".format(exists_output)
    exists = exists_output in {"1", "true"}
    value = None
    if exists:
        value = duthost.command(
            'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" "timezone"'
        )["stdout"].rstrip("\r\n")
    return {
        "exists": exists,
        "value": value
    }


def _get_timezone_config_restore_command(configured_timezone):
    if not configured_timezone["exists"]:
        return 'sonic-db-cli CONFIG_DB hdel "DEVICE_METADATA|localhost" "timezone"'
    return (
        'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "timezone" {}'
        .format(shlex.quote(configured_timezone["value"]))
    )


def _get_timezone_restore_commands(original_timezone, configured_timezone):
    excluded_timezones = {
        original_timezone,
        configured_timezone["value"] if configured_timezone["exists"] else None
    }
    barrier_timezones = [
        timezone
        for timezone in (
            "Etc/UTC",
            "Pacific/Kiritimati",
            "Pacific/Pago_Pago",
            "Europe/London"
        )
        if timezone not in excluded_timezones
    ][:2]
    wait_for_configured_timezone = "true"
    if configured_timezone["exists"] and configured_timezone["value"]:
        wait_for_configured_timezone = (
            "if timedatectl list-timezones | grep -Fxq -- {timezone}; "
            "then wait_for_timezone {timezone}; else true; fi"
        ).format(timezone=shlex.quote(configured_timezone["value"]))

    return """
monotonic_seconds() {{
    read -r uptime_seconds _ < /proc/uptime || return 1
    printf '%s\\n' "${{uptime_seconds%%.*}}"
}}
wait_for_timezone() {{
    expected_timezone=$1
    deadline=$(( $(monotonic_seconds) + {sync_timeout} ))
    while [ "$(timedatectl show --property=Timezone --value 2>/dev/null)" != "$expected_timezone" ]; do
        now=$(monotonic_seconds) || return 1
        [ "$now" -lt "$deadline" ] || return 1
        sleep 1
    done
}}
restore_timezone_config() {{
    {timezone_config_restore_command}
}}
finish_timezone_restore() {{
    script_result=$?
    trap - EXIT HUP INT TERM
    if [ "$timezone_recovery_complete" -ne 1 ]; then
        restore_timezone_config || script_result=1
        {wait_for_configured_timezone} || script_result=1
        timedatectl set-timezone {original_timezone} || script_result=1
        systemctl restart rsyslog || true
    fi
    exit "$script_result"
}}
timezone_recovery_complete=0
trap finish_timezone_restore EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
current_timezone=$(timedatectl show --property=Timezone --value) || exit 1
barrier_timezone=
for candidate in {barrier_timezone_1} {barrier_timezone_2}; do
    if [ "$current_timezone" != "$candidate" ] \
            && timedatectl list-timezones | grep -Fxq -- "$candidate"; then
        barrier_timezone=$candidate
        break
    fi
done
[ -n "$barrier_timezone" ] || exit 1
sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "timezone" "$barrier_timezone" || exit 1
wait_for_timezone "$barrier_timezone" || exit 1
restore_timezone_config || exit 1
{wait_for_configured_timezone} || exit 1
if timedatectl set-timezone {original_timezone}; then
    timezone_recovery_complete=1
else
    result=$?
fi
systemctl restart rsyslog || true
""".format(
        sync_timeout=CLOCK_TIMEZONE_SYNC_TIMEOUT,
        barrier_timezone_1=shlex.quote(barrier_timezones[0]),
        barrier_timezone_2=shlex.quote(barrier_timezones[1]),
        timezone_config_restore_command=_get_timezone_config_restore_command(
            configured_timezone
        ),
        wait_for_configured_timezone=wait_for_configured_timezone,
        original_timezone=shlex.quote(original_timezone)
    )


def _get_clock_offset(duthost, ntp_server):
    query = r"""timeout 10 python3 - %s <<'PY'
import socket
import struct
import sys
import time

NTP_EPOCH = 2208988800
server = sys.argv[1]


def pack_timestamp(value):
    seconds = int(value)
    fraction = int((value - seconds) * (1 << 32))
    return struct.pack("!II", seconds + NTP_EPOCH, fraction)


def unpack_timestamp(packet, offset):
    seconds, fraction = struct.unpack("!II", packet[offset:offset + 8])
    return seconds - NTP_EPOCH + fraction / float(1 << 32)


address = socket.getaddrinfo(server, 123, type=socket.SOCK_DGRAM)[0]
sock = socket.socket(address[0], address[1], address[2])
sock.settimeout(5)
sock.connect(address[4])
request = bytearray(48)
request[0] = 0x23
sent_at = time.time()
request[40:48] = pack_timestamp(sent_at)
sock.send(request)
response = sock.recv(512)
received_at = time.time()

if len(response) < 48:
    raise RuntimeError("Short NTP response: {} bytes".format(len(response)))
if response[0] & 0x7 != 4:
    raise RuntimeError("Unexpected NTP response mode: {}".format(response[0] & 0x7))
if not 1 <= response[1] <= 15:
    raise RuntimeError("Invalid NTP stratum: {}".format(response[1]))
if response[24:32] != request[40:48]:
    raise RuntimeError("NTP response originate timestamp does not match the request")

server_received_at = unpack_timestamp(response, 32)
server_sent_at = unpack_timestamp(response, 40)
offset = ((server_received_at - sent_at) + (server_sent_at - received_at)) / 2.0
print("{:.9f}".format(offset))
PY""" % shlex.quote(ntp_server)
    offset = float(duthost.shell(query)["stdout"].strip())
    return offset


def _clock_offset_is_safe(duthost, ntp_server, tolerance=CLOCK_OFFSET_TOLERANCE):
    offset = _get_clock_offset(duthost, ntp_server)
    logging.info(
        "Clock offset from NTP source %s: %.9fs (tolerance=%ss)",
        ntp_server,
        offset,
        tolerance
    )
    return abs(offset) <= tolerance


def _check_ntp_source(duthost, ntp_server):
    try:
        offset = _get_clock_offset(duthost, ntp_server)
    except (RunAnsibleModuleFail, ValueError) as error:
        logging.warning("NTP source %s is not reachable: %s", ntp_server, error)
        return False, "NTP source {} is not reachable".format(ntp_server)

    if abs(offset) > CLOCK_SOURCE_MAX_OFFSET:
        return False, (
            "NTP source {} differs from the DUT by {:.3f}s; "
            "refusing to change the DUT clock".format(ntp_server, offset)
        )

    logging.info(
        "Validated NTP source %s against the unmodified DUT clock: offset=%.9fs",
        ntp_server,
        offset
    )
    return True, None


def _validate_ntp_source(duthost, ntp_server):
    source_is_safe, failure_reason = _check_ntp_source(duthost, ntp_server)
    if not source_is_safe:
        pytest.skip(failure_reason)


def _require_recovery_tools(duthost, test_name):
    result = duthost.shell(
        "command -v systemd-run >/dev/null && "
        "command -v flock >/dev/null && "
        "command -v timeout >/dev/null",
        module_ignore_errors=True
    )
    if result["rc"] != 0:
        pytest.skip("{} requires systemd-run, flock, and timeout".format(test_name))


def _timezone_is_expected(duthosts, duthost, system_timezone, configured_timezone):
    return (
        ClockUtils.verify_timezone_value(
            duthosts,
            expected_tz_name=system_timezone
        )
        and _get_configured_timezone(duthost) == configured_timezone
    )


def _verify_timezone_restoration(duthosts, duthost, system_timezone, configured_timezone):
    assert wait_until(
        timeout=120,
        interval=5,
        delay=0,
        condition=_timezone_is_expected,
        duthosts=duthosts,
        duthost=duthost,
        system_timezone=system_timezone,
        configured_timezone=configured_timezone
    ), 'Timezone did not restore to "{}"'.format(system_timezone)
    time.sleep(CLOCK_POST_RESTORE_SETTLE_TIME)
    assert _timezone_is_expected(
        duthosts,
        duthost,
        system_timezone,
        configured_timezone
    ), 'Timezone restoration was not stable at "{}"'.format(system_timezone)


def _get_optional_ptfhost(request):
    try:
        return request.getfixturevalue("ptfhost")
    except (KeyError, pytest.FixtureLookupError) as error:
        logging.warning("No PTF host is defined for this testbed: %s", error)
        return None


@contextmanager
def _clock_ntp_source(request, duthost, recovery_state):
    configured_server = request.config.getoption("ntp_server")
    if configured_server:
        logging.info("Using NTP server from execution parameter: %s", configured_server)
        _validate_ntp_source(duthost, configured_server)
        yield configured_server
        return

    configured_source_failures = []
    ntp_servers = _get_ntp_config(duthost)
    for configured_server in ntp_servers:
        source_is_safe, failure_reason = _check_ntp_source(duthost, configured_server)
        if source_is_safe:
            logging.info("Using NTP server from DUT configuration: %s", configured_server)
            yield configured_server
            return
        configured_source_failures.append(failure_reason)
        logging.warning(
            "Configured DUT NTP server %s is unusable; trying the next recovery source",
            configured_server
        )

    ptfhost = _get_optional_ptfhost(request)
    if not ptfhost:
        if configured_source_failures:
            pytest.skip(
                "No safe configured NTP server is available, and this testbed has no PTF host: {}"
                .format("; ".join(configured_source_failures))
            )
        pytest.skip("No NTP server was supplied or configured, and this testbed has no PTF host")

    dut_facts = duthost.dut_basic_facts()["ansible_facts"]["dut_basic_facts"]
    ptf_use_ipv6 = dut_facts.get("is_mgmt_ipv6_only", False)
    if ptf_use_ipv6 and not ptfhost.mgmt_ipv6:
        pytest.skip("The DUT uses IPv6-only management but the PTF host has no IPv6 address")

    with setup_ntp_server_context(
        ptfhost,
        ptf_use_ipv6=ptf_use_ipv6,
        recovery_timeout=CLOCK_PTF_RECOVERY_TIMEOUT,
        recovery_state=recovery_state
    ) as ntp_server:
        logging.info(
            "Using temporary PTF %s NTP server: %s",
            "IPv6" if ptf_use_ipv6 else "IPv4",
            ntp_server
        )
        _validate_ntp_source(duthost, ntp_server)
        yield ntp_server


def _install_retry_watchdog(duthost, recovery):
    watchdog = """#!/bin/bash
monotonic_seconds() {{
    read -r uptime_seconds _ < /proc/uptime || return 1
    printf '%s\\n' "${{uptime_seconds%%.*}}"
}}
deadline=$(( $(monotonic_seconds) + {lease} ))
while true; do
    if [ ! -x {script_path} ]; then
        exit 0
    fi
    if timeout --kill-after={kill_after} {command_timeout} {script_path}; then
        exit 0
    fi
    now=$(monotonic_seconds) || exit 1
    if [ "$now" -ge "$deadline" ]; then
        exit 1
    fi
    sleep {retry_interval}
done
""".format(
        lease=CLOCK_RECOVERY_LEASE,
        kill_after=CLOCK_RECOVERY_KILL_AFTER,
        command_timeout=CLOCK_RECOVERY_COMMAND_TIMEOUT,
        script_path=shlex.quote(recovery["script_path"]),
        retry_interval=CLOCK_RECOVERY_RETRY_INTERVAL
    )
    duthost.copy(content=watchdog, dest=recovery["watchdog_path"], mode=0o755)


def _install_clock_recovery(duthost, ntp_daemon, ntp_server, service_name,
                            original_timezone, original_configured_timezone,
                            original_service_active):
    recovery_id = uuid.uuid4().hex
    unit_name = "sonic-mgmt-clock-recovery-{}".format(recovery_id)
    script_path = "/tmp/{}.sh".format(unit_name)
    watchdog_path = "/tmp/{}-watchdog.sh".format(unit_name)
    ntp_conf_path = "/tmp/{}.conf".format(unit_name)
    lock_path = "/run/{}.lock".format(unit_name)

    prepare_ntp_one_shot_config(
        duthost,
        ntp_daemon,
        ntp_server,
        ntp_conf_path
    )
    sync_command = get_ntp_one_shot_command(
        duthost,
        ntp_daemon,
        ntp_server,
        ntp_conf_path
    )

    service_restore_command = (
        "systemctl start {}".format(shlex.quote(service_name))
        if original_service_active == "active"
        else "systemctl stop {}".format(shlex.quote(service_name))
    )
    timezone_restore_commands = _get_timezone_restore_commands(
        original_timezone,
        original_configured_timezone
    )
    script = """#!/bin/bash
result=0
exec 9>{lock_path}
flock -w {lock_timeout} -x 9 || exit 75
restore_ntp_service() {{
    {service_restore_command}
}}
finish_ntp_service_restore() {{
    script_result=$?
    trap - EXIT HUP INT TERM
    if [ "$ntp_service_restored" -ne 1 ]; then
        restore_ntp_service || script_result=1
    fi
    exit "$script_result"
}}
ntp_service_restored=0
trap finish_ntp_service_restore EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
systemctl stop {service_name} || result=$?
sync_succeeded=0
if {sync_command}; then
    sync_succeeded=1
else
    result=$?
fi
if [ "$sync_succeeded" -eq 1 ] && command -v hwclock >/dev/null 2>&1; then
    if hwclock --show >/dev/null 2>&1; then
        hwclock --systohc || result=$?
    else
        echo "No accessible RTC; skipping RTC synchronization"
    fi
fi
if restore_ntp_service; then
    ntp_service_restored=1
    trap - EXIT HUP INT TERM
else
    result=$?
    exit "$result"
fi
{timezone_restore_commands}
exit $result
""".format(
        lock_path=shlex.quote(lock_path),
        lock_timeout=CLOCK_RECOVERY_LOCK_TIMEOUT,
        service_name=shlex.quote(service_name),
        sync_command=sync_command,
        timezone_restore_commands=timezone_restore_commands,
        service_restore_command=service_restore_command
    )
    duthost.copy(content=script, dest=script_path, mode=0o755)

    recovery = {
        "unit_name": unit_name,
        "script_path": script_path,
        "watchdog_path": watchdog_path,
        "ntp_conf_path": ntp_conf_path,
        "lock_path": lock_path,
        "timer_units": [],
        "current_timer_unit": None
    }
    _install_retry_watchdog(duthost, recovery)
    return recovery


def _install_timezone_recovery(duthost, original_timezone, original_configured_timezone):
    recovery_id = uuid.uuid4().hex
    unit_name = "sonic-mgmt-timezone-recovery-{}".format(recovery_id)
    script_path = "/tmp/{}.sh".format(unit_name)
    watchdog_path = "/tmp/{}-watchdog.sh".format(unit_name)
    lock_path = "/run/{}.lock".format(unit_name)
    timezone_restore_commands = _get_timezone_restore_commands(
        original_timezone,
        original_configured_timezone
    )
    script = """#!/bin/bash
result=0
exec 9>{lock_path}
flock -w {lock_timeout} -x 9 || exit 75
{timezone_restore_commands}
exit $result
""".format(
        lock_path=shlex.quote(lock_path),
        lock_timeout=CLOCK_RECOVERY_LOCK_TIMEOUT,
        timezone_restore_commands=timezone_restore_commands
    )
    duthost.copy(content=script, dest=script_path, mode=0o755)

    recovery = {
        "unit_name": unit_name,
        "script_path": script_path,
        "watchdog_path": watchdog_path,
        "lock_path": lock_path,
        "timer_units": [],
        "current_timer_unit": None
    }
    _install_retry_watchdog(duthost, recovery)
    return recovery


def _arm_recovery(duthost, recovery):
    previous_timer_unit = recovery["current_timer_unit"]
    timer_unit = "{}-{}".format(recovery["unit_name"], uuid.uuid4().hex[:8])
    runtime_max = (
        CLOCK_RECOVERY_LEASE
        + CLOCK_RECOVERY_COMMAND_TIMEOUT
        + CLOCK_RECOVERY_KILL_AFTER
        + (2 * CLOCK_RECOVERY_RETRY_INTERVAL)
    )
    recovery["timer_units"].append(timer_unit)
    recovery["current_timer_unit"] = timer_unit
    duthost.command(
        "systemd-run --unit={} --on-active={}s "
        "--timer-property=AccuracySec=1s --property=RuntimeMaxSec={}s {}".format(
            shlex.quote(timer_unit),
            CLOCK_RECOVERY_TIMEOUT,
            runtime_max,
            shlex.quote(recovery["watchdog_path"])
        )
    )
    if previous_timer_unit:
        duthost.shell(
            """systemctl stop {unit}.timer 2>/dev/null || true
for _ in 1 2 3 4 5; do
    timer_load=$(systemctl show {unit}.timer --property=LoadState --value 2>/dev/null) || exit 1
    timer_active=$(systemctl show {unit}.timer --property=ActiveState --value 2>/dev/null) || exit 1
    service_load=$(systemctl show {unit}.service --property=LoadState --value 2>/dev/null) || exit 1
    service_active=$(systemctl show {unit}.service --property=ActiveState --value 2>/dev/null) || exit 1
    if {{ [ "$timer_load" = "not-found" ] || [ "$timer_active" = "inactive" ]; }} \
            && {{ [ "$service_load" = "not-found" ] || [ "$service_active" = "inactive" ]; }}; then
        systemctl reset-failed {unit}.timer {unit}.service 2>/dev/null || true
        exit 0
    fi
    sleep 1
done
exit 1
""".format(unit=shlex.quote(previous_timer_unit))
        )


def _run_recovery(duthost, recovery):
    duthost.command(
        "timeout --kill-after={} {} {}".format(
            CLOCK_RECOVERY_KILL_AFTER,
            CLOCK_RECOVERY_COMMAND_TIMEOUT,
            shlex.quote(recovery["script_path"])
        )
    )


def _remove_recovery(duthost, recovery):
    cleanup_paths = [
        recovery["script_path"],
        recovery["watchdog_path"],
        recovery["lock_path"]
    ]
    if recovery.get("ntp_conf_path"):
        cleanup_paths.append(recovery["ntp_conf_path"])

    timer_units = " ".join(shlex.quote(unit) for unit in recovery["timer_units"])
    result = duthost.shell(
        """cleanup_ok=1
unit_is_stopped() {{
    load_state=$(systemctl show "$1" --property=LoadState --value 2>/dev/null) || return 1
    active_state=$(systemctl show "$1" --property=ActiveState --value 2>/dev/null) || return 1
    [ "$load_state" = "not-found" ] || [ "$active_state" = "inactive" ] || [ "$active_state" = "failed" ]
}}
for unit in {timer_units}; do
    systemctl stop "$unit.timer" 2>/dev/null || true
    stopped=0
    for _ in 1 2 3 4 5; do
        if unit_is_stopped "$unit.timer" && unit_is_stopped "$unit.service"; then
            stopped=1
            break
        fi
        sleep 1
    done
    if [ "$stopped" -ne 1 ]; then
        cleanup_ok=0
    fi
done
if [ "$cleanup_ok" -ne 1 ]; then
    exit 1
fi
for unit in {timer_units}; do
    systemctl reset-failed "$unit.timer" "$unit.service" 2>/dev/null || true
done
rm -f {cleanup_paths}
""".format(
            timer_units=timer_units,
            cleanup_paths=" ".join(shlex.quote(path) for path in cleanup_paths)
        ),
        module_ignore_errors=True
    )
    cleanup_succeeded = result["rc"] == 0
    if cleanup_succeeded:
        recovery["current_timer_unit"] = None
        recovery["timer_units"] = []
    return cleanup_succeeded


def _try_refresh_ptf_recovery(recovery_state):
    refresh_ptf_recovery = recovery_state.get("refresh")
    if not refresh_ptf_recovery:
        return True

    try:
        refresh_ptf_recovery()
        return True
    except RECOVERY_REFRESH_ERRORS:
        recovery_state["defer_cleanup"] = True
        logging.exception("Failed to refresh the PTF NTP recovery watchdog")
        return False


def _verify_clock_restoration(duthosts, duthost, ntp_server,
                              original_timezone, original_configured_timezone,
                              original_ntp_config, service_name, original_service_active,
                              original_service_enabled):
    assert wait_until(
        timeout=60,
        interval=5,
        delay=0,
        condition=_clock_offset_is_safe,
        duthost=duthost,
        ntp_server=ntp_server
    ), "DUT clock was not restored within {} seconds of the trusted source".format(
        CLOCK_OFFSET_TOLERANCE
    )
    assert ClockUtils.get_timezone_name(duthosts) == original_timezone, \
        "Timezone was not restored to {}".format(original_timezone)
    ClockUtils.verify_timezone_value(duthosts, expected_tz_name=original_timezone)
    assert _get_configured_timezone(duthost) == original_configured_timezone, \
        "Configured timezone changed during clock restoration"
    assert _get_ntp_config(duthost) == original_ntp_config, \
        "NTP configuration changed during clock restoration"
    assert _get_systemd_property(duthost, service_name, "ActiveState") == original_service_active, \
        "{} active state was not restored".format(service_name)
    assert _get_systemd_property(duthost, service_name, "UnitFileState") == original_service_enabled, \
        "{} enabled state was not restored".format(service_name)


def _verify_clock_restoration_stable(*args):
    _verify_clock_restoration(*args)
    time.sleep(CLOCK_POST_RESTORE_SETTLE_TIME)
    _verify_clock_restoration(*args)


@pytest.fixture(scope="function")
def init_timezone(duthosts):
    """
    @summary: fixture to init timezone before and after each test
    """
    duthost = duthosts[0]
    logging.info('Check current timezone before test')
    original_timezone = ClockUtils.get_timezone_name(duthosts)
    original_configured_timezone = _get_configured_timezone(duthost)
    logging.info(f'Original timezone: {original_timezone}')
    _require_recovery_tools(duthost, "Clock timezone testing")
    recovery = _install_timezone_recovery(
        duthost,
        original_timezone,
        original_configured_timezone
    )
    recovery_verified = False

    def refresh_recovery():
        _arm_recovery(duthost, recovery)

    try:
        refresh_recovery()
        logging.info(f'Set timezone to {ClockConsts.TEST_TIMEZONE} before test')
        ClockUtils.run_cmd(
            duthosts,
            ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE,
            ClockConsts.TEST_TIMEZONE,
            raise_err=True
        )
        assert wait_until(
            timeout=120,
            interval=5,
            delay=0,
            condition=lambda: ClockUtils.verify_timezone_value(
                duthosts,
                expected_tz_name=ClockConsts.TEST_TIMEZONE
            )
        ), f'Timezone did not change to "{ClockConsts.TEST_TIMEZONE}"'

        refresh_recovery()
        yield refresh_recovery
    finally:
        try:
            try:
                _arm_recovery(duthost, recovery)
            except RECOVERY_REFRESH_ERRORS:
                logging.exception("Failed to refresh the timezone recovery timer")

            _run_recovery(duthost, recovery)
            _verify_timezone_restoration(
                duthosts,
                duthost,
                original_timezone,
                original_configured_timezone
            )
            recovery_verified = True
        finally:
            if recovery_verified:
                assert _remove_recovery(duthost, recovery), \
                    "Failed to confirm timezone recovery timer cancellation"


@pytest.fixture(scope="function")
def restore_time(request, duthosts):
    """Restore date, timezone, NTP configuration, and daemon state after the test."""
    duthost = duthosts[0]
    ntp_daemon = get_ntp_daemon_in_use(duthost)
    service_name = get_ntp_service_name(ntp_daemon)
    original_timezone = ClockUtils.get_timezone_name(duthosts)
    original_configured_timezone = _get_configured_timezone(duthost)
    original_ntp_config = _get_ntp_config(duthost)
    original_service_active = _get_systemd_property(duthost, service_name, "ActiveState")
    original_service_enabled = _get_systemd_property(duthost, service_name, "UnitFileState")

    _require_recovery_tools(duthost, "Clock date testing")

    ntp_source_state = {"defer_cleanup": False}
    with _clock_ntp_source(request, duthost, ntp_source_state) as ntp_server:
        recovery = _install_clock_recovery(
            duthost,
            ntp_daemon,
            ntp_server,
            service_name,
            original_timezone,
            original_configured_timezone,
            original_service_active
        )
        recovery_status = {"armed": False}

        def refresh_recovery():
            recovery_status["armed"] = True
            if ntp_source_state.get("refresh"):
                ntp_source_state["defer_cleanup"] = True
            _arm_recovery(duthost, recovery)
            refresh_ptf_recovery = ntp_source_state.get("refresh")
            if refresh_ptf_recovery:
                refresh_ptf_recovery()

        try:
            refresh_recovery()

            # Prove the exact recovery command before any date mutation.
            _run_recovery(duthost, recovery)
            _verify_clock_restoration_stable(
                duthosts,
                duthost,
                ntp_server,
                original_timezone,
                original_configured_timezone,
                original_ntp_config,
                service_name,
                original_service_active,
                original_service_enabled
            )

            refresh_recovery()
            duthost.service(name=service_name, state="stopped")

            yield refresh_recovery
        finally:
            recovery_verified = False
            try:
                if recovery_status["armed"]:
                    try:
                        _arm_recovery(duthost, recovery)
                        recovery_status["armed"] = True
                    except RECOVERY_REFRESH_ERRORS:
                        logging.exception("Failed to refresh the clock recovery timer")
                    _try_refresh_ptf_recovery(ntp_source_state)

                _run_recovery(duthost, recovery)
                _verify_clock_restoration_stable(
                    duthosts,
                    duthost,
                    ntp_server,
                    original_timezone,
                    original_configured_timezone,
                    original_ntp_config,
                    service_name,
                    original_service_active,
                    original_service_enabled
                )
                recovery_verified = True
            finally:
                if recovery_verified:
                    cleanup_verified = _remove_recovery(duthost, recovery)
                    if cleanup_verified:
                        recovery_status["armed"] = False
                        ntp_source_state["defer_cleanup"] = False
                    else:
                        ntp_source_state["defer_cleanup"] = bool(
                            recovery_status["armed"] and ntp_source_state.get("refresh")
                        )
                        pytest.fail("Failed to confirm clock recovery timer cancellation")
                elif recovery_status["armed"] and ntp_source_state.get("refresh"):
                    ntp_source_state["defer_cleanup"] = True
