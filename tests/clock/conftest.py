import json
import shlex
import uuid
from contextlib import contextmanager

import pytest
import logging

from tests.clock.test_clock import ClockConsts, ClockUtils
from tests.common.helpers.ntp_helper import (
    get_ntp_daemon_in_use,
    get_ntp_one_shot_command,
    get_ntp_service_name,
    prepare_ntp_one_shot_config,
    setup_ntp_server_context
)
from tests.common.utilities import wait_until


CLOCK_RECOVERY_TIMEOUT = 300
CLOCK_RECOVERY_COMMAND_TIMEOUT = 120
CLOCK_RECOVERY_LEASE = 1800
CLOCK_RECOVERY_RETRY_INTERVAL = 60
CLOCK_OFFSET_TOLERANCE = 5
CLOCK_PTF_RECOVERY_TIMEOUT = 3600


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


def _clock_offset_is_safe(duthost, ntp_server):
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
    logging.info(
        "Clock offset from NTP source %s: %.9fs (tolerance=%ss)",
        ntp_server,
        offset,
        CLOCK_OFFSET_TOLERANCE
    )
    return abs(offset) <= CLOCK_OFFSET_TOLERANCE


@contextmanager
def _clock_ntp_source(request, ptfhost, recovery_state):
    configured_server = request.config.getoption("ntp_server")
    if configured_server:
        logging.info("Using NTP server from execution parameter: %s", configured_server)
        yield configured_server
        return

    with setup_ntp_server_context(
        ptfhost,
        ptf_use_ipv6=False,
        recovery_timeout=CLOCK_PTF_RECOVERY_TIMEOUT,
        recovery_state=recovery_state
    ) as ntp_server:
        logging.info("Using temporary PTF NTP server: %s", ntp_server)
        yield ntp_server


def _install_clock_recovery(duthost, ntp_daemon, ntp_server, service_name,
                            original_timezone, original_service_active):
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
    script = """#!/bin/bash
result=0
exec 9>{lock_path}
flock -x 9
systemctl stop {service_name} || result=$?
sync_succeeded=0
if {sync_command}; then
    sync_succeeded=1
else
    result=$?
fi
timedatectl set-timezone {timezone} || result=$?
if [ "$sync_succeeded" -eq 1 ] && command -v hwclock >/dev/null 2>&1; then
    if hwclock --show >/dev/null 2>&1; then
        hwclock --systohc || result=$?
    else
        echo "No accessible RTC; skipping RTC synchronization"
    fi
fi
{service_restore_command} || result=$?
exit $result
""".format(
        lock_path=shlex.quote(lock_path),
        service_name=shlex.quote(service_name),
        sync_command=sync_command,
        timezone=shlex.quote(original_timezone),
        service_restore_command=service_restore_command
    )
    duthost.copy(content=script, dest=script_path, mode=0o755)

    watchdog = """#!/bin/bash
deadline=$((SECONDS + {lease}))
while true; do
    if {script_path}; then
        rm -f {script_path} {config_path} {lock_path} {watchdog_path}
        exit 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        exit 1
    fi
    sleep {retry_interval}
done
""".format(
        lease=CLOCK_RECOVERY_LEASE,
        script_path=shlex.quote(script_path),
        config_path=shlex.quote(ntp_conf_path),
        lock_path=shlex.quote(lock_path),
        watchdog_path=shlex.quote(watchdog_path),
        retry_interval=CLOCK_RECOVERY_RETRY_INTERVAL
    )
    duthost.copy(content=watchdog, dest=watchdog_path, mode=0o755)

    return {
        "unit_name": unit_name,
        "script_path": script_path,
        "watchdog_path": watchdog_path,
        "ntp_conf_path": ntp_conf_path,
        "lock_path": lock_path
    }


def _arm_clock_recovery(duthost, recovery):
    duthost.command(
        "systemd-run --unit={} --on-active={}s --timer-property=AccuracySec=1s {}".format(
            shlex.quote(recovery["unit_name"]),
            CLOCK_RECOVERY_TIMEOUT,
            shlex.quote(recovery["watchdog_path"])
        )
    )


def _rearm_clock_recovery(duthost, recovery):
    duthost.command(
        "systemctl restart {}.timer".format(shlex.quote(recovery["unit_name"]))
    )


def _run_clock_recovery(duthost, recovery):
    duthost.command(
        "timeout {} {}".format(
            CLOCK_RECOVERY_COMMAND_TIMEOUT,
            shlex.quote(recovery["script_path"])
        )
    )


def _remove_clock_recovery(duthost, recovery):
    duthost.shell(
        "systemctl stop {unit}.timer {unit}.service 2>/dev/null || true; "
        "systemctl reset-failed {unit}.service 2>/dev/null || true; "
        "rm -f {script} {watchdog} {config} {lock}".format(
            unit=shlex.quote(recovery["unit_name"]),
            script=shlex.quote(recovery["script_path"]),
            watchdog=shlex.quote(recovery["watchdog_path"]),
            config=shlex.quote(recovery["ntp_conf_path"]),
            lock=shlex.quote(recovery["lock_path"])
        )
    )


def _verify_clock_restoration(duthosts, duthost, ntp_server,
                              original_timezone, original_ntp_config, service_name,
                              original_service_active, original_service_enabled):
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
    assert _get_ntp_config(duthost) == original_ntp_config, \
        "NTP configuration changed during clock restoration"
    assert _get_systemd_property(duthost, service_name, "ActiveState") == original_service_active, \
        "{} active state was not restored".format(service_name)
    assert _get_systemd_property(duthost, service_name, "UnitFileState") == original_service_enabled, \
        "{} enabled state was not restored".format(service_name)


@pytest.fixture(scope="function")
def init_timezone(duthosts):
    """
    @summary: fixture to init timezone before and after each test
    """
    logging.info('Check current timezone before test')
    original_timezone = ClockUtils.get_timezone_name(duthosts)
    logging.info(f'Original timezone: {original_timezone}')

    try:
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

        yield
    finally:
        logging.info(f'Set timezone to {original_timezone} after test')
        ClockUtils.run_cmd(
            duthosts,
            ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE,
            original_timezone,
            raise_err=True
        )
        assert wait_until(
            timeout=120,
            interval=5,
            delay=0,
            condition=lambda: ClockUtils.verify_timezone_value(
                duthosts,
                expected_tz_name=original_timezone
            )
        ), f'Timezone did not restore to "{original_timezone}"'


@pytest.fixture(scope="function")
def restore_time(request, duthosts, ptfhost):
    """Restore date, timezone, NTP configuration, and daemon state after the test."""
    duthost = duthosts[0]
    ntp_daemon = get_ntp_daemon_in_use(duthost)
    service_name = get_ntp_service_name(ntp_daemon)
    original_timezone = ClockUtils.get_timezone_name(duthosts)
    original_ntp_config = _get_ntp_config(duthost)
    original_service_active = _get_systemd_property(duthost, service_name, "ActiveState")
    original_service_enabled = _get_systemd_property(duthost, service_name, "UnitFileState")

    duthost.shell("command -v systemd-run >/dev/null && command -v flock >/dev/null")

    ntp_source_state = {"defer_cleanup": False}
    with _clock_ntp_source(request, ptfhost, ntp_source_state) as ntp_server:
        recovery = _install_clock_recovery(
            duthost,
            ntp_daemon,
            ntp_server,
            service_name,
            original_timezone,
            original_service_active
        )
        recovery_armed = False
        try:
            # Prove the exact recovery command and trusted source before any date mutation.
            _run_clock_recovery(duthost, recovery)
            _verify_clock_restoration(
                duthosts,
                duthost,
                ntp_server,
                original_timezone,
                original_ntp_config,
                service_name,
                original_service_active,
                original_service_enabled
            )

            _arm_clock_recovery(duthost, recovery)
            recovery_armed = True
            duthost.service(name=service_name, state="stopped")

            yield
        finally:
            recovery_verified = False
            try:
                if recovery_armed:
                    _rearm_clock_recovery(duthost, recovery)

                _run_clock_recovery(duthost, recovery)
                _verify_clock_restoration(
                    duthosts,
                    duthost,
                    ntp_server,
                    original_timezone,
                    original_ntp_config,
                    service_name,
                    original_service_active,
                    original_service_enabled
                )
                recovery_verified = True
            finally:
                if recovery_verified:
                    _remove_clock_recovery(duthost, recovery)
                else:
                    ntp_source_state["defer_cleanup"] = True
