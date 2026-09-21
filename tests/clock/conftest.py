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
CLOCK_OFFSET_TOLERANCE = 5


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
request = bytearray(48)
request[0] = 0x23
sent_at = time.time()
request[40:48] = pack_timestamp(sent_at)
sock.sendto(request, address[4])
response, _ = sock.recvfrom(512)
received_at = time.time()

if len(response) < 48:
    raise RuntimeError("Short NTP response: {} bytes".format(len(response)))
if response[0] & 0x7 not in (4, 5):
    raise RuntimeError("Unexpected NTP response mode: {}".format(response[0] & 0x7))
if not 1 <= response[1] <= 15:
    raise RuntimeError("Invalid NTP stratum: {}".format(response[1]))

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
def _clock_ntp_source(request, ptfhost):
    configured_server = request.config.getoption("ntp_server")
    if configured_server:
        logging.info("Using NTP server from execution parameter: %s", configured_server)
        yield configured_server
        return

    with setup_ntp_server_context(ptfhost, ptf_use_ipv6=False) as ntp_server:
        logging.info("Using temporary PTF NTP server: %s", ntp_server)
        yield ntp_server


def _install_clock_recovery(duthost, ntp_daemon, ntp_server, service_name,
                            original_timezone, original_service_active):
    recovery_id = uuid.uuid4().hex
    unit_name = "sonic-mgmt-clock-recovery-{}".format(recovery_id)
    script_path = "/tmp/{}.sh".format(unit_name)
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
{sync_command} || result=$?
timedatectl set-timezone {timezone} || result=$?
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

    return {
        "unit_name": unit_name,
        "script_path": script_path,
        "ntp_conf_path": ntp_conf_path,
        "lock_path": lock_path
    }


def _arm_clock_recovery(duthost, recovery):
    duthost.command(
        "systemd-run --unit={} --on-active={}s --timer-property=AccuracySec=1s {}".format(
            shlex.quote(recovery["unit_name"]),
            CLOCK_RECOVERY_TIMEOUT,
            shlex.quote(recovery["script_path"])
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
        "rm -f {script} {config} {lock}".format(
            unit=shlex.quote(recovery["unit_name"]),
            script=shlex.quote(recovery["script_path"]),
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

    with _clock_ntp_source(request, ptfhost) as ntp_server:
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
            finally:
                _remove_clock_recovery(duthost, recovery)
