import ipaddress
import re
import shlex
import uuid
from contextlib import contextmanager

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.ntp_helper import (
    NtpDaemon,
    check_max_root_dispersion,
    check_ntp_status,
    get_ntp_daemon_in_use
)
from tests.common.utilities import wait_until


NTP_SERVER_RECOVERY_TIMEOUT = 86400
NTP_SERVER_RECOVERY_LEASE = 1800
NTP_SERVER_RECOVERY_RETRY_INTERVAL = 60
NTP_SERVER_RECOVERY_COMMAND_TIMEOUT = 120
NTP_SERVER_LOCK_TIMEOUT = 30
NTP_SERVER_WATCHDOG_POLL_INTERVAL = 60


def _get_ntp_watchdog_identity_commands(recovery):
    """Return shell helpers for a watchdog's immutable process identity."""
    return """\
monotonic_seconds() {{
    read -r uptime_seconds _ < /proc/uptime || return 1
    printf '%s\\n' "${{uptime_seconds%%.*}}"
}}
process_identity() {{
    identity_pid=$1
    case "$identity_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$identity_pid" -gt 0 ] || return 1
    identity_stat=$(cat "/proc/$identity_pid/stat" 2>/dev/null) || return 1
    identity_fields=${{identity_stat##*) }}
    [ "$identity_fields" != "$identity_stat" ] || return 1
    set -f
    set -- $identity_fields
    [ "$#" -ge 20 ] || return 1
    case "$1" in Z|X|x) return 1 ;; esac
    shift 19
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    identity_boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    [ -n "$identity_boot" ] || return 1
    printf '%s %s %s %s\\n' "$identity_pid" "$1" "$identity_boot" {recovery_id}
}}
watchdog_is_live() {{
    recorded_identity=$(cat {pid} 2>/dev/null) || return 1
    set -f
    set -- $recorded_identity
    [ "$#" -eq 4 ] || return 1
    [ "$4" = {recovery_id} ] || return 1
    current_identity=$(process_identity "$1") || return 1
    [ "$recorded_identity" = "$current_identity" ]
}}
""".format(
        pid=shlex.quote(recovery["pid_path"]),
        recovery_id=shlex.quote(recovery["recovery_id"])
    )


def _retire_ntp_server_recovery(ptfhost, recovery):
    """Wait for an owner-fenced watchdog without signalling a numeric PID."""
    ptfhost.shell(
        """\
{identity_commands}
exec 9>{lock}
flock -w {lock_timeout} -x 9 || exit 75
if [ -s {owner} ] && [ "$(cat {owner})" = {recovery_id} ]; then
    echo 'Cannot retire an unrestored PTF NTP context' >&2
    exit 1
fi
flock -u 9
exec 9>&-
now=$(monotonic_seconds) || exit 1
retirement_deadline=$(( now + {retirement_timeout} ))
while watchdog_is_live; do
    now=$(monotonic_seconds) || exit 1
    if [ "$now" -ge "$retirement_deadline" ]; then
        echo 'PTF NTP recovery watchdog did not retire' >&2
        exit 1
    fi
    sleep 1
done
rm -f {script} {pid} {pid_tmp} {deadline} {deadline_tmp} {backup} {owner_tmp}
""".format(
            identity_commands=_get_ntp_watchdog_identity_commands(recovery),
            lock=shlex.quote(recovery["lock_path"]),
            lock_timeout=NTP_SERVER_LOCK_TIMEOUT,
            owner=shlex.quote(recovery["owner_path"]),
            recovery_id=shlex.quote(recovery["recovery_id"]),
            retirement_timeout=NTP_SERVER_WATCHDOG_POLL_INTERVAL + NTP_SERVER_LOCK_TIMEOUT + 5,
            script=shlex.quote(recovery["script_path"]),
            pid=shlex.quote(recovery["pid_path"]),
            pid_tmp=shlex.quote("{}.tmp".format(recovery["pid_path"])),
            deadline=shlex.quote(recovery["deadline_path"]),
            deadline_tmp=shlex.quote("{}.tmp".format(recovery["deadline_path"])),
            backup=shlex.quote(recovery["backup_path"]),
            owner_tmp=shlex.quote("{}.{}.tmp".format(recovery["owner_path"], recovery["recovery_id"]))
        )
    )


def normalize_ntp_server(ntp_server):
    """Validate and normalize an NTP server IP address or hostname."""
    ntp_server = str(ntp_server).strip()
    if not ntp_server:
        raise ValueError("NTP server must not be empty")

    try:
        return str(ipaddress.ip_address(ntp_server))
    except ValueError:
        if len(ntp_server) > 253 or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", ntp_server):
            raise ValueError("Invalid NTP server: {}".format(ntp_server))
        return ntp_server


def get_ntp_service_name(ntp_daemon_type):
    if ntp_daemon_type == NtpDaemon.NTPSEC:
        return 'ntpsec'
    if ntp_daemon_type == NtpDaemon.CHRONY:
        return 'chrony'
    if ntp_daemon_type == NtpDaemon.NTP:
        return 'ntp'
    raise ValueError("Unsupported NTP daemon type: {}".format(ntp_daemon_type))


def get_ntp_config_path(ntp_daemon_type):
    if ntp_daemon_type == NtpDaemon.NTPSEC:
        return '/etc/ntpsec/ntp.conf'
    if ntp_daemon_type == NtpDaemon.CHRONY:
        return '/etc/chrony/chrony.conf'
    if ntp_daemon_type == NtpDaemon.NTP:
        return '/etc/ntp.conf'
    raise ValueError("Unsupported NTP daemon type: {}".format(ntp_daemon_type))


def _configure_ntp_server(ptfhost, ntp_daemon_type, ntp_conf_path, ptf_use_ipv6):
    if ntp_daemon_type in (NtpDaemon.NTPSEC, NtpDaemon.NTP):
        res = ptfhost.command("ip link show mgmt", module_ignore_errors=True)
        if res.get("rc", 1) == 0:
            ptfhost.lineinfile(path=ntp_conf_path, line="interface ignore wildcard")
            ptfhost.lineinfile(path=ntp_conf_path, line="interface listen mgmt")
            if ptf_use_ipv6 and ptfhost.mgmt_ipv6:
                ptfhost.lineinfile(path=ntp_conf_path, line="interface listen %s" % ptfhost.mgmt_ipv6)

    if ntp_daemon_type == NtpDaemon.NTPSEC:
        ptfhost.lineinfile(path=ntp_conf_path, line="refclock local stratum 3 prefer",
                           regexp="^(server 127\\.127\\.1\\.0|refclock local)")
        ptfhost.lineinfile(path=ntp_conf_path, line="restrict 127.0.0.1")
        ptfhost.lineinfile(path=ntp_conf_path, line="restrict ::1")
    elif ntp_daemon_type == NtpDaemon.CHRONY:
        ptfhost.lineinfile(path=ntp_conf_path, line="local stratum 3", regexp="^local\\s+stratum\\s+")
        ptfhost.lineinfile(path=ntp_conf_path, line="allow all", regexp="^allow\\s+")
    else:
        ptfhost.lineinfile(path=ntp_conf_path, line="server 127.127.1.0 prefer")

    for pool in range(4):
        ptfhost.lineinfile(
            path=ntp_conf_path,
            line="#pool {}.debian.pool.ntp.org iburst".format(pool),
            regexp="^pool.*{}\\.debian.*pool.*ntp.*org.*".format(pool)
        )

    ptfhost.lineinfile(
        path=ntp_conf_path,
        line="#tos minclock 4 minsane 3",
        regexp="^tos.*minclock.*minsane.*"
    )


def _install_ntp_server_recovery(ptfhost, ntp_service_name, ntp_conf_path,
                                 ntp_conf_backup_path, ntp_service_was_active,
                                 recovery_timeout):
    recovery_id = uuid.uuid4().hex
    script_path = "/tmp/sonic-mgmt-ntp-server-recovery-{}.sh".format(recovery_id)
    pid_path = "/tmp/sonic-mgmt-ntp-server-recovery-{}.pid".format(recovery_id)
    deadline_path = "/tmp/sonic-mgmt-ntp-server-recovery-{}.deadline".format(recovery_id)
    deadline_tmp_path = "{}.tmp".format(deadline_path)
    owner_path = "/tmp/sonic-mgmt-ntp-server-{}.owner".format(ntp_service_name)
    owner_tmp_path = "{}.{}.tmp".format(owner_path, recovery_id)
    lock_path = "/tmp/sonic-mgmt-ntp-server-{}.lock".format(ntp_service_name)
    recovery = {
        "script_path": script_path,
        "pid_path": pid_path,
        "deadline_path": deadline_path,
        "backup_path": ntp_conf_backup_path,
        "owner_path": owner_path,
        "recovery_id": recovery_id,
        "lock_path": lock_path,
        "recovery_timeout": recovery_timeout,
    }
    identity_commands = _get_ntp_watchdog_identity_commands(recovery)

    service_restore_command = (
        "service {} restart".format(shlex.quote(ntp_service_name))
        if ntp_service_was_active
        else "service {} stop".format(shlex.quote(ntp_service_name))
    )
    script = """#!/bin/bash
result=0
if [ "${{SONIC_MGMT_NTP_LOCK_HELD:-0}}" -ne 1 ]; then
    exec 9>{lock_path}
    flock -w {lock_timeout} -x 9 || exit 75
fi
if [ ! -s {owner_path} ] || [ "$(cat {owner_path})" != {recovery_id} ]; then
    exit 0
fi
if [ ! -e {backup_path} ]; then
    echo "NTP configuration backup is missing: {backup_path}" >&2
    exit 1
fi
service {service_name} stop || true
cp -a {backup_path} {config_path} || result=$?
{service_restore_command} || result=$?
if [ "$result" -eq 0 ]; then
    rm -f {owner_path}
fi
exit $result
""".format(
        lock_path=shlex.quote(lock_path),
        lock_timeout=NTP_SERVER_LOCK_TIMEOUT,
        owner_path=shlex.quote(owner_path),
        recovery_id=shlex.quote(recovery_id),
        service_name=shlex.quote(ntp_service_name),
        backup_path=shlex.quote(ntp_conf_backup_path),
        config_path=shlex.quote(ntp_conf_path),
        service_restore_command=service_restore_command
    )
    try:
        ptfhost.copy(content=script, dest=script_path, mode=0o755)
        watchdog_command = """\
{identity_commands}
self_identity=''
finish_watchdog() {{
    watchdog_result=$?
    trap - EXIT HUP INT TERM
    if [ -n "$self_identity" ] && [ "$(cat {pid} 2>/dev/null)" = "$self_identity" ]; then
        rm -f {pid}
    fi
    rm -f {pid_tmp}
    if [ "$watchdog_result" -eq 0 ]; then
        rm -f {script} {deadline} {backup} {owner_tmp}
    else
        echo "PTF NTP recovery watchdog exited with status $watchdog_result; recovery state retained" >&2
    fi
    exit "$watchdog_result"
}}
trap finish_watchdog EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
exec 9>{lock}
flock -w {lock_timeout} -x 9 || exit 75
if [ ! -s {owner} ] || [ "$(cat {owner})" != {recovery_id} ]; then
    exit 0
fi
self_identity=$(process_identity "$$") || exit 1
printf '%s\\n' "$self_identity" > {pid_tmp} && mv -f {pid_tmp} {pid} || exit 1
flock -u 9
exec 9>&-
retry_deadline=0
while true; do
    exec 9>{lock}
    if ! flock -w {lock_timeout} -x 9; then
        exec 9>&-
        deadline=$(cat {deadline}) || exit 1
        now=$(monotonic_seconds) || exit 1
        if [ "$now" -lt "$deadline" ]; then
            retry_deadline=0
        elif [ "$retry_deadline" -eq 0 ]; then
            retry_deadline=$(( now + {lease} ))
        elif [ "$now" -ge "$retry_deadline" ]; then
            exit 1
        fi
        continue
    fi
    if [ ! -s {owner} ] || [ "$(cat {owner})" != {recovery_id} ]; then
        exit 0
    fi
    deadline=$(cat {deadline}) || exit 1
    now=$(monotonic_seconds) || exit 1
    remaining=$(( deadline - now ))
    if [ "$remaining" -gt 0 ]; then
        retry_deadline=0
        flock -u 9
        exec 9>&-
        if [ "$remaining" -gt {poll_interval} ]; then
            remaining={poll_interval}
        fi
        sleep "$remaining"
        continue
    fi
    if [ "$retry_deadline" -eq 0 ]; then
        retry_deadline=$(( now + {lease} ))
    fi
    if SONIC_MGMT_NTP_LOCK_HELD=1 timeout --kill-after=10 {command_timeout} {script}; then
        exit 0
    fi
    flock -u 9
    exec 9>&-
    now=$(monotonic_seconds) || exit 1
    if [ "$now" -ge "$retry_deadline" ]; then
        exit 1
    fi
    sleep {retry_interval}
done
""".format(
            identity_commands=identity_commands,
            lease=NTP_SERVER_RECOVERY_LEASE,
            command_timeout=NTP_SERVER_RECOVERY_COMMAND_TIMEOUT,
            script=shlex.quote(script_path),
            pid=shlex.quote(pid_path),
            pid_tmp=shlex.quote("{}.tmp".format(pid_path)),
            deadline=shlex.quote(deadline_path),
            backup=shlex.quote(ntp_conf_backup_path),
            owner_tmp=shlex.quote(owner_tmp_path),
            owner=shlex.quote(owner_path),
            recovery_id=shlex.quote(recovery_id),
            retry_interval=NTP_SERVER_RECOVERY_RETRY_INTERVAL,
            lock=shlex.quote(lock_path),
            lock_timeout=NTP_SERVER_LOCK_TIMEOUT,
            poll_interval=NTP_SERVER_WATCHDOG_POLL_INTERVAL
        )
        recovery["watchdog_command"] = watchdog_command
        ptfhost.shell(
            "{identity_commands}"
            "watchdog_started=0; "
            "cleanup_install() {{ "
            "install_result=$?; trap - EXIT HUP INT TERM; exec 9>&-; "
            "if [ \"$watchdog_started\" -eq 0 ]; then "
            "if ! timeout --kill-after=10 {command_timeout} {script}; then "
            "echo 'PTF NTP installation rollback failed; recovery state retained' >&2; "
            "fi; "
            "fi; "
            "exit \"$install_result\"; "
            "}}; "
            "trap cleanup_install EXIT; "
            "trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; "
            "exec 9>{lock}; flock -w {lock_timeout} -x 9 || exit 75; "
            "if [ -e {owner} ]; then "
            "echo 'Another NTP server context owns {owner}' >&2; exit 1; fi; "
            "cp -a {config} {backup} && "
            "printf '%s\\n' {recovery_id} > {owner_tmp} && "
            "mv -f {owner_tmp} {owner} || exit 1; "
            "read -r uptime_seconds _ < /proc/uptime || exit 1; "
            "deadline=$(( ${{uptime_seconds%%.*}} + {recovery_timeout} )); "
            "printf '%s\\n' \"$deadline\" > {deadline_tmp} && "
            "mv -f {deadline_tmp} {deadline} || exit 1; "
            "setsid sh -c {watchdog} 9>&- >/dev/null 2>&1 </dev/null & "
            "flock -u 9; exec 9>&-; "
            "now=$(monotonic_seconds) || exit 1; "
            "startup_deadline=$(( now + {lock_timeout} )); "
            "while ! watchdog_is_live; do "
            "now=$(monotonic_seconds) || exit 1; "
            "if [ \"$now\" -ge \"$startup_deadline\" ]; then "
            "echo 'PTF NTP watchdog did not publish a live identity' >&2; exit 1; fi; "
            "sleep 1; "
            "done; "
            "sleep 1; "
            "watchdog_is_live || exit 1; "
            "watchdog_started=1; "
            "trap - EXIT HUP INT TERM".format(
                identity_commands=identity_commands,
                watchdog=shlex.quote(watchdog_command),
                script=shlex.quote(script_path),
                command_timeout=NTP_SERVER_RECOVERY_COMMAND_TIMEOUT,
                lock=shlex.quote(lock_path),
                lock_timeout=NTP_SERVER_LOCK_TIMEOUT,
                owner=shlex.quote(owner_path),
                config=shlex.quote(ntp_conf_path),
                backup=shlex.quote(ntp_conf_backup_path),
                recovery_id=shlex.quote(recovery_id),
                owner_tmp=shlex.quote(owner_tmp_path),
                deadline=shlex.quote(deadline_path),
                deadline_tmp=shlex.quote(deadline_tmp_path),
                recovery_timeout=recovery_timeout
            )
        )
        ptfhost.command(
            "test -s {pid} -a -s {deadline}".format(
                pid=shlex.quote(pid_path),
                deadline=shlex.quote(deadline_path)
            )
        )
    except Exception:
        _restore_ntp_server(ptfhost, recovery)
        raise

    return recovery


def _refresh_ntp_server_recovery(ptfhost, recovery):
    deadline_tmp_path = "{}.{}.tmp".format(
        recovery["deadline_path"],
        uuid.uuid4().hex
    )
    ptfhost.shell(
        "{identity_commands}"
        "refresh_complete=0; "
        "cleanup_refresh() {{ "
        "if [ \"$refresh_complete\" -eq 0 ]; then "
        "rm -f {deadline_tmp}; "
        "fi; "
        "}}; "
        "abort_refresh() {{ cleanup_refresh; trap - EXIT HUP INT TERM; exit 130; }}; "
        "trap cleanup_refresh EXIT; trap abort_refresh HUP INT TERM; "
        "exec 9>{lock}; flock -w {lock_timeout} -x 9 || exit 75; "
        "test -s {owner} && [ \"$(cat {owner})\" = {recovery_id} ] || exit 1; "
        "watchdog_is_live || {{ echo 'PTF NTP watchdog identity is not live' >&2; exit 1; }}; "
        "read -r uptime_seconds _ < /proc/uptime || exit 1; "
        "deadline=$(( ${{uptime_seconds%%.*}} + {recovery_timeout} )); "
        "printf '%s\\n' \"$deadline\" > {deadline_tmp} && "
        "mv -f {deadline_tmp} {deadline} || exit 1; "
        "sleep 1; watchdog_is_live || exit 1; "
        "refresh_complete=1; trap - EXIT HUP INT TERM".format(
            identity_commands=_get_ntp_watchdog_identity_commands(recovery),
            deadline_tmp=shlex.quote(deadline_tmp_path),
            lock=shlex.quote(recovery["lock_path"]),
            lock_timeout=NTP_SERVER_LOCK_TIMEOUT,
            owner=shlex.quote(recovery["owner_path"]),
            recovery_id=shlex.quote(recovery["recovery_id"]),
            deadline=shlex.quote(recovery["deadline_path"]),
            recovery_timeout=recovery["recovery_timeout"]
        )
    )


def _restore_ntp_server(ptfhost, recovery):
    result = ptfhost.shell(
        "if [ -x {script} ]; then timeout --kill-after=10 {command_timeout} {script}; "
        "elif [ ! -e {backup} ]; then exit 0; "
        "else exit 1; fi".format(
            script=shlex.quote(recovery["script_path"]),
            backup=shlex.quote(recovery["backup_path"]),
            command_timeout=NTP_SERVER_RECOVERY_COMMAND_TIMEOUT
        ),
        module_ignore_errors=True
    )
    pytest_assert(
        result.get("rc", 1) == 0,
        "Failed to restore the PTF NTP server state: {}".format(result)
    )
    _retire_ntp_server_recovery(ptfhost, recovery)


def _check_chrony_server_ready(host, max_dispersion):
    result = host.command("chronyc tracking", module_ignore_errors=True)
    if result["rc"] != 0:
        return False

    values = {}
    for line in result["stdout"].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()

    try:
        stratum = int(values["Stratum"])
        root_dispersion = float(values["Root dispersion"].split()[0])
    except (KeyError, ValueError, IndexError):
        return False

    return (
        stratum > 0
        and values.get("Leap status") == "Normal"
        and root_dispersion < max_dispersion
    )


@contextmanager
def setup_ntp_server_context(ptfhost, ptf_use_ipv6=False,
                             recovery_timeout=NTP_SERVER_RECOVERY_TIMEOUT,
                             recovery_state=None):
    """Configure PTF temporarily; detached recovery requires the container to survive."""
    ntp_daemon_type = get_ntp_daemon_in_use(ptfhost)
    ntp_conf_path = get_ntp_config_path(ntp_daemon_type)
    ntp_service_name = get_ntp_service_name(ntp_daemon_type)
    ntp_service_was_active = ptfhost.command(
        "service {} status".format(shlex.quote(ntp_service_name)),
        module_ignore_errors=True
    )["rc"] == 0
    ntp_conf_backup_path = "{}.sonicmgmt.{}.bak".format(ntp_conf_path, uuid.uuid4().hex)

    ptfhost.shell("command -v flock >/dev/null")
    ptfhost.shell("command -v setsid >/dev/null")
    ptfhost.shell("command -v timeout >/dev/null")
    ptfhost.shell("test -r /proc/self/stat -a -r /proc/sys/kernel/random/boot_id")
    recovery = _install_ntp_server_recovery(
        ptfhost,
        ntp_service_name,
        ntp_conf_path,
        ntp_conf_backup_path,
        ntp_service_was_active,
        recovery_timeout
    )
    if recovery_state is not None:
        recovery_state["refresh"] = lambda: _refresh_ntp_server_recovery(
            ptfhost,
            recovery
        )
    try:
        _configure_ntp_server(ptfhost, ntp_daemon_type, ntp_conf_path, ptf_use_ipv6)
        ntp_en_res = ptfhost.service(name=ntp_service_name, state="restarted")

        if ntp_daemon_type == NtpDaemon.CHRONY:
            server_ready = wait_until(180, 10, 0, _check_chrony_server_ready, ptfhost, 3)
        else:
            server_ready = (
                wait_until(120, 5, 0, check_ntp_status, ptfhost, ntp_daemon_type)
                and wait_until(180, 10, 0, check_max_root_dispersion, ptfhost, 3, ntp_daemon_type)
            )
        pytest_assert(
            server_ready,
            "NTP server was not ready in PTF container {}; NTP service start result {}"
            .format(ptfhost.hostname, ntp_en_res)
        )

        yield ptfhost.mgmt_ipv6 if ptf_use_ipv6 else ptfhost.mgmt_ip
    finally:
        try:
            if not recovery_state or not recovery_state.get("defer_cleanup"):
                _restore_ntp_server(ptfhost, recovery)
        finally:
            if recovery_state is not None:
                recovery_state.pop("refresh", None)


def get_ntp_one_shot_command(duthost, ntp_daemon_type, ntp_server, ntp_conf_path=None):
    """Return a bounded command that synchronizes time from one explicit server."""
    ntp_server = normalize_ntp_server(ntp_server)
    if ntp_daemon_type == NtpDaemon.CHRONY:
        directive = shlex.quote("server {} iburst".format(ntp_server))
        return "timeout 60 chronyd -q -t 30 -F 1 {}".format(directive)

    if not ntp_conf_path:
        raise ValueError("ntp_conf_path is required for ntpd one-shot synchronization")

    if ntp_daemon_type == NtpDaemon.NTPSEC:
        ntp_user = "ntpsec:ntpsec"
    elif ntp_daemon_type == NtpDaemon.NTP:
        ntp_user = ":".join(duthost.command("getent passwd ntp")['stdout'].split(':')[2:4])
    else:
        raise ValueError("Unsupported NTP daemon type: {}".format(ntp_daemon_type))

    return "timeout 60 ntpd -gq -u {} -c {}".format(
        shlex.quote(ntp_user),
        shlex.quote(ntp_conf_path)
    )


def prepare_ntp_one_shot_config(duthost, ntp_daemon_type, ntp_server, ntp_conf_path):
    """Create the minimal config required by ntpd one-shot synchronization."""
    if ntp_daemon_type == NtpDaemon.CHRONY:
        return

    ntp_server = normalize_ntp_server(ntp_server)
    duthost.copy(
        content="server {} iburst\n".format(ntp_server),
        dest=ntp_conf_path,
        mode=0o644
    )
