from enum import Enum
import ipaddress
import pytest
import shlex
import time
import uuid
from contextlib import contextmanager
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


class NtpDaemon(Enum):
    NTP = 1
    NTPSEC = 2
    CHRONY = 3


NTP_SERVER_RECOVERY_TIMEOUT = 86400


def get_ntp_service_name(ntp_daemon_type):
    if ntp_daemon_type == NtpDaemon.NTPSEC:
        return 'ntpsec'
    if ntp_daemon_type == NtpDaemon.CHRONY:
        return 'chrony'
    if ntp_daemon_type == NtpDaemon.NTP:
        return 'ntp'
    pytest.fail("Unsupported NTP daemon type: {}".format(ntp_daemon_type))


def get_ntp_config_path(ntp_daemon_type):
    if ntp_daemon_type == NtpDaemon.NTPSEC:
        return '/etc/ntpsec/ntp.conf'
    if ntp_daemon_type == NtpDaemon.CHRONY:
        return '/etc/chrony/chrony.conf'
    if ntp_daemon_type == NtpDaemon.NTP:
        return '/etc/ntp.conf'
    pytest.fail("Unsupported NTP daemon type: {}".format(ntp_daemon_type))


def _configure_ntp_server(ptfhost, ntp_daemon_type, ntp_conf_path, ptf_use_ipv6):
    if ntp_daemon_type in (NtpDaemon.NTPSEC, NtpDaemon.NTP):
        # Limit listening to the mgmt interface, to prevent socket allocation
        # exhaustion.  Standalone Docker PTF containers may not have a "mgmt"
        # interface (only eth0/veth) and ntpsec cannot bind to those aliases,
        # so only apply interface restrictions when mgmt actually exists.
        res = ptfhost.command("ip link show mgmt", module_ignore_errors=True)
        if res.get("rc", 1) == 0:
            ptfhost.lineinfile(path=ntp_conf_path, line="interface ignore wildcard")
            ptfhost.lineinfile(path=ntp_conf_path, line="interface listen mgmt")
            # ntpsec resolves the "mgmt" interface name to its IPv4 address only,
            # so add an explicit listen directive for IPv6.
            if ptf_use_ipv6 and ptfhost.mgmt_ipv6:
                ptfhost.lineinfile(path=ntp_conf_path, line="interface listen %s" % ptfhost.mgmt_ipv6)

    if ntp_daemon_type == NtpDaemon.NTPSEC:
        # ntpsec dropped the classic "server 127.127.1.0" local clock address
        # syntax; use the refclock directive and add restrict lines for ntpq.
        ptfhost.lineinfile(path=ntp_conf_path, line="refclock local stratum 3 prefer",
                           regexp="^(server 127\\.127\\.1\\.0|refclock local)")
        ptfhost.lineinfile(path=ntp_conf_path, line="restrict 127.0.0.1")
        ptfhost.lineinfile(path=ntp_conf_path, line="restrict ::1")
    elif ntp_daemon_type == NtpDaemon.CHRONY:
        ptfhost.lineinfile(path=ntp_conf_path, line="local stratum 3", regexp="^local\\s+stratum\\s+")
        ptfhost.lineinfile(path=ntp_conf_path, line="allow all", regexp="^allow\\s+")
    else:
        ptfhost.lineinfile(path=ntp_conf_path, line="server 127.127.1.0 prefer")

    # Comment out the default pool configuration
    ptfhost.lineinfile(
        path=ntp_conf_path, line="#pool 0.debian.pool.ntp.org iburst", regexp="^pool.*0.debian.*pool.*ntp.*org.*")
    ptfhost.lineinfile(
        path=ntp_conf_path, line="#pool 1.debian.pool.ntp.org iburst", regexp="^pool.*1.debian.*pool.*ntp.*org.*")
    ptfhost.lineinfile(
        path=ntp_conf_path, line="#pool 2.debian.pool.ntp.org iburst", regexp="^pool.*2.debian.*pool.*ntp.*org.*")
    ptfhost.lineinfile(
        path=ntp_conf_path, line="#pool 3.debian.pool.ntp.org iburst", regexp="^pool.*3.debian.*pool.*ntp.*org.*")

    # Comment out the tos minclock minsane option line
    # Having this option enabled can cause the NTP server to not synchronize
    # with the PTF host, which can lead to test failures.
    ptfhost.lineinfile(
        path=ntp_conf_path, line="#tos minclock 4 minsane 3", regexp="^tos.*minclock.*minsane.*")


def _install_ntp_server_recovery(ptfhost, ntp_service_name, ntp_conf_path,
                                 ntp_conf_backup_path, ntp_service_was_active,
                                 recovery_timeout=None):
    recovery_id = uuid.uuid4().hex
    script_path = "/tmp/sonic-mgmt-ntp-server-recovery-{}.sh".format(recovery_id)
    pid_path = "/tmp/sonic-mgmt-ntp-server-recovery-{}.pid".format(recovery_id)
    owner_path = "/tmp/sonic-mgmt-ntp-server-{}.owner".format(ntp_service_name)
    owner_tmp_path = "{}.{}.tmp".format(owner_path, recovery_id)
    lock_path = "/tmp/sonic-mgmt-ntp-server-{}.lock".format(ntp_service_name)

    service_restore_command = (
        "service {} restart".format(shlex.quote(ntp_service_name))
        if ntp_service_was_active
        else "service {} stop".format(shlex.quote(ntp_service_name))
    )
    script = """#!/bin/bash
result=0
if [ "${{SONIC_MGMT_NTP_LOCK_HELD:-0}}" -ne 1 ]; then
    exec 9>{lock_path}
    flock -x 9
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
        owner_path=shlex.quote(owner_path),
        recovery_id=shlex.quote(recovery_id),
        service_name=shlex.quote(ntp_service_name),
        backup_path=shlex.quote(ntp_conf_backup_path),
        config_path=shlex.quote(ntp_conf_path),
        service_restore_command=service_restore_command
    )
    try:
        ptfhost.copy(content=script, dest=script_path, mode=0o755)
        watchdog_command = (
            "sleep {timeout}; "
            "until {script}; do sleep 300; done; "
            "rm -f {script} {pid} {backup} {owner_tmp}"
        ).format(
            timeout=recovery_timeout,
            script=shlex.quote(script_path),
            pid=shlex.quote(pid_path),
            backup=shlex.quote(ntp_conf_backup_path),
            owner_tmp=shlex.quote(owner_tmp_path)
        )
        ptfhost.shell(
            "watchdog_started=0; "
            "cleanup_install() {{ "
            "if [ \"$watchdog_started\" -eq 0 ]; then "
            "SONIC_MGMT_NTP_LOCK_HELD=1 {script} >/dev/null 2>&1 || true; "
            "fi; "
            "}}; "
            "trap cleanup_install EXIT HUP INT TERM; "
            "exec 9>{lock}; flock -x 9; "
            "if [ -e {owner} ]; then "
            "echo 'Another NTP server context owns {owner}' >&2; exit 1; fi; "
            "cp -a {config} {backup} && "
            "printf '%s\\n' {recovery_id} > {owner_tmp} && "
            "mv -f {owner_tmp} {owner} || exit 1; "
            "setsid sh -c {watchdog} 9>&- >/dev/null 2>&1 </dev/null & "
            "watchdog_pid=$!; printf '%s\\n' \"$watchdog_pid\" > {pid} || exit 1; "
            "kill -0 \"$watchdog_pid\" || exit 1; watchdog_started=1; "
            "trap - EXIT HUP INT TERM".format(
                watchdog=shlex.quote(watchdog_command),
                script=shlex.quote(script_path),
                lock=shlex.quote(lock_path),
                owner=shlex.quote(owner_path),
                config=shlex.quote(ntp_conf_path),
                backup=shlex.quote(ntp_conf_backup_path),
                recovery_id=shlex.quote(recovery_id),
                owner_tmp=shlex.quote(owner_tmp_path),
                pid=shlex.quote(pid_path)
            )
        )
        ptfhost.command("test -s {}".format(shlex.quote(pid_path)))
    except Exception:
        restore_result = ptfhost.command(
            shlex.quote(script_path),
            module_ignore_errors=True
        )
        owns_context = ptfhost.shell(
            "test -s {owner} && [ \"$(cat {owner})\" = {recovery_id} ]".format(
                owner=shlex.quote(owner_path),
                recovery_id=shlex.quote(recovery_id)
            ),
            module_ignore_errors=True
        )["rc"] == 0
        if restore_result["rc"] == 0 or not owns_context:
            ptfhost.shell(
                "if [ -s {pid} ]; then kill -- -$(cat {pid}) 2>/dev/null || true; fi; "
                "rm -f {script} {pid} {backup} {owner_tmp}".format(
                    script=shlex.quote(script_path),
                    pid=shlex.quote(pid_path),
                    backup=shlex.quote(ntp_conf_backup_path),
                    owner_tmp=shlex.quote(owner_tmp_path)
                )
            )
        raise

    return {
        "script_path": script_path,
        "pid_path": pid_path,
        "backup_path": ntp_conf_backup_path
    }


def _restore_ntp_server(ptfhost, recovery):
    result = ptfhost.shell(
        "if [ -x {script} ]; then {script}; "
        "elif [ ! -e {backup} ]; then exit 0; "
        "else exit 1; fi".format(
            script=shlex.quote(recovery["script_path"]),
            backup=shlex.quote(recovery["backup_path"])
        ),
        module_ignore_errors=True
    )
    if result["rc"] == 0:
        ptfhost.shell(
            "if [ -s {pid} ]; then kill -- -$(cat {pid}) 2>/dev/null || true; fi; "
            "rm -f {script} {pid} {backup}".format(
                script=shlex.quote(recovery["script_path"]),
                pid=shlex.quote(recovery["pid_path"]),
                backup=shlex.quote(recovery["backup_path"])
            )
        )

    pytest_assert(
        result["rc"] == 0,
        "Failed to restore the PTF NTP server state: {}".format(result)
    )


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
    """Configure the PTF host as a temporary NTP server and restore it verbatim."""
    ntp_daemon_type = get_ntp_daemon_in_use(ptfhost)
    ntp_conf_path = get_ntp_config_path(ntp_daemon_type)
    ntp_service_name = get_ntp_service_name(ntp_daemon_type)
    ntp_service_was_active = ptfhost.command(
        "service {} status".format(shlex.quote(ntp_service_name)),
        module_ignore_errors=True
    )["rc"] == 0
    ntp_conf_backup_path = "{}.sonicmgmt.{}.bak".format(ntp_conf_path, uuid.uuid4().hex)

    ptfhost.command("command -v flock >/dev/null")
    ptfhost.command("command -v setsid >/dev/null")
    recovery = _install_ntp_server_recovery(
        ptfhost,
        ntp_service_name,
        ntp_conf_path,
        ntp_conf_backup_path,
        ntp_service_was_active,
        recovery_timeout
    )
    try:
        _configure_ntp_server(ptfhost, ntp_daemon_type, ntp_conf_path, ptf_use_ipv6)

        # restart ntp server
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
        if not recovery_state or not recovery_state.get("defer_cleanup"):
            _restore_ntp_server(ptfhost, recovery)


def _ntp_add_command(ntp_server, ntp_server_options, ntp_add_iburst_present):
    ntp_server_options = ntp_server_options or {}
    iburst_enabled = str(ntp_server_options.get("iburst", "")).lower() in ("on", "true", "yes", "1")
    iburst_arg = "--iburst " if ntp_add_iburst_present and iburst_enabled else ""
    return "config ntp add {}{}".format(iburst_arg, shlex.quote(ntp_server))


@contextmanager
def setup_ntp_context(ptfhost, duthost, ptf_use_ipv6):
    """setup ntp client and server"""
    with setup_ntp_server_context(ptfhost, ptf_use_ipv6) as ntp_server:
        # check to see if iburst option is present
        ntp_add_help = duthost.command("config ntp add --help")
        ntp_add_iburst_present = "iburst" in ntp_add_help["stdout"]

        # setup ntp on dut to sync with ntp server
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        ntp_servers = config_facts.get('NTP_SERVER', {})
        try:
            for original_ntp_server in ntp_servers:
                duthost.command("config ntp del {}".format(shlex.quote(original_ntp_server)))

            duthost.command("config ntp add {}{}".format(
                "--iburst " if ntp_add_iburst_present else "",
                shlex.quote(ntp_server)
            ))

            yield
        finally:
            duthost.command("config ntp del {}".format(shlex.quote(ntp_server)), module_ignore_errors=True)
            for original_ntp_server, options in ntp_servers.items():
                duthost.command(_ntp_add_command(
                    original_ntp_server,
                    options,
                    ntp_add_iburst_present
                ))

            # The time jump can leave handled lldp_syncd errors in syslog.
            time.sleep(20)


def get_ntp_one_shot_command(duthost, ntp_daemon_type, ntp_server, ntp_conf_path=None):
    """Return a bounded command that synchronizes time from one explicit server."""
    ntp_server = str(ipaddress.ip_address(ntp_server))
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


def synchronize_time(duthost, ntp_daemon_type, ntp_server=None, ntp_conf_path=None,
                     service_active=True):
    """Synchronize time and restore the requested daemon active state."""
    ntp_service_name = get_ntp_service_name(ntp_daemon_type)
    if ntp_server:
        sync_command = get_ntp_one_shot_command(
            duthost,
            ntp_daemon_type,
            ntp_server,
            ntp_conf_path
        )
    elif ntp_daemon_type == NtpDaemon.NTPSEC:
        sync_command = "timeout 20 ntpd -gq -u ntpsec:ntpsec"
    elif ntp_daemon_type == NtpDaemon.NTP:
        ntp_uid = ":".join(duthost.command("getent passwd ntp")['stdout'].split(':')[2:4])
        sync_command = "timeout 20 ntpd -gq -u {}".format(shlex.quote(ntp_uid))
    elif ntp_daemon_type == NtpDaemon.CHRONY:
        sync_command = "timeout 20 chronyd -q -F 1"
    else:
        raise ValueError("Unsupported NTP daemon type: {}".format(ntp_daemon_type))

    try:
        duthost.service(name=ntp_service_name, state='stopped')
        duthost.command(sync_command)
    finally:
        duthost.service(
            name=ntp_service_name,
            state='restarted' if service_active else 'stopped'
        )


def prepare_ntp_one_shot_config(duthost, ntp_daemon_type, ntp_server, ntp_conf_path):
    """Create the minimal config required by ntpd one-shot synchronization."""
    if ntp_daemon_type == NtpDaemon.CHRONY:
        return

    ntp_server = str(ipaddress.ip_address(ntp_server))
    duthost.copy(
        content="server {} iburst\n".format(ntp_server),
        dest=ntp_conf_path,
        mode=0o644
    )


@pytest.fixture(scope="function")
def setup_ntp_func(ptfhost, duthosts, rand_one_dut_hostname, ptf_use_ipv6):
    with setup_ntp_context(ptfhost, duthosts[rand_one_dut_hostname], ptf_use_ipv6) as result:
        yield result


def get_ntp_daemon_in_use(host):
    ntpsec_conf_stat = host.stat(path="/etc/ntpsec/ntp.conf")
    if ntpsec_conf_stat["stat"]["exists"]:
        return NtpDaemon.NTPSEC
    chrony_conf_stat = host.stat(path="/etc/chrony/chrony.conf")
    if chrony_conf_stat["stat"]["exists"]:
        return NtpDaemon.CHRONY
    ntp_conf_stat = host.stat(path="/etc/ntp.conf")
    if ntp_conf_stat["stat"]["exists"]:
        return NtpDaemon.NTP
    pytest.fail("Unable to determine NTP daemon in use")


@pytest.fixture(scope="module")
def ntp_daemon_in_use(duthost):
    return get_ntp_daemon_in_use(duthost)


def check_ntp_status(host, ntp_daemon_in_use):
    if ntp_daemon_in_use == NtpDaemon.CHRONY:
        res = host.command("timedatectl show -p NTPSynchronized --value")
        return res['stdout'] == "yes"
    elif ntp_daemon_in_use == NtpDaemon.NTP or ntp_daemon_in_use == NtpDaemon.NTPSEC:
        res = host.command("ntpstat", module_ignore_errors=True)
        return res['rc'] == 0
    else:
        return False


def check_max_root_dispersion(host, max_dispersion, ntp_daemon_in_use):
    if ntp_daemon_in_use == NtpDaemon.CHRONY:
        res = host.command("sudo chronyc -n -c ntpdata")
        root_dispersion = float(res["stdout"].split(",")[14]) / 100
        return root_dispersion < max_dispersion
    elif ntp_daemon_in_use == NtpDaemon.NTP or ntp_daemon_in_use == NtpDaemon.NTPSEC:
        res = host.shell("ntpq -c sysinfo | grep 'root dispersion' | awk '{ print $3; }'")
        root_dispersion = float(res["stdout"]) / 1000
        return root_dispersion < max_dispersion
    else:
        return False


def run_ntp(duthost, ntp_daemon_in_use):
    """ Verify that DUT is synchronized with configured NTP server """
    synchronize_time(duthost, ntp_daemon_in_use)
    pytest_assert(wait_until(720, 10, 0, check_ntp_status, duthost, ntp_daemon_in_use),
                  "NTP not in sync")
