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


@contextmanager
def setup_ntp_server_context(ptfhost, ptf_use_ipv6=False):
    """Configure the PTF host as a temporary NTP server and restore it verbatim."""
    ntp_daemon_type = get_ntp_daemon_in_use(ptfhost)
    ntp_conf_path = get_ntp_config_path(ntp_daemon_type)
    ntp_service_name = get_ntp_service_name(ntp_daemon_type)
    ntp_service_was_active = ptfhost.command(
        "service {} status".format(shlex.quote(ntp_service_name)),
        module_ignore_errors=True
    )["rc"] == 0
    ntp_conf_backup_path = "{}.sonicmgmt.{}.bak".format(ntp_conf_path, uuid.uuid4().hex)
    quoted_conf_path = shlex.quote(ntp_conf_path)
    quoted_backup_path = shlex.quote(ntp_conf_backup_path)

    ptfhost.command("cp -a {} {}".format(quoted_conf_path, quoted_backup_path))
    try:
        _configure_ntp_server(ptfhost, ntp_daemon_type, ntp_conf_path, ptf_use_ipv6)

        # restart ntp server
        ntp_en_res = ptfhost.service(name=ntp_service_name, state="restarted")

        pytest_assert(wait_until(120, 5, 0, check_ntp_status, ptfhost, ntp_daemon_type),
                      "NTP server was not started in PTF container {}; NTP service start result {}"
                      .format(ptfhost.hostname, ntp_en_res))

        # Chrony clients reject sources whose root dispersion is too large.
        pytest_assert(wait_until(180, 10, 0, check_max_root_dispersion, ptfhost, 3, ntp_daemon_type),
                      "NTP timing hasn't converged enough in PTF container {}".format(ptfhost.hostname))

        yield ptfhost.mgmt_ipv6 if ptf_use_ipv6 else ptfhost.mgmt_ip
    finally:
        try:
            ptfhost.service(name=ntp_service_name, state="stopped")
        finally:
            try:
                ptfhost.command("mv -f {} {}".format(quoted_backup_path, quoted_conf_path))
            finally:
                if ntp_service_was_active:
                    ptfhost.service(name=ntp_service_name, state="restarted")


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
