from enum import Enum
import pytest
import time
from contextlib import contextmanager
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


class NtpDaemon(Enum):
    NTP = 1
    NTPSEC = 2
    CHRONY = 3


@contextmanager
def setup_ntp_context(ptfhost, duthost, ptf_use_ipv6):
    """setup ntp client and server"""
    ntp_daemon_type = get_ntp_daemon_in_use(ptfhost)
    ntp_conf_path = None
    ntp_service_name = None
    if ntp_daemon_type == NtpDaemon.NTPSEC:
        ntp_conf_path = '/etc/ntpsec/ntp.conf'
        ntp_service_name = 'ntpsec'
    elif ntp_daemon_type == NtpDaemon.CHRONY:
        ntp_conf_path = '/etc/chrony/chrony.conf'
        ntp_service_name = 'chrony'
    elif ntp_daemon_type == NtpDaemon.NTP:
        ntp_conf_path = '/etc/ntp.conf'
        ntp_service_name = 'ntp'

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

    ptfhost.lineinfile(path=ntp_conf_path, line="server 127.127.1.0 prefer")

    # restart ntp server
    ntp_en_res = ptfhost.service(name=ntp_service_name, state="restarted")

    pytest_assert(wait_until(120, 5, 0, check_ntp_status, ptfhost, ntp_daemon_type),
                  "NTP server was not started in PTF container {}; NTP service start result {}"
                  .format(ptfhost.hostname, ntp_en_res))

    # When using Chrony as the NTP daemon on the DUT, Chrony will not use NTP sources that have a
    # root dispersion of more than 3 seconds (configurable via /etc/chrony/chrony.conf, but we currently
    # don't touch that setting). Therefore, block here until the root dispersion is less than 3 seconds
    # so that we don't incorrectly fail the test.
    pytest_assert(wait_until(180, 10, 0, check_max_root_dispersion, ptfhost, 3, ntp_daemon_type),
                  "NTP timing hasn't converged enough in PTF container {}".format(ptfhost.hostname))

    # check to see if iburst option is present
    ntp_add_help = duthost.command("config ntp add --help")
    ntp_add_iburst_present = False
    if "iburst" in ntp_add_help["stdout"]:
        ntp_add_iburst_present = True

    # setup ntp on dut to sync with ntp server
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    ntp_servers = config_facts.get('NTP_SERVER', {})
    for ntp_server in ntp_servers:
        duthost.command("config ntp del %s" % ntp_server)

    duthost.command("config ntp add %s %s" % ("--iburst" if ntp_add_iburst_present else "",
                    ptfhost.mgmt_ipv6 if ptf_use_ipv6 else ptfhost.mgmt_ip))

    yield

    # stop ntp server
    ptfhost.service(name=ntp_service_name, state="stopped")

    # restore the default pool configuration
    ptfhost.lineinfile(
        path=ntp_conf_path, line="pool 0.debian.pool.ntp.org iburst", regexp="#pool.*0.debian.*pool.*ntp.*org.*")
    ptfhost.lineinfile(
        path=ntp_conf_path, line="pool 1.debian.pool.ntp.org iburst", regexp="#pool.*1.debian.*pool.*ntp.*org.*")
    ptfhost.lineinfile(
        path=ntp_conf_path, line="pool 2.debian.pool.ntp.org iburst", regexp="#pool.*2.debian.*pool.*ntp.*org.*")
    ptfhost.lineinfile(
        path=ntp_conf_path, line="pool 3.debian.pool.ntp.org iburst", regexp="#pool.*3.debian.*pool.*ntp.*org.*")

    ptfhost.lineinfile(path=ntp_conf_path, line="", regexp="^server.*127.127.1.0.*prefer")

    # reset ntp client configuration
    duthost.command("config ntp del %s" % (ptfhost.mgmt_ipv6 if ptf_use_ipv6 else ptfhost.mgmt_ip))
    for ntp_server in ntp_servers:
        duthost.command("config ntp add %s %s" % ("--iburst" if ntp_add_iburst_present else "", ntp_server))
    # The time jump leads to exception in lldp_syncd. The exception has been handled by lldp_syncd,
    # but it will leave error messages in syslog, which will cause subsequent test cases to fail.
    # So we need to wait for a while to make sure the error messages are flushed.
    # The default update interval of lldp_syncd is 10 seconds, so we wait for 20 seconds here.
    time.sleep(20)


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

    if ntp_daemon_in_use == NtpDaemon.NTPSEC:
        duthost.service(name='ntp', state='stopped')
        duthost.command("timeout 20 ntpd -gq -u ntpsec:ntpsec")
        duthost.service(name='ntp', state='restarted')
    elif ntp_daemon_in_use == NtpDaemon.NTP:
        duthost.service(name='ntp', state='stopped')
        ntp_uid = ":".join(duthost.command("getent passwd ntp")['stdout'].split(':')[2:4])
        duthost.command("timeout 20 ntpd -gq -u {}".format(ntp_uid))
        duthost.service(name='ntp', state='restarted')
    elif ntp_daemon_in_use == NtpDaemon.CHRONY:
        duthost.service(name='chrony', state='stopped')
        duthost.command("timeout 20 chronyd -q -F 1")
        duthost.service(name='chrony', state='restarted')
    pytest_assert(wait_until(720, 10, 0, check_ntp_status, duthost, ntp_daemon_in_use),
                  "NTP not in sync")
