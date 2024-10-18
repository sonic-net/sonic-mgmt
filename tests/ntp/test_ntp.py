from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.ntp_helper import check_ntp_status, run_ntp, _context_for_setup_ntp, NtpDaemon, \
        ntp_daemon_in_use  # noqa: F401
import logging
import time
import pytest


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

TIME_FORWARD = 3600


def pytest_generate_tests(metafunc):
    if "ptf_use_ipv6" in metafunc.fixturenames:
        metafunc.parametrize("ptf_use_ipv6", [False, True], scope="module", ids=["ipv4_allowed", "ipv6_only"])


def config_long_jump(duthost, ntp_daemon_in_use, enable=False):  # noqa: F811
    """change ntpd option to enable or disable long jump"""
    logger.info("{} ntp long jump".format("enable" if enable else "disable"))
    if ntp_daemon_in_use == NtpDaemon.NTPSEC:
        if enable:
            regex = "s/NTPD_OPTS=\\\"-x -N\\\"/NTPD_OPTS=\\\"-g -N\\\"/"
        else:
            regex = "s/NTPD_OPTS=\\\"-g -N\\\"/NTPD_OPTS=\\\"-x -N\\\"/"

        duthost.command("sed -i '%s' /etc/default/ntpsec" % regex)
        duthost.service(name='ntp', state='restarted')
    elif ntp_daemon_in_use == NtpDaemon.NTP:
        if enable:
            regex = "s/NTPD_OPTS='-x'/NTPD_OPTS='-g'/"
        else:
            regex = "s/NTPD_OPTS='-g'/NTPD_OPTS='-x'/"

        duthost.command("sed -i %s /etc/default/ntp" % regex)
        duthost.service(name='ntp', state='restarted')
    elif ntp_daemon_in_use == NtpDaemon.CHRONY:
        if enable:
            duthost.copy(dest="/etc/chrony/conf.d/enable-long-jump-for-test.conf", content="makestep 1 3\n")
        else:
            duthost.file(path="/etc/chrony/conf.d/enable-long-jump-for-test.conf", state="absent")

        duthost.service(name='chrony', state='restarted')


@pytest.fixture(scope="module")
def setup_ntp(ptfhost, duthosts, rand_one_dut_hostname, ptf_use_ipv6):
    if ptf_use_ipv6 and not ptfhost.mgmt_ipv6:
        pytest.skip("No IPv6 address on PTF host")
    with _context_for_setup_ntp(ptfhost, duthosts, rand_one_dut_hostname, ptf_use_ipv6) as result:
        yield result


@pytest.fixture
def setup_long_jump_config(duthosts, rand_one_dut_hostname, ntp_daemon_in_use):  # noqa: F811
    """set long jump config and set DUT's time forward"""

    duthost = duthosts[rand_one_dut_hostname]

    # collect long jump state
    long_jump_enable = False
    if ntp_daemon_in_use == NtpDaemon.NTP:
        if not duthost.shell("grep -q \"NTPD_OPTS='-g'\" /etc/default/ntp", module_ignore_errors=True)['rc']:
            long_jump_enable = True
    elif ntp_daemon_in_use == NtpDaemon.NTPSEC:
        if not duthost.shell("grep -q \"NTPD_OPTS=\\\"-g -N\\\"\" /etc/default/ntpsec",
                             module_ignore_errors=True)['rc']:
            long_jump_enable = True
    elif ntp_daemon_in_use == NtpDaemon.CHRONY:
        # By default, long jump (a.k.a. makestep) isn't enabled for chrony, so this should generally be false
        long_jump_conf_stat = duthost.stat(path="/etc/chrony/conf.d/enable-long-jump-for-test.conf")
        if long_jump_conf_stat["stat"]["exists"]:
            long_jump_enable = True

    # get time before set time
    start_time_dut = int(duthost.command("date +%s")['stdout'])
    start_time = time.time()

    # stop NTP and set time on DUT
    if ntp_daemon_in_use == NtpDaemon.CHRONY:
        duthost.service(name='chrony', state='stopped')
    elif ntp_daemon_in_use == NtpDaemon.NTP or ntp_daemon_in_use == NtpDaemon.NTPSEC:
        duthost.service(name='ntp', state='stopped')
    duthost.command("date -s '@{}'".format(start_time_dut - TIME_FORWARD))

    # set long jump config with variable
    yield

    # set DUT's time back after long jump test
    if ntp_daemon_in_use == NtpDaemon.CHRONY:
        duthost.service(name='chrony', state='stopped')
    elif ntp_daemon_in_use == NtpDaemon.NTP or ntp_daemon_in_use == NtpDaemon.NTPSEC:
        duthost.service(name='ntp', state='stopped')
    dut_end_time = int(time.time()) - int(start_time) + start_time_dut
    duthost.command("date -s '@{}'".format(dut_end_time))
    config_long_jump(duthost, ntp_daemon_in_use, long_jump_enable)


def test_ntp_long_jump_enabled(duthosts, rand_one_dut_hostname, ntp_daemon_in_use, setup_ntp,  # noqa: F811
                               setup_long_jump_config):
    duthost = duthosts[rand_one_dut_hostname]

    config_long_jump(duthost, ntp_daemon_in_use, enable=True)

    pytest_assert(wait_until(720, 10, 0, check_ntp_status, duthost, ntp_daemon_in_use),
                  "NTP long jump enable failed")


def test_ntp_long_jump_disabled(duthosts, rand_one_dut_hostname, ntp_daemon_in_use, setup_ntp,  # noqa: F811
                                setup_long_jump_config):
    duthost = duthosts[rand_one_dut_hostname]

    config_long_jump(duthost, ntp_daemon_in_use, enable=False)

    if ntp_daemon_in_use == NtpDaemon.CHRONY:
        pytest_assert(not wait_until(720, 10, 0, check_ntp_status, duthost, ntp_daemon_in_use),
                      "NTP long jump disable failed (long jump happened)")
    elif ntp_daemon_in_use == NtpDaemon.NTP or ntp_daemon_in_use == NtpDaemon.NTPSEC:
        # NTP (and NTPsec) don't actually support disabling long jump fully
        pytest_assert(wait_until(720, 10, 0, check_ntp_status, duthost, ntp_daemon_in_use),
                      "NTP long jump disable failed (time didn't synchronize)")


def test_ntp(duthosts, rand_one_dut_hostname, setup_ntp, ntp_daemon_in_use):  # noqa: F811
    run_ntp(duthosts, rand_one_dut_hostname, setup_ntp, ntp_daemon_in_use)
