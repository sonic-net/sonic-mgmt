from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
import logging
import time
logger = logging.getLogger(__name__)

import pytest

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

TIME_FORWARD = 3600

@pytest.fixture(scope="module")
def setup_ntp(ptfhost, duthosts, rand_one_dut_hostname, creds):
    """setup ntp client and server"""
    duthost = duthosts[rand_one_dut_hostname]

    ptfhost.lineinfile(path="/etc/ntp.conf", line="server 127.127.1.0 prefer")

    # restart ntp server
    ntp_en_res = ptfhost.service(name="ntp", state="restarted")

    pytest_assert(wait_until(120, 5, 0, check_ntp_status, ptfhost), \
        "NTP server was not started in PTF container {}; NTP service start result {}".format(ptfhost.hostname, ntp_en_res))

    # setup ntp on dut to sync with ntp server
    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    ntp_servers = config_facts.get('NTP_SERVER', {})
    for ntp_server in ntp_servers:
        duthost.command("config ntp del %s" % ntp_server)

    duthost.command("config ntp add %s" % ptfhost.mgmt_ip)
    logger.info("setup_ntp setup done")

    yield

    # stop ntp server
    ptfhost.service(name="ntp", state="stopped")
    # reset ntp client configuration
    duthost.command("config ntp del %s" % ptfhost.mgmt_ip)
    for ntp_server in ntp_servers:
        duthost.command("config ntp add %s" % ntp_server)

@pytest.fixture
def setup_long_jump(duthosts, rand_one_dut_hostname, creds):
    """set DUT's time forward"""
    duthost = duthosts[rand_one_dut_hostname]

    # get time before set time
    start_time_dut = int(duthost.command("date +%s")['stdout'])
    start_time = time.time()

    # set time on DUT
    duthost.service(name='ntp', state='stopped')
    duthost.command("date -s '@{}'".format(start_time_dut - TIME_FORWARD))
    duthost.service(name='ntp', state='restarted')

    yield

    # set DUT's time back after long jump test
    dut_end_time = int(time.time()) - int(start_time) + dut_start_time
    duthost.command("date -s '@{}'".format(dut_end_time))

def check_ntp_status(host):
    res = host.command("ntpstat", module_ignore_errors=True)
    if res['rc'] != 0:
       return False
    return True

def test_ntp_long_jump(duthosts, rand_one_dut_hostname, setup_ntp, setup_long_jump):
    duthost = duthosts[rand_one_dut_hostname]

    pytest_assert(wait_until(720, 10, 0, check_ntp_status, duthost),
                  "NTP long jump failed")

def test_ntp(duthosts, rand_one_dut_hostname, setup_ntp):
    """ Verify that DUT is synchronized with configured NTP server """
    duthost = duthosts[rand_one_dut_hostname]

    duthost.service(name='ntp', state='stopped')
    duthost.command("ntpd -gq")
    duthost.service(name='ntp', state='restarted')
    pytest_assert(wait_until(720, 10, 0, check_ntp_status, duthost),
                  "NTP not in sync")
                  