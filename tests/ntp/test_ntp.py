from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
import logging
logger = logging.getLogger(__name__)

import pytest

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

@pytest.fixture(scope="module")
def setup_ntp(ptfhost, duthost, creds):
    """setup ntp client and server"""
    if creds.get('proxy_env'):
        # If testbed is behaind proxy then force ntpd inside ptf use local time
        ptfhost.lineinfile(path="/etc/ntp.conf", line="server 127.127.1.0 prefer")

    # enable ntp server
    ntp_en_res = ptfhost.service(name="ntp", state="started")

    # setup ntp on dut to sync with ntp server
    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    ntp_servers = config_facts.get('NTP_SERVER', {})
    for ntp_server in ntp_servers:
        duthost.command("config ntp del %s" % ntp_server)

    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    duthost.command("config ntp add %s" % ptfip)
    pytest_assert(wait_until(120, 5, check_ntp_status, ptfhost), \
        "NTP server was not started in PTF container {}; NTP service start result {}".format(ptfhost.hostname, ntp_en_res))

    yield

    # stop ntp server
    ptfhost.service(name="ntp", state="stopped")
    # reset ntp client configuration
    duthost.command("config ntp del %s" % ptfip)
    for ntp_server in ntp_servers:
        duthost.command("config ntp add %s" % ntp_server)

def check_ntp_status(host):
    res = host.command("ntpstat", module_ignore_errors=True)
    if res['rc'] != 0:
       return False
    return True

def test_ntp(duthost, setup_ntp):
    """ verify the LLDP message on DUT """

    duthost.service(name='ntp', state='stopped')
    duthost.command("ntpd -gq")
    duthost.service(name='ntp', state='restarted')
    pytest_assert(wait_until(720, 10, check_ntp_status, duthost),
                  "NTP not in sync")
