from common.utilities import wait_until
import logging
logger = logging.getLogger(__name__)

import pytest

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
]

@pytest.fixture(scope="module")
def setup_ntp(ptfhost, duthost):
    """setup ntp client and server"""

    # enable ntp server
    ptfhost.service(name="ntp", state="started")

    # setup ntp on dut to sync with ntp server
    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    ntp_servers = config_facts.get('NTP_SERVER', {})
    for ntp_server in ntp_servers:
        duthost.command("sudo config ntp del %s" % ntp_server)

    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    duthost.command("sudo config ntp add %s" % ptfip)

    wait_until(120, 5, check_ntp_status, ptfhost)

    yield

    # stop ntp server
    ptfhost.service(name="ntp", state="stopped")

    # reset ntp client configuration
    duthost.command("sudo config ntp del %s" % ptfip)
    for ntp_server in ntp_servers:
        duthost.command("sudo config ntp add %s" % ntp_server)

def check_ntp_status(host):
    res = host.command("ntpstat")
    if res['rc'] != 0:
       return False
    return True

def test_ntp(testbed_devices, duthost, setup_ntp):
    """ verify the LLDP message on DUT """

    duthost.service(name='ntp', state='stopped')
    duthost.command("ntpd -gq")
    duthost.service(name='ntp', state='restarted')
    assert wait_until(120, 5, check_ntp_status, duthost), "Ntp not in sync"
