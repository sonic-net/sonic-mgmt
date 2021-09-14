import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.snmp_helpers import get_snmp_facts

try:
    import ntplib
    NTPLIB_INSTALLED = True
except ImportError:
    NTPLIB_INSTALLED = False

from tests.common.helpers.snmp_helpers import get_snmp_facts

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer globally
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

SONIC_SSH_PORT  = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'


def test_cacl_function(duthosts, rand_one_dut_hostname, localhost, creds):
    """Test control plane ACL functionality on a SONiC device"""

    duthost = duthosts[rand_one_dut_hostname]
    dut_mgmt_ip = duthost.mgmt_ip

    # Start an NTP client
    if NTPLIB_INSTALLED:
        ntp_client = ntplib.NTPClient()
    else:
        logging.warning("Will not check NTP connection. ntplib is not installed.")

    # Ensure we can gather basic SNMP facts from the device. Should fail on timeout
    get_snmp_facts(localhost, 
                   host=dut_mgmt_ip, 
                   version="v2c", 
                   community=creds['snmp_rocommunity'], 
                   wait=True, 
                   timeout = 20, 
                   interval=20)

    # Ensure we can send an NTP request
    if NTPLIB_INSTALLED:
        try:
            ntp_client.request(dut_mgmt_ip)
        except ntplib.NTPException:
            pytest.fail("NTP did timed out when expected to succeed!")

    # Copy config_service_acls.sh to the DuT (this also implicitly verifies we can successfully SSH to the DuT)
    duthost.copy(src="scripts/config_service_acls.sh", dest="/tmp/config_service_acls.sh", mode="0755")

    # We run the config_service_acls.sh script in the background because it
    # will install ACL rules which will only allow control plane traffic
    # to an unused IP range. Thus, if it works properly, it will sever our
    # SSH session, but we don't want the script itself to get killed,
    # because it is also responsible for resetting the control plane ACLs
    # back to their previous, working state
    duthost.shell("nohup /tmp/config_service_acls.sh < /dev/null > /dev/null 2>&1 &")

    # Wait until we are unable to SSH into the DuT
    res = localhost.wait_for(host=dut_mgmt_ip,
                             port=SONIC_SSH_PORT,
                             state='stopped',
                             search_regex=SONIC_SSH_REGEX,
                             delay=30,
                             timeout=40,
                             module_ignore_errors=True)

    pytest_assert(not res.is_failed, "SSH port did not stop. {}".format(res.get('msg', '')))

    # Try to SSH back into the DuT, it should time out
    res = localhost.wait_for(host=dut_mgmt_ip,
                             port=SONIC_SSH_PORT,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             delay=0,
                             timeout=10,
                             module_ignore_errors=True)

    pytest_assert(res.is_failed, "SSH did not timeout when expected. {}".format(res.get('msg', '')))

    # Ensure we CANNOT gather basic SNMP facts from the device
    res = get_snmp_facts(localhost, host=dut_mgmt_ip, version='v2c', community=creds['snmp_rocommunity'],
                         module_ignore_errors=True)

    pytest_assert('ansible_facts' not in res and "No SNMP response received before timeout" in res.get('msg', ''))

    # Ensure we cannot send an NTP request to the DUT
    if NTPLIB_INSTALLED:
        try:
            ntp_client.request(dut_mgmt_ip)
            pytest.fail("NTP did not time out when expected")
        except ntplib.NTPException:
            pass

    # Wait until the original service ACLs are reinstated and the SSH port on the
    # DUT is open to us once again. Note that the timeout here should be set sufficiently
    # long enough to allow config_service_acls.sh to reset the ACLs to their original
    # configuration.
    res = localhost.wait_for(host=dut_mgmt_ip,
                             port=SONIC_SSH_PORT,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             delay=0,
                             timeout=90,
                             module_ignore_errors=True)

    pytest_assert(not res.is_failed, "SSH did not start working when expected. {}".format(res.get('msg', '')))

    # Delete config_service_acls.sh from the DuT
    duthost.file(path="/tmp/config_service_acls.sh", state="absent")

    # Ensure we can gather basic SNMP facts from the device once again. Should fail on timeout
    get_snmp_facts(localhost, 
                   host=dut_mgmt_ip, 
                   version="v2c", 
                   community=creds['snmp_rocommunity'], 
                   wait=True, 
                   timeout = 20, 
                   interval=20)
