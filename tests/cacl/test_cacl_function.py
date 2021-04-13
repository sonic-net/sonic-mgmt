import pytest

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer globally
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

SONIC_SSH_PORT  = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'


def test_cacl_function(duthosts, rand_one_dut_hostname, localhost, creds):
    """Test control plane ACL functionality on a SONiC device
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_mgmt_ip = duthost.mgmt_ip

    # Ensure we can gather basic SNMP facts from the device
    res = localhost.snmp_facts(host=dut_mgmt_ip, version='v2c', community=creds['snmp_rocommunity'])

    if 'ansible_facts' not in res:
        pytest.fail("Failed to retrieve SNMP facts from DuT!")

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
                             delay=0,
                             timeout=20,
                             module_ignore_errors=True)

    if res.is_failed:
        pytest.fail("SSH port did not stop. {}".format(res.get('msg', '')))

    # Try to SSH back into the DuT, it should time out
    res = localhost.wait_for(host=dut_mgmt_ip,
                             port=SONIC_SSH_PORT,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             delay=0,
                             timeout=10,
                             module_ignore_errors=True)

    if not res.is_failed:
        pytest.fail("SSH did not timeout when expected. {}".format(res.get('msg', '')))

    # Ensure we CANNOT gather basic SNMP facts from the device
    res = localhost.snmp_facts(host=dut_mgmt_ip, version='v2c', community=creds['snmp_rocommunity'],
                               module_ignore_errors=True)

    if 'ansible_facts' in res or "No SNMP response received before timeout" not in res.get('msg', ''):
        pytest.fail("SNMP did not time out when expected")


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

    if res.is_failed:
        pytest.fail("SSH did not start working when expected. {}".format(res.get('msg', '')))

    # Delete config_service_acls.sh from the DuT
    duthost.file(path="/tmp/config_service_acls.sh", state="absent")

    # Ensure we can gather basic SNMP facts from the device once again
    res = localhost.snmp_facts(host=dut_mgmt_ip, version='v2c', community=creds['snmp_rocommunity'],
                               module_ignore_errors=True)

    if 'ansible_facts' not in res:
        pytest.fail("Failed to retrieve SNMP facts from DuT!")
