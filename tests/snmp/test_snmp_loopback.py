import pytest
import time
import logging
import ipaddress

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

@pytest.mark.bsl
def test_snmp_loopback(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo, localhost, creds):
    """
    Test SNMP query to DUT over loopback IP 
      - Send SNMP query over loopback IP from one of the BGP Neighbors
      - Get SysDescr from snmpfacts 
      - compare result from snmp query over loopback IP and snmpfacts
    """
    duthost = duthosts[rand_one_dut_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    # Get first neighbor VM information
    nbr = nbrhosts[list(nbrhosts.keys())[0]]


    # Copy config_service_acls.sh to the DuT (this also implicitly verifies we can successfully SSH to the DuT)
    duthost.copy(src="scripts/loopback_snmp_acls.sh", dest="/tmp/loopback_snmp_acls.sh", mode="0755")

    # TODO: Fix snmp query over Management IPv6 adderess and add SNMP test over management IPv6 address.

    # Perform SNMP walk from neighbor so that query is sent to front panel interface
    for ip in config_facts[u'LOOPBACK_INTERFACE'][u'Loopback0']:
        loip = ip.split('/')[0]
        loip = ipaddress.ip_address(loip)
        # TODO : Fix snmp query over loopback v6 and remove this check and add IPv6 ACL table/rule.
        if isinstance(loip, ipaddress.IPv6Address):
            continue
        # Run loopback_snmp_acls.sh script in the background to install the required ACL rule
        # and clean up after snmp query over the IP address is executed.
        shell_cmd = "nohup /tmp/loopback_snmp_acls.sh " + str(ip) + " /dev/null > /dev/null 2>&1 &" 
        duthost.shell(shell_cmd)
        eos_snmpwalk = 'bash snmpget -v2c -c ' + creds['snmp_rocommunity'] + ' ' + str(loip)  + ' 1.3.6.1.2.1.1.1.0'
        out = nbr['host'].eos_command(
            commands=[eos_snmpwalk])
        result = out[u'stdout_lines']
        assert len(out[u'stdout_lines']) > 0, 'No result from snmpwalk'
        for line in out[u'stdout_lines'][0]:
            assert snmp_facts['ansible_sysdescr'] in line, 'Sysdescr not found in SNMP result from loopbackIP.'
