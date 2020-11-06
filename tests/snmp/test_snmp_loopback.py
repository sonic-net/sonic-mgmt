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
def test_snmp_loopback(duthosts, dut_index, nbrhosts, tbinfo, localhost, creds):
    """
    Test SNMP query to DUT over loopback IP 

      - Send SNMP query over loopback IP from one of the BGP Neighbors
      - Get SysDescr from snmpfacts 
      - compare result from snmp query over loopback IP and snmpfacts

    """
    duthost = duthosts[dut_index]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    # Get first neighbor VM information
    nbr = nbrhosts[list(nbrhosts.keys())[0]]

    # Perform SNMP walk from neighbor  
    for ip in config_facts[u'LOOPBACK_INTERFACE'][u'Loopback0']:
        ip = ip.split('/')[0]
        eos_snmpwalk = 'bash snmpget -v2c -c ' + creds['snmp_rocommunity'] + ' ' + ip  + ' 1.3.6.1.2.1.1.1.0'
        out = nbr['host'].eos_command(
            commands=[eos_snmpwalk])
        result = out[u'stdout_lines']
        assert len(out[u'stdout_lines']) > 0, 'No result from snmpwalk'
        for line in out[u'stdout_lines'][0]:
            assert snmp_facts['ansible_sysdescr'] in line, 'Sysdescr not found in SNMP result from loopbackIP.'

