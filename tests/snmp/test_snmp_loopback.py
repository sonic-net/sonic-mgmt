import pytest
from tests.common.helpers.snmp_helpers import get_snmp_facts, get_snmp_output
from tests.common.devices.eos import EosHost

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'm0', 'mx'),
    pytest.mark.device_type('vs')
]


def test_snmp_loopback(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                       nbrhosts, tbinfo, localhost, creds_all_duts):
    """
    Test SNMP query to DUT over loopback IP
      - Send SNMP query over loopback IP from one of the BGP Neighbors
      - Get SysDescr from snmpfacts
      - compare result from snmp query over loopback IP and snmpfacts
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(
        localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="persistent")['ansible_facts']
    # Get first neighbor VM information
    nbr = nbrhosts[list(nbrhosts.keys())[0]]

    for ip in config_facts['LOOPBACK_INTERFACE']['Loopback0']:
        loip = ip.split('/')[0]
        result = get_snmp_output(loip, duthost, nbr, creds_all_duts)
        assert result is not None, 'No result from snmpget'
        assert len(result['stdout_lines']) > 0, 'No result from snmpget'
        if isinstance(nbr["host"], EosHost):
            stdout_lines = result['stdout_lines'][0][0]
        else:
            stdout_lines = result['stdout_lines'][0]
        assert "SONiC Software Version" in stdout_lines,\
            "Sysdescr not found in SNMP result from IP {}".format(ip)
        assert snmp_facts['ansible_sysdescr'] in stdout_lines,\
            "Sysdescr from IP{} not matching with result from Mgmt IPv4.".format(ip)
