"""
Test SNMPv2MIB in SONiC.
"""

import pytest
from tests.common.helpers.assertions import pytest_assert # pylint: disable=import-error

pytestmark = [
    pytest.mark.topology('any')
]


def test_snmp_v2mib(duthosts, rand_one_dut_hostname, localhost, creds):
    """
    Verify SNMPv2-MIB objects are functioning properly
    """
    duthost = duthosts[rand_one_dut_hostname]
    host_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=host_ip, version="v2c",
                                      community=creds["snmp_rocommunity"])['ansible_facts']
    dut_facts = duthost.setup()['ansible_facts']
    debian_ver = duthost.shell('cat /etc/debian_version')['stdout']
    cmd = 'docker exec snmp grep "sysContact" /etc/snmp/snmpd.conf'
    sys_contact = " ".join(duthost.shell(cmd)['stdout'].split()[1:])
    sys_location = duthost.shell("grep 'snmp_location' /etc/sonic/snmp.yml")['stdout'].split()[-1]

    expected_res = {'kernel_version': dut_facts['ansible_kernel'],
                    'hwsku': duthost.facts['hwsku'],
                    'os_version': 'SONiC.{}'.format(duthost.os_version),
                    'debian_version': '{} {}'.format(dut_facts['ansible_distribution'], debian_ver)}

    #Verify that sysName, sysLocation and sysContact MIB objects functions properly
    pytest_assert(snmp_facts['ansible_sysname'] == duthost.hostname,
                  "Unexpected MIB result {}".format(snmp_facts['ansible_sysname']))
    pytest_assert(snmp_facts['ansible_syslocation'] == sys_location,
                  "Unexpected MIB result {}".format(snmp_facts['ansible_syslocation']))
    pytest_assert(snmp_facts['ansible_syscontact'] == sys_contact,
                  "Unexpected MIB result {}".format(snmp_facts['ansible_syscontact']))

    #Verify that sysDescr MIB object functions properly
    missed_values = []
    for system_value in expected_res:
        if expected_res[system_value] not in snmp_facts['ansible_sysdescr']:
            missed_values.append(expected_res[system_value])
    pytest_assert(not missed_values, "System values {} was not found in SNMP facts: {}"
                  .format(missed_values, snmp_facts['ansible_sysdescr']))
