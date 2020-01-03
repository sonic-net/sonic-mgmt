import pytest
from ansible_host import AnsibleHost

PSU_STATUS_OK = 2

def test_snmp_numpsu(ansible_adhoc, testbed, creds, duthost):

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)
    hostip = ans_host.host.options['inventory_manager'].get_host(hostname).vars['ansible_host']

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community="public")['ansible_facts']
    print("SNMP_FACTS")
    print(snmp_facts)
    res = duthost.shell("psuutil numpsus")
    assert int(res[u'rc']) == 0, "Failed to get number of PSUs"

    numpsus = int(res['stdout'])
    assert numpsus == len(snmp_facts['snmp_psu'])


def test_snmp_psu_status(ansible_adhoc, testbed, creds):

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)
    hostip = ans_host.host.options['inventory_manager'].get_host(hostname).vars['ansible_host']

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community="public")['ansible_facts']

    for k, v in snmp_facts['snmp_psu'].items():
        if int(v['operstatus']) != PSU_STATUS_OK:
            pytest.fail("PSU {} operstatus is not OK!".format(k))