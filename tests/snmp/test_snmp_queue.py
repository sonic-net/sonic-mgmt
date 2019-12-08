import pytest
from ansible_host import AnsibleHost

def test_snmp_queues(ansible_adhoc, testbed, creds):

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)

    snmp_facts = lhost.snmp_facts(host=hostname, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['description']:
            if not v.has_key('queues'):
                pytest.fail("port %s does not have queue counters" % v['name'])
