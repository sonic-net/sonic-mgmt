import pytest
from ansible_host import AnsibleHost

def test_snmp_queues(ansible_adhoc, duthost, creds, collect_techsupport):

    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['description']:
            if not v.has_key('queues'):
                pytest.fail("port %s does not have queue counters" % v['name'])
