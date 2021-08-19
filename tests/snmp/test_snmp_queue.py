import pytest
from tests.common.helpers.snmp_helpers import get_snmp_facts

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_snmp_queues(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts, collect_techsupport_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("interfaces not present on supervisor node")
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"], wait=True)['ansible_facts']

    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['description']:
            if not v.has_key('queues'):
                pytest.fail("port %s does not have queue counters" % v['name'])
