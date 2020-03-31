import pytest
from ansible_host import AnsibleHost
from common.utilities import wait_until

@pytest.fixture(scope="module", autouse=True)
def setup_check_snmp_ready(testbed, testbed_devices):
    dut = testbed_devices['dut']
    assert wait_until(300, 20, dut.is_service_fully_started, "snmp"), "SNMP service is not running"

def test_snmp_queues(ansible_adhoc, testbed, creds, collect_techsupport):

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)
    hostip = ans_host.host.options['inventory_manager'].get_host(hostname).vars['ansible_host']

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['description']:
            if not v.has_key('queues'):
                pytest.fail("port %s does not have queue counters" % v['name'])
