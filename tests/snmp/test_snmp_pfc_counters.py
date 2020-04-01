import pytest
from ansible_host import AnsibleHost
from test_snmp import check_snmp_ready

@pytest.fixture(scope="module", autouse=True)
def setup_check_snmp_ready(testbed, testbed_devices):
    check_snmp_ready(testbed, testbed_devices)

def test_snmp_pfc_counters(ansible_adhoc, testbed, creds):

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)
    hostip = ans_host.host.options['inventory_manager'].get_host(hostname).vars['ansible_host']

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    # Check PFC counters
    # Ignore management ports, assuming the names starting with 'eth', eg. eth0
    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['description']:
            if not v.has_key('cpfcIfRequests') or \
               not v.has_key('cpfcIfIndications') or \
               not v.has_key('requestsPerPriority') or \
               not v.has_key('indicationsPerPriority'):
                pytest.fail("port %s does not have pfc counters" % v['name'])
