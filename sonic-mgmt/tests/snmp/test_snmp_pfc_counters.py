import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_snmp_pfc_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, creds_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"])['ansible_facts']

    # Check PFC counters
    # Ignore management ports, assuming the names starting with 'eth', eg. eth0
    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['description']:
            if not v.has_key('cpfcIfRequests') or \
               not v.has_key('cpfcIfIndications') or \
               not v.has_key('requestsPerPriority') or \
               not v.has_key('indicationsPerPriority'):
                pytest.fail("port %s does not have pfc counters" % v['name'])
