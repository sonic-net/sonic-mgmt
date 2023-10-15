import pytest
from tests.common.helpers.snmp_helpers import get_snmp_facts

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def test_snmp_pfc_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, creds_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']

    snmp_facts = get_snmp_facts(
        localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']

    # Check PFC counters
    # Ignore management ports, assuming the names starting with 'eth', eg. eth0
    for k, v in list(snmp_facts['snmp_interfaces'].items()):
        if "Ethernet" in v['description']:
            if 'cpfcIfRequests' not in v or \
               'cpfcIfIndications' not in v or \
               'requestsPerPriority' not in v or \
               'indicationsPerPriority' not in v:
                pytest.fail("port %s does not have pfc counters" % v['name'])
