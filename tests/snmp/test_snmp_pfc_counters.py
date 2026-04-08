import pytest
from tests.common.helpers.snmp_helpers import get_snmp_facts

pytestmark = [
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def test_snmp_pfc_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, creds_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']

    snmp_facts = get_snmp_facts(
        duthost, localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']

    # Get the hardware SKU of the DUT
    hwsku = duthost.facts.get('hwsku', '')

    # Check PFC counters
    # Ignore management ports, assuming the names starting with 'eth', eg. eth0
    for _, v in list(snmp_facts['snmp_interfaces'].items()):
        desc = v.get('description', '')
        name = v.get('name', '')

        if 'Ethernet' not in desc:
            continue

        # Skip management ports for Arista 7060x6 platforms
        if 'Arista-7060X6' in hwsku and 'PT0' in desc:
            continue

        # Check for required PFC counters
        required_keys = ['cpfcIfRequests', 'cpfcIfIndications', 'requestsPerPriority', 'indicationsPerPriority']
        if not all(key in v for key in required_keys):
            pytest.fail(f"Port {name} (desc: '{desc}') missing PFC counters: {required_keys}")
