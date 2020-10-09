import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_bgp_facts(duthost):
    """compare the bgp facts between observed states and target state"""

    bgp_facts = duthost.bgp_facts()['ansible_facts']
    mg_facts  = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'
        # Verify locat ASNs in bgp sessions
        assert v['local AS'] == mg_facts['minigraph_bgp_asn']
        # Check bgpmon functionality by validate STATE DB contains this neighbor as well
        state_fact = duthost.shell('sonic-db-cli STATE_DB HGET "NEIGH_STATE_TABLE|{}" "state"'.format(k), module_ignore_errors=False)['stdout_lines']
        assert state_fact[0] == "Established"

    for v in mg_facts['minigraph_bgp']:
        # Compare the bgp neighbors name with minigraph bgp neigbhors name
        assert v['name'] == bgp_facts['bgp_neighbors'][v['addr'].lower()]['description']
        # Compare the bgp neighbors ASN with minigraph
        assert v['asn'] == bgp_facts['bgp_neighbors'][v['addr'].lower()]['remote AS']
