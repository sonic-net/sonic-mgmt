from ansible_host import AnsibleHost

def test_bgp_facts(ansible_adhoc, testbed,duthost):
    """compare the bgp facts between observed states and target state"""

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    npus = duthost.num_npus()
    bgp_facts = ans_host.bgp_facts(num_npus=npus)['ansible_facts']
    mg_facts  = ans_host.minigraph_facts(host=hostname)['ansible_facts']

    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'
        # Verify locat ASNs in bgp sessions
        assert v['local AS'] == mg_facts['minigraph_bgp_asn']

    for v in mg_facts['minigraph_bgp']:
        # Compare the bgp neighbors name with minigraph bgp neigbhors name
        assert v['name'] == bgp_facts['bgp_neighbors'][v['addr'].lower()]['description']
        # Compare the bgp neighbors ASN with minigraph
        assert v['asn'] == bgp_facts['bgp_neighbors'][v['addr'].lower()]['remote AS']
