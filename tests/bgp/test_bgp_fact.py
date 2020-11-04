import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_bgp_facts(duthosts, dut_index, asic_index):
    """compare the bgp facts between observed states and target state"""

    duthost = duthosts[dut_index]
    bgp_facts =duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    config_facts = duthost.config_facts(host=duthost.hostname, source="running",namespace=namespace)['ansible_facts']

    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'
        # Verify locat ASNs in bgp sessions
        assert v['local AS'] == int(config_facts['DEVICE_METADATA']['localhost']['bgp_asn'].decode("utf-8"))

    for k, v in config_facts['BGP_NEIGHBOR'].items():
        # Compare the bgp neighbors name with config db bgp neigbhors name
        assert v['name'] == bgp_facts['bgp_neighbors'][k]['description']
        # Compare the bgp neighbors ASN with config db
        assert int(v['asn'].decode("utf-8")) == bgp_facts['bgp_neighbors'][k]['remote AS']

