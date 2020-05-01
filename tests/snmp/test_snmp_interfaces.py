import pytest
from ansible_host import AnsibleHost

@pytest.mark.bsl
def test_snmp_interfaces(ansible_adhoc, duthost, creds):
    """compare the bgp facts between observed states and target state"""

    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    npus =  duthost.num_npus()

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    config_facts  = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify management port in snmp interface list
    for name in config_facts.get('MGMT_INTERFACE', {}):
        assert name in snmp_ifnames

    if (npus > 1):
        for npu_inst in range(npus):
            npu_config_path = "/etc/sonic/config_db" + str(npu_inst) + ".json"
            config_facts  = duthost.config_facts(host=duthost.hostname, source="persistent", filename=npu_config_path)['ansible_facts']
            pdb.set_trace()
            for _, alias in config_facts['port_name_to_alias_map'].items():
                assert alias in snmp_ifnames
            for po_name in config_facts.get('PORTCHANNEL', {}):
                assert po_name in snmp_ifnames
    else:
        config_facts  = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
        for _, alias in config_facts['port_name_to_alias_map'].items():
            assert alias in snmp_ifnames
        for po_name in config_facts.get('PORTCHANNEL', {}):
            assert po_name in snmp_ifnames
