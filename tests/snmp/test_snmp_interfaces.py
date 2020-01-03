from ansible_host import AnsibleHost

def test_snmp_interfaces(ansible_adhoc, duthost, creds):
    """compare the bgp facts between observed states and target state"""

    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    config_facts  = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify all physical ports in snmp interface list
    for k, v in config_facts['config_ports'].items():
        assert config_facts['config_port_name_to_alias_map'][k] in snmp_ifnames

    # Verify all port channels in snmp interface list
    for k, v in config_facts['config_portchannels'].items():
        assert k in snmp_ifnames
    
    # Verify management port in snmp interface list
    assert config_facts['config_mgmt_interface']['alias'] in snmp_ifnames
    print config_facts['config_mgmt_interface']
