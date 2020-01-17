from ansible_host import AnsibleHost

def test_snmp_interfaces(ansible_adhoc, testbed, creds):
    """compare the bgp facts between observed states and target state"""

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)

    hostip = ans_host.host.options['inventory_manager'].get_host(hostname).vars['ansible_host']

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    mg_facts   = ans_host.minigraph_facts(host=hostname)['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify all physical ports in snmp interface list
    for k, v in mg_facts['minigraph_ports'].items():
        assert mg_facts['minigraph_port_name_to_alias_map'][k] in snmp_ifnames

    # Verify all port channels in snmp interface list
    for k, v in mg_facts['minigraph_portchannels'].items():
        assert k in snmp_ifnames
    
    # Verify management port in snmp interface list
    assert mg_facts['minigraph_mgmt_interface']['alias'] in snmp_ifnames
    print mg_facts['minigraph_mgmt_interface']
