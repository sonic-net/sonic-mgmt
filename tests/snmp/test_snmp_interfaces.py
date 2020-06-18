import pytest


@pytest.mark.bsl
def test_snmp_interfaces(duthost, localhost, creds):
    """compare the bgp facts between observed states and target state"""

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    config_facts  = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify all physical ports in snmp interface list
    for _, alias in config_facts['port_name_to_alias_map'].items():
        assert alias in snmp_ifnames

    # Verify all port channels in snmp interface list
    for po_name in config_facts.get('PORTCHANNEL', {}):
        assert po_name in snmp_ifnames

    # Verify management port in snmp interface list
    for name in config_facts.get('MGMT_INTERFACE', {}):
        assert name in snmp_ifnames

    # Verify Vlan interfaces in snmp interface list
    for name in config_facts.get('VLAN_INTERFACE', {}):
        assert name in snmp_ifnames


def test_snmp_interface_counters(duthost, localhost, creds):
    """Make sure Interface MIB has counters available"""
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['name'] or "PortChannel" in v['name']:
            if not v.has_key('ifInErrors') or \
               not v.has_key('ifOutErrors') or \
               not v.has_key('ifInDiscards') or \
               not v.has_key('ifHCInOctets') or \
               not v.has_key('ifOutDiscards') or \
               not v.has_key('ifHCOutOctets') or \
               not v.has_key('ifInUcastPkts') or \
               not v.has_key('ifOutUcastPkts'):
                pytest.fail("interface %s does not have counters" % v['name'])


def test_snmp_l3vlan_counters(duthost, localhost, creds):
    """Make sure Interface MIB has counters available for l3vlan"""
    if duthost.facts["asic_type"] not in ["mellanox"]:
        pytest.skip("Skip test due to RIF counter not supported{}".format(duthost.facts["platform"]))

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Vlan" in v['name']:
            if not v.has_key('ifInErrors') or \
               not v.has_key('ifOutErrors') or \
               not v.has_key('ifInUcastPkts') or \
               not v.has_key('ifOutUcastPkts'):
                pytest.fail("interface %s does not have counters" % v['name'])
