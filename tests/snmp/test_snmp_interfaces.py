import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

@pytest.mark.bsl
def test_snmp_interfaces(localhost, creds, duthosts, enum_dut_hostname, enum_asic_index):
    """compare the snmp facts between observed states and target state"""
    duthost = duthosts[enum_dut_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    namespace = duthost.get_namespace_from_asic_id(enum_asic_index)
    config_facts  = duthost.config_facts(host=duthost.hostname, source="persistent", namespace=namespace)['ansible_facts']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify all physical ports in snmp interface list
    for _, alias in config_facts['port_name_to_alias_map'].items():
        assert alias in snmp_ifnames, "Interface not found in SNMP facts."

    # Verify all port channels in snmp interface list
    for po_name in config_facts.get('PORTCHANNEL', {}):
        assert po_name in snmp_ifnames, "PortChannel not found in SNMP facts."

@pytest.mark.bsl
def test_snmp_mgmt_interface(localhost, creds, duthosts, enum_dut_hostname):
    """compare the snmp facts between observed states and target state"""

    duthost = duthosts[enum_dut_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify management port in snmp interface list
    for name in config_facts.get('MGMT_INTERFACE', {}):
        assert name in snmp_ifnames, "Management Interface not found in SNMP facts."
