import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def collect_all_facts(duthost):
    """
    Collect all data needed for test per each port from DUT
    :param duthost: DUT host object
    :return: dict with data collected from DUT per each port
    """
    result = {}
    setup = duthost.setup()['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    cmd = 'redis-cli -n 0 --raw hget "PORT_TABLE:{}" "{}"'
    ports_list = []
    _ = [ports_list.extend(config_facts.get(i, {}).keys())
         for i in ['port_name_to_alias_map', 'PORTCHANNEL', 'MGMT_INTERFACE']]

    for name in ports_list:
        key = 'ansible_{}'.format(name)
        # 6 stands for ethernet-csmacd and 161 stands for ieee8023adLag
        if_type = '161' if name.startswith("PortChannel") else '6'
        if name.startswith("Eth"):
            portname = config_facts['port_name_to_alias_map'][name]
            result.setdefault(portname, {})
            result[portname].update({'speed': int(config_facts.get('PORT', {})[name]['speed'])})
            result[portname].update({'mtu': str(setup[key]['mtu'])})
            result[portname].update({'type': if_type})
            # Workaround, some ports have missing key admin_status in config
            try:
                admin = config_facts.get('PORT', {})[name]['admin_status']
            except KeyError:
                admin = duthost.shell(cmd.format(name, 'admin_status'))['stdout']
            result[portname].update({'adminstatus': admin})
            oper = duthost.shell(cmd.format(name, 'oper_status'))['stdout']
            result[portname].update({'operstatus': oper})
            result[portname].update({'description': config_facts.get('PORT', {})[name]['description']})
        else:
            result.setdefault(name, {})
            key_word = "PORTCHANNEL" if name.startswith("PortChannel") else 'MGMT_PORT'
            result[name].update({'mtu': str(setup[key]['mtu'])})
            result[name].update({'type': if_type})
            result[name].update({'adminstatus': config_facts.get(key_word, {})[name]['admin_status']})
            if name.startswith("PortChannel"):
                oper = duthost.shell('redis-cli -n 0 --raw hget "LAG_TABLE:{}" "oper_status"'.format(name))
            else:
                oper = duthost.shell('redis-cli -n 6 --raw hget "MGMT_PORT_TABLE|{}" "oper_status"'.format(name))
            result[name].update({'operstatus': oper['stdout']})
            result[name].update({'description': config_facts.get(key_word, {})[name].get('description', '')})
    return result

def verify_port_snmp(facts, snmp_facts):
    """
    Compare port MIBs with ports data received from DUT
    :param facts: Dict with facts collected from DUT
    :param snmp_facts: Collected snmp_facts
    :return: Dict with unequal snmp_facts
    """
    missed = {}
    for _, port_snmp in snmp_facts['snmp_interfaces'].items():
        port_name = port_snmp['name']
        compare = ['operstatus', 'adminstatus', 'mtu', 'description', 'type']
        missed.setdefault(port_name, {})
        for field in compare:
            # Skip MTU on mgmt port for now, due to not implemented in Sonic for mgmt port
            if field == 'mtu' and port_name.startswith('eth0'):
                continue
            elif facts[port_name][field] != port_snmp[field]:
                missed[port_name].update({field: port_snmp[field]})
    return missed

def verify_port_ifindex(snmp_facts, results):
    """
    Verify correct behaviour of ports ifindex MIB
    :param snmp_facts: Collected snmp_facts
    :param results: Dict with unequal snmp_facts
    :return: dict with unequal snmp_facts per port
    """
    unique = []
    for port_index, port_snmp in snmp_facts['snmp_interfaces'].items():
        port_name = port_snmp['name']
        unique.append(port_snmp['ifindex'])
        if int(port_index) - 1 != int(port_snmp['ifindex']):
            results[port_name].update({'ifindex': port_snmp['ifindex']})
    if len(unique) != len(set(unique)):
        pytest.fail("Ifindex MIB values are not unique {}".format(unique))
    return {key: results[key] for key in results if results[key]}

def verify_snmp_speed(facts, snmp_facts, results):
    """
    Verify correct behaviour of physical ports MIBs ifSpeed, ifHighSpeed
    :param facts: Dict with facts collected from DUT
    :param snmp_facts: Collected snmp_facts
    :param results: Dict with unequal snmp_facts
    :return: Updated dict with unequal snmp_facts
    """
    speed, high_speed = "speed", "ifHighSpeed"
    for _, port_snmp in snmp_facts['snmp_interfaces'].items():
        port_name = port_snmp['name']
        if port_name.startswith('Eth'):
            speed_to_bps = facts[port_name][speed] * 1000000
            if speed_to_bps > int(port_snmp[speed]):
                # If the bandwidth of the interface is greater than the maximum value
                # reportable by this object then this object should report its
                # maximum value 4294967295 and ifHighSpeed must be used
                # to report the interace's speed.
                if int(port_snmp[speed]) != 4294967295:
                    results[port_name].update({speed: port_snmp[speed]})
                if int(port_snmp[high_speed]) != facts[port_name][speed]:
                    results[port_name].update({high_speed: port_snmp[high_speed]})
            elif speed_to_bps < int(port_snmp[speed]):
                results[port_name].update({speed: port_snmp[speed]})
                if int(port_snmp[high_speed]):
                    results[port_name].update({high_speed: port_snmp[high_speed]})
    return results

@pytest.mark.bsl
def test_snmp_interfaces(localhost, creds_all_duts, duthosts, enum_rand_one_per_hwsku_hostname, enum_asic_index):
    """compare the snmp facts between observed states and target state"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("interfaces not present on supervisor node")
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    namespace = duthost.get_namespace_from_asic_id(enum_asic_index)
    config_facts  = duthost.config_facts(host=duthost.hostname, source="persistent", namespace=namespace)['ansible_facts']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"])['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify all physical ports in snmp interface list
    for _, alias in config_facts['port_name_to_alias_map'].items():
        assert alias in snmp_ifnames, "Interface not found in SNMP facts."

    # Verify all port channels in snmp interface list
    for po_name in config_facts.get('PORTCHANNEL', {}):
        assert po_name in snmp_ifnames, "PortChannel not found in SNMP facts."

@pytest.mark.bsl
def test_snmp_mgmt_interface(localhost, creds_all_duts, duthosts, enum_rand_one_per_hwsku_hostname):
    """compare the snmp facts between observed states and target state"""

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"])['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify management port in snmp interface list
    for name in config_facts.get('MGMT_INTERFACE', {}):
        assert name in snmp_ifnames, "Management Interface not found in SNMP facts."

def test_snmp_interfaces_mibs(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts):
    """Verify correct behaviour of port MIBs ifIndex, ifMtu, ifSpeed,
       ifAdminStatus, ifOperStatus, ifAlias, ifHighSpeed, ifType """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"])['ansible_facts']

    dut_facts = collect_all_facts(duthost)
    ports_snmps = verify_port_snmp(dut_facts, snmp_facts)
    speed_snmp = verify_snmp_speed(dut_facts, snmp_facts, ports_snmps)
    result = verify_port_ifindex(snmp_facts, speed_snmp)
    pytest_assert(not result, "Unexpected comparsion of SNMP: {}".format(result))
