import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.snmp_helpers import get_snmp_facts

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def collect_all_facts(duthost, ports_list, namespace=None):
    """
    Collect all data needed for test per each port from DUT
    :param duthost: DUT host object
    :return: dict with data collected from DUT per each port
    """
    result = {}
    setup = duthost.interface_facts(namespace=namespace)['ansible_facts']['ansible_interface_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="running", namespace=namespace)['ansible_facts']

    if not namespace:
        sonic_db_cmd = "sonic-db-cli"
    else:
        sonic_db_cmd = "sonic-db-cli -n {}".format(namespace)

    for name in ports_list:
        key = name
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
                admin = duthost.shell('{} APPL_DB HGET "PORT_TABLE:{}" "admin_status"'.format(sonic_db_cmd, name), module_ignore_errors=False)['stdout']
            result[portname].update({'adminstatus': admin})
            oper = duthost.shell('{} APPL_DB HGET "PORT_TABLE:{}" "oper_status"'.format(sonic_db_cmd, name), module_ignore_errors=False)['stdout']
            result[portname].update({'operstatus': oper})
            result[portname].update({'description': config_facts.get('PORT', {})[name].get('description', '')})
        elif name.startswith("PortChannel"):
            result.setdefault(name, {})
            key_word = "PORTCHANNEL"
            result[name].update({'mtu': str(setup[key]['mtu'])})
            result[name].update({'type': if_type})
            result[name].update({'adminstatus': config_facts.get(key_word, {})[name]['admin_status']})
            oper = duthost.shell('{} APPL_DB HGET "LAG_TABLE:{}" "oper_status"'.format(sonic_db_cmd, name), module_ignore_errors=False)
            result[name].update({'operstatus': oper['stdout']})
            result[name].update({'description': config_facts.get(key_word, {})[name].get('description', '')})
        else:
            key_word = "MGMT_PORT"
            result.setdefault(name, {})
            result[name].update({'mtu': str(setup[key]['mtu'])})
            result[name].update({'type': if_type})
            result[name].update({'adminstatus': config_facts.get(key_word, {})[name]['admin_status']})
            oper = duthost.shell('{} STATE_DB HGET "MGMT_PORT_TABLE|{}" "oper_status"'.format(sonic_db_cmd, name), module_ignore_errors=False)
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
    snmp_port_map = { snmp_facts['snmp_interfaces'][idx]['name'] : idx for idx in snmp_facts['snmp_interfaces'] }

    for port_name in facts:
        idx = snmp_port_map[port_name]
        port_snmp = snmp_facts['snmp_interfaces'][idx]
        compare = ['operstatus', 'adminstatus', 'mtu', 'description', 'type']
        missed.setdefault(port_name, {})
        for field in compare:
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
    snmp_port_map = { snmp_facts['snmp_interfaces'][idx]['name'] : idx for idx in snmp_facts['snmp_interfaces'] }
    for port_name in results:
        idx = snmp_port_map[port_name]
        port_snmp = snmp_facts['snmp_interfaces'][idx]
        unique.append(port_snmp['ifindex'])
        if int(idx) - 1 != int(port_snmp['ifindex']):
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
    snmp_port_map = { snmp_facts['snmp_interfaces'][idx]['name'] : idx for idx in snmp_facts['snmp_interfaces'] }
    for port_name in results:
        idx = snmp_port_map[port_name]
        port_snmp = snmp_facts['snmp_interfaces'][idx]
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
    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"], wait=True)['ansible_facts']

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

    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"], wait=True)['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    snmp_ifnames = [ v['name'] for k, v in snmp_facts['snmp_interfaces'].items() ]
    print snmp_ifnames

    # Verify management port in snmp interface list
    for name in config_facts.get('MGMT_INTERFACE', {}):
        assert name in snmp_ifnames, "Management Interface not found in SNMP facts."

    # TODO: Remove this check after operational status of mgmt interface
    # is implemented for multi-asic platform
    if duthost.num_asics() == 1:
        ports_list = []
        ports_list.extend(config_facts.get('MGMT_INTERFACE', {}).keys())
        dut_facts = collect_all_facts(duthost, ports_list)
        ports_snmps = verify_port_snmp(dut_facts, snmp_facts)
        speed_snmp = verify_snmp_speed(dut_facts, snmp_facts, ports_snmps)
        result = verify_port_ifindex(snmp_facts, speed_snmp)
        pytest_assert(not result, "Unexpected comparsion of SNMP: {}".format(result))

def test_snmp_interfaces_mibs(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts, enum_asic_index):
    """Verify correct behaviour of port MIBs ifIndex, ifMtu, ifSpeed,
       ifAdminStatus, ifOperStatus, ifAlias, ifHighSpeed, ifType """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    namespace = duthost.get_namespace_from_asic_id(enum_asic_index)
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"], wait=True)['ansible_facts']
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent", namespace=namespace)['ansible_facts']

    ports_list = []
    for i in ['port_name_to_alias_map', 'PORTCHANNEL']:
        ports_list.extend(config_facts.get(i, {}).keys())

    dut_facts = collect_all_facts(duthost, ports_list, namespace)
    ports_snmps = verify_port_snmp(dut_facts, snmp_facts)
    speed_snmp = verify_snmp_speed(dut_facts, snmp_facts, ports_snmps)
    result = verify_port_ifindex(snmp_facts, speed_snmp)
    pytest_assert(not result, "Unexpected comparsion of SNMP: {}".format(result))
