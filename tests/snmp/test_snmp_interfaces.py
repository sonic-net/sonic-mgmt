import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.snmp_helpers import get_snmp_facts
from tests.common.constants import CounterpollConstants
from tests.common.helpers.counterpoll_helper import ConterpollHelper
from tests.common.utilities import parse_rif_counters, wait_until

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

SAI_PORT_STAT_IF_IN_ERRORS = 'SAI_PORT_STAT_IF_IN_ERRORS'
SAI_PORT_STAT_IF_OUT_ERRORS = 'SAI_PORT_STAT_IF_OUT_ERRORS'
SAI_PORT_STAT_IF_IN_DISCARDS = 'SAI_PORT_STAT_IF_IN_DISCARDS'
SAI_PORT_STAT_IF_OUT_DISCARDS = 'SAI_PORT_STAT_IF_OUT_DISCARDS'
SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS = 'SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS'
SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS = 'SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS'

COUNTERS_PORT_NAME_MAP = 'COUNTERS_PORT_NAME_MAP'
COUNTERS_RIF_NAME_MAP = 'COUNTERS_RIF_NAME_MAP'
COUNTER_VALUE = 5000


@pytest.fixture()
def disable_conterpoll(duthost):
    """
    Disable conterpoll for RIF and PORT and re-enable it when TC finished
    :param duthost: DUT host object
    :return: dict with data collected from DUT per each port
    """
    counter_type_list = [CounterpollConstants.PORT,
                         CounterpollConstants.RIF]
    if duthost.is_multi_asic:
        for asic in duthost.asics:
            ConterpollHelper.disable_counterpoll(duthost, counter_type_list, asic)
    else:
        ConterpollHelper.disable_counterpoll(duthost, counter_type_list)
    yield
    if duthost.is_multi_asic:
        for asic in duthost.asics:
            ConterpollHelper.enable_counterpoll(duthost, counter_type_list, asic)
    else:
        ConterpollHelper.enable_counterpoll(duthost, counter_type_list)


def get_interfaces(duthost, tbinfo):
    """
    Method to get interfaces for testing
    :param duthost: DUT host object
    :return: RIF interface name in case available in topo. If not - return Port Channel name and interface in Port
     Channel
    """
    rif_counters = parse_rif_counters(duthost.command("show interfaces counters rif")["stdout_lines"])
    for interface in rif_counters:
        if 'Eth' in interface:
            return interface, interface
        else:
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
            return mg_facts["minigraph_portchannels"][interface]['members'][0], interface


def get_oid_for_interface(duthost, table_name, interface_name):
    """
    Method to get interface oid from Counters DB
    :param duthost: DUT host object
    :param table_name: table name
    :param interface_name: interface name
    :return: oid for specific interface
    """
    return duthost.command(f"docker exec -i database redis-cli --raw -n 2 HMGET "
                           f"{table_name} {interface_name}")["stdout"]


def set_counters_value(duthost, interface_oid, counter_name, counter_value):
    """
    Method to set interface counter value in Counters DB
    :param duthost: DUT host object
    :param interface_oid: oid value
    :param counter_name: counter name
    :param counter_value: counter value
    """
    duthost.command(f"sudo redis-cli -n 2 hset COUNTERS:{interface_oid} {counter_name} {counter_value}")


def get_port_interface_counter(duthost, interface_name):
    """
    Method to set interface counter value in Counters DB
    :param duthost: DUT host object
    :param interface_name: name of interface to collect counters
    :return : dict with counters
    """
    port_counters = duthost.show_and_parse("show interfaces counters")
    for port_counter in port_counters:
        if port_counter['iface'] == interface_name:
            for key, value in port_counter.items():
                if ',' in value:
                    port_counter[key] = value.replace(',', '')
            return port_counter


def collect_all_facts(duthost, ports_list, namespace=None):
    """
    Collect all data needed for test per each port from DUT
    :param duthost: DUT host object
    :return: dict with data collected from DUT per each port
    """
    result = {}
    setup = duthost.interface_facts(namespace=namespace)[
        'ansible_facts']['ansible_interface_facts']
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", namespace=namespace)['ansible_facts']

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
            result[portname].update(
                {'speed': int(config_facts.get('PORT', {})[name]['speed'])})
            result[portname].update({'mtu': str(setup[key]['mtu'])})
            result[portname].update({'type': if_type})
            # Workaround, some ports have missing key admin_status in config
            try:
                admin = config_facts.get('PORT', {})[name]['admin_status']
            except KeyError:
                admin = duthost.shell('{} APPL_DB HGET "PORT_TABLE:{}" "admin_status"'.format(
                    sonic_db_cmd, name), module_ignore_errors=False)['stdout']
            result[portname].update({'adminstatus': admin})
            oper = duthost.shell('{} APPL_DB HGET "PORT_TABLE:{}" "oper_status"'.format(
                sonic_db_cmd, name), module_ignore_errors=False)['stdout']
            result[portname].update({'operstatus': oper})
            result[portname].update({'description': config_facts.get(
                'PORT', {})[name].get('description', '')})
        elif name.startswith("PortChannel"):
            result.setdefault(name, {})
            key_word = "PORTCHANNEL"
            result[name].update({'mtu': str(setup[key]['mtu'])})
            result[name].update({'type': if_type})
            result[name].update({'adminstatus': config_facts.get(
                key_word, {})[name]['admin_status']})
            oper = duthost.shell('{} APPL_DB HGET "LAG_TABLE:{}" "oper_status"'.format(
                sonic_db_cmd, name), module_ignore_errors=False)
            result[name].update({'operstatus': oper['stdout']})
            result[name].update({'description': config_facts.get(
                key_word, {})[name].get('description', '')})
        else:
            key_word = "MGMT_PORT"
            result.setdefault(name, {})
            result[name].update({'mtu': str(setup[key]['mtu'])})
            result[name].update({'type': if_type})
            result[name].update({'adminstatus': config_facts.get(
                key_word, {})[name]['admin_status']})
            oper = duthost.shell('{} STATE_DB HGET "MGMT_PORT_TABLE|{}" "oper_status"'.format(
                sonic_db_cmd, name), module_ignore_errors=False)
            result[name].update({'operstatus': oper['stdout']})
            result[name].update({'description': config_facts.get(
                key_word, {})[name].get('description', '')})
    return result


def verify_port_snmp(facts, snmp_facts):
    """
    Compare port MIBs with ports data received from DUT
    :param facts: Dict with facts collected from DUT
    :param snmp_facts: Collected snmp_facts
    :return: Dict with unequal snmp_facts
    """
    missed = {}
    snmp_port_map = {snmp_facts['snmp_interfaces'][idx]
                     ['name']: idx for idx in snmp_facts['snmp_interfaces']}

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
    snmp_port_map = {snmp_facts['snmp_interfaces'][idx]
                     ['name']: idx for idx in snmp_facts['snmp_interfaces']}
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
    snmp_port_map = {snmp_facts['snmp_interfaces'][idx]
                     ['name']: idx for idx in snmp_facts['snmp_interfaces']}
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
                    results[port_name].update(
                        {high_speed: port_snmp[high_speed]})
            elif speed_to_bps < int(port_snmp[speed]):
                results[port_name].update({speed: port_snmp[speed]})
                if int(port_snmp[high_speed]):
                    results[port_name].update(
                        {high_speed: port_snmp[high_speed]})
    return results


def verify_snmp_counter(duthost, localhost, creds_all_duts, hostip, mg_facts, rif_interface, rif_counters,
                        port_counters):
    """
    Verify correct correctness of snmp counter
    """
    snmp_facts = get_snmp_facts(
        duthost, localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']

    minigraph_port_name_to_alias_map = mg_facts['minigraph_port_name_to_alias_map']
    snmp_port_map = {snmp_facts['snmp_interfaces'][idx]['name']: idx for idx in snmp_facts['snmp_interfaces']}
    interface = rif_interface if 'PortChannel' in rif_interface else minigraph_port_name_to_alias_map[rif_interface]
    rif_snmp_facts = snmp_facts['snmp_interfaces'][snmp_port_map[interface]]

    if (int(rif_snmp_facts['ifInDiscards']) != int(rif_counters[rif_interface]['rx_err']) +
            int(port_counters['rx_drp'])):
        logger.info(f"ifInDiscards value is {rif_snmp_facts['ifInDiscards']} but must be "
                    f"{int(rif_counters[rif_interface]['rx_err']) + int(port_counters['rx_drp'])}")
        return False
    if (int(rif_snmp_facts['ifOutDiscards']) != int(rif_counters[rif_interface]['tx_err']) +
            int(port_counters['tx_drp'])):
        logger.info(f"ifOutDiscards value is {rif_snmp_facts['ifOutDiscards']} but must be "
                    f"{int(rif_counters[rif_interface]['tx_err']) + int(port_counters['tx_drp'])}")
        return False
    if int(rif_snmp_facts['ifInErrors']) != COUNTER_VALUE:
        logger.info(f"ifInErrors value is {rif_snmp_facts['ifInErrors']} but must be {COUNTER_VALUE}")
        return False
    if int(rif_snmp_facts['ifOutErrors']) != COUNTER_VALUE:
        logger.info(f"ifOutErrors value is {rif_snmp_facts['ifOutErrors']} but must be {COUNTER_VALUE}")
        return False

    return True


@pytest.mark.bsl
def test_snmp_interfaces(localhost, creds_all_duts, duthosts, enum_rand_one_per_hwsku_hostname):
    """compare the snmp facts between observed states and target state"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']

    snmp_facts = get_snmp_facts(
        duthost, localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']

    snmp_ifnames = [v['name']
                    for k, v in list(snmp_facts['snmp_interfaces'].items())]
    logger.info('snmp_ifnames: {}'.format(snmp_ifnames))

    for asic in duthost.asics:
        config_facts = duthost.config_facts(
            host=duthost.hostname, source="persistent", namespace=asic.namespace)['ansible_facts']

        # Verify all physical ports of current ASIC are in snmp interface list
        for _, alias in list(config_facts['port_name_to_alias_map'].items()):
            assert alias in snmp_ifnames, "Interface not found in SNMP facts."

        # Verify all port channels of current ASIC are in snmp interface list
        for po_name in config_facts.get('PORTCHANNEL', {}):
            assert po_name in snmp_ifnames, "PortChannel not found in SNMP facts."


@pytest.mark.bsl
def test_snmp_mgmt_interface(localhost, creds_all_duts, duthosts, enum_rand_one_per_hwsku_hostname):
    """compare the snmp facts between observed states and target state"""

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']

    snmp_facts = get_snmp_facts(
        duthost, localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="persistent")['ansible_facts']

    snmp_ifnames = [v['name']
                    for k, v in list(snmp_facts['snmp_interfaces'].items())]
    logger.info('snmp_ifnames: {}'.format(snmp_ifnames))

    # Verify management port in snmp interface list
    for name in config_facts.get('MGMT_INTERFACE', {}):
        assert name in snmp_ifnames, "Management Interface not found in SNMP facts."

    # TODO: Remove this check after operational status of mgmt interface
    # is implemented for multi-asic platform
    if duthost.num_asics() == 1:
        ports_list = []
        ports_list.extend(list(config_facts.get('MGMT_INTERFACE', {}).keys()))
        dut_facts = collect_all_facts(duthost, ports_list)
        ports_snmps = verify_port_snmp(dut_facts, snmp_facts)
        speed_snmp = verify_snmp_speed(dut_facts, snmp_facts, ports_snmps)
        result = verify_port_ifindex(snmp_facts, speed_snmp)
        pytest_assert(
            not result, "Unexpected comparsion of SNMP: {}".format(result))


def test_snmp_interfaces_mibs(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts):
    """Verify correct behaviour of port MIBs ifIndex, ifMtu, ifSpeed,
       ifAdminStatus, ifOperStatus, ifAlias, ifHighSpeed, ifType """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(
        duthost, localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']

    for asic in duthost.asics:
        config_facts = duthost.config_facts(
            host=duthost.hostname, source="persistent", namespace=asic.namespace)['ansible_facts']

        ports_list = []
        for i in ['port_name_to_alias_map', 'PORTCHANNEL']:
            ports_list.extend(list(config_facts.get(i, {}).keys()))

        dut_facts = collect_all_facts(duthost, ports_list, asic.namespace)
        ports_snmps = verify_port_snmp(dut_facts, snmp_facts)
        speed_snmp = verify_snmp_speed(dut_facts, snmp_facts, ports_snmps)
        result = verify_port_ifindex(snmp_facts, speed_snmp)
        pytest_assert(
            not result, "Unexpected comparsion of SNMP: {}".format(result))


def test_snmp_interfaces_error_discard(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts,
                                       enum_asic_index, disable_conterpoll, tbinfo, mg_facts):
    """Verify correct behaviour of port MIBs ifInError, ifOutError, IfInDiscards, IfOutDiscards """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    port_interface, rif_interface = get_interfaces(duthost, tbinfo)
    logger.info(f'Selected interfaces: port {port_interface}, rif {rif_interface}')
    # Get interfaces oid
    port_oid = get_oid_for_interface(duthost, COUNTERS_PORT_NAME_MAP, port_interface)
    rif_oid = get_oid_for_interface(duthost, COUNTERS_RIF_NAME_MAP, rif_interface)
    # Clear the counters from the cache to make test stable
    # if "sonic-clear counters" was done before the test, /tmp/cache/intfstat and /tmp/cache/portstat will be created.
    # if /tmp/cache/portstat exist, show interfaces counters will calculate the counters that get from redis-db and the
    # value saved in the cache file. then the value will not be the number that get from the redis db
    # if /tmp/cache/intfstat exist, show interfaces counters rif will calculate the counters that get from redis-db and
    # the value saved in the cache file. then the value will not be the number that get from the redis db
    # Clear the cache file to make sure that the "show interfaces counters" and "show interfaces counters rif" return
    # the number that set in the redis-db.
    duthost.shell("rm -rf /tmp/cache/intfstat", module_ignore_errors=True)
    duthost.shell("rm -rf /tmp/cache/portstat", module_ignore_errors=True)

    logger.info('Set port and rif counters in COUNTERS DB')
    logger.info(f'Set port {port_interface} {SAI_PORT_STAT_IF_IN_ERRORS} counter to {COUNTER_VALUE}')
    set_counters_value(duthost, port_oid, SAI_PORT_STAT_IF_IN_ERRORS, COUNTER_VALUE)
    logger.info(f'Set port {port_interface} {SAI_PORT_STAT_IF_IN_DISCARDS} counter to {COUNTER_VALUE}')
    set_counters_value(duthost, port_oid, SAI_PORT_STAT_IF_IN_DISCARDS, COUNTER_VALUE)
    logger.info(f'Set port {rif_interface} {SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS} counter to {COUNTER_VALUE}')
    set_counters_value(duthost, rif_oid, SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS, COUNTER_VALUE)
    logger.info(f'Set port {port_interface} {SAI_PORT_STAT_IF_OUT_DISCARDS} counter to {COUNTER_VALUE}')
    set_counters_value(duthost, port_oid, SAI_PORT_STAT_IF_OUT_DISCARDS, COUNTER_VALUE)
    logger.info(f'Set port {rif_interface} {SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS} counter to {COUNTER_VALUE}')
    set_counters_value(duthost, rif_oid, SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS, COUNTER_VALUE)
    logger.info(f'Set port {port_interface} {SAI_PORT_STAT_IF_OUT_ERRORS} counter to {COUNTER_VALUE}')
    set_counters_value(duthost, port_oid, SAI_PORT_STAT_IF_OUT_ERRORS, COUNTER_VALUE)

    rif_counters = parse_rif_counters(duthost.command("show interfaces counters rif")["stdout_lines"])
    port_counters = get_port_interface_counter(duthost, port_interface)

    logger.info('Compare rif counters in COUNTERS DB and counters get from SONiC CLI')
    assert int(rif_counters[rif_interface]['tx_err']) == COUNTER_VALUE, \
        f"tx_err value is {rif_counters[rif_interface]['tx_err']} not set to {COUNTER_VALUE}"
    assert int(rif_counters[rif_interface]['rx_err']) == COUNTER_VALUE, \
        f"rx_err value is {rif_counters[rif_interface]['rx_err']} not set to {COUNTER_VALUE}"

    logger.info('Compare port counters in COUNTERS DB and counters get from SONiC CLI')
    assert int(port_counters['tx_err']) == COUNTER_VALUE, \
        f"tx_err value is {port_counters['tx_err']} not set to {COUNTER_VALUE}"
    assert int(port_counters['rx_err']) == COUNTER_VALUE, \
        f"rx_err value is {port_counters['rx_err']} not set to {COUNTER_VALUE}"
    assert int(port_counters['tx_drp']) == COUNTER_VALUE, \
        f"tx_drp value is {port_counters['tx_drp']} not set to {COUNTER_VALUE}"
    assert int(port_counters['rx_drp']) == COUNTER_VALUE, \
        f"rx_drp value is {port_counters['rx_drp']} not set to {COUNTER_VALUE}"

    pytest_assert(wait_until(60, 10, 0, verify_snmp_counter, duthost, localhost, creds_all_duts, hostip, mg_facts,
                             rif_interface, rif_counters, port_counters), "SNMP counter validate Failure")
    # clear all counters after the test
    duthost.shell('sonic-clear counters')
    duthost.shell('sonic-clear rifcounters')
