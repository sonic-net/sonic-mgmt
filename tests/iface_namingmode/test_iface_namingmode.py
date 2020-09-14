import logging
import pytest
import re

from tests.common.devices import AnsibleHostBase
from tests.common.utilities import wait
from netaddr import IPAddress

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope='module', autouse=True)
def setup(duthost):
    """
    Sets up all the parameters needed for the interface naming mode tests

    Args:
        duthost: AnsiblecHost instance for DUT
    Yields:
        setup_info: dictionary containing port alias mappings, list of
        working interfaces, minigraph facts
    """
    hwsku = duthost.facts['hwsku']
    minigraph_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    port_alias_facts = duthost.port_alias(hwsku=hwsku)['ansible_facts']
    up_ports = minigraph_facts['minigraph_ports'].keys()
    default_interfaces = port_alias_facts['port_name_map'].keys()
    minigraph_portchannels = minigraph_facts['minigraph_portchannels']

    port_alias = list()
    port_name_map = dict()
    port_alias_map = dict()
    port_speed = dict()

    # Change port alias names to make it common for all platforms
    logger.info('Updating common port alias names in redis db')
    for i, item in enumerate(default_interfaces):
        port_alias_new = 'TestAlias{}'.format(i)
        port_alias_old = port_alias_facts['port_name_map'][item]
        port_alias.append(port_alias_new)
        port_name_map[item] = port_alias_new
        port_alias_map[port_alias_new] = item
        port_speed[port_alias_new] = port_alias_facts['port_speed'][port_alias_old]

        # Update port alias name in redis db
        duthost.command('redis-cli -n 4 HSET "PORT|{}" alias {}'.format(item, port_alias_new))

    upport_alias_list = [ port_name_map[item] for item in up_ports ]
    portchannel_members = [ member for portchannel in minigraph_portchannels.values() for member in portchannel['members'] ]
    physical_interfaces = [ item for item in up_ports if item not in portchannel_members ]
    setup_info = {
         'default_interfaces' : default_interfaces,
         'minigraph_facts' : minigraph_facts,
         'physical_interfaces' : physical_interfaces,
         'port_alias' : port_alias,
         'port_name_map' : port_name_map,
         'port_alias_map' : port_alias_map,
         'port_speed' : port_speed,
         'up_ports' : up_ports,
         'upport_alias_list' : upport_alias_list
    }

    yield setup_info

    logger.info('Reverting the port alias name in redis db to the actual values')
    for item in default_interfaces:
        port_alias_old = port_alias_facts['port_name_map'][item]
        duthost.command('redis-cli -n 4 HSET "PORT|{}" alias {}'.format(item, port_alias_old))

@pytest.fixture(scope='module', params=['alias', 'default'])
def setup_config_mode(ansible_adhoc, duthost, request):
    """
    Creates a guest user and configures the interface naming mode

    Args:
        ansible_adhoc: Fixture provided by the pytest-ansible package
        duthost: AnsibleHost instance for DUT
        request: request parameters for setup_config_mode fixture
    Yields:
        dutHostGuest: AnsibleHost instance for DUT with user as 'guest'
        mode: Interface naming mode to be configured
        ifmode: Current interface naming mode present in the DUT
    """
    mode = request.param

    logger.info('Creating a guest user')
    duthost.user(name='guest', groups='sudo', state ='present', shell='/bin/bash')
    duthost.shell('echo guest:guest | sudo chpasswd')

    logger.info('Configuring the interface naming mode as {} for the guest user'.format(mode))
    dutHostGuest = AnsibleHostBase(ansible_adhoc, duthost.hostname, become_user='guest')
    dutHostGuest.shell('sudo config interface_naming_mode {}'.format(mode))
    ifmode = dutHostGuest.shell('cat /home/guest/.bashrc | grep SONIC_CLI_IFACE_MODE')['stdout'].split('=')[-1]
    naming_mode = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show interfaces naming_mode'.format(ifmode))['stdout']

    # If the correct mode is not set in .bashrc, all test cases will fail.
    # So return Error from this fixture itself.
    if (ifmode != mode) or (naming_mode != mode):
        logger.info('Removing the created guest user')
        duthost.user(name='guest', groups='sudo', state ='absent', shell='/bin/bash', remove='yes')
        pytest.fail('Interface naming mode in .bashrc "{}", returned by show interfaces naming_mode "{}" does not the match the configured naming mode "{}"'.format(ifmode, naming_mode, mode))

    yield dutHostGuest, mode, ifmode

    logger.info('Removing the created guest user')
    duthost.user(name='guest', groups='sudo', state ='absent', shell='/bin/bash', remove='yes')

@pytest.fixture(scope='module')
def sample_intf(setup):
    """
    Selects and returns the alias, name and native speed of the test interface

    Args:
        setup: Fixture defined in this module
    Returns:
        sample_intf: a dictionary containing the alias, name and native
        speed of the test interface
    """
    minigraph_interfaces = setup['minigraph_facts']['minigraph_interfaces']
    interface_info = dict()
    interface_info['ip'] = None

    if setup['physical_interfaces']:
        interface = sorted(setup['physical_interfaces'])[0]
        interface_info['is_portchannel_member'] = False
        for item in minigraph_interfaces:
            if (item['attachto'] == interface) and (IPAddress(item['addr']).version == 4):
                interface_info['ip'] = item['subnet']
                break
    else:
        interface = sorted(setup['up_ports'])[0]
        interface_info['is_portchannel_member'] = True

    interface_info['default'] = interface
    interface_info['alias'] = setup['port_name_map'][interface]
    interface_info['native_speed'] = setup['port_speed'][interface_info['alias']]

    return interface_info

#############################################################
######################## START OF TESTS #####################
#############################################################

# Tests to be run in all topologies

class TestShowLLDP():

    @pytest.fixture(scope="class")
    def lldp_interfaces(self, setup):
        """
        Returns the alias and names of the lldp interfaces

        Args:
            setup: Fixture defined in this module
        Returns:
            lldp_interfaces: dictionary containing lists of aliases and
            names of the lldp interfaces
        """
        minigraph_neighbors = setup['minigraph_facts']['minigraph_neighbors']
        lldp_interfaces = dict()
        lldp_interfaces['alias'] = list()
        lldp_interfaces['interface'] = list()

        for key, value in minigraph_neighbors.items():
            if 'server' not in value['name'].lower():
                lldp_interfaces['alias'].append(setup['port_name_map'][key])
                lldp_interfaces['interface'].append(key)

        if len(lldp_interfaces['alias']) == 0:
            pytest.skip('No lldp interfaces found')

        return lldp_interfaces

    def test_show_lldp_table(self, setup, setup_config_mode, lldp_interfaces):
        """
        Checks whether 'show lldp table' lists the interface name as per
        the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_neighbors = setup['minigraph_facts']['minigraph_neighbors']

        lldp_table = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show lldp table'.format(ifmode))['stdout']
        logger.info('lldp_table:\n{}'.format(lldp_table))

        if mode == 'alias':
            for alias in lldp_interfaces['alias']:
                assert re.search(r'{}.*\s+{}'.format(alias, minigraph_neighbors[setup['port_alias_map'][alias]]['name']), lldp_table) is not None
        elif mode == 'default':
            for intf in lldp_interfaces['interface']:
                assert re.search(r'{}.*\s+{}'.format(intf, minigraph_neighbors[intf]['name']), lldp_table) is not None

    def test_show_lldp_neighbor(self, setup, setup_config_mode, lldp_interfaces):
        """
        Checks whether 'show lldp neighbor <port>' lists the lldp neighbor
        information corresponding to the test interface when its interface
        alias/name is provied according to the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = lldp_interfaces['alias'][0] if (mode == 'alias') else lldp_interfaces['interface'][0]
        minigraph_neighbors = setup['minigraph_facts']['minigraph_neighbors']

        lldp_neighbor = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show lldp neighbor {}'.format(ifmode, test_intf))['stdout']
        logger.info('lldp_neighbor:\n{}'.format(lldp_neighbor))

        if mode == 'alias':
            assert re.search(r'Interface:\s+{},\svia:\sLLDP,'.format(test_intf), lldp_neighbor) is not None
            assert re.search(r'SysName:\s+{}'.format(minigraph_neighbors[setup['port_alias_map'][test_intf]]['name']), lldp_neighbor) is not None
        elif mode == 'default':
            assert re.search(r'Interface:\s+{},\svia:\sLLDP,'.format(test_intf), lldp_neighbor) is not None
            assert re.search(r'SysName:\s+{}'.format(minigraph_neighbors[test_intf]['name']), lldp_neighbor) is not None

class TestShowInterfaces():

    def test_show_interfaces_counter(self, setup, setup_config_mode):
        """
        Checks whether 'show interfaces counter' lists the interface names
        as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        regex_int = re.compile(r'(\S+)\s+(\w)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)')
        interfaces = list()

        show_intf_counter = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show interfaces counter'.format(ifmode))
        logger.info('show_intf_counter:\n{}'.format(show_intf_counter['stdout']))

        for line in show_intf_counter['stdout_lines']:
            line = line.strip()
            if regex_int.match(line):
                interfaces.append(regex_int.match(line).group(1))

        for item in interfaces:
            if mode == 'alias':
                assert item in setup['port_alias']
            elif mode == 'default':
                assert item in setup['default_interfaces']

    def test_show_interfaces_description(self, setup_config_mode, sample_intf):
        """
        Checks whether 'show interfaces description <port>' lists the
        information corresponding to the test interface when its interface
        alias/name is provided according to the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = sample_intf[mode]
        interface = sample_intf['default']
        interface_alias = sample_intf['alias']

        show_intf_desc = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show interfaces description {} | sed -n "/^ *Eth/ p"'.format(ifmode, test_intf))['stdout']
        logger.info('show_intf_desc:\n{}'.format(show_intf_desc))

        assert re.search(r'{}.*{}'.format(interface, interface_alias), show_intf_desc) is not None

    def test_show_interfaces_status(self, setup_config_mode, sample_intf):
        """
        Checks whether 'show interfaces status <port>' lists the information
        corresponding to the test interface when its interface alias/name
        is provided according to the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = sample_intf[mode]
        interface = sample_intf['default']
        interface_alias = sample_intf['alias']
        regex_int = re.compile(r'(\S+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+[\w\/]+\s+([\w\/]+)\s+(\w+)\s+(\w+)\s+(\w+)')

        show_intf_status = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={0} show interfaces status {1} | grep -w {1}'.format(ifmode, test_intf))
        logger.info('show_intf_status:\n{}'.format(show_intf_status['stdout']))

        line = show_intf_status['stdout'].strip()
        if regex_int.match(line) and interface == regex_int.match(line).group(1):
            name = regex_int.match(line).group(1)
            alias = regex_int.match(line).group(4)

        assert (name == interface) and (alias == interface_alias)

    def test_show_interfaces_portchannel(self, setup, setup_config_mode):
        """
        Checks whether 'show interfaces portchannel' lists the member
        interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_portchannels = setup['minigraph_facts']['minigraph_portchannels']
        if not minigraph_portchannels:
            pytest.skip('No portchannels found')

        int_po = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show interfaces portchannel'.format(ifmode))['stdout']
        logger.info('int_po:\n{}'.format(int_po))

        for key, value in minigraph_portchannels.items():
            if mode == 'alias':
                assert re.search(r'{}\s+LACP\(A\)\(Up\).*{}'.format(key, setup['port_name_map'][value['members'][0]]), int_po) is not None
            elif mode == 'default':
                assert re.search(r'{}\s+LACP\(A\)\(Up\).*{}'.format(key, value['members'][0]), int_po) is not None

def test_show_pfc_counters(setup, setup_config_mode):
    """
    Checks whether 'show pfc counters' lists the interface names as
    per the configured naming mode
    """
    dutHostGuest, mode, ifmode = setup_config_mode
    pfc_rx = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show pfc counters | sed -n "/Port Rx/,/^$/p"'.format(ifmode))['stdout']
    pfc_tx = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show pfc counters | sed -n "/Port Tx/,/^$/p"'.format(ifmode))['stdout']
    logger.info('pfc_rx:\n{}'.format(pfc_rx))
    logger.info('pfc_tx:\n{}'.format(pfc_tx))

    if mode == 'alias':
        for alias in setup['port_alias']:
            assert (alias in pfc_rx) and (alias in pfc_tx)
            assert (setup['port_alias_map'][alias] not in pfc_rx) and (setup['port_alias_map'][alias] not in pfc_tx)
    elif mode == 'default':
        for intf in setup['default_interfaces']:
            assert (intf in pfc_rx) and (intf in pfc_tx)
            assert (setup['port_name_map'][intf] not in pfc_rx) and (setup['port_name_map'][intf] not in pfc_tx)

class TestShowPriorityGroup():

    def test_show_priority_group_persistent_watermark_headroom(self, setup, setup_config_mode):
        """
        Checks whether 'show priority-group persistent-watermark headroom'
        lists the interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_pg = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show priority-group persistent-watermark headroom'.format(ifmode))['stdout']
        logger.info('show_pg:\n{}'.format(show_pg))

        if mode == 'alias':
            for alias in setup['upport_alias_list']:
                assert re.search(r'{}.*'.format(alias), show_pg) is not None
        elif mode == 'default':
            for intf in setup['up_ports']:
                assert re.search(r'{}.*'.format(intf), show_pg) is not None

    def test_show_priority_group_persistent_watermark_shared(self, setup, setup_config_mode):
        """
        Checks whether 'show priority-group persistent-watermark shared'
        lists the interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_pg = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show priority-group persistent-watermark shared'.format(ifmode))['stdout']
        logger.info('show_pg:\n{}'.format(show_pg))

        if mode == 'alias':
            for alias in setup['upport_alias_list']:
                assert re.search(r'{}.*'.format(alias), show_pg) is not None
        elif mode == 'default':
            for intf in setup['up_ports']:
                assert re.search(r'{}.*'.format(intf), show_pg) is not None

    def test_show_priority_group_watermark_headroom(self, setup, setup_config_mode):
        """
        Checks whether 'show priority-group watermark headroom' lists the
        interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_pg = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show priority-group watermark headroom'.format(ifmode))['stdout']
        logger.info('show_pg:\n{}'.format(show_pg))

        if mode == 'alias':
            for alias in setup['upport_alias_list']:
                assert re.search(r'{}.*'.format(alias), show_pg) is not None
        elif mode == 'default':
            for intf in setup['up_ports']:
                assert re.search(r'{}.*'.format(intf), show_pg) is not None

    def test_show_priority_group_watermark_shared(self, setup, setup_config_mode):
        """
        Checks whether 'show priority-group watermark shared' lists the
        interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_pg = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show priority-group watermark shared'.format(ifmode))['stdout']
        logger.info('show_pg:\n{}'.format(show_pg))

        if mode == 'alias':
            for alias in setup['upport_alias_list']:
                assert re.search(r'{}.*'.format(alias), show_pg) is not None
        elif mode == 'default':
            for intf in setup['up_ports']:
                assert re.search(r'{}.*'.format(intf), show_pg) is not None

class TestShowQueue():

    def test_show_queue_counters(self, setup, setup_config_mode):
        """
        Checks whether 'show queue counters' lists the interface names as
        per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        queue_counter = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show queue counters | grep "UC\|MC"'.format(ifmode))['stdout']
        logger.info('queue_counter:\n{}'.format(queue_counter))

        if mode == 'alias':
            for alias in setup['port_alias']:
                assert (re.search(r'{}\s+[U|M]C\d\s+\S+\s+\S+\s+\S+\s+\S+'.format(alias), queue_counter) is not None) and (setup['port_alias_map'][alias] not in queue_counter)
        elif mode == 'default':
            for intf in setup['default_interfaces']:
                assert (re.search(r'{}\s+[U|M]C\d\s+\S+\s+\S+\s+\S+\s+\S+'.format(intf), queue_counter) is not None) and (setup['port_name_map'][intf] not in queue_counter)

    def test_show_queue_counters_interface(self, setup_config_mode, sample_intf):
        """
        Check whether the interface name is present in output in the format
        corresponding to the mode set
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = sample_intf[mode]
        queue_counter_intf = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show queue counters {} | grep "UC\|MC"'.format(ifmode, test_intf))
        logger.info('queue_counter_intf:\n{}'.format(queue_counter_intf))

        for i in range(len(queue_counter_intf['stdout_lines'])):
            assert re.search(r'{}\s+[U|M]C{}\s+\S+\s+\S+\s+\S+\s+\S+'.format(test_intf, i), queue_counter_intf['stdout']) is not None

    def test_show_queue_persistent_watermark_multicast(self, setup, setup_config_mode):
        """
        Checks whether 'show queue persistent-watermark multicast' lists
        the interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_queue_wm_mcast = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show queue persistent-watermark multicast'.format(ifmode))['stdout']
        logger.info('show_queue_wm_mcast:\n{}'.format(show_queue_wm_mcast))

        if mode == 'alias':
            for alias in setup['port_alias']:
                assert re.search(r'{}'.format(alias), show_queue_wm_mcast) is not None
        elif mode == 'default':
            for intf in setup['default_interfaces']:
                assert re.search(r'{}'.format(intf), show_queue_wm_mcast) is not None

    def test_show_queue_persistent_watermark_unicast(self, setup, setup_config_mode):
        """
        Checks whether 'show queue persistent-watermark unicast' lists
        the interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_queue_wm_ucast = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show queue persistent-watermark unicast'.format(ifmode))['stdout']
        logger.info('show_queue_wm_ucast:\n{}'.format(show_queue_wm_ucast))

        if mode == 'alias':
            for alias in setup['port_alias']:
                assert re.search(r'{}'.format(alias), show_queue_wm_ucast) is not None
        elif mode == 'default':
            for intf in setup['default_interfaces']:
                assert re.search(r'{}'.format(intf), show_queue_wm_ucast) is not None

    def test_show_queue_watermark_multicast(self, setup, setup_config_mode):
        """
        Checks whether 'show queue watermark multicast' lists the
        interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_queue_wm_mcast = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show queue watermark multicast'.format(ifmode))['stdout']
        logger.info('show_queue_wm_mcast:\n{}'.format(show_queue_wm_mcast))

        if mode == 'alias':
            for alias in setup['port_alias']:
                assert re.search(r'{}'.format(alias), show_queue_wm_mcast) is not None
        elif mode == 'default':
            for intf in setup['default_interfaces']:
                assert re.search(r'{}'.format(intf), show_queue_wm_mcast) is not None

    def test_show_queue_watermark_unicast(self, setup, setup_config_mode):
        """
        Checks whether 'show queue watermark unicast' lists the
        interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_queue_wm_ucast = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show queue watermark unicast'.format(ifmode))['stdout']
        logger.info('show_queue_wm_ucast:\n{}'.format(show_queue_wm_ucast))

        if mode == 'alias':
            for alias in setup['port_alias']:
                assert re.search(r'{}'.format(alias), show_queue_wm_ucast) is not None
        elif mode == 'default':
            for intf in setup['default_interfaces']:
                assert re.search(r'{}'.format(intf), show_queue_wm_ucast) is not None

# Tests to be run in t0 topology

class TestShowVlan():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, testbed):
        if testbed['topo']['type'] != 't0':
            pytest.skip('Unsupported topology')

    @pytest.fixture()
    def setup_vlan(self, setup_config_mode):
        """
        Creates VLAN 100 for testing and cleans it up on completion

        Args:
            setup_config_mode: Fixture defined in this module
        Yields:
            None
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        logger.info('Creating a test vlan 100')
        dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config vlan add 100'.format(ifmode))
        yield

        logger.info('Cleaning up the test vlan 100')
        dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config vlan del 100'.format(ifmode))

    def test_show_vlan_brief(self, setup, setup_config_mode):
        """
        Checks whether 'show vlan brief' lists the interface names
        as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_vlans = setup['minigraph_facts']['minigraph_vlans']

        show_vlan_brief = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show vlan brief'.format(ifmode))['stdout']
        logger.info('show_vlan_brief:\n{}'.format(show_vlan_brief))

        for item in minigraph_vlans['Vlan1000']['members']:
            if mode == 'alias':
                assert re.search(r'{}.*untagged'.format(setup['port_name_map'][item]), show_vlan_brief) is not None
            elif mode == 'default':
                assert re.search(r'{}.*untagged'.format(item), show_vlan_brief) is not None

    @pytest.mark.usefixtures('setup_vlan')
    def test_show_vlan_config(self, setup, setup_config_mode):
        """
        Checks whether 'config vlan member add <vlan> <intf>' adds
        the test interface when its interface alias/name is provided
        as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_vlans = setup['minigraph_facts']['minigraph_vlans']
        vlan_interface = minigraph_vlans[minigraph_vlans.keys()[0]]['members'][0]
        vlan_interface_alias = setup['port_name_map'][vlan_interface]
        v_intf = vlan_interface_alias if (mode == 'alias') else vlan_interface

        dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config vlan member add 100 {}'.format(ifmode, v_intf))
        show_vlan = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show vlan config | grep -w "Vlan100"'.format(ifmode))['stdout']
        logger.info('show_vlan:\n{}'.format(show_vlan))

        assert v_intf in show_vlan

# Tests to be run in t1 topology

class TestConfigInterface():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, testbed):
        if testbed['topo']['type'] != 't1':
            pytest.skip('Unsupported topology')

    @pytest.fixture(scope='class', autouse=True)
    def reset_config_interface(self, duthost, sample_intf):
        """
        Resets the test interface's configurations on completion of
        all tests in the enclosing test class.

        Args:
            duthost: AnsibleHost instance for DUT
            test_intf: Fixture defined in this module
        Yields:
            None
        """
        interface = sample_intf['default']
        interface_ip = sample_intf['ip']
        native_speed = sample_intf['native_speed']

        yield

        if interface_ip is not None:
            duthost.shell('config interface ip add {} {}'.format(interface, interface_ip))

        duthost.shell('config interface startup {}'.format(interface))
        duthost.shell('config interface speed {} {}'.format(interface, native_speed))

    def test_config_interface_ip(self, setup_config_mode, sample_intf):
        """
        Checks whether 'config interface ip add/remove <intf> <ip>'
        adds/removes the ip on the test interface when its interface
        alias/name is provided as per the configured naming mode
        """
        if sample_intf['ip'] is None:
            pytest.skip('No L3 physical interface present')

        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = sample_intf[mode]
        test_intf_ip = sample_intf['ip']

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface ip remove {} {}'.format(ifmode, test_intf, test_intf_ip))
        if out['rc'] != 0:
            pytest.fail()

        wait(3)
        show_ip_intf = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ip interface'.format(ifmode))['stdout']
        logger.info('show_ip_intf:\n{}'.format(show_ip_intf))

        assert re.search(r'{}\s+{}'.format(test_intf, test_intf_ip), show_ip_intf) is None

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface ip add {} {}'.format(ifmode, test_intf, test_intf_ip))
        if out['rc'] != 0:
            pytest.fail()

        wait(3)
        show_ip_intf = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ip interface'.format(ifmode))['stdout']
        logger.info('show_ip_intf:\n{}'.format(show_ip_intf))

        assert re.search(r'{}\s+{}'.format(test_intf, test_intf_ip), show_ip_intf) is not None

    def test_config_interface_state(self, setup_config_mode, sample_intf):
        """
        Checks whether 'config interface startup/shutdown <intf>'
        changes the admin state of the test interface to up/down when
        its interface alias/name is provided as per the configured
        naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = sample_intf[mode]
        interface = sample_intf['default']
        regex_int = re.compile(r'(\S+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+[\w\/]+\s+([\w\/]+)\s+(\w+)\s+(\w+)\s+(\w+)')

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface shutdown {}'.format(ifmode, test_intf))
        if out['rc'] != 0:
            pytest.fail()

        wait(3)
        show_intf_status = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={0} show interfaces status {1} | grep -w {1}'.format(ifmode, test_intf))
        logger.info('show_intf_status:\n{}'.format(show_intf_status['stdout']))

        line = show_intf_status['stdout'].strip()
        if regex_int.match(line) and interface == regex_int.match(line).group(1):
            admin_state = regex_int.match(line).group(7)

        assert admin_state == 'down'

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface startup {}'.format(ifmode, test_intf))
        if out['rc'] != 0:
            pytest.fail()

        wait(3)
        show_intf_status = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={0} show interfaces status {1} | grep -w {1}'.format(ifmode, test_intf))
        logger.info('show_intf_status:\n{}'.format(show_intf_status['stdout']))

        line = show_intf_status['stdout'].strip()
        if regex_int.match(line) and interface == regex_int.match(line).group(1):
            admin_state = regex_int.match(line).group(7)

        assert admin_state == 'up'

    def test_config_interface_speed(self, setup_config_mode, sample_intf):
        """
        Checks whether 'config interface speed <intf> <speed>' sets
        speed of the test interface when its interface alias/name is
        provided as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = sample_intf[mode]
        interface = sample_intf['default']
        native_speed = sample_intf['native_speed']

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface speed {} 10000'.format(ifmode, test_intf))
        if out['rc'] != 0:
            pytest.fail()

        speed = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo redis-cli -n 4 HGET "PORT|{}" speed'.format(ifmode, interface))['stdout']
        logger.info('speed: {}'.format(speed))

        assert speed == '10000'

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface speed {} {}'.format(ifmode, test_intf, native_speed))
        if out['rc'] != 0:
            pytest.fail()

        speed = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo redis-cli -n 4 HGET "PORT|{}" speed'.format(ifmode, interface))['stdout']
        logger.info('speed: {}'.format(speed))

        assert speed == native_speed

def test_show_acl_table(setup, setup_config_mode, testbed):
    """
    Checks whether 'show acl table DATAACL' lists the interface names
    as per the configured naming mode
    """
    if testbed['topo']['type'] != 't1':
        pytest.skip('Unsupported topology')

    if not setup['physical_interfaces']:
        pytest.skip('No non-portchannel member interface present')

    dutHostGuest, mode, ifmode = setup_config_mode
    minigraph_acls = setup['minigraph_facts']['minigraph_acls']

    acl_table = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show acl table DATAACL'.format(ifmode))['stdout']
    logger.info('acl_table:\n{}'.format(acl_table))

    for item in minigraph_acls['DataAcl']:
        if item in setup['physical_interfaces']:
            if mode == 'alias':
                assert setup['port_name_map'][item] in acl_table
            elif mode == 'default':
                assert item in acl_table

def test_show_interfaces_neighbor_expected(setup, setup_config_mode, testbed):
    """
    Checks whether 'show interfaces neighbor expected' lists the
    interface names as per the configured naming mode
    """
    if testbed['topo']['type'] != 't1':
        pytest.skip('Unsupported topology')

    dutHostGuest, mode, ifmode = setup_config_mode
    minigraph_neighbors = setup['minigraph_facts']['minigraph_neighbors']

    show_int_neighbor = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show interfaces neighbor expected'.format(ifmode))['stdout']
    logger.info('show_int_neighbor:\n{}'.format(show_int_neighbor))

    for key, value in minigraph_neighbors.items():
        if 'server' not in value['name'].lower():
            if mode == 'alias':
                assert re.search(r'{}\s+{}'.format(setup['port_name_map'][key], value['name']), show_int_neighbor) is not None
            elif mode == 'default':
                assert re.search(r'{}\s+{}'.format(key, value['name']), show_int_neighbor) is not None

class TestNeighbors():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, setup, testbed):
        if testbed['topo']['type'] != 't1':
            pytest.skip('Unsupported topology')

        if not setup['physical_interfaces']:
            pytest.skip('No non-portchannel member interface present')

    def test_show_arp(self, duthost, setup, setup_config_mode):
        """
        Checks whether 'show arp' lists the interface names as per the
        configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        arptable = duthost.switch_arptable()['ansible_facts']['arptable']
        minigraph_portchannels = setup['minigraph_facts']['minigraph_portchannels']

        arp_output = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show arp'.format(ifmode))['stdout']
        logger.info('arp_output:\n{}'.format(arp_output))

        for item in arptable['v4']:
            if (arptable['v4'][item]['interface'] != 'eth0') and (arptable['v4'][item]['interface'] not in minigraph_portchannels):
                if mode == 'alias':
                    assert re.search(r'{}.*\s+{}'.format(item, setup['port_name_map'][arptable['v4'][item]['interface']]), arp_output) is not None
                elif mode == 'default':
                    assert re.search(r'{}.*\s+{}'.format(item, arptable['v4'][item]['interface']), arp_output) is not None

    def test_show_ndp(self, duthost, setup, setup_config_mode):
        """
        Checks whether 'show ndp' lists the interface names as per the
        configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        arptable = duthost.switch_arptable()['ansible_facts']['arptable']
        minigraph_portchannels = setup['minigraph_facts']['minigraph_portchannels']

        ndp_output = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ndp'.format(ifmode))['stdout']
        logger.info('ndp:\n{}'.format(ndp_output))

        for item in arptable['v6']:
            if (arptable['v6'][item]['interface'] != 'eth0') and (arptable['v6'][item]['interface'] not in minigraph_portchannels):
                if mode == 'alias':
                    assert re.search(r'{}.*\s+{}'.format(item, setup['port_name_map'][arptable['v6'][item]['interface']]), ndp_output) is not None
                elif mode == 'default':
                    assert re.search(r'{}.*\s+{}'.format(item, arptable['v6'][item]['interface']), ndp_output) is not None

class TestShowIP():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, setup, testbed):
        if testbed['topo']['type'] != 't1':
            pytest.skip('Unsupported topology')

        if not setup['physical_interfaces']:
            pytest.skip('No non-portchannel member interface present')

    @pytest.fixture(scope='class')
    def spine_ports(self, setup):
        """
        Returns the alias and names of the spine ports

        Args:
            setup: Fixture defined in this module
        Returns:
            spine_ports: dictionary containing lists of aliases and names
            of the spine ports
        """
        minigraph_neighbors = setup['minigraph_facts']['minigraph_neighbors']
        spine_ports = dict()
        spine_ports['interface'] = list()
        spine_ports['alias'] = list()

        for key, value in minigraph_neighbors.items():
            if (key in setup['physical_interfaces']) and ('T2' in value['name']):
                spine_ports['interface'].append(key)
                spine_ports['alias'].append(setup['port_name_map'][key])

        if not spine_ports['interface']:
            pytest.skip('No non-portchannel member interface present')

        logger.info('spine_ports:\n{}'.format(spine_ports))
        return spine_ports

    def test_show_ip_interface(self, setup, setup_config_mode):
        """
        Checks whether 'show ip interface' lists the interface names as
        per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_interfaces = setup['minigraph_facts']['minigraph_interfaces']

        show_ip_interface = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ip interface'.format(ifmode))['stdout']
        logger.info('show_ip_interface:\n{}'.format(show_ip_interface))

        for item in minigraph_interfaces:
            if IPAddress(item['addr']).version == 4:
                if mode == 'alias':
                    assert re.search(r'{}\s+{}'.format(setup['port_name_map'][item['attachto']], item['addr']), show_ip_interface) is not None
                elif mode == 'default':
                    assert re.search(r'{}\s+{}'.format(item['attachto'], item['addr']), show_ip_interface) is not None

    def test_show_ipv6_interface(self, setup, setup_config_mode):
        """
        Checks whether 'show ipv6 interface' lists the interface names as
        per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_interfaces = setup['minigraph_facts']['minigraph_interfaces']

        show_ipv6_interface = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ipv6 interface'.format(ifmode))['stdout']
        logger.info('show_ipv6_interface:\n{}'.format(show_ipv6_interface))

        for item in minigraph_interfaces:
            if IPAddress(item['addr']).version == 6:
                if mode == 'alias':
                    assert re.search(r'{}\s+{}'.format(setup['port_name_map'][item['attachto']], item['addr']), show_ipv6_interface) is not None
                elif mode == 'default':
                    assert re.search(r'{}\s+{}'.format(item['attachto'], item['addr']), show_ipv6_interface) is not None

    def test_show_ip_route_v4(self, setup_config_mode, spine_ports):
        """
        Checks whether 'show ip route <ip>' lists the interface name as
        per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        route = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ip route 192.168.1.1'.format(ifmode))['stdout']
        logger.info('route:\n{}'.format(route))

        if mode == 'alias':
            for alias in spine_ports['alias']:
                assert re.search(r'via {}'.format(alias), route) is not None
        elif mode == 'default':
            for intf in spine_ports['interface']:
                assert re.search(r'via {}'.format(intf), route) is not None

    def test_show_ip_route_v6(self, setup_config_mode, spine_ports):
        """
        Checks whether 'show ipv6 route <ipv6>' lists the interface name
        as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        route = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ipv6 route 20c0:a800::/64'.format(ifmode))['stdout']
        logger.info('route:\n{}'.format(route))

        if mode == 'alias':
            for alias in spine_ports['alias']:
                assert re.search(r'via {}'.format(alias), route) is not None
        elif mode == 'default':
            for intf in spine_ports['interface']:
                assert re.search(r'via {}'.format(intf), route) is not None
