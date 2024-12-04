import logging
import pytest
import re
import ipaddress

from tests.common.devices.base import AnsibleHostBase
from tests.common.utilities import wait, wait_until
from netaddr import IPAddress
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import redis_get_keys

pytestmark = [
    pytest.mark.topology('any', 't1-multi-asic')
]

logger = logging.getLogger(__name__)

PORT_TOGGLE_TIMEOUT = 30

QUEUE_COUNTERS_RE_FMT = r'{}\s+[U|M]C|ALL\d\s+\S+\s+\S+\s+\S+\s+\S+'


def skip_test_for_multi_asic(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if duthost.is_multi_asic:
        pytest.skip('CLI command not supported')


@pytest.fixture(scope='module', autouse=True)
def setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    Sets up all the parameters needed for the interface naming mode tests

    Args:
        duthost: AnsiblecHost instance for DUT
    Yields:
        setup_info: dictionary containing port alias mappings, list of
        working interfaces, minigraph facts
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    hwsku = duthost.facts['hwsku']
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_alias_facts = duthost.port_alias(hwsku=hwsku, include_internal=False)['ansible_facts']
    up_ports = list(minigraph_facts['minigraph_ports'].keys())
    default_interfaces = list(port_alias_facts['port_name_map'].keys())
    minigraph_portchannels = minigraph_facts['minigraph_portchannels']
    port_speed_facts = port_alias_facts['port_speed']
    if not port_speed_facts:
        all_vars = duthost.host.options['variable_manager'].get_vars()
        iface_speed = all_vars['hostvars'][duthost.hostname]['iface_speed']
        iface_speed = str(iface_speed)
        port_speed_facts = {_: iface_speed for _ in
                            list(port_alias_facts['port_alias_map'].keys())}

    port_alias = list()
    port_name_map = dict()
    port_alias_map = dict()
    port_speed = dict()

    # Change port alias names to make it common for all platforms
    logger.info('Updating common port alias names in redis db')
    for i, item in enumerate(default_interfaces):
        port_alias_new = 'TestAlias{}'.format(i)
        asic_index = duthost.get_port_asic_instance(item).asic_index
        port_alias_old = port_alias_facts['port_name_map'][item]
        port_alias.append(port_alias_new)
        port_name_map[item] = port_alias_new
        port_alias_map[port_alias_new] = item
        port_speed[port_alias_new] = port_speed_facts[port_alias_old]

        # sonic-db-cli command
        db_cmd = 'sudo {} CONFIG_DB HSET "PORT|{}" alias {}'\
            .format(duthost.asic_instance(asic_index).sonic_db_cli,
                    item,
                    port_alias_new)
        # Update port alias name in redis db
        duthost.command(db_cmd)

    upport_alias_list = [port_name_map[item] for item in up_ports]
    portchannel_members = [member for portchannel in list(minigraph_portchannels.values())
                           for member in portchannel['members']]
    physical_interfaces = [item for item in up_ports if item not in portchannel_members]
    setup_info = {
         'default_interfaces': default_interfaces,
         'minigraph_facts': minigraph_facts,
         'physical_interfaces': physical_interfaces,
         'port_alias': port_alias,
         'port_name_map': port_name_map,
         'port_alias_map': port_alias_map,
         'port_speed': port_speed,
         'up_ports': up_ports,
         'upport_alias_list': upport_alias_list
    }

    yield setup_info

    logger.info('Reverting the port alias name in redis db to the actual values')
    for item in default_interfaces:
        asic_index = duthost.get_port_asic_instance(item).asic_index
        port_alias_old = port_alias_facts['port_name_map'][item]
        db_cmd = 'sudo {} CONFIG_DB HSET "PORT|{}" alias {}'\
            .format(duthost.asic_instance(asic_index).sonic_db_cli,
                    item,
                    port_alias_old)
        duthost.command(db_cmd)


@pytest.fixture(scope='module', params=['alias', 'default'])
def setup_config_mode(ansible_adhoc, duthosts, enum_rand_one_per_hwsku_frontend_hostname, request):
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
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mode = request.param

    logger.info('Creating a guest user')
    duthost.user(name='guest', groups='sudo', state='present', shell='/bin/bash')
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
        duthost.user(name='guest', groups='sudo', state='absent', shell='/bin/bash', remove='yes')
        pytest.fail('Interface naming mode in .bashrc "{}", returned by show interfaces naming_mode "{}" \
                    does not the match the configured naming mode "{}"'.format(ifmode, naming_mode, mode))

    yield dutHostGuest, mode, ifmode

    logger.info('Removing the created guest user')
    duthost.user(name='guest', groups='sudo', state='absent', shell='/bin/bash', remove='yes')


@pytest.fixture(scope='module')
def sample_intf(setup, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Selects and returns the alias, name and native speed of the test interface

    Args:
        setup: Fixture defined in this module
    Returns:
        sample_intf: a dictionary containing the alias, name and native
        speed of the test interface
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    minigraph_interfaces = setup['minigraph_facts']['minigraph_interfaces']
    interface_info = dict()
    interface_info['ip'] = None

    if setup['physical_interfaces']:
        interface = sorted(setup['physical_interfaces'])[0]
        nvidia_platform_support_400G_and_above_list = ["x86_64-nvidia_sn5600-r0"]
        if duthost.facts['platform'] in nvidia_platform_support_400G_and_above_list:
            interface = select_interface_for_mellnaox_device(setup, duthost)
        asic_index = duthost.get_port_asic_instance(interface).asic_index
        interface_info['is_portchannel_member'] = False
        for item in minigraph_interfaces:
            if (item['attachto'] == interface) and (IPAddress(item['addr']).version == 4):
                interface_info['ip'] = item['subnet']
                break
    else:
        interface = sorted(setup['up_ports'])[0]
        asic_index = duthost.get_port_asic_instance(interface).asic_index
        interface_info['is_portchannel_member'] = True

    interface_info['default'] = interface
    interface_info['asic_index'] = asic_index
    interface_info['alias'] = setup['port_name_map'][interface]
    interface_info['native_speed'] = setup['port_speed'][interface_info['alias']]
    interface_info['cli_ns_option'] = duthost.asic_instance(asic_index).cli_ns_option

    return interface_info


def select_interface_for_mellnaox_device(setup, duthost):
    """
    For nvidia device,the headroom size is related to the speed and cable length.
    When platform is x86_64-nvidia_sn5600-r0 and above,we need to choose interface whose cable length is 40m not 300m.
    Because this platform supports speeds of 400G and above, if we use 300m cable length
    it will exceed the headroom limit and cause some log errors like below:
    ERR syncd#SDK: [COS_SB.ERR] Failed to verify max headroom for port 0x100f1, error:No More Resources
    ERR syncd#SDK: [COS_SB.ERR] Failed to verify validate of the required configuration, error: No More Resources
    ERR syncd#SDK: [SAI_BUFFER.ERR] mlnx_sai_buffer.c[6161]- mlnx_sai_buffer_configure_reserved_buffers:
     Failed to configure reserved buffers. logical port:100f1, number of items:1 sx_status:5, message No More Resources
    ERR syncd#SDK: [SAI_BUFFER.ERR] mlnx_sai_buffer.c[4083]- mlnx_sai_buffer_apply_buffer_to_pg:
    Error applying buffer settings to port
    ERR syncd#SDK: [SAI_BUFFER.ERR] mlnx_sai_buffer.c[1318]- pg_profile_set:
    Failed to apply buffer profile for port index 60 pg index 3
    ERR syncd#SDK: [SAI_UTILS.ERR] mlnx_sai_utils.c[2130]- sai_set_attribute: Failed to set the attribute.
    ERR syncd#SDK: :- sendApiResponse:
    api SAI_COMMON_API_SET failed in syncd mode: SAI_STATUS_INSUFFICIENT_RESOURCES
    ERR syncd#SDK: :- processQuadEvent: VID: oid:0x1a000000000266 RID: oid:0x3c0003001a
    ERR syncd#SDK: :- processQuadEvent: attr: SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE: oid:0x19000000000b43
    ERR swss#orchagent: :- processPriorityGroup: Failed to set port:Ethernet0 pg:3 buffer profile attribute, status:-4
    """
    selected_interface = ''
    interface_cable_length_list = duthost.shell('redis-cli -n 4 hgetall "CABLE_LENGTH|AZURE" ')['stdout_lines']
    support_cable_length_list = ["40m", "5m"]
    for intf in setup['physical_interfaces']:
        if intf in interface_cable_length_list:
            if interface_cable_length_list[interface_cable_length_list.index(intf) + 1] in support_cable_length_list:
                selected_interface = intf
                break
    if not selected_interface:
        pytest.skip("Skipping test due to not find interface with cable length is 40m or 5m")
    return selected_interface


#############################################################
#                        START OF TESTS                     #
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

        for key, value in list(minigraph_neighbors.items()):
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
                assert re.search(r'{}.*\s+{}'
                                 .format(alias, minigraph_neighbors[setup['port_alias_map'][alias]]['name']),
                                 lldp_table) is not None
        elif mode == 'default':
            for intf in lldp_interfaces['interface']:
                assert re.search(r'{}.*\s+{}'.format(intf, minigraph_neighbors[intf]['name']),
                                 lldp_table) is not None

    def test_show_lldp_neighbor(self, setup, setup_config_mode, lldp_interfaces):
        """
        Checks whether 'show lldp neighbor <port>' lists the lldp neighbor
        information corresponding to the test interface when its interface
        alias/name is provied according to the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = lldp_interfaces['alias'][0] if (mode == 'alias') else lldp_interfaces['interface'][0]
        minigraph_neighbors = setup['minigraph_facts']['minigraph_neighbors']

        lldp_neighbor = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} show lldp neighbor {}'.format(ifmode, test_intf))['stdout']
        logger.info('lldp_neighbor:\n{}'.format(lldp_neighbor))

        if mode == 'alias':
            assert re.search(r'Interface:\s+{},\svia:\sLLDP,'.format(test_intf), lldp_neighbor) is not None
            assert re.search(r'SysName:\s+{}'.format(minigraph_neighbors[setup['port_alias_map'][test_intf]]['name']),
                             lldp_neighbor) is not None
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
        regex_int = re.compile(r'(\S+)(\d+)')
        interfaces = list()

        show_intf_counter = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show interfaces counter'.format(ifmode))
        logger.info('show_intf_counter:\n{}'.format(show_intf_counter['stdout']))

        for line in show_intf_counter['stdout_lines']:
            line = line.strip()
            if regex_int.match(line):
                interfaces.append(regex_int.match(line).group(0))

        assert (len(interfaces) > 0)

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

        show_intf_desc = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show interfaces description {} \
                                            | sed -n "/^ *Eth/ p"'.format(ifmode, test_intf))['stdout']
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

        show_intf_status = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={0} show interfaces status {1} | grep -w {1}'
                                              .format(ifmode, test_intf))
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

        for key, value in list(minigraph_portchannels.items()):
            if mode == 'alias':
                assert re.search(r'{}\s+LACP\(A\)\(Up\).*{}'.format(key, setup['port_name_map'][value['members'][0]]),
                                 int_po) is not None
            elif mode == 'default':
                assert re.search(r'{}\s+LACP\(A\)\(Up\).*{}'.format(key, value['members'][0]), int_po) is not None


def test_show_pfc_counters(setup, setup_config_mode):
    """
    Checks whether 'show pfc counters' lists the interface names as
    per the configured naming mode
    """
    dutHostGuest, mode, ifmode = setup_config_mode
    pfc_rx = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show pfc counters | sed -n "/Port Rx/,/^$/p"'
                                .format(ifmode))['stdout']
    pfc_tx = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo show pfc counters | sed -n "/Port Tx/,/^$/p"'
                                .format(ifmode))['stdout']
    logger.info('pfc_rx:\n{}'.format(pfc_rx))
    logger.info('pfc_tx:\n{}'.format(pfc_tx))

    pfc_rx_names = [x.strip().split(' ')[0] for x in pfc_rx.splitlines()]
    pfc_tx_names = [x.strip().split(' ')[0] for x in pfc_tx.splitlines()]
    logger.info('pfc_rx_names:\n{}'.format(pfc_rx_names))
    logger.info('pfc_tx_names:\n{}'.format(pfc_tx_names))

    if mode == 'alias':
        for alias in setup['port_alias']:
            assert (alias in pfc_rx_names) and (alias in pfc_tx_names)
            assert (setup['port_alias_map'][alias] not in pfc_rx_names) and \
                (setup['port_alias_map'][alias] not in pfc_tx_names)
    elif mode == 'default':
        for intf in setup['default_interfaces']:
            assert (intf in pfc_rx_names) and (intf in pfc_tx_names)
            assert (setup['port_name_map'][intf] not in pfc_rx_names) and \
                (setup['port_name_map'][intf] not in pfc_tx_names)


class TestShowPriorityGroup():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        skip_test_for_multi_asic(duthosts, enum_rand_one_per_hwsku_frontend_hostname)

    def test_show_priority_group_persistent_watermark_headroom(self, setup, setup_config_mode):
        """
        Checks whether 'show priority-group persistent-watermark headroom'
        lists the interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_pg = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show priority-group persistent-watermark headroom'
                                     .format(ifmode))['stdout']
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
        show_pg = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show priority-group persistent-watermark shared'
                                     .format(ifmode))['stdout']
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
        show_pg = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show priority-group watermark headroom'
                                     .format(ifmode))['stdout']
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
        show_pg = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show priority-group watermark shared'
                                     .format(ifmode))['stdout']
        logger.info('show_pg:\n{}'.format(show_pg))

        if mode == 'alias':
            for alias in setup['upport_alias_list']:
                assert re.search(r'{}.*'.format(alias), show_pg) is not None
        elif mode == 'default':
            for intf in setup['up_ports']:
                assert re.search(r'{}.*'.format(intf), show_pg) is not None


class TestShowQueue():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        skip_test_for_multi_asic(
            duthosts, enum_rand_one_per_hwsku_frontend_hostname)

    def test_show_queue_counters(self, setup, setup_config_mode, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Checks whether 'show queue counters' lists the interface names as
        per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        queue_counter = dutHostGuest.shell(
            r'SONIC_CLI_IFACE_MODE={} sudo show queue counters | grep "UC\|MC\|ALL"'.format(ifmode))['stdout']
        logger.info('queue_counter:\n{}'.format(queue_counter))

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        buffer_queue_keys = redis_get_keys(duthost, 'CONFIG_DB', 'BUFFER_QUEUE|*')
        interfaces = set()

        for key in buffer_queue_keys:
            try:
                fields = key.split("|")
                # The format of BUFFER_QUEUE entries on VOQ chassis is
                #   'BUFFER_QUEUE|<host name>|<asic-name>|Ethernet32|0-2'
                # where 'host name' could be any host in the chassis, including those from other
                # cards. This test only cares about local interfaces, so we can filter out the rest
                if duthost.facts['switch_type'] == 'voq':
                    hostname = fields[1]
                    if hostname != duthost.hostname:
                        continue
                # The interface name is always the last but one field in the BUFFER_QUEUE entry key
                interfaces.add(fields[-2])
            except IndexError:
                pass

        # For the test to be valid, we should have at least one interface selected
        assert (len(interfaces) > 0)

        intfsChecked = 0
        if mode == 'alias':
            for intf in interfaces:
                alias = setup['port_name_map'][intf]
                assert (re.search(QUEUE_COUNTERS_RE_FMT.format(alias),
                                  queue_counter) is not None) \
                    and (re.search(QUEUE_COUNTERS_RE_FMT.format(setup['port_alias_map'][alias]),
                                   queue_counter) is None)
                intfsChecked += 1
        elif mode == 'default':
            for intf in interfaces:
                if intf not in setup['port_name_map']:
                    continue
                assert (re.search(QUEUE_COUNTERS_RE_FMT.format(intf),
                                  queue_counter) is not None) \
                    and (re.search(QUEUE_COUNTERS_RE_FMT.format(setup['port_name_map'][intf]),
                                   queue_counter) is None)
                intfsChecked += 1

        # At least one interface should have been checked to have a valid result
        assert (intfsChecked > 0)

    def test_show_queue_counters_interface(self, setup_config_mode, sample_intf):
        """
        Check whether the interface name is present in output in the format
        corresponding to the mode set
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = sample_intf[mode]
        queue_counter_intf = dutHostGuest.shell(
            r'SONIC_CLI_IFACE_MODE={} sudo show queue counters {} | grep "UC\|MC\|ALL"'.format(ifmode, test_intf))
        logger.info('queue_counter_intf:\n{}'.format(queue_counter_intf))

        for i in range(len(queue_counter_intf['stdout_lines'])):
            assert re.search(r'{}\s+[U|M]C|ALL{}\s+\S+\s+\S+\s+\S+\s+\S+'
                             .format(test_intf, i), queue_counter_intf['stdout']) is not None

    def test_show_queue_persistent_watermark_multicast(self, setup, setup_config_mode):
        """
        Checks whether 'show queue persistent-watermark multicast' lists
        the interface names as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        show_queue_wm_mcast = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} show queue persistent-watermark multicast'.format(ifmode))['stdout']
        logger.info('show_queue_wm_mcast:\n{}'.format(show_queue_wm_mcast))

        if show_queue_wm_mcast != "Object map from the COUNTERS_DB is empty "\
                "because the multicast queues are not configured in the CONFIG_DB!":
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
        show_queue_wm_ucast = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} show queue persistent-watermark unicast'.format(ifmode))['stdout']
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
        show_queue_wm_mcast = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} show queue watermark multicast'.format(ifmode))['stdout']
        logger.info('show_queue_wm_mcast:\n{}'.format(show_queue_wm_mcast))

        if show_queue_wm_mcast != ("Object map from the COUNTERS_DB is empty because the multicast queues "
                                   "are not configured in the CONFIG_DB!"):
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
        show_queue_wm_ucast = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} show queue watermark unicast'.format(ifmode))['stdout']
        logger.info('show_queue_wm_ucast:\n{}'.format(show_queue_wm_ucast))

        if mode == 'alias':
            for alias in setup['port_alias']:
                assert re.search(r'{}'.format(alias), show_queue_wm_ucast) is not None
        elif mode == 'default':
            for intf in setup['default_interfaces']:
                assert re.search(r'{}'.format(intf), show_queue_wm_ucast) is not None

# Tests to be run in t0/m0 topology


class TestShowVlan():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, tbinfo):
        if tbinfo['topo']['type'] not in ['t0', 'm0']:
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
        res = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config vlan add 100'
                                 .format(ifmode), module_ignore_errors=True)
        if res["rc"] != 0 and "Restart service dhcp_relay failed with error" not in res["stderr"]:
            pytest.fail("Add vlan failed in setup")

        yield

        logger.info('Cleaning up the test vlan 100')
        res = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config vlan del 100'
                                 .format(ifmode), module_ignore_errors=True)
        if res["rc"] != 0 and "Restart service dhcp_relay failed with error" not in res["stderr"]:
            pytest.fail("Del vlan failed in teardown")

    def test_show_vlan_brief(self, setup, setup_config_mode):
        """
        Checks whether 'show vlan brief' lists the interface names
        as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_vlans = setup['minigraph_facts']['minigraph_vlans']

        show_vlan_brief = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} sudo show vlan brief'.format(ifmode))['stdout']
        logger.info('show_vlan_brief:\n{}'.format(show_vlan_brief))

        vlan_type = minigraph_vlans['Vlan1000'].get('type', 'untagged').lower()

        for item in minigraph_vlans['Vlan1000']['members']:
            if mode == 'alias':
                assert re.search(r'{}.*{}'
                                 .format(setup['port_name_map'][item], vlan_type), show_vlan_brief) is not None
            elif mode == 'default':
                assert re.search(r'{}.*{}'.format(item, vlan_type), show_vlan_brief) is not None

    @pytest.mark.usefixtures('setup_vlan')
    def test_show_vlan_config(self, setup, setup_config_mode):
        """
        Checks whether 'config vlan member add <vlan> <intf>' adds
        the test interface when its interface alias/name is provided
        as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_vlans = setup['minigraph_facts']['minigraph_vlans']
        vlan_interface = minigraph_vlans[list(minigraph_vlans.keys())[0]]['members'][0]
        vlan_interface_alias = setup['port_name_map'][vlan_interface]
        v_intf = vlan_interface_alias if (mode == 'alias') else vlan_interface

        dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} sudo config vlan member add 100 {}'.format(ifmode, v_intf))
        show_vlan = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} sudo show vlan config | grep -w "Vlan100"'.format(ifmode))['stdout']
        logger.info('show_vlan:\n{}'.format(show_vlan))
        dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} sudo config vlan member del 100 {}'.format(ifmode, v_intf))

        assert v_intf in show_vlan


# Tests to be run in t1 topology
class TestConfigInterface():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, tbinfo):
        if tbinfo['topo']['type'] not in ['t2', 't1']:
            pytest.skip('Unsupported topology')

    @pytest.fixture(scope='class', autouse=True)
    def reset_config_interface(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, sample_intf):
        """
        Resets the test interface's configurations on completion of
        all tests in the enclosing test class.

        Args:
            duthost: AnsibleHost instance for DUT
            test_intf: Fixture defined in this module
        Yields:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        interface = sample_intf['default']
        interface_ip = sample_intf['ip']
        native_speed = sample_intf['native_speed']
        cli_ns_option = sample_intf['cli_ns_option']

        yield

        if interface_ip is not None:
            duthost.shell('config interface {} ip add {} {}'.format(cli_ns_option, interface, interface_ip))

        duthost.shell('config interface {} startup {}'.format(cli_ns_option, interface))
        duthost.shell('config interface {} speed {} {}'.format(cli_ns_option, interface, native_speed))

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
        cli_ns_option = sample_intf['cli_ns_option']

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface {} ip remove {} {}'.format(
            ifmode, cli_ns_option, test_intf, test_intf_ip))
        if out['rc'] != 0:
            pytest.fail()

        wait(3)
        show_ip_intf = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ip interface'.format(ifmode))['stdout']
        logger.info('show_ip_intf:\n{}'.format(show_ip_intf))

        assert re.search(r'{}\s+{}'.format(test_intf, test_intf_ip), show_ip_intf) is None

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface {} ip add {} {}'.format(
            ifmode, cli_ns_option, test_intf, test_intf_ip))
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
        cli_ns_option = sample_intf['cli_ns_option']

        regex_int = re.compile(r'(\S+)\s+[\d,N\/A]+\s+(\w+)\s+(\d+)\s+[\w\/]+\s+([\w\/]+)\s+(\w+)\s+(\w+)\s+(\w+)')

        def _port_status(expected_state):
            admin_state = ""
            show_intf_status = dutHostGuest.shell(
                'SONIC_CLI_IFACE_MODE={0} show interfaces status {1} | grep -w {1}'.format(ifmode, test_intf))
            logger.info('show_intf_status:\n{}'.format(show_intf_status['stdout']))

            line = show_intf_status['stdout'].strip()
            if regex_int.match(line) and interface == regex_int.match(line).group(1):
                admin_state = regex_int.match(line).group(7)

            return admin_state == expected_state

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface {} shutdown {}'.format(
            ifmode, cli_ns_option, test_intf))
        if out['rc'] != 0:
            pytest.fail()
        pytest_assert(wait_until(PORT_TOGGLE_TIMEOUT, 2, 0, _port_status, 'down'),
                      "Interface {} should be admin down".format(test_intf))

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface {} startup {}'.format(
            ifmode, cli_ns_option, test_intf))
        if out['rc'] != 0:
            pytest.fail()
        pytest_assert(wait_until(PORT_TOGGLE_TIMEOUT, 2, 0, _port_status, 'up'),
                      "Interface {} should be admin up".format(test_intf))

    def test_config_interface_speed(self, setup_config_mode, sample_intf,
                                    duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Checks whether 'config interface speed <intf> <speed>' sets
        speed of the test interface when its interface alias/name is
        provided as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        test_intf = sample_intf[mode]
        interface = sample_intf['default']
        native_speed = sample_intf['native_speed']
        cli_ns_option = sample_intf['cli_ns_option']
        asic_index = sample_intf['asic_index']
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        # Get supported speeds for interface
        supported_speeds = duthost.get_supported_speeds(interface)
        # Remove native speed from supported speeds
        if supported_speeds is not None:
            supported_speeds.remove(native_speed)
        # Set speed to configure
        configure_speed = supported_speeds[0] if supported_speeds else native_speed

        db_cmd = 'sudo {} CONFIG_DB HGET "PORT|{}" speed'\
            .format(duthost.asic_instance(asic_index).sonic_db_cli,
                    interface)
        speed = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} {}'.format(ifmode, db_cmd))['stdout']
        hwsku = duthost.facts['hwsku']
        if hwsku in ["Cisco-88-LC0-36FH-M-O36", "Cisco-88-LC0-36FH-O36"]:
            if (int(speed) == 400000 and int(configure_speed) <= 100000) or \
               (int(speed) == 100000 and int(configure_speed) > 200000):
                pytest.skip(
                    "Cisco-88-LC0-36FH-M-O36 and Cisco-88-LC0-36FH-O36 \
                     currently does not support\
                     speed change from 100G to 400G and vice versa on runtime"
                )

        out = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} sudo config interface {} speed {} {}'
            .format(ifmode, cli_ns_option, test_intf, configure_speed))

        if out['rc'] != 0:
            pytest.fail()

        speed = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} {}'.format(ifmode, db_cmd))['stdout']
        logger.info('speed: {}'.format(speed))

        assert speed == configure_speed

        out = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} sudo config interface {}  speed {} {}'.format(
            ifmode, cli_ns_option, test_intf, native_speed))
        if out['rc'] != 0:
            pytest.fail()

        speed = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} {}'.format(ifmode, db_cmd))['stdout']
        logger.info('speed: {}'.format(speed))

        assert speed == native_speed


def test_show_acl_table(setup, setup_config_mode, tbinfo):
    """
    Checks whether 'show acl table DATAACL' lists the interface names
    as per the configured naming mode
    """
    if tbinfo['topo']['type'] not in ['t1', 't2']:
        pytest.skip('Unsupported topology')

    if not setup['physical_interfaces']:
        pytest.skip('No non-portchannel member interface present')

    dutHostGuest, mode, ifmode = setup_config_mode
    minigraph_acls = setup['minigraph_facts']['minigraph_acls']

    if 'DataAcl' not in minigraph_acls:
        pytest.skip("Skipping test since DATAACL table is not supported on this platform")

    acl_table = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show acl table DATAACL'.format(ifmode))['stdout']
    logger.info('acl_table:\n{}'.format(acl_table))

    for item in minigraph_acls['DataAcl']:
        if item in setup['physical_interfaces']:
            if mode == 'alias':
                assert setup['port_name_map'][item] in acl_table
            elif mode == 'default':
                assert item in acl_table


def test_show_interfaces_neighbor_expected(setup, setup_config_mode, tbinfo, duthosts,
                                           enum_rand_one_per_hwsku_frontend_hostname):
    """
    Checks whether 'show interfaces neighbor expected' lists the
    interface names as per the configured naming mode
    """
    if tbinfo['topo']['type'] not in ['t1', 't2']:
        pytest.skip('Unsupported topology')

    skip_test_for_multi_asic(duthosts, enum_rand_one_per_hwsku_frontend_hostname)

    dutHostGuest, mode, ifmode = setup_config_mode
    minigraph_neighbors = setup['minigraph_facts']['minigraph_neighbors']

    show_int_neighbor = dutHostGuest.shell(
        'SONIC_CLI_IFACE_MODE={} show interfaces neighbor expected'.format(ifmode))['stdout']
    logger.info('show_int_neighbor:\n{}'.format(show_int_neighbor))

    for key, value in list(minigraph_neighbors.items()):
        if 'server' not in value['name'].lower():
            if mode == 'alias':
                assert re.search(r'{}\s+{}'
                                 .format(setup['port_name_map'][key], value['name']), show_int_neighbor) is not None
            elif mode == 'default':
                assert re.search(r'{}\s+{}'.format(key, value['name']), show_int_neighbor) is not None


class TestNeighbors():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, setup, tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        if tbinfo['topo']['type'] not in ['t2', 't1']:
            pytest.skip('Unsupported topology')
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        if duthost.is_multi_asic:
            pytest.skip("CLI not supported")

        if not setup['physical_interfaces']:
            pytest.skip('No non-portchannel member interface present')

    def test_show_arp(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup, setup_config_mode):
        """
        Checks whether 'show arp' lists the interface names as per the
        configured naming mode
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        dutHostGuest, mode, ifmode = setup_config_mode
        arptable = duthost.switch_arptable()['ansible_facts']['arptable']
        minigraph_portchannels = setup['minigraph_facts']['minigraph_portchannels']

        arp_output = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show arp'.format(ifmode))['stdout']
        logger.info('arp_output:\n{}'.format(arp_output))

        for item in arptable['v4']:
            # To ignore Midplane interface, added check on what is being set in setup fixture
            if (arptable['v4'][item]['interface'] in setup['port_name_map']) \
                    and (arptable['v4'][item]['interface'] not in minigraph_portchannels):
                if mode == 'alias':
                    assert re.search(r'{}.*\s+{}'
                                     .format(item, setup['port_name_map'][arptable['v4'][item]['interface']]),
                                     arp_output) is not None
                elif mode == 'default':
                    assert re.search(r'{}.*\s+{}'
                                     .format(item, arptable['v4'][item]['interface']), arp_output) is not None

    def test_show_ndp(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup, setup_config_mode):
        """
        Checks whether 'show ndp' lists the interface names as per the
        configured naming mode
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        dutHostGuest, mode, ifmode = setup_config_mode
        arptable = duthost.switch_arptable()['ansible_facts']['arptable']
        minigraph_portchannels = setup['minigraph_facts']['minigraph_portchannels']

        ndp_output = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ndp'.format(ifmode))['stdout']
        logger.info('ndp:\n{}'.format(ndp_output))

        for addr, detail in list(arptable['v6'].items()):
            if (
                    detail['macaddress'] != 'None' and
                    detail['interface'] in setup['port_name_map'] and
                    detail['interface'] not in minigraph_portchannels
            ):
                if mode == 'alias':
                    assert re.search(r'{}.*\s+{}'
                                     .format(addr, setup['port_name_map'][detail['interface']]),
                                     ndp_output) is not None
                elif mode == 'default':
                    assert re.search(r'{}.*\s+{}'.format(addr, detail['interface']), ndp_output) is not None


class TestShowIP():

    @pytest.fixture(scope="class", autouse=True)
    def setup_check_topo(self, setup, tbinfo):
        if tbinfo['topo']['type'] not in ['t2', 't1']:
            pytest.skip('Unsupported topology')

        if not setup['physical_interfaces']:
            pytest.skip('No non-portchannel member interface present')

    @pytest.fixture(scope='class')
    def static_route_intf(self,  duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup, tbinfo):
        """
        Returns the alias and names of the spine ports

        Args:
            setup: Fixture defined in this module
        Returns:
            static_route_intf: dictionary containing lists of aliases and names
            of the spine ports
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        static_route_intf = dict()
        static_route_intf['interface'] = list()
        static_route_intf['alias'] = list()
        gw_ip_list = []

        if not setup['physical_interfaces']:
            pytest.skip('No non-portchannel member interface present')

        for mg_intf in setup['minigraph_facts'][u'minigraph_interfaces']:
            if mg_intf[u'attachto'] == setup['physical_interfaces'][0]:
                dev = mg_intf[u'attachto']
                namespace = setup['minigraph_facts']['minigraph_neighbors'][dev]['namespace']
                gw_ip = mg_intf['peer_addr']
                if ipaddress.ip_address(gw_ip).version == 4:
                    ip_version = ''
                    dst_ip = '192.168.1.1'
                else:
                    ip_version = '-6'
                    dst_ip = 'fd0a::1'
                if namespace:
                    duthost.shell("ip netns exec {} ip {} route add {}  via {} dev {}".
                                  format(namespace, ip_version, dst_ip, gw_ip, dev))
                else:
                    duthost.shell("ip {} route add {}  via {} dev {}".format(ip_version, dst_ip, gw_ip, dev))
                static_route_intf['interface'].append(dev)
                static_route_intf['alias'].append(setup['port_name_map'][dev])
                gw_ip_list.append((gw_ip, namespace))

        yield static_route_intf

        for gw_ip_ns in gw_ip_list:
            gw_ip, namespace = gw_ip_ns
            if ipaddress.ip_address(gw_ip).version == 4:
                ip_version = ''
                dst_ip = '192.168.1.1'
            else:
                ip_version = '-6'
                dst_ip = 'fd0a::1'

            if namespace:
                duthost.shell("ip netns exec {} ip {} route del {} via {}".
                              format(namespace, ip_version, dst_ip, gw_ip))
            else:
                duthost.shell("ip {} route del {} via {}".
                              format(ip_version, dst_ip, gw_ip))

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
                    assert re.search(r'{}\s+{}'
                                     .format(setup['port_name_map'][item['attachto']], item['addr']),
                                     show_ip_interface) is not None
                elif mode == 'default':
                    assert re.search(r'{}\s+{}'.format(item['attachto'], item['addr']), show_ip_interface) is not None

    def test_show_ipv6_interface(self, setup, setup_config_mode):
        """
        Checks whether 'show ipv6 interface' lists the interface names as
        per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        minigraph_interfaces = setup['minigraph_facts']['minigraph_interfaces']

        show_ipv6_interface = dutHostGuest.shell(
            'SONIC_CLI_IFACE_MODE={} show ipv6 interface'.format(ifmode))['stdout']
        logger.info('show_ipv6_interface:\n{}'.format(show_ipv6_interface))

        for item in minigraph_interfaces:
            if IPAddress(item['addr']).version == 6:
                if mode == 'alias':
                    assert re.search(r'{}\s+{}'.format(setup['port_name_map'][item['attachto']], item['addr']),
                                     show_ipv6_interface) is not None
                elif mode == 'default':
                    assert re.search(r'{}\s+{}'.format(item['attachto'], item['addr']),
                                     show_ipv6_interface) is not None

    def test_show_ip_route_v4(self, setup_config_mode, static_route_intf, tbinfo):
        """
        Checks whether 'show ip route <ip>' lists the interface name as
        per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        dip = '192.168.1.1'
        route = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ip route {}'.format(ifmode, dip))['stdout']
        logger.info('route:\n{}'.format(route))

        if mode == 'alias':
            for alias in static_route_intf['alias']:
                assert re.search(r'via {}'.format(alias), route) is not None
        elif mode == 'default':
            for intf in static_route_intf['interface']:
                assert re.search(r'via {}'.format(intf), route) is not None

    def test_show_ip_route_v6(self, setup_config_mode, static_route_intf):
        """
        Checks whether 'show ipv6 route <ipv6>' lists the interface name
        as per the configured naming mode
        """
        dutHostGuest, mode, ifmode = setup_config_mode
        dip = 'fd0a::1'
        route = dutHostGuest.shell('SONIC_CLI_IFACE_MODE={} show ipv6 route {}'.format(ifmode, dip))['stdout']
        logger.info('route:\n{}'.format(route))

        if mode == 'alias':
            for alias in static_route_intf['alias']:
                assert re.search(r'via {}'.format(alias), route) is not None
        elif mode == 'default':
            for intf in static_route_intf['interface']:
                assert re.search(r'via {}'.format(intf), route) is not None
