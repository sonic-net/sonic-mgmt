import pytest
from tests.common.plugins.ptfadapter import get_ifaces, get_ifaces_map
from tests.common import constants
from .iface_loopback_action_helper import get_tested_up_ports, remove_orig_dut_port_config, \
    get_portchannel_peer_port_map, recover_config, apply_config
from .iface_loopback_action_helper import ETHERNET_RIF, VLAN_RIF, PO_RIF, SUB_PORT_RIF, PO_SUB_PORT_RIF
from tests.common.fixtures.duthost_utils import \
    backup_and_restore_config_db_package  # lgtm[py/unused-import]  # noqa: F401

PORT_COUNT = 10


def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the rif loopback action tests.
    """

    parser.addoption(
        "--rif_loppback_reboot_type",
        action="store",
        type=str,
        default="cold",
        help="reboot type such as reload, cold, fast, warm, random"
    )


@pytest.fixture(scope="package")
def orig_ports_configuration(request, duthost, ptfhost, tbinfo):
    """
    Get the ports used to do test, return the dict of the port's original vlan, portchannel, infos.
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :return: Dictionary of original port configuration
    For example:
            {
            1: {
                'port': 'Ethernet0',
                'vlan': None,
                'portchannel': None,
                'ip_addr': '10.0.0.5',
                'ptf_port': 'eth0'
                },
            2: {
                'port': 'Ethernet4',
                'vlan': 'Vlan1000',
                'portchannel': None,
                'ip_addr': None,
                'ptf_port': 'eth1'
                },
            3: {
                'port': 'Ethernet8',
                'vlan': None,
                'portchannel': 'PortChannel102',
                'ip_addr': None,
                'ptf_port': 'eth2'
                }
            }
    """
    if 'backend' in tbinfo['topo']['name']:
        ptf_port_mapping_mode = getattr(request.module, "PTF_PORT_MAPPING_MODE",
                                        constants.PTF_PORT_MAPPING_MODE_DEFAULT)
    else:
        ptf_port_mapping_mode = 'use_orig_interface'
    res = ptfhost.command('cat /proc/net/dev')
    ptf_ifaces = get_ifaces(res['stdout'])
    ptf_ifaces_map = get_ifaces_map(ptf_ifaces, ptf_port_mapping_mode)
    port_dict = get_tested_up_ports(duthost, ptf_ifaces_map, count=PORT_COUNT)
    yield port_dict


@pytest.fixture(scope="package")
def ports_configuration(orig_ports_configuration):
    """
    Define the ports parameters
    :param orig_ports_configuration: original config of the ports.
    :return: Dictionary of port parameters for configuration DUT and PTF host
    For example:
            {
            'Ethernet4': {
                'type': 'ethernet',
                'port_index': '2',
                'port': 'Ethernet4',
                'ptf_port': 'eth1',
                'ip_addr': '11.0.0.1',
                'ptf_ip_addr': '11.0.0.10'
                },
            'Vlan11': {
                'type': 'vlan',
                'vlan_id': '11',
                'port_index': '3',
                'port': 'Ethernet8',
                'ptf_port': 'eth2',
                'ip_addr': '11.1.0.1',
                'ptf_ip_addr': '11.1.0.10'
                },
            'PortChannel222': {
                'type': 'po',
                'po_id': '222',
                'port_index': '4',
                'port': 'Ethernet12',
                'ptf_port': 'eth3',
                'ip_addr': '11.2.0.1',
                'ptf_ip_addr': '11.2.0.10'
                },
            'Ethernet8.33': {
                'type': 'sub_port',
                'vlan_id': '33',
                'port_index': '5',
                'port': 'Ethernet16',
                'ptf_port': 'eth4',
                'ip_addr': '11.3.0.1',
                'ptf_ip_addr': '11.3.0.10'
                },
            'Po444.44': {
                'type': 'po_sub_port',
                'po_id': '444',
                'vlan_id': '44',
                'port_index': '6',
                'port': 'Ethernet20',
                'ptf_port': 'eth5',
                'ip_addr': '11.4.0.1',
                'ptf_ip_addr': '11.4.0.10'
                },
            }
    """
    groups_of_ports = 5
    dut_ip_list, ptf_ip_list = generate_ip_list()
    ports_configuration = {}
    index = 0
    for port_index, port_dict in orig_ports_configuration.items():
        if index % groups_of_ports == 0:
            rif_port_name = port_dict['port']
            ports_configuration[rif_port_name] = {}
            ports_configuration[rif_port_name]['type'] = ETHERNET_RIF

        elif index % groups_of_ports == 1:
            vlan_id = 50 + index
            rif_port_name = "Vlan{}".format(vlan_id)
            ports_configuration[rif_port_name] = {}
            ports_configuration[rif_port_name]['type'] = VLAN_RIF
            ports_configuration[rif_port_name]['vlan_id'] = vlan_id

        elif index % groups_of_ports == 2:
            po_id = 50 + index
            rif_port_name = "PortChannel{}".format(po_id)
            ports_configuration[rif_port_name] = {}
            ports_configuration[rif_port_name]['type'] = PO_RIF
            ports_configuration[rif_port_name]['po_id'] = po_id

        elif index % groups_of_ports == 3:
            vlan_id = 50 + index
            rif_port_name = "{}.{}".format(port_dict['port'], vlan_id)
            ports_configuration[rif_port_name] = {}
            ports_configuration[rif_port_name]['type'] = SUB_PORT_RIF
            ports_configuration[rif_port_name]['vlan_id'] = vlan_id

        elif index % groups_of_ports == 4:
            po_id = 50 + index
            vlan_id = 50 + index
            rif_port_name = "Po{}.{}".format(po_id, vlan_id)
            ports_configuration[rif_port_name] = {}
            ports_configuration[rif_port_name]['type'] = PO_SUB_PORT_RIF
            ports_configuration[rif_port_name]['po_id'] = po_id
            ports_configuration[rif_port_name]['vlan_id'] = vlan_id

        ports_configuration[rif_port_name]['port'] = port_dict['port']
        ports_configuration[rif_port_name]['ptf_port'] = port_dict['ptf_port']
        ports_configuration[rif_port_name]['port_index'] = port_index
        ports_configuration[rif_port_name]['ip_addr'] = dut_ip_list[index]
        ports_configuration[rif_port_name]['ptf_ip_addr'] = ptf_ip_list[index]
        index += 1
    yield ports_configuration


def generate_ip_list():
    dut_ip_list = []
    ptf_ip_list = []
    for i in range(PORT_COUNT):
        dut_ip_list.append('11.{}.0.1/24'.format(i))
        ptf_ip_list.append('11.{}.0.10/24'.format(i))
    return dut_ip_list, ptf_ip_list


@pytest.fixture(scope="package", autouse=True)
def setup(duthost, ptfhost, orig_ports_configuration, ports_configuration,
          backup_and_restore_config_db_package, nbrhosts, tbinfo):                # noqa: F811
    """
    Config: Cleanup the original port configuration and add new configurations before test
    Cleanup: restore the config on the VMs
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :param orig_ports_configuration: original ports configuration parameters
    :param ports_configuration: ports configuration parameters
    :param backup_and_restore_config_db_package: backup and restore config db package fixture.
    :param nbrhosts: nbrhosts fixture.
    :param tbinfo: Testbed object
    """
    peer_shutdown_ports = get_portchannel_peer_port_map(duthost, orig_ports_configuration, tbinfo, nbrhosts)
    remove_orig_dut_port_config(duthost, orig_ports_configuration)
    for vm_host, peer_ports in peer_shutdown_ports.items():
        for peer_port in peer_ports:
            vm_host.shutdown(peer_port)
    apply_config(duthost, ptfhost, ports_configuration)

    yield
    for vm_host, peer_ports in peer_shutdown_ports.items():
        for peer_port in peer_ports:
            vm_host.no_shutdown(peer_port)


@pytest.fixture(scope="package", autouse=True)
def recover(duthost, ptfhost, ports_configuration):
    """
    restore the original configurations
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :param ports_configuration: ports configuration parameters
    """
    yield
    recover_config(duthost, ptfhost, ports_configuration)
