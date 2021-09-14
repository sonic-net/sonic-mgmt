import json
import os
import pytest
import logging
import yaml

import requests

from ipaddress import ip_interface
from jinja2 import Template
from natsort import natsorted

from tests.common import constants
from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)

ROOT_DIR = "/root"
OPT_DIR = "/opt"
TMP_DIR = '/tmp'
SUPERVISOR_CONFIG_DIR = "/etc/supervisor/conf.d/"
SCRIPTS_SRC_DIR = "scripts/"
TEMPLATES_DIR = "templates/"
ACS_TESTS = "acstests"
PTF_TESTS = "ptftests"
SAI_TESTS = "saitests"
ARP_RESPONDER_PY = "arp_responder.py"
ICMP_RESPONDER_PY = "icmp_responder.py"
ICMP_RESPONDER_CONF_TEMPL = "icmp_responder.conf.j2"
GARP_SERVICE_PY = 'garp_service.py'
GARP_SERVICE_CONF_TEMPL = 'garp_service.conf.j2'
PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'


@pytest.fixture(scope="session", autouse=True)
def copy_acstests_directory(ptfhost):
    """
        Copys ACS tests directory to PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    logger.info("Copy ACS test files to PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=ACS_TESTS, dest=ROOT_DIR)

    yield

    logger.info("Delete ACS test files from PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(ROOT_DIR, ACS_TESTS), state="absent")


@pytest.fixture(scope="session", autouse=True)
def copy_ptftests_directory(ptfhost):
    """
        Copys PTF tests directory to PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    logger.info("Copy PTF test files to PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=PTF_TESTS, dest=ROOT_DIR)

    yield

    logger.info("Delete PTF test files from PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(ROOT_DIR, PTF_TESTS), state="absent")


@pytest.fixture(scope="module", autouse=True)
def set_ptf_port_mapping_mode(ptfhost, request, tbinfo):
    """Set per-module ptf port mapping mode used by ptftests on ptf."""
    if "backend" in tbinfo["topo"]["name"]:
        ptf_port_mapping_mode = getattr(request.module, "PTF_PORT_MAPPING_MODE", constants.PTF_PORT_MAPPING_MODE_DEFAULT)
    else:
        ptf_port_mapping_mode = "use_orig_interface"
    logging.info("Set ptf port mapping mode: %s", ptf_port_mapping_mode)
    data = {
        "PTF_PORT_MAPPING_MODE": ptf_port_mapping_mode
    }
    ptfhost.copy(content=yaml.dump(data), dest=os.path.join(ROOT_DIR, PTF_TESTS, "constants.yaml"))
    return


@pytest.fixture(scope="session", autouse=True)
def copy_saitests_directory(ptfhost):
    """
        Copys SAI tests directory to PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    logger.info("Copy SAI test files to PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=SAI_TESTS, dest=ROOT_DIR)

    yield

    logger.info("Delete SAI test files from PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(ROOT_DIR, SAI_TESTS), state="absent")


@pytest.fixture(scope="session", autouse=True)
def change_mac_addresses(ptfhost):
    """
        Change MAC addresses (unique) on PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    logger.info("Change interface MAC addresses on ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.change_mac_addresses()


@pytest.fixture(scope="session", autouse=True)
def remove_ip_addresses(ptfhost):
    """
        Remove existing IP addresses on PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)
        Returns:
            None
    """
    logger.info("Remove existing IPs on ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.remove_ip_addresses()

    yield

    logger.info("Remove IPs to restore ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.remove_ip_addresses()


@pytest.fixture(scope="session", autouse=True)
def copy_arp_responder_py(ptfhost):
    """
        Copy arp_responder to PTF container.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)
        Returns:
            None
    """
    logger.info("Copy arp_responder.py to ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, ARP_RESPONDER_PY), dest=OPT_DIR)

    yield

    logger.info("Delete arp_responder.py from ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(OPT_DIR, ARP_RESPONDER_PY), state="absent")


@pytest.fixture(scope='class')
def ptf_portmap_file(duthosts, rand_one_dut_hostname, ptfhost):
    """
        Prepare and copys port map file to PTF host

        Args:
            request (Fixture): pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            filename (str): returns the filename copied to PTF host
    """
    duthost = duthosts[rand_one_dut_hostname]
    intfInfo = duthost.show_interface(command = "status")['ansible_facts']['int_status']
    portList = natsorted([port for port in intfInfo if port.startswith('Ethernet')])
    portMapFile = "/tmp/default_interface_to_front_map.ini"
    with open(portMapFile, 'w') as file:
        file.write("# ptf host interface @ switch front port name\n")
        file.writelines(
            map(
                    lambda (index, port): "{0}@{1}\n".format(index, port),
                    enumerate(portList)
                )
            )

    ptfhost.copy(src=portMapFile, dest="/root/")

    yield "/root/{}".format(portMapFile.split('/')[-1])


@pytest.fixture(scope="session", autouse=True)
def run_icmp_responder(duthost, ptfhost, tbinfo):
    """Run icmp_responder.py over ptfhost."""
    # No vlan is avaliable on non-t0 testbed, so skip this fixture 
    if 't0' not in tbinfo['topo']['type']:
        logger.info("Not running on a T0 testbed, not starting ICMP responder")
        yield
        return
    logger.debug("Copy icmp_responder.py to ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, ICMP_RESPONDER_PY), dest=OPT_DIR)

    logging.info("Start running icmp_responder")
    templ = Template(open(os.path.join(TEMPLATES_DIR, ICMP_RESPONDER_CONF_TEMPL)).read())
    ptf_indices = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_ptf_indices"]
    vlan_intfs = duthost.get_vlan_intfs()
    vlan_table = duthost.get_running_config_facts()['VLAN']
    vlan_name = list(vlan_table.keys())[0]
    vlan_mac = duthost.get_dut_iface_mac(vlan_name)
    icmp_responder_args = " ".join("-i eth%s" % ptf_indices[_] for _ in vlan_intfs)
    icmp_responder_args += " " + "-m {}".format(vlan_mac)
    ptfhost.copy(
        content=templ.render(icmp_responder_args=icmp_responder_args),
        dest=os.path.join(SUPERVISOR_CONFIG_DIR, "icmp_responder.conf")
    )
    ptfhost.shell("supervisorctl update")
    ptfhost.shell("supervisorctl start icmp_responder")

    yield

    logging.info("Stop running icmp_responder")
    ptfhost.shell("supervisorctl stop icmp_responder")


@pytest.fixture(scope='module', autouse=True)
def run_garp_service(duthost, ptfhost, tbinfo, change_mac_addresses, request):
    if tbinfo['topo']['type'] == 't0':
        garp_config = {}

        ptf_indices = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_ptf_indices"]
        if 'dualtor' not in tbinfo['topo']['name']:
            # For mocked dualtor testbed
            mux_cable_table = {}
            server_ipv4_base_addr, _ = request.getfixturevalue('mock_server_base_ip_addr')
            for i, intf in enumerate(request.getfixturevalue('tor_mux_intfs')):
                server_ipv4 = str(server_ipv4_base_addr + i)
                mux_cable_table[intf] = {}
                mux_cable_table[intf]['server_ipv4'] = unicode(server_ipv4)
        else:
            # For physical dualtor testbed
            mux_cable_table = duthost.get_running_config_facts()['MUX_CABLE']

        logger.info("Generating GARP service config file")

        for vlan_intf, config in mux_cable_table.items():
            ptf_port_index = ptf_indices[vlan_intf]
            server_ip = ip_interface(config['server_ipv4']).ip

            garp_config[ptf_port_index] = {
                                            'target_ip': '{}'.format(server_ip)
                                        }

        ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, GARP_SERVICE_PY), dest=OPT_DIR)

        with open(os.path.join(TEMPLATES_DIR, GARP_SERVICE_CONF_TEMPL)) as f:
            template = Template(f.read())

        ptfhost.copy(content=json.dumps(garp_config, indent=4, sort_keys=True), dest=os.path.join(TMP_DIR, 'garp_conf.json'))
        ptfhost.copy(content=template.render(garp_service_args = '--interval 10'), dest=os.path.join(SUPERVISOR_CONFIG_DIR, 'garp_service.conf'))
        logger.info("Starting GARP Service on PTF host")
        ptfhost.shell('supervisorctl update')
        ptfhost.shell('supervisorctl start garp_service')
    else:
        logger.info("Not running on a T0 testbed, not starting GARP service")

    yield

    if tbinfo['topo']['type'] == 't0':
        logger.info("Stopping GARP service on PTF host")
        ptfhost.shell('supervisorctl stop garp_service')


def ptf_test_port_map(ptfhost, tbinfo, duthosts, mux_server_url):
    active_dut_map = {}
    if 'dualtor' in tbinfo['topo']['name']:
        res = requests.get(mux_server_url)
        pt_assert(res.status_code==200, 'Failed to get mux status: {}'.format(res.text))
        for mux_status in res.json().values():
            active_dut_index = 0 if mux_status['active_side'] == 'upper_tor' else 1
            active_dut_map[str(mux_status['port_index'])] = active_dut_index

    disabled_ptf_ports = set()
    for ptf_map in tbinfo['topo']['ptf_map_disabled'].values():
        # Loop ptf_map of each DUT. Each ptf_map maps from ptf port index to dut port index
        disabled_ptf_ports = disabled_ptf_ports.union(set(ptf_map.keys()))

    router_macs = [duthost.facts['router_mac'] for duthost in duthosts]

    logger.info('active_dut_map={}'.format(active_dut_map))
    logger.info('disabled_ptf_ports={}'.format(disabled_ptf_ports))
    logger.info('router_macs={}'.format(router_macs))

    ports_map = {}
    for ptf_port, dut_intf_map in tbinfo['topo']['ptf_dut_intf_map'].items():
        if str(ptf_port) in disabled_ptf_ports:
            # Skip PTF ports that are connected to disabled VLAN interfaces
            continue

        if len(dut_intf_map.keys()) == 2:
            # PTF port is mapped to two DUTs -> dualtor topology and the PTF port is a vlan port
            # Packet sent from this ptf port will only be accepted by the active side DUT
            # DualToR DUTs use same special Vlan interface MAC address
            target_dut_index = int(active_dut_map[ptf_port])
            ports_map[ptf_port] = {
                'target_dut': target_dut_index,
                'target_mac': tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']['one_vlan_a']['Vlan1000']['mac']
            }
        else:
            # PTF port is mapped to single DUT
            target_dut_index = int(dut_intf_map.keys()[0])
            ports_map[ptf_port] = {
                'target_dut': target_dut_index,
                'target_mac': router_macs[target_dut_index]
            }

    logger.debug('ptf_test_port_map={}'.format(json.dumps(ports_map, indent=2)))

    ptfhost.copy(content=json.dumps(ports_map), dest=PTF_TEST_PORT_MAP)
    return PTF_TEST_PORT_MAP
