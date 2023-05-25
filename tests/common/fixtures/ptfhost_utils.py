import json
import os
import pytest
import logging
import yaml
import six
import requests

from ipaddress import ip_interface
from jinja2 import Template

from tests.common import constants
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.dut_utils import check_link_status
from tests.common.dualtor.dual_tor_utils import update_linkmgrd_probe_interval, recover_linkmgrd_probe_interval
from tests.common.utilities import wait_until

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
PROBER_INTERVAL_MS = 1000


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
        ptf_port_mapping_mode = getattr(request.module, "PTF_PORT_MAPPING_MODE",
                                        constants.PTF_PORT_MAPPING_MODE_DEFAULT)
    else:
        ptf_port_mapping_mode = "use_orig_interface"
    logger.info("Set ptf port mapping mode: %s", ptf_port_mapping_mode)
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
    # NOTE: up/down ptf interfaces in change_mac_address will interrupt icmp_responder
    # socket read/write operations, so let's restart icmp_responder if it is running
    icmp_responder_status = ptfhost.shell("supervisorctl status icmp_responder", module_ignore_errors=True)
    if icmp_responder_status["rc"] == 0 and "RUNNING" in icmp_responder_status["stdout"]:
        logger.debug("restart icmp_responder after change ptf port mac addresses")
        ptfhost.shell("supervisorctl restart icmp_responder", module_ignore_errors=True)


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
    # Interfaces restart is required, otherwise the ipv6 link-addresses won't back.
    ptfhost.restart_interfaces()


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


def _ptf_portmap_file(duthost, ptfhost, tbinfo):
    """
        Prepare and copys port map file to PTF host

        Args:
            request (Fixture): pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            filename (str): returns the filename copied to PTF host
    """
    intfInfo = duthost.show_interface(command="status")['ansible_facts']['int_status']
    portList = [port for port in intfInfo if port.startswith('Ethernet') and intfInfo[port]['admin_state'] == 'up']
    pt_assert(wait_until(50, 5, 0, check_link_status, duthost, portList, 'up'), "Partial of Ethernet port didn't go up")

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    portMapFile = "/tmp/default_interface_to_front_map.ini"
    with open(portMapFile, 'w') as file:
        file.write("# ptf host interface @ switch front port name\n")
        ptf_port_map = []
        for port in portList:
            if "Ethernet-Rec" not in port or "Ethernet-IB" not in port:
                index = mg_facts['minigraph_ptf_indices'][port]
                ptf_port_map.append("{}@{}\n".format(index, port))
        file.writelines(ptf_port_map)

    ptfhost.copy(src=portMapFile, dest="/root/")

    return "/root/{}".format(portMapFile.split('/')[-1])


@pytest.fixture(scope='class')
def ptf_portmap_file(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, tbinfo):
    """
    A class level fixture that calls _ptf_portmap_file
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield _ptf_portmap_file(duthost, ptfhost, tbinfo)


@pytest.fixture(scope='module')
def ptf_portmap_file_module(rand_selected_dut, ptfhost, tbinfo):
    """
    A module level fixture that calls _ptf_portmap_file
    """
    yield _ptf_portmap_file(rand_selected_dut, ptfhost, tbinfo)


icmp_responder_session_started = False


@pytest.fixture(scope="session", autouse=True)
def run_icmp_responder_session(duthosts, duthost, ptfhost, tbinfo):
    """Run icmp_responder on ptfhost session-wise on dualtor testbeds with active-active ports."""
    # No vlan is available on non-t0 testbed, so skip this fixture
    if "dualtor-mixed" not in tbinfo["topo"]["name"] and "dualtor-aa" not in tbinfo["topo"]["name"]:
        logger.info("Skip running icmp_responder at session level, "
                    "it is only for dualtor testbed with active-active mux ports.")
        yield
        return

    global icmp_responder_session_started

    update_linkmgrd_probe_interval(duthosts, tbinfo, PROBER_INTERVAL_MS)
    duthosts.shell("config save -y")

    duthost = duthosts[0]
    logger.debug("Copy icmp_responder.py to ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, ICMP_RESPONDER_PY), dest=OPT_DIR)

    logger.info("Start running icmp_responder")
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
    icmp_responder_session_started = True

    yield

    # NOTE: Leave icmp_responder running for dualtor-mixed topology
    return


@pytest.fixture(scope="module", autouse=True)
def run_icmp_responder(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, request):
    """Run icmp_responder.py over ptfhost."""
    # No vlan is available on non-t0 testbed, so skip this fixture
    if 't0' not in tbinfo['topo']['type']:
        logger.info("Not running on a T0 testbed, not starting ICMP responder")
        yield
        return
    elif 'dualtor' not in tbinfo['topo']['name'] and "test_advanced_reboot" in request.node.name:
        logger.info("Skip ICMP responder for advanced-reboot test on non dualtor devices")
        yield
        return

    if icmp_responder_session_started:
        logger.info("icmp_responder is already running.")
        yield
        return

    update_linkmgrd_probe_interval(duthosts, tbinfo, PROBER_INTERVAL_MS)
    duthosts.shell("config save -y")

    duthost = duthosts[rand_one_dut_hostname]
    logger.debug("Copy icmp_responder.py to ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, ICMP_RESPONDER_PY), dest=OPT_DIR)

    logger.info("Start running icmp_responder")
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

    logger.info("Stop running icmp_responder")
    ptfhost.shell("supervisorctl stop icmp_responder")
    logger.info("Recover linkmgrd probe interval")
    recover_linkmgrd_probe_interval(duthosts, tbinfo)
    duthosts.shell("config save -y")


@pytest.fixture
def pause_garp_service(ptfhost):
    """
    Temporarily pause GARP service on PTF for one test method

    `run_garp_service` is module scoped and autoused,
    but some tests in modules where it is imported need it disabled
    This fixture should only be used when garp_service is already running on the PTF
    """
    needs_resume = False
    res = ptfhost.shell("supervisorctl status garp_service", module_ignore_errors=True)
    if res['rc'] != 0:
        logger.warning("GARP service not present on PTF")
    elif 'RUNNING' in res['stdout']:
        needs_resume = True
        ptfhost.shell("supervisorctl stop garp_service")
    else:
        logger.warning("GARP service already stopped on PTF")

    yield

    if needs_resume:
        ptfhost.shell("supervisorctl start garp_service")


@pytest.fixture(scope='module', autouse=True)
def run_garp_service(duthost, ptfhost, tbinfo, change_mac_addresses, request):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    if tbinfo['topo']['type'] == 't0':
        garp_config = {}
        vlans = config_facts['VLAN']
        vlan_intfs = config_facts['VLAN_INTERFACE']
        dut_mac = ''
        for vlan_details in list(vlans.values()):
            if 'dualtor' in tbinfo['topo']['name']:
                dut_mac = vlan_details['mac'].lower()
            else:
                dut_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0]
            break

        dst_ipv6 = ''
        for intf_details in list(vlan_intfs.values()):
            for key in list(intf_details.keys()):
                try:
                    intf_ip = ip_interface(key)
                    if intf_ip.version == 6:
                        dst_ipv6 = intf_ip.ip
                        break
                except ValueError:
                    continue
            break

        ptf_indices = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_ptf_indices"]
        if 'dualtor' not in tbinfo['topo']['name']:
            if "test_advanced_reboot" in request.node.name:
                logger.info("Skip GARP service for advanced-reboot test on non dualtor devices")
                yield
                return
            # For mocked dualtor testbed
            mux_cable_table = {}
            server_ipv4_base_addr, server_ipv6_base_addr = request.getfixturevalue('mock_server_base_ip_addr')
            for i, intf in enumerate(request.getfixturevalue('tor_mux_intfs')):
                server_ipv4 = str(server_ipv4_base_addr + i)
                server_ipv6 = str(server_ipv6_base_addr + i)
                mux_cable_table[intf] = {}
                mux_cable_table[intf]['server_ipv4'] = six.text_type(server_ipv4)    # noqa F821
                mux_cable_table[intf]['server_ipv6'] = six.text_type(server_ipv6)    # noqa F821
        else:
            # For physical dualtor testbed
            mux_cable_table = duthost.get_running_config_facts()['MUX_CABLE']

        logger.info("Generating GARP service config file")

        for vlan_intf, config in list(mux_cable_table.items()):
            ptf_port_index = ptf_indices[vlan_intf]
            server_ip = ip_interface(config['server_ipv4']).ip
            server_ipv6 = ip_interface(config['server_ipv6']).ip

            garp_config[ptf_port_index] = {
                                            'dut_mac': '{}'.format(dut_mac),
                                            'dst_ipv6': '{}'.format(dst_ipv6),
                                            'target_ip': '{}'.format(server_ip),
                                            'target_ipv6': '{}'.format(server_ipv6)
                                        }

        ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, GARP_SERVICE_PY), dest=OPT_DIR)

        with open(os.path.join(TEMPLATES_DIR, GARP_SERVICE_CONF_TEMPL)) as f:
            template = Template(f.read())

        ptfhost.copy(content=json.dumps(garp_config, indent=4, sort_keys=True),
                     dest=os.path.join(TMP_DIR, 'garp_conf.json'))
        ptfhost.copy(content=template.render(garp_service_args='--interval 10'),
                     dest=os.path.join(SUPERVISOR_CONFIG_DIR, 'garp_service.conf'))
        logger.info("Starting GARP Service on PTF host")
        ptfhost.shell('supervisorctl update')
        ptfhost.shell('supervisorctl start garp_service')
    else:
        logger.info("Not running on a T0 testbed, not starting GARP service")

    yield

    if tbinfo['topo']['type'] == 't0':
        logger.info("Stopping GARP service on PTF host")
        ptfhost.shell('supervisorctl stop garp_service')


def ptf_test_port_map(ptfhost, tbinfo, duthosts, mux_server_url, duts_running_config_facts, duts_minigraph_facts):
    active_dut_map = {}
    if 'dualtor' in tbinfo['topo']['name']:
        res = requests.get(mux_server_url)
        pt_assert(res.status_code == 200, 'Failed to get mux status: {}'.format(res.text))
        for mux_status in list(res.json().values()):
            active_dut_index = 0 if mux_status['active_side'] == 'upper_tor' else 1
            active_dut_map[str(mux_status['port_index'])] = active_dut_index

    disabled_ptf_ports = set()
    for ptf_map in list(tbinfo['topo']['ptf_map_disabled'].values()):
        # Loop ptf_map of each DUT. Each ptf_map maps from ptf port index to dut port index
        disabled_ptf_ports = disabled_ptf_ports.union(set(ptf_map.keys()))

    router_macs = [duthost.facts['router_mac'] for duthost in duthosts]

    logger.info('active_dut_map={}'.format(active_dut_map))
    logger.info('disabled_ptf_ports={}'.format(disabled_ptf_ports))
    logger.info('router_macs={}'.format(router_macs))

    asic_idx = 0
    ports_map = {}
    for ptf_port, dut_intf_map in list(tbinfo['topo']['ptf_dut_intf_map'].items()):
        if str(ptf_port) in disabled_ptf_ports:
            # Skip PTF ports that are connected to disabled VLAN interfaces
            continue

        if len(list(dut_intf_map.keys())) == 2:
            # PTF port is mapped to two DUTs -> dualtor topology and the PTF port is a vlan port
            # Packet sent from this ptf port will only be accepted by the active side DUT
            # DualToR DUTs use same special Vlan interface MAC address
            target_dut_index = int(active_dut_map[ptf_port])
            ports_map[ptf_port] = {
                'target_dut': target_dut_index,
                'target_dest_mac': tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']['one_vlan_a']
                ['Vlan1000']['mac'],
                'target_src_mac': router_macs[target_dut_index],
                'asic_idx': asic_idx
            }
        else:
            # PTF port is mapped to single DUT
            target_dut_index = int(list(dut_intf_map.keys())[0])
            target_dut_port = int(list(dut_intf_map.values())[0])
            router_mac = router_macs[target_dut_index]
            dut_port = None
            if len(duts_minigraph_facts[duthosts[target_dut_index].hostname]) > 1:
                for list_idx, mg_facts_tuple in enumerate(duts_minigraph_facts[duthosts[target_dut_index].hostname]):
                    idx, mg_facts = mg_facts_tuple
                    for a_dut_port, a_dut_port_index in list(mg_facts['minigraph_port_indices'].items()):
                        if a_dut_port_index == target_dut_port and "Ethernet-Rec" not in a_dut_port and \
                           "Ethernet-IB" not in a_dut_port and "Ethernet-BP" not in a_dut_port:
                            dut_port = a_dut_port
                            router_mac = \
                                duts_running_config_facts[duthosts[target_dut_index].hostname][list_idx][1][
                                         'DEVICE_METADATA']['localhost']['mac'].lower()
                            asic_idx = idx
                            break
            ports_map[ptf_port] = {
                'target_dut': target_dut_index,
                'target_dest_mac': router_mac,
                'target_src_mac': router_mac,
                'dut_port': dut_port,
                'asic_idx': asic_idx
            }

    logger.debug('ptf_test_port_map={}'.format(json.dumps(ports_map, indent=2)))

    ptfhost.copy(content=json.dumps(ports_map), dest=PTF_TEST_PORT_MAP)
    return PTF_TEST_PORT_MAP


def ptf_test_port_map_active_active(ptfhost, tbinfo, duthosts, mux_server_url, duts_running_config_facts,
                                    duts_minigraph_facts, active_active_ports_mux_status=None):
    active_dut_map = {}
    if 'dualtor' in tbinfo['topo']['name']:
        res = requests.get(mux_server_url)
        pt_assert(res.status_code == 200, 'Failed to get mux status: {}'.format(res.text))
        for mux_status in list(res.json().values()):
            active_dut_index = 0 if mux_status['active_side'] == 'upper_tor' else 1
            active_dut_map[str(mux_status['port_index'])] = [active_dut_index]
        if active_active_ports_mux_status:
            for port_index, port_status in list(active_active_ports_mux_status.items()):
                active_dut_map[str(port_index)] = [active_dut_index for active_dut_index in (0, 1)
                                                   if port_status[active_dut_index]]

    disabled_ptf_ports = set()
    for ptf_map in list(tbinfo['topo']['ptf_map_disabled'].values()):
        # Loop ptf_map of each DUT. Each ptf_map maps from ptf port index to dut port index
        disabled_ptf_ports = disabled_ptf_ports.union(set(ptf_map.keys()))

    router_macs = [duthost.facts['router_mac'] for duthost in duthosts]

    logger.info('active_dut_map={}'.format(active_dut_map))
    logger.info('disabled_ptf_ports={}'.format(disabled_ptf_ports))
    logger.info('router_macs={}'.format(router_macs))

    asic_idx = 0
    ports_map = {}
    for ptf_port, dut_intf_map in list(tbinfo['topo']['ptf_dut_intf_map'].items()):
        if str(ptf_port) in disabled_ptf_ports:
            # Skip PTF ports that are connected to disabled VLAN interfaces
            continue

        if len(list(dut_intf_map.keys())) == 2:
            # PTF port is mapped to two DUTs -> dualtor topology and the PTF port is a vlan port
            # Packet sent from this ptf port will only be accepted by the active side DUT
            # DualToR DUTs use same special Vlan interface MAC address
            target_dut_indexes = list(map(int, active_dut_map[ptf_port]))
            ports_map[ptf_port] = {
                'target_dut': target_dut_indexes,
                'target_dest_mac': tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']['one_vlan_a']
                ['Vlan1000']['mac'],
                'target_src_mac': [router_macs[_] for _ in target_dut_indexes],
                'asic_idx': asic_idx
            }
        else:
            # PTF port is mapped to single DUT
            target_dut_index = int(list(dut_intf_map.keys())[0])
            target_dut_port = int(list(dut_intf_map.values())[0])
            router_mac = router_macs[target_dut_index]
            dut_port = None
            if len(duts_minigraph_facts[duthosts[target_dut_index].hostname]) > 1:
                for list_idx, mg_facts_tuple in enumerate(duts_minigraph_facts[duthosts[target_dut_index].hostname]):
                    idx, mg_facts = mg_facts_tuple
                    for a_dut_port, a_dut_port_index in list(mg_facts['minigraph_port_indices'].items()):
                        if a_dut_port_index == target_dut_port and "Ethernet-Rec" not in a_dut_port and \
                           "Ethernet-IB" not in a_dut_port and "Ethernet-BP" not in a_dut_port:
                            dut_port = a_dut_port
                            router_mac = \
                                duts_running_config_facts[duthosts[target_dut_index].hostname][list_idx][1][
                                         'DEVICE_METADATA']['localhost']['mac'].lower()
                            asic_idx = idx
                            break
            ports_map[ptf_port] = {
                'target_dut': [target_dut_index],
                'target_dest_mac': router_mac,
                'target_src_mac': [router_mac],
                'dut_port': dut_port,
                'asic_idx': asic_idx
            }

    logger.debug('ptf_test_port_map={}'.format(json.dumps(ports_map, indent=2)))

    ptfhost.copy(content=json.dumps(ports_map), dest=PTF_TEST_PORT_MAP)
    return PTF_TEST_PORT_MAP
