import os
import glob
import json
import logging
import getpass
import random
import re

import pytest
import yaml
import jinja2
import copy

from datetime import datetime
from ipaddress import ip_interface, IPv4Interface
from tests.common.fixtures.conn_graph_facts import conn_graph_facts     # noqa F401
from tests.common.devices.local import Localhost
from tests.common.devices.ptf import PTFHost
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.devices.fanout import FanoutHost
from tests.common.devices.k8s import K8sMasterHost
from tests.common.devices.k8s import K8sMasterCluster
from tests.common.devices.duthosts import DutHosts
from tests.common.devices.vmhost import VMHost
from tests.common.devices.base import NeighborDevice
from tests.common.devices.cisco import CiscoHost
from tests.common.helpers.parallel import parallel_run
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db_session    # noqa F401
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file                        # noqa F401
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map_active_active         # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder_session              # noqa F401

from tests.common.helpers.constants import (
    ASIC_PARAM_TYPE_ALL, ASIC_PARAM_TYPE_FRONTEND, DEFAULT_ASIC_ID, ASICS_PRESENT
)
from tests.common.helpers.dut_ports import encode_dut_port_name
from tests.common.helpers.dut_utils import encode_dut_and_container_name
from tests.common.system_utils import docker
from tests.common.testbed import TestbedInfo
from tests.common.utilities import get_inventory_files
from tests.common.utilities import get_host_vars
from tests.common.utilities import get_host_visible_vars
from tests.common.utilities import get_test_server_host
from tests.common.utilities import str2bool
from tests.common.utilities import safe_filename
from tests.common.helpers.dut_utils import is_supervisor_node, is_frontend_node
from tests.common.cache import FactsCache
from tests.common.config_reload import config_reload
from tests.common.connections.console_host import ConsoleHost

try:
    from tests.macsec import MacsecPlugin
except ImportError as e:
    logging.error(e)

from tests.platform_tests.args.advanced_reboot_args import add_advanced_reboot_args
from tests.platform_tests.args.cont_warm_reboot_args import add_cont_warm_reboot_args
from tests.platform_tests.args.normal_reboot_args import add_normal_reboot_args
from ptf import testutils
from ptf.mask import Mask

logger = logging.getLogger(__name__)
cache = FactsCache()

pytest_plugins = ('tests.common.plugins.ptfadapter',
                  'tests.common.plugins.ansible_fixtures',
                  'tests.common.plugins.dut_monitor',
                  'tests.common.plugins.loganalyzer',
                  'tests.common.plugins.pdu_controller',
                  'tests.common.plugins.sanity_check',
                  'tests.common.plugins.custom_markers',
                  'tests.common.plugins.test_completeness',
                  'tests.common.plugins.log_section_start',
                  'tests.common.plugins.custom_fixtures',
                  'tests.common.dualtor',
                  'tests.decap',
                  'tests.platform_tests.api',
                  'tests.common.plugins.allure_server',
                  'tests.common.plugins.conditional_mark')


def pytest_addoption(parser):
    parser.addoption("--testbed", action="store", default=None, help="testbed name")
    parser.addoption("--testbed_file", action="store", default=None, help="testbed file name")

    # test_vrf options
    parser.addoption("--vrf_capacity", action="store", default=None, type=int, help="vrf capacity of dut (4-1000)")
    parser.addoption("--vrf_test_count", action="store", default=None, type=int,
                     help="number of vrf to be tested (1-997)")

    # qos_sai options
    parser.addoption("--ptf_portmap", action="store", default=None, type=str,
                     help="PTF port index to DUT port alias map")
    parser.addoption("--qos_swap_syncd", action="store", type=str2bool, default=True,
                     help="Swap syncd container with syncd-rpc container")

    # Kubernetes master options
    parser.addoption("--kube_master", action="store", default=None, type=str,
                     help="Name of k8s master group used in k8s inventory, format: k8s_vms{msetnumber}_{servernumber}")

    # neighbor device type
    parser.addoption("--neighbor_type", action="store", default="eos", type=str, choices=["eos", "sonic", "cisco"],
                     help="Neighbor devices type")

    # FWUtil options
    parser.addoption('--fw-pkg', action='store', help='Firmware package file')

    ############################
    # pfc_asym options         #
    ############################
    parser.addoption("--server_ports_num", action="store", default=20, type=int, help="Number of server ports to use")
    parser.addoption("--fanout_inventory", action="store", default="lab", help="Inventory with defined fanout hosts")

    ############################
    # test_techsupport options #
    ############################
    parser.addoption("--loop_num", action="store", default=2, type=int,
                     help="Change default loop range for show techsupport command")
    parser.addoption("--loop_delay", action="store", default=2, type=int,
                     help="Change default loops delay")
    parser.addoption("--logs_since", action="store", type=int,
                     help="number of minutes for show techsupport command")
    parser.addoption("--collect_techsupport", action="store", default=True, type=str2bool,
                     help="Enable/Disable tech support collection. Default is enabled (True)")

    ############################
    #   sanity_check options   #
    ############################
    parser.addoption("--skip_sanity", action="store_true", default=False,
                     help="Skip sanity check")
    parser.addoption("--allow_recover", action="store_true", default=False,
                     help="Allow recovery attempt in sanity check in case of failure")
    parser.addoption("--check_items", action="store", default=False,
                     help="Change (add|remove) check items in the check list")
    parser.addoption("--post_check", action="store_true", default=False,
                     help="Perform post test sanity check if sanity check is enabled")
    parser.addoption("--post_check_items", action="store", default=False,
                     help="Change (add|remove) post test check items based on pre test check items")
    parser.addoption("--recover_method", action="store", default="adaptive",
                     help="Set method to use for recover if sanity failed")

    ########################
    #   pre-test options   #
    ########################
    parser.addoption("--deep_clean", action="store_true", default=False,
                     help="Deep clean DUT before tests (remove old logs, cores, dumps)")
    parser.addoption("--py_saithrift_url", action="store", default=None, type=str,
                     help="Specify the url of the saithrift package to be installed on the ptf "
                          "(should be http://<serverip>/path/python-saithrift_0.9.4_amd64.deb")

    ############################
    #  keysight ixanvl options #
    ############################
    parser.addoption("--testnum", action="store", default=None, type=str)

    ##################################
    # advance-reboot,upgrade options #
    ##################################
    add_advanced_reboot_args(parser)
    add_cont_warm_reboot_args(parser)
    add_normal_reboot_args(parser)

    ############################
    #   loop_times options     #
    ############################
    parser.addoption("--loop_times", metavar="LOOP_TIMES", action="store", default=1, type=int,
                     help="Define the loop times of the test")
    ############################
    #   collect logs option    #
    ############################
    parser.addoption("--collect_db_data", action="store_true", default=False, help="Collect db info if test failed")

    ############################
    #   macsec options         #
    ############################
    parser.addoption("--enable_macsec", action="store_true", default=False,
                     help="Enable macsec on some links of testbed")
    parser.addoption("--macsec_profile", action="store", default="all",
                     type=str, help="profile name list in macsec/profile.json")

    ############################
    #   QoS options         #
    ############################
    parser.addoption("--public_docker_registry", action="store_true", default=False,
                     help="To use public docker registry for syncd swap, by default is disabled (False)")


def pytest_configure(config):
    if config.getoption("enable_macsec"):
        config.pluginmanager.register(MacsecPlugin())


@pytest.fixture(scope="session", autouse=True)
def enhance_inventory(request):
    """
    This fixture is to enhance the capability of parsing the value of pytest cli argument '--inventory'.
    The pytest-ansible plugin always assumes that the value of cli argument '--inventory' is a single
    inventory file. With this enhancement, we can pass in multiple inventory files using the cli argument
    '--inventory'. The multiple inventory files can be separated by comma ','.

    For example:
        pytest --inventory "inventory1, inventory2" <other arguments>
        pytest --inventory inventory1,inventory2 <other arguments>

    This fixture is automatically applied, you don't need to declare it in your test script.
    """
    inv_opt = request.config.getoption("ansible_inventory")
    if isinstance(inv_opt, list):
        return
    inv_files = [inv_file.strip() for inv_file in inv_opt.split(",")]
    try:
        setattr(request.config.option, "ansible_inventory", inv_files)
    except AttributeError:
        logger.error("Failed to set enhanced 'ansible_inventory' to request.config.option")


def pytest_cmdline_main(config):

    # Filter out unnecessary pytest_ansible plugin log messages
    pytest_ansible_logger = logging.getLogger("pytest_ansible")
    if pytest_ansible_logger:
        pytest_ansible_logger.setLevel(logging.WARNING)

    # Filter out unnecessary ansible log messages (ansible v2.8)
    # The logger name of ansible v2.8 is nasty
    mypid = str(os.getpid())
    user = getpass.getuser()
    ansible_loggerv28 = logging.getLogger("p=%s u=%s | " % (mypid, user))
    if ansible_loggerv28:
        ansible_loggerv28.setLevel(logging.WARNING)

    # Filter out unnecessary ansible log messages (latest ansible)
    ansible_logger = logging.getLogger("ansible")
    if ansible_logger:
        ansible_logger.setLevel(logging.WARNING)

    # Filter out unnecessary logs generated by calling the ptfadapter plugin
    dataplane_logger = logging.getLogger("dataplane")
    if dataplane_logger:
        dataplane_logger.setLevel(logging.ERROR)


def pytest_collection(session):
    """Workaround to reduce messy plugin logs generated during collection only

    Args:
        session (ojb): Pytest session object
    """
    if session.config.option.collectonly:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.WARNING)


def get_tbinfo(request):
    """
    Helper function to create and return testbed information
    """
    tbname = request.config.getoption("--testbed")
    tbfile = request.config.getoption("--testbed_file")
    if tbname is None or tbfile is None:
        raise ValueError("testbed and testbed_file are required!")

    testbedinfo = cache.read(tbname, 'tbinfo')
    if testbedinfo is cache.NOTEXIST:
        testbedinfo = TestbedInfo(tbfile)
        cache.write(tbname, 'tbinfo', testbedinfo)

    return tbname, testbedinfo.testbed_topo.get(tbname, {})


@pytest.fixture(scope="session")
def tbinfo(request):
    """
    Create and return testbed information
    """
    _, testbedinfo = get_tbinfo(request)
    return testbedinfo


def get_specified_duts(request):
    """
    Get a list of DUT hostnames specified with the --host-pattern CLI option
    or -d if using `run_tests.sh`
    """
    tbname, tbinfo = get_tbinfo(request)
    testbed_duts = tbinfo['duts']

    host_pattern = request.config.getoption("--host-pattern")
    if host_pattern == 'all':
        return testbed_duts

    if ';' in host_pattern:
        specified_duts = host_pattern.replace('[', '').replace(']', '').split(';')
    else:
        specified_duts = host_pattern.split(',')

    if any([dut not in testbed_duts for dut in specified_duts]):
        pytest.fail("One of the specified DUTs {} does not belong to the testbed {}".format(specified_duts, tbname))

    if len(testbed_duts) != specified_duts:
        duts = specified_duts
        logger.debug("Different DUTs specified than in testbed file, using {}"
                     .format(str(duts)))

    return duts


@pytest.fixture(name="duthosts", scope="session")
def fixture_duthosts(enhance_inventory, ansible_adhoc, tbinfo, request):
    """
    @summary: fixture to get DUT hosts defined in testbed.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package.
        Source of the various device objects. It is
        mandatory argument for the class constructors.
    @param tbinfo: fixture provides information about testbed.
    """
    return DutHosts(ansible_adhoc, tbinfo, get_specified_duts(request))


@pytest.fixture(scope="session")
def duthost(duthosts, request):
    '''
    @summary: Shortcut fixture for getting DUT host. For a lengthy test case, test case module can
              pass a request to disable sh time out mechanis on dut in order to avoid ssh timeout.
              After test case completes, the fixture will restore ssh timeout.
    @param duthosts: fixture to get DUT hosts
    @param request: request parameters for duthost test fixture
    '''
    dut_index = getattr(request.session, "dut_index", 0)
    assert dut_index < len(duthosts), \
        "DUT index '{0}' is out of bound '{1}'".format(dut_index,
                                                       len(duthosts))

    duthost = duthosts[dut_index]

    return duthost


@pytest.fixture(scope="session")
def mg_facts(duthost):
    return duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']


@pytest.fixture(scope="module")
def rand_one_dut_hostname(request):
    """
    """
    dut_hostnames = generate_params_dut_hostname(request)
    if len(dut_hostnames) > 1:
        dut_hostnames = random.sample(dut_hostnames, 1)
    logger.info("Randomly select dut {} for testing".format(dut_hostnames[0]))
    return dut_hostnames[0]


@pytest.fixture(scope="module")
def rand_selected_dut(duthosts, rand_one_dut_hostname):
    """
    Return the randomly selected duthost
    """
    return duthosts[rand_one_dut_hostname]


@pytest.fixture(scope="module")
def rand_one_dut_front_end_hostname(request):
    """
    """
    dut_hostnames = generate_params_frontend_hostname(request)
    if len(dut_hostnames) > 1:
        dut_hostnames = random.sample(dut_hostnames, 1)
    logger.info("Randomly select dut {} for testing".format(dut_hostnames[0]))
    return dut_hostnames[0]


@pytest.fixture(scope="module")
def rand_selected_front_end_dut(duthosts, rand_one_dut_front_end_hostname):
    """
    Return the randomly selected duthost
    """
    return duthosts[rand_one_dut_front_end_hostname]


@pytest.fixture(scope="module")
def rand_unselected_dut(request, duthosts, rand_one_dut_hostname):
    """
    Return the left duthost after random selection.
    Return None for non dualtor testbed
    """
    dut_hostnames = generate_params_dut_hostname(request)
    if len(dut_hostnames) <= 1:
        return None
    idx = dut_hostnames.index(rand_one_dut_hostname)
    return duthosts[dut_hostnames[1 - idx]]


@pytest.fixture(scope="module")
def selected_rand_one_per_hwsku_hostname(request):
    """
    Return the selected hostnames for the given module.
    This fixture will return the list of selected dut hostnames
    when another fixture like enum_rand_one_per_hwsku_hostname
    or enum_rand_one_per_hwsku_frontend_hostname is used.
    """
    if request.module in _hosts_per_hwsku_per_module:
        return _hosts_per_hwsku_per_module[request.module]
    else:
        return []


@pytest.fixture(scope="module")
def rand_one_dut_portname_oper_up(request):
    oper_up_ports = generate_port_lists(request, "oper_up_ports")
    if len(oper_up_ports) > 1:
        oper_up_ports = random.sample(oper_up_ports, 1)
    return oper_up_ports[0]


@pytest.fixture(scope="module")
def rand_one_dut_lossless_prio(request):
    lossless_prio_list = generate_priority_lists(request, 'lossless')
    if len(lossless_prio_list) > 1:
        lossless_prio_list = random.sample(lossless_prio_list, 1)
    return lossless_prio_list[0]


@pytest.fixture(scope="module", autouse=True)
def reset_critical_services_list(duthosts):
    """
    Resets the critical services list between test modules to ensure that it is
    left in a known state after tests finish running.
    """
    [a_dut.critical_services_tracking_list() for a_dut in duthosts]


@pytest.fixture(scope="session")
def localhost(ansible_adhoc):
    return Localhost(ansible_adhoc)


@pytest.fixture(scope="session")
def ptfhost(enhance_inventory, ansible_adhoc, tbinfo, duthost, request):
    if "ptf_image_name" in tbinfo and "docker-keysight-api-server" in tbinfo["ptf_image_name"]:
        return None
    if "ptf" in tbinfo:
        return PTFHost(ansible_adhoc, tbinfo["ptf"], duthost, tbinfo,
                       macsec_enabled=request.config.option.enable_macsec)
    else:
        # when no ptf defined in testbed.csv
        # try to parse it from inventory
        ptf_host = duthost.host.options["inventory_manager"].get_host(duthost.hostname).get_vars()["ptf_host"]
        return PTFHost(ansible_adhoc, ptf_host, duthost, tbinfo, macsec_enabled=request.config.option.enable_macsec)


@pytest.fixture(scope="module")
def k8smasters(enhance_inventory, ansible_adhoc, request):
    """
    Shortcut fixture for getting Kubernetes master hosts
    """
    k8s_master_ansible_group = request.config.getoption("--kube_master")
    master_vms = {}
    inv_files = request.config.getoption("ansible_inventory")
    k8s_inv_file = None
    for inv_file in inv_files:
        if "k8s" in inv_file:
            k8s_inv_file = inv_file
    if not k8s_inv_file:
        pytest.skip("k8s inventory not found, skipping tests")
    with open('../ansible/{}'.format(k8s_inv_file), 'r') as kinv:
        k8sinventory = yaml.safe_load(kinv)
        for hostname, attributes in list(k8sinventory[k8s_master_ansible_group]['hosts'].items()):
            if 'haproxy' in attributes:
                is_haproxy = True
            else:
                is_haproxy = False
            master_vms[hostname] = {'host': K8sMasterHost(ansible_adhoc,
                                                          hostname,
                                                          is_haproxy)}
    return master_vms


@pytest.fixture(scope="module")
def k8scluster(k8smasters):
    k8s_master_cluster = K8sMasterCluster(k8smasters)
    return k8s_master_cluster


@pytest.fixture(scope="session")
def nbrhosts(enhance_inventory, ansible_adhoc, tbinfo, creds, request):
    """
    Shortcut fixture for getting VM host
    """

    devices = {}
    if (not tbinfo['vm_base'] and 'tgen' in tbinfo['topo']['name']) or 'ptf' in tbinfo['topo']['name']:
        logger.info("No VMs exist for this topology: {}".format(tbinfo['topo']['name']))
        return devices

    vm_base = int(tbinfo['vm_base'][2:])
    vm_name_fmt = 'VM%0{}d'.format(len(tbinfo['vm_base']) - 2)
    neighbor_type = request.config.getoption("--neighbor_type")

    if 'VMs' not in tbinfo['topo']['properties']['topology']:
        logger.info("No VMs exist for this topology: {}".format(tbinfo['topo']['properties']['topology']))
        return devices

    for k, v in list(tbinfo['topo']['properties']['topology']['VMs'].items()):
        vm_name = vm_name_fmt % (vm_base + v['vm_offset'])
        if neighbor_type == "eos":
            device = NeighborDevice(
                {
                    'host': EosHost(
                        ansible_adhoc,
                        vm_name,
                        creds['eos_login'],
                        creds['eos_password'],
                        shell_user=creds['eos_root_user'] if 'eos_root_user' in creds else None,
                        shell_passwd=creds['eos_root_password'] if 'eos_root_password' in creds else None
                    ),
                    'conf': tbinfo['topo']['properties']['configuration'][k]
                }
            )
        elif neighbor_type == "sonic":
            device = NeighborDevice(
                {
                    'host': SonicHost(
                        ansible_adhoc,
                        vm_name,
                        ssh_user=creds['sonic_login'] if 'sonic_login' in creds else None,
                        ssh_passwd=creds['sonic_password'] if 'sonic_password' in creds else None
                    ),
                    'conf': tbinfo['topo']['properties']['configuration'][k]
                }
            )
        elif neighbor_type == "cisco":
            device = NeighborDevice(
                {
                    'host': CiscoHost(
                        ansible_adhoc,
                        vm_name,
                        creds['cisco_login'],
                        creds['cisco_password'],
                    ),
                    'conf': tbinfo['topo']['properties']['configuration'][k]
                }
            )
        else:
            raise ValueError("Unknown neighbor type %s" % (neighbor_type, ))
        devices[k] = device
    return devices


@pytest.fixture(scope="module")
def fanouthosts(enhance_inventory, ansible_adhoc, conn_graph_facts, creds, duthosts):      # noqa F811
    """
    Shortcut fixture for getting Fanout hosts
    """

    dev_conn = conn_graph_facts.get('device_conn', {})
    fanout_hosts = {}
    # WA for virtual testbed which has no fanout
    for dut_host, value in list(dev_conn.items()):
        duthost = duthosts[dut_host]
        if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
            continue  # skip for kvm platform which has no fanout
        mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        for dut_port in list(value.keys()):
            fanout_rec = value[dut_port]
            fanout_host = str(fanout_rec['peerdevice'])
            fanout_port = str(fanout_rec['peerport'])

            if fanout_host in list(fanout_hosts.keys()):
                fanout = fanout_hosts[fanout_host]
            else:
                host_vars = ansible_adhoc().options[
                    'inventory_manager'].get_host(fanout_host).vars
                os_type = host_vars.get('os', 'eos')
                if 'fanout_tacacs_user' in creds:
                    fanout_user = creds['fanout_tacacs_user']
                    fanout_password = creds['fanout_tacacs_password']
                elif 'fanout_tacacs_{}_user'.format(os_type) in creds:
                    fanout_user = creds['fanout_tacacs_{}_user'.format(os_type)]
                    fanout_password = creds['fanout_tacacs_{}_password'.format(os_type)]
                elif os_type == 'sonic':
                    fanout_user = creds.get('fanout_sonic_user', None)
                    fanout_password = creds.get('fanout_sonic_password', None)
                elif os_type == 'eos':
                    fanout_user = creds.get('fanout_network_user', None)
                    fanout_password = creds.get('fanout_network_password', None)
                elif os_type == 'snappi':
                    fanout_user = creds.get('fanout_network_user', None)
                    fanout_password = creds.get('fanout_network_password', None)
                else:
                    # when os is mellanox, not supported
                    pytest.fail("os other than sonic and eos not supported")

                eos_shell_user = None
                eos_shell_password = None
                if os_type == "eos":
                    admin_user = creds['fanout_admin_user']
                    admin_password = creds['fanout_admin_password']
                    eos_shell_user = creds.get('fanout_shell_user', admin_user)
                    eos_shell_password = creds.get('fanout_shell_password', admin_password)

                fanout = FanoutHost(ansible_adhoc,
                                    os_type,
                                    fanout_host,
                                    'FanoutLeaf',
                                    fanout_user,
                                    fanout_password,
                                    eos_shell_user=eos_shell_user,
                                    eos_shell_passwd=eos_shell_password)
                fanout.dut_hostnames = [dut_host]
                fanout_hosts[fanout_host] = fanout

                if fanout.os == 'sonic':
                    ifs_status = fanout.host.get_interfaces_status()
                    for key, interface_info in list(ifs_status.items()):
                        fanout.fanout_port_alias_to_name[interface_info['alias']] = interface_info['interface']
                    logging.info("fanout {} fanout_port_alias_to_name {}"
                                 .format(fanout_host, fanout.fanout_port_alias_to_name))

            fanout.add_port_map(encode_dut_port_name(dut_host, dut_port), fanout_port)

            # Add port name to fanout port mapping port if dut_port is alias.
            if dut_port in mg_facts['minigraph_port_alias_to_name_map']:
                mapped_port = mg_facts['minigraph_port_alias_to_name_map'][dut_port]
                # only add the mapped port which isn't in device_conn ports to avoid overwriting port map wrongly,
                # it happens when an interface has the same name with another alias, for example:
                # Interface     Alias
                # --------------------
                # Ethernet108   Ethernet32
                # Ethernet32    Ethernet13/1
                if mapped_port not in list(value.keys()):
                    fanout.add_port_map(encode_dut_port_name(dut_host, mapped_port), fanout_port)

            if dut_host not in fanout.dut_hostnames:
                fanout.dut_hostnames.append(dut_host)

    return fanout_hosts


@pytest.fixture(scope="session")
def vmhost(enhance_inventory, ansible_adhoc, request, tbinfo):
    server = tbinfo["server"]
    inv_files = get_inventory_files(request)
    vmhost = get_test_server_host(inv_files, server)
    return VMHost(ansible_adhoc, vmhost.name)


@pytest.fixture(scope='session')
def eos():
    """ read and yield eos configuration """
    with open('eos/eos.yml') as stream:
        eos = yaml.safe_load(stream)
        return eos


@pytest.fixture(scope='session')
def sonic():
    """ read and yield sonic configuration """
    with open('sonic/sonic.yml') as stream:
        eos = yaml.safe_load(stream)
        return eos


@pytest.fixture(scope='session')
def pdu():
    """ read and yield pdu configuration """
    with open('../ansible/group_vars/pdu/pdu.yml') as stream:
        pdu = yaml.safe_load(stream)
        return pdu


def creds_on_dut(duthost):
    """ read credential information according to the dut inventory """
    groups = duthost.host.options['inventory_manager'].get_host(duthost.hostname).get_vars()['group_names']
    groups.append("fanout")
    logger.info("dut {} belongs to groups {}".format(duthost.hostname, groups))
    exclude_regex_patterns = [
        r'topo_.*\.yml',
        r'breakout_speed\.yml',
        r'lag_fanout_ports_test_vars\.yml',
        r'qos\.yml',
        r'sku-sensors-data\.yml',
        r'mux_simulator_http_port_map\.yml'
        ]
    files = glob.glob("../ansible/group_vars/all/*.yml")
    files += glob.glob("../ansible/vars/*.yml")
    for group in groups:
        files += glob.glob("../ansible/group_vars/{}/*.yml".format(group))
    filtered_files = [
        f for f in files if not re.search('|'.join(exclude_regex_patterns), f)
    ]

    creds = {}
    for f in filtered_files:
        with open(f) as stream:
            v = yaml.safe_load(stream)
            if v is not None:
                creds.update(v)
            else:
                logging.info("skip empty var file {}".format(f))

    cred_vars = [
        "sonicadmin_user",
        "sonicadmin_password",
        "docker_registry_host",
        "docker_registry_username",
        "docker_registry_password",
        "public_docker_registry_host"
    ]
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    for cred_var in cred_vars:
        if cred_var in creds:
            creds[cred_var] = jinja2.Template(creds[cred_var]).render(**hostvars)
    # load creds for console
    if "console_login" not in list(hostvars.keys()):
        console_login_creds = {}
    else:
        console_login_creds = hostvars["console_login"]
    creds["console_user"] = {}
    creds["console_password"] = {}

    for k, v in list(console_login_creds.items()):
        creds["console_user"][k] = v["user"]
        creds["console_password"][k] = v["passwd"]

    return creds


@pytest.fixture(scope="session")
def creds(duthost):
    return creds_on_dut(duthost)


@pytest.fixture(scope='module')
def creds_all_duts(duthosts):
    creds_all_duts = dict()
    for duthost in duthosts.nodes:
        creds_all_duts[duthost.hostname] = creds_on_dut(duthost)
    return creds_all_duts


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):

    if call.when == 'setup':
        item.user_properties.append(('start', str(datetime.fromtimestamp(call.start))))
    elif call.when == 'teardown':
        item.user_properties.append(('end', str(datetime.fromtimestamp(call.stop))))

    # Filter out unnecessary logs captured on "stdout" and "stderr"
    item._report_sections = list([report for report in item._report_sections if report[1] not in ("stdout", "stderr")])

    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


def collect_techsupport_on_dut(request, a_dut):
    # request.node is an "item" because we use the default
    # "function" scope
    testname = request.node.name
    if request.config.getoption("--collect_techsupport") and request.node.rep_call.failed:
        res = a_dut.shell("generate_dump -s \"-2 hours\"")
        fname = res['stdout_lines'][-1]
        a_dut.fetch(src=fname, dest="logs/{}".format(testname))

        logging.info("########### Collected tech support for test {} ###########".format(testname))


@pytest.fixture
def collect_techsupport(request, duthosts, enum_dut_hostname):
    yield
    # request.node is an "item" because we use the default
    # "function" scope
    duthost = duthosts[enum_dut_hostname]
    collect_techsupport_on_dut(request, duthost)


@pytest.fixture
def collect_techsupport_all_duts(request, duthosts):
    yield
    [collect_techsupport_on_dut(request, a_dut) for a_dut in duthosts]


@pytest.fixture(scope="session", autouse=True)
def tag_test_report(request, pytestconfig, tbinfo, duthost, record_testsuite_property):
    if not request.config.getoption("--junit-xml"):
        return

    # Test run information
    record_testsuite_property("topology", tbinfo["topo"]["name"])
    record_testsuite_property("testbed", tbinfo["conf-name"])
    record_testsuite_property("timestamp", datetime.utcnow())

    # Device information
    record_testsuite_property("host", duthost.hostname)
    record_testsuite_property("asic", duthost.facts["asic_type"])
    record_testsuite_property("platform", duthost.facts["platform"])
    record_testsuite_property("hwsku", duthost.facts["hwsku"])
    record_testsuite_property("os_version", duthost.os_version)


@pytest.fixture(scope="module", autouse=True)
def clear_neigh_entries(duthosts, tbinfo):
    """
        This is a stop bleeding change for dualtor testbed. Because dualtor duts will
        learn the same set of arp entries during tests. But currently the test only
        cleans up on the dut under test. So the other dut will accumulate arp entries
        until kernel start to barf.
        Adding this fixture to flush out IPv4/IPv6 static ARP entries after each test
        moduel is done.
    """

    yield

    if 'dualtor' in tbinfo['topo']['name']:
        for dut in duthosts:
            dut.command("sudo ip neigh flush nud permanent")


@pytest.fixture(scope="module")
def patch_lldpctl():
    def patch_lldpctl(localhost, duthost):
        output = localhost.shell('ansible --version')
        if 'ansible 2.8.12' in output['stdout']:
            """
                Work around a known lldp module bug in ansible version 2.8.12:
                When neighbor sent more than one unknown tlv. Ansible will throw
                exception.
                This function applies the patch before test.
            """
            duthost.shell(
                'sudo sed -i -e \'s/lldp lldpctl "$@"$/lldp lldpctl "$@" | grep -v "unknown-tlvs"/\' /usr/bin/lldpctl'
            )

    return patch_lldpctl


@pytest.fixture(scope="module")
def unpatch_lldpctl():
    def unpatch_lldpctl(localhost, duthost):
        output = localhost.shell('ansible --version')
        if 'ansible 2.8.12' in output['stdout']:
            """
                Work around a known lldp module bug in ansible version 2.8.12:
                When neighbor sent more than one unknown tlv. Ansible will throw
                exception.
                This function removes the patch after the test is done.
            """
            duthost.shell(
                'sudo sed -i -e \'s/lldp lldpctl "$@"$/lldp lldpctl "$@" | grep -v "unknown-tlvs"/\' /usr/bin/lldpctl'
            )

    return unpatch_lldpctl


@pytest.fixture(scope="module")
def disable_container_autorestart():
    def disable_container_autorestart(duthost, testcase="", feature_list=None):
        '''
        @summary: Disable autorestart of the features present in feature_list.

        @param duthosts: Instance of DutHost
        @param testcase: testcase name used to save pretest autorestart state. Later to be used for restoration.
        @feature_list: List of features to disable autorestart. If None, autorestart of all the features will be
                       disabled.
        '''
        command_output = duthost.shell("show feature autorestart", module_ignore_errors=True)
        if command_output['rc'] != 0:
            logging.info("Feature autorestart utility not supported. Error: {}".format(command_output['stderr']))
            logging.info("Skipping disable_container_autorestart")
            return
        container_autorestart_states = duthost.get_container_autorestart_states()
        state_file_name = "/tmp/autorestart_state_{}_{}.json".format(duthost.hostname, testcase)
        # Dump autorestart state to file
        with open(state_file_name, "w") as f:
            json.dump(container_autorestart_states, f)
        # Disable autorestart for all containers
        logging.info("Disable container autorestart")
        cmd_disable = "config feature autorestart {} disabled"
        cmds_disable = []
        for name, state in list(container_autorestart_states.items()):
            if state == "enabled" and (feature_list is None or name in feature_list):
                cmds_disable.append(cmd_disable.format(name))
        # Write into config_db
        cmds_disable.append("config save -y")
        duthost.shell_cmds(cmds=cmds_disable)

    return disable_container_autorestart


@pytest.fixture(scope="module")
def enable_container_autorestart():
    def enable_container_autorestart(duthost, testcase="", feature_list=None):
        '''
        @summary: Enable autorestart of the features present in feature_list.

        @param duthosts: Instance of DutHost
        @param testcase: testcase name used to find corresponding file to restore autorestart state.
        @feature_list: List of features to enable autorestart. If None, autorestart of all the features will
                       be disabled.
        '''
        state_file_name = "/tmp/autorestart_state_{}_{}.json".format(duthost.hostname, testcase)
        if not os.path.exists(state_file_name):
            return
        stored_autorestart_states = {}
        with open(state_file_name, "r") as f:
            stored_autorestart_states = json.load(f)
        container_autorestart_states = duthost.get_container_autorestart_states()
        # Recover autorestart states
        logging.info("Recover container autorestart")
        cmd_enable = "config feature autorestart {} enabled"
        cmds_enable = []
        for name, state in list(container_autorestart_states.items()):
            if state == "disabled" and (feature_list is None or name in feature_list) \
                    and name in stored_autorestart_states \
                    and stored_autorestart_states[name] == "enabled":
                cmds_enable.append(cmd_enable.format(name))
        # Write into config_db
        cmds_enable.append("config save -y")
        duthost.shell_cmds(cmds=cmds_enable)
        os.remove(state_file_name)

    return enable_container_autorestart


@pytest.fixture(scope='module')
def swapSyncd(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname, creds, tbinfo, lower_tor_host):
    """
        Swap syncd on DUT host

        Args:
            request (Fixture): pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)

        Returns:
            None
    """
    if 'dualtor' in tbinfo['topo']['name']:
        duthost = lower_tor_host
    else:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    swapSyncd = request.config.getoption("--qos_swap_syncd")
    public_docker_reg = request.config.getoption("--public_docker_registry")
    try:
        if swapSyncd:
            if public_docker_reg:
                new_creds = copy.deepcopy(creds)
                new_creds['docker_registry_host'] = new_creds['public_docker_registry_host']
                new_creds['docker_registry_username'] = ''
                new_creds['docker_registry_password'] = ''
            else:
                new_creds = creds
            docker.swap_syncd(duthost, new_creds)

        yield
    finally:
        if swapSyncd:
            docker.restore_default_syncd(duthost, new_creds)


def get_host_data(request, dut):
    '''
    This function parses multple inventory files and returns the dut information present in the inventory
    '''
    inv_files = get_inventory_files(request)
    return get_host_vars(inv_files, dut)


def generate_params_frontend_hostname(request):
    frontend_duts = []
    tbname, _ = get_tbinfo(request)
    duts = get_specified_duts(request)
    inv_files = get_inventory_files(request)
    for dut in duts:
        if is_frontend_node(inv_files, dut):
            frontend_duts.append(dut)
    assert len(frontend_duts) > 0, \
        "Test selected require at-least one frontend node, " \
        "none of the DUTs '{}' in testbed '{}' are a supervisor node".format(duts, tbname)
    return frontend_duts


def generate_params_hostname_rand_per_hwsku(request, frontend_only=False):
    hosts = get_specified_duts(request)
    if frontend_only:
        hosts = generate_params_frontend_hostname(request)
    inv_files = get_inventory_files(request)
    # Create a list of hosts per hwsku
    host_hwskus = {}
    for a_host in hosts:
        host_vars = get_host_visible_vars(inv_files, a_host)
        a_host_hwsku = None
        if 'hwsku' in host_vars:
            a_host_hwsku = host_vars['hwsku']
        else:
            # Lets try 'sonic_hwsku' as well
            if 'sonic_hwsku' in host_vars:
                a_host_hwsku = host_vars['sonic_hwsku']
        if a_host_hwsku:
            if a_host_hwsku not in host_hwskus:
                host_hwskus[a_host_hwsku] = [a_host]
            else:
                host_hwskus[a_host_hwsku].append(a_host)
        else:
            pytest.fail("Test selected require a node per hwsku, but 'hwsku' for '{}' not defined in the inventory"
                        .format(a_host))

    hosts_per_hwsku = []
    for hosts in list(host_hwskus.values()):
        if len(hosts) == 1:
            hosts_per_hwsku.append(hosts[0])
        else:
            hosts_per_hwsku.extend(random.sample(hosts, 1))

    return hosts_per_hwsku


def generate_params_supervisor_hostname(request):
    duts = get_specified_duts(request)
    if len(duts) == 1:
        # We have a single node - dealing with pizza box, return it
        return [duts[0]]
    inv_files = get_inventory_files(request)
    for dut in duts:
        # Expecting only a single supervisor node
        if is_supervisor_node(inv_files, dut):
            return [dut]
    # If there are no supervisor cards in a multi-dut tesbed, we are dealing with all pizza box in the testbed,
    # pick the first DUT
    return [duts[0]]


def generate_param_asic_index(request, dut_hostnames, param_type, random_asic=False):
    _, tbinfo = get_tbinfo(request)
    inv_files = get_inventory_files(request)
    logging.info("generating {} asic indicies for  DUT [{}] in ".format(param_type, dut_hostnames))

    asic_index_params = []
    for dut in dut_hostnames:
        inv_data = get_host_visible_vars(inv_files, dut)
        # if the params are not present treat the device as a single asic device
        dut_asic_params = [DEFAULT_ASIC_ID]
        if inv_data:
            if param_type == ASIC_PARAM_TYPE_ALL and ASIC_PARAM_TYPE_ALL in inv_data:
                if int(inv_data[ASIC_PARAM_TYPE_ALL]) == 1:
                    dut_asic_params = [DEFAULT_ASIC_ID]
                else:
                    if ASICS_PRESENT in inv_data:
                        dut_asic_params = inv_data[ASICS_PRESENT]
                    else:
                        dut_asic_params = list(range(int(inv_data[ASIC_PARAM_TYPE_ALL])))
            elif param_type == ASIC_PARAM_TYPE_FRONTEND and ASIC_PARAM_TYPE_FRONTEND in inv_data:
                dut_asic_params = inv_data[ASIC_PARAM_TYPE_FRONTEND]
            logging.info("dut name {}  asics params = {}".format(dut, dut_asic_params))

        if random_asic:
            asic_index_params.append(random.sample(dut_asic_params, 1))
        else:
            asic_index_params.append(dut_asic_params)
    return asic_index_params


def generate_params_dut_index(request):
    tbname, _ = get_tbinfo(request)
    num_duts = len(get_specified_duts(request))
    logging.info("Using {} duts from testbed '{}'".format(num_duts, tbname))

    return list(range(num_duts))


def generate_params_dut_hostname(request):
    tbname, _ = get_tbinfo(request)
    duts = get_specified_duts(request)
    logging.info("Using DUTs {} in testbed '{}'".format(str(duts), tbname))

    return duts


def get_completeness_level_metadata(request):
    completeness_level = request.config.getoption("--completeness_level")
    # if completeness_level is not set or an unknown completeness_level is set
    # return "thorough" to run all test set
    if not completeness_level or completeness_level not in ["debug", "basic", "confident", "thorough"]:
        return "thorough"
    return completeness_level


def get_testbed_metadata(request):
    """
    Get the metadata for the testbed name. Return None if tbname is
    not provided, or metadata file not found or metadata does not
    contain tbname
    """
    tbname = request.config.getoption("--testbed")
    if not tbname:
        return None

    folder = 'metadata'
    filepath = os.path.join(folder, tbname + '.json')
    metadata = None

    try:
        with open(filepath, 'r') as yf:
            metadata = json.load(yf)
    except IOError:
        return None

    return metadata.get(tbname)


def generate_port_lists(request, port_scope, with_completeness_level=False):
    empty = [encode_dut_port_name('unknown', 'unknown')]
    if 'ports' in port_scope:
        scope = 'Ethernet'
    elif 'pcs' in port_scope:
        scope = 'PortChannel'
    else:
        return empty

    if 'all' in port_scope:
        state = None
    elif 'oper_up' in port_scope:
        state = 'oper_state'
    elif 'admin_up' in port_scope:
        state = 'admin_state'
    else:
        return empty

    dut_ports = get_testbed_metadata(request)

    if dut_ports is None:
        return empty

    dut_port_map = {}
    for dut, val in list(dut_ports.items()):
        dut_port_pairs = []
        if 'intf_status' not in val:
            continue
        for intf, status in list(val['intf_status'].items()):
            if scope in intf and (not state or status[state] == 'up'):
                dut_port_pairs.append(encode_dut_port_name(dut, intf))
        dut_port_map[dut] = dut_port_pairs
    logger.info("Generate dut_port_map: {}".format(dut_port_map))

    if with_completeness_level:
        completeness_level = get_completeness_level_metadata(request)
        # if completeness_level in ["debug", "basic", "confident"],
        # only select several ports on every DUT to save test time

        def trim_dut_port_lists(dut_port_list, target_len):
            if len(dut_port_list) <= target_len:
                return dut_port_list
            # for diversity, fetch the ports from both the start and the end of the original list
            pos_1 = target_len // 2
            pos_2 = target_len - pos_1
            return dut_ports[:pos_1] + dut_ports[-pos_2:]

        if completeness_level in ["debug"]:
            for dut, dut_ports in list(dut_port_map.items()):
                dut_port_map[dut] = trim_dut_port_lists(dut_ports, 1)
        elif completeness_level in ["basic", "confident"]:
            for dut, dut_ports in list(dut_port_map.items()):
                dut_port_map[dut] = trim_dut_port_lists(dut_ports, 4)

    ret = sum(list(dut_port_map.values()), [])
    logger.info("Generate port_list: {}".format(ret))
    return ret if ret else empty


def generate_dut_feature_container_list(request):
    """
    Generate list of containers given the list of features.
    List of features and container names are both obtained from
    metadata file
    """
    empty = [encode_dut_and_container_name("unknown", "unknown")]

    meta = get_testbed_metadata(request)

    if meta is None:
        return empty

    container_list = []

    for dut, val in list(meta.items()):
        if "features" not in val:
            continue
        for feature in list(val["features"].keys()):
            if "disabled" in val["features"][feature]:
                continue

            dut_info = meta[dut]

            if "asic_services" in dut_info and dut_info["asic_services"].get(feature) is not None:
                for service in dut_info["asic_services"].get(feature):
                    container_list.append(encode_dut_and_container_name(dut, service))
            else:
                container_list.append(encode_dut_and_container_name(dut, feature))

    return container_list


def generate_dut_feature_list(request, duts_selected, asics_selected):
    """
    Generate a list of features.
    The list of features willl be obtained from
    metadata file.
    This list will be features that can be stopped
    or restarted.
    """
    meta = get_testbed_metadata(request)
    tuple_list = []

    if meta is None:
        return tuple_list

    skip_feature_list = ['database', 'database-chassis', 'gbsyncd']

    for a_dut_index, a_dut in enumerate(duts_selected):
        if len(asics_selected):
            for a_asic in asics_selected[a_dut_index]:
                # Create tuple of dut and asic index
                if "features" in meta[a_dut]:
                    for a_feature in list(meta[a_dut]["features"].keys()):
                        if a_feature not in skip_feature_list:
                            tuple_list.append((a_dut, a_asic, a_feature))
                else:
                    tuple_list.append((a_dut, a_asic, None))
        else:
            if "features" in meta[a_dut]:
                for a_feature in list(meta[a_dut]["features"].keys()):
                    if a_feature not in skip_feature_list:
                        tuple_list.append((a_dut, None, a_feature))
            else:
                tuple_list.append((a_dut, None, None))
    return tuple_list


def generate_dut_backend_asics(request, duts_selected):
    dut_asic_list = []

    metadata = get_testbed_metadata(request)

    if metadata is None:
        return [[None]]*len(duts_selected)

    for dut in duts_selected:
        mdata = metadata.get(dut)
        if mdata is None:
            dut_asic_list.append([None])
        dut_asic_list.append(mdata.get("backend_asics", [None]))

    return dut_asic_list


def generate_priority_lists(request, prio_scope):
    empty = []

    tbname = request.config.getoption("--testbed")
    if not tbname:
        return empty

    folder = 'priority'
    filepath = os.path.join(folder, tbname + '-' + prio_scope + '.json')

    try:
        with open(filepath, 'r') as yf:
            info = json.load(yf)
    except IOError:
        return empty

    if tbname not in info:
        return empty

    dut_prio = info[tbname]
    ret = []

    for dut, priorities in list(dut_prio.items()):
        for p in priorities:
            ret.append('{}|{}'.format(dut, p))

    return ret if ret else empty


def pfc_pause_delay_test_params(request):
    empty = []

    tbname = request.config.getoption("--testbed")
    if not tbname:
        return empty

    folder = 'pfc_headroom_test_params'
    filepath = os.path.join(folder, tbname + '.json')

    try:
        with open(filepath, 'r') as yf:
            info = json.load(yf)
    except IOError:
        return empty

    if tbname not in info:
        return empty

    dut_pfc_delay_params = info[tbname]
    ret = []

    for dut, pfc_pause_delay_params in list(dut_pfc_delay_params.items()):
        for pfc_delay, headroom_result in list(pfc_pause_delay_params.items()):
            ret.append('{}|{}|{}'.format(dut, pfc_delay, headroom_result))

    return ret if ret else empty


_frontend_hosts_per_hwsku_per_module = {}
_hosts_per_hwsku_per_module = {}
def pytest_generate_tests(metafunc):        # noqa E302
    # The topology always has atleast 1 dut
    dut_fixture_name = None
    duts_selected = None
    global _frontend_hosts_per_hwsku_per_module, _hosts_per_hwsku_per_module
    # Enumerators for duts are mutually exclusive
    if "enum_dut_hostname" in metafunc.fixturenames:
        duts_selected = generate_params_dut_hostname(metafunc)
        dut_fixture_name = "enum_dut_hostname"
    elif "enum_supervisor_dut_hostname" in metafunc.fixturenames:
        duts_selected = generate_params_supervisor_hostname(metafunc)
        dut_fixture_name = "enum_supervisor_dut_hostname"
    elif "enum_frontend_dut_hostname" in metafunc.fixturenames:
        duts_selected = generate_params_frontend_hostname(metafunc)
        dut_fixture_name = "enum_frontend_dut_hostname"
    elif "enum_rand_one_per_hwsku_hostname" in metafunc.fixturenames:
        if metafunc.module not in _hosts_per_hwsku_per_module:
            hosts_per_hwsku = generate_params_hostname_rand_per_hwsku(metafunc)
            _hosts_per_hwsku_per_module[metafunc.module] = hosts_per_hwsku
        duts_selected = _hosts_per_hwsku_per_module[metafunc.module]
        dut_fixture_name = "enum_rand_one_per_hwsku_hostname"
    elif "enum_rand_one_per_hwsku_frontend_hostname" in metafunc.fixturenames:
        if metafunc.module not in _frontend_hosts_per_hwsku_per_module:
            hosts_per_hwsku = generate_params_hostname_rand_per_hwsku(metafunc, frontend_only=True)
            _frontend_hosts_per_hwsku_per_module[metafunc.module] = hosts_per_hwsku
        duts_selected = _frontend_hosts_per_hwsku_per_module[metafunc.module]
        dut_fixture_name = "enum_rand_one_per_hwsku_frontend_hostname"

    asics_selected = None
    asic_fixture_name = None

    tbname, tbinfo = get_tbinfo(metafunc)
    if duts_selected is None:
        duts_selected = [tbinfo["duts"][0]]

    possible_asic_enums = ["enum_asic_index", "enum_frontend_asic_index", "enum_backend_asic_index",
                           "enum_rand_one_asic_index", "enum_rand_one_frontend_asic_index"]
    enums_asic_fixtures = set(metafunc.fixturenames).intersection(possible_asic_enums)
    assert len(enums_asic_fixtures) < 2, \
        "The number of asic_enum fixtures should be 1 or zero, " \
        "the following fixtures conflict one with each other: {}".format(str(enums_asic_fixtures))

    if "enum_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_asic_index"
        asics_selected = generate_param_asic_index(metafunc, duts_selected, ASIC_PARAM_TYPE_ALL)
    elif "enum_frontend_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_frontend_asic_index"
        asics_selected = generate_param_asic_index(metafunc, duts_selected, ASIC_PARAM_TYPE_FRONTEND)
    elif "enum_backend_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_backend_asic_index"
        asics_selected = generate_dut_backend_asics(metafunc, duts_selected)
    elif "enum_rand_one_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_rand_one_asic_index"
        asics_selected = generate_param_asic_index(metafunc, duts_selected, ASIC_PARAM_TYPE_ALL, random_asic=True)
    elif "enum_rand_one_frontend_asic_index" in metafunc.fixturenames:
        asic_fixture_name = "enum_rand_one_frontend_asic_index"
        asics_selected = generate_param_asic_index(metafunc, duts_selected, ASIC_PARAM_TYPE_FRONTEND, random_asic=True)

    # Create parameterization tuple of dut_fixture_name, asic_fixture_name and feature to parameterize
    if dut_fixture_name and asic_fixture_name and ("enum_dut_feature" in metafunc.fixturenames):
        tuple_list = generate_dut_feature_list(metafunc, duts_selected, asics_selected)
        feature_fixture = "enum_dut_feature"
        metafunc.parametrize(dut_fixture_name + "," + asic_fixture_name + "," + feature_fixture,
                             tuple_list, scope="module", indirect=True)
    # Create parameterization tuple of dut_fixture_name and asic_fixture_name to parameterize
    elif dut_fixture_name and asic_fixture_name:
        # parameterize on both - create tuple for each
        tuple_list = []
        for a_dut_index, a_dut in enumerate(duts_selected):
            if len(asics_selected):
                for a_asic in asics_selected[a_dut_index]:
                    # Create tuple of dut and asic index
                    tuple_list.append((a_dut, a_asic))
            else:
                tuple_list.append((a_dut, None))
        metafunc.parametrize(dut_fixture_name + "," + asic_fixture_name, tuple_list, scope="module", indirect=True)
    elif dut_fixture_name:
        # parameterize only on DUT
        metafunc.parametrize(dut_fixture_name, duts_selected, scope="module", indirect=True)
    elif asic_fixture_name:
        # We have no duts selected, so need asic list for the first DUT
        if len(asics_selected):
            metafunc.parametrize(asic_fixture_name, asics_selected[0], scope="module", indirect=True)
        else:
            metafunc.parametrize(asic_fixture_name, [None], scope="module", indirect=True)

    if "enum_dut_portname" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname", generate_port_lists(metafunc, "all_ports"))

    def format_portautoneg_test_id(param):
        speeds = param['speeds'] if 'speeds' in param else [param['speed']]
        return "{}|{}|{}".format(param['dutname'], param['port'], ','.join(speeds))

    if "enum_dut_portname_module_fixture" in metafunc.fixturenames or \
            "enum_speed_per_dutport_fixture" in metafunc.fixturenames:
        autoneg_tests_data = get_autoneg_tests_data()
        if "enum_dut_portname_module_fixture" in metafunc.fixturenames:
            metafunc.parametrize(
                "enum_dut_portname_module_fixture",
                autoneg_tests_data,
                scope="module",
                ids=format_portautoneg_test_id,
                indirect=True
            )

        if "enum_speed_per_dutport_fixture" in metafunc.fixturenames:
            metafunc.parametrize(
                "enum_speed_per_dutport_fixture",
                parametrise_per_supported_port_speed(autoneg_tests_data),
                scope="module",
                ids=format_portautoneg_test_id,
                indirect=True
            )

    if "enum_dut_portname_oper_up" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname_oper_up", generate_port_lists(metafunc, "oper_up_ports"))
    if "enum_dut_portname_admin_up" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname_admin_up", generate_port_lists(metafunc, "admin_up_ports"))
    if "enum_dut_portchannel" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portchannel", generate_port_lists(metafunc, "all_pcs"))
    if "enum_dut_portchannel_oper_up" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portchannel_oper_up", generate_port_lists(metafunc, "oper_up_pcs"))
    if "enum_dut_portchannel_admin_up" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portchannel_admin_up", generate_port_lists(metafunc, "admin_up_pcs"))
    if "enum_dut_portchannel_with_completeness_level" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portchannel_with_completeness_level",
                             generate_port_lists(metafunc, "all_pcs", with_completeness_level=True))
    if "enum_dut_feature_container" in metafunc.fixturenames:
        metafunc.parametrize(
            "enum_dut_feature_container", generate_dut_feature_container_list(metafunc)
        )
    if 'enum_dut_all_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_all_prio", generate_priority_lists(metafunc, 'all'))
    if 'enum_dut_lossless_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_lossless_prio", generate_priority_lists(metafunc, 'lossless'))
    if 'enum_dut_lossy_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_lossy_prio", generate_priority_lists(metafunc, 'lossy'))
    if 'enum_pfc_pause_delay_test_params' in metafunc.fixturenames:
        metafunc.parametrize("enum_pfc_pause_delay_test_params", pfc_pause_delay_test_params(metafunc))

    if 'topo_scenario' in metafunc.fixturenames:
        if tbinfo['topo']['type'] == 'm0' and 'topo_scenario' in metafunc.fixturenames:
            metafunc.parametrize('topo_scenario', ['m0_vlan_scenario', 'm0_l3_scenario'], scope='module')
        else:
            metafunc.parametrize('topo_scenario', ['default'], scope='module')

    if 'vlan_name' in metafunc.fixturenames:
        if tbinfo['topo']['type'] == 'm0' and 'topo_scenario' in metafunc.fixturenames:
            if tbinfo['topo']['name'] == 'm0-2vlan':
                metafunc.parametrize('vlan_name', ['Vlan1000', 'Vlan2000'], scope='module')
            else:
                metafunc.parametrize('vlan_name', ['Vlan1000'], scope='module')
        # Non M0 topo
        else:
            if tbinfo['topo']['type'] in ['t0', 'mx']:
                metafunc.parametrize('vlan_name', ['Vlan1000'], scope='module')
            else:
                metafunc.parametrize('vlan_name', ['no_vlan'], scope='module')


def get_autoneg_tests_data():
    folder = 'metadata'
    filepath = os.path.join(folder, 'autoneg-test-params.json')
    if not os.path.exists(filepath):
        logger.warning('Autoneg tests datafile is missing: {}. " \
            "Run test_pretest -k test_update_testbed_metadata to create it'.format(filepath))
        return [{'dutname': 'unknown', 'port': 'unknown', 'speeds': ['unknown']}]
    data = {}
    with open(filepath) as yf:
        data = json.load(yf)

    return [
        {'dutname': dutname, 'port': dutport, 'speeds': portinfo['common_port_speeds']}
        for dutname, ports in list(data.items())
        for dutport, portinfo in list(ports.items())
    ]


def parametrise_per_supported_port_speed(data):
    return [
        {'dutname': conn_info['dutname'], 'port': conn_info['port'], 'speed': speed}
        for conn_info in data for speed in conn_info['speeds']
    ]


# Override enum fixtures for duts and asics to ensure that parametrization happens once per module.
@pytest.fixture(scope="module")
def enum_dut_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_supervisor_dut_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_frontend_dut_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_rand_one_per_hwsku_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_rand_one_per_hwsku_frontend_hostname(request):
    return request.param


@pytest.fixture(scope="module")
def enum_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def enum_frontend_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def enum_backend_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def enum_rand_one_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def enum_dut_feature(request):
    return request.param


@pytest.fixture(scope="module")
def enum_rand_one_frontend_asic_index(request):
    return request.param


@pytest.fixture(scope="module")
def duthost_console(duthosts, enum_supervisor_dut_hostname, localhost, conn_graph_facts, creds):   # noqa F811
    duthost = duthosts[enum_supervisor_dut_hostname]
    dut_hostname = duthost.hostname
    console_host = conn_graph_facts['device_console_info'][dut_hostname]['ManagementIp']
    console_port = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['peerport']
    console_type = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['type']
    console_username = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['proxy']

    console_type = "console_" + console_type

    # console password and sonic_password are lists, which may contain more than one password
    sonicadmin_alt_password = localhost.host.options['variable_manager']._hostvars[dut_hostname].get(
        "ansible_altpassword")
    host = ConsoleHost(console_type=console_type,
                       console_host=console_host,
                       console_port=console_port,
                       sonic_username=creds['sonicadmin_user'],
                       sonic_password=[creds['sonicadmin_password'], sonicadmin_alt_password],
                       console_username=console_username,
                       console_password=creds['console_password'][console_type])
    yield host
    host.disconnect()


@pytest.fixture(scope='session')
def cleanup_cache_for_session(request):
    """
    This fixture allows developers to cleanup the cached data for all DUTs in the testbed before test.
    Use cases:
      - Running tests where some 'facts' about the DUT that get cached are changed.
      - Running tests/regression without running test_pretest which has a test to clean up cache (PR#2978)
      - Test case development phase to work out testbed information changes.

    This fixture is not automatically applied, if you want to use it, you have to add a call to it in your tests.
    """
    tbname, tbinfo = get_tbinfo(request)
    inv_files = get_inventory_files(request)
    cache.cleanup(zone=tbname)
    for a_dut in tbinfo['duts']:
        cache.cleanup(zone=a_dut)
    inv_data = get_host_visible_vars(inv_files, a_dut)
    if 'num_asics' in inv_data and inv_data['num_asics'] > 1:
        for asic_id in range(inv_data['num_asics']):
            cache.cleanup(zone="{}-asic{}".format(a_dut, asic_id))


def get_l2_info(dut):
    """
    Helper function for l2 mode fixture
    """
    config_facts = dut.get_running_config_facts()
    mgmt_intf_table = config_facts['MGMT_INTERFACE']
    metadata_table = config_facts['DEVICE_METADATA']['localhost']
    mgmt_ip = None
    for ip in list(mgmt_intf_table['eth0'].keys()):
        if type(ip_interface(ip)) is IPv4Interface:
            mgmt_ip = ip
    mgmt_gw = mgmt_intf_table['eth0'][mgmt_ip]['gwaddr']
    hwsku = metadata_table['hwsku']

    return mgmt_ip, mgmt_gw, hwsku


@pytest.fixture(scope='session')
def enable_l2_mode(duthosts, tbinfo, backup_and_restore_config_db_session):     # noqa F811
    """
    Configures L2 switch mode according to
    https://github.com/sonic-net/SONiC/wiki/L2-Switch-mode

    Currently not compatible with version 201811

    This fixture does not auto-cleanup after itself
    A manual config reload is required to restore regular state
    """
    base_config_db_cmd = 'echo \'{}\' | config reload /dev/stdin -y'
    l2_preset_cmd = 'sonic-cfggen --preset l2 -p -H -k {} -a \'{}\' | config load /dev/stdin -y'
    is_dualtor = 'dualtor' in tbinfo['topo']['name']

    for dut in duthosts:
        logger.info("Setting L2 mode on {}".format(dut))
        cmds = []
        mgmt_ip, mgmt_gw, hwsku = get_l2_info(dut)
        # step 1
        base_config_db = {
                            "MGMT_INTERFACE": {
                                "eth0|{}".format(mgmt_ip): {
                                    "gwaddr": "{}".format(mgmt_gw)
                                }
                            },
                            "DEVICE_METADATA": {
                                "localhost": {
                                    "hostname": "sonic"
                                }
                            }
                        }

        if is_dualtor:
            base_config_db["DEVICE_METADATA"]["localhost"]["subtype"] = "DualToR"
        cmds.append(base_config_db_cmd.format(json.dumps(base_config_db)))

        # step 2
        cmds.append('sonic-cfggen -H --write-to-db')

        # step 3 is optional and skipped here
        # step 4
        if is_dualtor:
            mg_facts = dut.get_extended_minigraph_facts(tbinfo)
            all_ports = list(mg_facts['minigraph_ports'].keys())
            downlinks = []
            for vlan_info in list(mg_facts['minigraph_vlans'].values()):
                downlinks.extend(vlan_info['members'])
            uplinks = [intf for intf in all_ports if intf not in downlinks]
            extra_args = {
                'is_dualtor': 'true',
                'uplinks': uplinks,
                'downlinks': downlinks
            }
        else:
            extra_args = {}
        cmds.append(l2_preset_cmd.format(hwsku, json.dumps(extra_args)))

        # extra step needed to render the feature table correctly
        if is_dualtor:
            cmds.append('while [ $(show feature config mux | awk \'{print $2}\' | tail -n 1) != "enabled" ]; '
                        'do sleep 1; done')

        # step 5
        cmds.append('config save -y')

        # step 6
        cmds.append('config reload -y')

        logger.debug("Commands to be run:\n{}".format(cmds))

        dut.shell_cmds(cmds=cmds)


@pytest.fixture(scope='session')
def duts_running_config_facts(duthosts):
    """Return running config facts for all multi-ASIC DUT hosts

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.

    Returns:
        dict: {
            <dut hostname>: [
                (asic0_idx, {asic0_cfg_facts}),
                (asic1_idx, {asic1_cfg_facts})
            ]
        }
    """
    cfg_facts = {}
    for duthost in duthosts:
        cfg_facts[duthost.hostname] = []
        for asic in duthost.asics:
            if asic.is_it_backend():
                continue
            asic_cfg_facts = asic.config_facts(source='running')['ansible_facts']
            cfg_facts[duthost.hostname].append((asic.asic_index, asic_cfg_facts))
    return cfg_facts


@pytest.fixture(scope='class')
def dut_test_params_qos(duthosts, tbinfo, ptfhost, get_src_dst_asic_and_duts, lower_tor_host, creds,
                        mux_server_url, mux_status_from_nic_simulator, duts_running_config_facts, duts_minigraph_facts):
    if 'dualtor' in tbinfo['topo']['name']:
        all_duts = [lower_tor_host]
    else:
        all_duts = get_src_dst_asic_and_duts['all_duts']

    src_asic = get_src_dst_asic_and_duts['src_asic']
    dst_asic = get_src_dst_asic_and_duts['dst_asic']

    src_dut = get_src_dst_asic_and_duts['src_dut']
    src_dut_ip = src_dut.host.options['inventory_manager'].get_host(src_dut.hostname).vars['ansible_host']
    src_server = "{}:{}".format(src_dut_ip, src_asic.get_rpc_port_ssh_tunnel())

    duthost = all_duts[0]
    mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["name"]

    rtn_dict = {
        "topo": topo,
        "hwsku": mgFacts["minigraph_hwsku"],
        "basicParams": {
            "router_mac": duthost.facts["router_mac"],
            "src_server": src_server,
            "port_map_file": ptf_test_port_map_active_active(
                ptfhost, tbinfo, duthosts, mux_server_url,
                duts_running_config_facts, duts_minigraph_facts,
                mux_status_from_nic_simulator()),
            "sonic_asic_type": duthost.facts['asic_type'],
            "sonic_version": duthost.os_version,
            "src_dut_index": get_src_dst_asic_and_duts['src_dut_index'],
            "src_asic_index": get_src_dst_asic_and_duts['src_asic_index'],
            "dst_dut_index": get_src_dst_asic_and_duts['dst_dut_index'],
            "dst_asic_index": get_src_dst_asic_and_duts['dst_asic_index'],
            "dut_username": creds['sonicadmin_user'],
            "dut_password": creds['sonicadmin_password']
        },

    }

    # Add dst server info if src and dst asic are different
    if src_asic != dst_asic:
        dst_dut = get_src_dst_asic_and_duts['dst_dut']
        dst_dut_ip = dst_dut.host.options['inventory_manager'].get_host(dst_dut.hostname).vars['ansible_host']
        rtn_dict["basicParams"]["dst_server"] = "{}:{}".format(dst_dut_ip, dst_asic.get_rpc_port_ssh_tunnel())

    if 'platform_asic' in duthost.facts:
        rtn_dict['basicParams']["platform_asic"] = duthost.facts['platform_asic']

    yield rtn_dict


@ pytest.fixture(scope='class')
def dut_test_params(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo,
                    ptf_portmap_file, lower_tor_host, creds):   # noqa F811
    """
        Prepares DUT host test params

        Args:
            duthost (AnsibleHost): Device Under Test (DUT)
            tbinfo (Fixture, dict): Map containing testbed information
            ptfPortMapFile (Fxiture, str): filename residing
              on PTF host and contains port maps information

        Returns:
            dut_test_params (dict): DUT host test params
    """
    if 'dualtor' in tbinfo['topo']['name']:
        duthost = lower_tor_host
    else:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["name"]

    rtn_dict = {
        "topo": topo,
        "hwsku": mgFacts["minigraph_hwsku"],
        "basicParams": {
            "router_mac": duthost.facts["router_mac"],
            "server": duthost.host.options['inventory_manager'].get_host(
                        duthost.hostname
                    ).vars['ansible_host'],
            "port_map_file": ptf_portmap_file,
            "sonic_asic_type": duthost.facts['asic_type'],
            "sonic_version": duthost.os_version,
            "dut_username": creds['sonicadmin_user'],
            "dut_password": creds['sonicadmin_password']
        }
    }
    if 'platform_asic' in duthost.facts:
        rtn_dict['basicParams']["platform_asic"] = duthost.facts['platform_asic']

    yield rtn_dict


@pytest.fixture(scope='module')
def duts_minigraph_facts(duthosts, tbinfo):
    """Return minigraph facts for all DUT hosts

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.
        tbinfo (object): Instance of TestbedInfo.

    Returns:
        dict: {
            <dut hostname>: [
                (asic0_idx, {asic0_mg_facts}),
                (asic1_idx, {asic1_mg_facts})
            ]
        }
    """
    mg_facts = {}
    for duthost in duthosts:
        mg_facts[duthost.hostname] = []
        for asic in duthost.asics:
            if asic.is_it_backend():
                continue
            asic_mg_facts = asic.get_extended_minigraph_facts(tbinfo)
            mg_facts[duthost.hostname].append((asic.asic_index, asic_mg_facts))

    return mg_facts


@pytest.fixture(scope="module", autouse=True)
def get_reboot_cause(duthost):
    uptime_start = duthost.get_up_time()
    yield
    uptime_end = duthost.get_up_time()
    if not uptime_end == uptime_start:
        if "201811" in duthost.os_version or "201911" in duthost.os_version:
            duthost.show_and_parse("show reboot-cause")
        else:
            duthost.show_and_parse("show reboot-cause history")


def collect_db_dump_on_duts(request, duthosts):
    '''When test failed, this fixture will dump all the DBs on DUT and collect them to local
    '''
    if hasattr(request.node, 'rep_call') and request.node.rep_call.failed:
        dut_file_path = "/tmp/db_dump"
        local_file_path = "./logs/db_dump"

        # Remove characters that can't be used in filename
        nodename = safe_filename(request.node.nodeid)
        db_dump_path = os.path.join(dut_file_path, nodename)
        db_dump_tarfile = os.path.join(dut_file_path, "{}.tar.gz".format(nodename))

        # We don't need to collect all DBs, db_names specify the DBs we want to collect
        db_names = ["APPL_DB", "ASIC_DB", "COUNTERS_DB", "CONFIG_DB", "STATE_DB"]
        raw_db_config = duthosts[0].shell("cat /var/run/redis/sonic-db/database_config.json")["stdout"]
        db_config = json.loads(raw_db_config).get("DATABASES", {})
        db_ids = set()
        for db_name in db_names:
            # Skip STATE_DB dump on release 201911.
            # JINJA2_CACHE can't be dumped by "redis-dump", and it is stored in STATE_DB on 201911 release.
            # Please refer to issue: https://github.com/sonic-net/sonic-buildimage/issues/5587.
            # The issue has been fixed in https://github.com/sonic-net/sonic-buildimage/pull/5646.
            # However, the fix is not included in 201911 release. So we have to skip STATE_DB on release 201911
            # to avoid raising exception when dumping the STATE_DB.
            if db_name == "STATE_DB" and duthosts[0].sonic_release in ['201911']:
                continue

            if db_name in db_config:
                db_ids.add(db_config[db_name].get("id", 0))

        namespace_list = duthosts[0].get_asic_namespace_list() if duthosts[0].is_multi_asic else []
        if namespace_list:
            for namespace in namespace_list:
                # Collect DB dump
                dump_dest_path = os.path.join(db_dump_path, namespace)
                dump_cmds = ["mkdir -p {}".format(dump_dest_path)]
                for db_id in db_ids:
                    dump_cmd = "ip netns exec {} redis-dump -d {} -y -o {}/{}" \
                               .format(namespace, db_id, dump_dest_path, db_id)
                    dump_cmds.append(dump_cmd)
                duthosts.shell_cmds(cmds=dump_cmds)
        else:
            # Collect DB dump
            dump_dest_path = db_dump_path
            dump_cmds = ["mkdir -p {}".format(dump_dest_path)]
            for db_id in db_ids:
                dump_cmd = "redis-dump -d {} -y -o {}/{}".format(db_id, dump_dest_path, db_id)
                dump_cmds.append(dump_cmd)
            duthosts.shell_cmds(cmds=dump_cmds)

        # compress dump file and fetch to docker
        duthosts.shell("tar -czf {} -C {} {}".format(db_dump_tarfile, dut_file_path, nodename))
        duthosts.fetch(src=db_dump_tarfile, dest=local_file_path)

        # remove dump file from dut
        duthosts.shell("rm -fr {} {}".format(db_dump_tarfile, db_dump_path))


@pytest.fixture(autouse=True)
def collect_db_dump(request, duthosts):
    """This autoused fixture is to generate DB dumps on DUT and collect them to local for later troubleshooting when
    a test case failed.
    """
    yield
    if request.config.getoption("--collect_db_data"):
        collect_db_dump_on_duts(request, duthosts)


def __dut_reload(duts_data, node=None, results=None):
    if node is None or results is None:
        logger.error('Missing kwarg "node" or "results"')
        return
    logger.info("dut reload called on {}".format(node.hostname))
    node.copy(content=json.dumps(duts_data[node.hostname]["pre_running_config"][None], indent=4),
              dest='/etc/sonic/config_db.json', verbose=False)

    if node.is_multi_asic:
        for asic_index in range(0, node.facts.get('num_asic')):
            asic_ns = "asic{}".format(asic_index)
            asic_cfg_file = "/tmp/{}_config_db{}.json".format(node.hostname, asic_index)
            with open(asic_cfg_file, "w") as outfile:
                outfile.write(json.dumps(duts_data[node.hostname]['pre_running_config'][asic_ns], indent=4))
            node.copy(src=asic_cfg_file, dest='/etc/sonic/config_db{}.json'.format(asic_index), verbose=False)
            os.remove(asic_cfg_file)

    config_reload(node, wait_before_force_reload=300)


def compare_running_config(pre_running_config, cur_running_config):
    if type(pre_running_config) != type(cur_running_config):
        return False
    if pre_running_config == cur_running_config:
        return True
    else:
        if type(pre_running_config) is dict:
            if set(pre_running_config.keys()) != set(cur_running_config.keys()):
                return False
            for key in pre_running_config.keys():
                if not compare_running_config(pre_running_config[key], cur_running_config[key]):
                    return False
                return True
        # We only have string in list in running config now, so we can ignore the order of the list.
        elif type(pre_running_config) is list:
            if set(pre_running_config) != set(cur_running_config):
                return False
            else:
                return True
        else:
            return False


@pytest.fixture(scope="module", autouse=True)
def core_dump_and_config_check(duthosts, tbinfo, request):
    '''
    Check if there are new core dump files and if the running config is modified after the test case running.
    If so, we will reload the running config after test case running.
    '''
    check_flag = True
    if hasattr(request.config.option, 'enable_macsec') and request.config.option.enable_macsec:
        check_flag = False
    for m in request.node.iter_markers():
        if m.name == "skip_check_dut_health":
            check_flag = False

    module_name = request.node.name

    duts_data = {}

    new_core_dumps = {}
    core_dump_check_pass = True

    inconsistent_config = {}
    pre_only_config = {}
    cur_only_config = {}
    config_db_check_pass = True

    check_result = {}

    if check_flag:
        for duthost in duthosts:
            logger.info("Collecting core dumps before test on {}".format(duthost.hostname))
            duts_data[duthost.hostname] = {}

            if "20191130" in duthost.os_version:
                pre_existing_core_dumps = duthost.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
            else:
                pre_existing_core_dumps = duthost.shell('ls /var/core/')['stdout'].split()
            duts_data[duthost.hostname]["pre_core_dumps"] = pre_existing_core_dumps

            logger.info("Collecting running config before test on {}".format(duthost.hostname))
            duts_data[duthost.hostname]["pre_running_config"] = {}
            if not duthost.stat(path="/etc/sonic/running_golden_config.json")['stat']['exists']:
                logger.info("Collecting running golden config before test on {}".format(duthost.hostname))
                duthost.shell("sonic-cfggen -d --print-data > /etc/sonic/running_golden_config.json")
            duts_data[duthost.hostname]["pre_running_config"][None] = \
                json.loads(duthost.shell("cat /etc/sonic/running_golden_config.json", verbose=False)['stdout'])

            if duthost.is_multi_asic:
                for asic_index in range(0, duthost.facts.get('num_asic')):
                    asic_ns = "asic{}".format(asic_index)
                    if not duthost.stat(
                            path="/etc/sonic/running_golden_config{}.json".format(asic_index))['stat']['exists']:
                        duthost.shell("sonic-cfggen -n {} -d --print-data > /etc/sonic/running_golden_config{}.json".
                                      format(asic_ns, asic_index))
                    duts_data[duthost.hostname]['pre_running_config'][asic_ns] = \
                        json.loads(duthost.shell("cat /etc/sonic/running_golden_config{}.json".format(asic_index),
                                                 verbose=False)['stdout'])

    yield

    if check_flag:
        for duthost in duthosts:
            inconsistent_config[duthost.hostname] = {}
            pre_only_config[duthost.hostname] = {}
            cur_only_config[duthost.hostname] = {}
            new_core_dumps[duthost.hostname] = []

            logger.info("Collecting core dumps after test on {}".format(duthost.hostname))
            if "20191130" in duthost.os_version:
                cur_cores = duthost.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
            else:
                cur_cores = duthost.shell('ls /var/core/')['stdout'].split()
            duts_data[duthost.hostname]["cur_core_dumps"] = cur_cores

            new_core_dumps[duthost.hostname] = list(
                set(duts_data[duthost.hostname]["cur_core_dumps"]) - set(duts_data[duthost.hostname]["pre_core_dumps"]))

            if new_core_dumps[duthost.hostname]:
                core_dump_check_pass = False

                base_dir = os.path.dirname(os.path.realpath(__file__))
                for new_core_dump in new_core_dumps[duthost.hostname]:
                    duthost.fetch(src="/var/core/{}".format(new_core_dump), dest=os.path.join(base_dir, "logs"))

            logger.info("Collecting running config after test on {}".format(duthost.hostname))
            # get running config after running
            duts_data[duthost.hostname]["cur_running_config"] = {}
            duts_data[duthost.hostname]["cur_running_config"][None] = \
                json.loads(duthost.shell("sonic-cfggen -d --print-data", verbose=False)['stdout'])
            if duthost.is_multi_asic:
                for asic_index in range(0, duthost.facts.get('num_asic')):
                    asic_ns = "asic{}".format(asic_index)
                    duts_data[duthost.hostname]["cur_running_config"][asic_ns] = \
                        json.loads(duthost.shell("sonic-cfggen -n {} -d --print-data".format(asic_ns),
                                                 verbose=False)['stdout'])

            # The tables that we don't care
            EXCLUDE_CONFIG_TABLE_NAMES = set([])
            # The keys that we don't care
            # Current skipped keys:
            # 1. "MUX_LINKMGR|LINK_PROBER"
            # NOTE: this key is edited by the `run_icmp_responder_session` or `run_icmp_responder`
            # to account for the lower performance of the ICMP responder/mux simulator compared to
            # real servers and mux cables.
            # Linkmgrd is the only service to consume this table so it should not affect other test cases.
            # Let's keep this setting in db and we don't want any config reload caused by this key, so
            # let's skip checking it.
            if "dualtor" in tbinfo["topo"]["name"]:
                EXCLUDE_CONFIG_KEY_NAMES = [
                    'MUX_LINKMGR|LINK_PROBER'
                ]
            else:
                EXCLUDE_CONFIG_KEY_NAMES = []

            def _remove_entry(table_name, key_name, config):
                if table_name in config and key_name in config[table_name]:
                    config[table_name].pop(key_name)
                    if len(config[table_name]) == 0:
                        config.pop(table_name)

            for cfg_context in duts_data[duthost.hostname]['pre_running_config']:
                pre_only_config[duthost.hostname][cfg_context] = {}
                cur_only_config[duthost.hostname][cfg_context] = {}
                inconsistent_config[duthost.hostname][cfg_context] = {}

                pre_running_config = duts_data[duthost.hostname]["pre_running_config"][cfg_context]
                cur_running_config = duts_data[duthost.hostname]["cur_running_config"][cfg_context]

                # Remove ignored keys from base config
                for exclude_key in EXCLUDE_CONFIG_KEY_NAMES:
                    fields = exclude_key.split('|')
                    if len(fields) != 2:
                        continue
                    _remove_entry(fields[0], fields[1], pre_running_config)
                    _remove_entry(fields[0], fields[1], cur_running_config)

                pre_running_config_keys = set(pre_running_config.keys())
                cur_running_config_keys = set(cur_running_config.keys())

                # Check if there are extra keys in pre running config
                pre_config_extra_keys = list(
                    pre_running_config_keys - cur_running_config_keys - EXCLUDE_CONFIG_TABLE_NAMES)
                for key in pre_config_extra_keys:
                    pre_only_config[duthost.hostname][cfg_context].update({key: pre_running_config[key]})

                # Check if there are extra keys in cur running config
                cur_config_extra_keys = list(
                    cur_running_config_keys - pre_running_config_keys - EXCLUDE_CONFIG_TABLE_NAMES)
                for key in cur_config_extra_keys:
                    cur_only_config[duthost.hostname][cfg_context].update({key: cur_running_config[key]})

                # Get common keys in pre running config and cur running config
                common_config_keys = list(pre_running_config_keys & cur_running_config_keys -
                                          EXCLUDE_CONFIG_TABLE_NAMES)

                # Check if the running config is modified after module running
                for key in common_config_keys:
                    # TODO: remove these code when solve the problem of "FLEX_COUNTER_DELAY_STATUS"
                    if key == "FLEX_COUNTER_TABLE":
                        for sub_key, sub_value in list(pre_running_config[key].items()):
                            try:
                                pre_value = pre_running_config[key][sub_key]
                                cur_value = cur_running_config[key][sub_key]
                                if pre_value["FLEX_COUNTER_STATUS"] != cur_value["FLEX_COUNTER_STATUS"]:
                                    inconsistent_config[duthost.hostname][cfg_context].update(
                                        {
                                            key: {
                                                "pre_value": pre_running_config[key],
                                                "cur_value": cur_running_config[key]
                                            }
                                        }
                                    )
                            except KeyError:
                                inconsistent_config[duthost.hostname][cfg_context].update(
                                    {
                                        key: {
                                            "pre_value": pre_running_config[key],
                                            "cur_value": cur_running_config[key]
                                        }
                                    }
                                )
                    elif not compare_running_config(pre_running_config[key], cur_running_config[key]):
                        inconsistent_config[duthost.hostname][cfg_context].update(
                            {
                                key: {
                                    "pre_value": pre_running_config[key],
                                    "cur_value": cur_running_config[key]
                                }
                            }
                        )

                if pre_only_config[duthost.hostname][cfg_context] or \
                        cur_only_config[duthost.hostname][cfg_context] or \
                        inconsistent_config[duthost.hostname][cfg_context]:
                    config_db_check_pass = False
        if not (core_dump_check_pass and config_db_check_pass):
            check_result = {
                "core_dump_check": {
                    "pass": core_dump_check_pass,
                    "new_core_dumps": new_core_dumps
                },
                "config_db_check": {
                    "pass": config_db_check_pass,
                    "pre_only_config": pre_only_config,
                    "cur_only_config": cur_only_config,
                    "inconsistent_config": inconsistent_config
                }
            }
            logger.warning("Core dump or config check failed for {}, results: {}"
                           .format(module_name, json.dumps(check_result)))
            results = parallel_run(__dut_reload, (), {"duts_data": duts_data}, duthosts, timeout=360)
            logger.debug('Results of dut reload: {}'.format(json.dumps(dict(results))))
        else:
            logger.info("Core dump and config check passed for {}".format(module_name))

    if check_result:
        items = request.session.items
        for item in items:
            if item.module.__name__ + ".py" == module_name.split("/")[-1]:
                item.user_properties.append(('CustomMsg', json.dumps({'DutChekResult': False})))


@pytest.fixture(scope="function")
def on_exit():
    '''
    Utility to register callbacks for cleanup. Runs callbacks despite assertion
    failures. Callbacks are executed in reverse order of registration.
    '''
    class OnExit():
        def __init__(self):
            self.cbs = []

        def register(self, fn):
            self.cbs.append(fn)

        def cleanup(self):
            while len(self.cbs) != 0:
                self.cbs.pop()()

    on_exit = OnExit()
    yield on_exit
    on_exit.cleanup()


def verify_packets_any_fixed(test, pkt, ports=[], device_number=0, timeout=None):
    """
    Check that a packet is received on _any_ of the specified ports belonging to
    the given device (default device_number is 0).

    Also verifies that the packet is not received on any other ports for this
    device, and that no other packets are received on the device (unless --relax
    is in effect).

    The function is redefined here to workaround code bug in testutils.verify_packets_any
    """
    received = False
    failures = []
    for device, port in testutils.ptf_ports():
        if device != device_number:
            continue
        if port in ports:
            logging.debug("Checking for pkt on device %d, port %d", device_number, port)
            result = testutils.dp_poll(test, device_number=device, port_number=port,
                                       timeout=timeout, exp_pkt=pkt)
            if isinstance(result, test.dataplane.PollSuccess):
                received = True
            else:
                failures.append((port, result))
        else:
            testutils.verify_no_packet(test, pkt, (device, port))
    testutils.verify_no_other_packets(test)

    if not received:
        def format_failure(port, failure):
            return "On port %d:\n%s" % (port, failure.format())
        failure_report = "\n".join([format_failure(*f) for f in failures])
        test.fail("Did not receive expected packet on any of ports %r for device %d.\n%s"
                  % (ports, device_number, failure_report))


# HACK: testutils.verify_packets_any to workaround code bug
# TODO: delete me when ptf version is advanced than https://github.com/p4lang/ptf/pull/139
testutils.verify_packets_any = verify_packets_any_fixed

# HACK: We are using set_do_not_care_scapy but it will be deprecated.
if not hasattr(Mask, "set_do_not_care_scapy"):
    Mask.set_do_not_care_scapy = Mask.set_do_not_care_packet
