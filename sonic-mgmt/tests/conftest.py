import os
import glob
import json
import logging
import getpass
import random

import pytest
import yaml
import jinja2

from datetime import datetime
from ipaddress import ip_interface, IPv4Interface
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.devices.local import Localhost
from tests.common.devices.ptf import PTFHost
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.devices.fanout import FanoutHost
from tests.common.devices.k8s import K8sMasterHost
from tests.common.devices.k8s import K8sMasterCluster
from tests.common.devices.duthosts import DutHosts
from tests.common.devices.vmhost import VMHost
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db_session

from tests.common.helpers.constants import (
    ASIC_PARAM_TYPE_ALL, ASIC_PARAM_TYPE_FRONTEND, DEFAULT_ASIC_ID,
)
from tests.common.helpers.dut_ports import encode_dut_port_name
from tests.common.helpers.dut_utils import encode_dut_and_container_name
from tests.common.system_utils import docker
from tests.common.testbed import TestbedInfo
from tests.common.utilities import get_inventory_files
from tests.common.utilities import get_host_vars
from tests.common.utilities import get_host_visible_vars
from tests.common.utilities import get_test_server_host
from tests.common.helpers.dut_utils import is_supervisor_node, is_frontend_node
from tests.common.cache import FactsCache

from tests.common.connections.console_host import ConsoleHost


logger = logging.getLogger(__name__)
cache = FactsCache()

pytest_plugins = ('tests.common.plugins.ptfadapter',
                  'tests.common.plugins.ansible_fixtures',
                  'tests.common.plugins.dut_monitor',
                  'tests.common.plugins.tacacs',
                  'tests.common.plugins.loganalyzer',
                  'tests.common.plugins.pdu_controller',
                  'tests.common.plugins.sanity_check',
                  'tests.common.plugins.custom_markers',
                  'tests.common.plugins.custom_skipif.CustomSkipIf',
                  'tests.common.plugins.test_completeness',
                  'tests.common.plugins.log_section_start',
                  'tests.common.plugins.custom_fixtures',
                  'tests.common.dualtor',
                  'tests.vxlan',
                  'tests.decap',
                  'tests.common.plugins.allure_server',
                  'tests.common.plugins.conditional_mark')


def pytest_addoption(parser):
    parser.addoption("--testbed", action="store", default=None, help="testbed name")
    parser.addoption("--testbed_file", action="store", default=None, help="testbed file name")

    # test_vrf options
    parser.addoption("--vrf_capacity", action="store", default=None, type=int, help="vrf capacity of dut (4-1000)")
    parser.addoption("--vrf_test_count", action="store", default=None, type=int, help="number of vrf to be tested (1-997)")

    # qos_sai options
    parser.addoption("--ptf_portmap", action="store", default=None, type=str, help="PTF port index to DUT port alias map")

    # Kubernetes master options
    parser.addoption("--kube_master", action="store", default=None, type=str, help="Name of k8s master group used in k8s inventory, format: k8s_vms{msetnumber}_{servernumber}")

    # neighbor device type
    parser.addoption("--neighbor_type", action="store", default="eos", type=str, choices=["eos", "sonic"],
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
    parser.addoption("--collect_techsupport", action="store", default=True, type=bool,
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
                     help="Specify the url of the saithrift package to be installed on the ptf (should be http://<serverip>/path/python-saithrift_0.9.4_amd64.deb")
    ############################
    #  keysight ixanvl options #
    ############################
    parser.addoption("--testnum", action="store", default=None, type=str)

    ############################
    # platform sfp api options #
    ############################
    # Allow user to skip the absent sfp modules. User can use it like below:
    # "--skip-absent-sfp=True"
    # If this option is not specified, False will be used by default.
    parser.addoption("--skip-absent-sfp", action="store", type=bool, default=False,
        help="Skip test on absent SFP",
    )

    ############################
    # upgrade_path options     #
    ############################
    parser.addoption("--upgrade_type", default="warm",
        help="Specify the type (warm/fast/cold/soft) of upgrade that is needed from source to target image",
    )

    parser.addoption("--base_image_list", default="",
        help="Specify the base image(s) for upgrade (comma seperated list is allowed)",
    )

    parser.addoption("--target_image_list", default="",
        help="Specify the target image(s) for upgrade (comma seperated list is allowed)",
    )

    parser.addoption("--restore_to_image", default="",
        help="Specify the target image to restore to, or stay in target image if empty",
    )


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
    inv_files = [inv_file.strip() for inv_file in inv_opt.split(",")]
    try:
        setattr(request.config.option, "ansible_inventory", inv_files)
    except AttributeError:
        logger.error("Failed to set enhanced 'ansible_inventory' to request.config.option")


@pytest.fixture(scope="session", autouse=True)
def config_logging(request):

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
    if host_pattern=='all':
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
def ptfhost(ansible_adhoc, tbinfo, duthost):
    if "ptf_image_name" in tbinfo and "docker-keysight-api-server" in tbinfo["ptf_image_name"]:
        return None
    if "ptf" in tbinfo:
        return PTFHost(ansible_adhoc, tbinfo["ptf"])
    else:
        # when no ptf defined in testbed.csv
        # try to parse it from inventory
        ptf_host = duthost.host.options["inventory_manager"].get_host(duthost.hostname).get_vars()["ptf_host"]
        return PTFHost(ansible_adhoc, ptf_host)


@pytest.fixture(scope="module")
def k8smasters(ansible_adhoc, request):
    """
    Shortcut fixture for getting Kubernetes master hosts
    """
    k8s_master_ansible_group = request.config.getoption("--kube_master")
    master_vms = {}
    inv_files = request.config.getoption("ansible_inventory")
    for inv_file in inv_files:
        if "k8s" in inv_file:
            k8s_inv_file = inv_file
    with open('../ansible/{}'.format(k8s_inv_file), 'r') as kinv:
        k8sinventory = yaml.safe_load(kinv)
        for hostname, attributes in k8sinventory[k8s_master_ansible_group]['hosts'].items():
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


@pytest.fixture(scope="module")
def nbrhosts(ansible_adhoc, tbinfo, creds, request):
    """
    Shortcut fixture for getting VM host
    """

    devices = {}
    if (not tbinfo['vm_base'] and 'tgen' in tbinfo['topo']['name']) or 'ptf' in tbinfo['topo']['name']:
        logger.info("No VMs exist for this topology: {}".format(tbinfo['topo']['name']))
        return devices

    vm_base = int(tbinfo['vm_base'][2:])
    neighbor_type = request.config.getoption("--neighbor_type")

    if not 'VMs' in tbinfo['topo']['properties']['topology']:
        logger.info("No VMs exist for this topology: {}".format(tbinfo['topo']['properties']['topology']))
        return devices

    for k, v in tbinfo['topo']['properties']['topology']['VMs'].items():
        if neighbor_type == "eos":
            devices[k] = {'host': EosHost(ansible_adhoc,
                                        "VM%04d" % (vm_base + v['vm_offset']),
                                        creds['eos_login'],
                                        creds['eos_password'],
                                        shell_user=creds['eos_root_user'] if 'eos_root_user' in creds else None,
                                        shell_passwd=creds['eos_root_password'] if 'eos_root_password' in creds else None),
                        'conf': tbinfo['topo']['properties']['configuration'][k]}
        elif neighbor_type == "sonic":
            devices[k] = {'host': SonicHost(ansible_adhoc,
                                        "VM%04d" % (vm_base + v['vm_offset']),
                                        ssh_user=creds['sonic_login'] if 'sonic_login' in creds else None,
                                        ssh_passwd=creds['sonic_password'] if 'sonic_password' in creds else None),
                        'conf': tbinfo['topo']['properties']['configuration'][k]}
        else:
            raise ValueError("Unknown neighbor type %s" % (neighbor_type, ))
    return devices


@pytest.fixture(scope="module")
def fanouthosts(ansible_adhoc, conn_graph_facts, creds):
    """
    Shortcut fixture for getting Fanout hosts
    """

    dev_conn = conn_graph_facts.get('device_conn', {})
    fanout_hosts = {}
    # WA for virtual testbed which has no fanout
    try:
        for dut_host, value in dev_conn.items():
            for dut_port in value.keys():
                fanout_rec = value[dut_port]
                fanout_host = str(fanout_rec['peerdevice'])
                fanout_port = str(fanout_rec['peerport'])

                if fanout_host in fanout_hosts.keys():
                    fanout = fanout_hosts[fanout_host]
                else:
                    host_vars = ansible_adhoc().options[
                        'inventory_manager'].get_host(fanout_host).vars
                    os_type = host_vars.get('os', 'eos')
                    admin_user = creds['fanout_admin_user']
                    admin_password = creds['fanout_admin_password']
                    # `fanout_network_user` and `fanout_network_password` are for
                    # accessing the non-shell CLI of fanout.
                    # Ansible will use this set of credentail for establishing
                    # `network_cli` connection with device when applicable.
                    network_user = creds.get('fanout_network_user', admin_user)
                    network_password = creds.get('fanout_network_password',
                                                 admin_password)
                    shell_user = creds.get('fanout_shell_user', admin_user)
                    shell_password = creds.get('fanout_shell_pass', admin_password)
                    if os_type == 'sonic':
                        shell_user = creds['fanout_sonic_user']
                        shell_password = creds['fanout_sonic_password']

                    fanout = FanoutHost(ansible_adhoc,
                                        os_type,
                                        fanout_host,
                                        'FanoutLeaf',
                                        network_user,
                                        network_password,
                                        shell_user=shell_user,
                                        shell_passwd=shell_password)
                    fanout.dut_hostnames = [dut_host]
                    fanout_hosts[fanout_host] = fanout
                fanout.add_port_map(encode_dut_port_name(dut_host, dut_port), fanout_port)
                if dut_host not in fanout.dut_hostnames:
                    fanout.dut_hostnames.append(dut_host)
    except:
        pass
    return fanout_hosts


@pytest.fixture(scope="session")
def vmhost(ansible_adhoc, request, tbinfo):
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
    files = glob.glob("../ansible/group_vars/all/*.yml")
    files += glob.glob("../ansible/vars/*.yml")
    for group in groups:
        files += glob.glob("../ansible/group_vars/{}/*.yml".format(group))
    creds = {}
    for f in files:
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
        "docker_registry_password"
    ]
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    for cred_var in cred_vars:
        if cred_var in creds:
            creds[cred_var] = jinja2.Template(creds[cred_var]).render(**hostvars)
    # load creds for console
    console_login_creds = getattr(hostvars, "console_login", {})
    creds["console_user"] = {}
    creds["console_password"] = {}

    for k, v in console_login_creds.iteritems():
        creds["console_user"][k] = v["user"]
        creds["console_password"][k] = v["passwd"]

    return creds

@pytest.fixture(scope="module")
def creds(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return creds_on_dut(duthost)


@pytest.fixture(scope='module')
def creds_all_duts(duthosts):
    creds_all_duts = dict()
    for duthost in duthosts.nodes:
        creds_all_duts[duthost] = creds_on_dut(duthost)
    return creds_all_duts


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):

    # Filter out unnecessary logs captured on "stdout" and "stderr"
    item._report_sections = filter(lambda report: report[1] not in ("stdout", "stderr"), item._report_sections)

    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


def fetch_dbs(duthost, testname):
    dbs = [[0, "appdb"], [1, "asicdb"], [2, "counterdb"], [4, "configdb"]]
    for db in dbs:
        duthost.shell("redis-dump -d {} --pretty -o {}.json".format(db[0], db[1]))
        duthost.fetch(src="{}.json".format(db[1]), dest="logs/{}".format(testname))


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
            duthost.shell('sudo sed -i -e \'s/lldp lldpctl "$@"$/lldp lldpctl "$@" | grep -v "unknown-tlvs"/\' /usr/bin/lldpctl')

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
            duthost.shell('sudo sed -i -e \'s/lldp lldpctl "$@"$/lldp lldpctl "$@" | grep -v "unknown-tlvs"/\' /usr/bin/lldpctl')

    return unpatch_lldpctl


@pytest.fixture(scope="module")
def disable_container_autorestart():
    def disable_container_autorestart(duthost, testcase="", feature_list=None):
        '''
        @summary: Disable autorestart of the features present in feature_list.

        @param duthosts: Instance of DutHost
        @param testcase: testcase name used to save pretest autorestart state. Later to be used for restoration.
        @feature_list: List of features to disable autorestart. If None, autorestart of all the features will be disabled.
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
        for name, state in container_autorestart_states.items():
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
        @feature_list: List of features to enable autorestart. If None, autorestart of all the features will be disabled.
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
        for name, state in container_autorestart_states.items():
            if state == "disabled"  and (feature_list is None or name in feature_list) \
                    and stored_autorestart_states.has_key(name) \
                    and stored_autorestart_states[name] == "enabled":
                cmds_enable.append(cmd_enable.format(name))
        # Write into config_db
        cmds_enable.append("config save -y")
        duthost.shell_cmds(cmds=cmds_enable)
        os.remove(state_file_name)

    return enable_container_autorestart

@pytest.fixture(scope='module')
def swapSyncd(request, duthosts, rand_one_dut_hostname, creds):
    """
        Swap syncd on DUT host

        Args:
            request (Fixture): pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)

        Returns:
            None
    """
    duthost = duthosts[rand_one_dut_hostname]
    swapSyncd = request.config.getoption("--qos_swap_syncd")
    try:
        if swapSyncd:
            docker.swap_syncd(duthost, creds)

        yield
    finally:
        if swapSyncd:
            docker.restore_default_syncd(duthost, creds)

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
            pytest.fail("Test selected require a node per hwsku, but 'hwsku' for '{}' not defined in the inventory".format(a_host))

    hosts_per_hwsku = []
    for hosts in host_hwskus.values():
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
    # If there are no supervisor cards in a multi-dut tesbed, we are dealing with all pizza box in the testbed, pick the first DUT
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
                    dut_asic_params = range(int(inv_data[ASIC_PARAM_TYPE_ALL]))
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

    return range(num_duts)


def generate_params_dut_hostname(request):
    tbname, _ = get_tbinfo(request)
    duts = get_specified_duts(request)
    logging.info("Using DUTs {} in testbed '{}'".format(str(duts), tbname))

    return duts


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
    except IOError as e:
        return None

    return metadata.get(tbname)


def generate_port_lists(request, port_scope):
    empty = [ encode_dut_port_name('unknown', 'unknown') ]
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

    ret = []
    for dut, val in dut_ports.items():
        if 'intf_status' not in val:
            continue
        for intf, status in val['intf_status'].items():
            if scope in intf and (not state or status[state] == 'up'):
                ret.append(encode_dut_port_name(dut, intf))

    return ret if ret else empty


def generate_dut_feature_container_list(request):
    """
    Generate list of containers given the list of features.
    List of features and container names are both obtained from
    metadata file
    """
    empty = [ encode_dut_and_container_name("unknown", "unknown") ]

    meta = get_testbed_metadata(request)

    if meta is None:
        return empty

    container_list = []

    for dut, val in meta.items():
        if "features" not in val:
            continue
        for feature in val["features"].keys():
            dut_info = meta[dut]
            services = dut_info["asic_services"].get(feature)

            if services is not None:
                for service in services:
                    container_list.append(encode_dut_and_container_name(dut, service))
            else:
                container_list.append(encode_dut_and_container_name(dut, feature))

    return container_list


def generate_dut_backend_asics(request, duts_selected):
    dut_asic_list = []

    metadata = get_testbed_metadata(request)

    if metadata is None:
        return [[None]]

    for dut in duts_selected:
        mdata = metadata.get(dut)
        if mdata is None:
            continue
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
    except IOError as e:
        return empty

    if tbname not in info:
        return empty

    dut_prio = info[tbname]
    ret = []

    for dut, priorities in dut_prio.items():
        for p in priorities:
            ret.append('{}|{}'.format(dut, p))

    return ret if ret else empty

_frontend_hosts_per_hwsku_per_module = {}
_hosts_per_hwsku_per_module = {}
def pytest_generate_tests(metafunc):
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

    if duts_selected is None:
        tbname, tbinfo = get_tbinfo(metafunc)
        duts_selected = [tbinfo["duts"][0]]

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

    # Create parameterization tuple of dut_fixture_name and asic_fixture_name to parameterize
    if dut_fixture_name and asic_fixture_name:
        # parameterize on both - create tuple for each
        tuple_list = []
        for a_dut_index, a_dut in enumerate(duts_selected):
            for a_asic in asics_selected[a_dut_index]:
                # Create tuple of dut and asic index
                tuple_list.append((a_dut, a_asic))
        metafunc.parametrize(dut_fixture_name + "," + asic_fixture_name, tuple_list, scope="module")
    elif dut_fixture_name:
        # parameterize only on DUT
        metafunc.parametrize(dut_fixture_name, duts_selected, scope="module")
    elif asic_fixture_name:
        # We have no duts selected, so need asic list for the first DUT
        metafunc.parametrize(asic_fixture_name, asics_selected[0], scope="module")

    if "enum_dut_portname" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname", generate_port_lists(metafunc, "all_ports"))
    if "enum_dut_portname_module_fixture" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname_module_fixture", generate_port_lists(metafunc, "all_ports"), scope="module")
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
    if "enum_dut_feature_container" in metafunc.fixturenames:
        metafunc.parametrize(
            "enum_dut_feature_container", generate_dut_feature_container_list(metafunc)
        )
    if 'enum_dut_lossless_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_lossless_prio", generate_priority_lists(metafunc, 'lossless'))
    if 'enum_dut_lossy_prio' in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_lossy_prio", generate_priority_lists(metafunc, 'lossy'))

@pytest.fixture(scope="module")
def duthost_console(localhost, creds, request):
    dut_hostname = request.config.getoption("ansible_host_pattern")

    vars = localhost.host.options['inventory_manager'].get_host(dut_hostname).vars
    # console password and sonic_password are lists, which may contain more than one password
    sonicadmin_alt_password = localhost.host.options['variable_manager']._hostvars[dut_hostname].get("ansible_altpassword")
    host = ConsoleHost(console_type=vars['console_type'],
                       console_host=vars['console_host'],
                       console_port=vars['console_port'],
                       sonic_username=creds['sonicadmin_user'],
                       sonic_password=[creds['sonicadmin_password'], sonicadmin_alt_password],
                       console_username=creds['console_user'][vars['console_type']],
                       console_password=creds['console_password'][vars['console_type']])
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
    cache.cleanup(zone=tbname)
    for a_dut in tbinfo['duts']:
        cache.cleanup(zone=a_dut)

def get_l2_info(dut):
    """
    Helper function for l2 mode fixture
    """
    config_facts = dut.get_running_config_facts()
    mgmt_intf_table = config_facts['MGMT_INTERFACE']
    metadata_table = config_facts['DEVICE_METADATA']['localhost']
    mgmt_ip = None
    for ip in mgmt_intf_table['eth0'].keys():
        if type(ip_interface(ip)) is IPv4Interface:
            mgmt_ip = ip
    mgmt_gw = mgmt_intf_table['eth0'][mgmt_ip]['gwaddr']
    hwsku = metadata_table['hwsku']

    return mgmt_ip, mgmt_gw, hwsku

@pytest.fixture(scope='session')
def enable_l2_mode(duthosts, tbinfo, backup_and_restore_config_db_session):
    """
    Configures L2 switch mode according to
    https://github.com/Azure/SONiC/wiki/L2-Switch-mode

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
            all_ports = mg_facts['minigraph_ports'].keys()
            downlinks = []
            for vlan_info in mg_facts['minigraph_vlans'].values():
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
            cmds.append('while [ $(show feature config mux | awk \'{print $2}\' | tail -n 1) != "enabled" ]; do sleep 1; done')

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
                {asic0_cfg_facts},
                {asic1_cfg_facts}
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
            cfg_facts[duthost.hostname].append(asic_cfg_facts)
    return cfg_facts


@pytest.fixture(scope='module')
def duts_minigraph_facts(duthosts, tbinfo):
    """Return minigraph facts for all DUT hosts

    Args:
        duthosts (DutHosts): Instance of DutHosts for interacting with DUT hosts.
        tbinfo (object): Instance of TestbedInfo.

    Returns:
        dict: {
            <dut hostname>: {dut_minigraph_facts}
        }
    """
    return duthosts.get_extended_minigraph_facts(tbinfo)
