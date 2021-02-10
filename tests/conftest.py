import os
import glob
import json
import tarfile
import logging
import getpass
import random

import pytest
import yaml
import jinja2

from datetime import datetime
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.devices import Localhost
from tests.common.devices import PTFHost, EosHost, FanoutHost, K8sMasterHost, K8sMasterCluster
from tests.common.helpers.constants import ASIC_PARAM_TYPE_ALL, ASIC_PARAM_TYPE_FRONTEND, DEFAULT_ASIC_ID
from tests.common.helpers.dut_ports import encode_dut_port_name
from tests.common.devices import DutHosts
from tests.common.testbed import TestbedInfo
from tests.common.utilities import get_inventory_files
from tests.common.utilities import get_host_vars
from tests.common.utilities import get_host_visible_vars
from tests.common.helpers.dut_utils import is_supervisor_node, is_frontend_node
from tests.common.cache import FactsCache

from tests.common.connections import ConsoleHost


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
                  'tests.common.plugins.test_completeness',
                  'tests.common.plugins.log_section_start',
                  'tests.common.plugins.custom_fixtures',
                  'tests.vxlan')


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

    ########################
    #   pre-test options   #
    ########################
    parser.addoption("--deep_clean", action="store_true", default=False,
                     help="Deep clean DUT before tests (remove old logs, cores, dumps)")
    parser.addoption("--py_saithrift_url", action="store", default=None, type=str,
                     help="Specify the url of the saithrift package to be installed on the ptf (should be http://<serverip>/path/python-saithrift_0.9.4_amd64.deb")


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
    if not testbedinfo:
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


@pytest.fixture(name="duthosts", scope="session")
def fixture_duthosts(enhance_inventory, ansible_adhoc, tbinfo):
    """
    @summary: fixture to get DUT hosts defined in testbed.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package.
        Source of the various device objects. It is
        mandatory argument for the class constructors.
    @param tbinfo: fixture provides information about testbed.
    """
    return DutHosts(ansible_adhoc, tbinfo)


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
    return dut_hostnames[0]


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
def nbrhosts(ansible_adhoc, tbinfo, creds):
    """
    Shortcut fixture for getting VM host
    """

    vm_base = int(tbinfo['vm_base'][2:])
    devices = {}
    for k, v in tbinfo['topo']['properties']['topology']['VMs'].items():
        devices[k] = {'host': EosHost(ansible_adhoc,
                                      "VM%04d" % (vm_base + v['vm_offset']),
                                      creds['eos_login'],
                                      creds['eos_password'],
                                      shell_user=creds['eos_root_user'] if 'eos_root_user' in creds else None,
                                      shell_passwd=creds['eos_root_password'] if 'eos_root_password' in creds else None),
                      'conf': tbinfo['topo']['properties']['configuration'][k]}
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
                fanout_host = fanout_rec['peerdevice']
                fanout_port = fanout_rec['peerport']

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

@pytest.fixture(scope='session')
def eos():
    """ read and yield eos configuration """
    with open('eos/eos.yml') as stream:
        eos = yaml.safe_load(stream)
        return eos


@pytest.fixture(scope='session')
def pdu():
    """ read and yield pdu configuration """
    with open('../ansible/group_vars/pdu/pdu.yml') as stream:
        pdu = yaml.safe_load(stream)
        return pdu


@pytest.fixture(scope="module")
def creds(duthosts, rand_one_dut_hostname):
    """ read credential information according to the dut inventory """
    duthost = duthosts[rand_one_dut_hostname]
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
        fname = res['stdout']
        a_dut.fetch(src=fname, dest="logs/{}".format(testname))
        tar = tarfile.open("logs/{}/{}/{}".format(testname, a_dut.hostname, fname))
        for m in tar.getmembers():
            if m.isfile():
                tar.extract(m, path="logs/{}/{}/".format(testname, a_dut.hostname))

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


def get_host_data(request, dut):
    '''
    This function parses multple inventory files and returns the dut information present in the inventory
    '''
    inv_files = get_inventory_files(request)
    return get_host_vars(inv_files, dut)


def generate_params_frontend_hostname(request):
    frontend_duts = []
    tbname, tbinfo = get_tbinfo(request)
    duts = tbinfo['duts']
    inv_files = get_inventory_files(request)
    for dut in duts:
        if is_frontend_node(inv_files, dut):
            frontend_duts.append(dut)
    assert len(frontend_duts) > 0, \
        "Test selected require at-least one frontend node, " \
        "none of the DUTs '{}' in testbed '{}' are a supervisor node".format(duts, tbname)
    return frontend_duts


def generate_params_hostname_rand_per_hwsku(request, frontend_only=False):
    tbname, tbinfo = get_tbinfo(request)
    hosts = tbinfo['duts']
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
    tbname, tbinfo = get_tbinfo(request)
    duts = tbinfo['duts']
    if len(duts) == 1:
        # We have a single node - dealing with pizza box, return it
        return [duts[0]]
    inv_files = get_inventory_files(request)
    for dut in duts:
        # Expecting only a single supervisor node
        if is_supervisor_node(inv_files, dut):
            return [dut]
    pytest.fail("Test selected require a supervisor node, " +
                "none of the DUTs '{}' in testbed '{}' are a supervisor node".format(duts, tbname))

def generate_param_asic_index(request, dut_indices, param_type):
    _, tbinfo = get_tbinfo(request)
    inv_files = get_inventory_files(request)
    logging.info("generating {} asic indicies for  DUT [{}] in ".format(param_type, dut_indices))
    #if the params are not present treat the device as a single asic device
    asic_index_params = [DEFAULT_ASIC_ID]

    for dut_id in dut_indices:
        dut = tbinfo['duts'][dut_id]
        inv_data = get_host_visible_vars(inv_files, dut)
        if inv_data is not None:
            if param_type == ASIC_PARAM_TYPE_ALL and ASIC_PARAM_TYPE_ALL in inv_data:
                if int(inv_data[ASIC_PARAM_TYPE_ALL]) == 1:
                    asic_index_params = [DEFAULT_ASIC_ID]
                else:
                    asic_index_params = range(int(inv_data[ASIC_PARAM_TYPE_ALL]))
            elif param_type == ASIC_PARAM_TYPE_FRONTEND and ASIC_PARAM_TYPE_FRONTEND in inv_data:
                asic_index_params = inv_data[ASIC_PARAM_TYPE_FRONTEND]
            logging.info("dut_index {} dut name {}  asics params = {}".format(
                dut_id, dut, asic_index_params))
    return asic_index_params


def generate_params_dut_index(request):
    tbname, tbinfo = get_tbinfo(request)
    num_duts = len(tbinfo['duts'])
    logging.info("Num of duts in testbed '{}' is {}".format(tbname, num_duts))
    return range(num_duts)


def generate_params_dut_hostname(request):
    tbname, tbinfo = get_tbinfo(request)
    duts = tbinfo["duts"]
    logging.info("DUTs in testbed '{}' are: {}".format(tbname, str(duts)))
    return duts


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

    tbname = request.config.getoption("--testbed")
    if not tbname:
        return empty

    folder = 'metadata'
    filepath = os.path.join(folder, tbname + '.json')

    try:
        with open(filepath, 'r') as yf:
            ports = json.load(yf)
    except IOError as e:
        return empty

    if tbname not in ports:
        return empty

    dut_ports = ports[tbname]
    ret = []
    for dut, val in dut_ports.items():
        if 'intf_status' not in val:
            continue
        for intf, status in val['intf_status'].items():
            if scope in intf and (not state or status[state] == 'up'):
                ret.append(encode_dut_port_name(dut, intf))

    return ret if ret else empty


def generate_dut_feature_list(request):
    empty = [ encode_dut_port_name('unknown', 'unknown') ]

    tbname = request.config.getoption("--testbed")
    if not tbname:
        return empty

    folder = 'metadata'
    filepath = os.path.join(folder, tbname + '.json')

    try:
        with open(filepath, 'r') as yf:
            metadata = json.load(yf)
    except IOError as e:
        return empty

    if tbname not in metadata:
        return empty

    meta = metadata[tbname]
    ret = []
    for dut, val in meta.items():
        if 'features' not in val:
            continue
        for feature, _ in val['features'].items():
            ret.append(encode_dut_port_name(dut, feature))

    return ret if ret else empty

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
    dut_indices = [0]
    global _frontend_hosts_per_hwsku_per_module, _hosts_per_hwsku_per_module
    # Enumerators ("enum_dut_index", "enum_dut_hostname", "rand_one_dut_hostname") are mutually exclusive
    if "enum_dut_index" in metafunc.fixturenames:
        dut_indices = generate_params_dut_index(metafunc)
        metafunc.parametrize("enum_dut_index", dut_indices, scope="module")
    elif "enum_dut_hostname" in metafunc.fixturenames:
        dut_hostnames = generate_params_dut_hostname(metafunc)
        metafunc.parametrize("enum_dut_hostname", dut_hostnames, scope="module")
    elif "enum_supervisor_dut_hostname" in metafunc.fixturenames:
        supervisor_hosts = generate_params_supervisor_hostname(metafunc)
        metafunc.parametrize("enum_supervisor_dut_hostname", supervisor_hosts, scope="module")
    elif "enum_frontend_dut_hostname" in metafunc.fixturenames:
        frontend_hosts = generate_params_frontend_hostname(metafunc)
        metafunc.parametrize("enum_frontend_dut_hostname", frontend_hosts, scope="module")
    elif "enum_rand_one_per_hwsku_hostname" in metafunc.fixturenames:
        if metafunc.module not in _hosts_per_hwsku_per_module:
            hosts_per_hwsku = generate_params_hostname_rand_per_hwsku(metafunc)
            _hosts_per_hwsku_per_module[metafunc.module] = hosts_per_hwsku
        hosts = _hosts_per_hwsku_per_module[metafunc.module]
        metafunc.parametrize("enum_rand_one_per_hwsku_hostname", hosts, scope="module")
    elif "enum_rand_one_per_hwsku_frontend_hostname" in metafunc.fixturenames:
        if metafunc.module not in _frontend_hosts_per_hwsku_per_module:
            hosts_per_hwsku = generate_params_hostname_rand_per_hwsku(metafunc, frontend_only=True)
            _frontend_hosts_per_hwsku_per_module[metafunc.module] = hosts_per_hwsku
        hosts = _frontend_hosts_per_hwsku_per_module[metafunc.module]
        metafunc.parametrize("enum_rand_one_per_hwsku_frontend_hostname", hosts, scope="module")

    if "enum_asic_index" in metafunc.fixturenames:
        metafunc.parametrize("enum_asic_index", generate_param_asic_index(metafunc, dut_indices, ASIC_PARAM_TYPE_ALL))
    if "enum_frontend_asic_index" in metafunc.fixturenames:
        metafunc.parametrize(
            "enum_frontend_asic_index",
            generate_param_asic_index(
                metafunc, dut_indices, ASIC_PARAM_TYPE_FRONTEND
            ),
            scope="class"
        )
    if "enum_dut_portname" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_portname", generate_port_lists(metafunc, "all_ports"))
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

    if "enum_dut_feature" in metafunc.fixturenames:
        metafunc.parametrize("enum_dut_feature", generate_dut_feature_list(metafunc))

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
