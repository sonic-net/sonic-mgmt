import os
import glob
import json
import tarfile
import logging
import string
import re
import getpass

import pytest
import csv
import yaml
import jinja2
import ipaddr as ipaddress

from collections import defaultdict
from datetime import datetime
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.devices import SonicHost, Localhost
from tests.common.devices import PTFHost, EosHost, FanoutHost

logger = logging.getLogger(__name__)

pytest_plugins = ('tests.common.plugins.ptfadapter',
                  'tests.common.plugins.ansible_fixtures',
                  'tests.common.plugins.dut_monitor',
                  'tests.common.plugins.fib',
                  'tests.common.plugins.tacacs',
                  'tests.common.plugins.loganalyzer',
                  'tests.common.plugins.psu_controller',
                  'tests.common.plugins.sanity_check',
                  'tests.common.plugins.custom_markers',
                  'tests.common.plugins.test_completeness',
                  'tests.common.plugins.log_section_start',
                  'tests.common.plugins.custom_fixtures',
                  'tests.vxlan')


class TestbedInfo(object):
    """
    Parse the CSV file used to describe whole testbed info
    Please refer to the example of the CSV file format
    CSV file first line is title
    The topology name in title is using conf-name
    """

    def __init__(self, testbed_file):
        self.testbed_filename = testbed_file
        self.testbed_topo = defaultdict()
        CSV_FIELDS = ('conf-name', 'group-name', 'topo', 'ptf_image_name', 'ptf', 'ptf_ip', 'ptf_ipv6', 'server', 'vm_base', 'dut', 'comment')

        with open(self.testbed_filename) as f:
            topo = csv.DictReader(f, fieldnames=CSV_FIELDS, delimiter=',')

            # Validate all field are in the same order and are present
            header = next(topo)
            for field in CSV_FIELDS:
                assert header[field].replace('#', '').strip() == field

            for line in topo:
                if line['conf-name'].lstrip().startswith('#'):
                    ### skip comment line
                    continue
                if line['ptf_ip']:
                    ptfaddress = ipaddress.IPNetwork(line['ptf_ip'])
                    line['ptf_ip'] = str(ptfaddress.ip)
                    line['ptf_netmask'] = str(ptfaddress.netmask)

                if line['ptf_ipv6']:
                    ptfaddress = ipaddress.IPNetwork(line['ptf_ipv6'])
                    line['ptf_ipv6'] = str(ptfaddress.ip)
                    line['ptf_netmask_v6'] = str(ptfaddress.netmask)

                line['duts'] = line['dut'].translate(string.maketrans("", ""), "[] ").split(';')
                del line['dut']

                topo = line['topo']
                del line['topo']
                line['topo'] = defaultdict()
                line['topo']['name'] = topo
                line['topo']['type'] = self.get_testbed_type(line['topo']['name'])
                with open("../ansible/vars/topo_{}.yml".format(topo), 'r') as fh:
                    line['topo']['properties'] = yaml.safe_load(fh)

                self.testbed_topo[line['conf-name']] = line

    def get_testbed_type(self, topo_name):
        pattern = re.compile(r'^(t0|t1|ptf|fullmesh)')
        match = pattern.match(topo_name)
        if match == None:
            raise Exception("Unsupported testbed type - {}".format(topo_name))
        return match.group()

def pytest_addoption(parser):
    parser.addoption("--testbed", action="store", default=None, help="testbed name")
    parser.addoption("--testbed_file", action="store", default=None, help="testbed file name")

    # test_vrf options
    parser.addoption("--vrf_capacity", action="store", default=None, type=int, help="vrf capacity of dut (4-1000)")
    parser.addoption("--vrf_test_count", action="store", default=None, type=int, help="number of vrf to be tested (1-997)")

    # qos_sai options
    parser.addoption("--ptf_portmap", action="store", default=None, type=str, help="PTF port index to DUT port alias map")

    ############################
    # pfc_asym options         #
    ############################
    parser.addoption("--server_ports_num", action="store", default=20, type=int, help="Number of server ports to use")
    parser.addoption("--fanout_inventory", action="store", default="lab", help="Inventory with defined fanout hosts")

    ############################
    # test_techsupport options #
    ############################
    parser.addoption("--loop_num", action="store", default=10, type=int,
                    help="Change default loop range for show techsupport command")
    parser.addoption("--loop_delay", action="store", default=10, type=int,
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


@pytest.fixture(scope="session")
def tbinfo(request):
    """
    Create and return testbed information
    """
    tbname = request.config.getoption("--testbed")
    tbfile = request.config.getoption("--testbed_file")
    if tbname is None or tbfile is None:
        raise ValueError("testbed and testbed_file are required!")

    testbedinfo = TestbedInfo(tbfile)
    return testbedinfo.testbed_topo[tbname]


@pytest.fixture(name="duthosts", scope="session")
def fixture_duthosts(ansible_adhoc, tbinfo):
    """
    @summary: fixture to get DUT hosts defined in testbed.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package.
        Source of the various device objects. It is
        mandatory argument for the class constructors.
    @param tbinfo: fixture provides information about testbed.
    """
    return [SonicHost(ansible_adhoc, dut) for dut in tbinfo["duts"]]


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

@pytest.fixture(scope="module", autouse=True)
def reset_critical_services_list(duthost):
    """
    Resets the critical services list between test modules to ensure that it is
    left in a known state after tests finish running.
    """

    duthost.reset_critical_services_tracking_list()

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
        for dut_port in dev_conn.keys():
            fanout_rec = dev_conn[dut_port]
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
                fanout_hosts[fanout_host] = fanout
            fanout.add_port_map(dut_port, fanout_port)
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
def creds(duthost):
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


@pytest.fixture
def collect_techsupport(request, duthost):
    yield
    # request.node is an "item" because we use the default
    # "function" scope
    testname = request.node.name
    if request.config.getoption("--collect_techsupport") and request.node.rep_call.failed:
        res = duthost.shell("generate_dump -s yesterday")
        fname = res['stdout']
        duthost.fetch(src=fname, dest="logs/{}".format(testname))
        tar = tarfile.open("logs/{}/{}/{}".format(testname, duthost.hostname, fname))
        for m in tar.getmembers():
            if m.isfile():
                tar.extract(m, path="logs/{}/{}/".format(testname, duthost.hostname))

        logging.info("########### Collected tech support for test {} ###########".format(testname))

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
def disable_container_autorestart(duthost, request):
    command_output = duthost.shell("show feature autorestart", module_ignore_errors=True)
    if command_output['rc'] != 0:
        logging.info("Feature autorestart utility not supported. Error: {}".format(command_output['stderr']))
        logging.info("Skipping disable_container_autorestart fixture")
        yield
        return
    skip = False
    for m in request.node.iter_markers():
        if m.name == "enable_container_autorestart":
            skip = True
            break
    if skip:
        yield
        return
    container_autorestart_states = duthost.get_container_autorestart_states()
    # Disable autorestart for all containers
    logging.info("Disable container autorestart")
    cmd_disable = "config feature autorestart {} disabled"
    cmds_disable = []
    for name, state in container_autorestart_states.items():
        if state == "enabled":
            cmds_disable.append(cmd_disable.format(name))
    duthost.shell_cmds(cmds=cmds_disable)
    yield
    # Recover autorestart states
    logging.info("Recover container autorestart")
    cmd_enable = "config feature autorestart {} enabled"
    cmds_enable = []
    for name, state in container_autorestart_states.items():
        if state == "enabled":
            cmds_enable.append(cmd_enable.format(name))
    duthost.shell_cmds(cmds=cmds_enable)