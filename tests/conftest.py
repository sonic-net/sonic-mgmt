import sys
import os
import glob
import tarfile
import logging
import time

import pytest
import csv
import yaml
import ipaddr as ipaddress

from ansible_host import AnsibleHost
from loganalyzer import LogAnalyzer
from common.sanity_check import check_critical_services, check_links_up

from common.devices import SonicHost, Localhost, PTFHost

logger = logging.getLogger(__name__)
pytest_plugins = ('ptf_fixtures',
                  'ansible_fixtures',
                  'plugins.dut_monitor.pytest_dut_monitor',
                  'fib',
                  'common.plugins.psu_controller')


class TestbedInfo(object):
    """
    Parse the CSV file used to describe whole testbed info
    Please refer to the example of the CSV file format
    CSV file first line is title
    The topology name in title is using uniq-name | conf-name
    """

    def __init__(self, testbed_file):
        self.testbed_filename = testbed_file
        self.testbed_topo = {}

        with open(self.testbed_filename) as f:
            topo = csv.DictReader(f)
            for line in topo:
                tb_prop = {}
                name = ''
                for key in line:
                    if ('uniq-name' in key or 'conf-name' in key) and '#' in line[key]:
                        continue
                    elif 'uniq-name' in key or 'conf-name' in key:
                        name = line[key]
                    elif 'ptf_ip' in key and line[key]:
                        ptfaddress = ipaddress.IPNetwork(line[key])
                        tb_prop['ptf_ip'] = str(ptfaddress.ip)
                        tb_prop['ptf_netmask'] = str(ptfaddress.netmask)
                    elif key == 'topo':
                        tb_prop['topo'] = {}
                        tb_prop['topo']['name'] = line[key]
                        with open("../ansible/vars/topo_{}.yml".format(tb_prop['topo']['name']), 'r') as fh:
                            tb_prop['topo']['properties'] = yaml.safe_load(fh)
                    else:
                        tb_prop[key] = line[key]

                if name:
                    self.testbed_topo[name] = tb_prop


def pytest_addoption(parser):
    parser.addoption("--testbed", action="store", default=None, help="testbed name")
    parser.addoption("--testbed_file", action="store", default=None, help="testbed file name")
    parser.addoption("--disable_loganalyzer", action="store_true", default=False,
                     help="disable loganalyzer analysis for 'loganalyzer' fixture")

    # test_vrf options
    parser.addoption("--vrf_capacity", action="store", default=None, type=int, help="vrf capacity of dut (4-1000)")
    parser.addoption("--vrf_test_count", action="store", default=None, type=int, help="number of vrf to be tested (1-997)")

@pytest.fixture(scope="session")
def testbed(request):
    """
    Create and return testbed information
    """
    tbname = request.config.getoption("--testbed")
    tbfile = request.config.getoption("--testbed_file")
    if tbname is None or tbfile is None:
        raise ValueError("testbed and testbed_file are required!")

    tbinfo = TestbedInfo(tbfile)
    return tbinfo.testbed_topo[tbname]


@pytest.fixture(scope="module")
def testbed_devices(ansible_adhoc, testbed):
    """
    @summary: Fixture for creating dut, localhost and other necessary objects for testing. These objects provide
        interfaces for interacting with the devices used in testing.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
        mandatory argument for the class constructors.
    @param testbed: Fixture for parsing testbed configuration file.
    @return: Return the created device objects in a dictionary
    """

    devices = {
        "localhost": Localhost(ansible_adhoc),
        "dut": SonicHost(ansible_adhoc, testbed["dut"], gather_facts=True)}

    if "ptf" in testbed:
        devices["ptf"] = PTFHost(ansible_adhoc, testbed["ptf"])
    else:
        # when no ptf defined in testbed.csv
        # try to parse it from inventory
        dut = devices["dut"]
        ptf_host = dut.host.options["inventory_manager"].get_host(dut.hostname).get_vars()["ptf_host"]
        devices["ptf"] = PTFHost(ansible_adhoc, ptf_host)

    # In the future, we can implement more classes for interacting with other testbed devices in the lib.devices
    # module. Then, in this fixture, we can initialize more instance of the classes and store the objects in the
    # devices dict here. For example, we could have
    #       from common.devices import FanoutHost
    #       devices["fanout"] = FanoutHost(ansible_adhoc, testbed["dut"])

    return devices

def disable_ssh_timout(dut):
    '''
    @summary disable ssh session on target dut
    @param dut: Ansible host DUT
    '''
    logger.info('Disabling ssh time out on dut: %s' % dut.hostname)
    dut.command("sudo sed -i 's/^ClientAliveInterval/#&/' /etc/ssh/sshd_config")
    dut.command("sudo sed -i 's/^ClientAliveCountMax/#&/' /etc/ssh/sshd_config")

    dut.command("sudo systemctl restart ssh")
    time.sleep(5)

def enable_ssh_timout(dut):
    '''
    @summary: enable ssh session on target dut
    @param dut: Ansible host DUT
    '''
    logger.info('Enabling ssh time out on dut: %s' % dut.hostname)
    dut.command("sudo sed -i '/^#ClientAliveInterval/s/^#//' /etc/ssh/sshd_config")
    dut.command("sudo sed -i '/^#ClientAliveCountMax/s/^#//' /etc/ssh/sshd_config")

    dut.command("sudo systemctl restart ssh")
    time.sleep(5)


@pytest.fixture(scope="module")
def duthost(testbed_devices, request):
    '''
    @summary: Shortcut fixture for getting DUT host. For a lengthy test case, test case module can
              pass a request to disable sh time out mechanis on dut in order to avoid ssh timeout.
              After test case completes, the fixture will restore ssh timeout.
    @param testbed_devices: Ansible framework testbed devices
    '''
    stop_ssh_timeout = getattr(request.module, "pause_ssh_timeout", None)

    duthost = testbed_devices["dut"]
    if stop_ssh_timeout is not None:
        disable_ssh_timout(duthost)

    yield duthost

    if stop_ssh_timeout is not None:
        enable_ssh_timout(duthost)

@pytest.fixture(scope="module")
def ptfhost(testbed_devices):
    """
    Shortcut fixture for getting PTF host
    """

    return testbed_devices["ptf"]


@pytest.fixture(scope='session')
def eos():
    """ read and yield eos configuration """
    with open('eos/eos.yml') as stream:
        eos = yaml.safe_load(stream)
        return eos


@pytest.fixture(autouse=True)
def loganalyzer(duthost, request):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=request.node.name)
    # Add start marker into DUT syslog
    marker = loganalyzer.init()
    yield loganalyzer
    if not request.config.getoption("--disable_loganalyzer") and "disable_loganalyzer" not in request.keywords:
        # Read existed common regular expressions located with legacy loganalyzer module
        loganalyzer.load_common_config()
        # Parse syslog and process result. Raise "LogAnalyzerError" exception if: total match or expected missing
        # match is not equal to zero
        loganalyzer.analyze(marker)
    else:
        # Add end marker into DUT syslog
        loganalyzer._add_end_marker(marker)

@pytest.fixture(scope="session")
def creds():
    """ read and yield lab configuration """
    files = glob.glob("../ansible/group_vars/lab/*.yml")
    creds = {}
    for f in files:
        with open(f) as stream:
            creds.update(yaml.safe_load(stream))
    return creds

@pytest.fixture(scope="module", autouse=True)
def base_sanity(duthost):
    """perform base sanity checks before and after each test"""

    check_critical_services(duthost)
    check_links_up(duthost)

    yield base_sanity

    check_critical_services(duthost)
    check_links_up(duthost)

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
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
    if request.node.rep_call.failed:
        res = duthost.shell("generate_dump")
        fname = res['stdout']
        duthost.fetch(src=fname, dest="logs/{}".format(testname))
        tar = tarfile.open("logs/{}/{}/{}".format(testname, duthost.hostname, fname))
        for m in tar.getmembers():
            if m.isfile():
                tar.extract(m, path="logs/{}/{}/".format(testname, duthost.hostname))

        logging.info("########### Collected tech support for test {} ###########".format(testname))
