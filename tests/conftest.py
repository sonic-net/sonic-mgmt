# Adding pytest base dir to Python system path.
# This is required in order to import from common package including pytest_plugins within this file.
import site
from os.path import dirname, abspath
site.addsitedir(dirname(abspath(__file__)))

import sys
import os
import glob
import json
import tarfile
import logging
import time
import string
import re

import pytest
import csv
import yaml
import ipaddr as ipaddress

from collections import defaultdict
from common.fixtures.conn_graph_facts import conn_graph_facts
from common.devices import SonicHost, Localhost, PTFHost, EosHost, FanoutHost

logger = logging.getLogger(__name__)

pytest_plugins = ('common.plugins.ptfadapter',
                  'common.plugins.ansible_fixtures',
                  'common.plugins.dut_monitor',
                  'common.plugins.fib',
                  'common.plugins.tacacs',
                  'common.plugins.loganalyzer',
                  'common.plugins.psu_controller',
                  'common.plugins.sanity_check')


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
        CSV_FIELDS = ('conf-name', 'group-name', 'topo', 'ptf_image_name', 'ptf', 'ptf_ip', 'server', 'vm_base', 'dut', 'comment')

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
        pattern = re.compile(r'^(t0|t1|ptf)')
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

    ############################
    # test_techsupport options #
    ############################
    parser.addoption("--loop_num", action="store", default=10, type=int,
                    help="Change default loop range for show techsupport command")
    parser.addoption("--loop_delay", action="store", default=10, type=int,
                    help="Change default loops delay")
    parser.addoption("--logs_since", action="store", type=int,
                    help="number of minutes for show techsupport command")

    ############################
    #   sanity_check options   #
    ############################
    parser.addoption("--skip_sanity", action="store_true", default=False,
                     help="Skip sanity check")
    parser.addoption("--allow_recover", action="store_true", default=False,
                     help="Allow recovery attempt in sanity check in case of failure")


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
def testbed_devices(ansible_adhoc, testbed, duthost):
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
        "duts" : [SonicHost(ansible_adhoc, x, gather_facts=True) for x in testbed["duts"]],
    }

    if "ptf" in testbed:
        devices["ptf"] = PTFHost(ansible_adhoc, testbed["ptf"])
    else:
        # when no ptf defined in testbed.csv
        # try to parse it from inventory
        ptf_host = duthost.host.options["inventory_manager"].get_host(duthost.hostname).get_vars()["ptf_host"]
        devices["ptf"] = PTFHost(ansible_adhoc, ptf_host)

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
def duthost(ansible_adhoc, testbed, request):
    '''
    @summary: Shortcut fixture for getting DUT host. For a lengthy test case, test case module can
              pass a request to disable sh time out mechanis on dut in order to avoid ssh timeout.
              After test case completes, the fixture will restore ssh timeout.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
        mandatory argument for the class constructors.
    @param testbed: Ansible framework testbed information
    @param request: request parameters for duthost test fixture
    '''
    stop_ssh_timeout = getattr(request.module, "pause_ssh_timeout", None)
    dut_index = getattr(request.module, "dut_index", 0)
    assert dut_index < len(testbed["duts"]), "DUT index '{0}' is out of bound '{1}'".format(dut_index, len(testbed["duts"]))

    duthost = SonicHost(ansible_adhoc, testbed["duts"][dut_index], gather_facts=True)
    if stop_ssh_timeout is not None:
        disable_ssh_timout(duthost)

    yield duthost

    if stop_ssh_timeout is not None:
        enable_ssh_timout(duthost)


@pytest.fixture(scope="module")
def localhost(ansible_adhoc):
    return Localhost(ansible_adhoc)


@pytest.fixture(scope="module")
def ptfhost(ansible_adhoc, testbed):
    if "ptf" in testbed:
        return PTFHost(ansible_adhoc, testbed["ptf"])
    else:
        # when no ptf defined in testbed.csv
        # try to parse it from inventory
        ptf_host = duthost.host.options["inventory_manager"].get_host(duthost.hostname).get_vars()["ptf_host"]
        return PTFHost(ansible_adhoc, ptf_host)


@pytest.fixture(scope="module")
def nbrhosts(ansible_adhoc, testbed, creds):
    """
    Shortcut fixture for getting VM host
    """

    vm_base = int(testbed['vm_base'][2:])
    devices = {}
    for k, v in testbed['topo']['properties']['topology']['VMs'].items():
        devices[k] = {'host': EosHost(ansible_adhoc, \
                                      "VM%04d" % (vm_base + v['vm_offset']), \
                                      creds['eos_login'], \
                                      creds['eos_password']),
                      'conf': testbed['topo']['properties']['configuration'][k]}
    return devices

@pytest.fixture(scope="module")
def fanouthosts(ansible_adhoc, conn_graph_facts, creds):
    """
    Shortcut fixture for getting Fanout hosts
    """

    dev_conn     = conn_graph_facts['device_conn'] if 'device_conn' in conn_graph_facts else {}
    fanout_hosts = {}
    for dut_port in dev_conn.keys():
        fanout_rec  = dev_conn[dut_port]
        fanout_host = fanout_rec['peerdevice']
        fanout_port = fanout_rec['peerport']
        if fanout_host in fanout_hosts.keys():
            fanout  = fanout_hosts[fanout_host]
        else:
            host_vars = ansible_adhoc().options['inventory_manager'].get_host(fanout_host).vars
            os_type = 'eos' if 'os' not in host_vars else host_vars['os']
            fanout  = FanoutHost(ansible_adhoc, os_type, fanout_host, 'FanoutLeaf', creds['fanout_admin_user'], creds['fanout_admin_password'])
            fanout_hosts[fanout_host] = fanout
        fanout.add_port_map(dut_port, fanout_port)

    return fanout_hosts

@pytest.fixture(scope='session')
def eos():
    """ read and yield eos configuration """
    with open('eos/eos.yml') as stream:
        eos = yaml.safe_load(stream)
        return eos


@pytest.fixture(scope="module")
def creds(duthost):
    """ read credential information according to the dut inventory """
    groups = duthost.host.options['inventory_manager'].get_host(duthost.hostname).get_vars()['group_names']
    logger.info("dut {} belongs to groups {}".format(duthost.hostname, groups))
    files = glob.glob("../ansible/group_vars/all/*.yml")
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
    return creds


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
