import sys
import os

import pytest
import csv
import yaml
import ipaddr as ipaddress

from ansible_host import AnsibleHost

pytest_plugins = ('ptf_fixtures', 'ansible_fixtures')

# Add the tests folder to sys.path, for importing the lib package
_current_file_dir = os.path.dirname(os.path.realpath(__file__))
if _current_file_dir not in sys.path:
    sys.path.append(current_file_dir)


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
                        ### skip comment line
                        continue
                    elif 'uniq-name' in key or 'conf-name' in key:
                        name = line[key]
                    elif 'ptf_ip' in key and line[key]:
                        ptfaddress = ipaddress.IPNetwork(line[key])
                        tb_prop['ptf_ip'] = str(ptfaddress.ip)
                        tb_prop['ptf_netmask'] = str(ptfaddress.netmask)
                    else:
                        tb_prop[key] = line[key]
                if name:
                    self.testbed_topo[name] = tb_prop


def pytest_addoption(parser):
    parser.addoption("--testbed", action="store", default=None, help="testbed name")
    parser.addoption("--testbed_file", action="store", default=None, help="testbed file name")


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
    from common.devices import SonicHost, Localhost

    devices = {}
    devices["localhost"] = Localhost(ansible_adhoc)
    devices["dut"] = SonicHost(ansible_adhoc, testbed["dut"], gather_facts=True)
    if "ptf" in testbed:
        devices["ptf"] = PTFHost(ansible_adhoc, testbed["ptf"])

    # In the future, we can implement more classes for interacting with other testbed devices in the lib.devices
    # module. Then, in this fixture, we can initialize more instance of the classes and store the objects in the
    # devices dict here. For example, we could have
    #       from common.devices import FanoutHost
    #       devices["fanout"] = FanoutHost(ansible_adhoc, testbed["dut"])

    return devices


@pytest.fixture(scope="module")
def duthost(ansible_adhoc, testbed):
    """
    Shortcut fixture for getting DUT host
    """

    hostname = testbed['dut']
    return AnsibleHost(ansible_adhoc, hostname)


@pytest.fixture(scope="module")
def ptfhost(ansible_adhoc, testbed):
    """
    Shortcut fixture for getting PTF host
    """

    hostname = testbed['ptf']
    return AnsibleHost(ansible_adhoc, hostname)


@pytest.fixture(scope='session')
def eos():
    """ read and yield eos configuration """
    with open('eos/eos.yml') as stream:
        eos = yaml.safe_load(stream)
        return eos
