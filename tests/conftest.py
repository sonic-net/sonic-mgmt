import pytest
import csv
import yaml
import ipaddr as ipaddress

from loganalyzer.loganalyzer import LogAnalyzer
from ansible_host import AnsibleHost


pytest_plugins = ('ptf_fixtures', 'ansible_fixtures')


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
    parser.addoption("--disable_loganalyzer", action="store_true", default=False, help="disable loganalyzer analysis for 'loganalyzer' fixture")


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

@pytest.fixture(autouse=True)
def loganalyzer(duthost, request):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=request.node.name)
    # Add start marker into DUT syslog
    marker = loganalyzer.init()
    yield loganalyzer
    if not request.config.getoption("--disable_loganalyzer") and "disable_loganalyzer" not in request.keywords:
        # Read existed common regular expressions located with legacy loganalyzer module
        loganalyzer.load_common_config()
        # Parse syslog and process result. Raise "LogAnalyzerError" exception if: total match or expected missing match is not equal to zero
        loganalyzer.analyze(marker)
    else:
        # Add end marker into DUT syslog
        loganalyzer._add_end_marker(marker)

