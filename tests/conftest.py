import pytest
import csv
import ipaddr as ipaddress


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


# Here we override ansible_adhoc fixture from pytest-ansible plugin to overcome
# scope limitation issue; since we want to be able to use ansible_adhoc in module/class scope
# fixtures we have to override the scope here in global conftest.py
# Let's have it with module scope for now, so if something really breaks next test module run will have
# this fixture reevaluated
@pytest.fixture(scope='module')
def ansible_adhoc(request):
    """Return an inventory initialization method."""
    plugin = request.config.pluginmanager.getplugin("ansible")

    def init_host_mgr(**kwargs):
        return plugin.initialize(request.config, request, **kwargs)
    return init_host_mgr


# Same as for ansible_adhoc, let's have localhost fixture with session scope
# as it feels that during session run the localhost object should persist unchanged.
# Also, we have autouse=True here to force pytest to evaluate localhost fixture to overcome
# some hidden dependency between localhost and ansible_adhoc (even with default scope) (FIXME)
@pytest.fixture(scope='session', autouse=True)
def localhost(request):
    """Return a host manager representing localhost."""
    # NOTE: Do not use ansible_adhoc as a dependent fixture since that will assert specific command-line parameters have
    # been supplied.  In the case of localhost, the parameters are provided as kwargs below.
    plugin = request.config.pluginmanager.getplugin("ansible")
    return plugin.initialize(request.config, request, inventory='localhost,', connection='local',
                             host_pattern='localhost').localhost

