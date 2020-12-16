import logging
import pytest
import json
import urllib2
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

TOR_A = "tor_a"
TOR_B = "tor_b"
NIC = "nic"

DROP = "drop"
OUTPUT = "output"
# Here we assume that the group name of host server starts with 'vm_host_'.
VMHOST_PREFIX = "vm_host_"
VMHOST_ADDRESS = ""

@pytest.fixture(scope='session', autouse=True)
def mux_simulator_server_address(tbinfo, localhost, duthost):
    """
    A session level fixture to retrieve the address of mux simulator address
    Args:
        tbinfo: A session level fixture
        localhost: A session level fixture
    Returns:
        str: The address (including vmset path) of mux simulator server, like http://10.0.0.64:8080/mux/vms17-8
    """
    vmhost_server_name = tbinfo['server']
    vmset_name = tbinfo['group-name']
    # We assume that if server name in testbed is server_#, then the vmhost server name is vm_host_#
    vmhost_group_name = VMHOST_PREFIX + vmhost_server_name.split('_')[-1]
    inv_mgr = localhost.host.options['inventory_manager']
    all_hosts = inv_mgr.get_hosts(pattern=vmhost_group_name)
    assert len(all_hosts) == 1
    vmhost_server = inv_mgr.get_host(all_hosts[0].get_name()).vars['ansible_host']
    vmhost_port = duthost.host.options["variable_manager"]._hostvars[all_hosts[0].get_name()]['mux_simulator_port']
    global VMHOST_ADDRESS
    VMHOST_ADDRESS = "http://{}:{}/mux/{}".format(vmhost_server, vmhost_port, vmset_name)

def _url(port, action):
    """
    Helper function to build an url for given port and target

    Args:
        port: physical port on switch, an integer starting from 1
        action: a str, either "output" or "drop"
    Returns:
        The url for posting flow update request, like http://10.0.0.64:8080/mux/vms17-8/1/drop(output)
    """
    return VMHOST_ADDRESS + "/{}/{}".format(port - 1, action)

def _post(physical_port, action, data):
    """
    Helper function for posting data to y_cable server.

    Args:
        physical_port: physical port on switch, an integer starting from 1
        action: a str, either "output" or "drop"
        data: data to post {"out_ports": ["nic", "tor_a", "tor_b"]}
    Returns:
        True if succeed. False otherwise
    """
    data = json.dumps(data).encode(encoding='utf-8')
    header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    req = urllib2.Request(url=_url(physical_port, action), data=data, headers=header)
    try:
        _ = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        try:
            err_msg = json.loads(e.read().decode())['err_msg']
            logger.warn("post request returns err. status_code = {} err_msg = {}".format(e.code, err_msg))
        except Exception:
            logger.warn("post request returns err. status_code = {}".format(e.code))
        return False
    except urllib2.URLError as e:
        logger.warn("post request returns err. err_msg = {}".format(str(e)))
        return False
    return True

def set_drop(physical_port, direction):
    """
    Function to set drop for a certain direction on a port
    Args:
        physical_port: physical port on switch, an integer starting from 1
        direction: a list, may contain "tor_a", "tor_b", "nic"
    Returns:
        None. 
    """
    data = {"out_ports": direction}
    pytest_assert(_post(physical_port, DROP, data), "Failed to set drop on {}".format(direction))

def set_output(physical_port, direction):
    """
    Function to set output for a certain direction on a port
    Args:
        physical_port: physical port on switch, an integer starting from 1
        direction: a list, may contain "tor_a", "tor_b", "nic"
    Returns:
        None. 
    """
    data = {"out_ports": direction}
    pytest_assert(_post(physical_port, OUTPUT, data), "Failed to set output on {}".format(direction))

def recover_all_directions(physical_port):
    """
    Function to recover all traffic on all directions on a certain port
    Args:
        physical_port: physical port on switch, an integer starting from 1
    Returns:
        None. 
    """
    data = {"out_ports": [TOR_A, TOR_B, NIC]}
    pytest_assert(_post(physical_port, OUTPUT, data), "Failed to set output on all directions")