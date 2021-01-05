import logging
import pytest
import json
import urllib2
from tests.common.helpers.assertions import pytest_assert
from tests.common import utilities

logger = logging.getLogger(__name__)

TOR_A = "tor_a"
TOR_B = "tor_b"
NIC = "nic"

DROP = "drop"
OUTPUT = "output"

@pytest.fixture(scope="session")
def mux_server_url(request, tbinfo):
    """
    A session level fixture to retrieve the address of mux simulator address
    Args:
        request: A fixture from Ansible
        tbinfo: A session level fixture
    Returns:
        str: The address of mux simulator server + vmset_name, like http://10.0.0.64:8080/mux/vms17-8
    """
    server = tbinfo['server']
    vmset_name = tbinfo['group-name']
    inv_files = request.config.option.ansible_inventory
    ip = utilities.get_test_server_vars(inv_files, server, 'ansible_host')
    port = utilities.get_group_visible_vars(inv_files, server, 'mux_simulator_port')
    return "http://{}:{}/mux/{}".format(ip, port, vmset_name)

def _url(server_url, physical_port=None, action=None):
    """
    Helper function to build an url for given port and target

    Args:
        server_url: a str, the url for mux server, like http://10.0.0.64:8080/mux/vms17-8
        physical_port: physical port on switch, an integer starting from 1
                        If physical_port is none, the returned url contains no '/port/action' (For polling/toggling all ports)
        action: a str, output|drop|None. If action is None, the returned url contains no '/action'
    Returns:
        The url for posting flow update request, like http://10.0.0.64:8080/mux/vms17-8[/1/drop|output]
    """
    if not physical_port:
        return server_url
    if not action:
        return server_url + "/{}".format(physical_port - 1)
    return server_url + "/{}/{}".format(physical_port - 1, action)

def _get(server_url):
    """
    Helper function for polling status from y_cable server.

    Args:
        server_url: a str, the full address of mux server, like http://10.0.0.64:8080/mux/vms17-8[/1]
    Returns:
        dict: A dict decoded from server's response.
        None: Returns None is error is detected.
    """
    req = urllib2.Request(url=server_url)
    try:
        res = urllib2.urlopen(req)
        data = res.read()
        return json.loads(data)
    except urllib2.HTTPError as e:
        err_msg = json.loads(e.read().decode())['err_msg']
        logger.warn("get request returns err. status_code = {} err_msg = {}".format(e.code, err_msg))
    except urllib2.URLError as e:
        logger.warn("get request returns err. err_msg = {}".format(str(e)))
    except json.decoder.JSONDecodeError as e:
        logger.warn("failed to parse response as json. err_msg = {}".format(str(e)))
    except Exception as e:
        logger.warn("get request returns err. err_msg = {}".format(str(e)))
    return None

def _post(server_url, data):
    """
    Helper function for posting data to y_cable server.

    Args:
        server_url: a str, the full address of mux server, like http://10.0.0.64:8080/mux/vms17-8[/1/drop|output]
        data: data to post {"out_ports": ["nic", "tor_a", "tor_b"]}
    Returns:
        True if succeed. False otherwise
    """
    data = json.dumps(data).encode(encoding='utf-8')
    header = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    req = urllib2.Request(url=server_url, data=data, headers=header)
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

def set_drop(mux_server_url, physical_port, directions):
    """
    A fixture to set drop for a certain direction on a port
    Args:
        mux_server_url: a str, the address of mux server
        physical_port: physical port on switch, an integer starting from 1
        directions: a list, may contain "tor_a", "tor_b", "nic"
    Returns:
        None.
    """
    server_url = _url(mux_server_url, physical_port, DROP)
    data = {"out_ports": directions}
    pytest_assert(_post(server_url, data), "Failed to set drop on {}".format(directions))

def set_output(mux_server_url, physical_port, directions):
    """
    Function to set output for a certain direction on a port
    Args:
        mux_server_url: a str, the address of mux server
        physical_port: physical port on switch, an integer starting from 1
        directions: a list, may contain "tor_a", "tor_b", "nic"
    Returns:
        None.
    """
    server_url = _url(mux_server_url, physical_port, OUTPUT)
    data = {"out_ports": directions}
    pytest_assert(_post(server_url, data), "Failed to set output on {}".format(directions))

def _simulator_port_toggle_to(mux_server_url, physical_port, target):
    """
    A helper function to toggle y_cable simulator ports
    Args:
        mux_server_url: a str, the address of mux server
        physical_port: physical port on switch, an integer starting from 1
        target: "tor_a" or "tor_b"
    """
    server_url = _url(mux_server_url, physical_port)
    data = {"active_side": target}
    pytest_assert(_post(server_url, data), "Failed to toggle to {} on port {}".format(target, physical_port))

def toggle_simulator_port_to_tor_a(mux_server_url, physical_port):
    """
    Function to toggle a given y_cable ports to tor_a
    Args:
        mux_server_url: a str, the address of mux server
        physical_port: physical port on switch, an integer starting from 1
    """
    _simulator_port_toggle_to(mux_server_url, physical_port, TOR_A)

def toggle_simulator_port_to_tor_b(mux_server_url, physical_port):
    """
    Function to toggle a given y_cable ports to tor_b
    Args:
        mux_server_url: a str, the address of mux server
        physical_port: physical port on switch, an integer starting from 1
    """
    _simulator_port_toggle_to(mux_server_url, physical_port, TOR_B)

def recover_all_directions(mux_server_url, physical_port):
    """
    Function to recover all traffic on all directions on a certain port
    Args:
        mux_server_url: a str, the address of mux server
        physical_port: physical port on switch, an integer starting from 1
    Returns:
        None.
    """
    server_url = _url(mux_server_url, physical_port, OUTPUT)
    data = {"out_ports": [TOR_A, TOR_B, NIC]}
    pytest_assert(_post(server_url, data), "Failed to set output on all directions")

def check_simulator_read_side(mux_server_url, physical_port):
    """
    Retrieve the current active tor from y_cable simulator server.
    Args:
        mux_server_url: a str, the address of mux server
        physical_port: physical port on switch, an integer starting from 1
    Returns:
        1 if TOR_A is active
        2 if TOR_B is active
        -1 for exception or inconstient status
    """
    server_url = _url(mux_server_url, physical_port)
    res = _get(server_url)
    if not res:
        return -1
    active_side = res["active_side"]
    if active_side == TOR_A:
        return 1
    elif active_side == TOR_B:
        return 2
    else:
        return -1

@pytest.fixture(scope='module')
def toggle_all_simulator_ports_to_tor_a(mux_server_url):
    """
    A module level fixture to toggle all ports to tor_a
    """
    server_url = _url(mux_server_url)
    data = {"active_side": TOR_A}
    pytest_assert(_post(server_url, data), "Failed to toggle all ports to TOR A")

@pytest.fixture(scope='module')
def toggle_all_simulator_ports_to_tor_b(mux_server_url):
    """
    A module level fixture to toggle all ports to tor_b
    """
    server_url = _url(mux_server_url)
    data = {"active_side": TOR_B}
    pytest_assert(_post(server_url, data), "Failed to toggle all ports to TOR A")

@pytest.fixture(scope='module')
def toggle_all_simulator_ports_to_another_side(mux_server_url):
    """
    A module level fixture to toggle all ports to another side
    For example, if the current active side for a certain port is tor_a,
    then it will be toggled to tor_b.
    """
    server_url = _url(mux_server_url)
    data = {"active_side": "toggle"}
    pytest_assert(_post(server_url, data), "Failed to toggle all ports to another side")

@pytest.fixture(scope='module')
def toggle_all_simulator_ports_to_random_side(mux_server_url):
    """
    A module level fixture to toggle all ports to a random side.
    """
    server_url = _url(mux_server_url)
    data = {"active_side": "random"}
    pytest_assert(_post(server_url, data), "Failed to toggle all ports to random side")

