import logging
import pytest
import time
import json
import uuid

import requests

from tests.common import utilities
from tests.common.dualtor.dual_tor_common import cable_type                             # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import mux_config                             # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR, TOGGLE, RANDOM, NIC, DROP, OUTPUT, FLAP_COUNTER, CLEAR_FLAP_COUNTER, RESET

__all__ = [
    'mux_server_info',
    'restart_mux_simulator',
    'mux_server_url',
    'url',
    'get_mux_status',
    'check_simulator_read_side',
    'set_output',
    'set_drop',
    'recover_all_directions',
    'reset_simulator_port',
    'toggle_all_simulator_ports_to_upper_tor',
    'toggle_all_simulator_ports_to_lower_tor',
    'toggle_all_simulator_ports_to_another_side',
    'toggle_all_simulator_ports_to_random_side',
    'toggle_simulator_port_to_upper_tor',
    'toggle_simulator_port_to_lower_tor',
    'toggle_all_simulator_ports',
    ]

logger = logging.getLogger(__name__)

TOGGLE_SIDES = [UPPER_TOR, LOWER_TOR, TOGGLE, RANDOM]


@pytest.fixture(scope='session')
def mux_server_info(request, tbinfo):
    """Fixture for getting ip, port  and vmset_name of mux simulator server

    Args:
        request (obj): Pytest request object
        tbinfo (dict): Testbed info

    Returns:
        tuple: Tuple with items: ip, port, vmset_name. For non-dualtor testbed, returns None, None, None
    """
    if 'dualtor' in tbinfo['topo']['name']:
        server = tbinfo['server']
        vmset_name = tbinfo['group-name']

        inv_files = request.config.option.ansible_inventory
        ip = utilities.get_test_server_vars(inv_files, server).get('ansible_host')
        _port_map = utilities.get_group_visible_vars(inv_files, server).get('mux_simulator_http_port')
        port = _port_map[tbinfo['conf-name']]
        return ip, port, vmset_name
    return None, None, None


@pytest.fixture(scope='session', autouse=True)
def restart_mux_simulator(mux_server_info, vmhost):
    """Session level fixture restart mux simulator server

    For dualtor testbed, it would be better to restart the mux simulator server to ensure that it is running in a
    healthy state before testing.

    This is a session level and auto used fixture.

    Args:
        mux_server_info (tuple): ip, port and vmset_name of mux simulator server
        vmhost (obj): The test server object.
    """
    ip, port, vmset_name = mux_server_info
    if ip is not None and port is not None and vmset_name is not None:
        vmhost.command('systemctl restart mux-simulator-{}'.format(port))
        time.sleep(5)  # Wait for the mux simulator to initialize


@pytest.fixture(scope='session')
def mux_server_url(mux_server_info):
    """
    A session level fixture to retrieve the address of mux simulator address

    Args:
        mux_server_info: A session scope fixture returns ip, port and vmset_name of mux simulator server
    Returns:
        str: The address of mux simulator server + vmset_name, like http://10.0.0.64:8080/mux/vms17-8
    """
    ip, port, vmset_name = mux_server_info
    if ip is not None and port is not None and vmset_name is not None:
        return "http://{}:{}/mux/{}".format(ip, port, vmset_name)
    return ""


@pytest.fixture(scope='module')
def url(mux_server_url, duthost, tbinfo):
    """
    A helper function is returned to make fixture accept arguments
    """
    def _url(interface_name=None, action=None):
        """
        Helper function to build an url for given port and target

        Args:
            interface_name: a str, the name of interface
                            If interface_name is none, the returned url contains no '/port/action' (For polling/toggling all ports)
                            or /mux/vms/flap_counter for retrieving flap counter for all ports
                            or /mux/vms/clear_flap_counter for clearing flap counter for given ports
            action: a str, output|drop|None. If action is None, the returned url contains no '/action'
        Returns:
            The url for posting flow update request, like http://10.0.0.64:8080/mux/vms17-8[/1/drop|output]
        """
        if not interface_name:
            if action:
                # Only for flap_counter, clear_flap_counter, or reset
                return mux_server_url + "/{}".format(action)
            return mux_server_url
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        mbr_index = mg_facts['minigraph_ptf_indices'][interface_name]
        if not action:
            return mux_server_url + "/{}".format(mbr_index)
        return mux_server_url + "/{}/{}".format(mbr_index, action)

    return _url

def _get(server_url):
    """
    Helper function for polling status from y_cable server.

    Args:
        server_url: a str, the full address of mux server, like http://10.0.0.64:8080/mux/vms17-8[/1]
    Returns:
        dict: A dict decoded from server's response.
        None: Returns None if request failed.
    """
    try:
        logger.debug('GET {}'.format(server_url))
        headers = {'Accept': 'application/json'}
        resp = requests.get(server_url, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        else:
            logger.warn("GET {} failed with {}".format(server_url, resp.text))
    except Exception as e:
        logger.warn("GET {} failed with {}".format(server_url, repr(e)))

    return None


def _post(server_url, data):
    """
    Helper function for posting data to y_cable server.

    Args:
        server_url: a str, the full address of mux server, like http://10.0.0.64:8080/mux/vms17-8[/1/drop|output]
        data: data to post {"out_sides": ["nic", "upper_tor", "lower_tor"]}
    Returns:
        True if succeed. False otherwise
    """
    try:
        server_url = '{}?reqId={}'.format(server_url, uuid.uuid4())  # Add query string param reqId for debugging
        logger.debug('POST {} with {}'.format(server_url, data))     # lgtm [py/clear-text-logging-sensitive-data]
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        resp = requests.post(server_url, json=data, headers=headers)
        logger.debug('Received response {}/{} with content {}'.format(resp.status_code, resp.reason, resp.text))
        return resp.status_code == 200
    except Exception as e:
        logger.warn("POST {} with data {} failed, err: {}".format(server_url, data, repr(e)))  # lgtm [py/clear-text-logging-sensitive-data]

    return False


@pytest.fixture(scope='function')
def set_drop(url, recover_all_directions):
    """
    A helper function is returned to make fixture accept arguments
    """
    drop_intfs = set()
    def _set_drop(interface_name, directions):
        """
        A fixture to set drop for a certain direction on a port
        Args:
            interface_name: a str, the name of interface
            directions: a list, may contain "upper_tor", "lower_tor", "nic"
        Returns:
            None.
        """
        drop_intfs.add(interface_name)
        server_url = url(interface_name, DROP)
        data = {"out_sides": directions}
        logger.info("Dropping packets to {} on {}".format(directions, interface_name))
        pytest_assert(_post(server_url, data), "Failed to set drop on {}".format(directions))

    yield _set_drop

    for intf in drop_intfs:
        recover_all_directions(intf)


@pytest.fixture(scope='function')
def set_output(url):
    """
    A helper function is returned to make fixture accept arguments
    """
    def _set_output(interface_name, directions):
        """
        Function to set output for a certain direction on a port
        Args:
            interface_name: a str, the name of interface
            directions: a list, may contain "upper_tor", "lower_tor", "nic"
        Returns:
            None.
        """
        server_url = url(interface_name, OUTPUT)
        data = {"out_sides": directions}
        pytest_assert(_post(server_url, data), "Failed to set output on {}".format(directions))

    return _set_output

@pytest.fixture(scope='module')
def toggle_simulator_port_to_upper_tor(url, tbinfo):
    """
    Returns _toggle_simulator_port_to_upper_tor to make fixture accept arguments
    """
    def _toggle_simulator_port_to_upper_tor(interface_name):
        """
        A helper function to toggle y_cable simulator ports
        Args:
            interface_name: a str, the name of interface
            target: "upper_tor" or "lower_tor"
        """
        # Skip on non dualtor testbed
        if 'dualtor' not in tbinfo['topo']['name']:
            return
        server_url = url(interface_name)
        data = {"active_side": UPPER_TOR}
        pytest_assert(_post(server_url, data), "Failed to toggle to upper_tor on interface {}".format(interface_name))

    return _toggle_simulator_port_to_upper_tor

@pytest.fixture(scope='module')
def toggle_simulator_port_to_lower_tor(url, tbinfo):
    """
    Returns _toggle_simulator_port_to_lower_tor to make fixture accept arguments
    """
    def _toggle_simulator_port_to_lower_tor(interface_name):
        """
        Function to toggle a given y_cable ports to lower_tor
        Args:
            interface_name: a str, the name of interface to control
        """
        # Skip on non dualtor testbed
        if 'dualtor' not in tbinfo['topo']['name']:
            return
        server_url = url(interface_name)
        data = {"active_side": LOWER_TOR}
        pytest_assert(_post(server_url, data), "Failed to toggle to lower_tor on interface {}".format(interface_name))

    return _toggle_simulator_port_to_lower_tor

@pytest.fixture(scope='module')
def recover_all_directions(url):
    """
    A function level fixture, will return _recover_all_directions to make fixture accept arguments
    """
    def _recover_all_directions(interface_name):
        """
        Function to recover all traffic on all directions on a certain port
        Args:
            interface_name: a str, the name of interface to control
        Returns:
            None.
        """
        server_url = url(interface_name, OUTPUT)
        data = {"out_sides": [UPPER_TOR, LOWER_TOR, NIC]}
        pytest_assert(_post(server_url, data), "Failed to set output on all directions for interface {}".format(interface_name))

    return _recover_all_directions

@pytest.fixture(scope='module')
def check_simulator_read_side(url):
    """
    A function level fixture, will return _check_simulator_read_side
    """
    def _check_simulator_read_side(interface_name):
        """
        Retrieve the current active tor from y_cable simulator server.
        Args:
            interface_name: a str, the name of interface to control
        Returns:
            1 if upper_tor is active
            2 if lower_tor is active
            -1 for exception or inconsistent status
        """
        server_url = url(interface_name)
        res = _get(server_url)
        if not res:
            return -1
        active_side = res["active_side"]
        if active_side == UPPER_TOR:
            return 1
        elif active_side == LOWER_TOR:
            return 2
        else:
            return -1

    return _check_simulator_read_side

@pytest.fixture(scope='module')
def get_active_torhost(upper_tor_host, lower_tor_host, check_simulator_read_side):
    """
    A function level fixture which returns a helper function
    """
    def _get_active_torhost(interface_name):
        active_tor_host = None
        active_side = check_simulator_read_side(interface_name)
        pytest_assert(active_side != -1, "Failed to retrieve the current active tor from y_cable simulator server")
        if active_side == 1:
            active_tor_host = upper_tor_host
        elif active_side == 2:
            active_tor_host = lower_tor_host
        return active_tor_host

    return _get_active_torhost

def _toggle_all_simulator_ports(mux_server_url, side, tbinfo):
    # Skip on non dualtor testbed
    if 'dualtor' not in tbinfo['topo']['name']:
        return
    pytest_assert(side in TOGGLE_SIDES, "Unsupported side '{}'".format(side))
    data = {"active_side": side}
    logger.info('Toggle all ports to "{}"'.format(side))
    pytest_assert(_post(mux_server_url, data), "Failed to toggle all ports to '{}'".format(side))

@pytest.fixture(scope='module')
def toggle_all_simulator_ports(mux_server_url, tbinfo):
    """
    A module level fixture to toggle all ports to specified side.
    """
    def _toggle(side):
        _toggle_all_simulator_ports(mux_server_url, side, tbinfo)
    return _toggle


@pytest.fixture
def toggle_all_simulator_ports_to_upper_tor(mux_server_url, tbinfo, cable_type):
    """
    A function level fixture to toggle all active-standby ports to upper_tor

    For this fixture to work properly, ICMP responder must be running. Please ensure that fixture run_icmp_responder
    is imported in test script. The run_icmp_responder fixture is defined in tests.common.fixtures.ptfhost_utils
    """
    if cable_type == CableType.active_standby:
        _toggle_all_simulator_ports(mux_server_url, UPPER_TOR, tbinfo)


@pytest.fixture
def toggle_all_simulator_ports_to_lower_tor(mux_server_url, tbinfo, cable_type):
    """
    A function level fixture to toggle all active-standby ports to lower_tor

    For this fixture to work properly, ICMP responder must be running. Please ensure that fixture run_icmp_responder
    is imported in test script. The run_icmp_responder fixture is defined in tests.common.fixtures.ptfhost_utils
    """
    if cable_type == CableType.active_standby:
        _toggle_all_simulator_ports(mux_server_url, LOWER_TOR, tbinfo)


def _are_muxcables_active(duthost):
    """Check if all the muxcables are active on the duthost.

    Example output of "show muxcable status --json"
        {
            "MUX_CABLE": {
                "Ethernet0": {
                    "STATUS": "active",
                    "HEALTH": "unhealthy"
                },
                "Ethernet4": {
                    "STATUS": "active",
                    "HEALTH": "unhealthy"
                },
                "Ethernet8": {
                    "STATUS": "active",
                    "HEALTH": "unhealthy"
                },
                ...
        }

    Args:
        duthost (ojb): Object for interacting with DUT.

    Returns:
        bool: True if all mux cables are active on DUT. False if not.
    """
    muxcables = json.loads(duthost.shell("show muxcable status --json")['stdout'])
    inactive_muxcables = [intf for intf, muxcable in muxcables['MUX_CABLE'].items() if muxcable['STATUS'] != 'active']
    if len(inactive_muxcables) > 0:
        logger.info('Found muxcables not active on {}: {}'.format(duthost.hostname, json.dumps(inactive_muxcables)))
        return False
    else:
        return True


@pytest.fixture
def toggle_all_simulator_ports_to_rand_selected_tor(duthosts, mux_server_url, tbinfo, rand_one_dut_hostname):
    """
    A function level fixture to toggle all ports to randomly selected tor

    For this fixture to work properly, ICMP responder must be running. Please ensure that fixture run_icmp_responder
    is imported in test script. The run_icmp_responder fixture is defined in tests.common.fixtures.ptfhost_utils
    """
    # Skip on non dualtor testbed
    if 'dualtor' not in tbinfo['topo']['name']:
        return
    logger.info("Toggling mux cable to {}".format(rand_one_dut_hostname))
    duthost = duthosts[rand_one_dut_hostname]
    dut_index = tbinfo['duts'].index(rand_one_dut_hostname)
    if dut_index == 0:
        data = {"active_side": UPPER_TOR}
    else:
        data = {"active_side": LOWER_TOR}

    # Allow retry for mux cable toggling
    for attempt in range(1, 4):
        logger.info('attempt={}, toggle active side of all muxcables to {} from mux simulator'.format(
            attempt,
            data['active_side']
        ))
        _post(mux_server_url, data)
        time.sleep(5)
        if _are_muxcables_active(duthost):
            break
    else:
        pytest_assert(False, "Failed to toggle all ports to {} from mux simulator".format(rand_one_dut_hostname))


@pytest.fixture
def toggle_all_simulator_ports_to_rand_unselected_tor(mux_server_url, tbinfo, rand_one_dut_hostname):
    """
    A function level fixture to toggle all ports to randomly unselected tor

    For this fixture to work properly, ICMP responder must be running. Please ensure that fixture run_icmp_responder
    is imported in test script. The run_icmp_responder fixture is defined in tests.common.fixtures.ptfhost_utils
    """
    # Skip on non dualtor testbed
    if 'dualtor' not in tbinfo['topo']['name']:
        return
    dut_index = tbinfo['duts'].index(rand_one_dut_hostname)
    if dut_index == 0:
        data = {"active_side": LOWER_TOR}
    else:
        data = {"active_side": UPPER_TOR}

    pytest_assert(_post(mux_server_url, data), "Failed to toggle all ports to the randomly unselected tor, the counterpart of {}".format(rand_one_dut_hostname))


@pytest.fixture
def toggle_all_simulator_ports_to_another_side(mux_server_url, tbinfo):
    """
    A function level fixture to toggle all ports to another side
    For example, if the current active side for a certain port is upper_tor,
    then it will be toggled to lower_tor.

    For this fixture to work properly, ICMP responder must be running. Please ensure that fixture run_icmp_responder
    is imported in test script. The run_icmp_responder fixture is defined in tests.common.fixtures.ptfhost_utils
    """
    _toggle_all_simulator_ports(mux_server_url, TOGGLE, tbinfo)


@pytest.fixture
def toggle_all_simulator_ports_to_rand_selected_tor_m(duthosts, mux_server_url, tbinfo, rand_one_dut_hostname):
    """
    A function level fixture to toggle all ports to randomly selected tor.

    Before toggling, this fixture firstly sets all muxcables to 'manual' mode on all ToRs.
    After test is done, restore all mux cables to 'auto' mode on all ToRs in teardown phase.
    """
    # Skip on non dualtor testbed
    if 'dualtor' not in tbinfo['topo']['name']:
        yield
        return

    logger.info('Set all muxcable to manual mode on all ToRs')
    duthosts.shell('config muxcable mode manual all')

    logger.info("Toggling mux cable to {}".format(rand_one_dut_hostname))
    duthost = duthosts[rand_one_dut_hostname]
    dut_index = tbinfo['duts'].index(rand_one_dut_hostname)
    if dut_index == 0:
        data = {"active_side": UPPER_TOR}
    else:
        data = {"active_side": LOWER_TOR}

    # Allow retry for mux cable toggling
    for attempt in range(1, 4):
        logger.info('attempt={}, toggle active side of all muxcables to {} from mux simulator'.format(
            attempt,
            data['active_side']
        ))
        _post(mux_server_url, data)
        utilities.wait(5, 'Wait for DUT muxcable status to update after toggled from mux simulator')
        if _are_muxcables_active(duthost):
            break
    else:
        pytest_assert(False, "Failed to toggle all ports to {} from mux simulator".format(rand_one_dut_hostname))

    yield

    logger.info('Set all muxcable to auto mode on all ToRs')
    duthosts.shell('config muxcable mode auto all')


@pytest.fixture
def toggle_all_simulator_ports_to_random_side(duthosts, mux_server_url, tbinfo, mux_config):
    """
    A function level fixture to toggle all ports to a random side.
    """
    def _get_mux_status(duthost):
        cmd = 'show mux status --json'
        return json.loads(duthost.shell(cmd)['stdout'])

    def _check_mux_status_consistency():
        """Ensure mux status is consistent between the ToRs and mux simulator."""
        upper_tor_mux_status = _get_mux_status(upper_tor_host)
        lower_tor_mux_status = _get_mux_status(lower_tor_host)
        simulator_mux_status = _get(mux_server_url)

        if not upper_tor_mux_status:
            logging.warn("Failed to retrieve mux status from the upper tor")
            return False
        if not lower_tor_mux_status:
            logging.warn("Failed to retrieve mux status from the lower tor")
            return False
        if not simulator_mux_status:
            logging.warn("Failed to retrieve mux status from the mux simulator")
            return False

        if not set(upper_tor_mux_status.keys()) == set(lower_tor_mux_status.keys()):
            logging.warn("Ports mismatch between the upper tor and lower tor")
            return False

        # get mapping from port indices to mux status
        simulator_port_mux_status = {int(k.split('-')[-1]):v for k,v in simulator_mux_status.items()}
        for intf in upper_tor_mux_status['MUX_CABLE']:

            if mux_config[intf]["SERVER"].get("cable_type", CableType.default_type) == CableType.active_active:
                continue

            intf_index = port_indices[intf]
            if intf_index not in simulator_port_mux_status:
                logging.warn("No mux status for interface %s from mux simulator", intf)
                return False

            simulator_status = simulator_port_mux_status[intf_index]
            upper_tor_status = upper_tor_mux_status['MUX_CABLE'][intf]['STATUS']
            lower_tor_status = lower_tor_mux_status['MUX_CABLE'][intf]['STATUS']

            if upper_tor_status == 'active' and lower_tor_status == 'standby' and simulator_status['active_side'] == 'upper_tor':
                continue
            if upper_tor_status == 'standby' and lower_tor_status == 'active' and simulator_status['active_side'] == 'lower_tor':
                continue
            logging.warn(
                "For interface %s, upper tor mux status: %s, lower tor mux status: %s, simulator status: %s",
                intf, upper_tor_status, lower_tor_status, simulator_status
            )
            logging.warn("Inconsistent mux status for interface %s", intf)
            return False
        return True

    if 'dualtor' not in tbinfo['topo']['name']:
        return

    _toggle_all_simulator_ports(mux_server_url, RANDOM, tbinfo)
    upper_tor_host, lower_tor_host = duthosts[0], duthosts[1]
    mg_facts = upper_tor_host.get_extended_minigraph_facts(tbinfo)
    port_indices = mg_facts['minigraph_port_indices']
    pytest_assert(
        utilities.wait_until(30, 5, 0, _check_mux_status_consistency),
        "Mux status is inconsistent between the DUTs and mux simulator after toggle"
    )


@pytest.fixture
def simulator_server_down(set_drop, set_output):
    """
    A fixture to set drop on a given mux cable
    """
    tmp_list = []
    def _drop_helper(interface_name):
        tmp_list.append(interface_name)
        set_drop(interface_name, [UPPER_TOR, LOWER_TOR])

    yield _drop_helper
    set_output(tmp_list[0], [UPPER_TOR, LOWER_TOR])


@pytest.fixture
def simulator_flap_counter(url):
    """
    A function level fixture to retrieve mux simulator flap counter for a given interface
    """
    def _simulator_flap_counter(interface_name):
        server_url = url(interface_name, FLAP_COUNTER)
        counter = _get(server_url)
        assert(counter and len(counter) == 1)
        return list(counter.values())[0]

    return _simulator_flap_counter


@pytest.fixture
def simulator_flap_counters(url):
    """
    A function level fixture to retrieve mux simulator flap counter for all ports of a testbed
    """
    server_url = url(action=FLAP_COUNTER)
    return _get(server_url)


@pytest.fixture
def simulator_clear_flap_counter(url, duthost, tbinfo):
    """
    A function level fixture to clear mux simulator flap counter for given port(s)
    """
    def _simulator_clear_flap_counter(interface_name):
        server_url = url(action=CLEAR_FLAP_COUNTER)
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        mbr_index = mg_facts['minigraph_ptf_indices'][interface_name]
        data = {"port_to_clear": str(mbr_index)}
        pytest_assert(_post(server_url, data), "Failed to clear flap counter for all ports")

    return _simulator_clear_flap_counter


@pytest.fixture
def simulator_clear_flap_counters(url):
    """
    A function level fixture to clear mux simulator flap counter for all ports of a testbed
    """
    server_url = url(action=CLEAR_FLAP_COUNTER)
    data = {"port_to_clear": "all"}
    pytest_assert(_post(server_url, data), "Failed to clear flap counter for all ports")

@pytest.fixture(scope='module')
def reset_simulator_port(url):

    def _reset_simulator_port(interface_name=None):
        logger.warn("Resetting simulator ports {}".format('all' if interface_name is None else interface_name))
        server_url = url(interface_name=interface_name, action=RESET)
        pytest_assert(_post(server_url, {}))

    return _reset_simulator_port

@pytest.fixture
def reset_all_simulator_ports(url):

    server_url = url(action=RESET)
    pytest_assert(_post(server_url, {}))

@pytest.fixture(scope='module')
def get_mux_status(url):

    def _get_mux_status(interface_name=None):
        return _get(url(interface_name=interface_name))

    return _get_mux_status
