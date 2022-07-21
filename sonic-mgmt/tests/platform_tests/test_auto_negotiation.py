"""
Test port auto negotiation.

To save test time, the script randomly chooses 3 ports to do following test:
1. Advertise all supported speeds and expect the negotiated speed is the highest speed
2. Advertise each supported speed and expect the negotiated speed is the one configured
3. Force each supported speed and expect the operational speed is the one configured
"""
import logging
import pytest

from natsort import natsorted
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.dut_ports import decode_dut_port_name
from tests.common.utilities import wait_until
from tests.common.platform.device_utils import list_dut_fanout_connections
from tests.common.utilities import skip_release
from tests.common.platform.interface_utils import get_physical_port_indices

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

STATE_DB = 'STATE_DB'
STATE_PORT_TABLE_TEMPLATE = 'PORT_TABLE|{}'
STATE_PORT_FIELD_SUPPORTED_SPEEDS = 'supported_speeds'
APPL_DB = 'APPL_DB'
APPL_PORT_TABLE_TEMPLATE = 'PORT_TABLE:{}'
ALL_PORT_WAIT_TIME = 60
SINGLE_PORT_WAIT_TIME = 40
PORT_STATUS_CHECK_INTERVAL = 10

# To avoid getting candidate test ports again and again, use a global variable
# to save all candidate test ports. 
# Key: dut host name, value: a dictionary of candidate ports tuple with dut port name as key
all_ports_by_dut = {}
fanout_original_port_states = {}

@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202106

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012"])

@pytest.fixture(autouse=True)
def save_fanout_port_state(enum_dut_portname_module_fixture):
    if enum_dut_portname_module_fixture not in fanout_original_port_states:
        global fanout_original_port_states
        fanout_original_port_states[enum_dut_portname_module_fixture] = {}
        dutname,portname = decode_dut_port_name(enum_dut_portname_module_fixture)
        duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]

        speed = fanout.get_speed(fanout_port)
        auto_neg_mode = fanout.get_auto_negotiation_mode(fanout_port)
        fanout_original_port_states[enum_dut_portname_module_fixture] = (fanout, fanout_port, speed, auto_neg_mode)

@pytest.fixture(scope='module', autouse=True)
def recover_ports(duthosts, fanouthosts):
    """Module level fixture that automatically do following job:
        1. Build global candidate test ports 
        2. Save fanout port state before the test
        3. Restore fanout and DUT after test

    Args:
        duthosts: DUT object
        enum_dut_portname_module_fixture (str): DUT port name
        fanouthosts: Fanout objects
    """
    global all_ports_by_dut
    global fanout_original_port_states

    logger.info('Collecting existing port configuration for DUT and fanout...')
    for duthost in duthosts:
        # Only do the sampling when there are no candidates
        if duthost.hostname in all_ports_by_dut.keys():
            continue

        all_ports_by_dut[duthost.hostname] = {}

        all_ports_set = list_dut_fanout_connections(duthost, fanouthosts)

        for dut_port, fanout, fanout_port in all_ports_set:
            all_ports_by_dut[duthost.hostname][dut_port] = (duthost, dut_port, fanout, fanout_port)

    yield

    logger.info('Recovering port configuration for fanout...')
    for fanout, port, speed, autoneg in fanout_original_port_states.values():
        fanout.set_auto_negotiation_mode(port, autoneg)
        fanout.set_speed(port, speed)

    logger.info('Recovering port configuration for DUT...')
    for duthost in duthosts:
        config_reload(duthost)


def get_supported_speeds_for_port(duthost, dut_port_name, fanout, fanout_port_name):
    """Get supported speeds list for a given port. The supported speeds list is 
       a intersection of DUT port supported speeds, fanout port supported speeds,
       and cable supported speeds.

    Args:
        duthost: DUT object
        dut_port_name (str): DUT interface name
        fanout: Fanout object
        fanout_port_name (str): The name of fanout port which connected to the DUT port

    Returns:
        list: A sorted list of supported speed strings
    """
    dut_supported_speeds = duthost.get_supported_speeds(dut_port_name)
    if not dut_supported_speeds:
        return [duthost.get_speed(dut_port_name)]

    fanout_supported_speeds = fanout.get_supported_speeds(fanout_port_name)
    if not fanout_supported_speeds:
        return [duthost.get_speed(dut_port_name)]

    # get supported speeds for the cable
    cable_supported_speeds = get_cable_supported_speeds(duthost, dut_port_name)
    if not cable_supported_speeds:
        return [duthost.get_speed(dut_port_name)]

    logger.info('dut_supported_speeds = {}, fanout_supported_speeds = {}, cable_supported_speeds = {}'.format(
        dut_supported_speeds,
        fanout_supported_speeds,
        cable_supported_speeds
    ))
    supported_speeds = set(dut_supported_speeds) & set(fanout_supported_speeds) & set(cable_supported_speeds)
    if not supported_speeds:
        # Since the port link is up before the test, we should not hit this branch
        # However, in case we hit here, we use current actual speed as supported speed
        return [duthost.get_speed(dut_port_name)]
    
    return natsorted(supported_speeds)


def get_cable_supported_speeds(duthost, dut_port_name):
    """Get cable supported speeds. As there is no SONiC CLI to get supported speeds for
       a given cable, this function depends on vendor implementation. 
       A sample: MlnxCableSupportedSpeedsHelper.

    Args:
        duthost: DUT object
        dut_port_name (str): DUT interface name

    Returns:
        list: A list of supported speed strings
    """
    helper = get_cable_supported_speeds_helper(duthost)
    return helper.get_cable_supported_speeds(duthost, dut_port_name) if helper else None


def check_ports_up(duthost, dut_ports, expect_speed=None):
    """Check if given ports are operational up or not

    Args:
        duthost: DUT object
        dut_ports (str): DUT interface name

    Returns:
        boolean: True if all given ports are up
    """
    ports_down = duthost.interface_facts(up_ports=dut_ports)["ansible_facts"]["ansible_interface_link_down_ports"]
    show_interface_output = duthost.show_interface(command="status", up_ports=dut_ports)["ansible_facts"]
    db_ports_down = show_interface_output["ansible_interface_link_down_ports"]
    down_ports = set(ports_down) | set(db_ports_down)
    logger.info('Down ports are: {}'.format(down_ports))
    if len(down_ports) == 0:
        if expect_speed:
            int_status = show_interface_output['int_status']
            for dut_port in dut_ports:
                actual_speed = int_status[dut_port]['speed'][:-1] + '000'
                if actual_speed != expect_speed:
                    return False
        return True
    else:
        return False

@pytest.fixture(params=['ALL_SPEEDS_BY_ALL_LITERAL', 'ALL_SPEEDS_BY_SPEEDS_LIST'])
def dut_all_supported_speeds(request):
    speed_val_repr = request.param

    def get_speeds_func(duthost, port_name):
        if speed_val_repr == 'ALL_SPEEDS_BY_ALL_LITERAL':
            return 'all'
        speeds = duthost.get_supported_speeds(port_name)
        return ','.join(speeds)

    res = {}
    for dutname, candidates in all_ports_by_dut.items():
        port_speeds = {}
        for duthost, dut_port, fanout, fanout_port in candidates.values():
            port_speeds[dut_port] = get_speeds_func(duthost, dut_port)
        res[dutname] = port_speeds
    return res
    
def test_auto_negotiation_advertised_speeds_all(enum_dut_portname_module_fixture):
    """Test all candidate ports to advertised all supported speeds and verify:
        1. All ports are up after auto negotiation
        2. All ports are negotiated to its highest supported speeds
    """
    dutname, portname = decode_dut_port_name(enum_dut_portname_module_fixture)
    duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]
    logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
    # Enable auto negotiation on fanout port
    success = fanout.set_auto_negotiation_mode(fanout_port, True)
    pytest_require(success, 'Failed to set autoneg mode on fanout. Fanout: {}, port: {}'.format(fanout, fanout_port))

    # Advertise all supported speeds in fanout port
    success = fanout.set_speed(fanout_port, None)
    pytest_require(success, 'Failed to advertise all speeds on fanout. Fanout: {}, port: {}'.format(fanout, fanout_port))

    duthost.shell('config interface autoneg {} enabled'.format(dut_port))
    duthost.shell('config interface advertised-speeds {} all'.format(dut_port))

    logger.info('Wait until all ports are up')
    wait_result = wait_until(ALL_PORT_WAIT_TIME, 
                                PORT_STATUS_CHECK_INTERVAL, 
                                0, 
                                check_ports_up, 
                                duthost, 
                                [portname])
    pytest_assert(wait_result, 'Some ports are still down')

    # Make sure ports are negotiated to the highest speed
    logger.info('Checking the actual speed is equal to highest speed')
    int_status = duthost.show_interface(command="status")["ansible_facts"]['int_status']
    supported_speeds = get_supported_speeds_for_port(duthost, dut_port, fanout, fanout_port)
    logger.info('DUT port = {}, fanout port = {}, supported speeds = {}, actual speed = {}'.format(
        dut_port,
        fanout_port,
        supported_speeds,
        int_status[dut_port]['speed']
    ))
    highest_speed = supported_speeds[-1]
    actual_speed = int_status[dut_port]['speed'][:-1] + '000'
    pytest_assert(actual_speed == highest_speed, 'Actual speed is not the highest speed')

def test_auto_negotiation_dut_advertises_each_speed(enum_dut_portname_module_fixture):
    """Test all candidate ports to advertised all supported speeds one by one and verify
       that the port operational status is up after auto negotiation
    """
    dutname, portname = decode_dut_port_name(enum_dut_portname_module_fixture)
    duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]

    logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
    # Enable auto negotiation on fanout port
    success = fanout.set_auto_negotiation_mode(fanout_port, True)
    pytest_require(success, 'Failed to set port autoneg on fanout port {}'.format(fanout_port))

    # Advertise all supported speeds in fanout port
    success = fanout.set_speed(fanout_port, None)
    pytest_require(success, 'Failed to advertise all speeds on fanout port {}'.format(fanout_port))

    logger.info('Trying to get a common supported speed set among dut port, fanout port and cable')
    supported_speeds = get_supported_speeds_for_port(duthost, dut_port, fanout, fanout_port)
    pytest_require(supported_speeds, 'Ignore test for port {} due to cannot get supported speed for it'.format(dut_port))

    logger.info('Run test based on supported speeds: {}'.format(supported_speeds))
    duthost.shell('config interface autoneg {} enabled'.format(dut_port))
    for speed in supported_speeds:
        duthost.shell('config interface advertised-speeds {} {}'.format(dut_port, speed))
        logger.info('Wait until the port status is up, expected speed: {}'.format(speed))
        wait_result = wait_until(SINGLE_PORT_WAIT_TIME, 
                                PORT_STATUS_CHECK_INTERVAL, 
                                0, 
                                check_ports_up, 
                                duthost, 
                                [dut_port], 
                                speed)
        pytest_assert(wait_result, '{} are still down'.format(dut_port))
        fanout_actual_speed = fanout.get_speed(fanout_port)
        pytest_assert(fanout_actual_speed == speed, 'expect fanout speed: {}, but got {}'.format(speed, fanout_actual_speed))

def test_auto_negotiation_fanout_advertises_each_speed(enum_dut_portname_module_fixture, dut_all_supported_speeds):
    """
    Test the case when DUT advertises all supported speeds while fanout advertises one speed at a time.
    Verify that the port operational status is up after auto negotiation
    """

    dutname, portname = decode_dut_port_name(enum_dut_portname_module_fixture)
    duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]

    logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))

    dut_advertised_speeds = dut_all_supported_speeds[dutname][dut_port]
    duthost.shell('config interface autoneg {} enabled'.format(dut_port))
    duthost.shell('config interface advertised-speeds {} {}'.format(dut_port, dut_advertised_speeds))

    logger.info('Trying to get a common supported speed set among dut port, fanout port and cable')
    supported_speeds = get_supported_speeds_for_port(duthost, dut_port, fanout, fanout_port)
    pytest_require(supported_speeds, 'Ignore test for port {} due to cannot get supported speed for it'.format(dut_port))

    logger.info('Run test based on supported speeds: {}'.format(supported_speeds))
    success = fanout.set_auto_negotiation_mode(fanout_port, True)
    pytest_require(success, 'Failed to set port autoneg on fanout port {}'.format(fanout_port))
    
    for speed in supported_speeds:
        success = fanout.set_speed(fanout_port, speed)
        pytest_require(success, 'Failed to advertised speeds on fanout port {}, speed {}'.format(fanout_port, speed))

        logger.info('Wait until the port status is up, expected speed: {}'.format(speed))
        wait_result = wait_until(SINGLE_PORT_WAIT_TIME, 
                                PORT_STATUS_CHECK_INTERVAL, 
                                0, 
                                check_ports_up, 
                                duthost, 
                                [dut_port], 
                                speed)

        pytest_assert(wait_result, '{} are still down. Advertised speeds: DUT = {}, fanout = {}'
            .format(dut_port, dut_advertised_speeds, speed))
        fanout_actual_speed = fanout.get_speed(fanout_port)
        pytest_assert(fanout_actual_speed == speed, 'expected fanout speed: {}, but got {}'.format(speed, fanout_actual_speed))

def test_force_speed(enum_dut_portname_module_fixture):
    """Test all candidate ports to force to all supported speeds one by one and verify
       that the port operational status is up after auto negotiation
    """

    dutname, portname = decode_dut_port_name(enum_dut_portname_module_fixture)
    duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]

    logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
    # Disable auto negotiation on fanout port
    success = fanout.set_auto_negotiation_mode(fanout_port, False)
    pytest_require(success, 'Failed to set port autoneg on fanout port {}'.format(fanout_port))

    logger.info('Trying to get a common supported speeds set among dut port, fanout port and cable')
    supported_speeds = get_supported_speeds_for_port(duthost, dut_port, fanout, fanout_port)
    pytest_require(supported_speeds, 'Ignore test for port {} due to cannot get supported speed for it'.format(dut_port))

    logger.info('Run test based on supported speeds: {}'.format(supported_speeds))
    duthost.shell('config interface autoneg {} disabled'.format(dut_port))
    for speed in supported_speeds:
        success = fanout.set_speed(fanout_port, speed)
        pytest_require(success, 'Failed to speed on fanout port {}, speed {}'.format(fanout_port, speed))

        duthost.shell('config interface speed {} {}'.format(dut_port, speed))
        logger.info('Wait until the port status is up, expected speed: {}'.format(speed))
        wait_result = wait_until(SINGLE_PORT_WAIT_TIME, 
                                PORT_STATUS_CHECK_INTERVAL, 
                                0, 
                                check_ports_up, 
                                duthost, 
                                [dut_port],
                                speed)
        pytest_assert(wait_result, '{} are still down'.format(dut_port))
        fanout_actual_speed = fanout.get_speed(fanout_port)
        pytest_assert(fanout_actual_speed == speed, 'expect fanout speed: {}, but got {}'.format(speed, fanout_actual_speed))


def get_cable_supported_speeds_helper(duthost):
    """Get a cable supported speeds helper

    Args:
        duthost: DUT object

    Returns:
        object: A helper class or instance
    """
    asic_type = duthost.facts["asic_type"]

    if asic_type == "mellanox":
        return MlnxCableSupportedSpeedsHelper
    else:
        return None

class MlnxCableSupportedSpeedsHelper(object):
    # To avoid getting ports list again and again, use a class level variable to save
    # all sorted ports.
    # Key: dut host object, value: a sorted list of interface name
    sorted_ports = {}

    # Key: tuple of dut host object and interface name, value: supported speed list
    supported_speeds = {}

    device_path = None

    @classmethod
    def get_cable_supported_speeds(cls, duthost, dut_port_name):
        """Helper function to get supported speeds for a cable

        Args:
            duthost: DUT object
            dut_port_name (str): DUT interface name

        Returns:
            list: A list of supported speed strings
        """
        if (duthost, dut_port_name) in cls.supported_speeds:
            return cls.supported_speeds[duthost, dut_port_name]

        if duthost not in cls.sorted_ports:
            int_status = duthost.show_interface(command="status")["ansible_facts"]['int_status']
            ports = natsorted([port_name for port_name in int_status.keys()])
            cls.sorted_ports[duthost] = ports

        if not cls.device_path:
            cls.device_path = duthost.shell('ls /dev/mst/*_pci_cr0')['stdout'].strip()
        port_index = get_physical_port_indices(duthost, [dut_port_name]).get(dut_port_name)
        cmd = 'mlxlink -d {} -p {} | grep "Supported Cable Speed"'.format(cls.device_path, port_index)
        output = duthost.shell(cmd)['stdout'].strip()
        # Valid output should be something like "Supported Cable Speed:0x68b1f141 (100G,56G,50G,40G,25G,10G,1G)"
        logger.info('Get supported speeds for {} {}: {}'.format(duthost, dut_port_name, output))
        if not output:
            return None
        pos = output.rfind('(')
        if pos == -1:
            return None
        speeds_str = output[pos+1:-1]
        speeds = list(set([speed.split('G')[0] + '000' for speed in speeds_str.split(',')]))
        cls.supported_speeds[(duthost, dut_port_name)] = speeds
        return speeds
