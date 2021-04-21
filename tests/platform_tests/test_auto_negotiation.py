import logging
import pytest
import random

from natsort import natsorted
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.dut_ports import decode_dut_port_name
from tests.common.utilities import wait_until
from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates

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
# Key: dut host object, value: a list of candidate ports tuple
cadidate_test_ports = {}


@pytest.fixture(scope='module', autouse=True)
def recover_ports(duthosts, enum_dut_portname_module_fixture, fanouthosts):
    """Module level fixture that automatically do following job:
        1. Build global candidate test ports 
        2. Save fanout port state before the test
        3. Restor fanout and DUT after test

    Args:
        duthosts: DUT object
        enum_dut_portname_module_fixture (str): DUT port name
        fanouthosts: Fanout objects
    """
    global cadidate_test_ports
    fanout_original_port_states = {}
    dutname, portname = decode_dut_port_name(enum_dut_portname_module_fixture)
    logger.info('Collecting existing port configuration for DUT and fanout...')
    for duthost in duthosts:
        if dutname == 'unknown' or dutname == duthost.hostname:
            all_ports = build_test_candidates(duthost, fanouthosts, portname)
            # Test all ports takes too much time (sometimes more than an hour), 
            # so we choose 3 ports randomly as the cadidates ports
            cadidate_test_ports[duthost] = random.sample(all_ports, 3)
            for _, fanout, fanout_port in cadidate_test_ports[duthost]:
                auto_neg_mode = fanout.get_auto_negotiation_mode(fanout_port)
                speed = fanout.get_speed(fanout_port)
                if not fanout in fanout_original_port_states:
                    fanout_original_port_states[fanout] = {}
                fanout_original_port_states[fanout][fanout_port] = (auto_neg_mode, speed)
    
    yield

    logger.info('Recovering port configuration for fanout...')
    for fanout, port_data in fanout_original_port_states.items():
        for port, state in port_data.items():
            fanout.set_auto_negotiation_mode(port, state[0])
            fanout.set_speed(port, state[1])

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



def test_auto_negotiation_advertised_speeds_all():
    """Test all candidate ports to advertised all supported speeds and verify:
        1. All ports are up after auto negotiation
        2. All ports are negotiated to its highest supported speeds
    """
    for duthost, candidates in cadidate_test_ports.items():
        if not candidates:
            continue
        logger.info('Test candidate ports are {}'.format(candidates))
        for dut_port, fanout, fanout_port in candidates:
            logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
            # Enable auto negotiation on fanout port
            success = fanout.set_auto_negotiation_mode(fanout_port, True)
            if not success:
                # Fanout does not support set auto negotiation mode for this port
                logger.info('Ignore port {} due to fanout port {} does not support setting auto-neg mode'.format(dut_port, fanout_port))
                continue

            # Advertise all supported speeds in fanout port
            success = fanout.set_speed(fanout_port, None)
            if not success:
                # Fanout does not support set advertise speeds for this port
                logger.info('Ignore port {} due to fanout port {} does not support setting advertised speeds'.format(dut_port, fanout_port))
                continue

            duthost.shell('config interface autoneg {} enabled'.format(dut_port))
            duthost.shell('config interface advertised-speeds {} all'.format(dut_port))

        logger.info('Wait until all ports are up')
        wait_result = wait_until(ALL_PORT_WAIT_TIME, 
                                 PORT_STATUS_CHECK_INTERVAL, 
                                 check_ports_up, 
                                 duthost, 
                                 [item[0] for item in candidates])
        pytest_assert(wait_result, 'Some ports are still down')

        # Make sure all ports are negotiated to the highest speed
        logger.info('Checking the actual speed is equal to highest speed')
        int_status = duthost.show_interface(command="status")["ansible_facts"]['int_status']
        for dut_port, fanout, fanout_port in candidates:
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


def test_auto_negotiation_advertised_each_speed():
    """Test all candidate ports to advertised all supported speeds one by one and verify
       that the port operational status is up after auto negotiation
    """
    for duthost, candidates in cadidate_test_ports.items():
        if not candidates:
            continue
        logger.info('Test candidate ports are {}'.format(candidates))
        for dut_port, fanout, fanout_port in candidates:
            logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
            # Enable auto negotiation on fanout port
            success = fanout.set_auto_negotiation_mode(fanout_port, True)
            if not success:
                # Fanout does not support set auto negotiation mode for this port
                logger.info('Ignore port {} due to fanout port {} does not support setting auto-neg mode'.format(dut_port, fanout_port))
                continue

            # Advertise all supported speeds in fanout port
            success = fanout.set_speed(fanout_port, None)
            if not success:
                # Fanout does not support set advertise speeds for this port
                logger.info('Ignore port {} due to fanout port {} does not support setting advertised speeds'.format(dut_port, fanout_port))
                continue

            logger.info('Trying to get a common supported speed set among dut port, fanout port and cable')
            supported_speeds = get_supported_speeds_for_port(duthost, dut_port, fanout, fanout_port)
            if not supported_speeds:
                logger.warn('Ignore test for port {} due to cannot get supported speed for it'.format(dut_port))
                continue

            logger.info('Run test based on supported speeds: {}'.format(supported_speeds))
            duthost.shell('config interface autoneg {} enabled'.format(dut_port))
            for speed in supported_speeds:
                duthost.shell('config interface advertised-speeds {} {}'.format(dut_port, speed))
                logger.info('Wait until the port status is up, expected speed: {}'.format(speed))
                wait_result = wait_until(SINGLE_PORT_WAIT_TIME, 
                                        PORT_STATUS_CHECK_INTERVAL, 
                                        check_ports_up, 
                                        duthost, 
                                        [dut_port], 
                                        speed)
                pytest_assert(wait_result, '{} are still down'.format(dut_port))
                fanout_actual_speed = fanout.get_speed(fanout_port)
                pytest_assert(fanout_actual_speed == speed, 'expect fanout speed: {}, but got {}'.format(speed, fanout_actual_speed))


def test_force_speed():
    """Test all candidate ports to force to all supported speeds one by one and verify
       that the port operational status is up after auto negotiation
    """
    for duthost, candidates in cadidate_test_ports.items():
        if not candidates:
            continue
        logger.info('Test candidate ports are {}'.format(candidates))
        for dut_port, fanout, fanout_port in candidates:
            logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
            # Disable auto negotiation on fanout port
            success = fanout.set_auto_negotiation_mode(fanout_port, False)
            if not success:
                # Fanout does not support set auto negotiation mode for this port
                logger.info('Ignore port {} due to fanout port {} does not support setting auto-neg mode'.format(dut_port, fanout_port))
                continue

            logger.info('Trying to get a common supported speeds set among dut port, fanout port and cable')
            supported_speeds = get_supported_speeds_for_port(duthost, dut_port, fanout, fanout_port)
            if not supported_speeds:
                logger.warn('Ignore test for port {} due to cannot get supported speed for it'.format(dut_port))
                continue

            logger.info('Run test based on supported speeds: {}'.format(supported_speeds))
            duthost.shell('config interface autoneg {} disabled'.format(dut_port))
            for speed in supported_speeds:
                success = fanout.set_speed(fanout_port, speed)
                if not success:
                    logger.info('Skip speed {} because fanout does not support it'.format(speed))
                    continue
                duthost.shell('config interface speed {} {}'.format(dut_port, speed))
                logger.info('Wait until the port status is up, expected speed: {}'.format(speed))
                wait_result = wait_until(SINGLE_PORT_WAIT_TIME, 
                                        PORT_STATUS_CHECK_INTERVAL, 
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
        port_index = cls.sorted_ports[duthost].index(dut_port_name) + 1
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
        speeds =  [speed[:-1] + '000' for speed in speeds_str.split(',')]
        cls.supported_speeds[(duthost, dut_port_name)] = speeds
        return speeds
