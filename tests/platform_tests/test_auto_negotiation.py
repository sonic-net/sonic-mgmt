"""
Test port auto negotiation.

To save test time, the script randomly chooses 3 ports to do following test:
1. Advertise all supported speeds and expect the negotiated speed is the highest speed
2. Advertise each supported speed and expect the negotiated speed is the one configured
3. Force each supported speed and expect the operational speed is the one configured
"""
import logging
import pytest

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.platform.device_utils import list_dut_fanout_connections
from tests.common.utilities import skip_release
from tests.common.helpers.port_utils import is_sfp_speed_supported

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


def save_fanout_port_state(portinfo):
    key = "{}|{}".format(portinfo['dutname'], portinfo['port'])
    global fanout_original_port_states
    if key not in fanout_original_port_states:
        dutname, portname = portinfo['dutname'], portinfo['port']
        duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]
        speed = fanout.get_speed(fanout_port)
        auto_neg_mode = fanout.get_auto_negotiation_mode(fanout_port)
        fec_mode = duthost.get_port_fec(portname)
        fanout_original_port_states[key] = (fanout, fanout_port, speed, auto_neg_mode, fec_mode)


def skip_if_datafile_is_not_read(params):
    pytest_require(
        params['dutname'] != 'unknown',
        'required datafile is missing at metadata/autoneg-test-params.json. '
        'To create it before the tests run: py.test test_pretest -k test_update_testbed_metadata'
    )


@pytest.fixture
def enum_dut_portname_module_fixture(request):
    skip_if_datafile_is_not_read(request.param)
    save_fanout_port_state(request.param)
    return request.param


@pytest.fixture
def enum_speed_per_dutport_fixture(request):
    skip_if_datafile_is_not_read(request.param)
    save_fanout_port_state(request.param)
    return request.param


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
    for fanout, port, speed, autoneg, fec_mode in fanout_original_port_states.values():
        fanout.set_auto_negotiation_mode(port, autoneg)
        fanout.set_speed(port, speed)
        if not autoneg:
            fanout.set_port_fec(port, fec_mode)

    logger.info('Recovering port configuration for DUT...')
    for duthost in duthosts:
        config_reload(duthost)


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


SPEEDS_BY_LITERAL = 'ALL_SPEEDS_BY_ALL_LITERAL'
SPEEDS_BY_LIST = 'ALL_SPEEDS_BY_SPEEDS_LIST'


def skip_if_no_multi_speed_adv_support(fanout, port):
    multi_adv_support = fanout.os != 'eos'
    pytest_require(multi_adv_support, 'Multi-speed advertisement is not supported on a given fanout/port')


@pytest.mark.parametrize('dut_all_speeds_option', [SPEEDS_BY_LITERAL, SPEEDS_BY_LIST])
def test_auto_negotiation_advertised_speeds_all(enum_dut_portname_module_fixture, dut_all_speeds_option):
    """Test all candidate ports to advertised all supported speeds and verify:
        1. All ports are up after auto negotiation
        2. All ports are negotiated to its highest supported speeds
    """
    dutname, portname = enum_dut_portname_module_fixture['dutname'], enum_dut_portname_module_fixture['port']
    duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]
    skip_if_no_multi_speed_adv_support(fanout, fanout_port)

    logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
    success = fanout.set_auto_negotiation_mode(fanout_port, True)
    pytest_require(success, 'Failed to set autoneg mode on fanout. Fanout: {}, port: {}'.format(fanout, fanout_port))

    # Advertise all supported speeds in fanout port
    success = fanout.set_speed(fanout_port, None)
    pytest_require(
        success,
        'Failed to advertise all speeds on fanout. Fanout: {}, port: {}'.format(fanout, fanout_port)
    )

    if dut_all_speeds_option == SPEEDS_BY_LITERAL:
        all_speeds = 'all'
    else:
        all_speeds = ','.join(duthost.get_supported_speeds(portname))

    duthost.shell('config interface autoneg {} enabled'.format(dut_port))
    duthost.shell('config interface advertised-speeds {} {}'.format(dut_port, all_speeds))

    logger.info('Wait until all ports are up')
    wait_result = wait_until(
        ALL_PORT_WAIT_TIME,
        PORT_STATUS_CHECK_INTERVAL,
        0,
        check_ports_up,
        duthost,
        [portname])
    pytest_assert(wait_result, 'The port is still down')

    # Make sure ports are negotiated to the highest speed
    logger.info('Checking the actual speed is equal to highest speed')
    int_status = duthost.show_interface(command="status")["ansible_facts"]['int_status']
    common_supported_speeds = enum_dut_portname_module_fixture['speeds']
    highest_speed = max(map(lambda p: int(p), common_supported_speeds))
    actual_speed = int(int_status[dut_port]['speed'][:-1] + '000')
    pytest_assert(actual_speed == highest_speed, 'Actual speed is not the highest speed')


def test_auto_negotiation_dut_advertises_each_speed(enum_speed_per_dutport_fixture):
    """Test all candidate ports to advertised all supported speeds one by one and verify
       that the port operational status is up after auto negotiation
    """
    dutname, portname = enum_speed_per_dutport_fixture['dutname'], enum_speed_per_dutport_fixture['port']
    duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]
    skip_if_no_multi_speed_adv_support(fanout, fanout_port)

    speed = enum_speed_per_dutport_fixture['speed']
    pytest_require(
        is_sfp_speed_supported(duthost, portname, speed),
        'Speed {} is not supported for given port/SFP'.format(speed)
    )

    logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
    success = fanout.set_auto_negotiation_mode(fanout_port, True)
    pytest_require(success, 'Failed to set port autoneg on fanout port {}'.format(fanout_port))

    # Advertise all supported speeds in fanout port
    success = fanout.set_speed(fanout_port, None)
    pytest_require(success, 'Failed to advertise all speeds on fanout port {}'.format(fanout_port))

    duthost.shell('config interface autoneg {} enabled'.format(dut_port))
    duthost.shell('config interface advertised-speeds {} {}'.format(dut_port, speed))
    logger.info('Wait until the port status is up, expected speed: {}'.format(speed))
    wait_result = wait_until(
        SINGLE_PORT_WAIT_TIME,
        PORT_STATUS_CHECK_INTERVAL,
        0,
        check_ports_up,
        duthost,
        [dut_port],
        speed)
    pytest_assert(wait_result, '{} are still down'.format(dut_port))
    fanout_actual_speed = fanout.get_speed(fanout_port)
    pytest_assert(
        fanout_actual_speed == speed,
        'expect fanout speed: {}, but got {}'.format(speed, fanout_actual_speed)
    )


@pytest.mark.parametrize('dut_all_speeds_option', [SPEEDS_BY_LITERAL, SPEEDS_BY_LIST])
def test_auto_negotiation_fanout_advertises_each_speed(enum_speed_per_dutport_fixture, dut_all_speeds_option):
    """
    Test the case when DUT advertises all supported speeds while fanout advertises one speed at a time.
    Verify that the port operational status is up after auto negotiation
    """

    dutname, portname = enum_speed_per_dutport_fixture['dutname'], enum_speed_per_dutport_fixture['port']
    duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]

    logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))

    if dut_all_speeds_option == SPEEDS_BY_LITERAL:
        dut_advertised_speeds = 'all'
    else:
        dut_advertised_speeds = ','.join(duthost.get_supported_speeds(portname))

    speed = enum_speed_per_dutport_fixture['speed']
    pytest_require(
        is_sfp_speed_supported(duthost, portname, speed),
        'Speed {} is not supported for given port/SFP'.format(speed)
    )

    duthost.shell('config interface autoneg {} enabled'.format(dut_port))
    duthost.shell('config interface advertised-speeds {} {}'.format(dut_port, dut_advertised_speeds))

    success = fanout.set_auto_negotiation_mode(fanout_port, True)
    pytest_require(success, 'Failed to set port autoneg on fanout port {}'.format(fanout_port))
    success = fanout.set_speed(fanout_port, speed)
    pytest_require(success, 'Failed to advertised speeds on fanout port {}, speed {}'.format(fanout_port, speed))

    logger.info('Wait until the port status is up, expected speed: {}'.format(speed))
    wait_result = wait_until(
        SINGLE_PORT_WAIT_TIME,
        PORT_STATUS_CHECK_INTERVAL,
        0,
        check_ports_up,
        duthost,
        [dut_port],
        speed)

    pytest_assert(
        wait_result, '{} are still down. Advertised speeds: DUT = {}, fanout = {}'
        .format(dut_port, dut_advertised_speeds, speed))
    fanout_actual_speed = fanout.get_speed(fanout_port)
    pytest_assert(
        fanout_actual_speed == speed,
        'expected fanout speed: {}, but got {}'.format(speed, fanout_actual_speed)
    )


def test_force_speed(enum_speed_per_dutport_fixture):
    """Test all candidate ports to force to all supported speeds one by one and verify
       that the port operational status is up after auto negotiation
    """

    dutname, portname = enum_speed_per_dutport_fixture['dutname'], enum_speed_per_dutport_fixture['port']

    duthost, dut_port, fanout, fanout_port = all_ports_by_dut[dutname][portname]
    speed = enum_speed_per_dutport_fixture['speed']
    pytest_require(
        is_sfp_speed_supported(duthost, portname, speed),
        'Speed {} is not supported for given port/SFP'.format(speed)
    )

    FEC_FOR_SPEED = {
        25000: 'fc',
        50000: 'fc',
        100000: 'rs',
        200000: 'rs',
        400000: 'rs'
    }

    fec_mode = FEC_FOR_SPEED.get(int(speed))

    logger.info('Start test for DUT port {} and fanout port {}'.format(dut_port, fanout_port))
    # Disable auto negotiation on fanout port
    success = fanout.set_auto_negotiation_mode(fanout_port, False)
    pytest_require(success, 'Failed to set port autoneg on fanout port {}'.format(fanout_port))

    success = fanout.set_speed(fanout_port, speed)
    pytest_require(success, 'Failed to speed on fanout port {}, speed {}'.format(fanout_port, speed))

    duthost.shell('config interface autoneg {} disabled'.format(dut_port))
    duthost.shell('config interface speed {} {}'.format(dut_port, speed))
    logger.info('Wait until the port status is up, expected speed: {}'.format(speed))

    duthost.set_port_fec(dut_port, fec_mode)
    fanout.set_port_fec(fanout_port, fec_mode)

    wait_result = wait_until(
        SINGLE_PORT_WAIT_TIME,
        PORT_STATUS_CHECK_INTERVAL,
        0,
        check_ports_up,
        duthost,
        [dut_port],
        speed
    )
    pytest_assert(wait_result, '{} are still down'.format(dut_port))

    fanout_actual_speed = fanout.get_speed(fanout_port)
    pytest_assert(
        fanout_actual_speed == speed,
        'expect fanout speed: {}, but got {}'.format(speed, fanout_actual_speed)
    )
