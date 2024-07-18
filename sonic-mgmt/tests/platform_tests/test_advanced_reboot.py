import pytest
import logging
import random

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory         # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses            # noqa F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db    # noqa F401
from tests.common.fixtures.advanced_reboot import get_advanced_reboot           # noqa F401
from tests.platform_tests.verify_dut_health import verify_dut_health            # noqa F401
from tests.platform_tests.verify_dut_health import add_fail_step_to_reboot      # noqa F401
from tests.platform_tests.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST

from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service    # noqa F401
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip, show_muxcable_status
from tests.common.dualtor.mux_simulator_control import get_mux_status, check_mux_status, validate_check_result,\
    toggle_all_simulator_ports, toggle_simulator_port_to_upper_tor              # noqa F401
from tests.common.dualtor.constants import LOWER_TOR
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0'),
    pytest.mark.skip_check_dut_health
]

SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'

logger = logging.getLogger()


def check_if_ssd(duthost):
    try:
        output = duthost.command("lsblk -d -o NAME,ROTA")
        lines = output['stdout'].strip().split('\n')
        for line in lines[1:]:
            name, rota = line.split()
            if name.startswith('sd') and int(rota) == 0:
                return True
        return False
    except Exception as e:
        logger.error(f"Error while checking SSD: {e}")
        return False


@pytest.fixture(scope="module", params=[SINGLE_TOR_MODE, DUAL_TOR_MODE])
def testing_config(request, duthosts, rand_one_dut_hostname, tbinfo):
    testing_mode = request.param
    duthost = duthosts[rand_one_dut_hostname]
    is_ssd = check_if_ssd(duthost)
    neighbor_type = request.config.getoption("--neighbor_type")
    if duthost.facts['platform'] == 'x86_64-arista_7050cx3_32s' and not is_ssd and neighbor_type == 'eos':
        pytest.skip("skip advanced reboot tests on 7050 devices without SSD")
    if 'dualtor' in tbinfo['topo']['name']:
        if testing_mode == SINGLE_TOR_MODE:
            pytest.skip("skip SINGLE_TOR_MODE tests on Dual ToR testbeds")
        if testing_mode == DUAL_TOR_MODE:
            yield testing_mode
    else:
        if testing_mode == DUAL_TOR_MODE:
            pytest.skip("skip DUAL_TOR_MODE tests on Single ToR testbeds")
        yield testing_mode


def pytest_generate_tests(metafunc):
    input_sad_cases = metafunc.config.getoption("sad_case_list")
    input_sad_list = list()
    for input_case in input_sad_cases.split(","):
        input_case = input_case.strip()
        if input_case.lower() not in SAD_CASE_LIST:
            logging.warn(
                "Unknown SAD case ({}) - skipping it.".format(input_case))
            continue
        input_sad_list.append(input_case.lower())
    if "sad_case_type" in metafunc.fixturenames:
        sad_cases = input_sad_list
        metafunc.parametrize("sad_case_type", sad_cases, scope="module")


# Tetcases to verify normal reboot procedure ###
def test_fast_reboot(request, get_advanced_reboot, verify_dut_health,           # noqa F811
                     advanceboot_loganalyzer, capture_interface_counters):
    '''
    Fast reboot test case is run using advanced reboot test fixture

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='fast-reboot',
                                         advanceboot_loganalyzer=advanceboot_loganalyzer)
    advancedReboot.runRebootTestcase()


def test_fast_reboot_from_other_vendor(duthosts,  rand_one_dut_hostname, request,
                                       get_advanced_reboot, verify_dut_health,      # noqa F811
                                       advanceboot_loganalyzer, capture_interface_counters):
    '''
    Fast reboot test from other vendor case is run using advanced reboot test fixture

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    duthost = duthosts[rand_one_dut_hostname]
    advancedReboot = get_advanced_reboot(rebootType='fast-reboot', other_vendor_nos=True,
                                         advanceboot_loganalyzer=advanceboot_loganalyzer)
    # Before rebooting, we will flush all unnecessary databases, to mimic reboot from other vendor.
    flush_dbs(duthost)
    advancedReboot.runRebootTestcase()


@pytest.mark.device_type('vs')
def test_warm_reboot(request, testing_config, get_advanced_reboot, verify_dut_health,           # noqa F811
                     duthosts, advanceboot_loganalyzer, capture_interface_counters,
                     toggle_all_simulator_ports, enum_rand_one_per_hwsku_frontend_hostname,     # noqa F811
                     toggle_simulator_port_to_upper_tor):                                       # noqa F811
    '''
    Warm reboot test case is run using advacned reboot test fixture

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    testing_mode = testing_config
    if testing_mode == DUAL_TOR_MODE:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        toggle_all_simulator_ports(LOWER_TOR)
        check_result = wait_until(120, 10, 10, check_mux_status, duthosts, LOWER_TOR)
        validate_check_result(check_result, duthosts, get_mux_status)
        mux_list = show_muxcable_status(duthost)
        toggle_mux_size = len(mux_list) / 2
        for i in range(toggle_mux_size):
            itfs, _ = rand_selected_interface(duthost)
            # Select half of interfaces and toggle to active on upper ToR
            toggle_simulator_port_to_upper_tor(itfs)

    advancedReboot = get_advanced_reboot(rebootType='warm-reboot',
                                         advanceboot_loganalyzer=advanceboot_loganalyzer)
    advancedReboot.runRebootTestcase()


def test_warm_reboot_mac_jump(request, get_advanced_reboot, verify_dut_health,          # noqa F811
                              advanceboot_loganalyzer, capture_interface_counters):
    '''
    Warm reboot testcase with one MAC address (00-06-07-08-09-0A) jumping from
    all VLAN ports.
    Part of the warm reboot handling is to ensure there are no MAC events reported
    while warm reboot is in progress. So at the beginning of warm reboot SONIC
    instructs SAI to disable MAC learning on all the ports.
    When the warm reboot completes, SAI is communicated again for each port to enable
    MAC learning. To ensure that this is properly handled by SAI, this test case
    purposely generates new MAC learn events or MAC move events during warm reboot
    and the expected results is to only see those MAC move events after warm reboot competed.
    If for some reason SAI is not adhering to this requirement, any MAC learn events
    generated during warm reboot will cause META checker failure resulting to Orchagent crash.
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot', allow_mac_jumping=True,
                                         advanceboot_loganalyzer=advanceboot_loganalyzer)
    advancedReboot.runRebootTestcase()


# Tetcases to verify reboot procedure with SAD cases ###
@pytest.mark.device_type('vs')
def test_warm_reboot_sad(duthosts, rand_one_dut_hostname, nbrhosts, fanouthosts, vmhost, tbinfo,
                         get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,           # noqa F811
                         backup_and_restore_config_db, advanceboot_neighbor_restore,                # noqa F811
                         sad_case_type):
    '''
    Warm reboot with sad path
    @param get_advanced_reboot: Fixture located in advanced_reboot.py
    @param verify_dut_health: Fixture to run DUT health checks before and after test
    @param advanceboot_loganalyzer: Log Analyzer based log checks - syslog, sairedis, etc
    @param backup_and_restore_config_db: To ensure after every test, config_db.json is restored
    @param advanceboot_neighbor_restore: To ensure after every SAD case, the peers are restored
    @param sad_case_type: Pytest test parameterized with different SAD cases.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot',
                                         advanceboot_loganalyzer=advanceboot_loganalyzer)

    sad_preboot_list, sad_inboot_list = get_sad_case_list(
        duthost, nbrhosts, fanouthosts, vmhost, tbinfo, sad_case_type)
    advancedReboot.runRebootTestcase(
        prebootList=sad_preboot_list,
        inbootList=sad_inboot_list
    )


# Testcases to verify abruptly failed reboot procedure ###
def test_cancelled_fast_reboot(request, add_fail_step_to_reboot,            # noqa F811
                               verify_dut_health, get_advanced_reboot):     # noqa F811
    '''
    Negative fast reboot test case to verify DUT is left in stable state
    when fast reboot procedure abruptly ends.

    @param request: Pytest request instance
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    add_fail_step_to_reboot('fast-reboot')
    advancedReboot = get_advanced_reboot(
        rebootType='fast-reboot', allow_fail=True)
    advancedReboot.runRebootTestcase()


def test_cancelled_warm_reboot(request, add_fail_step_to_reboot,            # noqa F811
                               verify_dut_health, get_advanced_reboot):     # noqa F811
    '''
    Negative warm reboot test case to verify DUT is left in stable state
    when warm reboot procedure abruptly ends.

    @param request: Pytest request instance
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    add_fail_step_to_reboot('warm-reboot')
    advancedReboot = get_advanced_reboot(
        rebootType='warm-reboot', allow_fail=True)
    advancedReboot.runRebootTestcase()


def rand_selected_interface(tor):
    """Select a random interface to test."""
    server_ips = mux_cable_server_ip(tor)
    iface = str(random.choice(server_ips.keys()))
    logging.info("select DUT interface %s to test.", iface)
    return iface, server_ips[iface]


def flush_dbs(duthost):
    """
    This Function will flush all unnecessary databases, to mimic reboot from other vendor
    """
    logger.info('Flushing databases from switch')
    db_dic = {0: 'Application DB',
              1: 'ASIC DB',
              2: 'Counters DB',
              5: 'Flex Counters DB',
              6: 'State DB'
              }
    for db in list(db_dic.keys()):
        duthost.shell('redis-cli -n {} flushdb'.format(db))
