import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db
from tests.platform_tests.verify_dut_health import verify_dut_health      # lgtm[py/unused-import]
from tests.platform_tests.verify_dut_health import add_fail_step_to_reboot # lgtm[py/unused-import]

from tests.common.helpers.sad_path import (
    DutVlanMemberDown,
    NeighVlanMemberDown,
    DutLagMemberDown,
    NeighLagMemberDown,
    PhyPropsPortSelector,
    DatetimeSelector,
)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0')
]


### Tetcases to verify normal reboot procedure ###
def test_fast_reboot(request, get_advanced_reboot, verify_dut_health,
    advanceboot_loganalyzer):
    '''
    Fast reboot test case is run using advacned reboot test fixture

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='fast-reboot')
    advancedReboot.runRebootTestcase()


@pytest.mark.device_type('vs')
def test_warm_reboot(request, get_advanced_reboot, verify_dut_health,
    advanceboot_loganalyzer):
    '''
    Warm reboot test case is run using advacned reboot test fixture

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    advancedReboot.runRebootTestcase()


### Testcases to verify abruptly failed reboot procedure ###
def test_cancelled_fast_reboot(request, add_fail_step_to_reboot, verify_dut_health,
    get_advanced_reboot):
    '''
    Negative fast reboot test case to verify DUT is left in stable state
    when fast reboot procedure abruptly ends.

    @param request: Pytest request instance
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    add_fail_step_to_reboot('fast-reboot')
    advancedReboot = get_advanced_reboot(rebootType='fast-reboot', allow_fail=True)
    advancedReboot.runRebootTestcase()


@pytest.mark.device_type('vs')
def test_cancelled_warm_reboot(request, add_fail_step_to_reboot, verify_dut_health,
    get_advanced_reboot):
    '''
    Negative warm reboot test case to verify DUT is left in stable state
    when warm reboot procedure abruptly ends.

    @param request: Pytest request instance
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    add_fail_step_to_reboot('warm-reboot')
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot', allow_fail=True)
    advancedReboot.runRebootTestcase()


### Tetcases to verify reboot procedure with SAD cases ###
def test_warm_reboot_sad(request, get_advanced_reboot, verify_dut_health,
                         backup_and_restore_config_db, advanceboot_neighbor_restore,
                         duthost, fanouthosts, nbrhosts):
    '''
    Warm reboot with sad path

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'neigh_bgp_down',               # Shutdown single BGP session on remote device (VM) before reboot DUT
        'dut_bgp_down',                 # Shutdown single BGP session on DUT brefore rebooting it
        'dut_lag_down',                 # Shutdown single LAG session on DUT brefore rebooting it
        'neigh_lag_down',               # Shutdown single LAG session on remote device (VM) before reboot DUT
        # Shutdown 1 LAG member corresponding to 1 remote device (VM) on DUT
        DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(1), PhyPropsPortSelector(duthost, 1)),
        # Shutdown 1 LAG member on 1 remote device (VM)
        NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(1), PhyPropsPortSelector(duthost, 1)),
        # Shutdown 1 vlan port (interface) on DUT
        DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 1)),
        # Shutdown 1 vlan port (interface) on fanout
        NeighVlanMemberDown(duthost, fanouthosts, PhyPropsPortSelector(duthost, 1)),
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )


def test_warm_reboot_multi_sad(request, get_advanced_reboot, verify_dut_health,
                               backup_and_restore_config_db, advanceboot_neighbor_restore,
                               duthost, fanouthosts, nbrhosts):
    '''
    Warm reboot with multi sad path

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    lagMemberCnt = advancedReboot.getlagMemberCnt()
    prebootList = [
        'neigh_bgp_down:2',             # Shutdown single BGP session on 2 remote devices (VMs) before reboot DUT
        'dut_bgp_down:3',               # Shutdown 3 BGP sessions on DUT brefore rebooting it
        'dut_lag_down:2',               # Shutdown 2 LAG sessions on DUT brefore rebooting it
        'neigh_lag_down:3',             # Shutdown 1 LAG session on 3 remote devices (VMs) before reboot DUT
        # Shutdown 1 LAG member of 3 LAG sessions corresponding to 3 remote devices (VM)
        # on DUT
        DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(3), PhyPropsPortSelector(duthost, 1)),
        # Shutdown 1 LAG member of 2 LAG sessions on 2 remote devices (VM) (1 each)
        NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(2), PhyPropsPortSelector(duthost, 1)),
        DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 4)),
        NeighVlanMemberDown(duthost, fanouthosts, PhyPropsPortSelector(duthost, 4)),
    ] + ([
        # Shutdown <lag count> LAG member(s) of 2 LAG sessions corresponding to 2 remote
        # devices (VM) on DUT
        DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(2), PhyPropsPortSelector(duthost, lagMemberCnt)),
        # Shutdown <lag count> LAG member(s) of 3 LAG sessions on 3 remote devices (VM)
        # (1 each)
        NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(3), PhyPropsPortSelector(duthost, lagMemberCnt)),
    ] if advancedReboot.getTestbedType() in ['t0-64', 't0-116', 't0-64-32'] else [])

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )


def test_warm_reboot_multi_sad_inboot(request, get_advanced_reboot, verify_dut_health,
    backup_and_restore_config_db):
    '''
    Warm reboot with multi sad path (during boot)

    inboot list format: 'inboot_oper:route_cnt'

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    inbootList = [
        'routing_del:50',               # Delete 50 routes IPv4/IPv6 each (100 total) from each BGP session
        'routing_add:50',               # Add 50 routes IPv4/IPv6 each (100 total) from each BGP session
    ]

    advancedReboot.runRebootTestcase(
        inbootList=inbootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )


def test_warm_reboot_sad_bgp(request, get_advanced_reboot, verify_dut_health,
    backup_and_restore_config_db, advanceboot_neighbor_restore):
    '''
    Warm reboot with sad (bgp)

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'neigh_bgp_down:2',             # Shutdown single BGP session on 2 remote devices (VMs) before reboot DUT
        'dut_bgp_down:3',               # Shutdown 3 BGP sessions on DUT brefore rebooting it
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )


def test_warm_reboot_sad_lag_member(request, get_advanced_reboot, verify_dut_health,
                                    backup_and_restore_config_db, advanceboot_neighbor_restore,
                                    duthost, fanouthosts, nbrhosts):
    '''
    Warm reboot with sad path (lag member)

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    lagMemberCnt = advancedReboot.getlagMemberCnt()
    prebootList = [
        # Shutdown 1 LAG member of 3 LAG sessions corresponding to 3 remote devices (VM)
        # on DUT
        DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(3), PhyPropsPortSelector(duthost, 1)),
        # Shutdown 1 LAG member of 2 LAG sessions on 2 remote devices (VM) (1 each)
        NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(2), PhyPropsPortSelector(duthost, 1)),
    ] + ([
        # Shutdown <lag count> LAG member(s) of 2 LAG sessions corresponding to 2 remote
        # devices (VM) on DUT
        DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(2), PhyPropsPortSelector(duthost, lagMemberCnt)),
        # Shutdown <lag count> LAG member(s) of 3 LAG sessions on 3 remote devices (VM)
        # (1 each)
        NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(3), PhyPropsPortSelector(duthost, lagMemberCnt)),
    ] if advancedReboot.getTestbedType() in ['t0-64', 't0-116', 't0-64-32'] else [])

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )


def test_warm_reboot_sad_lag(request, get_advanced_reboot, verify_dut_health,
    backup_and_restore_config_db, advanceboot_neighbor_restore):
    '''
    Warm reboot with sad path (lag)

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'dut_lag_down:2',               # Shutdown 2 LAG sessions on DUT brefore rebooting it
        'neigh_lag_down:3',             # Shutdown 1 LAG session on 3 remote devices (VMs) before reboot DUT
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )


def test_warm_reboot_sad_vlan_port(request, get_advanced_reboot, verify_dut_health,
                                   backup_and_restore_config_db, duthost, fanouthosts):
    '''
    Warm reboot with sad path (vlan port)

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 4)),                # Shutdown 4 vlan ports (interfaces) on DUT
        NeighVlanMemberDown(duthost, fanouthosts, PhyPropsPortSelector(duthost, 4)), # Shutdown 4 vlan ports (interfaces) on fanout
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )
