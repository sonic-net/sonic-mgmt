import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0')
]

@pytest.mark.usefixtures('get_advanced_reboot')
def test_fast_reboot(request, get_advanced_reboot):
    '''
    Fast reboot test case is run using advacned reboot test fixture

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='fast-reboot')
    advancedReboot.runRebootTestcase()

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot(request, get_advanced_reboot):
    '''
    Warm reboot test case is run using advacned reboot test fixture

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    advancedReboot.runRebootTestcase()

@pytest.mark.usefixtures('get_advanced_reboot', 'backup_and_restore_config_db')
def test_warm_reboot_sad(request, get_advanced_reboot):
    '''
    Warm reboot with sad path

    prebootList format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'neigh_bgp_down',               # Shutdown single BGP session on remote device (VM) before reboot DUT
        'dut_bgp_down',                 # Shutdown single BGP session on DUT brefore rebooting it
        'dut_lag_down',                 # Shutdown single LAG session on DUT brefore rebooting it
        'neigh_lag_down',               # Shutdown single LAG session on remote device (VM) before reboot DUT
        'dut_lag_member_down:1:1',      # Shutdown 1 LAG member corresponding to 1 remote device (VM) on DUT
        'neigh_lag_member_down:1:1',    # Shutdown 1 LAG member on 1 remote device (VM)
        'vlan_port_down',               # Shutdown 1 vlan port (interface) on DUT
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot', 'backup_and_restore_config_db')
def test_warm_reboot_multi_sad(request, get_advanced_reboot):
    '''
    Warm reboot with multi sad path

    prebootList format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped

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
        'dut_lag_member_down:3:1',      # Shutdown 1 LAG member of 3 LAG sessions corresponding to 3 remote devices (VM)
                                        # on DUT
        'neigh_lag_member_down:2:1',    # Shutdown 1 LAG member of 2 LAG sessions on 2 remote devices (VM) (1 each)
        'vlan_port_down:4',
    ] + ([
        'dut_lag_member_down:2:{0}'.format(lagMemberCnt),
                                        # Shutdown <lag count> LAG member(s) of 2 LAG sessions corresponding to 2 remote
                                        # devices (VM) on DUT
        'neigh_lag_member_down:3:{0}'.format(lagMemberCnt),
                                        # Shutdown <lag count> LAG member(s) of 3 LAG sessions on 3 remote devices (VM)
                                        # (1 each)
    ] if advancedReboot.getTestbedType() in ['t0-64', 't0-116', 't0-64-32'] else [])

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot', 'backup_and_restore_config_db')
def test_warm_reboot_multi_sad_inboot(request, get_advanced_reboot):
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

@pytest.mark.usefixtures('get_advanced_reboot', 'backup_and_restore_config_db')
def test_warm_reboot_sad_bgp(request, get_advanced_reboot):
    '''
    Warm reboot with sad (bgp)

    prebootList format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped

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

@pytest.mark.usefixtures('get_advanced_reboot', 'backup_and_restore_config_db')
def test_warm_reboot_sad_lag_member(request, get_advanced_reboot):
    '''
    Warm reboot with sad path (lag member)

    prebootList format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    lagMemberCnt = advancedReboot.getlagMemberCnt()
    prebootList = [
        'dut_lag_member_down:3:1',      # Shutdown 1 LAG member of 3 LAG sessions corresponding to 3 remote devices (VM)
                                        # on DUT
        'neigh_lag_member_down:2:1',    # Shutdown 1 LAG member of 2 LAG sessions on 2 remote devices (VM) (1 each)
    ] + ([
        'dut_lag_member_down:2:{0}'.format(lagMemberCnt),
                                        # Shutdown <lag count> LAG member(s) of 2 LAG sessions corresponding to 2 remote
                                        # devices (VM) on DUT
        'neigh_lag_member_down:3:{0}'.format(lagMemberCnt),
                                        # Shutdown <lag count> LAG member(s) of 3 LAG sessions on 3 remote devices (VM)
                                        # (1 each)
    ] if advancedReboot.getTestbedType() in ['t0-64', 't0-116', 't0-64-32'] else [])

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot', 'backup_and_restore_config_db')
def test_warm_reboot_sad_lag(request, get_advanced_reboot):
    '''
    Warm reboot with sad path (lag)

    prebootList format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped

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

@pytest.mark.usefixtures('get_advanced_reboot', 'backup_and_restore_config_db')
def test_warm_reboot_sad_vlan_port(request, get_advanced_reboot):
    '''
    Warm reboot with sad path (vlan port)

    prebootList format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped

    @param request: Spytest commandline argument
    @param get_advanced_reboot: advanced reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'vlan_port_down:4',              # Shutdown 4 vlan ports (interfaces) on DUT
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )
