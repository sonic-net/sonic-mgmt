import pytest

@pytest.mark.usefixtures('get_advanced_reboot')
def test_fast_reboot(request, get_advanced_reboot):
    '''
    Fast reboot test case is run using advacned reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='fast-reboot')
    advancedReboot.runRebootTestcase()

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot(request, get_advanced_reboot):
    '''
    Warm reboot test case is run using advacned reboot test fixture
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    advancedReboot.runRebootTestcase()

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot_sad(request, get_advanced_reboot):
    '''
    Warm reboot with sad path

    preboot_list format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'neigh_bgp_down',
        'dut_bgp_down',
        'dut_lag_down',
        'neigh_lag_down',
        'dut_lag_member_down:1:1',
        'neigh_lag_member_down:1:1',
        'vlan_port_down',
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot_multi_sad(request, get_advanced_reboot):
    '''
    Warm reboot with multi sad path

    preboot_list format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    lagMemberCnt = advancedReboot.getlagMemberCnt()
    prebootList = [
        'neigh_bgp_down:2',
        'dut_bgp_down:3',
        'dut_lag_down:2',
        'neigh_lag_down:3',
        'dut_lag_member_down:3:1',
        'neigh_lag_member_down:2:1',
        'vlan_port_down:4',
    ] + ([
        'dut_lag_member_down:2:{0}'.format(lagMemberCnt),
        'neigh_lag_member_down:3:{0}'.format(lagMemberCnt),
    ] if advancedReboot.getTestbedType() in ['t0-64', 't0-116', 't0-64-32'] else [])

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot_multi_sad_inboot(request, get_advanced_reboot):
    '''
    Warm reboot with multi sad path (during boot)

    inboot list format: 'inboot_oper:route_cnt'
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    inbootList = [
        'routing_del:50',
        'routing_add:50',
    ]

    advancedReboot.runRebootTestcase(
        inbootList=inbootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot_sad_bgp(request, get_advanced_reboot):
    '''
    Warm reboot with sad (bgp)

    preboot_list format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'neigh_bgp_down:2',
        'dut_bgp_down:3',
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot_sad_lag_member(request, get_advanced_reboot):
    '''
    Warm reboot with sad path (lag member)

    preboot_list format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    lagMemberCnt = advancedReboot.getlagMemberCnt()
    prebootList = [
        'dut_lag_member_down:3:1',
        'neigh_lag_member_down:2:1',
    ] + ([
        'dut_lag_member_down:2:{0}'.format(lagMemberCnt),
        'neigh_lag_member_down:3:{0}'.format(lagMemberCnt),
    ] if advancedReboot.getTestbedType() in ['t0-64', 't0-116', 't0-64-32'] else [])

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot_sad_lag(request, get_advanced_reboot):
    '''
    Warm reboot with sad path (lag)

    preboot_list format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'dut_lag_down:2',
        'neigh_lag_down:3',
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )

@pytest.mark.usefixtures('get_advanced_reboot')
def test_warm_reboot_sad_vlan_port(request, get_advanced_reboot):
    '''
    Warm reboot with sad path (vlan port)

    preboot_list format is 'preboot oper type:number of VMS down:number of lag members down'.
    For non lag member cases, this parameter will be skipped
    '''
    advancedReboot = get_advanced_reboot(rebootType='warm-reboot')
    prebootList = [
        'vlan_port_down:4',
    ]

    advancedReboot.runRebootTestcase(
        prebootList=prebootList,
        prebootFiles='peer_dev_info,neigh_port_info'
    )
