#############################################################################
#Script Title : BGP BFD with default and non default vrf for Single Hop
#Author       : Sooriya G
#Mail-id      : sooriya.gajendrababu@broadcom.com
#############################################################################

import pytest
from spytest import st, utils, SpyTestDict, tgapi
from spytest.tgen.tg import tgen_obj_dict
from apis.routing import ip as ip_api
from apis.routing import bfd
from apis.routing import arp
from apis.system import port
from apis.switching import vlan as vlan_api
from bfd_vars import *
from apis.system import basic
from apis.routing import ip_bgp
from apis.routing import bgp as bgp_api
import apis.system.reboot as reboot_api
import apis.routing.vrf as vrf_api
from utilities import parallel

data = SpyTestDict()
data.streams= {}

@pytest.fixture(scope="module", autouse=True)
def prologue_epilogue(request):
    global vars, tg1, tg2, dut1, dut2, dut3, D1_ports, D2_ports, D3_ports, flap_dut, flap_ports, tg_handles, D1_ports_vrf, D2_ports_vrf, D3_ports_vrf, flap_dut_vrf, flap_ports_vrf, tg_handles_vrf
    vars = st.ensure_min_topology("D1D2:6", "D1T1:2", "D2T1:2")
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    dut1 = vars.dut_list[0]
    if l2_switch == 'yes':
        dut2 = vars.dut_list[1]
        dut3 = vars.dut_list[2]
        D1_ports = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1T1P1]
        D2_ports = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D3P1, vars.D2D3P2, vars.D2D3P3]
        D3_ports = [vars.D3D2P1, vars.D3D2P2, vars.D3D2P3, vars.D3T1P1]
        flap_dut = dut2
        flap_ports = [vars.D2D3P1, vars.D2D3P2, vars.D2D3P3]
        tg_handles = [tg1.get_port_handle(vars.T1D1P1), tg1.get_port_handle(vars.T1D3P1)]
        D1_ports_vrf = [vars.D1D2P4, vars.D1D2P5, vars.D1D2P6, vars.D1T1P2]
        D2_ports_vrf = [vars.D2D1P4, vars.D2D1P5, vars.D2D1P6, vars.D2D3P4, vars.D2D3P5, vars.D2D3P6]
        D3_ports_vrf = [vars.D3D2P4, vars.D3D2P5, vars.D3D2P6, vars.D3T1P2]
        flap_dut_vrf = dut2
        flap_ports_vrf = [vars.D2D3P4, vars.D2D3P5, vars.D2D3P6]
        tg_handles_vrf = [tg2.get_port_handle(vars.T1D1P2), tg2.get_port_handle(vars.T1D3P2)]
    else:
        dut3 = vars.dut_list[1]
        D1_ports = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1T1P1]
        D3_ports = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2T1P1]
        flap_dut = dut3
        flap_ports = D3_ports[0:-1]
        tg_handles = [tg1.get_port_handle(vars.T1D1P1), tg1.get_port_handle(vars.T1D2P1)]
        D1_ports_vrf = [vars.D1D2P4, vars.D1D2P5, vars.D1D2P6, vars.D1T1P2]
        D3_ports_vrf = [vars.D2D1P4, vars.D2D1P5, vars.D2D1P6, vars.D2T1P2]
        flap_dut_vrf = dut3
        flap_ports_vrf = D3_ports_vrf[0:-1]
        tg_handles_vrf = [tg2.get_port_handle(vars.T1D1P2), tg2.get_port_handle(vars.T1D2P2)]

    for dut in vars.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)
    single_hop_config()
    yield
    single_hop_deconfig()

@pytest.fixture(scope="function")
def bfd_fixture_003(request,prologue_epilogue):
    # add things at the start every test case
    # use 'request.function.func_name' to compare
    # if any thing specific a particular test case
    yield


@pytest.mark.sanity
def test_FtOpSoRoBfdFn003_12_10_15_51_53_54(bfd_fixture_003):
    hdrMsg("TCid: FtOpSoRoBfdFn003,FtOpSoRoBfdFn012,FtOpSoRoBfdFn010,FtOpSoRoBfdFn015,"
           "FtOpSoRoBfdFn053,FtOpSoRoBfdFn054"
           ";TC SUMMARY : Verify IPv4/IPv6 BFD on iBGP neighborship in Spine to leaf topology ")
    ###########################################################################################
    hdrMsg("Sub-TC01: Verify BFD on trunk port ")
    ###########################################################################################

    result = verify_bfd_func_001(mode='trunk')
    if result:
        st.log("BFD functionality on Trunk port passed")
    else:
        st.report_fail('bfd_fail_tc','trunk','ipv4/ipv6')

    st.report_pass('test_case_passed')


@pytest.mark.sanity
def test_singlehop_bfd_vrf_functionality(bfd_fixture_003):
    '''
    Author      : vishnuvardhan t
    Mail-id     : vishnuvardhan.talluri@broadcom.com
    Test bed    : 1*TGEN ports--- D1---3 links-------D2--------1*TGEN ports
    Description : Verify IPv4/IPv6 single hop BFD VRF functionality on iBGP on the Spine to leaf topology
    :param prologue_epilogue:
    :return:
    '''

    hdrMsg("TC SUMMARY : Verify IPv4/IPv6 BFD VRF on iBGP functionality in Spine to leaf topology ")
    ###########################################################################################
    hdrMsg("Sub-TC01_VRF: Verify BFD on trunk port ")
    ###########################################################################################
    result = verify_singlehop_bfd_vrf_functionality()
    if result:
        st.log("BFD VRF functionality on Trunk port passed")
    else:
        st.report_fail('bfd_fail_tc', 'VRF on trunk', 'ipv4/ipv6')

    st.report_pass('test_case_passed')



@pytest.fixture(scope="function")
def bfd_fixture_vrf_session_timeout(request,prologue_epilogue):
    # add things at the start every test case
    # use 'request.function.func_name' to compare
    # if any thing specific a particular test case
    yield
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, \
    peer_v4, peer_v6, flap_ports = return_vars(user_vrf_name)
    hdrMsg("### CLEANUP for TC ###")
    access_vlan_name = access_vlan_name_vrf

    dict1 ={'vrf_name': user_vrf_name,"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ip_list[1],dut3_ipv6_list[0],dut3_ipv6_list[1]],'config':'no'}
    dict2 ={'vrf_name': user_vrf_name,"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ip_list[1],dut1_ipv6_list[0],dut1_ipv6_list[1]],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1 = {'vrf_name': user_vrf_name,"interface": access_vlan_name, 'neighbor_ip': dut3_ip_list[0], 'config': 'no'}
    dict2 = {'vrf_name': user_vrf_name,"interface": access_vlan_name, 'neighbor_ip': dut1_ip_list[0], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name,"interface": access_vlan_name, 'neighbor_ip': dut3_ipv6_list[0],'local_address':dut1_ipv6_list[0] ,'config': 'no'}
    dict2 = {'vrf_name': user_vrf_name,"interface": access_vlan_name, 'neighbor_ip': dut1_ipv6_list[0], 'local_address':dut3_ipv6_list[0],'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

@pytest.mark.sanity
def test_singlehop_bfd_vrf_session_timeout(bfd_fixture_vrf_session_timeout):
    '''
    Author      : vishnuvardhan t
    Mail-id     : vishnuvardhan.talluri@broadcom.com
    Description : Verify IPv4/IPv6 single hop BFD VRF session timeout when bfd is shutdown on Spine to leaf topology
    :param prologue_epilogue:
    :return:
    '''

    result = verify_FtOpSoRoBfdFn055_52_56_57_21(vrfname=user_vrf_name)
    if result:
        st.log("static BFD VRF functionality is passed")
    else:
        st.report_fail('bfd_fail_tc', 'VRF when BFD configured statically', 'ipv4/ipv6')

    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def bfd_fixture_007(request,prologue_epilogue):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP for TC7 ###")

    dict1 ={"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ip_list[1],dut3_ipv6_list[0],dut3_ipv6_list[1]],'config':'no'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ip_list[1],dut1_ipv6_list[0],dut1_ipv6_list[1]],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1 = {"interface": access_vlan_name, 'neighbor_ip': dut3_ip_list[0], 'config': 'no'}
    dict2 = {"interface": access_vlan_name, 'neighbor_ip': dut1_ip_list[0], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {"interface": access_vlan_name, 'neighbor_ip': dut3_ipv6_list[0],'local_address':dut1_ipv6_list[0] ,'config': 'no'}
    dict2 = {"interface": access_vlan_name, 'neighbor_ip': dut1_ipv6_list[0], 'local_address':dut3_ipv6_list[0],'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    hdrMsg("### CLEANUP End####")


def verify_FtOpSoRoBfdFn055_52_56_57_21(vrfname='default'):
    '''
    Verify API for test cases test_FtOpSoRoBfdFn055_52_56_57_21 and test_singlehop_static_bfd_vrf_functionality
    :param vrf_name:
    :return: result
    '''

    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, \
    peer_v4, peer_v6, flap_ports = return_vars(vrfname)

    result = True

    ###########################################################################################
    hdrMsg("Step T1: Configure BFD for ipv4 and ipv6 BGP neighbors on dut1 and dut3")
    ###########################################################################################

    dict1 = {'vrf_name': vrfname,"local_asn": dut1_as,
             'neighbor_ip': [dut3_ip_list[0], dut3_ip_list[1], dut3_ipv6_list[0], dut3_ipv6_list[1]], 'config': 'yes'}
    dict2 = {'vrf_name': vrfname,"local_asn": dut3_as,
             'neighbor_ip': [dut1_ip_list[0], dut1_ip_list[1], dut1_ipv6_list[0], dut1_ipv6_list[1]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    result = retry_api(bfd.verify_bfd_peer,dut1,peer=dut3_ip_list[0:2]+dut3_ipv6_list[0:2],status=['up']*4,
                                 rx_interval=[['300','300'],['300','300']]*2, vrf_name= vrfname,
                                 tx_interval = [['300', '300'], ['300','300']] * 2,retry_count=5,delay=1)
    ###########################################################################################
    hdrMsg("Step T2: Configure different non-default BFD timer values to each peer on both dut1 and dut3")
    ###########################################################################################

    dict1 = {'vrf_name': vrfname,"interface": [access_vlan_name,D1_ports[1]], 'neighbor_ip': dut3_ip_list[0], 'multiplier':['3'],'rx_intv':['150'],'tx_intv':['150']}
    dict2 = {'vrf_name': vrfname,"interface": [access_vlan_name,D3_ports[1]], 'neighbor_ip': dut1_ip_list[0], 'multiplier':['3'],'rx_intv':['150'],'tx_intv':['150']}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname,"interface": [access_vlan_name,D1_ports[1]], 'local_address':dut1_ipv6_list[0], 'neighbor_ip': dut3_ipv6_list[0], 'multiplier':['2'],'rx_intv':['150'],'tx_intv':['150']}
    dict2 = {'vrf_name': vrfname,"interface": [access_vlan_name,D3_ports[1]], 'local_address':dut3_ipv6_list[0], 'neighbor_ip': dut1_ipv6_list[0], 'multiplier':['3'],'rx_intv':['150'],'tx_intv':['150']}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])


    ###########################################################################################
    hdrMsg("Step T3: Verify Show BFD peers have updated with configured timer intervals for each peer")
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer,dut1,peer=dut3_ip_list[0:2]+dut3_ipv6_list[0:2],status=['up']*4,
                                 rx_interval=[['150','150'],['300','300']]*2, vrf_name= vrfname,
                                 tx_interval = [['150', '150'], ['300','300']] * 2,retry_count=5,delay=1)
    if result is False:
        st.log('bfd_peer_params failed for {}'.format(dut1))
        basic.get_techsupport(filename='FtOpSoRoBfdFn055_52_56_57_21')

    ###########################################################################################
    hdrMsg("Step T4: Do BFD shutdown under BFD for %s and verify BGP BFD sessions for %s didnot go down "%(dut3_ip_list[0],dut3_ipv6_list[0]))
    ###########################################################################################
    bfd.configure_bfd(dut1,interface=access_vlan_name,neighbor_ip=dut3_ip_list[0],shutdown='', vrf_name=vrfname)

    st.log("Verify only ipv4 BFD peer goes down and ipv6 on same interface is UP")
    result1 = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_ip_list[0],state='Established',vrf=vrfname)
    result2 = bfd.verify_bfd_peer(dut1, peer=dut3_ip_list[0], interface=access_vlan_name, status=['shutdown'], vrf_name=vrfname)
    if result1 != result2:
        st.log('bgp_bfd_params failed for DUT {} for ip list {} for {}'.format(dut1, dut3_ip_list[0], vrfname))
        result = False

    result1 = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_ipv6_list[0], state='Established', vrf=vrfname)
    result2 = bfd.verify_bfd_peer(dut1, peer=dut3_ipv6_list[0], interface=access_vlan_name, status=['up'], vrf_name=vrfname)
    if result1 != result2:
        st.log('bgp_bfd_params  failed for DUT {} for ip list {} for {}'.format(dut1, dut3_ipv6_list[0], vrfname))
        result = False

    st.log("Bring BFD peer %s also down and verify BGP session goes down"%dut3_ipv6_list[0])
    bfd.configure_bfd(dut1, interface=access_vlan_name,local_address=dut1_ipv6_list[0],neighbor_ip=dut3_ipv6_list[0], shutdown='', vrf_name=vrfname)

    result1 = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_ipv6_list[0], state='Established', vrf=vrfname)
    result2 = bfd.verify_bfd_peer(dut1, peer=dut3_ipv6_list[0], interface=access_vlan_name, status=['shutdown'], vrf_name=vrfname)
    if result1 != result2:
        st.log('bgp_bfd_params failed for DUT {} for ip list {} for {}'.format(dut1, dut3_ipv6_list[0], vrfname))
        result = False

    ###########################################################################################
    hdrMsg("Step T5: Do BFD no-shutdown under BFD and verify BGP BFD sessions %s comes up"%[dut3_ip_list[0],dut3_ipv6_list[0]])
    ###########################################################################################
    bfd.configure_bfd(dut1,interface=access_vlan_name,neighbor_ip=dut3_ip_list[0],noshut='', vrf_name=vrfname)
    bfd.configure_bfd(dut1, interface=access_vlan_name, local_address=dut1_ipv6_list[0], neighbor_ip=dut3_ipv6_list[0],noshut='', vrf_name=vrfname)
    st.wait(2)
    result1 = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_ip_list[0], state='Established', vrf=vrfname)
    result2 = bfd.verify_bfd_peer(dut1, peer=dut3_ip_list[0], status=['up'], interface=access_vlan_name, vrf_name=vrfname)
    if result1 != result2:
        st.log('bgp_bfd_params failed for DUT {} for ip list {} for {}'.format(dut1, dut3_ip_list[0], vrfname))
        result = False

    result1 = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_ipv6_list[0], state='Established', vrf=vrfname)
    result2 = bfd.verify_bfd_peer(dut1, peer=dut3_ipv6_list[0], status=['up'], interface=access_vlan_name, vrf_name=vrfname)
    if result1 != result2:
        st.log('bgp_bfd_params failed for DUT {} for ip list {} for {}'.format(dut1, dut3_ipv6_list[0], vrfname))
        result = False

    ###########################################################################################
    hdrMsg("StepT6: Remove BFD for all BGP neighbors and Verify autocreated BFD peers still continue to exist as static BFD peers")
    ###########################################################################################
    bfd.configure_bfd(dut1, local_asn=dut1_as, neighbor_ip=dut3_ip_list[0:2] + dut3_ipv6_list[0:2],config='no',vrf_name=vrfname)
    result = bfd.verify_bfd_peer(dut1,peer=[dut3_ip_list[0],dut3_ipv6_list[0]],status=['up']*2,
                                 rx_interval=[['150','150']]*2, vrf_name=vrfname,
                                 tx_interval = [['150', '150']]*2)
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for {}'.format(dut1, vrfname))


    ###########################################################################################
    hdrMsg("StepT7: Re-enable BFD  under BGP neighbors and verify BFD session comes up with already configured timers")
    ###########################################################################################

    bfd.configure_bfd(dut1, local_asn=dut1_as, neighbor_ip=dut3_ip_list[0:2] + dut3_ipv6_list[0:2],vrf_name=vrfname)
    result = retry_api(bfd.verify_bfd_peer,dut1,peer=dut3_ip_list[0:2]+dut3_ipv6_list[0:2],status=['up']*4,
                                 rx_interval=[['150','150'],['300','300']]*2, vrf_name=vrfname,
                                 tx_interval = [['150', '150'], ['300','300']] * 2,retry_count=3,delay=1)
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for {}'.format(dut1,vrfname))
    return result


@pytest.mark.functionality
def test_FtOpSoRoBfdFn055_52_56_57_21(bfd_fixture_007):
    '''
    Verify BFD with neighbor level parameter values
    :param bfd_fixture_007:
    :return:
    '''

    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn052 FtOpSoRoBfdFn055,FtOpSoRoBfdFn021 FtOpSoRoBfdFn056 FtOpSoRoBfdFn057; TC SUMMARY : BFD with neighbor level parameter values")
    ###########################################################################################

    result = verify_FtOpSoRoBfdFn055_52_56_57_21()
    if result is False:
        st.report_fail('bfd_peer_params', dut1)

    st.report_pass('test_case_passed')


def return_vars_010(vrf='default'):
    if vrf == 'default':
        return access_vlan_name, flap_ports
    else:
        return access_vlan_name_vrf, flap_ports_vrf


@pytest.fixture(scope="function")
def bfd_fixture_010(request,prologue_epilogue):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP for TC10 ###")
    for vrfname in ['default',user_vrf_name]:
        access_vlan_name, flap_ports = return_vars_010(vrfname)
        bfd.configure_bfd(dut1, vrf_name=vrfname, neighbor_ip=dut3_ip_list[0], interface=access_vlan_name, config='no')
        bfd.configure_bfd(dut1, vrf_name=vrfname, neighbor_ip=dut3_ipv6_list[0], interface=access_vlan_name, config='no')

        bfd.configure_bfd(dut3, vrf_name=vrfname, neighbor_ip=dut1_ip_list[0], interface=access_vlan_name, config='no')
        bfd.configure_bfd(dut3, vrf_name=vrfname, neighbor_ip=dut1_ipv6_list[0], interface=access_vlan_name, config='no')

        dict1 = {'vrf_name': vrfname, "local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]],
                 'config': 'no'}
        dict2 = {'vrf_name': vrfname, "local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]],
                 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    hdrMsg("### CLEANUP End####")


@pytest.mark.functionality
def test_FtOpSoRoBfdFn011_20(bfd_fixture_010):

    tc_result = True
    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn011,FtOpSoRoBfdFn020; TC SUMMARY : Verify BFD Tx and Rx stats for IPv4/IPv6 BGP session")
    ###########################################################################################

    ###########################################################################################
    hdrMsg("Step T1: Enable BFD for ipv4 BGP neighbor %s on dut1 and %s on dut3"%(dut3_ip_list[0],dut1_ip_list[0]))
    ###########################################################################################
    for vrfname in ['default',user_vrf_name]:
        access_vlan_name, flap_ports = return_vars_010(vrfname)
        dict1 ={'vrf_name': vrfname, "local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ipv6_list[0]],'config':'yes'}
        dict2 ={'vrf_name': vrfname, "local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ipv6_list[0]],'config':'yes'}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

        ###########################################################################################
        hdrMsg("Step T2: Verify BFD session comes up for %s on dut1"%dut3_ip_list[0])
        ###########################################################################################
        result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name= vrfname, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2,status=['up']*2,retry_count=3,delay=1)
        if result is False:
            st.report_fail('bfd_peer_params', dut1)

        ###########################################################################################
        hdrMsg("Step T2-1: clear the BFD Tx/RX stats for BFD neighbors %s and %s"%(dut3_ip_list[0],dut3_ipv6_list[0]))
        ###########################################################################################
        dict1 = {'vrf_name': vrfname, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]], 'tx_intv': ['10000'] * 2,
                 'interface': [access_vlan_name] * 2, 'multiplier': ['2'] * 2, 'rx_intv': ['10000'] * 2, 'config': 'yes'}
        dict2 = {'vrf_name': vrfname, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]], 'tx_intv': ['10000'] * 2,
                 'interface': [access_vlan_name] * 2, 'multiplier': ['2'] * 2, 'rx_intv': ['10000'] * 2, 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
        result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=vrfname, peer=[dut3_ip_list[0], dut3_ipv6_list[0]],
                  rx_interval=[['10000', '10000'], ['10000', '10000']], tx_interval=[['10000', '10000'], ['10000', '10000']], status=['up', 'up'], retry_count=3, delay=1)
        if result is False:
            st.error('BFD timers are not updated with configured values')

        for icount in range(2):
            bfd.clear_bfd_peer_counters(dut1,vrf_name= vrfname, peer=dut3_ip_list[0],interface=access_vlan_name)
            if icount == 1:
                st.wait(2)
            counters = bfd.get_bfd_peer_counters(dut1, vrf_name=vrfname, peer=dut3_ip_list[0], interface=access_vlan_name)

            if len(counters) == 0:
                st.error("BFD counters did not retrieve any data for %s or %s"%(dut3_ip_list[0],dut3_ipv6_list[0]))
                tc_result = False
            else:
                bfd_rx_pkt = int(counters[0]['cntrlpktin'])
                bfd_tx_pkt = int(counters[0]['cntrlpktout'])
                zebra_cnt = int(counters[0]['zebranotifys'])
                st.log("BFD stats for %s Rx : %s and Tx : %s"%(dut3_ip_list[0],bfd_rx_pkt,bfd_tx_pkt))
                if bfd_rx_pkt == 0 and bfd_tx_pkt == 0:
                    st.log("BFD RX and TX stats are cleared as expected for ipv4")
                    break
                else:
                    st.error("BFD RX and TX packet counts are not cleared for ipv4")
                    if icount == 0:
                        continue
                    else:
                        tc_result = False

        for icount in range(2):
            bfd.clear_bfd_peer_counters(dut1, vrf_name=vrfname, peer=dut3_ipv6_list[0], interface=access_vlan_name,
                                        local_addr=dut1_ipv6_list[0])
            if icount == 1:
                st.wait(2)
            counters_v6 = bfd.get_bfd_peer_counters(dut1, vrf_name=vrfname, peer=dut3_ipv6_list[0],
                                                    interface=access_vlan_name)
            if len(counters_v6) == 0:
                st.error("BFD counters did not retrieve any data for %s or %s" % (dut3_ip_list[0], dut3_ipv6_list[0]))
                tc_result = False
            else:
                bfd_rx_pkt_v6 = int(counters_v6[0]['cntrlpktin'])
                bfd_tx_pkt_v6 = int(counters_v6[0]['cntrlpktout'])
                zebra_cnt_v6 = int(counters_v6[0]['zebranotifys'])
                st.log("BFD stats for %s Rx : %s and Tx : %s" % (dut3_ipv6_list[0], bfd_rx_pkt_v6, bfd_tx_pkt_v6))
                if bfd_rx_pkt_v6 == 0 and bfd_tx_pkt_v6 == 0:
                    st.log("BFD RX and TX stats are cleared as expected for ipv6")
                    break
                else:
                    st.error("BFD RX and TX packet counts are not cleared for ipv6")
                    if icount == 0:
                        continue
                    else:
                        tc_result = False

        ###########################################################################################
        hdrMsg("Step T3: Get the BFD Tx/RX stats for BFD neighbors %s and %s"%(dut3_ip_list[0],dut3_ipv6_list[0]))
        ###########################################################################################
        bfd.configure_bfd(dut1, vrf_name= vrfname, neighbor_ip=[dut3_ip_list[0], dut3_ipv6_list[0]], interface=[access_vlan_name] * 2,
                          multiplier=['2'] * 2, rx_intv=['250'] * 2, tx_intv=['250'] * 2)
        bfd.configure_bfd(dut3, vrf_name= vrfname, neighbor_ip=[dut1_ip_list[0], dut1_ipv6_list[0]], interface=[access_vlan_name] * 2,
                          multiplier=['3'] * 2, rx_intv=['300'] * 2, tx_intv=['300'] * 2)
        # configured the interval to 10seconds hence waiting for 10 seconds
        st.wait(11)
        counters = bfd.get_bfd_peer_counters(dut1,vrf_name= vrfname, peer=dut3_ip_list[0],interface=access_vlan_name)
        counters_v6 = bfd.get_bfd_peer_counters(dut1,vrf_name= vrfname, peer=dut3_ipv6_list[0],interface=access_vlan_name)
        if len(counters) == 0 or len(counters_v6) == 0:
            st.error("BFD counters did not retrieve any data for %s or %s"%(dut3_ip_list[0],dut3_ipv6_list[0]))
            tc_result = False
        else:
            bfd_rx_pkt = int(counters[0]['cntrlpktin'])
            bfd_tx_pkt = int(counters[0]['cntrlpktout'])
            zebra_cnt = int(counters[0]['zebranotifys'])
            st.log("BFD stats for %s Rx : %s and Tx : %s"%(dut3_ip_list[0],bfd_rx_pkt,bfd_tx_pkt))
            bfd_rx_pkt_v6 = int(counters_v6[0]['cntrlpktin'])
            bfd_tx_pkt_v6 = int(counters_v6[0]['cntrlpktout'])
            zebra_cnt_v6 = int(counters_v6[0]['zebranotifys'])
            st.log("BFD stats for %s Rx : %s and Tx : %s"%(dut3_ipv6_list[0],bfd_rx_pkt_v6,bfd_tx_pkt_v6))

            ###########################################################################################
            hdrMsg("Step T4: Verify Tx and RX packet count is incrementing for %s" % dut3_ip_list[0])
            ###########################################################################################
            # Using below stats base count and counters should not cross after reset ,some times failing
            st.wait(5)
            counters_1 = bfd.get_bfd_peer_counters(dut1,vrf_name= vrfname, peer=dut3_ip_list[0],interface=access_vlan_name)
            counters_1_v6 = bfd.get_bfd_peer_counters(dut1,vrf_name= vrfname, peer=dut3_ipv6_list[0],interface=access_vlan_name)
            bfd_rx_pkt_new = int(counters_1[0]['cntrlpktin'])
            bfd_tx_pkt_new = int(counters_1[0]['cntrlpktout'])
            bfd_rx_pkt_new_v6 = int(counters_1_v6[0]['cntrlpktin'])
            bfd_tx_pkt_new_v6 = int(counters_1_v6[0]['cntrlpktout'])

            st.log("%s BFD stats Rx : %s and Tx : %s" % (dut3_ip_list[0],bfd_rx_pkt_new, bfd_tx_pkt_new))

            if bfd_rx_pkt_new > bfd_rx_pkt and bfd_tx_pkt_new > bfd_tx_pkt :
                st.log("BFD RX and TX stats are incrementing as expected for ipv4")
            else:
                st.error("BFD RX and TX packet counts are not incrementing for ipv6")
                tc_result = False

            st.log("%s BFD stats Rx : %s and Tx : %s" % (dut3_ipv6_list[0],bfd_rx_pkt_new_v6, bfd_tx_pkt_new_v6))

            if bfd_rx_pkt_new_v6 > bfd_rx_pkt_v6 and bfd_tx_pkt_new_v6 > bfd_tx_pkt_v6 :
                st.log("BFD RX and TX stats are incrementing as expected for ipv4")
            else:
                st.error("BFD RX and TX packet counts are not incrementing for ipv6")
                tc_result = False
            ###########################################################################################
            hdrMsg("Step T5: Verify BFD echo rx/txpackets are 0")
            ###########################################################################################

            session_up_event = int(counters_1[0]['sessionupev'])
            session_down_event = int(counters_1[0]['sessiondownev'])
            echo_tx = int(counters_1[0]['echopktout'])
            echo_rx = int(counters_1[0]['echopktin'])

            session_up_event_v6 = int(counters_1_v6[0]['sessionupev'])
            session_down_event_v6 = int(counters_1_v6[0]['sessiondownev'])
            echo_tx_v6 = int(counters_1_v6[0]['echopktout'])
            echo_rx_v6 = int(counters_1_v6[0]['echopktin'])

            st.log("Peer : %s session_up : %s , Session_down : %s , Echo Tx : %s , Echo Rx : %s ,Zebra: %s"\
                   %(dut3_ip_list[0],session_up_event,session_down_event,echo_tx,echo_rx,zebra_cnt))
            if  echo_rx != 0 or echo_tx != 0:
                st.error("One or more BFD counters not as expected for ipv4")
                tc_result=False
            st.log("Peer : %s session_up : %s , Session_down : %s , Echo Tx : %s , Echo Rx : %s ,Zebra: %s"\
                   %(dut3_ipv6_list[0],session_up_event_v6,session_down_event_v6,echo_tx_v6,echo_rx_v6,zebra_cnt_v6))
            if  echo_rx_v6 != 0 or echo_tx_v6 != 0:
                st.error("One or more BFD counters not as expected for ipv6")
                tc_result=False

            ###########################################################################################
            hdrMsg("Step T6: Bring down port connected to L2 switch(dut2) and verify BFD session_down_event received")
            ###########################################################################################
            port.shutdown(flap_dut,[flap_ports[0]])
            result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name= vrfname, peer=[dut3_ip_list[0],dut3_ipv6_list[0]], interface=[access_vlan_name]*2,status=['down']*2,retry_count=10,delay=1)
            counters_2 = bfd.get_bfd_peer_counters(dut1, vrf_name= vrfname, peer=dut3_ip_list[0],interface=access_vlan_name)
            counters_2_v6 = bfd.get_bfd_peer_counters(dut1, vrf_name= vrfname, peer=dut3_ipv6_list[0],interface=access_vlan_name)
            if result:
                session_down_event_new = int(counters_2[0]['sessiondownev'])
                session_down_event_new_v6 = int(counters_2_v6[0]['sessiondownev'])
                if session_down_event_new != (session_down_event+1):
                    st.error("Session_down_evevnt counter not incremented after BFD goes down for ipv4")
                    tc_result=False

                    st.log("Verify Zebra notification count incremented to %s for ipv4"%(zebra_cnt+1))
                    if int(counters_2[0]['zebranotifys']) != (zebra_cnt+1):
                        st.error("Zebra notification counter not incremented for ipv4")
                        tc_result=False
                if session_down_event_new_v6 != (session_down_event_v6+1):
                    st.error("Session_down_evevnt counter not incremented after BFD goes down for ipv6")
                    tc_result=False

                    st.log("Verify Zebra notification count incremented to %s for ipv6"%(zebra_cnt_v6+1))
                    if int(counters_2_v6[0]['zebranotifys']) != (zebra_cnt_v6+1):
                        st.error("Zebra notification counter not incremented for ipv6")
                        tc_result=False
            else:
                st.error("BFD sessions did not come up")
                tc_result = False
            ###########################################################################################
            hdrMsg("Step T7: Bring up port connected to L2 switch(dut2) and verify BFD session_up_event received")
            ###########################################################################################
            port.noshutdown(flap_dut, [flap_ports[0]])

            result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name= vrfname, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2, status=['up']*2,retry_count=10,delay=1)
            counters_3 = bfd.get_bfd_peer_counters(dut1, vrf_name= vrfname, peer=dut3_ip_list[0],interface=access_vlan_name)
            counters_3_v6 = bfd.get_bfd_peer_counters(dut1, vrf_name= vrfname, peer=dut3_ipv6_list[0],interface=access_vlan_name)
            if result:
                session_up_event_new = int(counters_3[0]['sessionupev'])
                if session_up_event_new != (session_up_event+1):
                    st.error("Session_up_evevnt counter not incremented after BFD goes down")
                    tc_result = False

                    st.log("Verify Zebra notification count incremented to %s"%(zebra_cnt + 2))
                    if int(counters_3[0]['zebranotifys']) != (zebra_cnt + 2):
                        st.error("Zebra notification counter not incremented")
                        tc_result = False
                session_up_event_new_v6 = int(counters_3_v6[0]['sessionupev'])
                if session_up_event_new_v6 != (session_up_event_v6+1):
                    st.error("Session_up_evevnt counter not incremented after BFD goes down for ipv6")
                    tc_result = False

                    st.log("Verify Zebra notification count incremented to %s"%(zebra_cnt_v6 + 2))
                    if int(counters_3_v6[0]['zebranotifys']) != (zebra_cnt_v6 + 2):
                        st.error("Zebra notification counter not incremented for ipv6")
                        tc_result = False
            else:
                st.error("BFD sessions did not come up")
                tc_result = False
            ###########################################################################################
            hdrMsg("Step T8: Disable BFD for neighbor %s,%s and verify counters output not shown "%(dut3_ip_list[0],dut3_ipv6_list[0]))
            ###########################################################################################
            bfd.configure_bfd(dut1, vrf_name= vrfname, local_asn=dut1_as, neighbor_ip=[dut3_ip_list[0],dut3_ipv6_list[0]], config='no')
            bfd.configure_bfd(dut1, vrf_name= vrfname, neighbor_ip=dut3_ip_list[0], interface=access_vlan_name, config='no')
            bfd.configure_bfd(dut1, vrf_name= vrfname, neighbor_ip=dut3_ipv6_list[0], interface=access_vlan_name, config='no')
            st.wait(2)
            counters_4 = bfd.get_bfd_peer_counters(dut1, vrf_name= vrfname, peer=dut3_ip_list[0],interface=access_vlan_name)
            counters_4_v6 = bfd.get_bfd_peer_counters(dut1, vrf_name= vrfname, peer=dut3_ipv6_list[0],interface=access_vlan_name)
            if counters_4 == False or counters_4_v6 == False:
                tc_result = False
            elif len(counters_4) != 0 or len(counters_4_v6) != 0:
                st.error("BFD counter entries are still shown after disabling BFD")
                tc_result= False

            ###########################################################################################
            hdrMsg("Step T9: Re-enable BFD for neighbor %s ,%sand verify counters output resets again " % (dut3_ip_list[0],dut3_ipv6_list[0]))
            ###########################################################################################
            bfd.configure_bfd(dut1, vrf_name= vrfname, local_asn=dut1_as, neighbor_ip=[dut3_ip_list[0],dut3_ipv6_list[0]], config='yes')
            result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name= vrfname, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2, status=['up']*2,retry_count=3,delay=1)

            if result:
                # Expecting stats more than zero for that Waiting to avoid in consistency in stats
                st.wait(2)
                st.log("Ensuring stats are  incremented gratter than ZERO")
                counters_5 = bfd.get_bfd_peer_counters(dut1, vrf_name= vrfname, peer=dut3_ip_list[0],interface=access_vlan_name)
                counters_5_v6 = bfd.get_bfd_peer_counters(dut1, vrf_name= vrfname, peer=dut3_ipv6_list[0],interface=access_vlan_name)
                if counters_5 != [] and counters_5_v6 != []:
                    bfd_rx_pkt_new_1 = int(counters_5[0]['cntrlpktin'])
                    bfd_tx_pkt_new_1 = int(counters_5[0]['cntrlpktout'])
                    if bfd_tx_pkt_new_1 < 0 or bfd_rx_pkt_new_1 < 0:
                        st.error("BFD RX/TX stats did not reset after disabling and enabling BFD for neighbor and not incremented %s"%dut3_ip_list[0])
                        tc_result = False
                    bfd_rx_pkt_new_1_v6 = int(counters_5_v6[0]['cntrlpktin'])
                    bfd_tx_pkt_new_1_v6 = int(counters_5_v6[0]['cntrlpktout'])
                    if bfd_tx_pkt_new_1_v6 < 0 or bfd_rx_pkt_new_1_v6 < 0:
                        st.error("BFD RX/TX stats did not reset after disabling and enabling BFD for neighbor and not incremented %s"%dut3_ipv6_list[0])
                        tc_result = False
                else:
                    st.error("BFD output is displaying null after disabling and enabling BFD for neighbor %s" %dut3_ipv6_list[0])
                    tc_result = False

            else:
                st.error("BFD sessions did not come up")
                tc_result = False
    if tc_result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('bfd_counters_fail',dut3_ip_list[0])


def return_vars_012(vrf='default'):
    if vrf == 'default':
        return D1_ports, D3_ports
    else:
        return D1_ports_vrf, D3_ports_vrf


@pytest.fixture(scope="function")
def bfd_fixture_012(request, prologue_epilogue):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP for TC12 ###")
    for vrfname in ['default',user_vrf_name]:
        D1_ports, D3_ports = return_vars_012(vrfname)

        dict1 = {'vrf_name':vrfname, "interface": D1_ports[1], 'neighbor_ip': dut3_ip_list[1], 'config': 'no'}
        dict2 = {'vrf_name':vrfname, "interface": D3_ports[1], 'neighbor_ip': dut1_ip_list[1], 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

        dict1 = {'vrf_name':vrfname, "interface": D1_ports[1], 'neighbor_ip': dut3_ipv6_list[1], 'config': 'no'}
        dict2 = {'vrf_name':vrfname, "interface": D3_ports[1], 'neighbor_ip': dut1_ipv6_list[1], 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

        dict1 = {'vrf_name': vrfname, "local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[1], dut3_ipv6_list[1]], 'config': 'no'}
        dict2 = {'vrf_name': vrfname, "local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[1], dut1_ipv6_list[1]], 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    hdrMsg("### CLEANUP End####")


@pytest.mark.functionality
def test_FtOpSoRoBfdFn009(bfd_fixture_012):

    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn009; TC SUMMARY : Verify BFD functionality with echo mode enabled")
    ###########################################################################################
    for vrfname in ['default',user_vrf_name]:
        D1_ports, D3_ports = return_vars_012(vrfname)

        ###########################################################################################
        hdrMsg("Step T1: Enable BFD for ipv4/ipv6 BGP neighbor on dut1  dut3")
        ###########################################################################################

        dict1 ={'vrf_name':vrfname, "local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[1],dut3_ipv6_list[1]],'config':'yes'}
        dict2 ={'vrf_name':vrfname, "local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[1],dut1_ipv6_list[1]],'config':'yes'}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

        ###########################################################################################
        hdrMsg("Step T2: Enable echo mode on both ipv4/ipv6 peers")
        ###########################################################################################
        dict1 = {'vrf_name': vrfname, 'interface': [D1_ports[1]] * 2, 'echo_mode_enable': '', 'neighbor_ip': [dut3_ip_list[1], dut3_ipv6_list[1]], 'noshut': "yes"}
        dict2 = {'vrf_name': vrfname, 'interface': [D3_ports[1]] * 2, 'echo_mode_enable': '', 'neighbor_ip': [dut1_ip_list[1], dut1_ipv6_list[1]], 'noshut': "yes"}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

        ###########################################################################################
        hdrMsg("Step T3: Verify echo tranmission interval set to 50ms by default under BFD peers")
        ###########################################################################################

        result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name=vrfname, peer=[dut3_ip_list[1],dut3_ipv6_list[1]],echo_tx_interval=[['50','50'],['50','50']],status=['up','up'],retry_count=5,delay=1)
        if result is False:
            st.report_fail('bfd_fail_reason','DUT1: BFD session did not come up with default timers')

        ###########################################################################################
        hdrMsg("Step T4: verify echo packets are transmitted and received in 50ms interval")
        ###########################################################################################

        get_rate = get_echo_interval(dut1, dut3_ip_list[1], D1_ports[1], interval=0.002, vrfname=vrfname)
        if not get_rate:
            st.report_fail('bfd_fail_reason', 'BFD counters output is empty')
        if 0.00625 < get_rate[0] < 0.06:
            st.log("Echo packets are sent out in 50ms interval as expected")
        else:
            st.report_fail('bfd_fail_reason','Echo packets are not sent out in default interval 50ms')

        if 0.00625 < get_rate[1] < 0.06:
            st.log("Echo packets are received in 50ms interval as expected")
        else:
            st.report_fail('bfd_fail_reason','Echo packets are not received in default interval 50ms')


        get_rate = get_echo_interval(dut1, dut3_ipv6_list[1], D1_ports[1], interval=0.002, vrfname=vrfname)
        if not get_rate:
            st.report_fail('bfd_fail_reason', 'BFD counters output is empty')
        if 0.00625 < get_rate[0] < 0.06:
            st.log("Echo packets are sent out in 50ms interval as expected")
        else:
            st.report_fail('bfd_fail_reason','Echo packets are not sent out in default interval 50ms')

        if 0.00625 < get_rate[1] < 0.06:
            st.log("Echo packets are received in 50ms interval as expected")
        else:
            st.report_fail('bfd_fail_reason','Echo packets are not received in default interval 50ms')
        ###########################################################################################
        hdrMsg("Step T5:Set echo -interval to 100 msec on dut1 and 500 sec on dut3 and verify timers updated correctly under peer")
        ###########################################################################################
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=D1_ports[1],neighbor_ip=dut3_ip_list[1],echo_mode_enable='', shutdown= "yes")
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=D1_ports[1], neighbor_ip=dut3_ipv6_list[1], echo_mode_enable='', shutdown="yes")

        dict1 ={'vrf_name':vrfname, 'interface':[D1_ports[1]]*2,'neighbor_ip':[dut3_ip_list[1],dut3_ipv6_list[1]],'echo_intv':['100']*2,'noshut': "yes"}
        dict2 ={'vrf_name':vrfname, 'interface':[D3_ports[1]]*2,'neighbor_ip':[dut1_ip_list[1],dut1_ipv6_list[1]],'echo_intv':['500']*2,'noshut': "yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
        st.wait(1)
        result = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=[dut3_ip_list[1],dut3_ipv6_list[1]],echo_tx_interval=[['100','500'],['100','500']],status=['up','up'])
        if result is False:
            st.report_fail('bfd_fail_reason','DUT1: BFD session did not come up with configured echo intervals')

        ###########################################################################################
        hdrMsg("Step T6:verify max timer 500 msec selected as transmission interval on dut1")
        ###########################################################################################

        get_rate = get_echo_interval(dut1, dut3_ip_list[1], D1_ports[1], interval=0.006, vrfname=vrfname)
        if not get_rate:
            st.report_fail('bfd_fail_reason', 'BFD counters output is empty')
        if 0.125 < get_rate[0] < 0.6:
            st.log("Echo packets are sent out in max of echo intervals 500ms interval as expected")
        else:
            st.report_fail('bfd_fail_reason', 'Echo packets are not sent out with max of echo timers.Actual : %s msec'%get_rate[0])

        st.log("Verify peer %s did not tx/rx any Echo packets" % dut3_ipv6_list[1])

        if 0.125 < get_rate[1] < 0.6:
            st.log("Echo packets are received in max of echo intervals 500ms interval as expected")
        else:
            st.report_fail('bfd_fail_reason', 'Echo packets are not received with max of echo timers.Actual : %s msec'%get_rate[1])

        ###########################################################################################
        hdrMsg("Step T7:Disable echo mode and verify echo pkts drops tx/rx and re-enable")
        ###########################################################################################

        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=D1_ports[1],neighbor_ip=dut3_ip_list[1],echo_mode_disable='', noshut= "yes")
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=D1_ports[1], neighbor_ip=dut3_ipv6_list[1], echo_mode_disable='', noshut= "yes")

        st.log("Verify Echo packets stop sending out")
        st.log("Verify peer %s did not tx/rx any Echo packets" % dut3_ip_list[1])
        get_rate = get_echo_interval(dut1,dut3_ip_list[1],D1_ports[1],interval=0.002, vrfname=vrfname)
        if get_rate is False or get_rate[0] != 0:
            st.report_fail('bfd_fail_reason','DUT1: after disabling echo-mode,echo packets getting transmitted for %s'%dut3_ip_list[1])

        st.log("Verify peer %s did not tx/rx any Echo packets"%dut3_ipv6_list[1])
        get_rate = get_echo_interval(dut1,dut3_ipv6_list[1],D1_ports[1],interval=0.002, vrfname=vrfname)
        if get_rate is False or get_rate[0] != 0:
            st.report_fail('bfd_fail_reason','DUT1: after disabling echo-mode ,echo packets getting transmitted for %s'%dut3_ipv6_list[1])


        ###########################################################################################
        hdrMsg("Step T8:Verify configuring echo interval with minimum and maximum timer values are accepted")
        ###########################################################################################
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=D1_ports[1],neighbor_ip=dut3_ip_list[1],echo_mode_enable='', shutdown= "yes")
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=D1_ports[1], neighbor_ip=dut3_ipv6_list[1], echo_mode_enable='', shutdown="yes")

        dict1 ={'vrf_name':vrfname, 'interface':D1_ports[1],'neighbor_ip':dut3_ip_list[1],'echo_intv':'10','noshut': "yes"}
        dict2 ={'vrf_name':vrfname, 'interface':D3_ports[1],'neighbor_ip':dut1_ip_list[1],'echo_intv':'60000','noshut': "yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
        dict1 ={'vrf_name':vrfname, 'interface':D1_ports[1],'neighbor_ip':dut3_ipv6_list[1],'echo_intv':'60000','noshut': "yes"}
        dict2 ={'vrf_name':vrfname, 'interface':D3_ports[1],'neighbor_ip':dut1_ipv6_list[1],'echo_intv':'10','noshut': "yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
        st.wait(1)
        result = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=[dut3_ip_list[1],dut3_ipv6_list[1]],echo_tx_interval=[['10','60000'],['60000','10']],status=['up','up'])
        if result is False:
            st.report_fail('bfd_fail_reason','DUT1: BFD session did not come up with configured echo intervals')

    st.report_pass('test_case_passed')


def return_vars(vrfname='default'):
    if vrfname == 'default':
        return access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, \
               peer_v4, peer_v6, flap_ports
    else:
        return access_vlan_vrf, access_vlan_name_vrf, trunk_vlan_vrf, trunk_vlan_name_vrf, D1_ports_vrf, D3_ports_vrf,\
                tg_handles_vrf, peer_v4_vrf, peer_v6_vrf, flap_ports_vrf


@pytest.fixture(scope="function")
def bfd_fixture_013(request, prologue_epilogue):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP for TC13 ###")
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ip_list[0], password='abcd', neighbor_shutdown='', no_form='no')
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ipv6_list[0], password='abcd', neighbor_shutdown='', no_form='no')

    bgp_api.config_bgp_neighbor_properties(dut3, dut3_as, dut1_ip_list[0], password='abcd', neighbor_shutdown='', no_form='no')
    bgp_api.config_bgp_neighbor_properties(dut3, dut3_as, dut1_ipv6_list[0], password='abcd', neighbor_shutdown='', no_form='no')

    ###########################################################################################
    hdrMsg("Verify BGP sessions for %s and %s" % (dut3_ip_list[0], dut1_ipv6_list[0]))
    ###########################################################################################

    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=nbr, state='Established', retry_count=3,
                           delay=3)
        if result is False:
            if nbr == dut3_ip_list[0]:
                bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ip_list[0], remote_as=dut3_as,
                                   config_type_list=["neighbor", 'connect'], connect=1)
            else:
                bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ipv6_list[0], remote_as=dut3_as,
                                   config_type_list=["neighbor", 'activate', 'connect', "routeMap"], routeMap='rmap_v6',
                                   diRection='in', addr_family='ipv6', connect=1)

    dict1 ={"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ipv6_list[0]],'config':'no'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ipv6_list[0]],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    hdrMsg("### CLEANUP End####")


@pytest.mark.functionality
def test_FtOpSoRoBfdFn036_37_38_40_25(bfd_fixture_013):

    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn025,FtOpSoRoBfdFn036,FtOpSoRoBfdFn037,FtOpSoRoBfdFn038,FtOpSoRoBfdFn040; TC SUMMARY : Verify removing BGP configuration on global level")
    ###########################################################################################

    ###########################################################################################
    hdrMsg("Step T1: Enable BFD for all ipv4 and ipv6 BGP neighbors on dut1 and dut3")
    ###########################################################################################
    dict1 ={"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ipv6_list[0]],'config':'yes'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ipv6_list[0]],'config':'yes'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])


    ###########################################################################################
    hdrMsg("Step T2: Verify BFD states are UP under BFD show output")
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer,dut1,peer=[dut3_ip_list[0],dut3_ipv6_list[0]],status=['up']*2,retry_count=10,delay=3)
    if result is False:
        st.report_fail('bfd_fail_reason','One or more BFD ssession did not come up')

    ###########################################################################################
    hdrMsg("Step T3: Delete and configure BGP on dut1 with all neighbors")
    ###########################################################################################
    bgp_api.config_bgp(dut=dut1, config='no', removeBGP='yes', config_type_list=["removeBGP"], local_as=dut1_as, vrf_name=user_vrf_name)
    bgp_api.config_bgp(dut=dut1, config='no', removeBGP='yes', config_type_list=["removeBGP"],local_as = dut1_as)

    #st.log("Re-Configure all BGP ipv4/ipv6 neighbors on dut1")
    for ivrfname in ['default',user_vrf_name]:
        access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, \
        peer_v4, peer_v6, flap_ports = return_vars(ivrfname)
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, router_id=dut1_router_id, config_type_list=['router_id',"max_path_ibgp"],max_path_ibgp=1)
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, config_type_list=["max_path_ibgp"], max_path_ibgp=1,  addr_family='ipv6')
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, neighbor=dut3_ip_list[0], remote_as=dut3_as, config_type_list=["neighbor",'connect'],connect=1, keepalive=keep_alive, holdtime=hold_down)
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, neighbor=dut3_ip_list[1], remote_as=dut3_as, config_type_list=["neighbor",'connect'],connect=1)
        for nbr in dut3_ip_list[2:5]:
           bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, peergroup=peer_v4,config_type_list=['peergroup'],remote_as=dut3_as, neighbor=nbr)
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, peergroup=peer_v4, config_type_list=['connect'], remote_as=dut3_as, neighbor=peer_v4, connect=1)
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, neighbor=dut3_ipv6_list[0], remote_as=dut3_as,config_type_list=["neighbor",'activate','connect',"routeMap"],routeMap='rmap_v6', diRection='in',addr_family='ipv6',connect=1)
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, neighbor=dut3_ipv6_list[1], remote_as=dut3_as,config_type_list=["neighbor",'activate','connect',"routeMap"],routeMap='rmap_v6', diRection='in',addr_family='ipv6',connect=1)
        for nbr in dut3_ipv6_list[2:5]:
            bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, peergroup=peer_v6, config_type_list=['peergroup','activate'], remote_as=dut3_as,neighbor=nbr,addr_family='ipv6')
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, peergroup=peer_v6,config_type_list=['connect',"routeMap"],routeMap='rmap_v6', diRection='in', remote_as=dut3_as, neighbor=peer_v6,addr_family='ipv6', connect=1)
        bgp_api.config_bgp(dut=dut1, local_as=dut1_as, vrf_name=ivrfname, config_type_list=["max_path_ibgp"], max_path_ibgp=1, addr_family='ipv6')

    tc_result= True
    err_list=[]
    ###########################################################################################
    hdrMsg("Step T4: Verify all BGP sessions came up with BFD disabled")
    ###########################################################################################
    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',delay=4,retry_count=10)
        if result is False:
            err="BFD /BGP state incorrect for %s after delete/create BGP"%nbr
            st.error(err);err_list.append(err); tc_result=False

    ###########################################################################################
    hdrMsg("Step T5: Re-Enable BFD for all ipv4 and ipv6 BGP neighbors on dut1")
    ###########################################################################################
    bfd.configure_bfd(dut1, local_asn=dut1_as, neighbor_ip=[dut3_ip_list[0],dut3_ipv6_list[0]])

    ###########################################################################################
    hdrMsg("Step T6: VerifyBFD session is enabled for all BGP neighbors")
    ###########################################################################################

    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=2,delay=1)
        if result is False:
            err= "BFD /BGP state incorrect for %s after delete/recreate BGP"%nbr
            st.error(err);err_list.append(err); tc_result=False

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[0], dut3_ipv6_list[0]], status=['up'] * 2,
                       retry_count=3, delay=3)
    if result is False:
        err = 'BFD session did not come up after re-enable BFD peers'
        st.error(err); err_list.append(err); tc_result = False

    ###########################################################################################
    hdrMsg("Step T7: Delete and re-Configure BGP neighbors %s and %s on dut1" % (dut3_ip_list[0], dut3_ipv6_list[0]))
    ###########################################################################################

    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ip_list[0], remote_as=dut3_as,
                   config_type_list=["neighbor"], config='no')
    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ipv6_list[0], remote_as=dut3_as,
                   config_type_list=["neighbor"], config='no')

    st.log("Re-Configure BGP ipv4/ipv6 neighbors on dut1")

    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ip_list[0], remote_as=dut3_as,
                   config_type_list=["neighbor",'connect'],connect=1)
    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ipv6_list[0], remote_as=dut3_as,
                   config_type_list=["neighbor", 'activate','connect',"routeMap"],routeMap='rmap_v6', diRection='in', addr_family='ipv6',connect=1)

    ###########################################################################################
    hdrMsg("Step T8: Verify BGP sessions for %s and %s came up with BFD disabled" % (dut3_ip_list[0], dut1_ipv6_list[0]))
    ###########################################################################################
    for nbr in [dut3_ip_list[0] , dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1, neighborip=nbr, state='Established',retry_count=10,delay=3)
    if result is False:
        err = "BFD /BGP state incorrect for %s after delete/create BGP neighbor" % nbr
        st.error(err);err_list.append(err); tc_result=False

    ###########################################################################################
    hdrMsg("Step T9: Re-Enable BFD for all ipv4 and ipv6 BGP neighbors on dut1 and dut3")
    ###########################################################################################
    bfd.configure_bfd(dut1, local_asn=dut1_as, neighbor_ip=[dut3_ip_list[0], dut3_ipv6_list[0]])

    ###########################################################################################
    hdrMsg("Step T10: VerifyBFD session is enabled for all BGP neighbors")
    ###########################################################################################

    for nbr in [dut3_ip_list[0] , dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1, neighborip=nbr, state='Established', retry_count=5,delay=2)
    if result is False:
        err ="BFD /BGP state incorrect for %s after delete/recreate BGP neighbor " % nbr
        st.error(err); err_list.append(err); tc_result = False

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[0], dut3_ipv6_list[0]], status=['up'] * 2,
                       retry_count=3, delay=3)
    if result is False:
        err = 'BFD session did not come up after re-enable BFD peers'
        st.error(err); err_list.append(err); tc_result = False

    ###########################################################################################
    hdrMsg("Step T11: Configure neighbor authentication for %s and %s on dut1" % (dut3_ip_list[0], dut3_ipv6_list[0]))
    ###########################################################################################

    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ip_list[0], password='abcd', config_type_list=["pswd"])
    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ipv6_list[0], password='abcd', config_type_list=["pswd"])

    st.wait(2)

    ###########################################################################################
    hdrMsg("Step T12: Verify Both BGP session state and BFD state goes down for the BGP neighbors due to authentication mismatch ")
    ###########################################################################################

    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = bfd.verify_bgp_bfd_down(dut1,nbr,access_vlan_name)
        if result is False:
            err ="BFD /BGP state incorrect for %s after authentication mismatch" % nbr
            st.error(err); err_list.append(err); tc_result = False

    ###########################################################################################
    hdrMsg("Step T13: Enable authentication on remote dut3 and verify BGP and BFD sessions comes up")
    ###########################################################################################

    bgp_api.config_bgp(dut=dut3, local_as=dut3_as, neighbor=dut1_ip_list[0], password='abcd', config_type_list=["pswd"])
    bgp_api.config_bgp(dut=dut3, local_as=dut3_as, neighbor=dut1_ipv6_list[0], password='abcd', config_type_list=["pswd"])

    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1, neighborip=nbr, state='Established')
        if result is False:
            err ="BGP state did not come up for %s" % nbr
            st.error(err); err_list.append(err); tc_result = False

    ###########################################################################################
    hdrMsg("Step T14: Verify BFD peers output and check state is UP")
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[0], dut3_ipv6_list[0]], status=['up', 'up'], retry_count=5, delay=1)
    if result is False:
        err = 'One or more BFD session did not come up after configuring authentication on both the DUTs'
        st.error(err); err_list.append(err); tc_result = False

    ###########################################################################################
    hdrMsg("Step T15: Shutdown BGPv4/v6 neighbors and verify BFD session also goes down")
    ###########################################################################################

    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ip_list[0], neighbor_shutdown='')
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ipv6_list[0], neighbor_shutdown='')

    #bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ip_list[0], config_type_list=["shutdown"], shutdown=True, active=False)
    #bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ipv6_list[0], config_type_list=["shutdown"], shutdown=True, active=False)

    ###########################################################################################
    hdrMsg("Step T16: Verify BGP goes down and BFD also goes down")
    ###########################################################################################

    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = ip_bgp.verify_bgp_neighbor(dut1, neighborip=nbr, state='Idle')
    if result is False:
        err ="BFD /BGP state incorrect for %s" % nbr
        st.error(err); err_list.append(err); tc_result = False

    output = bfd.verify_bfd_peer(dut1,peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2,return_dict='yes')
    if len(output) != 0:
        err ='BFD session did not auto delete after BGP goes down'
        st.error(err); err_list.append(err); tc_result = False

    ###########################################################################################
    hdrMsg("Step T17: No shutdown BGP neighbors and verify both BGP and BFD sessions comes up")
    ###########################################################################################
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ip_list[0], neighbor_shutdown='', no_form='no')
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ipv6_list[0], neighbor_shutdown='', no_form='no')

    #bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ip_list[0], config_type_list=["shutdown"], config='no', shutdown=True, active=False)
    #bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut3_ipv6_list[0], config_type_list=["shutdown"], config='no', shutdown=True, active=False)

    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1, neighborip=nbr, state='Established', retry_count=10, delay=3)
        if result is False:
            err ="BGP state incorrect for %s" % nbr
            st.error(err); err_list.append(err); tc_result = False


    ###########################################################################################
    hdrMsg("Step T18: Clear all BGP neighbors")
    ###########################################################################################
    bgp_api.clear_ip_bgp_vtysh(dut1)
    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1, neighborip=nbr, state='Established',retry_count=10,delay=3)
        if result is False:
            err ='BGP/BFD state did not come up after clear bgp for %s'%nbr
            st.error(err); err_list.append(err); tc_result = False

    result = bfd.verify_bfd_peer(dut1, peer=[dut3_ip_list[0], dut3_ipv6_list[0]], status=['up', 'up'])
    if result is False:
        err = 'One or more BFD session did not come up after clear BGP'
        st.error(err); err_list.append(err); tc_result = False

    if tc_result is False:
        st.report_fail('bfd_fail_reason',err_list[0])
    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def bfd_fixture_017(request, prologue_epilogue):
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, peer_v4, family="ipv4", neighbor_shutdown='', peergroup=peer_v4)
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, peer_v6, family="ipv6", neighbor_shutdown='', peergroup=peer_v6)
    yield
    hdrMsg("### CLEANUP for TC17 ###")
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, peer_v4, family="ipv4", neighbor_shutdown='',no_form='no', peergroup=peer_v4)
    bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, peer_v6, family="ipv6", neighbor_shutdown='',no_form='no', peergroup=peer_v6)

    dict1 ={"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0], dut3_ipv6_list[0]],'config':'no'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0], dut1_ipv6_list[0]],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1 = {"interface": access_vlan_name, 'neighbor_ip': dut3_ipv6_list[0], 'config': 'no'}
    dict2 = {"interface": access_vlan_name, 'neighbor_ip': dut1_ipv6_list[0], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 ={"interface":access_vlan_name,'neighbor_ip':dut3_ip_list[0],'config':'no'}
    dict2 ={"interface":access_vlan_name,'neighbor_ip':dut1_ip_list[0],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    hdrMsg("### CLEANUP End####")


@pytest.mark.functionality
def test_FtOpSoRoBfdFn089(bfd_fixture_017):
    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn089; TC SUMMARY : Verify performance measurements with minimum RX/TX timer values")
    ###########################################################################################

    ###########################################################################################
    hdrMsg("Step T1: Enable BFD for %s and %s on dut1 and %s,%s on dut3" % (dut3_ip_list[0], dut3_ipv6_list[0],dut1_ip_list[0], dut1_ipv6_list[0]))
    ###########################################################################################

    dict1 ={"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0], dut3_ipv6_list[0]],'config':'yes'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0], dut1_ipv6_list[0]],'config':'yes'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    if l2_switch == 'yes':
        ###########################################################################################
        hdrMsg("Step T2: Configure minimum bfd tx/rx interval to 10ms on both dut1 and 1 sec on dut3")
        ###########################################################################################

        dict1 ={"interface":[access_vlan_name]*2,'neighbor_ip':[dut3_ip_list[0], dut3_ipv6_list[0]],'tx_intv':[10,10],'rx_intv':[10,10],'multiplier':[2,2]}
        dict2 ={"interface":[access_vlan_name]*2,'neighbor_ip':[dut1_ip_list[0], dut1_ipv6_list[0]],'tx_intv':[1000,1000],'rx_intv':[1000,1000],'multiplier':[2,2]}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
        ###########################################################################################
        hdrMsg("Step T3: Verify BFD tmers are updated apprprately as per configuration")
        ###########################################################################################

        result = bfd.verify_bfd_peer(dut1, peer=[dut3_ip_list[0], dut3_ipv6_list[0]], tx_interval=[['10', '1000'], ['10', '1000']],
                                     rx_interval=[['10', '1000'], ['10', '1000']])
        if result is False:
            st.report_fail('bfd_fail_reason', 'BFD peers are not updated with configured timers')

        ###########################################################################################
        hdrMsg("Step T4: Verify BFD chooses max timers 1000*2 msec as convergence time")
        ###########################################################################################

        converged = convergence_measure(flap_dut,flap_ports[0],version='both')

        if converged < 400.0 or converged is False:
            st.report_fail('bfd_fail_reason','Higher TX interval not used for failure detection')


    ###########################################################################################
    hdrMsg("Step T6: Measure Traffic convergence time with minimum timer interval for ipv4 and ipv6")
    ###########################################################################################
    dict1 = {"interface": [access_vlan_name] * 2, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]],'tx_intv': [10, 10], 'rx_intv': [10, 10], 'multiplier': [2, 2]}
    dict2 = {"interface": [access_vlan_name] * 2, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]], 'tx_intv': [10, 10], 'rx_intv': [10, 10], 'multiplier': [2, 2]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    converged_v4_min = convergence_measure(flap_dut,flap_ports[0],version='both')
    if l2_switch == 'yes':
        if converged_v4_min > 200.0 or converged_v4_min is False:
            st.report_fail('bfd_fail_reason','Traffic convergence is more than expected 10ms')
    else:
        if converged_v4_min > 120.0 or converged_v4_min is False:
            st.report_fail('bfd_fail_reason','Traffic convergence is more than expected 10ms')


    ###########################################################################################
    hdrMsg("Step T7: Configure default 300ms for BFD peers and measure traffic convergence")
    ###########################################################################################

    dict1 ={"interface":[access_vlan_name]*2,'neighbor_ip':[dut3_ip_list[0], dut3_ipv6_list[0]],'tx_intv':[300,300],'rx_intv':[300,300],'multiplier':[2,2]}
    dict2 ={"interface":[access_vlan_name]*2,'neighbor_ip':[dut1_ip_list[0], dut1_ipv6_list[0]],'tx_intv':[300,300],'rx_intv':[300,300],'multiplier':[2,2]}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step T8: Measure Traffic convergence time with 300*2 timer interval for ipv4 and ipv6")
    ###########################################################################################

    converged_v4 = convergence_measure(flap_dut,flap_ports[0],version='both')
    if l2_switch == 'yes':
        if converged_v4 > 800.0 or converged_v4 is False:
            st.report_fail('bfd_fail_reason','Traffic convergence is more than expected 600ms')
    else:
        if converged_v4 > 1000.0 or converged_v4 is False:
            st.report_fail('bfd_fail_reason', 'Traffic convergence is more than expected 1000ms')

    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def bfd_fixture_018(request, prologue_epilogue):
    yield
    hdrMsg("### CLEANUP for TC18 ###")
    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut2_ip_list[1], remote_as=dut3_as, config_type_list=["neighbor"],config='no')
    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut2_ipv6_list[1], remote_as=dut3_as,config_type_list=["neighbor"], addr_family='ipv6',config='no')
    dict1 ={"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ipv6_list[0],dut3_ip_list[1],dut3_ipv6_list[1]],'config':'no'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ipv6_list[0],dut1_ip_list[1],dut1_ipv6_list[1]],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    hdrMsg("### CLEANUP End####")


@pytest.mark.functionality
def test_FtOpSoRoBfdFn035_26(bfd_fixture_018):
    err_list=[]
    tc_result= True
    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn035,FtOpSoRoBfdFn026; TC SUMMARY : Verify deleting IP address from Physical/Vlan interface")
    ###########################################################################################

    ###########################################################################################
    hdrMsg("Step T1: Enable BFD for BGP neighbors over access vlan and physical port")
    ###########################################################################################

    dict1 ={"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ip_list[1],dut3_ipv6_list[0],dut3_ipv6_list[1]],'config':'yes'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ip_list[1],dut1_ipv6_list[0],dut1_ipv6_list[1]],'config':'yes'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])


    ###########################################################################################
    hdrMsg("Step T2: Verify BFD session is UP under al BGP neighbors with BFD enabled")
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer,dut1,peer=dut3_ip_list[0:2]+dut3_ipv6_list[0:2],status=['up']*4,retry_count=2,delay=1)
    if result is False:
        st.report_fail('bfd_fail_reason','one or more BFD session did not come up')

    ###########################################################################################
    hdrMsg("Step T3: Delete ip/ipv6 address from %s on dut3 and verify BFD session goes down  "%(access_vlan_name))
    ###########################################################################################

    ip_api.delete_ip_interface(dut3, access_vlan_name, dut3_ip_list[0], subnet=ip_mask)
    ip_api.config_ip_addr_interface(dut3, access_vlan_name, dut2_ip_list[1], ip_mask)
    ip_api.delete_ip_interface(dut3, access_vlan_name, dut3_ipv6_list[0], subnet=ipv6_mask, family='ipv6')
    ip_api.config_ip_addr_interface(dut3, access_vlan_name, dut2_ipv6_list[1], ipv6_mask, family="ipv6")
    st.wait(1)
    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = bfd.verify_bgp_bfd_down(dut1, nbr, access_vlan_name)
        if result is False:
            err = "BGP and BFD session did not go down after deleting ip address from Vlan interface"
            st.error(err);err_list.append(err);tc_result=False


    ###########################################################################################
    hdrMsg("Step T4: Configure BGP neighbor in dut1 for the new ip/ipv6 configured on dut2 and enable BFD")
    ###########################################################################################
    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut2_ip_list[1], remote_as=dut3_as,
                   config_type_list=["neighbor",'connect'],connect=1)
    bgp_api.config_bgp(dut=dut1, local_as=dut1_as, neighbor=dut2_ipv6_list[1], remote_as=dut3_as,
                   config_type_list=["neighbor", 'activate','connect'], addr_family='ipv6',connect=1)
    bfd.configure_bfd(dut1, local_asn=dut1_as, neighbor_ip=[dut2_ip_list[1],dut2_ipv6_list[1]], config="yes")


    ###########################################################################################
    hdrMsg("Step T5: Verify BFD sessions are UP under BGP and BFD for new neighbor")
    ###########################################################################################
    for nbr in [dut2_ip_list[1], dut2_ipv6_list[1]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=nbr, state='Established', retry_count=10, delay=3)
        if result is False:
            err = 'BGP state under %s is incorrect' % nbr;err_list.append(err); tc_result = False
            st.error(err)

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut2_ip_list[1], dut2_ipv6_list[1]], status=['up'] * 2,
                       retry_count=2, delay=1)
    if result is False:
        err = 'BFD state under %s is incorrect' % nbr;
        err_list.append(err); tc_result = False; st.error(err)

    ###########################################################################################
    hdrMsg("Step T6: Revert to old ip/ipv6 address from %s on dut3 and verify BFD/BGP session comes up "%(access_vlan_name))
    ###########################################################################################
    ip_api.delete_ip_interface(dut3, access_vlan_name, dut2_ip_list[1], subnet=ip_mask)
    ip_api.config_ip_addr_interface(dut3, access_vlan_name, dut3_ip_list[0], ip_mask)
    ip_api.delete_ip_interface(dut3, access_vlan_name, dut2_ipv6_list[1], subnet=ipv6_mask, family='ipv6')
    ip_api.config_ip_addr_interface(dut3, access_vlan_name, dut3_ipv6_list[0], ipv6_mask, family='ipv6')

    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            err = "BGP and BFD session did not come up after adding  ip address from Vlan interface"
            st.error(err); err_list.append(err);tc_result=False

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[0],dut3_ipv6_list[0]], status=['up'] * 2,
                       retry_count=2, delay=1)
    if result is False:
        err = 'BFD state under %s is incorrect' % nbr
        err_list.append(err)
        tc_result = False
        st.error(err)

    ###########################################################################################
    hdrMsg("Step T7: Delete ip address from %s on dut3 and verify BFD session goes down " % (D3_ports[1]))
    ###########################################################################################

    ip_api.delete_ip_interface(dut3, D3_ports[1], dut3_ip_list[1], subnet=ip_mask)
    ip_api.delete_ip_interface(dut3, D3_ports[1], dut3_ipv6_list[1], subnet=ipv6_mask, family='ipv6')
    st.wait(1)
    for nbr in [dut3_ip_list[1], dut3_ipv6_list[1]]:
        result = bfd.verify_bgp_bfd_down(dut1, nbr, D3_ports[1])
        if result is False:
            err = "BGP and BFD session did not go down after deleting ip address from physical interface"
            st.error(err);err_list.append(err);tc_result=False

    ###########################################################################################
    hdrMsg("Step T8: Re-add ip address from %s on dut3 and verify BFD/BGP session comes up " % (D3_ports[1]))
    ###########################################################################################
    ip_api.config_ip_addr_interface(dut3, D3_ports[1], dut3_ip_list[1], ip_mask)
    ip_api.config_ip_addr_interface(dut3, D3_ports[1], dut3_ipv6_list[1], ipv6_mask, family='ipv6')
    for nbr in [dut3_ip_list[1],dut3_ipv6_list[1]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            err = "BGP and BFD session did not come up after adding  ip address from Vlan interface"
            st.error(err); err_list.append(err);tc_result=False

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[1], dut3_ipv6_list[1]], status=['up'] * 2,
                       retry_count=2, delay=1)
    if result is False:
        err = 'BFD state under %s is incorrect' % nbr
        err_list.append(err)
        tc_result = False
        st.error(err)

    if tc_result is False:
        st.report_fail('bfd_fail_reason',err_list[0])
    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def bfd_fixture_019(request, prologue_epilogue):
    yield
    hdrMsg("### CLEANUP for TC19 ###")
    dict1 ={"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ipv6_list[0]],'config':'no'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ipv6_list[0]],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    bfd.configure_bfd(dut1,interface=[access_vlan_name], neighbor_ip=dut3_ip_list[0], config='no')
    bfd.configure_bfd(dut1,interface=[access_vlan_name], neighbor_ip=dut3_ipv6_list[0], config='no')
    dict1 ={'vrf_name': user_vrf_name,"local_asn":dut1_as,'neighbor_ip':[dut3_ip_list[0],dut3_ipv6_list[0]],'config':'no'}
    dict2 ={'vrf_name': user_vrf_name,"local_asn":dut3_as,'neighbor_ip':[dut1_ip_list[0],dut1_ipv6_list[0]],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    bfd.configure_bfd(dut1, vrf_name= user_vrf_name, interface=[access_vlan_name], neighbor_ip=dut3_ip_list[0], config='no')
    bfd.configure_bfd(dut1, vrf_name= user_vrf_name, interface=[access_vlan_name], neighbor_ip=dut3_ipv6_list[0] ,config='no')
    hdrMsg("### CLEANUP End####")


def remove_bgp_and_config():
    ###########################################################################################
    hdrMsg("Step T3: Delete and configure BGP on dut1 with all neighbors")
    ###########################################################################################
    bgp_api.config_bgp(dut=dut1, config='no', removeBGP='yes', config_type_list=["removeBGP"], local_as=dut1_as,
                       vrf_name=user_vrf_name)
    bgp_api.config_bgp(dut=dut1, config='no', removeBGP='yes', config_type_list=["removeBGP"], local_as=dut1_as)

    st.log("Re-Configure all BGP ipv4/ipv6 neighbors on dut1")
    for ivrfname in ['default', user_vrf_name]:
        access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, \
        peer_v4, peer_v6, flap_ports = return_vars(ivrfname)
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, router_id=dut1_router_id, local_as=dut1_as,
                           config_type_list=['router_id', "max_path_ibgp"], max_path_ibgp=1)
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, local_as=dut1_as, config_type_list=["max_path_ibgp"], max_path_ibgp=1,
                           addr_family='ipv6')
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, local_as=dut1_as, neighbor=dut3_ip_list[0], remote_as=dut3_as,
                           config_type_list=["neighbor", 'connect'], connect=1, keepalive=keep_alive,
                           holdtime=hold_down)
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, neighbor=dut3_ip_list[1],local_as=dut1_as, remote_as=dut3_as,
                           config_type_list=["neighbor", 'connect'], connect=1)
        for nbr in dut3_ip_list[2:5]:
            bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, peergroup=peer_v4, local_as=dut1_as, config_type_list=['peergroup'],
                               remote_as=dut3_as, neighbor=nbr)
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, peergroup=peer_v4, local_as=dut1_as, config_type_list=['connect'],
                           remote_as=dut3_as, neighbor=peer_v4, connect=1)
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, neighbor=dut3_ipv6_list[0], local_as=dut1_as, remote_as=dut3_as,
                           config_type_list=["neighbor", 'activate', 'connect', "routeMap"], routeMap='rmap_v6',
                           diRection='in', addr_family='ipv6', connect=1)
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, neighbor=dut3_ipv6_list[1], local_as=dut1_as, remote_as=dut3_as,
                           config_type_list=["neighbor", 'activate', 'connect', "routeMap"], routeMap='rmap_v6',
                           diRection='in', addr_family='ipv6', connect=1)
        for nbr in dut3_ipv6_list[2:5]:
            bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, peergroup=peer_v6,
                               config_type_list=['peergroup', 'activate'], remote_as=dut3_as, local_as=dut1_as, neighbor=nbr,
                               addr_family='ipv6')
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, peergroup=peer_v6, local_as=dut1_as, config_type_list=['connect', "routeMap"],
                           routeMap='rmap_v6', diRection='in', remote_as=dut3_as, neighbor=peer_v6, addr_family='ipv6',
                           connect=1)
        bgp_api.config_bgp(dut=dut1, vrf_name=ivrfname, config_type_list=["max_path_ibgp"], local_as=dut1_as, max_path_ibgp=1,
                           addr_family='ipv6')


@pytest.mark.functionality
def test_FtOpSoRoBfdFn001_60_61(bfd_fixture_019):
    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn060; FtOpSoRoBfdFn061,FtOpSoRoBfdFn001; TC SUMMARY : Verify BFD after config Save and Reload/Container restart")
    ###########################################################################################

    ###########################################################################################
    hdrMsg("Step T1: Enable BFD on all BGP ipv4 and ipv6 neighbors on both dut1 and dut3")
    ###########################################################################################
    pass_status = True
    dict1 = {'local_asn': dut1_as, 'preserve_state': 'yes', 'config': 'add'}
    dict2 = {'local_asn': dut3_as, 'preserve_state': 'yes', 'config': 'add'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp_graceful_restart, [dict1, dict2])

    dict1 = {'local_asn': dut1_as, 'preserve_state': 'yes', 'vrf':user_vrf_name, 'config': 'add'}
    dict2 = {'local_asn': dut3_as, 'preserve_state': 'yes', 'vrf':user_vrf_name, 'config': 'add'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp_graceful_restart, [dict1, dict2])

    dict1 = {"local_asn": dut1_as,'neighbor_ip': [dut3_ip_list[0],dut3_ipv6_list[0]], 'config': 'yes'}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': [dut1_ip_list[0],dut1_ipv6_list[0]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name,"local_asn": dut1_as,'neighbor_ip': [dut3_ip_list[0],dut3_ipv6_list[0]], 'config': 'yes'}
    dict2 = {'vrf_name': user_vrf_name,"local_asn": dut3_as,'neighbor_ip': [dut1_ip_list[0],dut1_ipv6_list[0]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step T2: Configure non-default bfd timer values for each peer on dut1")
    ###########################################################################################
    intf_list= [access_vlan_name]
    bfd.configure_bfd(dut1,interface=intf_list*2, neighbor_ip=[dut3_ip_list[0],dut3_ipv6_list[0]], multiplier=["2"]*2,
                      rx_intv=["210",'320'],tx_intv=["200",'290'],echo_mode_enable='',echo_intv=[100,120])

    intf_list_vrf= [access_vlan_name_vrf]
    bfd.configure_bfd(dut1,vrf_name=user_vrf_name, interface=intf_list_vrf*2, neighbor_ip=[dut3_ip_list[0],dut3_ipv6_list[0]], multiplier=["2"]*2,
                      rx_intv=["210",'320'],tx_intv=["200",'290'],echo_mode_enable='',echo_intv=[100,120])

    ###########################################################################################
    hdrMsg("Step T3: Verify BFD peers have the configured parameters")
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer,dut1, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']],retry_count=2,delay=1)
    if result is False:
        st.report_fail('bfd_fail_reason',"BFD parameters are incorrect for one or more BFD ipv4 peers")

    result = retry_api(bfd.verify_bfd_peer,dut1,vrf_name=user_vrf_name, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name_vrf]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']],retry_count=2,delay=1)
    if result is False:
        st.report_fail('bfd_fail_reason',"BFD-VRF parameters are incorrect for one or more BFD ipv4 peers")

    ###########################################################################################
    hdrMsg("Step T4: Verify BFD state under each neighbor before reboot")
    ###########################################################################################
    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.report_fail('bfd_fail_reason',"BGP parameters are incorrect for one or more BFD ipv4 peers before reboot")

    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,vrf=user_vrf_name,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.report_fail('bfd_fail_reason',"BGP-VRF parameters are incorrect for one or more BFD ipv4 peers before reboot")

    ###########################################################################################
    hdrMsg("Step T5: Save and reload DUT")
    ###########################################################################################
    reboot_api.config_save(dut1)
    reboot_api.config_save(dut1,shell='vtysh')
    protocol = 'bfd' if st.get_ui_type(dut1, cli_type='') != 'click' else None
    output = basic.get_frr_config(dut1, protocol=protocol)
    match_nbr_v4 = "neighbor %s bfd"%dut3_ip_list[0]
    match_nbr_v6 = "neighbor %s bfd" % dut3_ipv6_list[0]
    bfd_params_v6 = "peer %s local-address %s interface %s\n  detect-multiplier 2\n  receive-interval 320\n  transmit-interval 290\n  echo-interval 120\n  echo-mode\n  no shutdown"%(dut3_ipv6_list[0],dut1_ipv6_list[0],access_vlan_name)
    bfd_params_v4 = "peer %s interface %s\n  detect-multiplier 2\n  receive-interval 210\n  transmit-interval 200\n  echo-interval 100\n  echo-mode\n  no shutdown"%(dut3_ip_list[0],access_vlan_name)
    bfd_params_v6_1 = "peer %s local-address %s vrf default interface %s\n  detect-multiplier 2\n  receive-interval 320\n  transmit-interval 290\n  echo-interval 120\n  echo-mode\n  no shutdown" % (
    dut3_ipv6_list[0], dut1_ipv6_list[0], access_vlan_name)
    bfd_params_v4_1 = "peer %s vrf default interface %s\n  detect-multiplier 2\n  receive-interval 210\n  transmit-interval 200\n  echo-interval 100\n  echo-mode\n  no shutdown" % (
    dut3_ip_list[0], access_vlan_name)

    bfd_params_v6_2 = "peer %s interface %s\n  detect-multiplier 2\n  transmit-interval 290\n  receive-interval 320\n  echo-mode\n  echo-interval 120" % (dut3_ipv6_list[0], access_vlan_name)
    bfd_params_v4_2 = "peer %s interface %s\n  detect-multiplier 2\n  transmit-interval 200\n  receive-interval 210\n  echo-mode\n  echo-interval 100" % (dut3_ip_list[0], access_vlan_name)

    bfd_params_v6_3 = "peer %s interface %s\n  detect-multiplier 2\n  transmit-interval 290\n  receive-interval 320\n  no shutdown\n  echo-mode\n  echo-interval 120" % (dut3_ipv6_list[0], access_vlan_name)
    bfd_params_v4_3 = "peer %s interface %s\n  detect-multiplier 2\n  transmit-interval 200\n  receive-interval 210\n  no shutdown\n  echo-mode\n  echo-interval 100" % (dut3_ip_list[0], access_vlan_name)

    arlo_patten = match_nbr_v4 not in output or match_nbr_v6 not in output or bfd_params_v4 not in output or bfd_params_v6 not in output
    buzznik_pattern = match_nbr_v4 not in output or match_nbr_v6 not in output or bfd_params_v4_1 not in output or bfd_params_v6_1 not in output
    arlo_patten_1 = match_nbr_v4 not in output or match_nbr_v6 not in output or bfd_params_v4_2 not in output or bfd_params_v6_2 not in output
    buzznikplus_klish_pattern = bfd_params_v4_3 not in output or bfd_params_v6_3 not in output

    if arlo_patten and buzznik_pattern and arlo_patten_1 and buzznikplus_klish_pattern:
        st.error('Failed: bfd_fail_reason one or more BFD configs mismatch in frr.conf file')
        pass_status = False
    else:
        st.report_tc_pass("FtOpSoRoBfdFn001", "bfd_peer_success", "in frr")

    st.log('######------Config reload with BFD-VRF------######')
    st.log("Config reload the DUT")
    reboot_api.config_save_reload(vars.D1)

    ###########################################################################################
    hdrMsg("Step T6: Verify BFD state under each neighbor after reboot")
    ###########################################################################################
    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.error('Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after config reboot')
            pass_status = False

    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,vrf=user_vrf_name, neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.error('Failed bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after config reboot')
            pass_status = False
    if not pass_status:
        basic.get_techsupport(filename="FtOpSoRoBfdFn001")
    ###########################################################################################
    hdrMsg("Step T6: Verify BFD peers have the configured parameters after reboot")
    ###########################################################################################
    result = bfd.verify_bfd_peer(dut1, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']])
    if result is False:
        st.error('Failed bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after config reboot')
        pass_status = False

    result = bfd.verify_bfd_peer(dut1, vrf_name=user_vrf_name, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name_vrf]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']])
    if result is False:
        st.error('Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after config reboot')
        pass_status = False
    else:
        st.report_tc_pass("FtOpSoRoBfdFn060", "bfd_peer_success", "after save and reload")
        st.report_tc_pass("FtOpSoRoBfdVrfFn029", "bfd_peer_success", "after config reload")

    if pass_status == False:
        remove_bgp_and_config()
        dict1 = {"local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]], 'config': 'yes'}
        dict2 = {"local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]], 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

        dict1 = {'vrf_name': user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]],
                 'config': 'yes'}
        dict2 = {'vrf_name': user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]],
                 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    utils.exec_all(True, [[bgp_api.clear_ip_bgp_vtysh, dut1],[ bgp_api.clear_ip_bgp_vtysh, dut3]])
    utils.exec_all(True, [[bgp_api.clear_ipv6_bgp_vtysh, dut1], [bgp_api.clear_ipv6_bgp_vtysh, dut3]])
    ###########################################################################################
    hdrMsg("Step T7: Verify BFD state under each neighbor after clear bgp ")
    ###########################################################################################

    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.error('Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after clear bgp')
            pass_status = False

    result = bfd.verify_bfd_peer(dut1, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']])
    if result is False:
        st.error('Failed : bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after clear bgp')
        pass_status = False

    st.log("clear ipv4 bgp neighbors")
    utils.exec_all(True,[[bgp_api.clear_ip_bgp_vrf_vtysh,dut1,user_vrf_name],[bgp_api.clear_ip_bgp_vrf_vtysh,dut3, user_vrf_name]])
    st.log("clear ipv6 bgp neighbors")
    utils.exec_all(True, [[bgp_api.clear_ip_bgp_vrf_vtysh, dut1, user_vrf_name,'ipv6'],[bgp_api.clear_ip_bgp_vrf_vtysh, dut3, user_vrf_name, 'ipv6']])
    ###########################################################################################
    hdrMsg("Step T8: Verify BFD state under each neighbor after clear bgp on vrf ")
    ###########################################################################################
    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,vrf=user_vrf_name, neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.error('Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after reboot')
            pass_status = False

    result = bfd.verify_bfd_peer(dut1, vrf_name=user_vrf_name, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name_vrf]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']])
    if result is False:
        st.error('bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers')
        pass_status = False
    else:
        st.report_tc_pass("FtOpSoRoBfdVrfFn026", "bfd_peer_success", "after clear BGP ")

    if pass_status == False:
        remove_bgp_and_config()
        dict1 = {"local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]], 'config': 'yes'}
        dict2 = {"local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]], 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

        dict1 = {'vrf_name': user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]],
                 'config': 'yes'}
        dict2 = {'vrf_name': user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]],
                 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
        ###########################################################################################
        hdrMsg("Step T7: Verify BFD state under each neighbor before fast reboot")
        ###########################################################################################
        for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
            if result is False:
                st.error('Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after clear bgp')
                pass_status = False

        for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,vrf=user_vrf_name, neighborip=nbr,state='Established',retry_count=10,delay=3)
            if result is False:
                st.error('Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after clear bgp')
                pass_status = False

    st.reboot(dut1, 'fast')
    ###########################################################################################
    hdrMsg("Step T7: Verify BFD state under each neighbor after fast reboot")
    ###########################################################################################
    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.error('Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after fast-reboot')
            pass_status = False

    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,vrf=user_vrf_name, neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.error('Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after fast-reboot')
            pass_status = False

    ###########################################################################################
    hdrMsg("Step T8: Verify BFD peers have the configured parameters after fast reboot")
    ###########################################################################################
    result = bfd.verify_bfd_peer(dut1, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']])
    if result is False:
        st.error('Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers')
        pass_status = False

    result = bfd.verify_bfd_peer(dut1, vrf_name=user_vrf_name, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name_vrf]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']])
    if result is False:
        st.error('Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers')
        pass_status = False
    else:
        st.report_tc_pass("FtOpSoRoBfdVrfFn036", "bfd_peer_success", "after fast-reboot ")


    if pass_status == False:
        remove_bgp_and_config()
        dict1 = {"local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]], 'config': 'yes'}
        dict2 = {"local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]], 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

        dict1 = {'vrf_name': user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]],
                 'config': 'yes'}
        dict2 = {'vrf_name': user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]],
                 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
        ###########################################################################################
        hdrMsg("Step T7: Verify BFD state under each neighbor before fast reboot")
        ###########################################################################################
        for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=nbr, state='Established', retry_count=10, delay=3)
            if result is False:
                st.error(
                    'Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after fast-reboot')
                pass_status = False

        for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                               retry_count=10, delay=3)
            if result is False:
                st.error(
                    'Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after fast-reboot')
                pass_status = False


    ###########################################################################################
    hdrMsg("Step T9: Stop and Start the BGP container")
    ###########################################################################################
    #Enabling warm restart for BGP and system
    reboot_api.config_warm_restart(dut1, oper="enable", tasks=["bgp", "system"])
    reboot_api.verify_warm_restart(dut1, mode='config')
    #send contiuous traffic for 5 seconds while BGP docker restart
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_handles)
    tg1.tg_traffic_control(action='run', stream_handle=data.streams['stream_handle_list'])
    st.wait(5)
    basic.service_operations_by_systemctl(dut1, 'bgp', 'restart')
    st.wait(5)
    reboot_api.verify_warm_restart(dut1, mode='config')

    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg1],
            'stream_list': [data.streams['stream_handle_list']]
        }

    }
    tg1.tg_traffic_control(action='stop', stream_handle=data.streams['stream_handle_list'])
    # verify traffic mode stream level

    streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count', tolerance_factor=0)
    if streamResult:
        st.log('traffic verification passed for BGP docker restart')
        st.report_tc_pass("FtOpSoRoBfdFn061", "bfd_peer_success", "is up and no traffic loss while docker restart and after restart BFD ")
    else:
        st.log('traffic verification failed for BGP docker restart')
        st.report_fail('bfd_fail_reason','Traffic loss while BGP docker restart')

    ###########################################################################################
    hdrMsg("Step T10: Verify BFD state under each neighbor after BGP container restart")
    ###########################################################################################
    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.error('bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after BGP container restart')
            pass_status = False

    for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,vrf=user_vrf_name,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.error('Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after BGP container restart')
            pass_status = False

    ###########################################################################################
    hdrMsg("Step T11: Verify BFD peers have the configured parameters after BGP container restart")
    ###########################################################################################

    result = bfd.verify_bfd_peer(dut1, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']])
    if result is False:
        st.error('Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after BGP container restart')
        pass_status = False

    result = bfd.verify_bfd_peer(dut1, vrf_name=user_vrf_name, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name_vrf]*2,status=['up']*2,
                                 rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']])
    if result is False:
        st.error('Failed: bfd_fail_reason BFD on default and non default vrf parameters are incorrect for one or more BFD ipv4 peers after BGP container restart')
        pass_status = False
    else:
        st.report_tc_pass("FtOpSoRoBfdVrfFn030", "bfd_peer_success", "after BGP docker restart")

    if pass_status == False:
        remove_bgp_and_config()
        dict1 = {"local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]], 'config': 'yes'}
        dict2 = {"local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]], 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

        dict1 = {'vrf_name': user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]],
                 'config': 'yes'}
        dict2 = {'vrf_name': user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]],
                 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
        st.report_fail('bfd_fail_reason', "BFD parameters are incorrect for one or more BFD ipv4 peers after reboot")
    else:
        st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def bfd_fixture_021(request, prologue_epilogue):
    ###########################################################################################
    hdrMsg("Step test-config1: Enable BFD session for all BGP neighbors for both ipv4 and ipv6 on dut1 and dut3")
    ###########################################################################################
    dict1 = {"local_asn": dut1_as,'neighbor_ip': [peer_v4,peer_v6], 'config': 'yes', 'peergroup': [peer_v4,peer_v6]}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': [peer_v4,peer_v6], 'config': 'yes', 'peergroup': [peer_v4,peer_v6]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    #port.shutdown(flap_dut, [flap_ports[1],flap_ports[2]])
    ###
    yield
    hdrMsg("### CLEANUP for TC21 ###")
    dict1 ={"local_asn":dut1_as,'neighbor_ip':[peer_v4,peer_v6],'config':'no', 'peergroup': [peer_v4,peer_v6]}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':[peer_v4,peer_v6],'config':'no', 'peergroup': [peer_v4,peer_v6]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    #port.noshutdown(flap_dut, [flap_ports[0],flap_ports[1],flap_ports[2]])
    bfd.configure_bfd(dut1, neighbor_ip=dut3_ip_list[2], interface=trunk_vlan_name[0],config='no')
    bfd.configure_bfd(dut1, neighbor_ip=dut3_ipv6_list[2], interface=trunk_vlan_name[0], config='no')
    #retry_api(ip_bgp.check_bgp_session,dut1, nbr_list=dut3_ip_list + dut3_ipv6_list, state_list=['Established'] * 10,retry_count=10,delay=3)
    hdrMsg("### CLEANUP End####")


@pytest.mark.functionality
def test_FtOpSoRoBfdFn090_92_93(bfd_fixture_021):
    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn090, FtOpSoRoBfdFn092, FtOpSoRoBfdFn093; TC SUMMARY : Verify BFD sessions after continuous link flaps")
    ###########################################################################################
    ###########################################################################################
    hdrMsg("Step T1: Verify BFD session is UP for all peers")
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer,dut1, peer=[dut3_ip_list[2],dut3_ipv6_list[2]], interface=[trunk_vlan_name[0]]*2, status=['up'] * 2)
    if result is False:
        st.report_fail('bfd_fail_reason', "BFD parameters are incorrect for one or more BFD peers")

    ###########################################################################################
    hdrMsg("Step T2: Verify BFD under BGP neighbor is UP for all peers")
    ###########################################################################################
    for nbr in [dut3_ip_list[2],dut3_ipv6_list[2]]:
        result = ip_bgp.verify_bgp_neighbor(dut1, neighborip=nbr, state='Established')
        if result is False:
            st.report_fail('bfd_fail_reason', "BGP State incorrect for BGP neighbor %s" % nbr)

    for iteration in range(2):

        st.log('>>>>>>>>>>>>>> ITERATION : %s <<<<<<<<<<<<<<<<<<<<' %(iteration+1))

        ###########################################################################################
        hdrMsg("Step : Flap dut2 port and verify all BFD peers and BGP neighbors goes down")
        ###########################################################################################

        port.shutdown(flap_dut,[flap_ports[2]])
        port.noshutdown(flap_dut, [flap_ports[2]])

        for nbr in [dut3_ip_list[2],dut3_ipv6_list[2]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor,dut1, neighborip=nbr, state='Established',retry_count=10,delay=4)
            if result is False:
                st.report_fail('bfd_fail_reason',"BGP State incorrect for BGP neighbor %s after link flap"% nbr)

        result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[2], dut3_ipv6_list[2]],
                           interface=[trunk_vlan_name[0]] * 2, status=['up'] * 2)
        if result is False:
            st.report_fail('bfd_fail_reason', "BFD parameters are incorrect for one or more BFD peers after link flap")

        ###########################################################################################
        hdrMsg("Step: Shutdown /no shutdown BFD peers on dut1 and verify BFD and BGP goes down")
        ###########################################################################################
        bfd.configure_bfd(dut1, neighbor_ip=[dut3_ip_list[2],dut3_ipv6_list[2]], interface=[trunk_vlan_name[0]]*2, shutdown='')
        bfd.configure_bfd(dut1, neighbor_ip=[dut3_ip_list[2],dut3_ipv6_list[2]], interface=[trunk_vlan_name[0]]*2, noshut='')

        for nbr in [dut3_ip_list[2], dut3_ipv6_list[2]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=nbr, state='Established',
                               retry_count=10, delay=4)
            if result is False:
                st.report_fail('bfd_fail_reason', "BFD State incorrect for BGP neighbor %s after bfd peer shut/no shut" % nbr)

        result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[2], dut3_ipv6_list[2]],
                           interface=[trunk_vlan_name[0]] * 2, status=['up'] * 2)
        if result is False:
            st.report_fail('bfd_fail_reason', "BFD parameters are incorrect for one or more BFD peers after peer shut/no shut")

        ###########################################################################################
        hdrMsg("Step: Disbale and Enable BFD under bgp neighbor on dut1 and verify BFD and BGP goes down")
        ###########################################################################################
        bfd.configure_bfd(dut1, local_asn=dut1_as, neighbor_ip=[dut3_ip_list[2], dut3_ipv6_list[2]], config='no')
        bfd.configure_bfd(dut1, local_asn=dut1_as, neighbor_ip=[dut3_ip_list[2], dut3_ipv6_list[2]], config='yes')

        for nbr in [dut3_ip_list[2], dut3_ipv6_list[2]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=nbr, state='Established',
                               retry_count=10, delay=4)
            if result is False:
                st.report_fail('bfd_fail_reason', "BFD State incorrect for BGP neighbor %s after bfd disable/enable" % nbr)

        result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[2], dut3_ipv6_list[2]],
                           interface=[trunk_vlan_name[0]] * 2, status=['up'] * 2)
        if result is False:
            st.report_fail('bfd_fail_reason', "BFD parameters are incorrect for one or more BFD peers after bfd disable/enable")

    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def bfd_fixture_022(request,prologue_epilogue):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP ###")
    for vrfname in ['default', user_vrf_name]:
        D1_ports, D3_ports = return_vars_012(vrfname)
        access_vlan_name, flap_ports = return_vars_010(vrfname)
        dict1 = {'vrf_name': vrfname, "local_as": dut1_as,'neighbor':D1_ports[1],'remote_as':dut3_as,'config_type_list': ["neighbor"],'config':'no'}
        dict2 = {'vrf_name': vrfname, "local_as": dut3_as,'neighbor':D3_ports[1],'remote_as':dut1_as,'config_type_list': ["neighbor"],'config':'no'}
        parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

        utils.exec_all(True, [[ip_api.delete_ip_interface, dut1, D1_ports[1], dut1_link_local, ipv6_mask, 'ipv6'],
                              [ip_api.delete_ip_interface, dut3, D3_ports[1], dut2_link_local, ipv6_mask, 'ipv6']])


        dict1 ={'vrf_name': vrfname, "interface":D1_ports[1],'neighbor_ip':dut2_link_local,'local_address':dut1_link_local,'config':'no'}
        dict2 ={'vrf_name': vrfname, "interface":D3_ports[1],'neighbor_ip':dut1_link_local,'local_address':dut2_link_local,'config':'no'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
        port.noshutdown(flap_dut, [flap_ports[1]])
    hdrMsg("### CLEANUP End####")


@pytest.mark.functionality
def test_FtOpSoRoBfdFn019(bfd_fixture_022):

    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn019;TC SUMMARY : Verify BFD functionality through link local BGP sessions")
    ###########################################################################################
    for vrfname in ['default', user_vrf_name]:
        D1_ports, D3_ports = return_vars_012(vrfname)
        access_vlan_name, flap_ports = return_vars_010(vrfname)
        ###########################################################################################
        hdrMsg("Step T1: Configure ipv6 link-local address %s/64 on dut1 and %s/64 on dut3"%(dut1_link_local,dut2_link_local))
        ###########################################################################################

        utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, D1_ports[1], dut1_link_local, ipv6_mask,'ipv6'],
                              [ip_api.config_ip_addr_interface, dut3, D3_ports[1], dut2_link_local, ipv6_mask,'ipv6']])

        ###########################################################################################
        hdrMsg("Step T2: Configure BGP neighbors for ipv6 link-local on bith dut1 and dut3")
        ###########################################################################################

        dict1 = {'vrf_name': vrfname, "local_as": dut1_as, 'neighbor': D1_ports[1], 'remote_as': dut3_as,
                 'config_type_list': ["remote-as", "activate",'bfd'], 'connect': 1, 'interface': D1_ports[1],
                 'addr_family': 'ipv6'}
        dict2 = {'vrf_name': vrfname, "local_as": dut3_as, 'neighbor': D3_ports[1], 'remote_as': dut1_as,
                 'config_type_list': ["remote-as", "activate",'bfd'], 'connect': 1, 'interface': D3_ports[1],
                 'addr_family': 'ipv6'}
        parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

        ###########################################################################################
        hdrMsg("Step T3: Verify BGP session is UP over link-local ipv6 address")
        ###########################################################################################

        result = retry_api(bgp_api.verify_bgp_summary, vars.D1, family = 'ipv6', shell = 'vtysh', vrf=vrfname, neighbor = D1_ports[1], state = 'Established', retry_count=10,delay=3)
        if result is False:
            debug_bgp_vrf([dut1,dut3], [dut2_link_local,dut1_link_local], 'ipv6', vrfname,[D1_ports[1],D3_ports[1]])
            st.report_fail('bfd_fail_reason','bgp_ip_peer_establish_fail for %s'%dut2_link_local)


        ###########################################################################################
        hdrMsg("Step T5:Verify BFD session is UP under BGP and BFD")
        ###########################################################################################

        result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name= vrfname, peer=dut2_link_local,local_addr=dut1_link_local,interface=D1_ports[1],status='up',retry_count=2,delay=1)
        if result is False:
            st.report_fail('bfd_fail_reason','BFD session did not come up over link-local address')

        result = retry_api(bgp_api.verify_bgp_summary, vars.D1, family='ipv6', shell='vtysh', neighbor=D1_ports[1],
                           state='Established', vrf=vrfname, retry_count=3, delay=1)
        if result is False:
            st.report_fail('bfd_fail_reason','BFD state incorrect for %s'%dut2_link_local)

        ###########################################################################################
        hdrMsg("Step T6:Bring down the interface on dut2 and verify BFD and BGP session goes down")
        ###########################################################################################
        debug_bgp_vrf([dut1, dut3], [dut2_link_local, dut1_link_local], 'ipv6', vrfname,[D1_ports[1],D3_ports[1]])
        port.shutdown(flap_dut,[flap_ports[1]])
        st.wait(1)
        result = bgp_api.verify_bgp_summary(vars.D1, family='ipv6', shell='vtysh', neighbor=D1_ports[1],
                           state='Established', vrf=vrfname,)
        result1 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=dut2_link_local,
                           local_addr=dut1_link_local, interface=D1_ports[1], status='down')
        if result is True or result1 is True:
            debug_bgp_vrf([dut1, dut3], [dut2_link_local, dut1_link_local], 'ipv6', vrfname,[D1_ports[1],D3_ports[1]])
            st.report_fail('bfd_fail_reason','BGP link-local neighbor did not go down')

        ###########################################################################################
        hdrMsg("Step T7:Bring up the interface on dut2 and verify BFD and BGP session comes up")
        ###########################################################################################

        port.noshutdown(flap_dut,[flap_ports[1]])
        result = retry_api(bgp_api.verify_bgp_summary, vars.D1, family='ipv6', shell='vtysh', neighbor=D1_ports[1],
                           state='Established', vrf=vrfname, retry_count=10, delay=3)
        if result is False:
            st.report_fail('bfd_fail_reason','BFD state not UP for %s after link is admin up'%dut2_link_local)

        ###########################################################################################
        hdrMsg("Step T8:Configure non-default timers under BFD peers and verify it gets updated")
        ###########################################################################################

        dict1 ={'vrf_name': vrfname, "interface":D1_ports[1],'neighbor_ip':dut2_link_local,'local_address':dut1_link_local,'tx_intv':'4000','rx_intv':'5000','multiplier':'4'}
        dict2 ={'vrf_name': vrfname, "interface":D3_ports[1],'neighbor_ip':dut1_link_local,'local_address':dut2_link_local,'tx_intv':'2000','rx_intv':'3000','multiplier':'3'}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

        ###########################################################################################
        hdrMsg("Step T9: Verify BFD peers are updated with user configured non-default timers")
        ###########################################################################################

        result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name= vrfname, peer=dut2_link_local,local_addr=dut1_link_local,interface=D1_ports[1],status='up',rx_interval=[['5000','3000']],tx_interval=[['4000','2000']],multiplier=[['4','3']],
                           retry_count=3,delay=1)
        if result is False:
            st.report_fail('bfd_fail_reason','BFD  Peers did not have configured timer values')

    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def bfd_fixture_024(request, prologue_epilogue):
    ###########################################################################################
    hdrMsg("Step test-config1: Enable BFD session for BGP neighbors %s on dut1 and %s on dut3"%(dut3_ip_list[0],dut1_ip_list[0]))
    ###########################################################################################
    dict1 = {"local_asn": dut1_as,'neighbor_ip': dut3_ip_list[2], 'config': 'yes'}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': dut1_ip_list[2], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {"interface": trunk_vlan_name[0], 'neighbor_ip': dut3_ip_list[2],
              'tx_intv': '300', 'rx_intv': '300', 'multiplier': '3'}
    dict2 = {"interface": trunk_vlan_name[0], 'neighbor_ip': dut1_ip_list[2],
              'tx_intv': '300', 'rx_intv': '300', 'multiplier': '3'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    yield
    hdrMsg("### CLEANUP for TC24 ###")
    #tg1.tg_traffic_control(action='stop', port_handle=tg_handles)
    dict1 = {"interface": trunk_vlan_name[0], 'neighbor_ip': dut3_ip_list[2],'config':'no'}
    dict2 = {"interface": trunk_vlan_name[0], 'neighbor_ip': dut1_ip_list[2],'config':'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {"local_asn": dut1_as,'neighbor_ip': dut3_ip_list[2], 'config': 'no'}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': dut1_ip_list[2], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    tg1.tg_traffic_config(mode='modify',stream_id=data.streams['stream_handle_list'][0],rate_pps=traffic_rate)
    tg1.tg_traffic_config(mode='enable', stream_id=data.streams['stream_handle_list'][1])
    tg1.tg_traffic_control(action='reset', port_handle=tg_handles[1])
    arp.delete_static_arp(dut1, tg_dut1_ip)
    hdrMsg("### CLEANUP End####")


@pytest.mark.functionality
def test_FtOpSoRoBfdFn094(bfd_fixture_024):
    ###########################################################################################
    hdrMsg("TCid: FtOpSoRoBfdFn094; TC SUMMARY : BFD control packet forwarding with data traffic at line rate")
    ###########################################################################################

    ###########################################################################################
    hdrMsg("Step T1: Configure static arp on dut1 and configure ipv4 stream on tg2 with 100 percent line-rate")
    ###########################################################################################

    arp.add_static_arp(dut1,tg_dut1_ip,tg_dut1_mac, interface=D1_ports[3])
    D3_tg2_mac = basic.get_ifconfig(dut3, D3_ports[3])[0]['mac']
    stream_v4_tg2 = tg1.tg_traffic_config(mac_src=tg_dut3_mac, mac_dst=D3_tg2_mac, rate_percent=100.00, \
                                      mode='create', port_handle=tg_handles[1], transmit_mode='continuous',
                                      l3_protocol='ipv4', ip_src_addr=tg_dut3_ip \
                                      , ip_dst_addr=tg_dut1_ip, mac_discovery_gw=dut3_tg_ip)
    data.streams['stream_tg2_handle'] = stream_v4_tg2['stream_id']

    ###########################################################################################
    hdrMsg("Step T2: Modify line-rate for ipv4 stream on tg1 to 100 percent")
    ###########################################################################################
    tg1.tg_traffic_config(mode='disable',stream_id=data.streams['stream_handle_list'][1])
    tg1.tg_traffic_config(mode='modify',stream_id=data.streams['stream_handle_list'][0],rate_percent=100.0)


    ###########################################################################################
    hdrMsg("Step T3: Verify BFD session is UP for BGP nbr %s"%dut3_ip_list[2])
    ###########################################################################################
    result= bfd.verify_bfd_peer(dut1,peer=dut3_ip_list[2],interface=trunk_vlan_name[0],status='up')
    if result is False:
        st.report_fail('bfd_fail_reason','BFD session is not up')

    ###########################################################################################
    hdrMsg("Step T4: Start 100 percent bidriectional traffic for 60 sec and verify BFD session did not flap")
    ###########################################################################################
    st.log("Get the initial BFD session up time")
    output = bfd.verify_bfd_peer(dut1, peer=dut3_ip_list[2], interface=trunk_vlan_name[0], return_dict='yes')
    if output[0]['uptimemin'] == '':
        uptimemin = 0
    else:
        uptimemin = int(output[0]['uptimemin'])
    if output[0]['uptimesec'] == '':
        st.report_fail('bfd_fail_reason', 'BFD timers not displayed properly')
    uptime = {}
    uptime['initial'] = (uptimemin*60) + int(output[0]['uptimesec'])

    tg1.tg_traffic_control(action='run', stream_handle=data.streams['stream_tg2_handle'])

    st.log("Poll BFD uptime every 10 sec and verify BFD did not flap")
    for i in range(4):
        output = bfd.verify_bfd_peer(dut1,peer=dut3_ip_list[2],interface=trunk_vlan_name[0],return_dict='yes')
        if len(output) != 0:
            if output[0]['uptimemin'] == '':
                uptimemin = 0
            else:
                uptimemin = int(output[0]['uptimemin'])
            uptime[i] = (uptimemin * 60) + int(output[0]['uptimesec'])
        else:
            st.report_fail('bfd_fail_reason','BFD session went down')
        st.wait(1)

    tg1.tg_traffic_control(action='stop', stream_handle=data.streams['stream_tg2_handle'])
    st.log(uptime)
    if uptime['initial'] < uptime[1]:
        for i in range(4):
            if i < 3:
                if uptime[i] > uptime[i+1]:
                    st.report_fail('bfd_fail_reason','BFD session uptime resets with line-rate traffic Old_uptime: %s sec and new_uptime = %s sec'%(uptime[i],uptime[i+1]))
    else:
        st.report_fail('bfd_fail_reason','BFD uptime is less than initial uptime value. Initial: %s sec current :%s sec'%(uptime['initial'],uptime[1]))
    st.report_pass('test_case_passed')


def get_echo_interval(dut,peer,interface,interval=50.0,vrfname='default'):
    tx_interval=0;rx_interval=0
    counters = bfd.get_bfd_peer_counters(dut,peer=peer,interface=interface,vrf_name=vrfname)
    if len(counters) !=0:
        echo_tx = int(counters[0]['echopktout'])
        echo_rx = int(counters[0]['echopktin'])
        st.log("Wait for packets to tx/receive")
        if type(interval) is float:
            wait_time = 500 * interval
        else:
            wait_time = 5*interval
        st.log("wait for %s sec"%wait_time)
        st.wait(wait_time)
        counters = bfd.get_bfd_peer_counters(dut,peer=peer,interface=interface,vrf_name=vrfname)
        echo_tx_1 = int(counters[0]['echopktout'])
        echo_rx_1 = int(counters[0]['echopktin'])

        packets_tx = echo_tx_1- echo_tx
        packets_rx = echo_rx_1 - echo_rx
        st.log("Total Echo packets transmitted : %s"%packets_tx)
        st.log("Total Echo packets Received : %s" % packets_rx)
        if packets_tx !=0 and packets_rx !=0:
            tx_interval = (float(wait_time)/float(packets_tx))
            rx_interval = (float(wait_time)/float(packets_rx))
            st.log("Transmit interval : %s sec"%tx_interval)
            st.log("Receive Interval : %s sec"%rx_interval)
        return tx_interval,rx_interval
    else:
        st.log("output is empty")
        return False


def get_bfd_control_interval(dut,peer,interface,interval=50):
    tx_interval=0
    counters = bfd.get_bfd_peer_counters(dut,peer=peer,interface=interface)
    if len(counters) !=0:
        bfd_tx = int(counters[0]['cntrlpktout'])

        st.log("Wait for packets to transmit")
        if type(interval) is float:
            wait_time = 500 * interval
        else:
            wait_time = 5*interval
        st.log("wait for %s sec"%wait_time)
        st.wait(wait_time)
        counters = bfd.get_bfd_peer_counters(dut,peer=peer,interface=interface)
        bfd_tx_1 = int(counters[0]['cntrlpktout'])

        packets_tx = bfd_tx_1- bfd_tx

        st.log("Total BFD control packets transmitted : %s"%packets_tx)

        if packets_tx !=0:
            tx_interval = (float(wait_time)/float(packets_tx))
            st.log("Transmit interval : %s sec"%tx_interval)
        return tx_interval
    else:
        st.log("output is empty")
        return False


def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n %s \n######################################################################"%msg)


def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 10)
    delay = kwargs.get("delay", 3)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if func(args,**kwargs):
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


def single_hop_config():
    hdrMsg("##### BASE config Starts ####")
    if l2_switch == 'yes':
        ############################################################################################
        hdrMsg(" \n####### BFD single-hop between dut1 and dut3 with dut2 as L2 switch in between ##############\n")
        ############################################################################################
    else:
        ############################################################################################
        hdrMsg(" \n####### BFD single-hop between directly connected dut1 and dut3 ##############\n")
        ############################################################################################

    ############################################################################################
    hdrMsg("Step-C1: Configure Vlans %s  on all duts"%([access_vlan]+trunk_vlan))
    ############################################################################################

    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.config_vlan_range, dut1, '{} {}'.format(access_vlan,trunk_vlan_vrf[-1])],
                              [vlan_api.config_vlan_range, dut2, '{} {}'.format(access_vlan,trunk_vlan_vrf[-1])],
                             [vlan_api.config_vlan_range, dut3, '{} {}'.format(access_vlan,trunk_vlan_vrf[-1])]])
    else:
        utils.exec_all(True, [[vlan_api.config_vlan_range, dut1, '{} {}'.format(access_vlan, trunk_vlan_vrf[-1])],
                              [vlan_api.config_vlan_range, dut3, '{} {}'.format(access_vlan, trunk_vlan_vrf[-1])]])

    ############################################################################################
    hdrMsg("Step-C2: Configure Vlan %s as untagged on all duts"%access_vlan)
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True,[[vlan_api.add_vlan_member,dut1,access_vlan,D1_ports[0], False],
                             [vlan_api.add_vlan_member,dut2, access_vlan, [D2_ports[0], D2_ports[3]], False],
                            [vlan_api.add_vlan_member,dut3,access_vlan,D3_ports[0], False]])
    else:
        utils.exec_all(True, [[vlan_api.add_vlan_member, dut1, access_vlan, D1_ports[0], False],
                              [vlan_api.add_vlan_member, dut3, access_vlan, D3_ports[0], False]])

    ############################################################################################
    hdrMsg("Step-C3: Configure Vlans %s as Tagged on all duts"%trunk_vlan)
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True,[[vlan_api.config_vlan_range_members,dut1,'{} {}'.format(trunk_vlan[0],trunk_vlan[-1]),D1_ports[2]],
                             [vlan_api.config_vlan_range_members,dut2,'{} {}'.format(trunk_vlan[0],trunk_vlan[-1]),D2_ports[2]],
                                 [vlan_api.config_vlan_range_members,dut3,'{} {}'.format(trunk_vlan[0],trunk_vlan[-1]),D3_ports[2]]])
        vlan_api.config_vlan_range_members(dut2, '{} {}'.format(trunk_vlan[0], trunk_vlan[-1]), D2_ports[5])
    else:
        utils.exec_all(True,[[vlan_api.config_vlan_range_members,dut1,'{} {}'.format(trunk_vlan[0],trunk_vlan[-1]),D1_ports[2]],
                                 [vlan_api.config_vlan_range_members,dut3,'{} {}'.format(trunk_vlan[0],trunk_vlan[-1]),D3_ports[2]]])

    if l2_switch == 'yes':
        ############################################################################################
        hdrMsg("Step-C4: Configure vlan %s on dut2 to access router port between dut1 and dut3"%dut2_l2_vlan)
        ############################################################################################
        vlan_api.create_vlan(dut2, dut2_l2_vlan)
        vlan_api.add_vlan_member(dut2,dut2_l2_vlan, [D2_ports[1], flap_ports[1]], False)


    ############################################################################################
    hdrMsg("Step-C5: Configure ip address %s on dut1 and %s on dut3 for vlan %s"\
           % (dut1_ip_list[0],dut3_ip_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,dut1, access_vlan_name,dut1_ip_list[0],ip_mask],[ip_api.config_ip_addr_interface,dut3, access_vlan_name, dut3_ip_list[0], ip_mask]])

    ############################################################################################
    hdrMsg("Step-C6: Configure ip address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_ip_list[2:5],dut3_ip_list[2:5],trunk_vlan))
    ############################################################################################
    for vlan,ip_1,ip_3 in zip(trunk_vlan_name,dut1_ip_list[2:5],dut3_ip_list[2:5]):
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,dut1, vlan,ip_1,ip_mask],[ip_api.config_ip_addr_interface,dut3, vlan,ip_3,ip_mask]])


    ############################################################################################
    hdrMsg("Step-C7: Configure ip address %s on D1D2P2 dut1 and %s on D3D2P2 dut3 " \
           % (dut1_ip_list[1],dut3_ip_list[1]))
    ############################################################################################

    utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1,D1_ports[1], dut1_ip_list[1], ip_mask],[ip_api.config_ip_addr_interface, dut3, D3_ports[1], dut3_ip_list[1], ip_mask]])

    ############################################################################################
    hdrMsg("Step-C8: Configure ipv6 address %s on dut1 and %s on dut3 for vlan %s" \
           % (dut1_ipv6_list[0], dut3_ipv6_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, access_vlan_name, dut1_ipv6_list[0], ipv6_mask,'ipv6'],[ip_api.config_ip_addr_interface, dut3, access_vlan_name, dut3_ipv6_list[0], ipv6_mask,'ipv6']])


    ############################################################################################
    hdrMsg("Step-C9: Configure ipv6 address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_ipv6_list[2:5], dut3_ipv6_list[2:5], trunk_vlan))
    ############################################################################################
    for vlan,ip_1,ip_3 in zip(trunk_vlan_name,dut1_ipv6_list[2:5],dut3_ipv6_list[2:5]):
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,dut1, vlan,ip_1,ipv6_mask,'ipv6'],[ip_api.config_ip_addr_interface,dut3, vlan,ip_3,ipv6_mask,'ipv6']])

    ############################################################################################
    hdrMsg("Step-C10: Configure ipv6 address %s on D1D2P2 dut1 and %s on D3D2P2 dut3 "\
           % (dut1_ipv6_list[1], dut3_ipv6_list[1]))
    ############################################################################################

    utils.exec_all(True,[[ip_api.config_ip_addr_interface,dut1, D1_ports[1], dut1_ipv6_list[1], ipv6_mask,'ipv6'],[ip_api.config_ip_addr_interface,dut3, D3_ports[1], dut3_ipv6_list[1], ipv6_mask,'ipv6']])
    ############################################################################################
    hdrMsg("##### Configure iBGP neighbors btween dut1 and dut3 ##########")
    ############################################################################################

    ############################################################################################
    hdrMsg("Step-C11: Configure BGP routerlocals-as %s ,router-id %s on dut1 and local-as %s ,router-id %s on dut3"%(dut1_as,dut1_router_id,dut3_as,dut3_router_id))
    ############################################################################################

    dict1 = {'local_as':dut1_as,'router_id':dut1_router_id,'config_type_list':['router_id',"max_path_ibgp"],'max_path_ibgp':1}
    dict2 = {'local_as':dut3_as,'router_id':dut3_router_id,'config_type_list':['router_id',"max_path_ibgp","network"],'network':'{}/{}'.format(tg_dest_nw,ip_mask),'max_path_ibgp':1}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'local_as':dut1_as, 'config_type_list': ["max_path_ibgp"],'max_path_ibgp':1,'addr_family':'ipv6'}
    dict2 = {'local_as':dut3_as, 'config_type_list': ["max_path_ibgp","network"], 'network':'{}/{}'.format(tg_dest_nw_v6,ipv6_mask),'max_path_ibgp':1,'addr_family':'ipv6'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])
    ############################################################################################
    hdrMsg("Step-C12: Configure iBGP neighbors %s on dut1 and %s on dut3"%(dut3_ip_list[0:2],dut1_ip_list[0:2]))
    ############################################################################################

    dict1 = {'local_as':dut1_as, 'neighbor':dut3_ip_list[0],'remote_as':dut3_as,'config_type_list':["neighbor","connect"],'connect':1,'keepalive':keep_alive,'holdtime':hold_down}
    dict2 = {'local_as':dut3_as, 'neighbor':dut1_ip_list[0],'remote_as':dut1_as,'config_type_list':["neighbor","connect"],'connect':1}
    parallel.exec_parallel(True,[dut1,dut3],bgp_api.config_bgp,[dict1,dict2])

    dict1 = {'local_as':dut1_as, 'neighbor':dut3_ip_list[1],'remote_as':dut3_as,'config_type_list':["neighbor","connect"],'connect':1}
    dict2 = {'local_as':dut3_as, 'neighbor':dut1_ip_list[1],'remote_as':dut1_as,'config_type_list':["neighbor","connect"],'connect':1}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    ############################################################################################
    hdrMsg("Step-C13: Configure neighbors %s under peer-group %s on dut1 and %s on dut3 "%(dut3_ip_list[2:5],peer_v4,dut1_ip_list[2:5]))
    ############################################################################################
    for nbr_1,nbr_3 in zip(dut3_ip_list[2:5],dut1_ip_list[2:5]):
       dict1 = {'local_as':dut1_as, 'peergroup':peer_v4,'config_type_list':['peergroup'],'remote_as':dut3_as,'neighbor':nbr_1}
       dict2 = {'local_as':dut3_as, 'peergroup': peer_v4, 'config_type_list': ['peergroup'], 'remote_as': dut1_as,'neighbor': nbr_3}
       parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])


    dict1 = {'local_as':dut1_as, 'peergroup': peer_v4, 'config_type_list': ['connect'], 'neighbor': peer_v4,'connect':1}
    dict2 = {'local_as':dut3_as, 'peergroup': peer_v4, 'config_type_list': ['connect'], 'neighbor': peer_v4,'connect':1}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])
    ############################################################################################
    hdrMsg("##### Configure iBGP+ neighbors btween dut1 and dut3 ##########")
    ############################################################################################

    ############################################################################################
    hdrMsg("Step-C14: Configure iBGP neighbors %s on dut1 and %s on dut3" % (dut3_ipv6_list[0:2], dut1_ipv6_list[0:2]))
    ############################################################################################
    ip_api.config_route_map_global_nexthop(dut1,'rmap_v6',config='yes')
    ip_api.config_route_map_global_nexthop(dut3, 'rmap_v6',config='yes')
    dict1 = {'local_as':dut1_as,'neighbor':dut3_ipv6_list[0],'remote_as':dut3_as,'config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'rmap_v6','diRection':'in','connect':1,'addr_family':'ipv6'}
    dict2 = {'local_as':dut3_as,'neighbor':dut1_ipv6_list[0],'remote_as':dut1_as,'config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'rmap_v6','diRection':'in','connect':1,'addr_family':'ipv6'}
    parallel.exec_parallel(True,[dut1,dut3],bgp_api.config_bgp,[dict1,dict2])

    dict1 = {'local_as':dut1_as, 'neighbor':dut3_ipv6_list[1],'remote_as':dut3_as,'config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'rmap_v6','diRection':'in','connect':1,'addr_family':'ipv6'}
    dict2 = {'local_as':dut3_as, 'neighbor':dut1_ipv6_list[1],'remote_as':dut1_as,'config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'rmap_v6','diRection':'in','connect':1,'addr_family':'ipv6'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    ############################################################################################
    hdrMsg("Step-C15: Configure neighbors %s under peer-group %s on dut1 "%(dut3_ipv6_list[2:5],peer_v6))
    ############################################################################################
    for nbr_1,nbr_3 in zip(dut3_ipv6_list[2:5],dut1_ipv6_list[2:5]):
        dict1 = {'local_as': dut1_as, 'peergroup': peer_v6, 'config_type_list': ['peergroup','activate'], 'remote_as': dut3_as,'neighbor': nbr_1,'addr_family':'ipv6'}
        dict2 = {'local_as': dut3_as, 'peergroup': peer_v6, 'config_type_list': ['peergroup','activate'], 'remote_as': dut1_as,'neighbor': nbr_3,'addr_family':'ipv6'}
        parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'local_as':dut1_as, 'peergroup': peer_v6, 'config_type_list': ['connect','routeMap'],'routeMap':'rmap_v6','diRection':'in', 'neighbor': peer_v6,'connect':1,'addr_family':'ipv6'}
    dict2 = {'local_as':dut3_as, 'peergroup': peer_v6, 'config_type_list': ['connect','routeMap'],'routeMap':'rmap_v6','diRection':'in', 'neighbor': peer_v6,'connect':1,'addr_family':'ipv6'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    ############################################################################################
    hdrMsg("Step-C16: Config ip address %s and ipv6 address %s on dut1 tg port " % (dut1_tg_ip,dut1_tg_ipv6))
    ############################################################################################

    ip_api.config_ip_addr_interface(dut1, D1_ports[3], dut1_tg_ip, ip_mask)
    ip_api.config_ip_addr_interface(dut1, D1_ports[3], dut1_tg_ipv6, ipv6_mask,family='ipv6')

    ############################################################################################
    hdrMsg("Step-C17: Config ip address %s and ipv6 address %s on dut3 tg port " % (dut3_tg_ip,dut3_tg_ipv6))
    ############################################################################################

    ip_api.config_ip_addr_interface(dut3, D3_ports[3], dut3_tg_ip, ip_mask)
    ip_api.config_ip_addr_interface(dut3, D3_ports[3], dut3_tg_ipv6, ipv6_mask,family='ipv6')

    ############################################################################################
    hdrMsg("Step-C18: Get mac for D1T1P1 from dut1")
    ############################################################################################

    D1_tg1_mac = basic.get_ifconfig(dut1,D1_ports[3])[0]['mac']
    arp.add_static_arp(dut3,tg_dut3_ip,tg_dut3_mac, interface=D3_ports[3])
    arp.config_static_ndp(dut3,tg_dut3_ipv6, tg_dut3_mac,D3_ports[3], operation="add")
    ############################################################################################
    hdrMsg("Step-C19: Configure ipv4 and ipv6 L3 streams on T1D1P1 to destination %s ,%s on T1D3P1"%(tg_dut3_ip,tg_dut3_ipv6))
    ############################################################################################
    tg1.tg_traffic_control(action='reset',port_handle=tg_handles)

    stream_v4 = tg1.tg_traffic_config(mac_src = tg_dut1_mac,mac_dst=D1_tg1_mac,rate_pps=traffic_rate,\
            mode='create',port_handle=tg_handles[0],transmit_mode='continuous',l3_protocol='ipv4', ip_src_addr=tg_dut1_ip\
                          , ip_dst_addr=tg_dut3_ip, mac_discovery_gw=dut1_tg_ip, port_handle2=tg_handles[1])
    stream_v4_handle = stream_v4['stream_id']


    stream_v6 = tg1.tg_traffic_config(mac_src = tg_dut1_mac,mac_dst=D1_tg1_mac,rate_pps=traffic_rate,\
            mode='create',port_handle=tg_handles[0],transmit_mode='continuous',l3_protocol='ipv6', ipv6_src_addr=tg_dut1_ipv6\
                          , ipv6_dst_addr=tg_dut3_ipv6, mac_discovery_gw=dut1_tg_ipv6, port_handle2=tg_handles[1])
    stream_v6_handle = stream_v6['stream_id']

    data.streams['stream_handle_list'] = [stream_v4_handle,stream_v6_handle]

    hdrMsg("stream handle list created %s " % data.streams['stream_handle_list'])
    ############################################################################################
    hdrMsg("Step-C20: Verify all BGP/BGP+ sessions are in Established state")
    ############################################################################################
    result = retry_api(ip_bgp.check_bgp_session,dut1,nbr_list=dut3_ip_list+dut3_ipv6_list, state_list=['Established']*10,retry_count=10,delay=3)
    if result is False:
        st.error("One or more BGP sessions did not come up")
        bfd.debug_bgp_bfd([dut1, dut3])
        st.report_fail('module_config_failed', 'One or more BGP sessions did not come up')
    hdrMsg("##### BASE config for default vrf END ####")


    hdrMsg("##### VRF BASE config Starts ####")
    ############################################################################################
    ############################################################################################
    ############################################################################################
    hdrMsg("Step-C1_VRF: Configure vrf  %s" % ('vrf-101'))
    ############################################################################################
    dict1 = {'vrf_name': user_vrf_name , 'skip_error': True}
    parallel.exec_parallel(True, [dut1, dut3], vrf_api.config_vrf, [dict1, dict1])

    if l2_switch == 'yes':
        ############################################################################################
        hdrMsg(" \n####### VRF-BFD single-hop between dut1 and dut3 with dut2 as L2 switch in between ##############\n")
        ############################################################################################
    else:
        ############################################################################################
        hdrMsg(" \n####### VRF-BFD single-hop between directly connected dut1 and dut3 ##############\n")
        ############################################################################################

    ############################################################################################
    hdrMsg("Step-C2_VRF: Configure Vlan %s as untagged on all duts" % access_vlan_vrf)
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.add_vlan_member, dut1, access_vlan_vrf, D1_ports_vrf[0], False],
                              [vlan_api.add_vlan_member, dut2, access_vlan_vrf, [D2_ports_vrf[0], D2_ports_vrf[3]], False],
                              [vlan_api.add_vlan_member, dut3, access_vlan_vrf, D3_ports_vrf[0], False]])
    else:
        utils.exec_all(True, [[vlan_api.add_vlan_member, dut1, access_vlan_vrf, D1_ports_vrf[0], False],
                              [vlan_api.add_vlan_member, dut3, access_vlan_vrf, D3_ports_vrf[0], False]])

    ############################################################################################
    hdrMsg("Step-C3_VRF: Configure Vlans %s as Tagged on all duts" % trunk_vlan_vrf)
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [
            [vlan_api.config_vlan_range_members, dut1, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D1_ports_vrf[2]],
            [vlan_api.config_vlan_range_members, dut2, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D2_ports_vrf[2]],
            [vlan_api.config_vlan_range_members, dut3, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D3_ports_vrf[2]]])
        vlan_api.config_vlan_range_members(dut2, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D2_ports_vrf[5])
    else:
        utils.exec_all(True, [
            [vlan_api.config_vlan_range_members, dut1, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D1_ports_vrf[2]],
            [vlan_api.config_vlan_range_members, dut3, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D3_ports_vrf[2]]])

    if l2_switch == 'yes':
        ############################################################################################
        hdrMsg("Step-C4_VRF: Configure vlan %s on dut2 to access router port between dut1 and dut3" % dut2_l2_vlan)
        ############################################################################################
        vlan_api.create_vlan(dut2, dut2_l2_vlan)
        vlan_api.add_vlan_member(dut2, dut2_l2_vlan, [D2_ports_vrf[1], flap_ports_vrf[1]], False)

    ############################################################################################
    hdrMsg("Step-C5_VRF: Bind to vrf and configure ip address %s on dut1 and %s on dut3 for vlan %s" \
           % (dut1_ip_list[0], dut3_ip_list[0], access_vlan_vrf))
    ############################################################################################
    #for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
    dict1 = {'vrf_name':user_vrf_name, 'intf_name':access_vlan_name_vrf,'skip_error':True}
    dict2 = {'vrf_name':user_vrf_name, 'intf_name':access_vlan_name_vrf,'skip_error':True}
    parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, access_vlan_name_vrf, dut1_ip_list[0], ip_mask],
                          [ip_api.config_ip_addr_interface, dut3, access_vlan_name_vrf, dut3_ip_list[0], ip_mask]])

    ############################################################################################
    hdrMsg("Step-C6_VRF: Bind to vrf and configure ip address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_ip_list[2:5], dut3_ip_list[2:5], trunk_vlan_vrf))
    ############################################################################################
    for vlan, ip_1, ip_3 in zip(trunk_vlan_name_vrf, dut1_ip_list[2:5], dut3_ip_list[2:5]):
        dict1 = {'vrf_name': user_vrf_name, 'intf_name': vlan, 'skip_error': True}
        dict2 = {'vrf_name': user_vrf_name, 'intf_name': vlan, 'skip_error': True}
        parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

        utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, vlan, ip_1, ip_mask],
                              [ip_api.config_ip_addr_interface, dut3, vlan, ip_3, ip_mask]])

    ############################################################################################
    hdrMsg("Step-C7_VRF: Bind to vrf and configure ip address %s on D1D2P2 dut1 and %s on D3D2P2 dut3 " \
           % (dut1_ip_list[1], dut3_ip_list[1]))
    ############################################################################################
    dict1 = {'vrf_name':user_vrf_name, 'intf_name':D1_ports_vrf[1],'skip_error':True}
    dict2 = {'vrf_name':user_vrf_name, 'intf_name':D3_ports_vrf[1],'skip_error':True}
    parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, D1_ports_vrf[1], dut1_ip_list[1], ip_mask],
                          [ip_api.config_ip_addr_interface, dut3, D3_ports_vrf[1], dut3_ip_list[1], ip_mask]])

    ############################################################################################
    hdrMsg("Step-C8_VRF: Configure ipv6 address %s on dut1 and %s on dut3 for vlan %s" \
           % (dut1_ipv6_list[0], dut3_ipv6_list[0], access_vlan_vrf))
    ############################################################################################

    utils.exec_all(True,
                   [[ip_api.config_ip_addr_interface, dut1, access_vlan_name_vrf, dut1_ipv6_list[0], ipv6_mask, 'ipv6'],
                    [ip_api.config_ip_addr_interface, dut3, access_vlan_name_vrf, dut3_ipv6_list[0], ipv6_mask, 'ipv6']])

    ############################################################################################
    hdrMsg("Step-C9_VRF: Configure ipv6 address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_ipv6_list[2:5], dut3_ipv6_list[2:5], trunk_vlan_vrf))
    ############################################################################################
    for vlan, ip_1, ip_3 in zip(trunk_vlan_name_vrf, dut1_ipv6_list[2:5], dut3_ipv6_list[2:5]):
        utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, vlan, ip_1, ipv6_mask, 'ipv6'],
                              [ip_api.config_ip_addr_interface, dut3, vlan, ip_3, ipv6_mask, 'ipv6']])

    ############################################################################################
    hdrMsg("Step-C10_VRF: Configure ipv6 address %s on D1D2P2 dut1 and %s on D3D2P2 dut3 " \
           % (dut1_ipv6_list[1], dut3_ipv6_list[1]))
    ############################################################################################

    utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, D1_ports_vrf[1], dut1_ipv6_list[1], ipv6_mask, 'ipv6'],
                          [ip_api.config_ip_addr_interface, dut3, D3_ports_vrf[1], dut3_ipv6_list[1], ipv6_mask, 'ipv6']])
    ############################################################################################
    hdrMsg("##### Configure iBGP neighbors btween dut1 and dut3 over VRF##########")
    ############################################################################################

    ############################################################################################
    hdrMsg("Step-C11_VRF: Configure BGP routerlocals-as %s ,router-id %s on dut1 and local-as %s ,router-id %s on dut3" % (
    dut1_as, dut1_router_id, dut3_as, dut3_router_id))
    ############################################################################################

    dict1 = {'vrf_name':user_vrf_name, 'local_as': dut1_as, 'router_id': dut1_router_id, 'config_type_list': ['router_id', "max_path_ibgp"],
             'max_path_ibgp': 1}
    dict2 = {'vrf_name':user_vrf_name, 'local_as': dut3_as, 'router_id': dut3_router_id,
             'config_type_list': ['router_id', "max_path_ibgp", "network"],
             'network': '{}/{}'.format(tg_dest_nw, ip_mask), 'max_path_ibgp': 1}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'vrf_name':user_vrf_name, 'config_type_list': ["max_path_ibgp"], 'local_as': dut1_as, 'max_path_ibgp': 1, 'addr_family': 'ipv6'}
    dict2 = {'vrf_name':user_vrf_name, 'config_type_list': ["max_path_ibgp", "network"], 'local_as': dut3_as, 'network': '{}/{}'.format(tg_dest_nw_v6, ipv6_mask),
             'max_path_ibgp': 1, 'addr_family': 'ipv6'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])
    ############################################################################################
    hdrMsg("Step-C12_VRF: Configure iBGP neighbors %s on dut1 and %s on dut3" % (dut3_ip_list[0:2], dut1_ip_list[0:2]))
    ############################################################################################

    dict1 = {'local_as': dut1_as, 'vrf_name':user_vrf_name, 'neighbor': dut3_ip_list[0], 'remote_as': dut3_as, 'config_type_list': ["neighbor", "connect"],
             'connect': 1, 'keepalive': keep_alive, 'holdtime': hold_down}
    dict2 = {'local_as': dut3_as, 'vrf_name':user_vrf_name, 'neighbor': dut1_ip_list[0], 'remote_as': dut1_as, 'config_type_list': ["neighbor", "connect"],
             'connect': 1}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'local_as': dut1_as, 'vrf_name':user_vrf_name, 'neighbor': dut3_ip_list[1], 'remote_as': dut3_as, 'config_type_list': ["neighbor", "connect"],
             'connect': 1}
    dict2 = {'local_as': dut3_as, 'vrf_name':user_vrf_name, 'neighbor': dut1_ip_list[1], 'remote_as': dut1_as, 'config_type_list': ["neighbor", "connect"],
             'connect': 1}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    ############################################################################################
    hdrMsg("Step-C13_VRF: Configure neighbors %s under peer-group %s on dut1 and %s on dut3 " % (
    dut3_ip_list[2:5], peer_v4_vrf, dut1_ip_list[2:5]))
    ############################################################################################
    for nbr_1, nbr_3 in zip(dut3_ip_list[2:5], dut1_ip_list[2:5]):
        dict1 = {'local_as': dut1_as, 'vrf_name':user_vrf_name, 'peergroup': peer_v4_vrf, 'config_type_list': ['peergroup'], 'remote_as': dut3_as, 'neighbor': nbr_1}
        dict2 = {'local_as': dut3_as, 'vrf_name':user_vrf_name, 'peergroup': peer_v4_vrf, 'config_type_list': ['peergroup'], 'remote_as': dut1_as, 'neighbor': nbr_3}
        parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'local_as': dut1_as, 'vrf_name':user_vrf_name, 'peergroup': peer_v4_vrf, 'config_type_list': ['connect'], 'neighbor': peer_v4_vrf,
             'connect': 1}
    dict2 = {'local_as': dut3_as, 'vrf_name':user_vrf_name, 'peergroup': peer_v4_vrf, 'config_type_list': ['connect'], 'neighbor': peer_v4_vrf,
             'connect': 1}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])
    ############################################################################################
    hdrMsg("##### Configure iBGP+ neighbors over VRF btween dut1 and dut3 ##########")
    ############################################################################################

    ############################################################################################
    hdrMsg("Step-C14_VRF: Configure iBGP-VRF neighbors %s on dut1 and %s on dut3" % (dut3_ipv6_list[0:2], dut1_ipv6_list[0:2]))
    ############################################################################################
    ip_api.config_route_map_global_nexthop(dut1, 'rmap_v6', config='yes')
    ip_api.config_route_map_global_nexthop(dut3, 'rmap_v6', config='yes')
    dict1 = {'local_as': dut1_as, 'vrf_name':user_vrf_name, 'neighbor': dut3_ipv6_list[0], 'remote_as': dut3_as,
             'config_type_list': ["neighbor", "connect", 'activate', 'routeMap'], 'routeMap': 'rmap_v6',
             'diRection': 'in', 'connect': 1, 'addr_family': 'ipv6'}
    dict2 = {'local_as': dut3_as, 'vrf_name':user_vrf_name, 'neighbor': dut1_ipv6_list[0], 'remote_as': dut1_as,
             'config_type_list': ["neighbor", "connect", 'activate', 'routeMap'], 'routeMap': 'rmap_v6',
             'diRection': 'in', 'connect': 1, 'addr_family': 'ipv6'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'local_as': dut1_as, 'vrf_name':user_vrf_name, 'neighbor': dut3_ipv6_list[1], 'remote_as': dut3_as,
             'config_type_list': ["neighbor", "connect", 'activate', 'routeMap'], 'routeMap': 'rmap_v6',
             'diRection': 'in', 'connect': 1, 'addr_family': 'ipv6'}
    dict2 = {'local_as': dut3_as, 'vrf_name':user_vrf_name, 'neighbor': dut1_ipv6_list[1], 'remote_as': dut1_as,
             'config_type_list': ["neighbor", "connect", 'activate', 'routeMap'], 'routeMap': 'rmap_v6',
             'diRection': 'in', 'connect': 1, 'addr_family': 'ipv6'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    ############################################################################################
    hdrMsg("Step-C15_VRF: Configure neighbors %s under peer-group %s on dut1 " % (dut3_ipv6_list[2:5], peer_v6_vrf))
    ############################################################################################
    for nbr_1, nbr_3 in zip(dut3_ipv6_list[2:5], dut1_ipv6_list[2:5]):
        dict1 = {'local_as': dut1_as, 'vrf_name':user_vrf_name, 'peergroup': peer_v6_vrf, 'config_type_list': ['peergroup', 'activate'],
                 'remote_as': dut3_as, 'neighbor': nbr_1, 'addr_family': 'ipv6'}
        dict2 = {'local_as': dut3_as, 'vrf_name':user_vrf_name, 'peergroup': peer_v6_vrf, 'config_type_list': ['peergroup', 'activate'],
                 'remote_as': dut1_as, 'neighbor': nbr_3, 'addr_family': 'ipv6'}
        parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'local_as': dut1_as, 'vrf_name':user_vrf_name, 'peergroup': peer_v6_vrf, 'config_type_list': ['connect', 'routeMap'], 'routeMap': 'rmap_v6',
             'diRection': 'in', 'neighbor': peer_v6_vrf, 'connect': 1, 'addr_family': 'ipv6'}
    dict2 = {'local_as': dut3_as, 'vrf_name':user_vrf_name, 'peergroup': peer_v6_vrf, 'config_type_list': ['connect', 'routeMap'], 'routeMap': 'rmap_v6',
             'diRection': 'in', 'neighbor': peer_v6_vrf, 'connect': 1, 'addr_family': 'ipv6'}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])

    ############################################################################################
    hdrMsg("Step-C16_VRF: Config ip address %s and ipv6 address %s on dut1 tg port " % (dut1_tg_ip, dut1_tg_ipv6))
    ############################################################################################

    dict1 = {'vrf_name':user_vrf_name, 'intf_name':D1_ports_vrf[3],'skip_error':True}
    dict2 = {'vrf_name':user_vrf_name, 'intf_name':D3_ports_vrf[3],'skip_error':True}
    parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

    ip_api.config_ip_addr_interface(dut1, D1_ports_vrf[3], dut1_tg_ip, ip_mask)
    ip_api.config_ip_addr_interface(dut1, D1_ports_vrf[3], dut1_tg_ipv6, ipv6_mask,family='ipv6')

    ############################################################################################
    hdrMsg("Step-C17_VRF: Config ip address %s and ipv6 address %s on dut3 tg port " % (dut3_tg_ip,dut3_tg_ipv6))
    ############################################################################################

    ip_api.config_ip_addr_interface(dut3, D3_ports_vrf[3], dut3_tg_ip, ip_mask)
    ip_api.config_ip_addr_interface(dut3, D3_ports_vrf[3], dut3_tg_ipv6, ipv6_mask,family='ipv6')

    ############################################################################################
    hdrMsg("Step-C18_VRF: Get mac for D1T1P1 from dut1")
    ############################################################################################

    D1_tg1_mac_vrf = basic.get_ifconfig(dut1, D1_ports_vrf[3])[0]['mac']
    arp.add_static_arp(dut3, tg_dut3_ip, tg_dut3_mac_vrf, interface=D3_ports_vrf[3])
    arp.config_static_ndp(dut3, tg_dut3_ipv6, tg_dut3_mac_vrf, D3_ports_vrf[3], operation="add")
    ############################################################################################
    hdrMsg("Step-C19_VRF: Configure ipv4 and ipv6 L3 streams on T1D1P1 to destination %s ,%s on T1D3P1" % (
    tg_dut3_ip, tg_dut3_ipv6))
    ############################################################################################

    stream_v4_vrf = tg2.tg_traffic_config(mac_src=tg_dut1_mac_vrf, mac_dst=D1_tg1_mac_vrf, rate_pps=traffic_rate,
                                      mode='create', port_handle=tg_handles_vrf[0], transmit_mode='continuous',
                                      l3_protocol='ipv4', ip_src_addr=tg_dut1_ip
                                      , ip_dst_addr=tg_dut3_ip, mac_discovery_gw=dut1_tg_ip,
                                          port_handle2=tg_handles_vrf[1])
    stream_v4_handle_vrf = stream_v4_vrf['stream_id']

    stream_6_vrf = tg2.tg_traffic_config(mac_src=tg_dut1_mac_vrf, mac_dst=D1_tg1_mac_vrf, rate_pps=traffic_rate,
                                      mode='create', port_handle=tg_handles_vrf[0], transmit_mode='continuous',
                                      l3_protocol='ipv6', ipv6_src_addr=tg_dut1_ipv6
                                      , ipv6_dst_addr=tg_dut3_ipv6, mac_discovery_gw=dut1_tg_ipv6,
                                         port_handle2=tg_handles_vrf[1])
    stream_6_handle_vrf = stream_6_vrf['stream_id']

    data.streams['stream_handle_list_vrf'] = [stream_v4_handle_vrf, stream_6_handle_vrf]
    hdrMsg("stream handle list created %s " % data.streams['stream_handle_list_vrf'])
    ############################################################################################
    hdrMsg("Step-C20_VRF: Verify all BGP/BGP+ sessions are in Established state")
    ############################################################################################
    result = retry_api(ip_bgp.check_bgp_session, dut1, nbr_list=dut3_ip_list + dut3_ipv6_list,
                       state_list=['Established'] * 10, vrf_name=user_vrf_name, retry_count=10, delay=3)

    if result is False:
        st.error("One or more BGP-VRF sessions did not come up")
        bfd.debug_bgp_bfd([dut1, dut3])
        st.report_fail('module_config_failed', 'One or more BGP sessions did not come up')

    basic.debug_bfdconfig_using_frrlog(dut=dut1, config="yes", log_file_name="bfd.log")
    basic.debug_bfdconfig_using_frrlog(dut=dut3, config="yes", log_file_name="bfd.log")
    bgp_api.bgp_debug_config(dut1)
    bgp_api.bgp_debug_config(dut3)
    hdrMsg("##### BASE vrf config END ####")


def debug_bgp_vrf(duts=[], neighbors=[], family='ipv4', vrf='default', interface=[], **kwargs):
    '''
    Argments duts and neighbors should be in sync dut name and its neighbor in same index
    :param duts:
    :param vrf:
    :param neighbors:
    :param kwargs:
    :return:
    '''
    st.log("Dubug commands starts")
    i = 0
    for dut_name,neighbor_ip in zip(duts,neighbors):
        bgp_api.show_bgp_ipv6_summary_vtysh(dut_name)
        bgp_api.show_bgp_ipv6_neighbor_vtysh(dut_name, neighbor_ip)
        if interface:
            ip_api.ping(dut_name, neighbor_ip, family, interface=interface[i])
        else:
            ip_api.ping(dut_name, neighbor_ip, family)
        if vrf != 'default':
            bgp_api.show_bgp_ipv6_summary_vtysh(dut_name, vrf)
            bgp_api.show_bgp_ipv6_neighbor_vtysh(dut_name, neighbor_ip, vrf)
        i = i + 1
    st.log(" End of Dubug commands")


def single_hop_deconfig(vrfunconfig='yes'):
    hdrMsg("##### Deconfig Starts ####")
    basic.debug_bfdconfig_using_frrlog(dut=dut3, config="no", log_file_name="bfd.log")
    basic.debug_bfdconfig_using_frrlog(dut=dut1, config="no", log_file_name="bfd.log")
    ############################################################################################
    hdrMsg("Step-DC1: Remove BGP router from dut1 and dut3 at the end of config")
    ############################################################################################
    ############################################################################################
    hdrMsg("Step-DC2: Remove IP/IPv6 from Vlan interfaces on dut1 and dut3")
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1, access_vlan_name,dut1_ip_list[0], ip_mask],[ip_api.delete_ip_interface,dut3, access_vlan_name, dut3_ip_list[0], ip_mask]])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1, access_vlan_name,dut1_ipv6_list[0], ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut3,access_vlan_name, dut3_ipv6_list[0], ipv6_mask,'ipv6']])

    for vlan,ip_1,ip_3 in zip(trunk_vlan_name,dut1_ip_list[2:5],dut3_ip_list[2:5]):
        utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, vlan,ip_1,ip_mask],[ip_api.delete_ip_interface,dut3, vlan,ip_3,ip_mask]])
    for vlan,ip_1,ip_3 in zip(trunk_vlan_name,dut1_ipv6_list[2:5],dut3_ipv6_list[2:5]):
        utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, vlan,ip_1,ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut3, vlan,ip_3,ipv6_mask,'ipv6']])
    ############################################################################################
    hdrMsg("Step-DC4: Remove vlan membership from ports in all DUTs")
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True,[[vlan_api.config_vlan_range_members,dut1,'{} {}'.format(trunk_vlan[0],trunk_vlan[-1]),D1_ports[2],'del'],
                             [vlan_api.config_vlan_range_members,dut2,'{} {}'.format(trunk_vlan[0],trunk_vlan[-1]),D2_ports[2],'del'],
                             [vlan_api.config_vlan_range_members,dut3,'{} {}'.format(trunk_vlan[0],trunk_vlan[-1]),D3_ports[2],'del']])
        vlan_api.config_vlan_range_members(dut2, '{} {}'.format(trunk_vlan[0], trunk_vlan[-1]), D2_ports[5],'del')

        utils.exec_all(True,[[vlan_api.delete_vlan_member,dut1,access_vlan,D1_ports[0]],
                             [vlan_api.delete_vlan_member,dut3,access_vlan,D3_ports[0]],
                             [vlan_api.delete_vlan_member,dut2,access_vlan,[D2_ports[0],D2_ports[3]]]])
        utils.exec_all(True,[[vlan_api.delete_vlan_member,dut2,dut2_l2_vlan,[D2_ports[1],D2_ports[4]]]])
    else:
        utils.exec_all(True, [
            [vlan_api.config_vlan_range_members, dut1, '{} {}'.format(trunk_vlan[0], trunk_vlan[-1]), D1_ports[2],'del'],
            [vlan_api.config_vlan_range_members, dut3, '{} {}'.format(trunk_vlan[0], trunk_vlan[-1]), D3_ports[2],'del']])

        utils.exec_all(True, [[vlan_api.delete_vlan_member, dut1, access_vlan, D1_ports[0]],
                              [vlan_api.delete_vlan_member, dut3, access_vlan, D3_ports[0]]])


    ############################################################################################
    hdrMsg("Step-DC4: Delete Vlans from dut1,dut2 and dut3")
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.config_vlan_range, dut1, '{} {}'.format(access_vlan, trunk_vlan[-1]),'del'],
                          [vlan_api.config_vlan_range, dut2, '{} {}'.format(access_vlan, trunk_vlan[-1]),'del'],
                          [vlan_api.config_vlan_range, dut3, '{} {}'.format(access_vlan, trunk_vlan[-1]),'del']])
        vlan_api.delete_vlan(dut2, [dut2_l2_vlan])
    else:
        utils.exec_all(True, [[vlan_api.config_vlan_range, dut1, '{} {}'.format(access_vlan, trunk_vlan[-1]),'del'],
                          [vlan_api.config_vlan_range, dut3, '{} {}'.format(access_vlan, trunk_vlan[-1]),'del']])

    ############################################################################################
    hdrMsg("Step-DC5: Remove IP/IPv6 addresses from physical interfaces")
    ############################################################################################

    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1, D1_ports[1],dut1_ip_list[1], ip_mask],[ip_api.delete_ip_interface,dut3, D3_ports[1], dut3_ip_list[1], ip_mask]])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1, D1_ports[1],dut1_ipv6_list[1], ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut3, D3_ports[1], dut3_ipv6_list[1], ipv6_mask,'ipv6']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, D1_ports[3],dut1_tg_ip,ip_mask],[ip_api.delete_ip_interface,dut3, D3_ports[3], dut3_tg_ip,ip_mask]])
    utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, D1_ports[3],dut1_tg_ipv6,ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut3, D3_ports[3], dut3_tg_ipv6,ipv6_mask,'ipv6']])

    ############################################################################################
    hdrMsg("Step-DC6: Remove arp and ipv6 neighbor entry on dut3")
    ############################################################################################
    arp.delete_static_arp(dut3, tg_dut3_ip)
    arp.config_static_ndp(dut3,tg_dut3_ipv6, tg_dut3_mac,D3_ports[3], operation="del")
    ############################################################################################
    hdrMsg("Step-DC7: Remove Traffic streams")
    ############################################################################################
    tg1.tg_traffic_control(action='reset', port_handle=tg_handles)

    ip_api.config_route_map_global_nexthop(dut1, route_map='rmap_v6', config='no')
    ip_api.config_route_map_global_nexthop(dut3, route_map='rmap_v6', config='no')
    hdrMsg("##### Deconfig END for default vrf ####")
    if vrfunconfig == 'yes':
        hdrMsg("##### Deconfig Starts for user vrf ####")
        ############################################################################################
        hdrMsg("Step-DC1_VRF: Remove BGP-VRF router from dut1 and dut3")
        ############################################################################################
        dict1 = {'vrf_name':user_vrf_name, 'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as':dut1_as}
        dict2 = {'vrf_name':user_vrf_name, 'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as':dut3_as}
        parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])
        ############################################################################################
        hdrMsg("Step-DC2_VRF: Remove IP/IPv6 from Vlan interfaces on dut1 and dut3")
        ############################################################################################
        utils.exec_all(True, [[ip_api.delete_ip_interface,dut1, access_vlan_name_vrf,dut1_ip_list[0], ip_mask],[ip_api.delete_ip_interface,dut3, access_vlan_name_vrf, dut3_ip_list[0], ip_mask]])
        utils.exec_all(True, [[ip_api.delete_ip_interface,dut1, access_vlan_name_vrf,dut1_ipv6_list[0], ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut3,access_vlan_name_vrf, dut3_ipv6_list[0], ipv6_mask,'ipv6']])

        for vlan,ip_1,ip_3 in zip(trunk_vlan_name_vrf,dut1_ip_list[2:5],dut3_ip_list[2:5]):
            utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, vlan,ip_1,ip_mask],[ip_api.delete_ip_interface,dut3, vlan,ip_3,ip_mask]])
        for vlan,ip_1,ip_3 in zip(trunk_vlan_name_vrf,dut1_ipv6_list[2:5],dut3_ipv6_list[2:5]):
            utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, vlan,ip_1,ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut3, vlan,ip_3,ipv6_mask,'ipv6']])
        ############################################################################################
        hdrMsg("Step-DC4_VRF: Remove vlan membership from ports in all DUTs")
        ############################################################################################
        if l2_switch == 'yes':
            utils.exec_all(True,[[vlan_api.config_vlan_range_members,dut1,'{} {}'.format(trunk_vlan_vrf[0],trunk_vlan_vrf[-1]),D1_ports_vrf[2],'del'],
                                 [vlan_api.config_vlan_range_members,dut2,'{} {}'.format(trunk_vlan_vrf[0],trunk_vlan_vrf[-1]),D2_ports_vrf[2],'del'],
                                 [vlan_api.config_vlan_range_members,dut3,'{} {}'.format(trunk_vlan_vrf[0],trunk_vlan_vrf[-1]),D3_ports_vrf[2],'del']])
            vlan_api.config_vlan_range_members(dut2, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D2_ports_vrf[5],'del')

            utils.exec_all(True,[[vlan_api.delete_vlan_member,dut1,access_vlan_vrf,D1_ports_vrf[0]],
                                 [vlan_api.delete_vlan_member,dut3,access_vlan_vrf,D3_ports_vrf[0]],
                                 [vlan_api.delete_vlan_member,dut2,access_vlan_vrf,[D2_ports_vrf[0],D2_ports_vrf[3]]]])
            utils.exec_all(True,[[vlan_api.delete_vlan_member,dut2,dut2_l2_vlan,[D2_ports_vrf[1],D2_ports_vrf[4]]]])
        else:
            utils.exec_all(True, [
                [vlan_api.config_vlan_range_members, dut1, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D1_ports_vrf[2],'del'],
                [vlan_api.config_vlan_range_members, dut3, '{} {}'.format(trunk_vlan_vrf[0], trunk_vlan_vrf[-1]), D3_ports_vrf[2],'del']])

            utils.exec_all(True, [[vlan_api.delete_vlan_member, dut1, access_vlan_vrf, D1_ports_vrf[0]],
                                  [vlan_api.delete_vlan_member, dut3, access_vlan_vrf, D3_ports_vrf[0]]])


        ############################################################################################
        hdrMsg("Step-DC4_VRF: Delete Vlans from dut1,dut2 and dut3")
        ############################################################################################
        if l2_switch == 'yes':
            utils.exec_all(True, [[vlan_api.config_vlan_range, dut1, '{} {}'.format(access_vlan_vrf, trunk_vlan_vrf[-1]),'del'],
                              [vlan_api.config_vlan_range, dut2, '{} {}'.format(access_vlan_vrf, trunk_vlan_vrf[-1]),'del'],
                              [vlan_api.config_vlan_range, dut3, '{} {}'.format(access_vlan_vrf, trunk_vlan_vrf[-1]),'del']])
            vlan_api.delete_vlan(dut2, [dut2_l2_vlan])
        else:
            utils.exec_all(True, [[vlan_api.config_vlan_range, dut1, '{} {}'.format(access_vlan_vrf, trunk_vlan_vrf[-1]),'del'],
                              [vlan_api.config_vlan_range, dut3, '{} {}'.format(access_vlan_vrf, trunk_vlan_vrf[-1]),'del']])

        ############################################################################################
        hdrMsg("Step-DC5_VRF: Remove IP/IPv6 addresses from physical interfaces")
        ############################################################################################

        utils.exec_all(True, [[ip_api.delete_ip_interface,dut1, D1_ports_vrf[1],dut1_ip_list[1], ip_mask],[ip_api.delete_ip_interface,dut3, D3_ports_vrf[1], dut3_ip_list[1], ip_mask]])
        utils.exec_all(True, [[ip_api.delete_ip_interface,dut1, D1_ports_vrf[1],dut1_ipv6_list[1], ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut3, D3_ports_vrf[1], dut3_ipv6_list[1], ipv6_mask,'ipv6']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, D1_ports_vrf[3],dut1_tg_ip,ip_mask],[ip_api.delete_ip_interface,dut3, D3_ports_vrf[3], dut3_tg_ip,ip_mask]])
        utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, D1_ports_vrf[3],dut1_tg_ipv6,ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut3, D3_ports_vrf[3], dut3_tg_ipv6,ipv6_mask,'ipv6']])

        ############################################################################################
        hdrMsg("Step-DC6_VRF: Remove arp and ipv6 neighbor entry on dut3")
        ############################################################################################
        arp.delete_static_arp(dut3, tg_dut3_ip)
        arp.config_static_ndp(dut3,tg_dut3_ipv6, tg_dut3_mac_vrf,D3_ports_vrf[3], operation="del")
        ############################################################################################
        hdrMsg("Step-DC7_VRF: Remove Traffic streams")
        ############################################################################################
        dict1 = {'vrf_name': user_vrf_name, 'skip_error': True, 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3], vrf_api.config_vrf, [dict1, dict1])
        hdrMsg("##### Deconfig END for non default vrf ####")
    dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as':dut1_as}
    dict2 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as':dut3_as}
    parallel.exec_parallel(True, [dut1, dut3], bgp_api.config_bgp, [dict1, dict2])
    hdrMsg("##### Deconfig END####")


def convergence_measure(dut,intf_to_flap,version='ipv4', vrf_name= 'default'):
    multiplier=1.0
    if vrf_name == 'default-vrf':
        tg_lvar = tg1
        tg_handles_lvar = tg_handles
        if version == 'ipv4':
            stream = data.streams['stream_handle_list'][0]
        elif version == 'ipv6':
            stream = data.streams['stream_handle_list'][1]
        else:
            stream = data.streams['stream_handle_list']
            multiplier=2.0
    else:
        tg_lvar =  tg2
        tg_handles_lvar = tg_handles_vrf
        if version == 'ipv4':
            stream = data.streams['stream_handle_list_vrf'][0]
        elif version == 'ipv6':
            stream = data.streams['stream_handle_list_vrf'][1]
        else:
            stream = data.streams['stream_handle_list_vrf']
            multiplier=2.0
    key_val = tgapi.get_counter_name("aggregate", tg1.tg_type, "packet_count", 'tx')
    tg_lvar.tg_traffic_control(action='clear_stats', port_handle=tg_handles_lvar)
    tg_lvar.tg_traffic_control(action='run',stream_handle=stream)
    st.wait(2)
    st.log("Bring down port %s on DUT %s"%(intf_to_flap,dut))
    port.shutdown(dut,[intf_to_flap])
    st.wait(5)
    tg_lvar.tg_traffic_control(action='stop',stream_handle=stream)
    tx_count = tg_lvar.tg_traffic_stats(port_handle=tg_handles_lvar[0], mode='aggregate')[tg_handles_lvar[0]]['aggregate']['tx'][key_val]
    rx_count = tg_lvar.tg_traffic_stats(port_handle=tg_handles_lvar[1], mode='aggregate')[tg_handles_lvar[1]]['aggregate']['rx'][key_val]
    st.log("Total Tx pkt count : {}".format(int(tx_count)))
    st.log("Total Rx pkt count : {}".format(int(rx_count)))
    if int(rx_count) == 0:
        st.error("Traffic Failed: RX port did not receive any packets")
        port.noshutdown(dut, [intf_to_flap])
        bfd.debug_bgp_bfd([dut1, dut3])
        return False
    else:
        drop = float(tx_count) - float(rx_count)
        convergence_time = (float(drop)/float(traffic_rate))*1000
        st.log("Bring up port %s on DUT %s" % (intf_to_flap, dut))
        port.noshutdown(dut, [intf_to_flap])
        st.log("Traffic Convergence time : %s msec" % (convergence_time/multiplier))
        return (convergence_time/multiplier)


def verify_bfd_func_001(mode='access'):
    if mode == 'access':
        enable_bfd_list_1 = [dut3_ip_list[0],dut3_ipv6_list[0]];enable_bfd_list_2 = [dut1_ip_list[0],dut1_ipv6_list[0]]
        bfd_nbrs_dut1 = [dut3_ip_list[0],dut3_ipv6_list[0]]; non_bfd_nbrs_dut1 = dut3_ip_list[1:]+dut3_ipv6_list[1:]
        bfd_nbrs_dut3 = [dut1_ip_list[0],dut1_ipv6_list[0]]; non_bfd_nbrs_dut3 = dut1_ip_list[1:]+dut1_ipv6_list[1:]
        intf_list = [access_vlan_name]*2
        non_bfd_intf_list = [D1_ports[1]] + trunk_vlan_name *2
        flap_intf = flap_ports[0]
    elif mode =='router-port':
        enable_bfd_list_1= [dut3_ip_list[1],dut3_ipv6_list[1]];enable_bfd_list_2= [dut1_ip_list[1],dut1_ipv6_list[1]]
        bfd_nbrs_dut1 = [dut3_ip_list[1],dut3_ipv6_list[1]]; non_bfd_nbrs_dut1 = dut3_ip_list[2:]+dut3_ipv6_list[2:]
        bfd_nbrs_dut3 = [dut1_ip_list[1],dut1_ipv6_list[1]]; non_bfd_nbrs_dut3 = dut1_ip_list[2:]+dut1_ipv6_list[2:]
        bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ip_list[0], family="ipv4", neighbor_shutdown='')
        bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ipv6_list[0], family="ipv6",neighbor_shutdown='')
        intf_list = [D1_ports[1]]*2
        non_bfd_intf_list = trunk_vlan_name *2
        flap_intf = flap_ports[1]
    else:
        #config_route_map(dut3,'rmap1')
        enable_bfd_list_1 = [peer_v4,peer_v6];enable_bfd_list_2 = [peer_v4,peer_v6];
        bfd_nbrs_dut1 = dut3_ip_list[2:]+dut3_ipv6_list[2:]; non_bfd_nbrs_dut1 = [dut3_ip_list[0],dut3_ipv6_list[0]]
        bfd_nbrs_dut3 = dut1_ip_list[2:]+dut1_ipv6_list[2:]; non_bfd_nbrs_dut3 = [dut1_ip_list[0],dut1_ipv6_list[0]]
        #bgp_api.config_bgp_neighbor_properties(dut1, dut1_as,dut3_ip_list[1], family="ipv4", neighbor_shutdown='')
        #bgp_api.config_bgp(dut3,local_as=dut3_as,config_type_list =["routeMap"], routeMap ='rmap1', diRection='out',neighbor=dut1_ip_list[0])
        #bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ipv6_list[1], family="ipv6",neighbor_shutdown='')
        #bgp_api.config_bgp(dut3, local_as=dut3_as, config_type_list=["routeMap"], routeMap='rmap1', diRection='out',neighbor=dut1_ipv6_list[0], addr_family='ipv6')
        intf_list = trunk_vlan_name*2
        non_bfd_intf_list = [access_vlan_name] *2
        flap_intf = flap_ports[2]
    ret_val = True

    ###########################################################################################
    hdrMsg("Step T1: Enable BFD for BGP neighbor %s on dut1 and %s on dut3"%(bfd_nbrs_dut1,bfd_nbrs_dut3))
    ###########################################################################################
    dict1 ={"local_asn":dut1_as,'neighbor_ip':enable_bfd_list_1,'config':'yes','peergroup':enable_bfd_list_1}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':enable_bfd_list_2,'config':'yes','peergroup':enable_bfd_list_2}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step T2: Verify BFD session comes up for %s"%bfd_nbrs_dut1)
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer,dut1,peer=bfd_nbrs_dut1,interface=intf_list,rx_interval=[['300','300']]*len(bfd_nbrs_dut1),
                                 status=['up']*len(bfd_nbrs_dut1),tx_interval=[['300','300']]*len(bfd_nbrs_dut1),multiplier=[['3','3']]*len(bfd_nbrs_dut1))
    if result is False:
        st.error("FAILED : BFD session parameters mismatch ")
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T3: Verify BFD state under BGP neighbors %s on dut1"%bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result =ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established')
        if result:
            st.log("BGP neighbor state is as expected for %s"%peer)
        else:
            st.error("FAILED:BGP neighbor state incorrect for %s"%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step T4: Verify BFD is disabled for other BGP neighbors %s"% non_bfd_nbrs_dut1)
    ###########################################################################################

    for peer,intf in zip(non_bfd_nbrs_dut1,non_bfd_intf_list):
        result = bfd.verify_bfd_peer(dut1, peer=peer, interface=intf,status='up')
        if result is True:
            st.error("FAILED: BFD peer entry should not be created for %s" % peer)
            ret_val = False
        else:
            st.log("BFD peer %s not created as expected" % peer)

    ###########################################################################################
    hdrMsg("Step T5: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest_nw,intf_list[0]))
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(tg_dest_nw,ip_mask),interface=intf_list[0], family='ipv4')
    if result:
        st.log("DUT1: Destination route %s installed with nexthop interface %s "%(tg_dest_nw,intf_list[0]))
    else:
        st.error("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_nw, intf_list[0]))
        ret_val = False
    ###########################################################################################
    hdrMsg("Step T6: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest_nw_v6,intf_list[0]))
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(tg_dest_nw_v6,ipv6_mask),interface=intf_list[0], family='ipv6')
    if result:
        st.log("DUT1: Destination route %s installed with nexthop interface %s "%(tg_dest_nw_v6,intf_list[0]))
    else:
        st.error("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_nw_v6, intf_list[0]))
        ret_val = False
    ###########################################################################################
    hdrMsg("Step T7: Trigger link failure on L2 switch between dut2 and dut3 for vlan %s"%intf_list[0])
    ###########################################################################################
    port.shutdown(flap_dut,[flap_intf])
    st.wait(1)
    ###########################################################################################
    hdrMsg("Step T8: Verify BFD state and BGP state goes down immediately for neighbor %s"%bfd_nbrs_dut1)
    ###########################################################################################
    for peer,intf in zip(bfd_nbrs_dut1,intf_list):
        result =bfd.verify_bfd_peer(dut1,peer=peer,interface=intf,status='down')
        if result is True:
            st.error("FAILED : BFD session did not go down for %s" %peer)
            ret_val = False
        else:
            st.log("BFD peer %s went down as expected" % peer)

    ###########################################################################################
    hdrMsg("Step T9: Verify BFD state under BFP neighbors %s on dut1" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=peer, bgpdownreason="BFD down received",
                           retry_count=5, delay=1)
        if result is False:
            st.error("FAILED : BGP neighbor %s did not go down after BFD went down"%peer)
            ret_val = False
    ###########################################################################################
    hdrMsg("Step T10: Verify other BGP neighbors are still in Established state %s"% non_bfd_nbrs_dut1)
    ###########################################################################################

    result= ip_bgp.check_bgp_session(dut1,nbr_list=non_bfd_nbrs_dut1,state_list=['Established']*len(non_bfd_nbrs_dut1))
    if result:
        st.log("BGP neighbors in ESTABLISHED state")
    else:
        st.error("FAILED: one or more Non-BFD BGP neighbors not in Established state")
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T11: Verify routing table to check if destination network %s installed with next best next-hop interface %s" % (tg_dest_nw, non_bfd_intf_list[0]))
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (tg_dest_nw, ip_mask), interface=non_bfd_intf_list[0], family='ipv4')
    if result:
        st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw,non_bfd_intf_list[0]))
    else:
        st.error("FAILED :DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_nw, non_bfd_intf_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T12: Verify routing table to check if destination network %s installed with next best next-hop interface %s" % (tg_dest_nw_v6, non_bfd_intf_list[0]))
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (tg_dest_nw_v6, ipv6_mask), interface=non_bfd_intf_list[0], family='ipv6')
    if result:
        st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw_v6,non_bfd_intf_list[0]))
    else:
        st.error("FAILED :DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_nw_v6, non_bfd_intf_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T13: Re-enable port on L2 switch between dut2 and dut3 for vlan %s" % intf_list[0])
    ###########################################################################################
    port.noshutdown(flap_dut,[flap_intf])

    ###########################################################################################
    hdrMsg("Step T13: Verify BGP neighbors %s comes up back on dut1 after re-enable" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',retry_count=10,delay=3)
        if result:
            st.log("BGP peer %s in Established state" % peer)
        else:
            st.error("FAILED: BGP peer %s not in Established state"%peer)
            ret_val=False

    ###########################################################################################
    hdrMsg("Step T14: Verify BFD state comes up for neighbor %s" % bfd_nbrs_dut1)
    ###########################################################################################

    result = bfd.verify_bfd_peer(dut1,peer=bfd_nbrs_dut1,interface=intf_list,rx_interval=[['300','300']]*len(bfd_nbrs_dut1),
                                 status=['up']*len(bfd_nbrs_dut1),tx_interval=[['300','300']]*len(bfd_nbrs_dut1),multiplier=[['3','3']]*len(bfd_nbrs_dut1))
    if result is False:
        st.error("FAILED : BFD session parameters mismatch ")
        ret_val = False
    """
    ###########################################################################################
    hdrMsg("Step T15: Measure Traffic convergence with BFD enabled by shutting dut2<---> dut3 port")
    ###########################################################################################
    converged_bfd = convergence_measure(flap_dut,flap_intf,version='both')
    if converged_bfd is not False:
        if converged_bfd > 1500.0:
            st.error("FAILED : Traffic convergence with BFD taking more time")
            ret_val=False
        st.log(" >>>>> Traffic Convergence with BFD : %s ms  <<<<<<"%converged_bfd)
    """
    ###########################################################################################
    hdrMsg("Step T16: Configure BFD timers to greater value to 20 sec than BGP holdover interval on dut1 and dut3 ")
    ###########################################################################################

    dict1 ={"interface":trunk_vlan_name[0],'neighbor_ip':bfd_nbrs_dut1[0],'multiplier':'4','rx_intv':'5000','tx_intv':'5000'}
    dict2 ={"interface":trunk_vlan_name[0],'neighbor_ip':bfd_nbrs_dut3[0],'multiplier':'4','rx_intv':'5000','tx_intv':'5000'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    st.log("Verify BFD timers are updated")
    result = retry_api(bfd.verify_bfd_peer, dut1,peer=[bfd_nbrs_dut1[0]],interface=[trunk_vlan_name[0]],
                                 rx_interval=[['5000','5000']],tx_interval=[['5000','5000']],retry_count=5,delay=2)
    if result is False:
        st.error('BFD timers are incorrect')
        ret_val=False
    ###########################################################################################
    hdrMsg("Step T17: Trigger link failure on L2 switch(dut2) for port D2D3P1 ")
    ###########################################################################################

    port.shutdown(flap_dut,[flap_intf])
    st.wait(10,"for expiring hold timer")
    ###########################################################################################
    hdrMsg("Step T18: Verify BGP session goes down because of hold-down timer expiry")
    ###########################################################################################

    result=retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=bfd_nbrs_dut1[0],bgpdownreason="Hold Timer Expired",retry_count=10,delay=3)
    if result is False:
        st.error('BGP down reason incorrect for %s'%bfd_nbrs_dut1[0])
        ret_val=False

    ###########################################################################################
    hdrMsg("Step T19: Disable BFD under BGP neighbors")
    ###########################################################################################
    dict1 ={"local_asn":dut1_as,'neighbor_ip':enable_bfd_list_1,'config':'no','peergroup':enable_bfd_list_1}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':enable_bfd_list_2,'config':'no','peergroup':enable_bfd_list_2}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1 ={"interface":trunk_vlan_name[0],'neighbor_ip':bfd_nbrs_dut1[0],'config':'no'}
    dict2 ={"interface":trunk_vlan_name[0],'neighbor_ip':bfd_nbrs_dut3[0],'config':'no'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    port.noshutdown(flap_dut,[flap_intf])
    st.log("Verify BGP sessions comes up")
    retry_api(ip_bgp.check_bgp_session, dut1, nbr_list=dut3_ip_list + dut3_ipv6_list, state_list=['Established'] * 10,retry_count=10, delay=3)

    if mode == 'router-port':
        bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ip_list[0], family="ipv4", neighbor_shutdown='',no_form='no')
        bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ipv6_list[0], family="ipv6", neighbor_shutdown='', no_form='no')
    elif mode == 'trunk':
        #bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ip_list[1], family="ipv4", neighbor_shutdown='',no_form='no')
        #bgp_api.config_bgp(dut3,local_as=dut3_as, config_type_list=["routeMap"], routeMap='rmap1', diRection='out',neighbor=dut1_ip_list[0],config='no')
        #bgp_api.config_bgp_neighbor_properties(dut1, dut1_as, dut3_ipv6_list[1], family="ipv6", neighbor_shutdown='', no_form='no')
        #bgp_api.config_bgp(dut3,local_as=dut3_as, config_type_list=["routeMap"], routeMap='rmap1', diRection='out', neighbor=dut1_ipv6_list[0], addr_family='ipv6',config='no')
        #config_route_map(dut3,"rmap1",config='no')
        pass
    return ret_val


def verify_singlehop_bfd_vrf_functionality():
    """
    API to verify single hop bfd-vrf functionality
    :param mode:
    :return:
    """
    enable_bfd_list_1 = [peer_v4_vrf,peer_v6_vrf];enable_bfd_list_2 = [peer_v4_vrf,peer_v6_vrf];
    # enable_bfd_list_3 = [peer_v4, peer_v6];
    # enable_bfd_list_4 = [peer_v4, peer_v6];
    bfd_nbrs_dut1 = dut3_ip_list[2:]+dut3_ipv6_list[2:]; non_bfd_nbrs_dut1 = [dut3_ip_list[0],dut3_ipv6_list[0]]
    bfd_nbrs_dut3 = dut1_ip_list[2:]+dut1_ipv6_list[2:]; # non_bfd_nbrs_dut3 = [dut1_ip_list[0],dut1_ipv6_list[0]]
    intf_list = trunk_vlan_name_vrf*2
    non_bfd_intf_list = [access_vlan_name_vrf] *2
    flap_intf = flap_ports_vrf[2]

    ret_val = True

    ###########################################################################################
    hdrMsg("Step T1: Enable BFD for BGP neighbor %s on dut1 and %s on dut3"%(bfd_nbrs_dut1,bfd_nbrs_dut3))
    ###########################################################################################

    dict1 ={'vrf_name':user_vrf_name, "local_asn":dut1_as,'neighbor_ip':enable_bfd_list_1,'config':'yes','peergroup':enable_bfd_list_1}
    dict2 ={'vrf_name':user_vrf_name, "local_asn":dut3_as,'neighbor_ip':enable_bfd_list_2,'config':'yes','peergroup':enable_bfd_list_2}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step T2: Verify BFD session comes up for %s"%bfd_nbrs_dut1)
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer,dut1,vrf_name = user_vrf_name, peer=bfd_nbrs_dut1,interface=intf_list,rx_interval=[['300','300']]*len(bfd_nbrs_dut1),
                                 status=['up']*len(bfd_nbrs_dut1),tx_interval=[['300','300']]*len(bfd_nbrs_dut1),multiplier=[['3','3']]*len(bfd_nbrs_dut1))
    if result is False:
        st.error("FAILED : BFD session parameters mismatch ")
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T3: Verify BGP neighbors %s on dut1"%bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result =ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established', vrf=user_vrf_name)
        if result:
            st.log("BGP neighbor state is as expected for %s"%peer)
        else:
            st.error("FAILED:BGP neighbor state is incorrect for %s"%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step T4: Verify BFD is disabled for other BGP neighbors %s"% non_bfd_nbrs_dut1)
    ###########################################################################################

    for peer,intf in zip(non_bfd_nbrs_dut1,non_bfd_intf_list):
        result = bfd.verify_bfd_peer(dut1, peer=peer, interface=intf,status='up',vrf_name=user_vrf_name)
        if result is True:
            st.error("FAILED: BFD peer entry should not be created for %s" % peer)
            ret_val = False
        else:
            st.log("BFD peer %s not created as expected" % peer)


    ###########################################################################################
    hdrMsg("Step T5: Verify routing table to check if destination network %s installed with next-hop %s" % (
        tg_dest_nw, intf_list[0]))
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (tg_dest_nw, ip_mask), interface=intf_list[0],
                                    family='ipv4', vrf_name=user_vrf_name)
    if result:
        st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw, intf_list[0]))
    else:
        st.error(
            "FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_nw, intf_list[0]))
        ret_val = False
    ###########################################################################################
    hdrMsg("Step T6: Verify routing table to check if destination network %s installed with next-hop %s" % (
        tg_dest_nw_v6, intf_list[0]))
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (tg_dest_nw_v6, ipv6_mask), interface=intf_list[0],
                                    family='ipv6', vrf_name=user_vrf_name)
    if result:
        st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw_v6, intf_list[0]))
    else:
        st.error(
            "FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (
            tg_dest_nw_v6, intf_list[0]))
        ret_val = False
    ###########################################################################################
    hdrMsg("Step T7: Trigger link failure on L2 switch between dut2 and dut3 for vlan %s" % intf_list[0])
    ###########################################################################################
    port.shutdown(flap_dut, [flap_intf])
    st.wait(1)
    ###########################################################################################
    hdrMsg("Step T8: Verify BFD state and BGP state goes down immediately for neighbor %s" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer, intf in zip(bfd_nbrs_dut1, intf_list):
        result = bfd.verify_bfd_peer(dut1, peer=peer, interface=intf, status='down', vrf_name=user_vrf_name)
        if result is True:
            st.error("FAILED : BFD session did not go down for %s" % peer)
            ret_val = False


    ###########################################################################################
    hdrMsg("Step T9: Verify BGP neighbors goes down %s on dut1" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1[0:3]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=peer, bgpdownreason="BFD down received",
                           retry_count=2, delay=1)
        if result is False:
             st.error("FAILED : BGP neighbor %s did not go down after BFD went down" % peer)
             ret_val = False

    ###########################################################################################
    hdrMsg("Step T10: Verify other BGP neighbors are still in Established state %s" % non_bfd_nbrs_dut1)
    ###########################################################################################

    result = ip_bgp.check_bgp_session(dut1, nbr_list=non_bfd_nbrs_dut1,
                                      state_list=['Established'] * len(non_bfd_nbrs_dut1),
                                      vrf_name=user_vrf_name)
    if result:
        st.log("PASS: BGP neighbors not in ESTABLISHED state")
    else:
        st.error("FAILED: one or more Non-BFD BGP neighbors not in Established state")
        ret_val = False

    ###########################################################################################
    hdrMsg(
        "Step T11: Verify routing table to check if destination network %s installed with next best next-hop interface %s" % (
            tg_dest_nw, non_bfd_intf_list[0]))
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (tg_dest_nw, ip_mask), interface=non_bfd_intf_list[0],
                                    family='ipv4', vrf_name=user_vrf_name)
    if result:
        st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw, non_bfd_intf_list[0]))
    else:
        st.error("FAILED :DUT1: Destination route %s not installed with nexthop interface %s " % (
            tg_dest_nw, non_bfd_intf_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T12: Verify routing table to check if destination network %s installed with next best next-hop interface %s" % (
            tg_dest_nw_v6, non_bfd_intf_list[0]))
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (tg_dest_nw_v6, ipv6_mask),
                                    interface=non_bfd_intf_list[0],
                                    family='ipv6', vrf_name=user_vrf_name)
    if result:
        st.log(
            "DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw_v6, non_bfd_intf_list[0]))
    else:
        st.error("FAILED :DUT1: Destination route %s not installed with nexthop interface %s " % (
            tg_dest_nw_v6, non_bfd_intf_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T13: Re-enable port on L2 switch between dut2 and dut3 for vlan %s" % intf_list[0])
    ###########################################################################################
    port.noshutdown(flap_dut, [flap_intf])

    ###########################################################################################
    hdrMsg("Step T13: Verify BGP neighbors %s comes up back on dut1 after no shutdown" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=peer, state='Established',
                           vrf=user_vrf_name, retry_count=10, delay=3)
        if result:
            st.log("BGP peer %s in Established state" % peer)
        else:
            st.error("FAILED: BGP peer %s not in Established state" % peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step T14: Verify BFD state comes up for neighbor %s" % bfd_nbrs_dut1)
    ###########################################################################################

    result = bfd.verify_bfd_peer(dut1, peer=bfd_nbrs_dut1, interface=intf_list,
                                 rx_interval=[['300', '300']] * len(bfd_nbrs_dut1),
                                 status=['up'] * len(bfd_nbrs_dut1), tx_interval=[['300', '300']] * len(bfd_nbrs_dut1),
                                 multiplier=[['3', '3']] * len(bfd_nbrs_dut1), vrf_name=user_vrf_name)
    if result is False:
        st.error("FAILED : BFD session parameters mismatch ")
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T16: Configure BFD timers to greate value to 20 sec than BGP holdover interval on dut1 and dut3 ")
    ###########################################################################################
    dict1 ={'vrf_name':user_vrf_name, "interface":trunk_vlan_name_vrf[0],'neighbor_ip':bfd_nbrs_dut1[0],'multiplier':'4','rx_intv':'5000','tx_intv':'5000'}
    dict2 ={'vrf_name':user_vrf_name, "interface":trunk_vlan_name_vrf[0],'neighbor_ip':bfd_nbrs_dut3[0],'multiplier':'4','rx_intv':'5000','tx_intv':'5000'}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    st.log("Verify BFD timers are updated")
    result = retry_api(bfd.verify_bfd_peer, dut1,peer=[bfd_nbrs_dut1[0]],interface=[trunk_vlan_name_vrf[0]],
                             rx_interval=[['5000','5000']],tx_interval=[['5000','5000']],vrf_name=user_vrf_name, retry_count=5, delay=2)
    if result is False:
        st.error('BFD timers are incorrect')
        ret_val=False
    ###########################################################################################
    hdrMsg("Step T17: Trigger link failure on L2 switch(dut2) for port D2D3P1 ")
    ###########################################################################################

    port.shutdown(flap_dut, [flap_intf])
    st.wait(10, "for expiring hold timer")
    ###########################################################################################
    hdrMsg("Step T18: Verify BGP session goes down because of hold-down timer expiry")
    ###########################################################################################

    result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=bfd_nbrs_dut1[0],
                       bgpdownreason="Hold Timer Expired", vrf=user_vrf_name, retry_count=10, delay=3)
    if result is False:
        st.error('BGP down reason incorrect for %s' % bfd_nbrs_dut1[0])
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T19: Disable BFD under BGP neighbors")
    ###########################################################################################
    dict1 = {'vrf_name': user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': enable_bfd_list_1, 'config': 'no', 'peergroup': enable_bfd_list_1}
    dict2 = {'vrf_name': user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': enable_bfd_list_2, 'config': 'no', 'peergroup': enable_bfd_list_2}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name, "interface": trunk_vlan_name_vrf[0], 'neighbor_ip': bfd_nbrs_dut1[0],
             'config': 'no'}
    dict2 = {'vrf_name': user_vrf_name, "interface": trunk_vlan_name_vrf[0], 'neighbor_ip': bfd_nbrs_dut3[0],
             'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    port.noshutdown(flap_dut, [flap_intf])
    st.log("Verify BGP sessions comes up")
    retry_api(ip_bgp.check_bgp_session, dut1, nbr_list=dut3_ip_list + dut3_ipv6_list, state_list=['Established'] * 10,
              vrf_name=user_vrf_name, retry_count=10, delay=3)

    return ret_val


@pytest.mark.functionality
def test_bfd_vrf_save_and_reload(bfd_fixture_019):
    '''
    author :vishnuvardhan.talluri@broadcom.com
    :param bfd_fixture_019:
    :return:
    '''

    ###########################################################################################
    hdrMsg("Step T1: Enable BFD on all BGP ipv4 and ipv6 neighbors on both dut1 and dut3")
    ###########################################################################################

    dict1 = {"local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]], 'config': 'yes'}
    dict2 = {"local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': [dut3_ip_list[0], dut3_ipv6_list[0]],
             'config': 'yes'}
    dict2 = {'vrf_name': user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': [dut1_ip_list[0], dut1_ipv6_list[0]],
             'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step T2: Configure non-default bfd timer values for each peer on dut1")
    ###########################################################################################
    intf_list = [access_vlan_name]
    bfd.configure_bfd(dut1, interface=intf_list * 2, neighbor_ip=[dut3_ip_list[0], dut3_ipv6_list[0]],
                      multiplier=["2"] * 2,
                      rx_intv=["210", '320'], tx_intv=["200", '290'], echo_mode_enable='', echo_intv=[100, 120])

    intf_list_vrf = [access_vlan_name_vrf]
    bfd.configure_bfd(dut1, vrf_name=user_vrf_name, interface=intf_list_vrf * 2,
                      neighbor_ip=[dut3_ip_list[0], dut3_ipv6_list[0]], multiplier=["2"] * 2,
                      rx_intv=["210", '320'], tx_intv=["200", '290'], echo_mode_enable='', echo_intv=[100, 120])

    ###########################################################################################
    hdrMsg("Step T3: Verify BFD peers have the configured parameters")
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[0], dut3_ipv6_list[0]],
                       interface=[access_vlan_name] * 2, status=['up'] * 2,
                       rx_interval=[['210', '300'], ['320', '300']], tx_interval=[['200', '300'], ['290', '300']],
                       echo_tx_interval=[['100', '50'], ['120', '50']], retry_count=2, delay=1)
    if result is False:
        st.report_fail('bfd_fail_reason', "BFD parameters are incorrect for one or more BFD ipv4 peers")

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_ip_list[0], dut3_ipv6_list[0]],
                       interface=[access_vlan_name_vrf] * 2, status=['up'] * 2,
                       rx_interval=[['210', '300'], ['320', '300']], tx_interval=[['200', '300'], ['290', '300']],
                       echo_tx_interval=[['100', '50'], ['120', '50']], retry_count=2, delay=1)
    if result is False:
        st.report_fail('bfd_fail_reason', "BFD-VRF parameters are incorrect for one or more BFD ipv4 peers")

    ###########################################################################################
    hdrMsg("Step T4: Verify BFD state under each neighbor before reboot")
    ###########################################################################################
    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.report_fail('bfd_fail_reason',
                           "BFD parameters are incorrect for one or more BFD ipv4 peers before reboot")

    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.report_fail('bfd_fail_reason',
                           "BFD-VRF parameters are incorrect for one or more BFD ipv4 peers before reboot")

    bgp_api.enable_docker_routing_config_mode(vars.D1)
    reboot_api.config_save(dut1)
    reboot_api.config_save(dut1, shell='vtysh')
    st.reboot(dut1)

    ###########################################################################################
    hdrMsg("Step T3: Verify BFD peers have the configured parameters")
    ###########################################################################################

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_ip_list[0], dut3_ipv6_list[0]],
                       interface=[access_vlan_name] * 2, status=['up'] * 2,
                       rx_interval=[['210', '300'], ['320', '300']], tx_interval=[['200', '300'], ['290', '300']],
                       echo_tx_interval=[['100', '50'], ['120', '50']], retry_count=2, delay=1)
    if result is False:
        st.report_fail('bfd_fail_reason', "BFD parameters are incorrect for one or more BFD ipv4 peers")

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_ip_list[0], dut3_ipv6_list[0]],
                       interface=[access_vlan_name_vrf] * 2, status=['up'] * 2,
                       rx_interval=[['210', '300'], ['320', '300']], tx_interval=[['200', '300'], ['290', '300']],
                       echo_tx_interval=[['100', '50'], ['120', '50']], retry_count=2, delay=1)
    if result is False:
        st.report_fail('bfd_fail_reason', "BFD-VRF parameters are incorrect for one or more BFD ipv4 peers")

    ###########################################################################################
    hdrMsg("Step T4: Verify BFD state under each neighbor before reboot")
    ###########################################################################################
    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.report_fail('bfd_fail_reason',
                           "BFD parameters are incorrect for one or more BFD ipv4 peers after reboot")

    for nbr in [dut3_ip_list[0], dut3_ipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.report_fail('bfd_fail_reason',
                           "BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after reboot")
    st.report_pass('test_case_passed')


@pytest.mark.functionality
def test_bfd_vrf_warm_reboot_cold_restart(bfd_fixture_019):
    '''
    author : vishnuvardhan.talluri@broadcom.com
    :param bfd_fixture_019:
    :return:
    '''

    set_result = True
    ###########################################################################################
    hdrMsg("Step T1: Enable BFD on all BGP ipv4 and ipv6 neighbors on both dut1 and dut3")
    ###########################################################################################

    dict1 = {"local_asn": dut1_as,'neighbor_ip': [dut3_ip_list[0],dut3_ipv6_list[0]], 'config': 'yes'}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': [dut1_ip_list[0],dut1_ipv6_list[0]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name,"local_asn": dut1_as,'neighbor_ip': [dut3_ip_list[0],dut3_ipv6_list[0]], 'config': 'yes'}
    dict2 = {'vrf_name': user_vrf_name,"local_asn": dut3_as,'neighbor_ip': [dut1_ip_list[0],dut1_ipv6_list[0]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step T2: Configure non-default bfd timer values for each peer on dut1")
    ###########################################################################################
    intf_list= [access_vlan_name]
    bfd.configure_bfd(dut1,interface=intf_list*2, neighbor_ip=[dut3_ip_list[0],dut3_ipv6_list[0]], multiplier=["2"]*2,
                      rx_intv=["210",'320'],tx_intv=["200",'290'],echo_mode_enable='',echo_intv=[100,120])

    intf_list_vrf= [access_vlan_name_vrf]
    bfd.configure_bfd(dut1,vrf_name=user_vrf_name, interface=intf_list_vrf*2, neighbor_ip=[dut3_ip_list[0],dut3_ipv6_list[0]], multiplier=["2"]*2,
                      rx_intv=["210",'320'],tx_intv=["200",'290'],echo_mode_enable='',echo_intv=[100,120])
    for ireload in range(2):
        ###########################################################################################
        hdrMsg("Step T3: Verify BFD peers have the configured parameters")
        ###########################################################################################

        result = retry_api(bfd.verify_bfd_peer,dut1, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name]*2,status=['up']*2,
                                     rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']],retry_count=20,delay=1)
        if result is False:
            st.error('Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers')
            set_result = False

        result = retry_api(bfd.verify_bfd_peer,dut1,vrf_name=user_vrf_name, peer=[dut3_ip_list[0],dut3_ipv6_list[0]],interface=[access_vlan_name_vrf]*2,status=['up']*2,
                                     rx_interval=[['210','300'],['320','300']],tx_interval=[['200','300'],['290','300']],echo_tx_interval=[['100','50'],['120','50']],retry_count=20,delay=1)
        if result is False:
            st.error('Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers')
            set_result = False

        ###########################################################################################
        hdrMsg("Step T4: Verify BFD state under each neighbor before reboot")
        ###########################################################################################
        for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
            if result is False:
                st.error('Failed: bfd_fail_reason BFD parameters are incorrect for one or more BFD ipv4 peers after reboot')
                set_result = False

        for nbr in [dut3_ip_list[0],dut3_ipv6_list[0]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,vrf=user_vrf_name,neighborip=nbr,state='Established',retry_count=10,delay=3)
            if result is False:
                st.error('Failed: bfd_fail_reason BFD-VRF parameters are incorrect for one or more BFD ipv4 peers after reboot')
                set_result = False
        if set_result == False and ireload == 0:
            st.report_fail('bfd_fail_reason',
                           "BFD parameters are incorrect for one or more BFD ipv4 peers before warm reboot")

        if ireload == 0:
            bgp_api.enable_docker_routing_config_mode(vars.D1)
            reboot_api.config_save(dut1)
            reboot_api.config_save(dut1, shell='vtysh')
            st.log("Performing warm reboot")
            st.reboot(vars.D1, "warm")

    if set_result == False:
        st.report_fail('bfd_fail_reason',
                       "BFD parameters are incorrect for one or more BFD ipv4 peers after warm and cold reboot")
    else:
        st.report_pass('test_case_passed')
