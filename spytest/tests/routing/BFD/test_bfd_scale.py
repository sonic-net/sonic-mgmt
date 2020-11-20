#############################################################################
#Script Title : BGP BFD scale 
#Author       : Sooriya G
#Mail-id      : sooriya.gajendrababu@broadcom.com
#############################################################################

import pytest
from spytest import st, utils
from apis.routing import ip as ip_api
from apis.routing import bfd
from apis.system import port
from apis.switching import vlan as vlan_api
from spytest.tgen.tg import *
from apis.routing import ip_bgp
from apis.routing import bgp as bgp_api
from test_bfd_single_hop import hdrMsg,retry_api
from bfd_scale_vars import *
from utilities import parallel
import apis.routing.vrf as vrf_api



@pytest.fixture(scope="module", autouse=True)
def prologue_epilogue(request):
    global vars, dut1, dut2, D1_ports, D2_ports, D1_ports_vrf, D2_ports_vrf
    vars = st.ensure_min_topology("D1D2:6")
    dut1 = vars.dut_list[0]
    dut2 = vars.dut_list[1]
    D1_ports = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3]
    D2_ports = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3]
    D1_ports_vrf = [vars.D1D2P4, vars.D1D2P5, vars.D1D2P6]
    D2_ports_vrf = [vars.D2D1P4, vars.D2D1P5, vars.D2D1P6]

    for dut in vars.dut_list:
        bgp_api.enable_docker_routing_config_mode(dut)
    base_config('default')
    base_config(user_vrf_name)
    yield
    base_deconfig(user_vrf_name)
    base_deconfig('default')

def return_vars(vrfname='deafult'):
    if vrfname == 'default':
        return D1_ports, D2_ports, max_bfd, ipv4_bgp, ipv6_bgp, dut1_ip, dut2_ip, dut1_ipv6, dut2_ipv6, vlan_list, vlan_intf
    else:
        return D1_ports_vrf, D2_ports_vrf, max_bfd_vrf, ipv4_bgp_vrf, ipv6_bgp_vrf, dut1_ip_vrf, dut2_ip_vrf, dut1_ipv6_vrf, dut2_ipv6_vrf, vlan_list_vrf, vlan_intf_vrf



def ip_config(test_type, vrfname='default'):
    D1_ports, D2_ports, max_bfd, ipv4_bgp, ipv6_bgp, dut1_ip, dut2_ip, dut1_ipv6, dut2_ipv6, vlan_list, vlan_intf = \
    return_vars(vrfname)

    if test_type == 'mix':
        ############################################################################################
        hdrMsg("Step-C1: Configure ip address %s on dut1 and %s on dut2 for all Vlans"  % (dut1_ip,dut2_ip))
        ############################################################################################
        for vlan,ip_1,ip_3 in zip(vlan_intf,dut1_ip,dut2_ip):
            utils.exec_all(True,[[ip_api.config_ip_addr_interface,dut1, vlan,ip_1,ip_mask],[ip_api.config_ip_addr_interface,dut2, vlan,ip_3,ip_mask]])

        ############################################################################################
        hdrMsg("Step-C2: Configure ipv6 address %s on dut1 and %s on dut2 for all Vlans"  % (dut1_ipv6,dut2_ipv6))
        ############################################################################################
        for vlan,ip_1,ip_3 in zip(vlan_intf,dut1_ipv6,dut2_ipv6):
            utils.exec_all(True,[[ip_api.config_ip_addr_interface,dut1, vlan,ip_1,ipv6_mask,'ipv6'],[ip_api.config_ip_addr_interface,dut2, vlan,ip_3,ipv6_mask,'ipv6']])
    elif test_type == 'ipv4':
        ############################################################################################
        hdrMsg("Step-C1: Configure ip address %s on dut1 and %s on dut2 for all Vlans"  % (dut1_ip,dut2_ip))
        ############################################################################################
        for vlan,ip_1,ip_3 in zip(vlan_intf,dut1_ip,dut2_ip):
            utils.exec_all(True,[[ip_api.config_ip_addr_interface,dut1, vlan,ip_1,ip_mask],[ip_api.config_ip_addr_interface,dut2, vlan,ip_3,ip_mask]])

    else:
        ############################################################################################
        hdrMsg("Step-C1: Configure ipv6 address %s on dut1 and %s on dut2 for all Vlans"  % (dut1_ipv6,dut2_ipv6))
        ############################################################################################
        for vlan,ip_1,ip_3 in zip(vlan_intf,dut1_ipv6,dut2_ipv6):
            utils.exec_all(True,[[ip_api.config_ip_addr_interface,dut1, vlan,ip_1,ipv6_mask,'ipv6'],[ip_api.config_ip_addr_interface,dut2, vlan,ip_3,ipv6_mask,'ipv6']])



def bgp_config(test_type, vrfname='default'):
    D1_ports, D2_ports, max_bfd, ipv4_bgp, ipv6_bgp, dut1_ip, dut2_ip, dut1_ipv6, dut2_ipv6, vlan_list, vlan_intf = \
    return_vars(vrfname)
    if test_type == 'ipv4':
        ############################################################################################
        hdrMsg( "Config %s  BGP ipv4 neighbors between dut1 and dut2 under peer-group"%(max_bfd+1))
        ############################################################################################
        for nbr_1,nbr_2 in zip(dut2_ip,dut1_ip):
            dict1 = {'local_as':dut1_as, 'vrf_name': vrfname, 'peergroup': 'peer_v4', 'config_type_list': ['peergroup'], 'remote_as': dut2_as, 'neighbor': nbr_1}
            dict2 = {'local_as':dut2_as, 'vrf_name': vrfname, 'peergroup': 'peer_v4', 'config_type_list': ['peergroup'], 'remote_as': dut1_as, 'neighbor': nbr_2}
            parallel.exec_parallel(True, [dut1, dut2], bgp_api.config_bgp, [dict1, dict2])

    elif test_type == 'ipv6':
        ############################################################################################
        hdrMsg( "Config %s  BGP ipv4 neighbors between dut1 and dut2 under peer-group"%(max_bfd+1))
        ############################################################################################
        for nbr_1,nbr_2 in zip(dut2_ipv6,dut1_ipv6):
            dict1 = {'local_as':dut1_as, 'vrf_name': vrfname, 'peergroup': 'peer_v6', 'config_type_list': ['peergroup'], 'remote_as': dut2_as, 'neighbor': nbr_1,}
            dict2 = {'local_as':dut2_as, 'vrf_name': vrfname, 'peergroup': 'peer_v6', 'config_type_list': ['peergroup',], 'remote_as': dut1_as, 'neighbor': nbr_2,'addr_family':'ipv6'}
            parallel.exec_parallel(True, [dut1, dut2], bgp_api.config_bgp, [dict1, dict2])
        dict1 = {'local_as':dut1_as, 'vrf_name': vrfname, 'peergroup': 'peer_v6', 'config_type_list': ['connect', 'activate'], 'neighbor': 'peer_v6', 'connect': 1,'addr_family':'ipv6'}
        dict2 = {'local_as':dut2_as, 'vrf_name': vrfname, 'peergroup': 'peer_v6', 'config_type_list': ['connect', 'activate'], 'neighbor': 'peer_v6', 'connect': 1,'addr_family':'ipv6'}
        parallel.exec_parallel(True, [dut1, dut2], bgp_api.config_bgp, [dict1, dict2])

    else:
        ############################################################################################
        hdrMsg( "Config %s  BGP ipv4 neighbors between dut1 and dut2 under peer-group"%(len(dut2_ip)))
        ############################################################################################
        for nbr_1,nbr_2 in zip(dut2_ip,dut1_ip) :
            dict1 = {'local_as':dut1_as, 'vrf_name': vrfname, 'peergroup': 'peer_v4', 'config_type_list': ['peergroup'], 'remote_as': dut2_as, 'neighbor': nbr_1}
            dict2 = {'local_as':dut2_as, 'vrf_name': vrfname, 'peergroup': 'peer_v4', 'config_type_list': ['peergroup'], 'remote_as': dut1_as, 'neighbor': nbr_2}
            parallel.exec_parallel(True, [dut1, dut2], bgp_api.config_bgp, [dict1, dict2])

        ############################################################################################
        hdrMsg( "Config %s  BGP ipv6 neighbors between dut1 and dut2 under peer-group"%(dut2_ipv6))
        ############################################################################################
        for nbr_1,nbr_2 in zip(dut2_ipv6,dut1_ipv6):
            dict1 = {'local_as':dut1_as, 'vrf_name': vrfname, 'peergroup': 'peer_v6', 'config_type_list': ['peergroup'], 'remote_as': dut2_as, 'neighbor': nbr_1,'addr_family':'ipv6'}
            dict2 = {'local_as':dut2_as, 'vrf_name': vrfname, 'peergroup': 'peer_v6', 'config_type_list': ['peergroup'], 'remote_as': dut1_as, 'neighbor': nbr_2,'addr_family':'ipv6'}
            parallel.exec_parallel(True, [dut1, dut2], bgp_api.config_bgp, [dict1, dict2])
        dict1 = {'local_as':dut1_as, 'vrf_name': vrfname, 'peergroup': 'peer_v6', 'config_type_list': ['connect', 'activate'], 'neighbor': 'peer_v6', 'connect': 1,'addr_family':'ipv6'}
        dict2 = {'local_as':dut2_as, 'vrf_name': vrfname, 'peergroup': 'peer_v6', 'config_type_list': ['connect', 'activate'], 'neighbor': 'peer_v6', 'connect': 1,'addr_family':'ipv6'}
        parallel.exec_parallel(True, [dut1, dut2], bgp_api.config_bgp, [dict1, dict2])



def base_config(vrfname='default'):
    D1_ports, D2_ports, max_bfd, ipv4_bgp, ipv6_bgp, dut1_ip, dut2_ip, dut1_ipv6, dut2_ipv6, vlan_list, vlan_intf = \
    return_vars(vrfname)

    hdrMsg("##### BASE config Starts ####")

    ############################################################################################
    hdrMsg("Step-C1: Configure %s Vlans  on dut1 and dut2"%max_bfd)
    ############################################################################################
    utils.exec_all(True, [[vlan_api.config_vlan_range, dut1, '{} {}'.format(vlan_list[0], vlan_list[-1])],
                          [vlan_api.config_vlan_range, dut2, '{} {}'.format(vlan_list[0], vlan_list[-1])]])
    if vrfname == user_vrf_name:
        dict1 = {'vrf_name': user_vrf_name, 'skip_error': True}
        parallel.exec_parallel(True, [dut1, dut2], vrf_api.config_vrf, [dict1, dict1])
        dict1 = {'vrf_name': [vrfname]*len(vlan_intf), 'intf_name': vlan_intf, 'skip_error': True}
        dict2 = {'vrf_name': [vrfname]*len(vlan_intf), 'intf_name': vlan_intf, 'skip_error': True}
        parallel.exec_parallel(True, [dut1, dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    ############################################################################################
    hdrMsg("Step-C2: Configure %s as tagged member for vlans %s  on dut1 and %s on dut2"%(D1_ports[0],vlan_list[0:((total_vlans/2))],D2_ports[0]))
    ############################################################################################

    utils.exec_all(True,[[vlan_api.config_vlan_range_members,dut1,'{} {}'.format(vlan_list[0],vlan_list[total_vlans/2]),D1_ports[0]],
                             [vlan_api.config_vlan_range_members,dut2,'{} {}'.format(vlan_list[0],vlan_list[total_vlans/2]),D2_ports[0]]])

    ############################################################################################
    hdrMsg("Step-C2: Configure %s as tagged member for vlans %s  on dut1 and %s on dut2"%(D1_ports[1],vlan_list[((total_vlans/2)):],D2_ports[1]))
    ############################################################################################

    utils.exec_all(True,[[vlan_api.config_vlan_range_members,dut1,'{} {}'.format(vlan_list[((total_vlans/2)+1)],vlan_list[-1]),D1_ports[1]],
                             [vlan_api.config_vlan_range_members,dut2,'{} {}'.format(vlan_list[((total_vlans/2)+1)],vlan_list[-1]),D2_ports[1]]])


    ip_config(test_type,vrfname)
    dict1 = {'vrf_name': vrfname, 'local_as':dut1_as,'router_id':'1.1.1.1','config_type_list':['router_id']}
    dict2 = {'vrf_name': vrfname, 'local_as':dut2_as,'router_id':'2.2.2.2','config_type_list':['router_id']}
    parallel.exec_parallel(True, [dut1, dut2], bgp_api.config_bgp, [dict1, dict2])

    bgp_config(test_type,vrfname)

    ############################################################################################
    hdrMsg("Step-C3: Verify all BGP/BGP+ sessions are in Established state")
    ############################################################################################
    if test_type == 'ipv4':
        nbr_list = dut2_ip
    elif test_type == 'ipv6':
        nbr_list = dut2_ipv6
    else:
        nbr_list= dut2_ip + dut2_ipv6
    result = retry_api(ip_bgp.check_bgp_session,dut1,nbr_list=nbr_list, state_list=['Established']*len(nbr_list),vrf_name=vrfname, retry_count=10,delay=3)

    if result is False:
        st.error("One or more BGP sessions did not come up")
        st.report_fail('module_config_failed', 'One or more BGP sessions did not come up')
    hdrMsg("##### BASE config END ####")


def ip_deconfig(test_type,vrfname='default'):
    D1_ports, D2_ports, max_bfd, ipv4_bgp, ipv6_bgp, dut1_ip, dut2_ip, dut1_ipv6, dut2_ipv6, vlan_list, vlan_intf = \
    return_vars(vrfname)
    if test_type == 'mix':
        ############################################################################################
        hdrMsg("Delete ip address %s on dut1 and %s on dut2 for all Vlans"  % (dut1_ip,dut2_ip))
        ############################################################################################
        for vlan,ip_1,ip_3 in zip(vlan_intf,dut1_ip,dut2_ip):
            utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, vlan,ip_1,ip_mask],[ip_api.delete_ip_interface,dut2, vlan,ip_3,ip_mask]])

        ############################################################################################
        hdrMsg("Delete ipv6 address %s on dut1 and %s on dut2 for all Vlans"  % (dut1_ipv6,dut2_ipv6))
        ############################################################################################
        for vlan,ip_1,ip_3 in zip(vlan_intf,dut1_ipv6,dut2_ipv6):
            utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, vlan,ip_1,ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut2, vlan,ip_3,ipv6_mask,'ipv6']])

    elif test_type == 'ipv4':
        ############################################################################################
        hdrMsg("Delete ip address %s on dut1 and %s on dut2 for all Vlans" % (dut1_ip, dut2_ip))
        ############################################################################################
        for vlan, ip_1, ip_3 in zip(vlan_intf, dut1_ip, dut2_ip):
            utils.exec_all(True, [[ip_api.delete_ip_interface, dut1, vlan, ip_1, ip_mask],
                                  [ip_api.delete_ip_interface, dut2, vlan, ip_3, ip_mask]])

    else:
        ############################################################################################
        hdrMsg("Delete ipv6 address %s on dut1 and %s on dut2 for all Vlans"  % (dut1_ipv6,dut2_ipv6))
        ############################################################################################
        for vlan,ip_1,ip_3 in zip(vlan_intf,dut1_ipv6,dut2_ipv6):
            utils.exec_all(True,[[ip_api.delete_ip_interface,dut1, vlan,ip_1,ipv6_mask,'ipv6'],[ip_api.delete_ip_interface,dut2, vlan,ip_3,ipv6_mask,'ipv6']])


def base_deconfig(vrfname='default'):
    D1_ports, D2_ports, max_bfd, ipv4_bgp, ipv6_bgp, dut1_ip, dut2_ip, dut1_ipv6, dut2_ipv6, vlan_list, vlan_intf = \
    return_vars(vrfname)
    hdrMsg("##### BASE Deconfig Starts ####")
    ############################################################################################
    hdrMsg("Step-DC1: Remove BGP router from dut1 and dut2")
    ############################################################################################
    dict1 = {'local_as':dut1_as, 'vrf_name': vrfname, 'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}
    dict2 = {'local_as':dut2_as, 'vrf_name': vrfname, 'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut2], bgp_api.config_bgp, [dict1, dict2])

    ip_deconfig(test_type,vrfname)

    utils.exec_all(True,[[vlan_api.config_vlan_range_members,dut1,'{} {}'.format(vlan_list[0],vlan_list[total_vlans/2]),D1_ports[0],'del'],
                             [vlan_api.config_vlan_range_members,dut2,'{} {}'.format(vlan_list[0],vlan_list[total_vlans/2]),D2_ports[0],'del']])


    utils.exec_all(True,[[vlan_api.config_vlan_range_members,dut1,'{} {}'.format(vlan_list[((total_vlans/2)+1)],vlan_list[-1]),D1_ports[1],'del'],
                             [vlan_api.config_vlan_range_members,dut2,'{} {}'.format(vlan_list[((total_vlans/2)+1)],vlan_list[-1]),D2_ports[1],'del']])

    if vrfname == user_vrf_name:
        dict1 = {'vrf_name': [vrfname]*len(vlan_intf), 'intf_name': vlan_intf, 'skip_error': True, 'config': 'no'}
        dict2 = {'vrf_name': [vrfname]*len(vlan_intf), 'intf_name': vlan_intf, 'skip_error': True, 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True, [[vlan_api.config_vlan_range, dut1, '{} {}'.format(vlan_list[0], vlan_list[-1]),'del'],
                          [vlan_api.config_vlan_range, dut2, '{} {}'.format(vlan_list[0], vlan_list[-1]),'del']])

    hdrMsg("##### BASE Deconfig End ####")


@pytest.mark.scale
def test_FtOpSoRoBfdSc085(prologue_epilogue):
    tc_result =True;err_list=[]

    ############################################################################################
    hdrMsg("Step T1 : Enable BFD for 64 BGP neighbors under peer-group")
    ############################################################################################
    if test_type == 'ipv4':
        bfd_peer = ['peer_v4']; nbr_list = dut2_ip; local_list = dut1_ip
    elif test_type == 'ipv6':
        bfd_peer = ['peer_v6'] ;nbr_list = dut2_ipv6;local_list = dut1_ipv6
    else:
        bfd_peer = ['peer_v4','peer_v6'] ; nbr_list= dut2_ip + dut2_ipv6 ;local_list= dut1_ip+dut1_ipv6
        nbr_list_vrf = dut2_ip_vrf + dut2_ipv6_vrf
        local_list_vrf = dut1_ip_vrf + dut1_ipv6_vrf
    dict1 = {"local_asn": dut1_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'yes'}
    dict2 = {"local_asn": dut2_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut2], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name':user_vrf_name, "local_asn": dut1_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'yes'}
    dict2 = {'vrf_name':user_vrf_name, "local_asn": dut2_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut2], bfd.configure_bfd, [dict1, dict2])

    ############################################################################################
    hdrMsg("Step T2 :Verify all 64 BFD sessions are UP with default timers")
    ############################################################################################
    if test_type != 'mix':
        intf_multiplier = 1
    else:
        intf_multiplier = 2
    result = retry_api(bfd.verify_bfd_peer,dut1, peer=nbr_list,interface=vlan_intf*intf_multiplier,status=['up']*max_bfd,rx_interval=[['300','300']]*max_bfd,tx_interval=[['300','300']]*max_bfd,retry_count=5,delay=1)
    if result is False:
        err = "BFD parameters are incorrect for one or more BFD peers"
        err_list.append(err);tc_result =False
        st.error(err)
    result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name=user_vrf_name, peer=nbr_list_vrf,interface=vlan_intf_vrf*intf_multiplier,status=['up']*max_bfd_vrf,rx_interval=[['300','300']]*max_bfd_vrf,tx_interval=[['300','300']]*max_bfd_vrf,retry_count=5,delay=1)
    if result is False:
        err = "BFD parameters are incorrect for one or more BFD peers"
        err_list.append(err);tc_result =False
        st.error(err)



    ############################################################################################
    hdrMsg("Step T3 :Configure 100ms*3 for all BFD sessions and enable echo-mode on both dut")
    ############################################################################################
    bfd.configure_bfd(dut1, interface=vlan_intf*intf_multiplier, neighbor_ip=nbr_list, multiplier=["3"] * max_bfd,rx_intv=["100"]*max_bfd, tx_intv=["100"]*max_bfd, echo_mode_enable='', echo_intv=[1000]*max_bfd)
    bfd.configure_bfd(dut2, interface=vlan_intf * intf_multiplier, neighbor_ip=local_list, multiplier=["3"] * max_bfd,rx_intv=["100"] * max_bfd, tx_intv=["100"] * max_bfd, echo_mode_enable='', echo_intv=[1000]*max_bfd)

    bfd.configure_bfd(dut1, vrf_name=user_vrf_name, interface=vlan_intf_vrf*intf_multiplier, neighbor_ip=nbr_list_vrf, multiplier=["3"] * max_bfd_vrf,rx_intv=["100"]*max_bfd_vrf, tx_intv=["100"]*max_bfd_vrf, echo_mode_enable='', echo_intv=[1000]*max_bfd_vrf)
    bfd.configure_bfd(dut2, vrf_name=user_vrf_name, interface=vlan_intf_vrf * intf_multiplier, neighbor_ip=local_list_vrf, multiplier=["3"] * max_bfd_vrf,rx_intv=["100"] * max_bfd_vrf, tx_intv=["100"] * max_bfd_vrf, echo_mode_enable='', echo_intv=[1000]*max_bfd_vrf)

    ############################################################################################
    hdrMsg("Step T4 :Verify all 64 BFD sessions are UP with 100*3 ms timers")
    ############################################################################################
    st.wait(120)
    result = retry_api(bfd.verify_bfd_peer,dut1, peer=nbr_list,interface=vlan_intf*intf_multiplier,status=['up']*max_bfd,rx_interval=[['100','100']]*max_bfd,tx_interval=[['100','100']]*max_bfd,retry_count=2,delay=1)
    if result is False:
        err ="BFD parameters are incorrect for one or more BFD peers"
        err_list.append(err);tc_result =False
        st.error(err)
    result = retry_api(bfd.verify_bfd_peer,dut1, vrf_name=user_vrf_name, peer=nbr_list_vrf,interface=vlan_intf_vrf*intf_multiplier,status=['up']*max_bfd_vrf,rx_interval=[['100','100']]*max_bfd_vrf,tx_interval=[['100','100']]*max_bfd_vrf,retry_count=2,delay=1)
    if result is False:
        err ="BFD parameters are incorrect for one or more BFD peers"
        err_list.append(err);tc_result =False
        st.error(err)
    ############################################################################################
    hdrMsg("Step T5 :Verify BFD state under BGP neighbors are up")
    ############################################################################################

    result = ip_bgp.verify_bgp_neighbor(dut1,neighborip=nbr_list,state=['Established']*len(nbr_list))
    if result is False:
        err = "BFD parameters are incorrect for BGP neighbor with scale config"
        err_list.append(err);tc_result = False
        st.error(err)
    result = ip_bgp.verify_bgp_neighbor(dut1,vrf=user_vrf_name, neighborip=nbr_list_vrf,state=['Established']*len(nbr_list_vrf))
    if result is False:
        err = "BFD parameters are incorrect for BGP neighbor with scale config"
        err_list.append(err);tc_result = False
        st.error(err)
    ############################################################################################
    hdrMsg("Step T6 :Disable/enable BFD unser BGP and verify max BFD sessions gets established")
    ############################################################################################

    dict1 = {"local_asn": dut1_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'no'}
    dict2 = {"local_asn": dut2_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut2], bfd.configure_bfd, [dict1, dict2])


    dict1 = {"local_asn": dut1_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'yes'}
    dict2 = {"local_asn": dut2_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut2], bfd.configure_bfd, [dict1, dict2])

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=nbr_list, interface=vlan_intf*intf_multiplier, status=['up'] * max_bfd,
                       rx_interval=[['100', '100']] * max_bfd, tx_interval=[['100', '100']] * max_bfd, retry_count=2,
                       delay=1)
    if result is False:
        err ="BFD parameters are incorrect for one or more BFD peers after disable/enable BFD"
        err_list.append(err);tc_result =False
        st.error(err)


    ############################################################################################
    hdrMsg("Step T7 :Bring down port on dut2 and verify BGP sessions goes down immediately")
    ############################################################################################
    port.shutdown(dut2,[D2_ports[0],D2_ports[1]])
    st.wait(2)

    result = retry_api(bfd.verify_bfd_peer,dut1, peer=nbr_list,interface=vlan_intf*intf_multiplier,status=['down']*max_bfd,retry_count=2,delay=1)
    if result is False:
        err ="BFD parameters are incorrect for one or more BFD peers"
        err_list.append(err);tc_result =False
        st.error(err)

    ############################################################################################
    hdrMsg("Step T8 :Verify BFD state and BGP state is down under BGP neighbors")
    ############################################################################################

    result = ip_bgp.check_bgp_session(dut1,nbr_list=nbr_list,state_list=['Established']*max_bfd)
    if result is True:
        err ='BGP sessions did not go down after link down'
        err_list.append(err);tc_result =False
        st.error(err)

    ############################################################################################
    hdrMsg("Step T9 :Bring up port on dut2 and verify BGP  BFD sessions comes up")
    ############################################################################################
    port.noshutdown(dut2,[D2_ports[0],D2_ports[1]])
    result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr_list,state=['Established']*len(nbr_list))
    if result is False:
        err = "BFD /BGP state not UP for one or more BGP neighbors with scale config"
        err_list.append(err);tc_result = False
        st.error(err)

    ############################################################################################
    hdrMsg("Step T10 :Disable BFD under BGP and delete static BFD entries")
    ############################################################################################

    dict1 = {"local_asn": dut1_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'no'}
    dict2 = {"local_asn": dut2_as, 'peergroup': bfd_peer, 'neighbor_ip': bfd_peer, 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut2], bfd.configure_bfd, [dict1, dict2])

    if test_type == 'ipv6':
        bfd.configure_bfd(dut1, interface=vlan_intf, neighbor_ip=nbr_list, local_address=local_list,config='no')
        bfd.configure_bfd(dut2, interface=vlan_intf, neighbor_ip=local_list, local_address=nbr_list, config='no')
    elif test_type == 'mix':
        bfd.configure_bfd(dut1, interface=vlan_intf, neighbor_ip=dut2_ip, config='no')
        bfd.configure_bfd(dut1, interface=vlan_intf, neighbor_ip=dut2_ipv6, local_address=dut1_ipv6, config='no')
        bfd.configure_bfd(dut2, interface=vlan_intf, neighbor_ip=dut1_ip, config='no')
        bfd.configure_bfd(dut2, interface=vlan_intf, neighbor_ip=dut1_ipv6, local_address=dut2_ipv6, config='no')
    else:
        bfd.configure_bfd(dut1, interface=vlan_intf, neighbor_ip=nbr_list,config='no')
        bfd.configure_bfd(dut2, interface=vlan_intf, neighbor_ip=local_list, config='no')

    if tc_result is False:
        st.report_fail('bfd_fail_reason',err_list[0])

    st.report_pass('test_case_passed')
