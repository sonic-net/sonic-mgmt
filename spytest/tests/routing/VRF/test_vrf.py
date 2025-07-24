##################################################################################
# Script Title : VRF Lite
# Author       : Manisha Joshi
# Mail-id      : manisha.joshi@broadcom.com
#################################################################################

import pytest

from spytest import st
from spytest.tgen.tg import tgen_obj_dict

from vrf_vars import data
import vrf_lib as loc_lib

from apis.system import basic
import apis.routing.ip as ip_api
import apis.routing.vrf as vrf_api
import apis.routing.bgp as bgp_api
import apis.routing.arp as arp_api
import apis.system.reboot as reboot_api

from utilities import common as utils
from utilities.utils import rif_support_check


def initialize_topology():
    st.banner("Initialize variables")
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2", "D2T1:2")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    utils.exec_all(True, [[bgp_api.enable_docker_routing_config_mode, data.dut1], [bgp_api.enable_docker_routing_config_mode, data.dut2]])
    platform_1 = basic.get_hwsku(data.dut1)
    platform_2 = basic.get_hwsku(data.dut2)
    data.platform_1 = rif_support_check(data.dut1, platform=platform_1.lower())
    data.platform_2 = rif_support_check(data.dut2, platform=platform_2.lower())
    data.d1_dut_ports = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]
    data.d2_dut_ports = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    data.dut1_tg1_ports = [vars.D1T1P1]
    data.dut2_tg1_ports = [vars.D2T1P1]
    data.tg_dut1_hw_port = vars.T1D1P1
    data.tg_dut2_hw_port = vars.T1D2P1
    data.tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg_dut1_p1 = data.tg1.get_port_handle(vars.T1D1P1)
    data.tg_dut2_p1 = data.tg2.get_port_handle(vars.T1D2P1)
    data.d1_p1_intf_v4 = {}
    data.d1_p1_intf_v6 = {}
    data.d2_p1_intf_v4 = {}
    data.d2_p1_intf_v6 = {}
    data.d1_p1_bgp_v4 = {}
    data.d1_p1_bgp_v6 = {}
    data.d2_p1_bgp_v4 = {}
    data.d2_p1_bgp_v6 = {}
    data.stream_list = {}
    data.sub_intf = st.get_args("routed_sub_intf")
    st.banner("sub interface mode is: {}".format(data.sub_intf))
    if data.sub_intf:
        data.phy_port121 = "{}.{}".format(data.d1_dut_ports[0], 111)
        data.phy_port211 = "{}.{}".format(data.d2_dut_ports[0], 111)
        data.phy_port123 = data.d1_dut_ports[2]
        data.phy_port213 = data.d2_dut_ports[2]
        data.phy_port124 = data.d1_dut_ports[3]
        data.phy_port214 = data.d2_dut_ports[3]
        data.port_channel12 = 'PortChannel10.123'
    else:
        data.phy_port121 = data.d1_dut_ports[0]
        data.phy_port211 = data.d2_dut_ports[0]
        data.phy_port123 = data.d1_dut_ports[2]
        data.phy_port213 = data.d2_dut_ports[2]
        data.phy_port124 = data.d1_dut_ports[3]
        data.phy_port214 = data.d2_dut_ports[3]
        data.port_channel12 = 'PortChannel10'


@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue():
    initialize_topology()
    loc_lib.vrf_base_config()
    yield
    # loc_lib.vrf_base_unconfig()


@pytest.mark.sanity
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli001'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli006'])
def test_VrfFun001_06():
    st.log('#######################################################################################################################')
    st.log(' Combining FtRtVrfFun001 and FtRtVrfFun006')
    st.log(' FtRtVrfFun001: Verify address family IPv4 and IPv6 in VRF instance')
    st.log(' FtRtVrfFun006: Configure multiple interfaces to a VRF and configure same interface to multiple VRFs')
    st.log('#######################################################################################################################')

    err_list = []
    output = vrf_api.get_vrf_verbose(dut=data.dut1, vrfname=data.vrf_name[0])
    if data.vrf_name[0] in output['vrfname']:
        st.banner('STEP 1 PASS: VRF {} configured on DUT1 is as expected'.format(data.vrf_name[0]))
    else:
        err = st.banner('STEP 1 FAIL: VRF {} configured on DUT1 is not expected'.format(data.vrf_name[0]))
        err_list.append(err)
    for value in output['interfaces']:
        if data.phy_port121 or data.dut1_loopback[0] or data.dut1_loopback[1] or value == 'Vlan11':
            st.banner('STEP 2 PASS: Bind to VRF for intf {} is as expected'.format(value))
        else:
            err = st.banner('STEP 2 FAIL: Bind to VRF for intf {} is not as expected'.format(value))
            err_list.append(err)
    output = vrf_api.get_vrf_verbose(dut=data.dut2, vrfname=data.vrf_name[0])
    if data.vrf_name[0] in output['vrfname']:
        st.banner('STEP 3 PASS: VRF {} configured on DUT1 is as expected'.format(data.vrf_name[0]))
    else:
        err = st.banner('STEP 3 FAIL: VRF {} configured on DUT1 is as not expected'.format(data.vrf_name[0]))
        err_list.append(err)
    for value in output['interfaces']:
        if data.d2_dut_ports[0] or data.dut2_loopback[0] or value == 'Vlan16':
            st.banner('STEP 4 PASS: Bind to VRF for intf {} is as expected'.format(value))
        else:
            err = st.banner('STEP 4 FAIL: Bind to VRF for intf {} is not as expected'.format(value))
            err_list.append(err)
    if not ip_api.verify_interface_ip_address(data.dut1, data.port_channel12, data.dut1_dut2_vrf_ip[0] + '/24', vrfname=data.vrf_name[2]):
        err = st.banner('STEP 5 FAIL: IPv4 address configuration on portchannel interface failed')
        err_list.append(err)
    else:
        st.banner('STEP 5 PASS: IPv4 address configuration on portchannel interface')
    if not ip_api.verify_interface_ip_address(data.dut2, data.port_channel12, data.dut2_dut1_vrf_ipv6[0] + '/64', vrfname=data.vrf_name[2], family='ipv6'):
        err = st.banner('STEP 6 FAIL: IPv6 address configuration on portchannel interface failed')
        err_list.append(err)
    else:
        st.banner('STEP 6 PASS: IPv6 address configuration on portchannel interface')
    if arp_api.get_arp_count(data.dut1, vrf=data.vrf_name[1]) < 2:
        err = st.banner('STEP 7 FAIL: ARP entry for VRF-102 not as expected on DUT1')
        err_list.append(err)
    else:
        st.banner('STEP 7 PASS: ARP entry for VRF-102 found as expected on DUT1')
    if arp_api.get_arp_count(data.dut2, vrf=data.vrf_name[1]) < 2:
        err = st.banner('STEP 8 FAIL: ARP entry for VRF-102 not as expected on DUT2')
        err_list.append(err)
    else:
        st.banner('STEP 8 PASS: ARP entry for VRF-102 found as expected on DUT2')
    if arp_api.get_ndp_count(data.dut1, vrf=data.vrf_name[1]) < 2:
        err = st.banner('STEP 9 FAIL: NDP entry for VRF-102 not as expected on DUT1')
        err_list.append(err)
    else:
        st.banner('STEP 9 PASS: NDP entry for VRF-102 found as expected on DUT1')
    if arp_api.get_ndp_count(data.dut2, vrf=data.vrf_name[1]) < 2:
        err = st.banner('STEP 10 FAIL: NDP entry for VRF-102 not as expected on DUT2')
        err_list.append(err)
    else:
        st.banner('STEP 10 PASS: NDP entry for VRF-102 found as expected on DUT2')
    if not loc_lib.verify_bgp(phy='1', ip='ipv6'):
        err = st.banner('STEP 11 FAIL: IPv6 BGP session on VRF-101 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 11 PASS: IPv6 BGP session on VRF-101 did come up')
    if not loc_lib.verify_bgp(ve='1', ip='ipv4'):
        err = st.banner('STEP 12 FAIL: IPv4 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 12 PASS: IPv4 BGP session on VRF-102 did come up')
    if not loc_lib.verify_bgp(ve='1', ip='ipv6'):
        err = st.banner('STEP 13 FAIL: IPv6 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 13 PASS: IPv6 BGP session on VRF-102 did come up')
    if not loc_lib.verify_bgp(pc='1', ip='ipv4'):
        err = st.banner('STEP 14 FAIL: IPv4 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 14 PASS: IPv4 BGP session on VRF-103 did come up')
    if not loc_lib.verify_bgp(pc='1', ip='ipv6'):
        err = st.banner('STEP 15 FAIL: IPv6 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 15 PASS: IPv6 BGP session on VRF-103 did come up')

    if err_list:
        loc_lib.debug_bgp_vrf()

    st.report_result(err_list, first_only=True)


def vrf_tc_26_27():
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.tg1_dut1_vrf_ip[0],
                       remote_as=data.dut1_tg_as, config='yes', config_type_list=['neighbor'])
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.tg1_dut1_vrf_ip[0],
                       remote_as=data.dut1_tg_as, config='yes', config_type_list=['activate'])
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.dut2_dut1_vrf_ip[0],
                       remote_as=data.dut2_as[0], config='yes', config_type_list=['neighbor'])
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.dut2_dut1_vrf_ip[0],
                       remote_as=data.dut2_as[0], config='yes', config_type_list=['activate', 'nexthop_self'])

# @pytest.mark.depends('test_VrfFun001_06')


@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun026'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun027'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun037'])
def test_VrfFun_26_27():
    st.log('#######################################################################################################################')
    st.log('Combined FtRtVrfFun026 and FtRtVrfFun027 ')
    st.log(' FtRtVrfFun026: Verify IBGP neighbor for BGPv4 in vrf ')
    st.log('FtRtVrfFun027 Verify EBGP neighbor for BGPv4 in vrf for ipv4 ')
    st.log('#######################################################################################################################')

    err_list = []
    st.banner('Remove EBGP IPv4 neighbor configuration from all the VRFs  ')
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.dut2_dut1_vrf_ip[0],
                       remote_as=data.dut2_as[0], config='no', config_type_list=['neighbor'])
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.dut2_dut1_vrf_ip[0],
                       remote_as=data.dut2_as[0], config='yes', config_type_list=['neighbor'])
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.dut2_dut1_vrf_ip[0],
                       remote_as=data.dut2_as[0], config='yes', config_type_list=['activate', 'nexthop_self'])
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.tg1_dut1_vrf_ip[0],
                       remote_as=data.dut1_tg_as, config='no', config_type_list=['neighbor'])
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.tg1_dut1_vrf_ip[0],
                       remote_as=data.dut1_tg_as, config='yes', config_type_list=['neighbor'])
    bgp_api.config_bgp(dut=data.dut1, vrf_name=data.vrf_name[0], local_as=data.dut1_as[0], neighbor=data.tg1_dut1_vrf_ip[0],
                       remote_as=data.dut1_tg_as, config='yes', config_type_list=['activate'])
    st.wait(5, "Waiting for 5 sec")
    if not ip_api.verify_ip_route(data.dut1, vrf_name=data.vrf_name[0], type='B', nexthop=data.tg1_dut1_vrf_ip[0], interface='Vlan' + data.dut1_tg1_vlan[0]):
        err = st.banner('STEP 1 FAIL: IPv4 routes on VRF-101, not learnt on DUT1')
        err_list.append(err)
    else:
        st.banner('STEP 1 PASS: IPv4 routes on VRF-101, learnt on DUT1')
    if not ip_api.verify_ip_route(data.dut2, vrf_name=data.vrf_name[0], type='B', nexthop=data.dut1_dut2_vrf_ip[0], interface=data.phy_port211):
        err = st.banner('STEP 2 FAIL: IPv4 routes on VRF-101, not learnt on DUT2')
        err_list.append(err)
    else:
        st.banner('STEP 2 PASS: IPv4 routes on VRF-101, learnt on DUT2')

    if err_list:
        err = st.banner('IPv4 BGP session did not come up, after delete/add IPv4 IBGP and EBGP config')
        err_list.insert(0, err)
        loc_lib.debug_bgp_vrf()
        vrf_tc_26_27()
    return st.report_result(err_list)


@pytest.fixture(scope="function")
def vrf_fixture_tc_10_12_14(request, prologue_epilogue):
    yield
    st.banner('Delete the static routes configured in VRF 1')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ip[0], data.dut2_tg1_vrf_ip_subnet, data.dut2_dut1_vrf_ip[0], 'ipv4', data.vrf_name[0], 'no'],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ip[0], data.dut1_tg1_vrf_ip_subnet, data.dut1_dut2_vrf_ip[0], 'ipv4', data.vrf_name[0], 'no']])
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ipv6[0], data.dut2_tg1_vrf_ipv6_subnet, data.dut2_dut1_vrf_ipv6[0], 'ipv6', data.vrf_name[0], 'no'],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ipv6[0], data.dut1_tg1_vrf_ipv6_subnet, data.dut1_dut2_vrf_ipv6[0], 'ipv6', data.vrf_name[0], 'no']])

    st.banner('Delete the static routes configured in VRF 2')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ip[1], data.dut2_tg1_vrf_ip_subnet, data.dut2_dut1_vrf_ip[0], 'ipv4', data.vrf_name[1], 'no'],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ip[1], data.dut1_tg1_vrf_ip_subnet, data.dut1_dut2_vrf_ip[0], 'ipv4', data.vrf_name[1], 'no']])
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ipv6[1], data.dut2_tg1_vrf_ipv6_subnet, data.dut2_dut1_vrf_ipv6[0], 'ipv6', data.vrf_name[1], 'no'],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ipv6[1], data.dut1_tg1_vrf_ipv6_subnet, data.dut1_dut2_vrf_ipv6[0], 'ipv6', data.vrf_name[1], 'no']])

    st.banner('Delete the static routes configured in VRF 3')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ip[2], data.dut2_tg1_vrf_ip_subnet, data.dut2_dut1_vrf_ip[0], 'ipv4', data.vrf_name[2], 'no'],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ip[2], data.dut1_tg1_vrf_ip_subnet, data.dut1_dut2_vrf_ip[0], 'ipv4', data.vrf_name[2], 'no']])
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ipv6[2], data.dut2_tg1_vrf_ipv6_subnet, data.dut2_dut1_vrf_ipv6[0], 'ipv6', data.vrf_name[2], 'no'],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ipv6[2], data.dut1_tg1_vrf_ipv6_subnet, data.dut1_dut2_vrf_ipv6[0], 'ipv6', data.vrf_name[2], 'no']])

    loc_lib.dut_vrf_bgp(phy='1')
    loc_lib.dut_vrf_bgp(ve='1')
    loc_lib.dut_vrf_bgp(pc='1')
    loc_lib.tg_vrf_bgp(phy='1')
    loc_lib.tg_vrf_bgp(ve='1')
    loc_lib.tg_vrf_bgp(pc='1')


@pytest.mark.functionality
# @pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun010'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun012'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun014'])
def test_VrfFun_10_12_14(vrf_fixture_tc_10_12_14):

    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun0010: Add/delete static route under vrf with next hop as physical interface')
    st.log('FtRtVrfFun0012: Add/delete static route under vrf with next hop as virtual interface ')
    st.log('FtRtVrfFun0014: Add/delete static route under vrf with next hop as port channel ')
    st.log('#######################################################################################################################')

    err_list = []
    loc_lib.dut_vrf_bgp(phy='1', config='no')
    loc_lib.dut_vrf_bgp(ve='1', config='no')
    loc_lib.dut_vrf_bgp(pc='1', config='no')
    st.banner('Configure IPv4 static routes on VRF-101')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ip[0], data.dut2_tg1_vrf_ip_subnet, data.dut2_dut1_vrf_ip[0], 'ipv4', data.vrf_name[0], ''],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ip[0], data.dut1_tg1_vrf_ip_subnet, data.dut1_dut2_vrf_ip[0], 'ipv4', data.vrf_name[0], '']])
    if not ip_api.ping(data.dut1, data.dut2_tg1_vrf_ip[0], interface=data.vrf_name[0], count=2):
        err = st.banner('STEP 1 FAIL: IPv4 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 failed after static route configuration')
        err_list.append(err)
    else:
        st.banner('STEP 1 PASS: IPv4 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 passed after static route configuration')
    st.banner('Configure IPv6 static routes on VRF-101')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ipv6[0], data.dut2_tg1_vrf_ipv6_subnet, data.dut2_dut1_vrf_ipv6[0], 'ipv6', data.vrf_name[0], ''],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ipv6[0], data.dut1_tg1_vrf_ipv6_subnet, data.dut1_dut2_vrf_ipv6[0], 'ipv6', data.vrf_name[0], '']])
    if not ip_api.ping(data.dut1, data.dut2_tg1_vrf_ipv6[0], interface=data.vrf_name[0], count=2, family='ipv6'):
        err = st.banner('STEP 2 FAIL: IPv6 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 failed after static route configuration')
        err_list.append(err)
    else:
        st.banner('STEP 2 PASS: IPv6 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 passed after static route configuration')
    st.banner('Configure IPv4 static routes on VRF-102')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ip[1], data.dut2_tg1_vrf_ip_subnet, data.dut2_dut1_vrf_ip[0], 'ipv4', data.vrf_name[1], ''],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ip[1], data.dut1_tg1_vrf_ip_subnet, data.dut1_dut2_vrf_ip[0], 'ipv4', data.vrf_name[1], '']])
    if not ip_api.ping(data.dut1, data.dut2_tg1_vrf_ip[1], interface=data.vrf_name[1], count=2):
        err = st.banner('STEP 3 FAIL: IPv4 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration')
        err_list.append(err)
    else:
        st.banner('STEP 3 PASS: IPv4 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 passed after static route configuration')
    st.banner('Configure IPv6 static routes on VRF-102')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ipv6[1], data.dut2_tg1_vrf_ipv6_subnet, data.dut2_dut1_vrf_ipv6[0], 'ipv6', data.vrf_name[1], ''],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ipv6[1], data.dut1_tg1_vrf_ipv6_subnet, data.dut1_dut2_vrf_ipv6[0], 'ipv6', data.vrf_name[1], '']])
    if not ip_api.ping(data.dut1, data.dut2_tg1_vrf_ipv6[1], family='ipv6', interface=data.vrf_name[1], count=2):
        err = st.banner('STEP 4 FAIL: IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration')
        err_list.append(err)
    else:
        st.banner('STEP 4 PASS: IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 passed after static route configuration')
    st.banner('Configure IPv4 static routes on VRF-103')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ip[2], data.dut2_tg1_vrf_ip_subnet, data.dut2_dut1_vrf_ip[0], 'ipv4', data.vrf_name[2], ''],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ip[2], data.dut1_tg1_vrf_ip_subnet, data.dut1_dut2_vrf_ip[0], 'ipv4', data.vrf_name[2], '']])
    if not ip_api.ping(data.dut1, data.dut2_tg1_vrf_ip[2], interface=data.vrf_name[2], count=2):
        err = st.banner('STEP 5 FAIL: IPv4 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed after static route configuration')
        err_list.append(err)
    else:
        st.banner('STEP 5 PASS: IPv4 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 passed after static route configuration')
    st.banner('Configure IPv6 static routes on VRF-103')
    utils.exec_all(True, [[ip_api.config_static_route_vrf, data.dut1, data.dut2_tg1_vrf_ipv6[2], data.dut2_tg1_vrf_ipv6_subnet, data.dut2_dut1_vrf_ipv6[0], 'ipv6', data.vrf_name[2], ''],
                          [ip_api.config_static_route_vrf, data.dut2, data.dut1_tg1_vrf_ipv6[2], data.dut1_tg1_vrf_ipv6_subnet, data.dut1_dut2_vrf_ipv6[0], 'ipv6', data.vrf_name[2], '']])
    if not ip_api.ping(data.dut1, data.dut2_tg1_vrf_ipv6[2], family='ipv6', interface=data.vrf_name[2], count=2):
        err = st.banner('STEP 6 FAIL: IPv6 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed after static route configuration')
        err_list.append(err)
    else:
        st.banner('STEP 6 PASS: IPv6 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 passed after static route configuration')

    if err_list:
        err = st.banner('Static route between VRFs failed for VRf-101, VRF-102 and VRF-103')
        err_list.insert(0, err)
        loc_lib.debug_bgp_vrf()

    return st.report_result(err_list)


@pytest.fixture(scope="function")
def vrf_fixture_tc_20_24_25_32_33_44_45(request, prologue_epilogue):
    yield
    dict1 = {'config': 'no', 'vrf_name': data.vrf_name[1], 'local_as': data.dut1_as[1], 'neighbor': data.dut2_dut1_vrf_ip[0], 'remote_as': data.dut2_as[1], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    dict2 = {'config': 'no', 'vrf_name': data.vrf_name[1], 'local_as': data.dut2_as[1], 'neighbor': data.dut1_dut2_vrf_ip[0], 'remote_as': data.dut1_as[1], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'config': 'no', 'vrf_name': data.vrf_name[1], 'local_as': data.dut1_as[1], 'neighbor': data.dut2_dut1_vrf_ipv6[0], 'addr_family': 'ipv6', 'remote_as': data.dut2_as[1], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    dict2 = {'config': 'no', 'vrf_name': data.vrf_name[1], 'local_as': data.dut2_as[1], 'neighbor': data.dut1_dut2_vrf_ipv6[0], 'addr_family': 'ipv6', 'remote_as': data.dut1_as[1], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'config': 'no', 'vrf_name': data.vrf_name[2], 'local_as': data.dut1_as[2], 'neighbor': data.dut2_dut1_vrf_ip[0], 'remote_as': data.dut2_as[2], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    dict2 = {'config': 'no', 'vrf_name': data.vrf_name[2], 'local_as': data.dut2_as[2], 'neighbor': data.dut1_dut2_vrf_ip[0], 'remote_as': data.dut1_as[2], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'config': 'no', 'vrf_name': data.vrf_name[2], 'local_as': data.dut1_as[2], 'neighbor': data.dut2_dut1_vrf_ipv6[0], 'addr_family': 'ipv6', 'remote_as': data.dut2_as[2], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    dict2 = {'config': 'no', 'vrf_name': data.vrf_name[2], 'local_as': data.dut2_as[2], 'neighbor': data.dut1_dut2_vrf_ipv6[0], 'addr_family': 'ipv6', 'remote_as': data.dut1_as[2], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    # dict1 = {'vrf_name':'default','local_as':dut1_as[1],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    # dict2 = {'vrf_name':'default','local_as':dut2_as[1],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    # st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    # port_api.noshutdown(data.dut1, ['Vlan2','Vlan3'])


# @pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun020'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun024'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun025'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun032'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun033'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun044'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun045'])
def test_VrfFun_20_24_25_32_33_44_45(vrf_fixture_tc_20_24_25_32_33_44_45):

    st.log('#######################################################################################################################')
    st.log('FtRtVrfFun020: IPv4 static route leak from non-default vrf to another non-default vrf')
    st.log('FtRtVrfFun024: IPv6 static route leak from non-default vrf to another non-default vrf')
    st.log('FtRtVrfFun025: Import same route from VRF A to VRF B, C and D ')
    st.log('#######################################################################################################################')

    err_list = []
    # port_api.shutdown(data.dut1, ['Vlan2','Vlan3'])
    dict1 = {'vrf_name': data.vrf_name[1], 'local_as': data.dut1_as[1], 'neighbor': data.dut2_dut1_vrf_ip[0], 'remote_as': data.dut2_as[1], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    dict2 = {'vrf_name': data.vrf_name[1], 'local_as': data.dut2_as[1], 'neighbor': data.dut1_dut2_vrf_ip[0], 'remote_as': data.dut1_as[1], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name': data.vrf_name[1], 'local_as': data.dut1_as[1], 'neighbor': data.dut2_dut1_vrf_ipv6[0], 'addr_family': 'ipv6', 'remote_as': data.dut2_as[1], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    dict2 = {'vrf_name': data.vrf_name[1], 'local_as': data.dut2_as[1], 'neighbor': data.dut1_dut2_vrf_ipv6[0], 'addr_family': 'ipv6', 'remote_as': data.dut1_as[1], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    ip_api.show_ip_route(data.dut2, family="ipv4", shell="sonic", vrf_name=data.vrf_name[1])
    ip_api.show_ip_route(data.dut2, family="ipv6", shell="sonic", vrf_name=data.vrf_name[1])
    dict1 = {'vrf_name': data.vrf_name[2], 'local_as': data.dut1_as[2], 'neighbor': data.dut2_dut1_vrf_ip[0], 'remote_as': data.dut2_as[2], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    dict2 = {'vrf_name': data.vrf_name[2], 'local_as': data.dut2_as[2], 'neighbor': data.dut1_dut2_vrf_ip[0], 'remote_as': data.dut1_as[2], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name': data.vrf_name[2], 'local_as': data.dut1_as[2], 'neighbor': data.dut2_dut1_vrf_ipv6[0], 'addr_family': 'ipv6', 'remote_as': data.dut2_as[2], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    dict2 = {'vrf_name': data.vrf_name[2], 'local_as': data.dut2_as[2], 'neighbor': data.dut1_dut2_vrf_ipv6[0], 'addr_family': 'ipv6', 'remote_as': data.dut1_as[2], 'config_type_list': ['import_vrf'], 'import_data.vrf_name': data.vrf_name[0]}
    st.exec_each2([data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    ip_api.show_ip_route(data.dut2, family="ipv4", shell="sonic", vrf_name=data.vrf_name[2])
    ip_api.show_ip_route(data.dut2, family="ipv6", shell="sonic", vrf_name=data.vrf_name[2])
    if not loc_lib.verify_bgp(ve='1', ip='ipv4'):
        err = st.banner('STEP 1 FAIL: IPv4 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 1 PASS: IPv4 BGP session on VRF-102 came up')
    if not loc_lib.verify_bgp(ve='1', ip='ipv6'):
        err = st.banner('STEP 2 FAIL: IPv6 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 2 PASS: IPv6 BGP session on VRF-102 came up')
    if not loc_lib.verify_bgp(pc='1', ip='ipv4'):
        err = st.banner('STEP 3 FAIL: IPv4 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 3 PASS: IPv4 BGP session on VRF-103 came up')
    if not loc_lib.verify_bgp(pc='1', ip='ipv6'):
        err = st.banner('STEP 4 FAIL: IPv6 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 4 PASS: IPv6 BGP session on VRF-103 came up')

    if err_list:
        err = st.banner('Static route between VRFs failed for VRf-101, VRF-102 and VRF-103')
        err_list.insert(0, err)
        loc_lib.debug_bgp_vrf()

    return st.report_result(err_list)


# @pytest.mark.depends('test_VrfFun001_06')
@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfCli005'])
@pytest.mark.inventory(testcases=['FtOpSoRoVrfFun050'])
def test_VrfFun_05_50():

    st.log('######################################################################################################################')
    st.log('FtRtVrfFun005 Configure overlapping IP addresses belonging to different VRFs ')
    st.log('FtRtVrfFun050 Verify non-default vrf after cold reboot ')
    st.log('#######################################################################################################################')

    err_list = []
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve='1', ip='ipv4'):
        err = st.banner('STEP 1 FAIL: IPv4 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 1 PASS: IPv4 BGP session on VRF-102 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve='1', ip='ipv6'):
        err = st.banner('STEP 2 FAIL: IPv6 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 2 PASS: IPv6 BGP session on VRF-102 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc='1', ip='ipv4'):
        err = st.banner('STEP 3 FAIL: IPv4 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 3 PASS: IPv4 BGP session on VRF-103 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc='1', ip='ipv6'):
        err = st.banner('STEP 4 FAIL: IPv6 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 4 PASS: IPv6 BGP session on VRF-103 came up')
    reboot_api.config_save(data.dut1)
    reboot_api.config_save(data.dut1, shell='vtysh')
    st.reboot(data.dut1, 'fast')
    st.wait(40, "Waiting for the sessions to come up")
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve='1', ip='ipv4'):
        err = st.banner('STEP 5 FAIL: IPv4 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 5 PASS: IPv4 BGP session on VRF-102 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve='1', ip='ipv6'):
        err = st.banner('STEP 6 FAIL: IPv6 BGP session on VRF-102 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 6 PASS: IPv6 BGP session on VRF-102 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc='1', ip='ipv4'):
        err = st.banner('STEP 7 FAIL: IPv4 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 7 PASS: IPv4 BGP session on VRF-103 came up')
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc='1', ip='ipv6'):
        err = st.banner('STEP 8 FAIL: IPv6 BGP session on VRF-103 did not come up')
        err_list.append(err)
    else:
        st.banner('STEP 8 PASS: IPv6 BGP session on VRF-103 came up')

    if err_list:
        err = st.banner('Save and reload with VRF configuration failed')
        err_list.insert(0, err)
        loc_lib.debug_bgp_vrf()

    return st.report_result(err_list)
