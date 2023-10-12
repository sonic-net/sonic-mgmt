##############################################################################
# Script Title : VRF Lite scale
# Author       : Manisha Joshi
# Mail-id      : manisha.joshi@broadcom.com
###############################################################################

import pytest
import os
import ipaddress

from spytest import st, utils, tgapi
from spytest.tgen.tg import tgen_obj_dict

from vrf_vars import data
import vrf_lib as loc_lib

import apis.switching.mac as mac_api
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.routing.vrf as vrf_api
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
import apis.system.port as port_api
import apis.system.reboot as reboot_api
import apis.system.basic as basic_obj

from utilities import parallel

plat_name1 = ''
plat_name2 = ''
max_vrfs = ''
config_db_dut1 = ''
config_db_dut2 = ''
static_lower = ''
static_upper = ''
bgp_vrfs_start = ''
bgp_vrfs_end = ''
vrf_list = []


def initialize_topology():
    st.banner("Initialize variables")
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2", "D2T1:2")
    global plat_name1
    global plat_name2
    global max_vrfs
    global config_db_dut1
    global config_db_dut2
    global static_lower
    global static_upper
    global bgp_vrfs_start
    global bgp_vrfs_end
    global vrf_list
    plat_name1 = basic_obj.get_hwsku(vars.D1)
    plat_name2 = basic_obj.get_hwsku(vars.D2)
    st.banner("plat_name1 ======> {} & plat_name2 ======> {}".format(plat_name1, plat_name2))
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    utils.exec_all(True, [[bgp_api.enable_docker_routing_config_mode, data.dut1], [bgp_api.enable_docker_routing_config_mode, data.dut2]])
    data.d1_dut_ports = [vars.D1D2P1]
    data.d2_dut_ports = [vars.D2D1P1]
    data.dut1_tg1_ports = [vars.D1T1P1]
    data.dut2_tg1_ports = [vars.D2T1P1]
    data.tg_dut1_hw_port = vars.T1D1P1
    data.tg_dut2_hw_port = vars.T1D2P1
    data.tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg_dut1_p1 = data.tg1.get_port_handle(vars.T1D1P1)
    data.tg_dut2_p1 = data.tg2.get_port_handle(vars.T1D2P1)
    if "AS9716" in plat_name1 or "AS9716" in plat_name2 or "Z9432f" in plat_name1 or "Z9432f" in plat_name2 or "Z9664f" in plat_name1 or "Z9664f" in plat_name2:
        max_vrfs = 512
        static_lower = 200
        static_upper = 411
        bgp_vrfs_start = 411
        bgp_vrfs_end = 512
        config_db_dut1 = 'vrf_scale_dut1_TH3_as9716.json'
        config_db_dut2 = 'vrf_scale_dut2_TH3_as9716.json'
    elif basic_obj.is_campus_build(vars.D1) or basic_obj.is_campus_build(vars.D2):
        max_vrfs = 32
        static_lower = 12
        static_upper = 25
        bgp_vrfs_start = 25
        bgp_vrfs_end = 32
        config_db_dut1 = 'vrf_scale_dut1_campus.json'
        config_db_dut2 = 'vrf_scale_dut2_campus.json'
    else:
        max_vrfs = 1000
        static_lower = 425
        static_upper = 899
        bgp_vrfs_start = 899
        bgp_vrfs_end = 1000
        config_db_dut1 = 'vrf_scale_dut1.json'
        config_db_dut2 = 'vrf_scale_dut2.json'
    st.banner("max_vrfs ======> {}, static_lower ======> {}, static_upper ======> {}".format(max_vrfs, static_lower, static_upper))
    st.banner("config_db_dut1 ======> {}, config_db_dut2 ======> {}".format(config_db_dut1, config_db_dut2))
    data.d1_p1_intf_v4 = {}
    data.d1_p1_intf_v6 = {}
    data.d2_p1_intf_v4 = {}
    data.d2_p1_intf_v6 = {}
    data.stream_list_scale = {}
    data.stream = []
    dut1_dut2_vlan_scale = ['%s' % x for x in range(1, max_vrfs)]
    vrf_list = ['Vrf-' + '%s' % x for x in range(1, max_vrfs)]
    data.dut1_dut2_ip_list = ip_range('5.0.0.1', 2, max_vrfs)
    data.dut2_dut1_ip_list = ip_range('5.0.0.2', 2, max_vrfs)
    data.dut1_tg_host = '6.0.0.1'
    data.tg_dut1_host = '6.0.0.2'
    data.dut2_tg_host = '7.0.0.1'
    data.tg_dut2_host = '7.0.0.2'
    data.tg_dut1_stream_start = ip_range('6.0.0.3', 3, max_vrfs)
    data.tg_dut2_stream_start = ip_range('7.0.0.3', 3, max_vrfs)
    data.intf_list = []
    for vlan in dut1_dut2_vlan_scale:
        data.intf_list.append('Vlan' + vlan)


@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue():
    initialize_topology()
    base_config()
    yield


def base_config():
    st.banner('Base config STEP 1: Taking backup for unconfig')
    src_path = "/etc/sonic/config_db.json"
    dst_path = "/etc/sonic/default.json"
    utils.exec_all(True, [[basic_obj.copy_file_to_local_path, data.dut1, src_path, dst_path], [basic_obj.copy_file_to_local_path, data.dut2, src_path, dst_path]])

    st.banner('Base config STEP 2: Loading json file with vrf and IP address config')
    st.banner("config_db_dut1======> {} & config_db_dut2======> {}".format(config_db_dut1, config_db_dut2))
    curr_path = os.getcwd()
    json_file_dut1 = curr_path + "/routing/VRF/" + config_db_dut1
    st.apply_files(data.dut1, [json_file_dut1])

    json_file_dut2 = curr_path + "/routing/VRF/" + config_db_dut2
    st.apply_files(data.dut2, [json_file_dut2])

    utils.exec_all(True, [[st.apply_files, data.dut1, [json_file_dut1]], [st.apply_files, data.dut2, [json_file_dut2]]])

    st.banner('Base config STEP 3: Configure vlans and add members')
    utils.exec_all(True, [[vlan_api.config_vlan_range, data.dut1, '1 {}'.format(max_vrfs - 1), 'add'], [vlan_api.config_vlan_range, data.dut2, '1 {}'.format(max_vrfs - 1), 'add']])
    utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut1, '1 {}'.format(max_vrfs - 1), data.d1_dut_ports[0], 'add'], [vlan_api.config_vlan_range_members, data.dut2, '1 {}'.format(max_vrfs - 1), data.d2_dut_ports[0], 'add']])

    st.banner('Base config STEP 4: Configure IP on DUT--TG interface')
    utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.dut1_tg1_ports[0], data.dut1_tg_host, '16', 'ipv4'], [ip_api.config_ip_addr_interface, data.dut2, data.dut2_tg1_ports[0], data.dut2_tg_host, '16', 'ipv4']])

    st.banner('Base config STEP 5: Configure TG end hosts and get the DUT1 interface MAC')
    host_config()
    gateway_mac = mac_api.get_sbin_intf_mac(data.dut1, data.dut1_tg1_ports[0])

    st.banner('Base config STEP 6: Create traffic streams for all VRFs')
    send_rate_pps = tgapi.normalize_pps(1000)
    data.stream = data.tg1.tg_traffic_config(port_handle=data.tg_dut1_p1, mode='create', duration='5', transmit_mode='continuous', length_mode='fixed', port_handle2=data.tg_dut2_p1, rate_pps=send_rate_pps, mac_src='00.00.00.11.12.53', mac_dst=gateway_mac, ip_src_addr=data.tg_dut1_stream_start[0], ip_dst_addr=data.tg_dut2_stream_start[0], l3_protocol='ipv4', ip_src_mode='increment', ip_src_count=max_vrfs, ip_src_step='0.0.0.1')
    data.stream_list_scale.update({'pc_v4_stream': data.stream['stream_id']})

    st.wait(30, "Waiting for 30 sec after TG traffic config")


def base_unconfig():
    st.banner("base_unconfig STEP 1: Unconfigure static routes on {} VRFs".format(max_vrfs - 100))
    for vrf, dut1_as, dut2_as in zip(vrf_list[bgp_vrfs_start:bgp_vrfs_end], data.dut1_as_scale[0:100], data.dut2_as_scale[0:100]):
        dict1 = {'vrf_name': vrf, 'local_as': dut1_as, 'config': 'no', 'removeBGP': 'yes', 'config_type_list': ['removeBGP']}
        dict2 = {'vrf_name': vrf, 'local_as': dut2_as, 'config': 'no', 'removeBGP': 'yes', 'config_type_list': ['removeBGP']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    st.banner("base_unconfig STEP 2: Unconfigure static routes on {} VRFs".format(max_vrfs - 100))
    dict1 = {'dest_list': data.tg_dut2_stream_start[0:static_lower], 'next_hop_list': data.dut2_dut1_ip_list[0:static_lower], 'vrf_list': vrf_list[0:static_lower], 'config': 'no'}
    dict2 = {'dest_list': data.tg_dut2_stream_start[0:static_lower], 'vrf_list': vrf_list[0:static_lower], 'config': 'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_static_route, [dict1, dict2])

    st.wait(30, "Waiting for 30 sec after unconfiguring of static route")

    st.banner('base_unconfig STEP 3: UnConfigure IP on DUT--TG interface')
    utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.dut1_tg1_ports[0], data.dut1_tg_host, '16', 'ipv4', 'remove'], [ip_api.config_ip_addr_interface, data.dut2, data.dut2_tg1_ports[0], data.dut2_tg_host, '16', 'ipv4', 'remove']])

    dict1 = {'dest_list': data.tg_dut2_stream_start[static_lower:static_upper], 'next_hop_list': data.dut2_dut1_ip_list[static_lower:static_upper], 'vrf_list': vrf_list[static_lower:static_upper], 'config': 'no'}
    dict2 = {'dest_list': data.tg_dut2_stream_start[static_lower:static_upper], 'vrf_list': vrf_list[static_lower:static_upper], 'config': 'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_static_route, [dict1, dict2])

    st.wait(30, "Waiting for 30 sec after unconfiguring of IP on DUT--TG interface")

    st.banner('base_unconfig STEP 4: Laoding back the config_db file')
    src_path = "/etc/sonic/default.json"
    dst_path = "/etc/sonic/config_db.json"
    utils.exec_all(True, [[basic_obj.copy_file_to_local_path, data.dut1, src_path, dst_path], [basic_obj.copy_file_to_local_path, data.dut2, src_path, dst_path]])
    utils.exec_all(True, [[st.reboot, data.dut1, 'fast'], [st.reboot, data.dut2, 'fast']])

    st.banner('base_unconfig STEP 4: Started TG end host config')
    host_config(config='no')


@pytest.fixture(scope="function")
def vrf_fixture_vrf_scale(request, prologue_epilogue):
    yield
    st.banner('Started UnConfig ')


@pytest.mark.inventory(feature='L3 Scale and Performance', release='Arlo+')
@pytest.mark.inventory(feature='VRF-Lite', testcases=['FtOpSoRoVrfFun052'])
@pytest.mark.inventory(testcases=['FtRtPerfFn023'])
@pytest.mark.inventory(testcases=['FtRtPerfFn024'])
def test_vrf_scale(vrf_fixture_vrf_scale):
    result = 0

    if not vrf_api.verify_vrf(data.dut2, vrfname=vrf_list):
        st.banner('STEP 1 FAIL: VRF creation failed on DUT2')
        result += 1
    else:
        st.banner('STEP 1 PASS: VRF creation done on DUT2')

    st.banner('Flap the underlying interface and reverify the VRF')
    port_api.shutdown(data.dut1, data.d1_dut_ports)
    port_api.noshutdown(data.dut1, data.d1_dut_ports)

    st.wait(5, "Waiting for 5 sec after flapping the underlying interface")

    if not vrf_api.verify_vrf(data.dut1, vrfname=vrf_list):
        st.banner('STP 2 FAIL: Binding of VRF to interfaces failed on DUT1')
        result += 1
    else:
        st.banner('STEP 2 PASS: Binding of VRF to interfaces done on DUT1')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('STEP 3 Test Case: Interface binding failed for 1000 VRFs')
        st.report_fail('test_case_failed')


@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfScl057'])
def test_vrf_route_leak():
    result = 0

    st.banner("STEP 1: Configure static routes on {} VRFs for lower subnets".format(max_vrfs - 100))
    dict1 = {'dest_list': data.tg_dut2_stream_start[0:static_lower], 'next_hop_list': data.dut2_dut1_ip_list[0:static_lower], 'vrf_list': vrf_list[0:static_lower]}
    dict2 = {'dest_list': data.tg_dut2_stream_start[0:static_lower], 'vrf_list': vrf_list[0:static_lower]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_static_route, [dict1, dict2])
    st.wait(30, "Waiting for 30 sec after static route config for lower subnet")

    st.banner("STEP 2: Configure static routes on {} VRFs for lower to upper subnet".format(max_vrfs - 100))
    dict1 = {'dest_list': data.tg_dut2_stream_start[static_lower:static_upper], 'next_hop_list': data.dut2_dut1_ip_list[static_lower:static_upper], 'vrf_list': vrf_list[static_lower:static_upper]}
    dict2 = {'dest_list': data.tg_dut2_stream_start[static_lower:static_upper], 'vrf_list': vrf_list[static_lower:static_upper]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_static_route, [dict1, dict2])
    st.wait(30, "Waiting for 30 sec after static route config for lower to upper subnet")

    st.banner('STEP 3: Clear the TG port counters and start the traffic')
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action='run', stream_handle=data.stream_list_scale.values(), duration=5)

    traffic_details = {'1': {'tx_ports': [data.tg_dut1_hw_port], 'tx_obj': [data.tg1], 'exp_ratio': [1], 'rx_ports': [data.tg_dut2_hw_port], 'rx_obj': [data.tg2]}}
    st.banner('STEP 4: Stop the traffic from TG end')
    data.tg2.tg_traffic_control(action='stop', stream_handle=data.stream_list_scale.values())

    st.banner('STEP 5: Validate the aggregate traffic result from TG end to end')
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    if not aggrResult:
        st.banner("STEP 5 FAIL: IPv4 Traffic on {} VRF with route leak failed".format(max_vrfs))
    else:
        st.banner("STEP 5 PASS: IPv4 Traffic on {} VRF with route leak PASSED".format(max_vrfs))

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('STEP 6 Test Case: Traffic on VRF with static route leak failed')
        st.report_fail('test_case_failed')


@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfScl056'])
def test_vrf_bgp():
    result = 0
    vrfs_total = bgp_vrfs_end - bgp_vrfs_start

    st.banner('STEP 1: Configure BGP on {} VRFs'.format(vrfs_total))
    for vrf, dut1_ip, dut2_ip, dut1_as, dut2_as in zip(vrf_list[bgp_vrfs_start:bgp_vrfs_end], data.dut1_dut2_ip_list[bgp_vrfs_start:bgp_vrfs_end], data.dut2_dut1_ip_list[bgp_vrfs_start:bgp_vrfs_end], data.dut1_as_scale[0:100], data.dut2_as_scale[0:100]):
        dict1 = {'vrf_name': vrf, 'router_id': data.dut1_router_id, 'local_as': dut1_as, 'neighbor': dut2_ip, 'remote_as': dut2_as, 'config_type_list': ['neighbor']}
        dict2 = {'vrf_name': vrf, 'router_id': data.dut2_router_id, 'local_as': dut2_as, 'neighbor': dut1_ip, 'remote_as': dut1_as, 'config_type_list': ['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
        dict1 = {'vrf_name': vrf, 'local_as': dut1_as, 'neighbor': dut2_ip, 'remote_as': dut2_as, 'connect': '3', 'config_type_list': ['activate', 'nexthop_self', 'connect']}
        dict2 = {'vrf_name': vrf, 'local_as': dut2_as, 'neighbor': dut1_ip, 'remote_as': dut1_as, 'connect': '3', 'config_type_list': ['activate', 'nexthop_self', 'connect']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    st.banner('STEP 2: Verify the BGP neighbors have come up')
    if not st.poll_wait(ip_bgp.verify_bgp_neighbor, 60, data.dut1, neighborip=data.dut2_dut1_ip_list[bgp_vrfs_start], state='Established', vrf=vrf_list[bgp_vrfs_start]):
        st.banner("STEP 2 FAIL: IPv4 BGP session on {} did not come up".format(bgp_vrfs_start))
        result += 1
    else:
        st.banner("STEP 2 PASS: IPv4 BGP session on {} came up".format(bgp_vrfs_start))

    if not st.poll_wait(ip_bgp.verify_bgp_neighbor, 60, data.dut1, neighborip=data.dut2_dut1_ip_list[bgp_vrfs_end - 4], state='Established', vrf=vrf_list[bgp_vrfs_end - 4]):
        st.banner("STEP 3 FAIL: IPv4 BGP session on {} did not come up".format(bgp_vrfs_end - 4))
        result += 1
    else:
        st.banner("STEP 3 PASS: IPv4 BGP session on {} came up".format(bgp_vrfs_end - 4))

    st.banner('STEP 4: Clear BGP and reverify')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_list[bgp_vrfs_start], family='ipv4')

    st.wait(10, "Waiting for 10 sec for BGP to come up after clear BGP route")

    st.banner('STEP 5: Verify BGP neighbor session')
    if not st.poll_wait(ip_bgp.verify_bgp_neighbor, 60, data.dut1, neighborip=data.dut2_dut1_ip_list[bgp_vrfs_start], state='Established', vrf=vrf_list[bgp_vrfs_start]):
        st.banner("STEP 5 FAIL: IPv4 BGP session on {} did not come up".format(bgp_vrfs_start))
        result += 1
    else:
        st.banner("STEP 5 PASS : IPv4 BGP session on {} came up".format(bgp_vrfs_start))

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('STEP 6 Test case: BGP neighborship on {} VRFs failed'.format(vrfs_total))
        st.report_fail('test_case_failed')


@pytest.mark.inventory(feature='VRF-Lite', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRoVrfScl058'])
def test_vrf_reload():
    result = 0
    st.banner('Save the config in DUT 1')
    reboot_api.config_save(data.dut1)
    st.vtysh(data.dut1, "copy running startup")

    st.banner('Trigger Fast reboot of DUT 1')
    st.reboot(data.dut1, 'fast')

    if not vrf_api.verify_vrf(data.dut1, vrfname=vrf_list):
        st.banner('STEP 1 FAIL: Binding of VRF to interfaces failed on DUT1')
        result += 1
    else:
        st.banner('STEP 1 PASS: Binding of VRF to interfaces passed on DUT1')

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.banner('STEP 2 Test case: Save and reload with VRF configuration failed')
        st.report_fail('test_case_failed')


def ipaddresslist():
    st.banner('Generate 1000 IPs between the DUTs')
    start = ipaddress.IPv4Address(u'1.1.1.1')
    end = ipaddress.IPv4Address(u'1.1.4.231')
    ipaddress_list = [start]
    temp = start
    while temp != end:
        temp += 1
        ipaddress_list.append(temp)

    return ipaddress_list


def ip_incr(ip, octet):
    ip_list = ip.split(".")
    ip_list[octet] = str(int(ip_list[octet]) + 1)
    return '.'.join(ip_list)


def ip_range(ip, octet, scl):
    ip_list = [ip]
    ip2 = ip
    i = 1
    j = int(ip.split(".")[octet])
    while i < scl:
        if j == 255:
            ip = ip_incr(ip, octet - 1)
            j = int(ip.split(".")[octet])
            ip2 = ip
            ip_list.append(ip2)
            i += 1
        else:
            ip2 = ip_incr(ip2, octet)
            ip_list.append(ip2)
            i += 1
            j += 1
    return ip_list


def vrf_static_route(dut, **kwargs):
    config = kwargs.get('config', '')
    next_hop_list = kwargs.get('next_hop_list', [])
    vrf_list = kwargs.get('vrf_list', [])
    dest_list = kwargs.get('dest_list', [])
    my_cmd = ''
    if dut == data.dut1:
        st.banner('vrf_static_route lib STEP: Configure static route leak across VRF in DUT1')
        for dest, vrf, next_hop in zip(dest_list, vrf_list, next_hop_list):
            my_cmd += '{} ip route {}/32 {} nexthop-vrf {} \n'.format(config, dest, next_hop, vrf)
    if dut == data.dut2:
        st.banner('vrf_static_route lib STEP: Configure static route leak across VRF in DUT2')
        for dest, vrf in zip(dest_list, vrf_list):
            my_cmd += '{} ip route {}/32 7.0.0.2 nexthop-vrf default vrf {} \n'.format(config, dest, vrf)
    st.vtysh_config(dut, my_cmd)
    return True


def host_config(**kwargs):
    config = kwargs.get('config', 'yes')
    if config.lower() == 'yes':
        st.banner('host_config lib STEP: Configure host on TG for DUT1 and DUT2')
        intf_hand_v4 = data.tg1.tg_interface_config(port_handle=data.tg_dut1_p1, mode='config', intf_ip_addr=data.tg_dut1_host, gateway=data.dut1_tg_host, netmask='255.255.0.0', arp_send_req='1')
        data.d1_p1_intf_v4.update({data.tg_dut1_host: intf_hand_v4})
        intf_hand_v4 = data.tg2.tg_interface_config(port_handle=data.tg_dut2_p1, mode='config', intf_ip_addr=data.tg_dut2_host, gateway=data.dut2_tg_host, netmask='255.255.0.0', arp_send_req='1')
        data.d2_p1_intf_v4.update({data.tg_dut2_host: intf_hand_v4})
    else:
        st.banner('host_config lib STEP: Remove host on TG for DUT1 and DUT2')
        data.tg1.tg_interface_config(port_handle=data.tg_dut1_p1, handle=data.d1_p1_intf_v4.get(data.tg_dut1_host)['handle'], mode='destroy')
        data.tg1.tg_interface_config(port_handle=data.tg_dut2_p1, handle=data.d2_p1_intf_v4.get(data.tg_dut2_host)['handle'], mode='destroy')
