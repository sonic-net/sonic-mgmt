import re, os

from spytest import st, putils
import apis.system.basic as basic_obj
import utilities.utils as util_obj
import apis.switching.vlan as vlan_obj
import apis.routing.ip as ip_obj
import apis.routing.bgp as bgp_obj
import apis.routing.vrf as vrf_obj
import apis.switching.portchannel as pc_obj

from chef_evpn_vars import data, chef_server
import apis.system.chef_evpn as chef_evpn_obj

def verify_ping():
    def f1():
        ping_res = ip_obj.ping(data.d1, data.lbk_ip_list[1][0], timeout=7)
        return ping_res
    def f2():
        ping_res = ip_obj.ping(data.d2, data.lbk_ip_list[2][0], timeout=7)
        return ping_res
    def f3():
        ping_res = ip_obj.ping(data.d3, data.lbk_ip_list[3][0], timeout=7)
        return ping_res
    [res, _] = putils.exec_all(True, [[f1], [f2], [f3]])
    if res[0] and res[1] and res[2]:
        return True
    return False


def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
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

def print_debug():
    def f1():
        pc_obj.verify_portchannel(data.d1, data.d1_d4_pc_1)
        ip_obj.ping(data.d1, data.d2_d1_vlan_1_ip)
        ip_obj.ping(data.d1, data.d4_d1_pc_1_ip)
    def f2():
        pc_obj.verify_portchannel(data.d2, data.d2_d3_pc_1)
        ip_obj.ping(data.d3, data.d4_d3_intf_1_ip)
        ip_obj.ping(data.d3, data.d4_d3_vlan_1_ip)
        ip_obj.ping(data.d3, data.d3_d3_pc_1_ip)
    def f3():
        pc_obj.verify_portchannel(data.d3, data.d3_d2_pc_1)
    def f4():
        pc_obj.verify_portchannel(data.d4, data.d4_d1_pc_1)

    putils.exec_all(True, [[f1], [f2], [f3], [f4]])



def bgp_unconfig():
        dict1 = {'config':'no','local_as': data.d1_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'config':'no','local_as': data.d2_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict3 = {'config':'no','local_as': data.d3_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict4 = {'config':'no','local_as': data.d4_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        putils.exec_parallel(True, [data.d1, data.d2, data.d3, data.d4], bgp_obj.config_bgp, [dict1, dict2, dict3, dict4])

        dict5 = {'config':'no','local_as': data.d1_as,'removeBGP':'yes','config_type_list':['removeBGP'],'vrf_name':'Vrf-01'}
        dict6 = {'config':'no','local_as': data.d2_as,'removeBGP':'yes','config_type_list':['removeBGP'],'vrf_name':'Vrf-01'}
        putils.exec_parallel(True, [data.d1, data.d2], bgp_obj.config_bgp, [dict5, dict6])

def ip_unconfig():
    def f1():
        ip_obj.config_ip_addr_interface(data.d1, data.d1_d2_intf_1, data.d1_d2_intf_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d1, 'Vlan121', data.d1_d2_vlan_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d1, data.d1_d4_pc_1, data.d1_d4_pc_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d1, data.d1_d2_intf_1, data.d1_d2_intf_1_ip6, data.def_mask_ip6, 'ipv6',config='remove')
        ip_obj.config_ip_addr_interface(data.d1, 'Loopback1', '1.1.1.1', '32', 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d1, 'Loopback2', '1.1.1.2', '32', 'ipv4',config='remove')
    def f2():
        ip_obj.config_ip_addr_interface(data.d2, data.d2_d1_intf_1, data.d2_d1_intf_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d2, 'Vlan121', data.d2_d1_vlan_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d2, data.d2_d3_pc_1, data.d2_d3_pc_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d2, data.d2_d1_intf_1, data.d2_d1_intf_1_ip6, data.def_mask_ip6, 'ipv6',config='remove')
        ip_obj.config_ip_addr_interface(data.d2, 'Loopback1', '2.2.2.1', '32', 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d2, 'Loopback2', '2.2.2.2', '32', 'ipv4',config='remove')
    def f3():
        ip_obj.config_ip_addr_interface(data.d3, data.d3_d4_intf_1, data.d3_d4_intf_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d3, 'Vlan343', data.d3_d4_vlan_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d3, data.d3_d2_pc_1, data.d3_d2_pc_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        #ip_obj.config_ip_addr_interface(data.d3, data.d3_d4_intf_1, data.d3_d4_intf_1_ip6, data.def_mask_ip6, 'ipv6',config='remove')
        ip_obj.config_ip_addr_interface(data.d3, 'Loopback1', '3.3.3.1', '32', 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d3, 'Loopback2', '3.3.3.2', '32', 'ipv4',config='remove')
    def f4():
        ip_obj.config_ip_addr_interface(data.d4, data.d4_d3_intf_1, data.d4_d3_intf_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d4, 'Vlan343', data.d4_d3_vlan_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d4, data.d4_d1_pc_1, data.d4_d1_pc_1_ip, data.def_mask_ip, 'ipv4',config='remove')
        #ip_obj.config_ip_addr_interface(data.d4, data.d4_d3_intf_1, data.d4_d3_intf_1_ip6, data.def_mask_ip6, 'ipv6',config='remove')
        ip_obj.config_ip_addr_interface(data.d4, 'Loopback1', '4.4.4.1', '32', 'ipv4',config='remove')
        ip_obj.config_ip_addr_interface(data.d4, 'Loopback2', '4.4.4.2', '32', 'ipv4',config='remove')

    putils.exec_all(True, [[f1], [f2], [f3], [f4]])

def portchannel_unconfig():
    def f1():
        pc_obj.add_del_portchannel_member(data.d1, data.d1_d4_pc_1, data.d1_d4_intf_1, 'del')
        pc_obj.add_del_portchannel_member(data.d1, data.d1_d4_pc_1, data.d1_d4_intf_2, 'del')
        pc_obj.delete_portchannel(data.d1, data.d1_d4_pc_1)

    def f2():
        pc_obj.add_del_portchannel_member(data.d2, data.d2_d3_pc_1, data.d2_d3_intf_1, 'del')
        pc_obj.add_del_portchannel_member(data.d2, data.d2_d3_pc_1, data.d2_d3_intf_2, 'del')
        pc_obj.delete_portchannel(data.d2, data.d2_d3_pc_1)

    def f3():
        pc_obj.add_del_portchannel_member(data.d3, data.d3_d2_pc_1, data.d3_d2_intf_1, 'del')
        pc_obj.add_del_portchannel_member(data.d3, data.d3_d2_pc_1, data.d3_d2_intf_2, 'del')
        pc_obj.delete_portchannel(data.d3, data.d3_d2_pc_1)

    def f4():
        pc_obj.add_del_portchannel_member(data.d4, data.d4_d1_pc_1, data.d4_d1_intf_1, 'del')
        pc_obj.add_del_portchannel_member(data.d4, data.d4_d1_pc_1, data.d4_d1_intf_2, 'del')
        pc_obj.delete_portchannel(data.d4, data.d4_d1_pc_1)

    putils.exec_all(True, [[f1], [f2], [f3], [f4]])

def vlan_unconfig():
    def f1():
        vlan_obj.delete_vlan_member(data.d1,'121',data.d1_d2_intf_2)
        vlan_obj.delete_vlan(data.d1, '121')
    def f2():
        vlan_obj.delete_vlan_member(data.d2,'121',data.d2_d1_intf_2)
        vlan_obj.delete_vlan(data.d2, '121')
    def f3():
        vlan_obj.delete_vlan_member(data.d3,'343',data.d3_d4_intf_2)
        vlan_obj.delete_vlan(data.d3, '343')
    def f4():
        vlan_obj.delete_vlan_member(data.d4,'343',data.d4_d3_intf_2)
        vlan_obj.delete_vlan(data.d4, '343')

    putils.exec_all(True, [[f1], [f2], [f3], [f4]])

def static_route_unconfig():
    def f1():
        ip_obj.delete_static_route(data.d1, data.d2_d1_intf_1_ip, '2.2.2.0/30', family='ipv4', shell="vtysh")
        ip_obj.delete_static_route(data.d1, data.d2_d1_vlan_1_ip, '2.2.2.0/30', family='ipv4', shell="vtysh")
        ip_obj.delete_static_route(data.d1, data.d4_d1_pc_1_ip, '4.4.4.0/30', family='ipv4', shell="vtysh")
    def f2():
        ip_obj.delete_static_route(data.d2, data.d1_d2_intf_1_ip, '1.1.1.0/30', family='ipv4', shell="vtysh")
        ip_obj.delete_static_route(data.d2, data.d1_d2_vlan_1_ip, '1.1.1.0/30', family='ipv4', shell="vtysh")
        ip_obj.delete_static_route(data.d2, data.d3_d2_pc_1_ip, '3.3.3.0/30', family='ipv4', shell="vtysh")
    def f3():
        ip_obj.delete_static_route(data.d3, data.d3_d4_intf_1_ip, '4.4.4.0/30', family='ipv4', shell="vtysh")
        ip_obj.delete_static_route(data.d3, data.d3_d4_vlan_1_ip, '4.4.4.0/30', family='ipv4', shell="vtysh")
        ip_obj.delete_static_route(data.d3, data.d2_d3_pc_1_ip, '2.2.2.0/30', family='ipv4', shell="vtysh")
    def f4():
        ip_obj.delete_static_route(data.d4, data.d4_d3_intf_1_ip, '3.3.3.0/30', family='ipv4', shell="vtysh")
        ip_obj.delete_static_route(data.d4, data.d4_d3_vlan_1_ip, '3.3.3.0/30', family='ipv4', shell="vtysh")
        ip_obj.delete_static_route(data.d4, data.d1_d4_pc_1_ip, '1.1.1.0/30', family='ipv4', shell="vtysh")

    putils.exec_all(True, [[f1], [f2], [f3], [f4]])

def vrf_unconfig():
    vrf_obj.config_vrf(data.d1, config='no', vrf_name= 'Vrf-01', skip_error=True)
    vrf_obj.config_vrf(data.d2, config='no', vrf_name= 'Vrf-01', skip_error=True)


def get_dut_ip(dut):
    chef_server.mgmt_intf = util_obj.ensure_service_params(dut, chef_server.name, "mgmt_intf")
    ip_addr = basic_obj.get_ifconfig_inet(dut, chef_server.mgmt_intf)
    if not ip_addr:
        st.log("IP Address not found on eth0")
        st.report_env_fail("test_case_not_executeds")
    return ip_addr[0]


def chef_pre_config(dut, dut_ip):
    st.log("Installing CHEF on the Sonic device")
    basic_obj.deploy_package(dut, mode='update')
    basic_obj.deploy_package(dut, packane_name='sshpass', mode='install')
    if not chef_evpn_obj.chef_package_install(dut, chef_server.url, dut_ip, 'admin', 'broadcom', 'YourPaSsWoRd'):
        st.report_env_fail("test_case_not_executeds")
    st.log("Done Installing the dependents packages if not installed.")

    '''
    if not chef_evpn_obj.sync_with_server_time(dut, chef_server.ip, chef_server.username, chef_server.password):
        st.report_env_fail("test_case_not_executeds")
    '''

def copy_role_file_to_chef_server(file_name):
    data.cur_file_name = os.path.join(data.role_path, file_name)
    chef_server.cur_file_name = os.path.join(chef_server.role_dir, file_name)
    chef_evpn_obj.copy_files_to_server(chef_server.ip, chef_server.username, chef_server.password,data.cur_file_name)
    tmp_src_file = os.path.join(chef_server.user_home_folder,file_name)
    chef_evpn_obj.config_chef(chef_server.ssh_obj, action='copy_files', src_file=tmp_src_file, dst_file=chef_server.role_dir)
    st.log('Copied file {} to {}'.format(data.cur_file_name, chef_server.role_dir))

def modify_role_file(file_name):
    new_file_name = re.sub(r'tmpl','new',file_name)
    file_name = os.path.join(data.role_path,file_name)
    fin = open(os.path.join(data.role_path,file_name), 'r')
    fout = open(os.path.join(data.role_path,new_file_name), 'w')
    file_data = fin.readlines()
    for line in file_data:

        for var,value in zip(['D1D2P1', 'D2D1P1', 'D1D2P2', 'D2D1P2', 'D1D4P1', 'D4D1P1', 'D1D4P2', 'D4D1P2', 'D3D4P1', 'D4D3P1', 'D3D4P2', 'D4D3P2', 'D3D2P1', 'D2D3P1', 'D3D2P2', 'D2D3P2'],[data.d1_d2_intf_1, data.d2_d1_intf_1, data.d1_d2_intf_2, data.d2_d1_intf_2, data.d1_d4_intf_1, data.d4_d1_intf_1, data.d1_d4_intf_2, data.d4_d1_intf_2, data.d3_d4_intf_1, data.d4_d3_intf_1, data.d3_d4_intf_2, data.d4_d3_intf_2, data.d3_d2_intf_1, data.d2_d3_intf_1, data.d3_d2_intf_2, data.d2_d3_intf_2]):

            if var in line:
                line = re.sub(r'{}'.format(var),value,line)

        fout.write(line)

    fin.close()
    fout.close()
    return new_file_name


