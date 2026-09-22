import pytest

from spytest import st
from spytest.dicts import SpyTestDict

import utilities.common as utils

import apis.routing.ip as ip_obj
import apis.routing.nat as nat_obj
import apis.system.basic as basic_obj

dut = dict()

data = SpyTestDict()
data.d1d2_ip_addr = "44.44.44.1"
data.d2d1_ip_addr = "44.44.44.2"
data.d2d3_ip_addr = "12.12.12.1"
data.d3d2_ip_addr = "12.12.12.2"
data.ip_addr_mask = "24"
data.d1_static_nw = "12.12.12.0"
data.d3_static_nw = "44.44.44.0"
data.zone_1 = "0"
data.zone_2 = "1"
data.proto_all = "all"
data.proto_tcp = "tcp"
data.proto_udp = "udp"
data.pool_name = ["pool_tr"]
data.bind_name = ["bind_tr"]
data.global_port_range = "2000-2002"
data.global_port = ["2000","2001","2002"]
data.af_ipv4 = "ipv4"
data.shell_sonic = "sonic"
data.shell_vtysh = "vtysh"
data.config_add='add'
data.config_del='del'

@pytest.fixture(scope="module", autouse=True)
def nat_module_config(request):
    nat_pre_config()
    yield
    nat_post_config()


@pytest.fixture(scope="function")
def cmds_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield

def nat_pre_config():
    global vars
    vars = st.ensure_min_topology("D1D2:1", "D2D3:1")
    platform = basic_obj.get_hwsku(vars.D2)
    common_constants = st.get_datastore(vars.D2, "constants", "default")
    if platform.lower() in common_constants['TH3_PLATFORMS']:
        st.error("NAT is not supported for this platform {}".format(platform))
        st.report_unsupported('NAT_unsupported_platform',platform)
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1D2P1, data.d1d2_ip_addr, data.ip_addr_mask, family=data.af_ipv4)
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.d2d1_ip_addr, data.ip_addr_mask, family=data.af_ipv4)
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D3P1, data.d2d3_ip_addr, data.ip_addr_mask, family=data.af_ipv4)
    ip_obj.config_ip_addr_interface(vars.D3, vars.D3D2P1, data.d3d2_ip_addr, data.ip_addr_mask, family=data.af_ipv4)
    ip_obj.create_static_route(vars.D1, data.d2d1_ip_addr,"{}/{}".format(data.d1_static_nw, data.ip_addr_mask),
                               shell=data.shell_vtysh, family=data.af_ipv4)
    ip_obj.create_static_route(vars.D3, data.d2d3_ip_addr, "{}/{}".format(data.d3_static_nw, data.ip_addr_mask),
                               shell=data.shell_vtysh, family=data.af_ipv4)
    st.log("NAT Configuration")
    nat_obj.config_nat_feature(vars.D2, 'enable')
    util_nat_zone_config(vars.D2, [vars.D2D1P1, vars.D2D3P1], [data.zone_1, data.zone_2], config=data.config_add)
    st.log("Creating NAT Pool")
    nat_obj.config_nat_pool(vars.D2, pool_name=data.pool_name[0], global_ip_range=data.d2d1_ip_addr,
                            global_port_range=data.global_port_range, config=data.config_add)
    st.log("Creating NAT Pool binding")
    nat_obj.config_nat_pool_binding(vars.D2, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    config=data.config_add)
    utils.exec_all(True, [[ip_obj.show_ip_route, vars.D1], [ip_obj.show_ip_route, vars.D2]])
    ip_obj.show_ip_route(vars.D3)


@pytest.mark.nat_regression1
def test_ft_dynamic_napt_traceroute():
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Eamil: kiran-kumar.vedulaa@broadcom.com
    # ################################################
    # Objective - Verify traceroute over a NAT translation
    # #################################################
    nat_obj.clear_nat(vars.D2, translations=True)
    nat_obj.clear_nat(vars.D2, statistics=True)

    ip_obj.ping(vars.D3, data.d1d2_ip_addr, family='ipv4', count=3)
    ip_obj.traceroute(vars.D3, data.d1d2_ip_addr)

    trn_val = nat_obj.get_nat_translations(vars.D2, protocol=data.proto_udp, dst_ip=data.d2d1_ip_addr,
                                           dst_ip_port=data.global_port[0])
    if not trn_val:
        ip_obj.ping(vars.D1, data.d2d1_ip_addr, family='ipv4', count=1)
        ip_obj.ping(vars.D1, data.d3d2_ip_addr, family='ipv4', count=1)
        st.error("Received empty list0,nat translation table not updated")
        st.report_fail("traceroute_over_nat_failed")

    trn_val = nat_obj.get_nat_translations(vars.D2, protocol=data.proto_udp, dst_ip=data.d2d1_ip_addr,
                                           dst_ip_port=data.global_port[1])
    if not trn_val:
        ip_obj.ping(vars.D2, data.d3d2_ip_addr, family='ipv4', count=1)
        st.error("Received empty list1,nat translation table not updated")
        st.report_fail("traceroute_over_nat_failed")

    trn_val = nat_obj.get_nat_translations(vars.D2, protocol=data.proto_udp, dst_ip=data.d2d1_ip_addr,
                                           dst_ip_port=data.global_port[2])
    if not trn_val:
        st.error("Received empty list2,nat translation table not updated")
        st.report_fail("traceroute_over_nat_failed")
    st.report_pass("traceroute_over_nat_translation_successful")

def nat_post_config():
    vars = st.get_testbed_vars()
    util_nat_zone_config(vars.D2, [vars.D2D1P1, vars.D2D3P1], [data.zone_1, data.zone_2], config=data.config_del)
    nat_obj.clear_nat_config(vars.D2)
    nat_obj.config_nat_feature(vars.D2, 'disable')
    ip_obj.delete_static_route(vars.D1, data.d2d1_ip_addr,"{}/{}".format(data.d1_static_nw, data.ip_addr_mask))
    ip_obj.delete_static_route(vars.D3, data.d2d3_ip_addr,"{}/{}".format(data.d3_static_nw, data.ip_addr_mask))
    ip_obj.clear_ip_configuration(st.get_dut_names())



def util_nat_zone_config(dut,intf,zone,config):
    if config == data.config_add:
        st.log("zone value configuration")
        for i in range(len(intf)):
            nat_obj.config_nat_interface(dut, interface_name=intf[i], zone_value=zone[i], config=data.config_add)
    else:
        st.log("zone value un configuration")
        for i in range(len(intf)):
            nat_obj.config_nat_interface(dut, interface_name=intf[i], zone_value=zone[i], config=data.config_del)

    return True

