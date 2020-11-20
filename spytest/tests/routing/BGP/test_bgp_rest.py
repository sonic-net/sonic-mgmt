import pytest

from spytest import SpyTestDict, st
from utilities.common import poll_wait
from utilities.parallel import ensure_no_exception, exec_all, exec_parallel
from apis.routing.ip import config_interface_ip6_link_local
from apis.switching.vlan import create_vlan_and_add_members, clear_vlan_configuration
from apis.switching.portchannel import config_portchannel, clear_portchannel_configuration
from spytest.utils import random_vlan_list

bgp_rst_data = SpyTestDict()


def bgp_rst_initialize_variables():
    bgp_rst_data.dut1_ip_l = ["139.8.1.1", "147.8.1.1"]
    bgp_rst_data.dut2_ip_l = ["139.8.1.2", "147.8.1.2"]
    bgp_rst_data.dut1_lpbk_ip_l = ["39.8.1.1", "47.8.1.1"]
    bgp_rst_data.dut2_lpbk_ip_l = ["39.8.1.2", "47.8.1.2"]
    bgp_rst_data.dut1_asn = 1339
    bgp_rst_data.dut2_asn = 1447
    bgp_rst_data.ip_pre_len = 24
    bgp_rst_data.dut1_ip6_l = ["3009::1", "3109::1"]
    bgp_rst_data.dut2_ip6_l = ["3009::2", "3109::2"]
    bgp_rst_data.ip6_pre_len = 64
    bgp_rst_data.unconfig_flag = False
    bgp_rst_data.portchannel_name = "PortChannel3"
    bgp_rst_data.vlan_id = random_vlan_list(count=1)


@pytest.fixture(scope="module", autouse=True)
def bgp_rst_module_config(request):
    bgp_rst_initialize_variables()
    bgp_rst_prologue()
    ipv6_link_local_config(action="add")
    yield
    ipv6_link_local_config(action="del")
    bgp_rst_epilogue()


@pytest.fixture(scope="function", autouse=True)
def bgp_rst_func_hooks(request):
    yield
    if st.get_func_name(request) == "test_ft_bgp_rst002":
        [_, exceptions] = exec_all(True, [[config_ip_addr_rst, vars.D1, bgp_rst_data.dut1_ip6_l[0], bgp_rst_data.ip6_pre_len, vars.D1D2P1, "ipv6", "del"],
                                          [config_ip_addr_rst, vars.D2, bgp_rst_data.dut2_ip6_l[0], bgp_rst_data.ip6_pre_len, vars.D2D1P1, "ipv6", "del"]])
        ensure_no_exception(exceptions)

def bgp_rst_prologue():
    global vars
    vars = st.ensure_min_topology("D1D2:4")
    st.banner("Routing interface configuration in both DUTs")
    [_, exceptions] =exec_all(True, [[dut1_routing_int_cfg, "add"], [dut2_routing_int_cfg, "add"]])
    ensure_no_exception(exceptions)


def bgp_rst_epilogue():
    st.banner("Routing interface un-configuration in both DUTs")
    [_, exceptions] =exec_all(True, [[dut1_routing_int_cfg, "del"], [dut2_routing_int_cfg, "del"]])
    ensure_no_exception(exceptions)
    [_, exceptions] = exec_all(True, [[config_bgp_router_rst, vars.D1, bgp_rst_data.dut1_asn, "del"], \
                                      [config_bgp_router_rst, vars.D2, bgp_rst_data.dut2_asn, "del"]])
    ensure_no_exception(exceptions)


def config_ip_addr_rst(dut, ip_addr, pre_len, interface, family, config="add"):
    ip_addr_create_data = {
        "openconfig-if-ip:address": [
            {
                "ip": ip_addr,
                "config": {
                    "ip": ip_addr,
                    "prefix-length": pre_len
                }
            }
        ]
    }
    if family == "ipv4":
        ip_addr_create_url = "/restconf/data/openconfig-interfaces:interfaces/interface={}/subinterfaces/subinterface=0/openconfig-if-ip:ipv4/addresses".format(
            interface)
        ip_addr_delete_url = "/restconf/data/openconfig-interfaces:interfaces/interface={}/subinterfaces/subinterface=0/openconfig-if-ip:ipv4/addresses".format(
            interface)
    else:
        ip_addr_create_url = "/restconf/data/openconfig-interfaces:interfaces/interface={}/subinterfaces/subinterface=0/openconfig-if-ip:ipv6/addresses".format(
            interface)
        ip_addr_delete_url = "/restconf/data/openconfig-interfaces:interfaces/interface={}/subinterfaces/subinterface=0/openconfig-if-ip:ipv6/addresses".format(
            interface)

    if config == "add":
        try:
            res_create = st.rest_create(dut, path=ip_addr_create_url, data=ip_addr_create_data)
        except Exception as e:
            st.log(e)
            return False
        if not res_create["status"] in [200, 201, 204]:
            st.error("Failed to configure the {} routing interface with {} through REST".format(family, ip_addr))
            return False
    elif config == "del":
        try:
            res_delete = st.rest_delete(dut, path=ip_addr_delete_url)
        except Exception as e:
            st.log(e)
            return False
        if not res_delete["status"] in [200, 201, 204]:
            st.error("Failed to un-configure the {} routing interface with {} through rst".format(family, ip_addr))
            return False

    return True


def config_bgp_router_rst(dut, asn, config="add"):
    bgp_router_create_data = {
        "openconfig-network-instance:global": {
            "config": {
                "as": asn
            }
        }
    }
    bgp_router_create_url = "/restconf/data/openconfig-network-instance:network-instances/network-instance=default/protocols/protocol=BGP,bgp/bgp"
    bgp_router_del_url = "/restconf/data/openconfig-network-instance:network-instances/network-instance=default/protocols/protocol=BGP,bgp/bgp"
    if config == "add":
        try:
            res_create = st.rest_create(dut, path=bgp_router_create_url, data=bgp_router_create_data)
        except Exception as e:
            st.log(e)
            return False
        if not res_create["status"] in [200, 201, 204]:
            st.error("Failed to configure the BGP Router with {} through REST".format(asn))
            return False
    elif config == "del":
        try:
            res_delete = st.rest_delete(dut, path=bgp_router_del_url)
        except Exception as e:
            st.log(e)
            return False
        if not res_delete["status"] in [200, 201, 204]:
            st.error("Failed to un-configure the BGP Router with {} through REST".format(asn))
            return False

    return True


def config_bgp_neighbor_rst(dut, **kwargs):
    neigh_ip = kwargs.get('neigh_ip')
    local_asn = kwargs.get('local_asn')
    remote_asn = kwargs.get('remote_asn')
    peer_type = kwargs.get('peer_type')
    family = kwargs.get('family')
    config = kwargs.get('config')

    if family == "ipv4":
        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
    else:
        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"

    bgp_ipv4_neighbor_create_data = {
        "openconfig-network-instance:neighbor": [{

            "neighbor-address": neigh_ip,
            "config": {
                "neighbor-address": neigh_ip,
                "enabled": True,
                "peer-as": remote_asn,
                "local-as": local_asn,
                "peer-type": peer_type
            },
            "afi-safis": {
                "afi-safi": [{
                    "afi-safi-name": afi_safi_name,
                    "config": {
                        "afi-safi-name": afi_safi_name,
                        "enabled": True
                    }
                }]
            }
        }]
    }
    bgp_neighbor_create_url = "/restconf/data/openconfig-network-instance:network-instances/network-instance=default/protocols/protocol=BGP,bgp/bgp/neighbors"
    bgp_neighbor_delete_url = "/restconf/data/openconfig-network-instance:network-instances/network-instance=default/protocols/protocol=BGP,bgp/bgp/neighbors"
    if config == "add":
        try:
            res_create = st.rest_create(dut, path=bgp_neighbor_create_url, data=bgp_ipv4_neighbor_create_data)
        except Exception as e:
            st.log(e)
            return False
        if not res_create["status"] in [200, 201, 204]:
            st.error("Failed to configure the {} BGP neighbor {} through REST".format(family, neigh_ip))
            return False
    elif config == "del":
        try:
            res_delete = st.rest_delete(dut, path=bgp_neighbor_delete_url)
        except Exception as e:
            st.log(e)
            return False
        if not res_delete["status"] in [200, 201, 204]:
            st.error("Failed to un-configure the {} BGP neighbor {} through REST".format(family, neigh_ip))
            return False
    return True


def verify_bgp_neighbor_rst(dut, neigh_ip):
    bgp_neigh_get_url = "/restconf/data/openconfig-network-instance:network-instances/network-instance=default/protocols/" \
                        "protocol=BGP,bgp/bgp/neighbors/neighbor={}".format(neigh_ip)
    try:
        res_bgp_get = st.rest_read(dut, bgp_neigh_get_url)
        state = res_bgp_get['output'][u'openconfig-network-instance:neighbor'][0][u'state'][u'session-state']
        if not state.encode('UTF-8') == 'ESTABLISHED':
            return False
    except Exception as e:
        st.log(e)
        return False
    return True


def bgp_neighbor_del_rst(dut, neigh_ip):
    bgp_neighbor_delete_url = "/restconf/data/openconfig-network-instance:network-instances/network-instance=default/protocols/protocol=BGP,bgp/bgp/neighbors/neighbor={}".format(neigh_ip)
    try:
        res_delete = st.rest_delete(dut, path=bgp_neighbor_delete_url)
    except Exception as e:
        st.log(e)
        return False
    if not res_delete["status"] in [200, 201, 204]:
        st.error("Failed to un-configure the BGP neighbor {} through REST".format(neigh_ip))
        return False
    return True

def dut1_routing_int_cfg(action):
    config_ip_addr_rst(vars.D1, bgp_rst_data.dut1_ip_l[0], bgp_rst_data.ip_pre_len, vars.D1D2P1, "ipv4", config = action)
    if action == "add":
        config_ip_addr_rst(vars.D1, bgp_rst_data.dut1_ip6_l[0], bgp_rst_data.ip6_pre_len, vars.D1D2P1, "ipv6", config = action)
    # config_ip_addr_rst(vars.D1, bgp_rst_data.dut1_lpbk_ip_l[0], 32, "Loopback0", "ipv4", config = action)


def dut2_routing_int_cfg(action):
    config_ip_addr_rst(vars.D2, bgp_rst_data.dut2_ip_l[0], bgp_rst_data.ip_pre_len, vars.D2D1P1, "ipv4", config = action)
    if action == "add":
        config_ip_addr_rst(vars.D2, bgp_rst_data.dut2_ip6_l[0], bgp_rst_data.ip6_pre_len, vars.D2D1P1, "ipv6", config = action)
    # config_ip_addr_rst(vars.D2, bgp_rst_data.dut2_lpbk_ip_l[0], 32, "Loopback0", "ipv4", config = action)

def ipv6_link_local_config(action="add"):
    if action == "add":
        st.log("Creating VLAN and participating interfaces ...")
        vlan_data = [{"dut": [vars.D1], "vlan_id": bgp_rst_data.vlan_id[0], "tagged": [vars.D1D2P2]},
                     {"dut": [vars.D2], "vlan_id": bgp_rst_data.vlan_id[0], "tagged": [vars.D2D1P2]}]
        create_vlan_and_add_members(vlan_data)
        st.log("Creating PortChannel and participating interfaces ...")
        config_portchannel(vars.D1, vars.D2, bgp_rst_data.portchannel_name,[vars.D1D2P3, vars.D1D2P4], [vars.D2D1P3, vars.D2D1P4])
        st.log("Enable IPV6 on physical interface on both the devices")
        [_, exceptions] = exec_all(True, [[config_interface_ip6_link_local, vars.D1, ["Vlan{}".format(bgp_rst_data.vlan_id[0]), bgp_rst_data.portchannel_name]], \
                                            [config_interface_ip6_link_local, vars.D2, ["Vlan{}".format(bgp_rst_data.vlan_id[0]), bgp_rst_data.portchannel_name]]])
        ensure_no_exception(exceptions)
    else:
        [_, exceptions] = exec_all(True, [
            [config_interface_ip6_link_local, vars.D1, [vars.D1D2P1, "Vlan{}".format(bgp_rst_data.vlan_id[0]), bgp_rst_data.portchannel_name], "disable"], \
            [config_interface_ip6_link_local, vars.D2, [vars.D2D1P1, "Vlan{}".format(bgp_rst_data.vlan_id[0]), bgp_rst_data.portchannel_name], "disable"]])
        ensure_no_exception(exceptions)
        clear_portchannel_configuration([vars.D1, vars.D2])
        clear_vlan_configuration([vars.D1, vars.D2])


@pytest.mark.bgp_rst
def test_ft_bgp_rst001():
#     """
#     Validate the BGP IPv4 neighborship when configured through REST
#     :return:
#     """
    [out, exceptions] = exec_all(True, [[config_bgp_router_rst, vars.D1, bgp_rst_data.dut1_asn, "add"], \
                                      [config_bgp_router_rst, vars.D2, bgp_rst_data.dut2_asn, "add"]])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_router_create_delete", "Creation", "REST", "FAILED")
    st.wait(5)
    dut1_data = {'neigh_ip': bgp_rst_data.dut2_ip_l[0], 'local_asn' : bgp_rst_data.dut1_asn,
                                    'remote_asn' : bgp_rst_data.dut2_asn, 'peer_type':"EXTERNAL", 'family':"ipv4", 'config':"add"}
    dut2_data = {'neigh_ip' :bgp_rst_data.dut1_ip_l[0], 'local_asn' :bgp_rst_data.dut2_asn,
                                    'remote_asn' :bgp_rst_data.dut1_asn, 'peer_type':"EXTERNAL", 'family':"ipv4", 'config':"add"}
    exec_parallel(True, [vars.D1, vars.D2], config_bgp_neighbor_rst, [dut1_data, dut2_data])
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v4", "Creation", "REST", "FAILED")
    if not poll_wait(verify_bgp_neighbor_rst, 10, vars.D1, bgp_rst_data.dut2_ip_l[0]):
        st.report_fail("bgp_neighbor_create_delete", "v4", "Creation", "REST", "FAILED")
    [out, exceptions] = exec_all(True, [[bgp_neighbor_del_rst, vars.D1, bgp_rst_data.dut2_ip_l[0]] , \
                                      [bgp_neighbor_del_rst, vars.D2, bgp_rst_data.dut1_ip_l[0]]])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v4", "Delrtion", "REST", "FAILED")
    st.report_pass("bgp_neighbor_status", "v4", "Successful", "REST")


@pytest.mark.bgp_rst
def test_ft_bgp_rst002():
    """
    Validate the BGP IPv6 neighborship when configured through REST
    :return:
    """
    dut1_data = {'neigh_ip': bgp_rst_data.dut2_ip6_l[0], 'local_asn' : bgp_rst_data.dut1_asn,
                                    'remote_asn' : bgp_rst_data.dut2_asn, 'peer_type':"EXTERNAL", 'family':"ipv6", 'config':"add"}
    dut2_data = {'neigh_ip' :bgp_rst_data.dut1_ip6_l[0], 'local_asn' :bgp_rst_data.dut2_asn,
                                    'remote_asn' :bgp_rst_data.dut1_asn, 'peer_type':"EXTERNAL", 'family':"ipv6", 'config':"add"}
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], config_bgp_neighbor_rst, [dut1_data, dut2_data])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v6", "Creation", "REST", "FAILED")
    if not poll_wait(verify_bgp_neighbor_rst, 10, vars.D1, bgp_rst_data.dut2_ip6_l[0]):
        st.report_fail("bgp_neighbor_create_delete", "v6", "Creation", "REST", "FAILED")
    [out, exceptions] = exec_all(True, [[bgp_neighbor_del_rst, vars.D1, bgp_rst_data.dut2_ip6_l[0]] , \
                                      [bgp_neighbor_del_rst, vars.D2, bgp_rst_data.dut1_ip6_l[0]]])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v6", "Delrtion", "REST", "FAILED")
    st.report_pass("bgp_neighbor_status", "v6", "Successful", "REST")


@pytest.mark.bgp_rst
def test_ft_bgp_rst003():
    [_, exceptions] = exec_all(True, [
        [config_interface_ip6_link_local, vars.D1, [vars.D1D2P1]], \
        [config_interface_ip6_link_local, vars.D2, [vars.D2D1P1]]])
    ensure_no_exception(exceptions)
    dut1_data = {'neigh_ip': vars.D1D2P1, 'local_asn': bgp_rst_data.dut1_asn,
                 'remote_asn': bgp_rst_data.dut2_asn, 'peer_type': "EXTERNAL", 'family': "ipv6", 'config': "add"}
    dut2_data = {'neigh_ip': vars.D2D1P1, 'local_asn': bgp_rst_data.dut2_asn,
                 'remote_asn': bgp_rst_data.dut1_asn, 'peer_type': "EXTERNAL", 'family': "ipv6", 'config': "add"}
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], config_bgp_neighbor_rst, [dut1_data, dut2_data])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v6", "Creation", "REST", "FAILED")
    if not poll_wait(verify_bgp_neighbor_rst, 10, vars.D1, vars.D1D2P1):
        st.report_fail("bgp_neighbor_create_delete", "v6", "Creation", "REST", "FAILED")
    [out, exceptions] = exec_all(True, [[bgp_neighbor_del_rst, vars.D1, vars.D2D1P1], \
                                        [bgp_neighbor_del_rst, vars.D2, vars.D1D2P1]])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v6", "Delrtion", "REST", "FAILED")
    st.report_pass("bgp_neighbor_status", "v6", "Successful", "REST")

@pytest.mark.bgp_rst
def test_ft_bgp_rst004():
    dut1_data = {'neigh_ip': "Vlan{}".format(bgp_rst_data.vlan_id[0]), 'local_asn': bgp_rst_data.dut1_asn,
                 'remote_asn': bgp_rst_data.dut2_asn, 'peer_type': "EXTERNAL", 'family': "ipv6", 'config': "add"}
    dut2_data = {'neigh_ip': "Vlan{}".format(bgp_rst_data.vlan_id[0]), 'local_asn': bgp_rst_data.dut2_asn,
                 'remote_asn': bgp_rst_data.dut1_asn, 'peer_type': "EXTERNAL", 'family': "ipv6", 'config': "add"}
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], config_bgp_neighbor_rst, [dut1_data, dut2_data])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v6", "Creation", "REST", "FAILED")
    if not poll_wait(verify_bgp_neighbor_rst, 10, vars.D1, "Vlan{}".format(bgp_rst_data.vlan_id[0])):
        st.report_fail("bgp_neighbor_create_delete", "v6", "Creation", "REST", "FAILED")
    [out, exceptions] = exec_all(True, [[bgp_neighbor_del_rst, vars.D1, "Vlan{}".format(bgp_rst_data.vlan_id[0])], \
                                        [bgp_neighbor_del_rst, vars.D2, "Vlan{}".format(bgp_rst_data.vlan_id[0])]])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v6", "Delrtion", "REST", "FAILED")
    st.report_pass("bgp_neighbor_status", "v6", "Successful", "REST")

@pytest.mark.bgp_rst
def test_ft_bgp_rst005():
    dut1_data = {'neigh_ip': bgp_rst_data.portchannel_name, 'local_asn': bgp_rst_data.dut1_asn,
                 'remote_asn': bgp_rst_data.dut2_asn, 'peer_type': "EXTERNAL", 'family': "ipv6", 'config': "add"}
    dut2_data = {'neigh_ip': bgp_rst_data.portchannel_name, 'local_asn': bgp_rst_data.dut2_asn,
                 'remote_asn': bgp_rst_data.dut1_asn, 'peer_type': "EXTERNAL", 'family': "ipv6", 'config': "add"}
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], config_bgp_neighbor_rst, [dut1_data, dut2_data])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v6", "Creation", "REST", "FAILED")
    if not poll_wait(verify_bgp_neighbor_rst, 10, vars.D1, bgp_rst_data.portchannel_name):
        st.report_fail("bgp_neighbor_create_delete", "v6", "Creation", "REST", "FAILED")
    [out, exceptions] = exec_all(True, [[bgp_neighbor_del_rst, vars.D1, bgp_rst_data.portchannel_name], \
                                        [bgp_neighbor_del_rst, vars.D2, bgp_rst_data.portchannel_name]])
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.report_fail("bgp_neighbor_create_delete", "v6", "Delrtion", "REST", "FAILED")
    st.report_pass("bgp_neighbor_status", "v6", "Successful", "REST")