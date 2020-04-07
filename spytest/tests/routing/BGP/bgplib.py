##############################################################################################
# This file contains the library function to perform BPG elastic operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
##############################################################################################

from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *
import random
import pprint
from spytest import st
from spytest.dicts import SpyTestDict
import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.routing.route_map as rmapapi
import apis.switching.portchannel as poapi
import apis.switching.vlan as vlanapi
import utilities.utils as utils_obj
import BGP.resource as res_data_obj
import utilities.common as utils
from spytest.utils import filter_and_select


# Global vars
global fast_start, tg_info, topo_info, loopback_info, static_rt_info, fixed_nw_info, tg_connected_routers
global as_info, bgp_password, underlay_info
fast_start = True  # To Enable parallel config
tg_info = SpyTestDict()
topo_info = SpyTestDict()
loopback_info = SpyTestDict()
static_rt_info = SpyTestDict()
fixed_nw_info = SpyTestDict()
tg_connected_routers = []
as_info = SpyTestDict()
bgp_password = 'Test_127'
underlay_info = SpyTestDict()


def init_resource_data(vars):
    global data
    data = res_data_obj.resource_data(vars)


"""
Configure underlay interface and form underlay list
for physical interfaces - it is just a list of dut_links
for ves -it is vlan interface names
for veLag - this api configures lag, adds to vlan, and forms ve underlay list
currently it supports following underlays - physical interface, ve over lag
future this function can be expanded to support different other variations
"""


def l3tc_underlay_config_unconfig(config='yes', config_type='phy'):
    """

    :param config:
    :config_type:'phy' - physical interface ; 'veLag' - ve over lag ; 'l3Lag' - L3 over LAG
    :return:
    """
    st.banner("{}Configuring Underlay between Spine and Leaf nodes.".format('Un' if config != 'yes' else ''))
    max_mem = int(data['l3_max_links_leaf_spine'])
    po_id = int(data['start_lag_id'])
    vlan_id = int(data['start_vlan_id'])
    result = True
    leaf_index = 1
    underlay_info['links'] = SpyTestDict()
    for leaf in data['leaf_routers']:
        underlay_info['links'][leaf] = SpyTestDict()
        ipapi.get_interface_ip_address(data[leaf], family="ipv4")
        ipapi.get_interface_ip_address(data[leaf], family="ipv6")
        for spine in data['spine_routers']:
            ipapi.get_interface_ip_address(data[spine], family="ipv4")
            ipapi.get_interface_ip_address(data[spine], family="ipv6")
            underlay_info['links'][leaf][spine] = []
            po_name = 'PortChannel'+str(po_id)
            # for physical interface underlay just store the underlay link info
            if config_type == 'phy':
                link_index = 1
                for local, partner, remote in st.get_dut_links(data[leaf], data[spine]):
                    if link_index <= max_mem:
                        underlay_info['links'][leaf][spine].append([local, remote])
                    link_index += 1
            # for ve over lag
            elif config_type == 'veLag':
                local_lag_mbrs = []
                remote_lag_mbrs = []
                ve_int_name = 'Vlan'+str(vlan_id)
                underlay_info['links'][leaf][spine].append([ve_int_name, ve_int_name])
                link_index = 1
                for local, partner, remote in st.get_dut_links(data[leaf], data[spine]):
                    if link_index <= max_mem:
                        local_lag_mbrs.append(local)
                        remote_lag_mbrs.append(remote)
                    link_index += 1
                l3tc_underlay_ve_lag_config_unconfig(config, data[leaf],
                                                     data[spine], vlan_id, po_name, local_lag_mbrs, remote_lag_mbrs)
            # for ve over lag
            elif config_type == 'l3Lag':
                local_lag_mbrs = []
                remote_lag_mbrs = []
                underlay_info['links'][leaf][spine].append([po_name, po_name])
                link_index = 1
                for local, partner, remote in st.get_dut_links(data[leaf], data[spine]):
                    if link_index <= max_mem:
                        local_lag_mbrs.append(local)
                        remote_lag_mbrs.append(remote)
                    link_index += 1
                l3tc_underlay_lag_config_unconfig(config, data[leaf],
                                                  data[spine], po_name, local_lag_mbrs, remote_lag_mbrs)
            po_id += 1
            vlan_id += 1
        leaf_index += 1
    return result


def l3tc_underlay_ve_lag_config_unconfig(config, dut1, dut2, vlan_id, po_name, members_dut1, members_dut2):
    """

    :param config:
    :param dut1:
    :param dut2:
    :param vlan_id:
    :param po_name:
    :param members_dut1:
    :param members_dut2:
    :return:
    """
    st.banner("{}Configuring VE over LAG between Spine and Leaf node.".format('Un' if config != 'yes' else ''))
    result = True

    if config == 'yes':
        # configure vlan
        [out, exceptions] = \
                    utils.exec_all(fast_start,
                                   [[vlanapi.create_vlan, dut1, vlan_id],
                                    [vlanapi.create_vlan, dut2, vlan_id]])
        st.log([out, exceptions])

        # configure po and add members
        [out, exceptions] = \
                utils.exec_all(fast_start, [[poapi.config_portchannel, dut1, dut2, po_name,
                                             members_dut1, members_dut2, "add"]])
        st.log([out, exceptions])

        # add po to vlan
        [out, exceptions] = \
            utils.exec_all(fast_start,
                           [[vlanapi.add_vlan_member, dut1, vlan_id, po_name, True],
                            [vlanapi.add_vlan_member, dut2, vlan_id, po_name, True]])
        st.log([out, exceptions])
    else:
        # del po from vlan
        [out, exceptions] = \
            utils.exec_all(fast_start,
                           [[vlanapi.delete_vlan_member, dut1, vlan_id, po_name],
                            [vlanapi.delete_vlan_member, dut2, vlan_id, po_name]])
        st.log([out, exceptions])

        # del po and delete members
        [out, exceptions] = \
                utils.exec_all(fast_start, [[poapi.config_portchannel, dut1, dut2, po_name, members_dut1,
                                             members_dut2, "del"]])
        st.log([out, exceptions])

        # del vlan
        [out, exceptions] = \
                    utils.exec_all(fast_start,
                                   [[vlanapi.delete_vlan, dut1, vlan_id],
                                    [vlanapi.delete_vlan, dut2, vlan_id]])
        st.log([out, exceptions])
    return result


def l3tc_underlay_lag_config_unconfig(config, dut1, dut2, po_name, members_dut1, members_dut2):
    """

    :param config:
    :param dut1:
    :param dut2:
    :param po_name:
    :param members_dut1:
    :param members_dut2:
    :return:
    """
    st.banner("{}Configuring LAG between Spine and Leaf node.".format('Un' if config != 'yes' else ''))
    result = True

    if config == 'yes':
        # configure po and add members
        [out, exceptions] = \
                utils.exec_all(fast_start, [[poapi.config_portchannel, dut1, dut2, po_name,
                                             members_dut1, members_dut2, "add"]])
        st.log([out, exceptions])
    else:
        # del po and delete members
        [out, exceptions] = \
                utils.exec_all(fast_start, [[poapi.config_portchannel, dut1, dut2, po_name,
                                             members_dut1, members_dut2, "del"]])
        st.log([out, exceptions])
    return result


def l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='yes', vrf_type='all', config_type='all'):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :return:
    """
    st.banner("{}Configuring IP Addresses between Spine and Leaf nodes.".format('Un' if config != 'yes' else ''))

    topo_info['ipv4'] = SpyTestDict()
    topo_info['ipv6'] = SpyTestDict()

    config = 'add' if config == 'yes' else 'remove'
    ipv4_adr = data['ipv4_addres_first_octet']
    ipv6_adr = data['ipv6_addres_first_octet']
    result = True
    k = 1
    for leaf in data['leaf_routers']:
        topo_info['ipv4'][leaf] = []
        topo_info['ipv6'][leaf] = []

        for spine in data['spine_routers']:
            topo_info['ipv4'][spine] = []
            topo_info['ipv6'][spine] = []

            link = 1
            for local, remote in underlay_info['links'][leaf][spine]:
                if config_type == 'ipv4' or config_type == 'all':
                    ipaddr1 = "{}.{}.{}.1".format(ipv4_adr, k, link)
                    ipaddr2 = "{}.{}.{}.2".format(ipv4_adr, k, link)
                    topo_info['ipv4'][leaf].append([local, ipaddr1, spine, remote, ipaddr2, link])
                    topo_info['ipv4'][spine].append([remote, ipaddr2, leaf, local, ipaddr1, link])

                    [out, exceptions] = \
                        utils.exec_all(fast_start,
                                       [[ipapi.config_ip_addr_interface, data[leaf], local, ipaddr1, '24',
                                         "ipv4", config],
                                        [ipapi.config_ip_addr_interface, data[spine], remote, ipaddr2, '24',
                                         "ipv4", config]])
                    st.log([out, exceptions])

                if config_type == 'ipv6' or config_type == 'all':
                    ip6addr_1 = "{}:{}:{}::1".format(ipv6_adr, k, link)
                    ip6addr_2 = "{}:{}:{}::2".format(ipv6_adr, k, link)
                    topo_info['ipv6'][leaf].append([local, ip6addr_1, spine, remote, ip6addr_2, link])
                    topo_info['ipv6'][spine].append([remote, ip6addr_2, leaf, local, ip6addr_1, link])

                    [out, exceptions] = \
                        utils.exec_all(fast_start,
                                       [[ipapi.config_ip_addr_interface, data[leaf], local, ip6addr_1, '64',
                                         "ipv6", config],
                                        [ipapi.config_ip_addr_interface, data[spine], remote, ip6addr_2, '64',
                                         "ipv6", config]])
                    st.log([out, exceptions])
                link += 1
            k += 1
    return result


def l3tc_vrfipv4v6_address_leafspine_loopback_config_unconfig(config='yes', config_type='all'):
    """

    :param config:
    :param config_type:
    :return:
    """
    st.banner("{}Configuring Loopback Addresses on both Spine and Leaf nodes.".format('Un' if config != 'yes' else ''))
    lo_config = config
    config = 'add' if config == 'yes' else 'remove'
    result = True
    i = 1
    loopback_info['ipv4'] = SpyTestDict()
    loopback_info['ipv6'] = SpyTestDict()
    thread4_info = []
    thread6_info = []
    loop_back_int_create = []
    for j, leaf in enumerate(data['leaf_routers'], start=0):
        loopback1 = "{}.{}.{}.{}".format(i, i+1, i+2, i+3)
        loopback6addr_1 = "{}::{}".format(6000+i, i)
        loopback_info['ipv4'][leaf] = loopback1
        loopback_info['ipv6'][leaf] = loopback6addr_1

        loop_back_int_create.append(utils.ExecAllFunc(ipapi.configure_loopback, data[leaf], loopback_name="Loopback0",
                                                      config=lo_config))
        thread4_info.append([ipapi.config_ip_addr_interface, data[leaf], "Loopback0", loopback1, '32', "ipv4", config])
        thread6_info.append([ipapi.config_ip_addr_interface, data[leaf], "Loopback0", loopback6addr_1, '128', "ipv6",
                             config])
        i += 1

    for j, spine in enumerate(data['spine_routers'], start=0):
        loopback1 = "{}.{}.{}.{}".format(i, i+1, i+2, i+3)
        loopback6addr_1 = "{}::{}".format(6000+i, i)
        loopback_info['ipv4'][spine] = loopback1
        loopback_info['ipv6'][spine] = loopback6addr_1

        loop_back_int_create.append(utils.ExecAllFunc(ipapi.configure_loopback, data[spine], loopback_name="Loopback0",
                                                      config=lo_config))
        thread4_info.append([ipapi.config_ip_addr_interface, data[spine], "Loopback0", loopback1, '32', "ipv4", config])
        thread6_info.append([ipapi.config_ip_addr_interface, data[spine], "Loopback0", loopback6addr_1, '128', "ipv6",
                             config])
        i += 1

    if config == 'add':
        [out, exceptions] = utils.exec_all(fast_start, loop_back_int_create)
        st.log([out, exceptions])
    if config_type == 'ipv4' or config_type == 'all':
        [out, exceptions] = utils.exec_all(fast_start, thread4_info)
        st.log([out, exceptions])

    if config_type == 'ipv6' or config_type == 'all':
        [out, exceptions] = utils.exec_all(fast_start, thread6_info)
        st.log([out, exceptions])
    if config == 'remove':
        [out, exceptions] = utils.exec_all(fast_start, loop_back_int_create)
        st.log([out, exceptions])

    return result


def l3tc_vrfipv4v6_static_route_leafspine_config_unconfig(config='yes', vrf_type='all', config_type='all'):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :return:
    """
    st.banner("{}Configuring Static route  between Spine and Leaf nodes.".format('Un' if config != 'yes' else ''))

    static_rt_info['ipv4'] = SpyTestDict()
    static_rt_info['ipv6'] = SpyTestDict()

    result = True
    config = 'add' if config == 'yes' else 'remove'

    dut_name_map = SpyTestDict()
    dut_name_list = {each:[] for each in data['spine_routers'] + data['leaf_routers']}
    for dut_idx, dut_name in enumerate(dut_name_list, start=1):
        dut_name_map[dut_name] = "D{}".format(dut_idx)

    if topo_info:
        for dut_idx, dut_name in enumerate(dut_name_list, start=1):
            static_rt_info['ipv4'][dut_name] = []
            static_rt_info['ipv6'][dut_name] = []

            actual_dut = data[dut_name]

            if config_type == 'ipv4' or config_type == 'all':
                afamily = 'ipv4'
                dut_port_list = [each for each in topo_info[afamily][dut_name] if each[2] in dut_name_map]
                for port_idx, each_port in enumerate(dut_port_list, start=1):
                    port_rmt_ip4 = each_port[4]
                    port_lnk_num = each_port[5]

                    staticip = "{}.{}.{}.0/24".format(data['ipv4_static_addres_first_octet'], dut_idx, port_idx)
                    nexthop = port_rmt_ip4

                    if config == 'yes':
                        static_rt_info[afamily][dut_name].append([staticip, nexthop])
                        static_rt_info[afamily][dut_name].append([staticip, nexthop])

                    if config == 'add':
                        [out, exceptions] = \
                           utils.exec_all(fast_start, [[ipapi.create_static_route, actual_dut, nexthop, staticip,
                                                        "vtysh", 'ipv4']])
                    elif config == 'remove':
                        [out, exceptions] = \
                           utils.exec_all(fast_start, [[ipapi.delete_static_route, actual_dut, nexthop, staticip,
                                                        'ipv4', "vtysh"]])
                    st.log([out, exceptions])

            if config_type == 'ipv6' or config_type == 'all':
                afamily = 'ipv6'
                dut_port_list = [each for each in topo_info[afamily][dut_name] if each[2] in dut_name_map]
                for port_idx, each_port in enumerate(dut_port_list, start=1):
                    port_rmt_ip6 = each_port[4]
                    port_lnk_num = each_port[5]

                    staticip = "{}:{}:{}::2/64".format(data['ipv6_static_addres_first_octet'], dut_idx, port_idx)
                    nexthop = port_rmt_ip6

                    static_rt_info[afamily][dut_name].append([staticip, nexthop])
                    static_rt_info[afamily][dut_name].append([staticip, nexthop])

                    if config == 'add':
                        [out, exceptions] = \
                           utils.exec_all(fast_start, [[ipapi.create_static_route, actual_dut, nexthop, staticip,
                                                        "vtysh", 'ipv6']])
                    elif config == 'remove':
                        [out, exceptions] = \
                           utils.exec_all(fast_start, [[ipapi.delete_static_route, actual_dut, nexthop, staticip,
                                                        'ipv6', "vtysh"]])
                    st.log([out, exceptions])
    else:
        st.log("Topology information not available")
        return False
    return result


def l3tc_vrfipv4v6_address_leafspine_ping_test(vrf_type='all', config_type='all', ping_count=3):
    """

    :param vrf_type:
    :param config_type:
    :param ping_count:
    :return:
    """
    st.banner("Ping Checking between Spine and Leaf nodes.")
    ipv4_adr = data['ipv4_addres_first_octet']
    ipv6_adr = data['ipv6_addres_first_octet']
    result = True
    k = 1
    for leaf in data['leaf_routers']:
        for spine in data['spine_routers']:
            link = 1
            for local, remote in underlay_info['links'][leaf][spine]:
                if config_type == 'ipv4' or config_type == 'all':
                    ipaddr1 = "{}.{}.{}.1".format(ipv4_adr, k, link)
                    ipaddr2 = "{}.{}.{}.2".format(ipv4_adr, k, link)
                    if not ipapi.ping(data[leaf], ipaddr2, family='ipv4', count=ping_count):
                        st.log("{}- {} configured on {} - ping failed".format(data[leaf], local, ipaddr2))
                        result = False
                if config_type == 'ipv6' or config_type == 'all':
                    ip6addr_1 = "{}:{}:{}::1".format(ipv6_adr, k, link)
                    ip6addr_2 = "{}:{}:{}::2".format(ipv6_adr, k, link)
                    if not ipapi.ping(data[leaf], ip6addr_2, family='ipv6', count=ping_count):
                        st.log("{}- {} configured on {} - ping v6 failed".format(data[leaf], local, ip6addr_2))
                        result = False
                link += 1
            k += 1
    return result


def l3tc_vrfipv4v6_address_leafspine_bgp_config(config='yes', vrf_type='all', config_type='all', **kwargs):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :return:
    """
    st.banner("{}Configuring BGP between Spine and Leaf nodes.".format('Un' if config != 'yes' else ''))

    config = 'add' if config == 'yes' else 'remove'
    ipv4_adr = data['ipv4_addres_first_octet']
    ipv6_adr = data['ipv6_addres_first_octet']
    spine_as = int(data['spine_as'])
    leaf_as = int(data['leaf_as'])
    if kwargs.has_key('rr_enable'):
        leaf_as = spine_as

    result = True
    thread4_info = []
    thread6_info = []
    if config == 'add':
        k = 1
        for leaf in data['leaf_routers']:
            as_info[leaf] = leaf_as
            for spine in data['spine_routers']:
                as_info[spine] = spine_as
                link = 1
                if config == 'add':
                    spine_neigh_list, leaf_neigh_list, spine_neigh6_list, leaf_neigh6_list = [], [], [], []
                    for local, remote in underlay_info['links'][leaf][spine]:
                        if config_type == 'ipv4' or config_type == 'all':
                            ipaddr1 = "{}.{}.{}.1".format(ipv4_adr, k, link)
                            ipaddr2 = "{}.{}.{}.2".format(ipv4_adr, k, link)
                            spine_neigh_list.append(ipaddr2)
                            leaf_neigh_list.append(ipaddr1)
                        if config_type == 'ipv6' or config_type == 'all':
                            ip6addr_1 = "{}:{}:{}::1".format(ipv6_adr, k, link)
                            ip6addr_2 = "{}:{}:{}::2".format(ipv6_adr, k, link)
                            spine_neigh6_list.append(ip6addr_2)
                            leaf_neigh6_list.append(ip6addr_1)
                        link += 1
                    k += 1
                    if config_type == 'ipv4' or config_type == 'all':
                        thread4_info.append(utils.ExecAllFunc(bgpapi.config_bgp_multi_neigh_use_peergroup, data[leaf],
                                                              local_asn=leaf_as, peer_grp_name='leaf_spine',
                                                              remote_asn=spine_as, neigh_ip_list=spine_neigh_list,
                                                              family='ipv4', activate=1, password=bgp_password))
                        thread4_info.append(utils.ExecAllFunc(bgpapi.config_bgp_multi_neigh_use_peergroup, data[spine],
                                                              local_asn=spine_as, peer_grp_name='spine_leaf',
                                                              remote_asn=leaf_as, neigh_ip_list=leaf_neigh_list,
                                                              family='ipv4', activate=1, password=bgp_password))

                    if config_type == 'ipv6' or config_type == 'all':
                        thread6_info.append(utils.ExecAllFunc(bgpapi.config_bgp_multi_neigh_use_peergroup, data[leaf],
                                                              local_asn=leaf_as, peer_grp_name='leaf_spine6',
                                                              remote_asn=spine_as, neigh_ip_list=spine_neigh6_list,
                                                              family='ipv6', activate=1, password=bgp_password))
                        thread6_info.append(utils.ExecAllFunc(bgpapi.config_bgp_multi_neigh_use_peergroup, data[spine],
                                                              local_asn=spine_as, peer_grp_name='spine_leaf6',
                                                              remote_asn=leaf_as, neigh_ip_list=leaf_neigh6_list,
                                                              family='ipv6', activate=1, password=bgp_password))

        if config_type == 'ipv4' or config_type == 'all':
            [out, exceptions] = utils.exec_all(False, thread4_info)
            st.log([out, exceptions])

        if config_type == 'ipv6' or config_type == 'all':
            [out, exceptions] = utils.exec_all(False, thread6_info)
            st.log([out, exceptions])
    else:
        bgpapi.cleanup_bgp_config([data[dut] for dut in data['leaf_routers']+data['spine_routers']])

    return result


def l3tc_vrfipv4v6_bgp_network_leafspine_config_unconfig(config='yes', vrf_type='all', config_type='all'):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :return:
    """
    st.banner("{}Configuring network route  between Spine and Leaf nodes.".format('Un' if config != 'yes' else ''))

    fixed_nw_info['ipv4'] = SpyTestDict()
    fixed_nw_info['ipv6'] = SpyTestDict()

    result = True
    thread4_info = []
    thread6_info = []

    dut_name_map = SpyTestDict()
    dut_name_list = {each:[] for each in data['spine_routers'] + data['leaf_routers']}
    for dut_idx, dut_name in enumerate(dut_name_list, start=1):
        dut_name_map[dut_name] = "D{}".format(dut_idx)

    if topo_info:
        for dut_idx, dut_name in enumerate(dut_name_list, start=1):
            fixed_nw_info['ipv4'][dut_name] = []
            fixed_nw_info['ipv6'][dut_name] = []

            actual_dut = data[dut_name]

            if config_type == 'ipv4' or config_type == 'all':
                afamily = 'ipv4'
                dut_port_list = [each for each in topo_info[afamily][dut_name] if each[2] in dut_name_map]
                for port_idx, each_port in enumerate(dut_port_list, start=1):
                    port_lnk_num = each_port[5]
                    networkip = "{}.{}.{}.0/24".format(data['ipv4_nw_addres_first_octet'], dut_idx, port_idx)

                    if config == 'yes':
                        fixed_nw_info[afamily][dut_name].append(networkip)
                        fixed_nw_info[afamily][dut_name].append(networkip)

                    if as_info:
                        bgpapi.config_bgp(actual_dut, config=config,
                                          addr_family=afamily, local_as=as_info[dut_name],
                                          config_type_list=["network"], network=networkip)
                    '''
                    [out, exceptions] = \
                           utils.exec_all(fast_start, [[bgpapi.config_bgp, actual_dut, config=config,
                                                          addr_family=afamily, local_as=as_info[dut_name],
                                                          config_type_list=["network"], network=networkip]])
                    thread4_info.append(utils.ExecAllFunc(bgpapi.config_bgp, actual_dut, config=config,
                                                          addr_family=afamily, local_as=as_info[dut_name],
                                                          config_type_list=["network"], network=networkip))
                    '''

            if config_type == 'ipv6' or config_type == 'all':
                afamily = 'ipv6'
                dut_port_list = [each for each in topo_info[afamily][dut_name] if each[2] in dut_name_map]
                for port_idx, each_port in enumerate(dut_port_list, start=1):
                    port_lnk_num = each_port[5]
                    networkip = "{}:{}:{}::2/64".format(data['ipv6_nw_addres_first_octet'], dut_idx, port_idx)

                    fixed_nw_info[afamily][dut_name].append(networkip)
                    fixed_nw_info[afamily][dut_name].append(networkip)

                    if as_info:
                        bgpapi.config_bgp(actual_dut, config=config,
                                          addr_family=afamily, local_as=as_info[dut_name],
                                          config_type_list=["network"], network=networkip)
                    '''
                    [out, exceptions] = \
                           utils.exec_all(fast_start, [[bgpapi.config_bgp, actual_dut, config=config,
                                                          addr_family=afamily, local_as=as_info[dut_name],
                                                          config_type_list=["network"], network= networkip]])
                    thread6_info.append(utils.ExecAllFunc(bgpapi.config_bgp, actual_dut, config=config,
                                                          addr_family=afamily, local_as=as_info[dut_name],
                                                          config_type_list=["network"], network= networkip))
                    '''
    else:
        st.log("Topology information not available")
        return False

    '''
    if config_type == 'ipv4' or config_type == 'all':
        [out, exceptions] = utils.exec_all(fast_start, thread4_info)
        st.log([out, exceptions])

    if config_type == 'ipv6' or config_type == 'all':
        [out, exceptions] = utils.exec_all(fast_start, thread6_info)
        st.log([out, exceptions])
    '''
    return result


def l3tc_vrfipv4v6_address_leafspine_bgp_check(config_type='all'):
    """

    :param config_type:
    :return:
    """
    st.banner("BGP Neighbor Checking between Spine and Leaf nodes.")
    ipv4_adr = data['ipv4_addres_first_octet']
    ipv6_adr = data['ipv6_addres_first_octet']
    result = True
    k = 1
    for leaf in data['leaf_routers']:
        spine_neigh_list, leaf_neigh_list, spine_neigh6_list, leaf_neigh6_list = [], [], [], []
        for spine in data['spine_routers']:
            link = 1
            for local, remote in underlay_info['links'][leaf][spine]:
                if config_type == 'ipv4' or config_type == 'all':
                    ipaddr1 = "{}.{}.{}.1".format(ipv4_adr, k, link)
                    ipaddr2 = "{}.{}.{}.2".format(ipv4_adr, k, link)
                    spine_neigh_list.append(ipaddr2)
                    leaf_neigh_list.append(ipaddr1)

                if config_type == 'ipv6' or config_type == 'all':
                    ip6addr_1 = "{}:{}:{}::1".format(ipv6_adr, k, link)
                    ip6addr_2 = "{}:{}:{}::2".format(ipv6_adr, k, link)
                    spine_neigh6_list.append(ip6addr_2)
                    leaf_neigh6_list.append(ip6addr_1)
                link += 1
            k += 1

        if config_type == 'ipv4' or config_type == 'all':
            neigh_list = list(set(spine_neigh_list))
            if not bgpapi.verify_bgp_summary(data[leaf], family='ipv4', neighbor=neigh_list, state='Established'):
                st.log("{} - Neighbor {} is failed to Establish".format(data[leaf], neigh_list))
                result = False

        if config_type == 'ipv6' or config_type == 'all':
            neigh_list = list(set(spine_neigh6_list))
            if not bgpapi.verify_bgp_summary(data[leaf], family='ipv6', neighbor=neigh_list, state='Established'):
                st.log("{} - Neighbor {} is failed to Establish".format(data[leaf], neigh_list))
                result = False

    return result


def l3tc_vrfipv4v6_address_leafspine_tg_config_unconfig(config='yes', vrf_type='all', config_type='all'):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :return:
    """
    st.banner("{}Configuring IP Addresses to TG connected interfaces and on TG.".
              format('Un' if config != 'yes' else ''))

    global tg_connected_routers
    config = 'add' if config == 'yes' else 'remove'
    max_mem = int(data['l3_max_tg_links_each_leaf_spine'])
    mas_addr_spine = data['mac_addres_tg_src_spine']
    mas_addr_leaf = data['mac_addres_tg_src_leaf']
    ipv4_adr_spine = data['ipv4_addres_first_octet_tg_spine']
    ipv6_adr_spine = data['ipv6_addres_first_octet_tg_spine']
    ipv4_adr_leaf = data['ipv4_addres_first_octet_tg_leaf']
    ipv6_adr_leaf = data['ipv6_addres_first_octet_tg_leaf']
    tg_in_spine = sum([len(st.get_tg_links(data[spine])) for spine in data['spine_routers']])
    tg_in_leaf = sum([len(st.get_tg_links(data[leaf])) for leaf in data['leaf_routers']])
    mac_list_spine = utils_obj.get_mac_address(mas_addr_spine, start=1, end=tg_in_spine+1, step=1)
    mac_list_leaf = utils_obj.get_mac_address(mas_addr_leaf, start=1, end=tg_in_leaf+1, step=1)

    result = True

    # Logic to scan and pick TG ports in 1:1 or N:N topology.
    tg_connected_routers = []
    step = 0
    if len(data['leaf_routers']) == 1 and (len(data['spine_routers']) == 1 or len(data['spine_routers']) >= 2):
        if not len(st.get_tg_links(data[data['leaf_routers'][0]])) >= 1:
            step += 1
        if not len(st.get_tg_links(data[data['spine_routers'][0]])) >= 1:
            step += 1
        if step:
            st.error("Expecting altest one TG port connected to each of Leaf1 and Spine1 in 1:1 topology case.")
            st.error("Failed due to TG ports shortage")
            st.report_env_fail('test_case_not_executeds')
        else:
            st.log("TG Mode 1:1 mode")
            tg_connected_routers.append(data['leaf_routers'][0])
            tg_connected_routers.append(data['spine_routers'][0])
            st.log("tg_connected_routers {}".format(tg_connected_routers))
    else:
        st.log("TG Mode N:N mode")
        start, stop = 0, 0
        for leaf in data['leaf_routers']:
            if len(st.get_tg_links(data[leaf])) >= 1:
                if not start:
                    start = leaf
                    tg_connected_routers.append(leaf)
        for leaf in data['leaf_routers'][::-1]:
            if len(st.get_tg_links(data[leaf])) >= 1:
                if not stop:
                    stop = leaf
                    tg_connected_routers.append(leaf)
        st.log("start {}".format(start))
        st.log("stop {}".format(stop))
        st.log("tg_connected_routers {}".format(tg_connected_routers))
        if start == stop:
            st.error("Expecting altest one TG port connected to atlest 2 of Leafs in N:N topology case.")
            st.error("Failed due to TG ports shortage")
            st.report_env_fail('test_case_not_executeds')

    i = 0
    for j, device_type in enumerate(tg_connected_routers, start=1):
        if config == 'add':
            tg_info[device_type] = SpyTestDict()
            tg_info[device_type]['ipv4'] = SpyTestDict()
            tg_info[device_type]['ipv6'] = SpyTestDict()

        link = 1
        for local, partner, remote in st.get_tg_links(data[device_type]):
            if link <= max_mem:
                # TG reset.
                tg = tgen_obj_dict[partner]
                tg.tg_traffic_control(action="reset", port_handle=tg.get_port_handle(remote))

                if config_type == 'ipv4' or config_type == 'all':
                    ipaddr1 = "{}.{}.{}.1".format(ipv4_adr_leaf, j, link)
                    ipaddr2 = "{}.{}.{}.2".format(ipv4_adr_leaf, j, link)

                    ipapi.config_ip_addr_interface(dut=data[device_type], interface_name=local,
                                                   ip_address=ipaddr1, subnet='24', family="ipv4", config=config)
                    if config == 'add':
                        tg_info[device_type]['ipv4'][local] = create_routing_interface_on_tg(partner, remote, ipaddr2,
                                                                                             '255.255.255.0',
                                                                                             ipaddr1, config=config,
                                                                                             handle='', af='ipv4')
                    else:
                        tg_info[device_type]['ipv4'][local] = create_routing_interface_on_tg(partner, remote, ipaddr2,
                                                     '255.255.255.0', ipaddr1, config=config,
                                                     handle=tg_info[device_type]['ipv4'][local][2], af='ipv4')
                    tg_info[device_type]['ipv4'][local].append([ipaddr1, ipaddr2])

                if config_type == 'ipv6' or config_type == 'all':
                    ip6addr_1 = "{}:{}:{}::1".format(ipv6_adr_leaf, j, link)
                    ip6addr_2 = "{}:{}:{}::2".format(ipv6_adr_leaf, j, link)

                    ipapi.config_ip_addr_interface(dut=data[device_type], interface_name=local,
                                                   ip_address=ip6addr_1, subnet='64', family="ipv6", config=config)
                    if config == 'add':
                        tg_info[device_type]['ipv6'][local] = create_routing_interface_on_tg(partner, remote,
                                                                                             ip6addr_2, '64',
                                                                                             ip6addr_1, config=config,
                                                                                             handle='', af='ipv6')
                    else:
                        tg_info[device_type]['ipv6'][local] = create_routing_interface_on_tg(partner, remote,
                                                                                             ip6addr_2, '64',
                                                                                             ip6addr_1, config=config,
                                                                                             handle=tg_info[device_type]
                                                                                             ['ipv6'][local][2],
                                                                                             af='ipv6')
                    tg_info[device_type]['ipv6'][local].append([ip6addr_1, ip6addr_2])

                i += 1
                link += 1

    return result, tg_info


def l3tc_vrfipv4v6_address_leafspine_tg_bgp_config(config='yes', vrf_type='all', config_type='all',
                                                   class_reconfig='No'):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :param class_reconfig:
    :return:
    """
    st.banner("{}Configuring BGP on TG connected interafces and on TG.".format('Un' if config != 'yes' else ''))
    st.banner("OPTION class_reconfig is provided : {}".format(class_reconfig))

    config = 'add' if config == 'yes' else 'remove'
    max_mem = int(data['l3_max_tg_links_each_leaf_spine'])
    ipv4_adr_leaf = data['ipv4_addres_first_octet_tg_leaf']
    ipv6_adr_leaf = data['ipv6_addres_first_octet_tg_leaf']

    spine_as = int(data['spine_as'])
    leaf_as = int(data['leaf_as'])
    spine_tg_as = int(data['spine_tg_as'])
    leaf_tg_as = int(data['leaf_tg_as'])

    result = True
    if config == "add":
        i = 0
        for j, device_type in enumerate(tg_connected_routers, start=1):
            tg_neigh_list, leaf_neigh_list, tg_neigh6_list, leaf_neigh6_list = [], [], [], []
            link = 1
            tg_as = leaf_tg_as
            dut_as = leaf_as
            if 'spine' in device_type:
                tg_as = spine_tg_as
                dut_as = spine_as

            for local, partner, remote in st.get_tg_links(data[device_type]):
                if link <= max_mem:
                    if config_type == 'ipv4' or config_type == 'all':
                        ipaddr1 = "{}.{}.{}.1".format(ipv4_adr_leaf, j, link)
                        ipaddr2 = "{}.{}.{}.2".format(ipv4_adr_leaf, j, link)
                        tg_neigh_list.append(ipaddr2)
                        leaf_neigh_list.append(ipaddr1)
                        if class_reconfig == "No":
                            [tg, tg_ph_x, h1, ip_info] = tg_info[device_type]['ipv4'][local]
                            rv = config_bgp_on_tg(tg, h1, dut_as, tg_as+j-1, ipaddr1, action='start', af='ipv4')
                            tg_info[device_type]['ipv4'][local].append(rv)

                    if config_type == 'ipv6' or config_type == 'all':
                        ip6addr_1 = "{}:{}:{}::1".format(ipv6_adr_leaf, j, link)
                        ip6addr_2 = "{}:{}:{}::2".format(ipv6_adr_leaf, j, link)
                        tg_neigh6_list.append(ip6addr_2)
                        leaf_neigh6_list.append(ip6addr_1)
                        if class_reconfig == "No":
                            [tg, tg_ph_x, h1, ip_info] = tg_info[device_type]['ipv6'][local]
                            rv = config_bgp_on_tg(tg, h1, dut_as, tg_as+j-1, ip6addr_1, action='start', af='ipv6')
                            tg_info[device_type]['ipv6'][local].append(rv)

                    i += 1
                    link += 1

            if config_type == 'ipv4' or config_type == 'all':
                bgpapi.config_bgp_multi_neigh_use_peergroup(data[device_type], local_asn=dut_as,
                                                            peer_grp_name='leaf_tg', remote_asn=tg_as+j-1,
                                                            neigh_ip_list=tg_neigh_list, family='ipv4', activate=1)

            if config_type == 'ipv6' or config_type == 'all':
                bgpapi.config_bgp_multi_neigh_use_peergroup(data[device_type], local_asn=dut_as,
                                                            peer_grp_name='leaf_tg6', remote_asn=tg_as+j-1,
                                                            neigh_ip_list=tg_neigh6_list, family='ipv6', activate=1)

    else:
        bgpapi.cleanup_bgp_config([data[dut] for dut in data['leaf_routers']+data['spine_routers']])

    return result, tg_info


def l3tc_vrfipv4v6_address_leafspine_rr_tg_bgp_config(config='yes', vrf_type='all', config_type='all', **kwargs):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :param kwargs:
    :return:
    """
    st.banner("{}Configuring BGP on TG connected interafces and on TG.".format('Un' if config != 'yes' else ''))

    config = 'add' if config == 'yes' else 'remove'
    max_mem = int(data['l3_max_tg_links_each_leaf_spine'])
    mas_addr_spine = data['mac_addres_tg_src_spine']
    mas_addr_leaf = data['mac_addres_tg_src_leaf']
    ipv4_adr_spine = data['ipv4_addres_first_octet_tg_spine']
    ipv6_adr_spine = data['ipv6_addres_first_octet_tg_spine']
    ipv4_adr_leaf = data['ipv4_addres_first_octet_tg_leaf']
    ipv6_adr_leaf = data['ipv6_addres_first_octet_tg_leaf']

    spine_as = int(data['spine_as'])
    leaf_as = int(data['leaf_as'])
    leaf_tg_as = int(data['leaf_tg_as'])
    spine_tg_as = int(data['spine_tg_as'])
    if kwargs.has_key('rr_enable'):
        spine_tg_as = spine_as
        leaf_as = spine_as

    result = True
    if config == "add":
        i = 0
        for j, device_type in enumerate(tg_connected_routers, start=1):
            tg_neigh_list, leaf_neigh_list, tg_neigh6_list, leaf_neigh6_list = [], [], [], []
            link = 1
            tg_as = leaf_tg_as
            dut_as = leaf_as
            if 'spine' in device_type:
                tg_as = spine_tg_as
                dut_as = spine_as

            for local, partner, remote in st.get_tg_links(data[device_type]):
                if link <= max_mem:
                    if config_type == 'ipv4' or config_type == 'all':
                        ipaddr1 = "{}.{}.{}.1".format(ipv4_adr_leaf, j, link)
                        ipaddr2 = "{}.{}.{}.2".format(ipv4_adr_leaf, j, link)
                        tg_neigh_list.append(ipaddr2)
                        leaf_neigh_list.append(ipaddr1)
                        [tg, tg_ph_x, h1, ip_info] = tg_info[device_type]['ipv4'][local]
                        rv = config_bgp_on_tg(tg, h1, dut_as, tg_as, ipaddr1, action='start', af='ipv4')
                        tg_info[device_type]['ipv4'][local].append(rv)

                    if config_type == 'ipv6' or config_type == 'all':
                        ip6addr_1 = "{}:{}:{}::1".format(ipv6_adr_leaf, j, link)
                        ip6addr_2 = "{}:{}:{}::2".format(ipv6_adr_leaf, j, link)
                        tg_neigh6_list.append(ip6addr_2)
                        leaf_neigh6_list.append(ip6addr_1)

                        [tg, tg_ph_x, h1, ip_info] = tg_info[device_type]['ipv6'][local]
                        rv = config_bgp_on_tg(tg, h1, dut_as, tg_as, ip6addr_1, action='start', af='ipv6')
                        tg_info[device_type]['ipv6'][local].append(rv)

                    i += 1
                    link += 1

            if config_type == 'ipv4' or config_type == 'all':
                bgpapi.config_bgp_multi_neigh_use_peergroup(data[device_type], local_asn=dut_as,
                                                            peer_grp_name='leaf_tg', remote_asn=tg_as,
                                                            neigh_ip_list=tg_neigh_list, family='ipv4', activate=1)

            if config_type == 'ipv6' or config_type == 'all':
                bgpapi.config_bgp_multi_neigh_use_peergroup(data[device_type], local_asn=dut_as,
                                                            peer_grp_name='leaf_tg6', remote_asn=tg_as,
                                                            neigh_ip_list=tg_neigh6_list, family='ipv6', activate=1)

    else:
        bgpapi.cleanup_bgp_config([data[dut] for dut in data['leaf_routers']+data['spine_routers']])

    return result, tg_info


def create_routing_interface_on_tg(tg, tg_port, intf_ip_addr, netmask, gateway, config, handle='none', af='ipv4'):
    """

    :param tg:
    :param tg_port:
    :param intf_ip_addr:
    :param netmask:
    :param gateway:
    :param af:
    :return:
    """
    tg = tgen_obj_dict[tg]
    tg_ph_x = tg.get_port_handle(tg_port)
    config = 'config' if config == 'add' else 'destroy'
    if af == 'ipv4':
        if config == 'config':
            h1 = tg.tg_interface_config(port_handle=tg_ph_x, mode=config, intf_ip_addr=intf_ip_addr, gateway=gateway,
                                        netmask=netmask, arp_send_req='1')
        else:
            tg.tg_interface_config(port_handle=tg_ph_x, handle=handle['handle'], mode=config)
    else:
        if config == 'config':
            h1 = tg.tg_interface_config(port_handle=tg_ph_x, mode=config, ipv6_intf_addr=intf_ip_addr,
                                        ipv6_prefix_length=netmask, ipv6_gateway=gateway, arp_send_req='1')
        else:
            tg.tg_interface_config(port_handle=tg_ph_x, handle=handle['handle'], mode=config)

    if config == 'config':
        st.log("#"*30)
        st.log("h1 = {}".format(h1))
        st.log("#"*30)
        return [tg, tg_ph_x, h1]
    else:
        return [tg, tg_ph_x]


def config_bgp_on_tg(tg, handle, local_asn, tg_asn, local_ipaddr, action='start', af='ipv4'):
    """

    :param tg:
    :param handle:
    :param local_asn:
    :param tg_asn:
    :param local_ipaddr:
    :param action:
    :param af:
    :return:
    """

    # STC / IXIA
    handle_key_v4 = 'handle'
    handle_key_v6 = 'handle'
    if af == 'ipv4':
        bgp_rtr1 = tg.tg_emulation_bgp_config(handle=handle[handle_key_v4], mode='enable', active_connect_enable='1',
                                              local_as=tg_asn, remote_as=local_asn, remote_ip_addr=local_ipaddr,
                                              enable_4_byte_as='1')
        st.wait(5)
        tg.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')

    else:

        bgp_rtr1 = tg.tg_emulation_bgp_config(handle=handle[handle_key_v6], mode='enable', ip_version='6',
                                              active_connect_enable='1', local_as=tg_asn, remote_as=local_asn,
                                              remote_ipv6_addr=local_ipaddr, enable_4_byte_as='1')
        st.wait(5)
        tg.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')

    st.log("#"*30)
    st.log("bgp_rtr1 = {}".format(bgp_rtr1))
    st.log("#"*30)
    return bgp_rtr1


def get_tg_topology_leafspine_bgp(dut_type, max_tg_links, nodes, af='all'):
    """

    :param dut_type:
    :param max_tg_links:
    :param nodes:
    :param af:
    :return:
    """
    st.banner("Getting TG topology info")
    st.log("dut_type {}, max_tg_links {}, nodes {}".format(dut_type, max_tg_links, nodes))

    rv = []
    if dut_type == '':
        return rv
    # For 1:1 mode TG handled here, dut_type over written
    if 'spine' in ','.join(tg_connected_routers) and nodes >= 2:
        dut_type = "leaf-spine"

    final_rv = SpyTestDict()
    if dut_type in ['leaf-spine', 'spine-leaf']:
        temp = {}
        for i, spine in enumerate(data['spine_routers'], start=1):
            tg_list = st.get_tg_links(data[spine])
            if int(max_tg_links) <= len(tg_list):
                temp[spine] = tg_list
        for i, leaf in enumerate(data['leaf_routers'], start=1):
            tg_list = st.get_tg_links(data[leaf])
            if int(max_tg_links) <= len(tg_list):
                temp[leaf] = tg_list

        if int(nodes) <= len(temp):
            for each in temp:
                final_rv[each] = random.sample(temp[each][:int(max_tg_links)], k=int(max_tg_links))
        else:
            st.log("Requested topology not found.")
            return False
        while True:
            # TODO : Need to check this - 'leaf-spine', 'spine-leaf'
            rv = {each: final_rv[each] for each in random.sample(final_rv.keys(), k=int(nodes))}
            if 'spine' in str(rv.keys()) and 'leaf' in str(rv.keys()):
                break

    elif dut_type == 'spine':
        temp = {}
        for i, spine in enumerate(data['spine_routers'], start=1):
            tg_list = st.get_tg_links(data[spine])
            if int(max_tg_links) <= len(tg_list):
                temp[spine] = tg_list

        if int(nodes) <= len(temp):
            for each in temp:
                final_rv[each] = random.sample(temp[each][:int(max_tg_links)], k=int(max_tg_links))
        else:
            st.log("Requested topology not found.")
            return False
        rv = {each: final_rv[each] for each in random.sample(final_rv.keys(), k=int(nodes))}

    elif dut_type == 'leaf':
        temp = {}
        for i, leaf in enumerate(data['leaf_routers'], start=1):
            tg_list = st.get_tg_links(data[leaf])
            if int(max_tg_links) <= len(tg_list):
                temp[leaf] = tg_list

        if int(nodes) <= len(temp):
            for each in temp:
                final_rv[each] = random.sample(temp[each][:int(max_tg_links)], k=int(max_tg_links))
        else:
            st.log("Requested topology not found.")
            return False
        rv = {each: final_rv[each] for each in random.sample(final_rv.keys(), k=int(nodes))}

    rv = get_leaf_spine_topology_info(rv, af)
    return rv


def get_leaf_spine_topology_info(input=[], af='all'):
    """

    :param input:
    :param af:
    :return:
    """
    max_mem = int(data['l3_max_tg_links_each_leaf_spine'])
    st.banner("Getting topology info")
    if not input:
        input = {each:[] for each in data['spine_routers']+data['leaf_routers']}
        temp = {}
        for i, dut_type in enumerate(input, start=1):
            if dut_type in tg_connected_routers:
                tg_list = st.get_tg_links(data[dut_type])
                if int(max_mem) <= len(tg_list):
                    temp[dut_type] = tg_list
        for each in temp:
            input[each] = random.sample(temp[each][:int(max_mem)], k=int(max_mem))

    st.log("input = {}".format(input))
    debug_print()

    if af == "ipv4":
        afmly = ['ipv4']
    elif af == "ipv6":
        afmly = ['ipv6']
    else:
        afmly = ['ipv4', 'ipv6']
    st.log("afmly = {}".format(afmly))

    rv = SpyTestDict()
    temp = SpyTestDict()
    rv['dut_list'] = []
    rv['tg_dut_list'] = []
    rv['tg_dut_list_name'] = []
    rv['leaf_list'] = []
    rv['spine_list'] = []
    for i, dut_type in enumerate(input, start=1):
        temp[dut_type] = "D{}".format(i)
        rv["D{}_name".format(i)] = dut_type
        rv["D{}".format(i)] = data[dut_type]

        # List items
        rv['dut_list'].append(data[dut_type])
        if 'leaf' in dut_type:
            rv['leaf_list'].append(data[dut_type])
        if 'spine' in dut_type:
            rv['spine_list'].append(data[dut_type])
        if dut_type in tg_connected_routers:
            rv['tg_dut_list'].append(data[dut_type])
            rv['tg_dut_list_name'].append("D{}".format(i))

    if tg_info:
        for i, dut_type in enumerate(input, start=1):
            if dut_type in tg_connected_routers:
                for j, each_tgport in enumerate(input[dut_type], start=1):
                    rv["{}T1P{}".format(temp[dut_type], j)] = each_tgport[0]
                    rv["T1{}P{}".format(temp[dut_type], j)] = each_tgport[2]
                    for each_af in afmly:
                        rv["T1{}P{}_tg_obj".format(temp[dut_type], j)] = tg_info[dut_type][each_af][each_tgport[0]][0]
                        rv["T1{}P{}_{}_tg_ph".format(temp[dut_type], j, each_af)] = \
                            tg_info[dut_type][each_af][each_tgport[0]][1]
                        rv["T1{}P{}_{}_tg_ih".format(temp[dut_type], j, each_af)] = \
                            tg_info[dut_type][each_af][each_tgport[0]][2]
                        rv["T1{}P{}_{}_neigh".format(temp[dut_type], j, each_af)] = \
                            tg_info[dut_type][each_af][each_tgport[0]][3][0]
                        rv["T1{}P{}_{}".format(temp[dut_type], j, each_af)] = \
                            tg_info[dut_type][each_af][each_tgport[0]][3][1]
                        rv["T1{}P{}_{}_tg_bh".format(temp[dut_type], j, each_af)] = \
                            tg_info[dut_type][each_af][each_tgport[0]][4]

    if topo_info:
        for i, dut_type in enumerate(input, start=1):
            for each_af in afmly:
                if each_af == "ipv4":
                    list_of_port = [each for each in topo_info[each_af][dut_type] if each[2] in temp]
                    for each_port in list_of_port:
                        k = each_port[5]
                        rv["{}{}P{}".format(temp[dut_type], temp[each_port[2]], k)] = each_port[0]
                        rv["{}{}P{}_ipv4".format(temp[dut_type], temp[each_port[2]], k)] = each_port[1]
                        rv["{}{}P{}_neigh".format(temp[dut_type], temp[each_port[2]], k)] = data[each_port[2]]
                        rv["{}{}P{}_neigh_ipv4".format(temp[dut_type], temp[each_port[2]], k)] = each_port[4]
                        rv["{}{}P{}_neigh_port".format(temp[dut_type], temp[each_port[2]], k)] = each_port[3]

                        rv["{}{}P{}".format(temp[each_port[2]], temp[dut_type], k)] = each_port[3]
                        rv["{}{}P{}_ipv4".format(temp[each_port[2]], temp[dut_type], k)] = each_port[4]
                        rv["{}{}P{}_neigh".format(temp[each_port[2]], temp[dut_type], k)] = data[dut_type]
                        rv["{}{}P{}_neigh_ipv4".format(temp[each_port[2]], temp[dut_type], k)] = each_port[1]
                        rv["{}{}P{}_neigh_port".format(temp[each_port[2]], temp[dut_type], k)] = each_port[0]

                if each_af == "ipv6":
                    list_of_port = [each for each in topo_info[each_af][dut_type] if each[2] in temp]
                    for each_port in list_of_port:
                        k = each_port[5]
                        rv["{}{}P{}".format(temp[dut_type], temp[each_port[2]], k)] = each_port[0]
                        rv["{}{}P{}_ipv6".format(temp[dut_type], temp[each_port[2]], k)] = each_port[1]
                        rv["{}{}P{}_neigh".format(temp[dut_type], temp[each_port[2]], k)] = data[each_port[2]]
                        rv["{}{}P{}_neigh_ipv6".format(temp[dut_type], temp[each_port[2]], k)] = each_port[4]
                        rv["{}{}P{}_neigh_port".format(temp[dut_type], temp[each_port[2]], k)] = each_port[3]

                        rv["{}{}P{}".format(temp[each_port[2]], temp[dut_type], k)] = each_port[3]
                        rv["{}{}P{}_ipv6".format(temp[each_port[2]], temp[dut_type], k)] = each_port[4]
                        rv["{}{}P{}_neigh".format(temp[each_port[2]], temp[dut_type], k)] = data[dut_type]
                        rv["{}{}P{}_neigh_ipv6".format(temp[each_port[2]], temp[dut_type], k)] = each_port[1]
                        rv["{}{}P{}_neigh_port".format(temp[each_port[2]], temp[dut_type], k)] = each_port[0]

    for i, dut_type in enumerate(input, start=1):
        if as_info:
            rv["{}_as".format(temp[dut_type])] = as_info[dut_type]
        for each_af in afmly:
            if loopback_info:
                if each_af == "ipv4":
                    rv["{}_loopback_ipv4".format(temp[dut_type])] = loopback_info[each_af][dut_type]
                if each_af == "ipv6":
                    rv["{}_loopback_ipv6".format(temp[dut_type])] = loopback_info[each_af][dut_type]

    st.log(pprint.pformat(rv, width=2))
    return rv


def get_topo_info():
    """

    :return:
    """
    return topo_info


def get_tg_info():
    """

    :return:
    """
    return tg_info


def get_loopback_info():
    """

    :return:
    """
    return loopback_info


def get_as_info():
    """

    :return:
    """
    return as_info


def get_static_rt_info():
    """

    :return:
    """
    return static_rt_info


def get_fixed_nw_info():
    """

    :return:
    """
    return fixed_nw_info


def get_underlay_info():
    """

    :return:
    """
    return underlay_info


def get_route_attribute(output, parameter, **kwargs):
    st.log("GET ROUTE ATTR -- {}".format(output))
    st.log("PARAMS -- {}".format(parameter))
    st.log("KWARGS -- {}".format(kwargs))
    nw_route = filter_and_select(output, [parameter], kwargs)
    st.log("NW_ROUTE -- {}".format(nw_route))
    if not nw_route:
        st.report_fail("entry_not_found")
    return nw_route[0][parameter]


def debug_print():
    """

    :return:
    """
    st.log("get_tg_info(): \n{}  ".format(get_tg_info()))
    st.log("get_topo_info():  \n{}  ".format(get_topo_info()))
    st.log("get_as_info():  \n{}  ".format(get_as_info()))
    st.log("get_loopback_info():  \n{}  ".format(get_loopback_info()))
    st.log("get_static_rt_info():  \n{}  ".format(get_static_rt_info()))
    st.log("get_fixed_nw_info():  \n{}  ".format(get_fixed_nw_info()))
    st.log("get_underlay_info():  \n{}  ".format(get_underlay_info()))


def configure_base_for_route_adv_and_filter(dut1, dut2, topo, config_items):
    """

    :param dut1:
    :param dut2:
    :param topo:
    :param config_items:
    :return:
    """

    use_global_rmap = rmapapi.RouteMap("UseGlobal")
    use_global_rmap.add_permit_sequence('10')
    use_global_rmap.add_sequence_set_ipv6_next_hop_prefer_global('10')

    config_items['dut1'] = []
    config_items['dut2'] = []

    bgpapi.config_bgp_network_advertise(dut1, topo['dut1_as'], '101.1.1.0/24')
    bgpapi.config_bgp_network_advertise(dut1, topo['dut1_as'], '102.1.1.0/24')
    bgpapi.config_bgp_network_advertise(dut1, topo['dut1_as'], '101:1::/64', addr_family='ipv6')
    bgpapi.config_bgp_network_advertise(dut1, topo['dut1_as'], '102:1::/64', addr_family='ipv6')

    bgpapi.config_bgp_network_advertise(dut2, topo['dut2_as'], '201.1.1.0/24')
    bgpapi.config_bgp_network_advertise(dut2, topo['dut2_as'], '202.1.1.0/24')
    bgpapi.config_bgp_network_advertise(dut2, topo['dut2_as'], '201:1::/64', addr_family='ipv6')
    bgpapi.config_bgp_network_advertise(dut2, topo['dut2_as'], '202:1::/64', addr_family='ipv6')

    use_global_rmap.execute_command(dut1)
    config_items['dut1'].append(use_global_rmap)

    bgpapi.config_bgp(dut=dut1, local_as=topo['dut1_as'], addr_family='ipv6',
                      config='yes',
                      neighbor=topo['dut2_addr_ipv6'],
                      config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in')

    use_global_rmap.execute_command(dut2)
    config_items['dut2'].append(use_global_rmap)

    bgpapi.config_bgp(dut=dut2, local_as=topo['dut2_as'], addr_family='ipv6',
                      config='yes',
                      neighbor=topo['dut1_addr_ipv6'],
                      config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in')

    leaf_ip_acl_11 = ipapi.AccessList("11")
    leaf_ip_acl_11.add_match_deny_sequence('102.1.1.0/24')
    leaf_ip_acl_11.add_match_permit_sequence('any')

    leaf_ip_acl_12 = ipapi.AccessList("12", family='ipv6')
    leaf_ip_acl_12.add_match_deny_sequence('102:1::/64')
    leaf_ip_acl_12.add_match_permit_sequence('any')

    leaf_prefix_list_202 = ipapi.PrefixList("PREFIXOUT")
    leaf_prefix_list_202.add_match_deny_sequence('202.1.1.0/24')
    leaf_prefix_list_202.add_match_permit_sequence('any')

    leaf_prefix_list_202_v6 = ipapi.PrefixList("PREFIXOUT6", family='ipv6')
    leaf_prefix_list_202_v6.add_match_deny_sequence('202:1::/64')
    leaf_prefix_list_202_v6.add_match_permit_sequence('any')

    aspath_acl = bgpapi.ASPathAccessList("FILTER")
    aspath_acl.add_match_deny_sequence(['{}'.format(topo['dut1_as'])])

    leaf1_cmd = leaf_ip_acl_11.config_command_string() + leaf_ip_acl_12.config_command_string() \
                + leaf_prefix_list_202.config_command_string() + leaf_prefix_list_202_v6.config_command_string() \
                + aspath_acl.config_command_string()
    config_items['dut2'].append(leaf_ip_acl_11)
    config_items['dut2'].append(leaf_ip_acl_12)
    config_items['dut2'].append(leaf_prefix_list_202)
    config_items['dut2'].append(leaf_prefix_list_202_v6)
    config_items['dut2'].append(aspath_acl)

    leaf_prefix_list_101 = ipapi.PrefixList("MATCHPREFIX1")
    leaf_prefix_list_101.add_match_permit_sequence('101.1.1.0/24')
    leaf_prefix_list_101.add_match_deny_sequence('any')
    leaf_prefix_list_102 = ipapi.PrefixList("MATCHPREFIX2")
    leaf_prefix_list_102.add_match_permit_sequence('102.1.1.0/24')
    leaf_prefix_list_102.add_match_deny_sequence('any')
    leaf_prefix_list_101_v6 = ipapi.PrefixList("MATCHPREFIX61", family='ipv6')
    leaf_prefix_list_101_v6.add_match_permit_sequence('101:1::/64')
    leaf_prefix_list_101_v6.add_match_deny_sequence('any')
    leaf_prefix_list_102_v6 = ipapi.PrefixList("MATCHPREFIX62", family='ipv6')
    leaf_prefix_list_102_v6.add_match_permit_sequence('102:1::/64')
    leaf_prefix_list_102_v6.add_match_deny_sequence('any')

    leaf1_cmd += leaf_prefix_list_101.config_command_string() + leaf_prefix_list_102.config_command_string() \
                 + leaf_prefix_list_101_v6.config_command_string() + leaf_prefix_list_102_v6.config_command_string()
    config_items['dut2'].append(leaf_prefix_list_101)
    config_items['dut2'].append(leaf_prefix_list_102)
    config_items['dut2'].append(leaf_prefix_list_101_v6)
    config_items['dut2'].append(leaf_prefix_list_102_v6)

    leaf_rmap_setprops = rmapapi.RouteMap('SETPROPS')
    leaf_rmap_setprops.add_permit_sequence('10')
    leaf_rmap_setprops.add_sequence_match_prefix_list('10', 'MATCHPREFIX1')
    leaf_rmap_setprops.add_sequence_set_local_preference('10', '200')
    leaf_rmap_setprops.add_permit_sequence('20')
    leaf_rmap_setprops.add_sequence_match_prefix_list('20', 'MATCHPREFIX2')
    leaf_rmap_setprops.add_sequence_set_metric('20', '400')

    leaf_rmap_setprops_v6 = rmapapi.RouteMap('SETPROPS6')
    leaf_rmap_setprops_v6.add_permit_sequence('10')
    leaf_rmap_setprops_v6.add_sequence_set_ipv6_next_hop_prefer_global('10')
    leaf_rmap_setprops_v6.add_sequence_match_prefix_list('10', 'MATCHPREFIX61', family='ipv6')
    leaf_rmap_setprops_v6.add_sequence_set_local_preference('10', '6200')
    leaf_rmap_setprops_v6.add_permit_sequence('20')
    leaf_rmap_setprops_v6.add_sequence_set_ipv6_next_hop_prefer_global('20')
    leaf_rmap_setprops_v6.add_sequence_match_prefix_list('20', 'MATCHPREFIX62', family='ipv6')
    leaf_rmap_setprops_v6.add_sequence_set_metric('20', '6400')

    leaf1_cmd += leaf_rmap_setprops.config_command_string() + leaf_rmap_setprops_v6.config_command_string()
    config_items['dut2'].append(leaf_rmap_setprops)
    config_items['dut2'].append(leaf_rmap_setprops_v6)

    st.vtysh_config(dut2, leaf1_cmd)


def unconfigure_base_for_route_adv_and_filter(dut1, dut2, topo, config_items):
    """

    :param dut1:
    :param dut2:
    :param topo:
    :param config_items:
    :return:
    """
    bgpapi.config_bgp_network_advertise(dut1, topo['dut1_as'], '101.1.1.0/24', config='no')
    bgpapi.config_bgp_network_advertise(dut1, topo['dut1_as'], '102.1.1.0/24', config='no')
    bgpapi.config_bgp_network_advertise(dut1, topo['dut1_as'], '101:1::/64', addr_family='ipv6', config='no')
    bgpapi.config_bgp_network_advertise(dut1, topo['dut1_as'], '102:1::/64', addr_family='ipv6', config='no')

    bgpapi.config_bgp_network_advertise(dut2, topo['dut2_as'], '201.1.1.0/24', config='no')
    bgpapi.config_bgp_network_advertise(dut2, topo['dut2_as'], '202.1.1.0/24', config='no')
    bgpapi.config_bgp_network_advertise(dut2, topo['dut2_as'], '201:1::/64', addr_family='ipv6', config='no')
    bgpapi.config_bgp_network_advertise(dut2, topo['dut2_as'], '202:1::/64', addr_family='ipv6', config='no')

    bgpapi.config_bgp(dut=dut1, local_as=topo['dut1_as'], addr_family='ipv6',
                      config='no',
                      neighbor=topo['dut2_addr_ipv6'],
                      config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in')

    bgpapi.config_bgp(dut=dut2, local_as=topo['dut2_as'], addr_family='ipv6',
                      config='no',
                      neighbor=topo['dut1_addr_ipv6'],
                      config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in')

    leaf1_cmd = ''
    for item in reversed(config_items['dut2']):
        leaf1_cmd += item.unconfig_command_string()

    spine1_cmd = ''
    for item in reversed(config_items['dut1']):
        spine1_cmd += item.unconfig_command_string()

    st.vtysh_config(dut2, leaf1_cmd)
    st.vtysh_config(dut1, spine1_cmd)


def show_bgp_neighbors(dut, af='ipv4'):
    if af in ['ipv4', 'both']:
        utils.exec_foreach(True, utils.make_list(dut), bgpapi.show_bgp_ipv4_neighbor_vtysh)
    if af in ['ipv6', 'both']:
        utils.exec_foreach(True, utils.make_list(dut), bgpapi.show_bgp_ipv6_neighbor_vtysh)
