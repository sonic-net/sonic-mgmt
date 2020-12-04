#BGP 4 node linear topology
from spytest import st, SpyTestDict

import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import BGP.bgplib as bgplib

import utilities.common as utils

topo = SpyTestDict()

def l3_ipv4v6_address_config_unconfig(config='yes', vrf_type='all', config_type='all'):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :return:
    """
    st.banner("{}Configuring IP Addresses between linear topology nodes.".format('Un' if config != 'yes' else ''))
    tb_vars = st.get_testbed_vars()
    st.log("TestBed Vars => {}\n".format(tb_vars))

    topo['dut_list'] = tb_vars.dut_list
    st.log("topo dut_list {}".format(topo['dut_list']))

    config = 'add' if config == 'yes' else 'remove'
    ipv4_adr = '11'
    ipv6_adr = '67fe'
    result = True
    k = 1

    i=0
    while i < (len(topo['dut_list']) - 1):
        dut = topo['dut_list'][i]
        peer_dut = topo['dut_list'][i+1]
        link = 1
        for local, _, remote in st.get_dut_links(dut, peer_dut):
            if config_type == 'ipv4' or config_type == 'all':
                ipaddr1 = "{}.{}.0.1".format(ipv4_adr, k)
                ipaddr2 = "{}.{}.0.2".format(ipv4_adr, k)
                topo['D{}D{}P{}'.format(i+1,i+2,link)] = local
                topo['D{}D{}P{}_ipv4'.format(i+1,i+2,link)] = ipaddr1
                topo['D{}D{}P{}_neigh_ipv4'.format(i+1,i+2,link)] = ipaddr2
                topo['D{}D{}P{}'.format(i+2,i+1,link)] = remote
                topo['D{}D{}P{}_ipv4'.format(i+2,i+1,link)] = ipaddr2
                topo['D{}D{}P{}_neigh_ipv4'.format(i+2,i+1,link)] = ipaddr1
                [out, exceptions] = utils.exec_all(bgplib.fast_start,[[ipapi.config_ip_addr_interface, dut, local, ipaddr1, '24', "ipv4", config],[ipapi.config_ip_addr_interface, peer_dut, remote, ipaddr2,'24', "ipv4", config]])
                st.log([out, exceptions])

            if config_type == 'ipv6' or config_type == 'all':
                ip6addr1 = "{}:{}::1".format(ipv6_adr, k)
                ip6addr2 = "{}:{}::2".format(ipv6_adr, k)
                topo['D{}D{}P{}'.format(i+1,i+2,link)] = local
                topo['D{}D{}P{}_ipv6'.format(i+1,i+2,link)] = ip6addr1
                topo['D{}D{}P{}_neigh_ipv6'.format(i+1,i+2,link)] = ip6addr2
                topo['D{}D{}P{}'.format(i+2,i+1,link)] = remote
                topo['D{}D{}P{}_ipv6'.format(i+2,i+1,link)] = ip6addr2
                topo['D{}D{}P{}_neigh_ipv6'.format(i+2,i+1,link)] = ip6addr1
                [out, exceptions] = utils.exec_all(bgplib.fast_start,[[ipapi.config_ip_addr_interface, dut, local, ip6addr1, '64', "ipv6", config],[ipapi.config_ip_addr_interface, peer_dut, remote, ip6addr2,'64', "ipv6", config]])
                st.log([out, exceptions])
            link += 1
            break
        k += 1
        i += 1
    return result


def l3tc_vrfipv4v6_address_ping_test(vrf_type='all', config_type='all', ping_count=3):
    """

    :param vrf_type:
    :param config_type:
    :param ping_count:
    :return:
    """
    st.banner("Ping Checking between Spine and Leaf nodes.")
    ipv4_adr = '11'
    ipv6_adr = '67fe'
    result = True
    k = 1

    i=0
    while i < (len(topo['dut_list']) - 1):
        dut = topo['dut_list'][i]
        peer_dut = topo['dut_list'][i+1]
        link = 1
        for local, _, _ in st.get_dut_links(dut, peer_dut):
            if config_type == 'ipv4' or config_type == 'all':
                ipaddr2 = "{}.{}.0.2".format(ipv4_adr, k)
                if not ipapi.ping(dut, ipaddr2, family='ipv4', count=ping_count):
                    st.log("{}- {} configured on {} - ping failed".format(dut, local, ipaddr2))
                    result = False

            if config_type == 'ipv6' or config_type == 'all':
                ip6addr2 = "{}:{}::2".format(ipv6_adr, k)
                if not ipapi.ping(dut, ip6addr2, family='ipv6', count=ping_count):
                    st.log("{}- {} configured on {} - ping v6 failed".format(dut, local, ip6addr2))
                    result = False
            link += 1
            break
        k += 1
        i += 1
    return result

def l3tc_vrfipv4v6_confed_bgp_config(config='yes', vrf_type='all', config_type='all'):
    """

    :param config:
    :param vrf_type:
    :param config_type:
    :return:
    """
    st.banner("{}Configuring BGP with 4-node confederation topology.".format('Un' if config != 'yes' else ''))
    #Confedration topo:
    #DUT1 in sub-AS1 (AS1 = 24)
    #DUT2, DUT3, DUT 4 in sub-AS2 (AS2 = 35)
    #IBGP AS = 100
    config = 'add' if config == 'yes' else 'remove'

    leftconfed_as = 24
    rightconfed_as = 35
    iBGP_as = 100

    topo['D1_as'] = 24
    topo['D2_as'] = 35
    topo['D3_as'] = 35
    topo['D4_as'] = 35

    result = True

    if config == 'add':
        if config_type == 'ipv4' or config_type == 'all':
            #Confederation config for DUT1
            dut = topo['dut_list'][0]
            neighbor = topo['D1D2P1_neigh_ipv4']
            bgpapi.config_bgp(dut, local_as = leftconfed_as, config = 'yes', conf_peers = rightconfed_as, conf_identf = iBGP_as, remote_as = rightconfed_as, config_type_list = ["neighbor"], neighbor = neighbor)

            #Confederation config for DUT2
            dut = topo['dut_list'][1]
            neighbor = topo['D2D3P1_neigh_ipv4']
            bgpapi.config_bgp(dut, local_as = rightconfed_as, config = 'yes', conf_peers = leftconfed_as, conf_identf = iBGP_as, remote_as = rightconfed_as, config_type_list = ["neighbor"], neighbor = neighbor)
            bgpapi.create_bgp_neighbor(dut, rightconfed_as, topo['D2D1P1_neigh_ipv4'], leftconfed_as)

            #Confederation config for DUT3
            dut = topo['dut_list'][2]
            neighbor = topo['D3D4P1_neigh_ipv4']
            bgpapi.config_bgp(dut, local_as = rightconfed_as, config = 'yes', conf_peers = leftconfed_as, conf_identf = iBGP_as, remote_as = rightconfed_as, config_type_list = ["neighbor"], neighbor = neighbor)
            bgpapi.create_bgp_neighbor(dut, rightconfed_as, topo['D3D2P1_neigh_ipv4'], rightconfed_as)

            #Confederation config for DUT4
            dut = topo['dut_list'][3]
            neighbor = topo['D4D3P1_neigh_ipv4']
            bgpapi.config_bgp(dut, local_as = rightconfed_as, config = 'yes', conf_peers = leftconfed_as, conf_identf = iBGP_as, remote_as = rightconfed_as, config_type_list = ["neighbor"], neighbor = neighbor)

        if config_type == 'ipv6' or config_type == 'all':
            #Confederation config for DUT1
            dut = topo['dut_list'][0]
            neighbor = topo['D1D2P1_neigh_ipv6']
            bgpapi.config_bgp(dut, local_as = leftconfed_as, config = 'yes', addr_family ='ipv6', conf_peers = rightconfed_as, conf_identf = iBGP_as, remote_as = rightconfed_as, config_type_list = ["neighbor", "activate"], neighbor = neighbor)

            #Confederation config for DUT2
            dut = topo['dut_list'][1]
            neighbor = topo['D2D3P1_neigh_ipv6']
            bgpapi.config_bgp(dut, local_as = rightconfed_as, config = 'yes', addr_family ='ipv6', conf_peers = leftconfed_as, conf_identf = iBGP_as, remote_as = rightconfed_as, config_type_list = ["neighbor", "activate"], neighbor = neighbor)
            bgpapi.create_bgp_neighbor(dut, rightconfed_as, topo['D2D1P1_neigh_ipv6'], leftconfed_as, family="ipv6")

            #Confederation config for DUT3
            dut = topo['dut_list'][2]
            neighbor = topo['D3D4P1_neigh_ipv6']
            bgpapi.config_bgp(dut, local_as = rightconfed_as, config = 'yes', addr_family ='ipv6', conf_peers = leftconfed_as, conf_identf = iBGP_as, remote_as = rightconfed_as, config_type_list = ["neighbor", "activate"], neighbor = neighbor)
            bgpapi.create_bgp_neighbor(dut, rightconfed_as, topo['D3D2P1_neigh_ipv6'], rightconfed_as, family="ipv6")

            #Confederation config for DUT4
            dut = topo['dut_list'][3]
            neighbor = topo['D4D3P1_neigh_ipv6']
            bgpapi.config_bgp(dut, local_as = rightconfed_as, config = 'yes', addr_family ='ipv6', conf_peers = leftconfed_as, conf_identf = iBGP_as, remote_as = rightconfed_as, config_type_list = ["neighbor", "activate"], neighbor = neighbor)

    else:
        bgpapi.cleanup_router_bgp(topo['dut_list'])

    return result

def l3tc_vrfipv4v6_address_confed_bgp_check(config_type='all'):
    st.banner("BGP Neighbor Checking in confederation topology")

    result = True
    if config_type == 'ipv4' or config_type == 'all':
        #Check link between DUT 1----DUT2 and DUT2----DUT3
        neigh_list = []
        neigh_list.append(topo['D2D3P1_neigh_ipv4'])
        neigh_list.append(topo['D2D1P1_neigh_ipv4'])
        neigh_list = list(set(neigh_list))
        if not bgpapi.verify_bgp_summary(topo['dut_list'][1], family='ipv4', neighbor=neigh_list, state='Established'):
            st.log("{} - Neighbor {} is failed to Establish".format(topo['dut_list'][1], neigh_list))
            result = False

        #Check link between DUT3----DUT4
        if not bgpapi.verify_bgp_summary(topo['dut_list'][2], family='ipv4', neighbor=topo['D3D4P1_neigh_ipv4'], state='Established'):
            st.log("{} - Neighbor {} is failed to Establish".format(topo['dut_list'][2], topo['D3D4P1_neigh_ipv4']))
            result = False

    if config_type == 'ipv6' or config_type == 'all':
        #Check link between DUT 1----DUT2 and DUT2----DUT3
        neigh_list = []
        neigh_list.append(topo['D2D3P1_neigh_ipv6'])
        neigh_list.append(topo['D2D1P1_neigh_ipv6'])
        neigh_list = list(set(neigh_list))
        if not bgpapi.verify_bgp_summary(topo['dut_list'][1], family='ipv6', neighbor=neigh_list, state='Established'):
            st.log("{} - Neighbor {} is failed to Establish".format(topo['dut_list'][1], neigh_list))
            result = False

        #Check link between DUT3----DUT4
        if not bgpapi.verify_bgp_summary(topo['dut_list'][2], family='ipv6', neighbor=topo['D3D4P1_neigh_ipv6'], state='Established'):
            st.log("{} - Neighbor {} is failed to Establish".format(topo['dut_list'][2], topo['D3D4P1_neigh_ipv6']))
            result = False
    return result

def get_confed_topology_info():
    return topo
