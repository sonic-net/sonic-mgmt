#   BGP SP Topology APIs
#   Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

import copy

from spytest import st, utils, putils
from spytest.dicts import SpyTestDict
import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.system.interface as ifapi
from spytest.tgen.tg import tgen_obj_dict
import BGP.bgplib as bgplib

sp_topo = SpyTestDict()
bgp_topo = SpyTestDict()


class BGPSP:


    @staticmethod
    def bgp_sp_topology_data_present():
        if not sp_topo['dut_list'] or len(sp_topo['dut_list']) == 0 :
            return False
        return True


    @staticmethod
    def bgp_sp_dut_present(dut):
        if dut in sp_topo['dut_list'] :
            return True
        if dut in sp_topo['tg_list'] :
            return True
        return False


    @staticmethod
    def bgp_sp_dut_list_present(dut_name_list = []):

        if not dut_name_list or len(dut_name_list) == 0 :
            return False
        for dut_name in dut_name_list:
            if dut_name not in sp_topo['dut_list'] :
                return False
        return True


    @staticmethod
    def bgp_sp_get_dut_count():
        return len (sp_topo['dut_list'])


    @staticmethod
    def bgp_sp_get_dut_list():
        return copy.deepcopy(sp_topo['dut_list'])


    @staticmethod
    def bgp_sp_get_dut_from_device(device_name):

        for dut in sp_topo['dut_list'] :
            if device_name == sp_topo[dut]['device'] :
                st.log("BGP SP - DUT device {} is dut {}".format(device_name, dut))
                return dut
        for dut in sp_topo['tg_list'] :
            if device_name == sp_topo[dut]['device'] :
                st.log("BGP SP - TG device {} is dut {}".format(device_name, dut))
                return dut
        st.log("BGP SP - device {} not in dut list".format(device_name))
        return ""


    @staticmethod
    def bgp_sp_get_dut_device(dut):

        if dut in sp_topo['dut_list'] :
            return  sp_topo[dut]['device']
        return ''


    @staticmethod
    def bgp_sp_get_tg_list():
        return copy.deepcopy(sp_topo['tg_list'])


    @staticmethod
    def bgp_sp_dut_is_tg(dut):

        if dut in sp_topo['tg_list'] :
            if dut in sp_topo.keys() :
                if  sp_topo[dut]['type'] == 'TG' :
                    return True
        return False


    @staticmethod
    def bgp_sp_valid_link_type(link_type):

        if link_type == "ETH" :
            return True
        if link_type == "LBK" :
            return True
        return False


    @staticmethod
    def bgp_sp_dut_link_present(dut, link_name):

        if not BGPSP.bgp_sp_dut_present(dut) :
            st.log("BGP SP - Link dut {} not in dut list".format(dut))
            return False

        if link_name not in sp_topo[dut]['intf'].keys():
            return False

        return True


    @staticmethod
    def bgp_sp_link_present(link_name):

        if not link_name or link_name == '' :
            return False
        for dut in BGPSP.bgp_sp_get_dut_list():
            if link_name in sp_topo[dut]['intf'].keys():
                return True
        for dut in BGPSP.bgp_sp_get_tg_list():
            if link_name in sp_topo[dut]['intf'].keys():
                return True
        return False


    """ UNUSED AND USES UNDEFINED VARIABLE
    @staticmethod
    def bgp_sp_link_list_present(link_name_list = []):

        if not link_name_list or len(link_name_list) == 0 :
            return False

        topo_links = sp_topo[dut]['intf'].keys()

        for link_name in link_name_list:
            if link_name not in topo_links :
                return False
        return True
    """


    @staticmethod
    def bgp_sp_dut_get_all_links(dut):

        if not BGPSP.bgp_sp_dut_present(dut):
            return []

        link_name_list = []
        for link_name, link_data in sp_topo[dut]['intf'].items():
            if link_data['type'] == 'LBK' :
                continue
            link_name_list.append(link_name)

        return copy.deepcopy(link_name_list)


    @staticmethod
    def bgp_sp_get_link_dut_interface(dut, link_name):

        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if_data = sp_topo[dut]['intf'][link_name]
            if 'if' in if_data.keys():
                return if_data['if']

        return ''


    @staticmethod
    def bgp_sp_dut_link_connected(dut, link_name):

        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if_data = sp_topo[dut]['intf'][link_name]
            if 'rmt_dut' in if_data.keys():
                if 'rmt_link' in if_data.keys():
                    return True

        return False


    @staticmethod
    def bgp_sp_dut_get_remote_dut(dut, link_name):

        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if_data = sp_topo[dut]['intf'][link_name]
            if 'rmt_dut' in if_data.keys():
                return sp_topo[dut]['intf'][link_name]['rmt_dut']

        return ''


    @staticmethod
    def bgp_sp_dut_get_remote_link(dut, link_name):

        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if_data = sp_topo[dut]['intf'][link_name]
            if 'rmt_dut' in if_data.keys():
                if 'rmt_link' in if_data.keys():
                    return sp_topo[dut]['intf'][link_name]['rmt_link']

        return ''

    @staticmethod
    def bgp_sp_is_tg_connected_link(dut, link_name):

        rmt_dut = BGPSP.bgp_sp_dut_get_remote_dut(dut, link_name)
        if rmt_dut == '' :
            return False

        if BGPSP.bgp_sp_dut_is_tg(rmt_dut):
           return True

        return False


    @staticmethod
    def bgp_sp_dut_get_tg_connected_links(dut):

        if not BGPSP.bgp_sp_dut_present(dut):
            return []

        link_name_list = []
        for link_name, link_data in sp_topo[dut]['intf'].items():
            if 'rmt_dut' in link_data.keys():
                rmt_dut = link_data['rmt_dut']
                if BGPSP.bgp_sp_dut_is_tg(rmt_dut):
                    link_name_list.append(link_name)

        return link_name_list


    @staticmethod
    def bgp_sp_dut_get_tg_connected_link_data(dut, link_name):

        if not BGPSP.bgp_sp_is_tg_connected_link(dut, link_name):
            return {}

        link_data = sp_topo[dut]['intf'][link_name]
        rmt_dut = link_data['rmt_dut']
        if BGPSP.bgp_sp_dut_is_tg(rmt_dut):
            return copy.deepcopy(link_data)

        return {}


    @staticmethod
    def bgp_sp_dut_get_connected_first_link(from_dut, to_dut):

        if not BGPSP.bgp_sp_dut_present(from_dut):
            return ''

        if not BGPSP.bgp_sp_dut_present(to_dut):
            return ''

        for link_name, link_data in sp_topo[from_dut]['intf'].items():
            if 'rmt_dut' in link_data.keys():
                if link_data['rmt_dut'] == to_dut :
                    if 'rmt_link' in link_data.keys():
                         return link_name

        return ''


    @staticmethod
    def bgp_sp_dut_get_connected_links(from_dut, to_dut):

        if not BGPSP.bgp_sp_dut_present(from_dut):
            return []

        if not BGPSP.bgp_sp_dut_present(to_dut):
            return []

        link_name_list = []
        for link_name, link_data in sp_topo[from_dut]['intf'].items():
            if 'rmt_dut' in link_data.keys():
                if link_data['rmt_dut'] == to_dut :
                    if 'rmt_link' in link_data.keys():
                         link_name_list.append(link_name)

        return link_name_list


    @staticmethod
    def bgp_sp_dut_link_connected_to_each_other(from_dut, from_link, to_dut, to_link):

        if not BGPSP.bgp_sp_dut_link_connected(from_dut, from_link):
            return False

        if not BGPSP.bgp_sp_dut_link_connected(to_dut, to_link):
            return False

        from_if_info = sp_topo[from_dut]['intf'][from_link]
        to_if_info = sp_topo[to_dut]['intf'][to_link]

        if from_if_info['rmt_dut'] != to_dut:
            return False
        if to_if_info['rmt_dut'] != from_dut:
            return False
        if from_if_info['rmt_link'] != to_link:
            return False
        if to_if_info['rmt_link'] == from_link :
            return False

        return True


    @staticmethod
    def bgp_sp_get_unused_dut_interface(dut):

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - not present in {}".format(dut))
            return ''

        dut_if_list = []
        for _, link_data in sp_topo[dut]['intf'].items():
            if 'if' in link_data.keys():
                dut_if_list.append(link_data['if'])

        if_idx = 80
        while if_idx < 100:
            if_name = "Ethernet{}".format(if_idx)
            if if_name not in dut_if_list :
               st.log("BGP SP - Found unused interface {} in dut {}".format(if_name, dut))
               return copy.deepcopy(if_name)
            if_idx += 4

        st.log("BGP SP - No unused interfaces in {}".format(dut))
        return ''


    @staticmethod
    def bgp_sp_addr_family_valid(addr_family):

        if addr_family != 'ipv4' and addr_family != 'ipv6' :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return False
        return True


    @staticmethod
    def bgp_sp_get_address_family_list(addr_family):

        addr_family_list = []
        if addr_family == 'ipv4' or addr_family == 'all':
            addr_family_list.append('ipv4')
        if addr_family == 'ipv6' or addr_family == 'all':
            addr_family_list.append('ipv6')
        return addr_family_list


    @staticmethod
    def bgp_sp_ip_prefix_to_route_prefix(prefix, addr_family):

        route_prefix = prefix

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return route_prefix

        if addr_family == 'ipv6' :
            temp_prefix = prefix.partition(":0/")
            if temp_prefix and len(temp_prefix) == 3 and temp_prefix[1] == ":0/" :
                route_prefix = "{}:/{}".format(temp_prefix[0], temp_prefix[2])

        return route_prefix


    @staticmethod
    def bgp_sp_ip_prefix_list_to_route_prefix_list(prefix_list, addr_family):

        route_prefix_list = []

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return route_prefix_list

        for prefix in prefix_list :
            route_prefix = BGPSP.bgp_sp_ip_prefix_to_route_prefix(prefix, addr_family)
            if route_prefix != '':
                route_prefix_list.append(route_prefix)

        #st.log("BGP SP - route_prefix list {}".format(route_prefix_list))
        return copy.deepcopy(route_prefix_list)


    @staticmethod
    def bgp_sp_dut_ip_link_present(dut, link_name, addr_family):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return False

        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if link_name in sp_topo[dut][addr_family]['link'].keys():
                return True

        return False


    @staticmethod
    def bgp_sp_dut_get_ip_link(dut, link_name, addr_family):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return {}

        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if link_name in sp_topo[dut][addr_family]['link'].keys():
                ip_data = sp_topo[dut][addr_family]['link'][link_name]
                return copy.deepcopy(ip_data)

        return {}


    @staticmethod
    def bgp_sp_dut_link_has_ip(dut, link_name, addr_family):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return False

        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if link_name in sp_topo[dut][addr_family]['link'].keys():
                ip_data = sp_topo[dut][addr_family]['link'][link_name]
                if 'ip' in ip_data.keys():
                    return True

        st.log("BGP SP - {} {} doesnot have ip address".format(dut, link_name))
        return False


    @staticmethod
    def bgp_sp_dut_get_link_local_ip(dut, link_name, addr_family):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return False

        st.log("BGP SP - Find local ip {} {} {}".format(dut, link_name, addr_family))
        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if link_name in sp_topo[dut][addr_family]['link'].keys():
                ip_data = sp_topo[dut][addr_family]['link'][link_name]
                if 'ip' in ip_data.keys():
                    return ip_data['ip']

        st.log("BGP SP - {} {} doesnot have local ip address".format(dut, link_name))
        return ""


    @staticmethod
    def bgp_sp_dut_get_link_remote_ip(dut, link_name, addr_family):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return False

        if BGPSP.bgp_sp_dut_link_present(dut, link_name):
            if link_name in sp_topo[dut][addr_family]['link'].keys():
                ip_data = sp_topo[dut][addr_family]['link'][link_name]
                if 'rmt_ip' in ip_data.keys():
                    return ip_data['rmt_ip']

        st.log("BGP SP - {} {} doesnot have local remote address".format(dut, link_name))
        return ""


    @staticmethod
    def bgp_sp_get_dut_loopback_ip(dut, lpbk_num, addr_family):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return ""

        link_name = "{}L{}".format(dut, lpbk_num)

        if not BGPSP.bgp_sp_dut_link_present(dut, link_name):
            st.log("BGP SP - Link {} not in intf list".format(link_name))
            return ''

        if link_name in sp_topo[dut][addr_family]['link'].keys():
            ip_data = sp_topo[dut][addr_family]['link'][link_name]
            if 'ip' not in ip_data.keys():
                st.log("BGP SP - {} doesnt have ip address".format(link_name))
                return ''

            return ip_data['ip']

        return ''


    @staticmethod
    def bgp_sp_get_dut_loopback_ip_list(dut, addr_family):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            return []

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return []

        lpbk_ip_list = []
        for _, ip_data in sp_topo[dut][addr_family]['link'].items():
            if ip_data['type'] == 'LBK' :
                if 'ip' in ip_data.keys():
                    lpbk_ip_list.append(ip_data['ip'])

        return copy.deepcopy(lpbk_ip_list)


    @staticmethod
    def bgp_sp_get_loopback_ip_in_dut_list(dut_list=[], addr_family='ipv4'):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            return []

        lpbk_ip_list = []

        for dut in dut_list:
            if not BGPSP.bgp_sp_dut_present(dut):
                continue

            for _, ip_data in sp_topo[dut][addr_family]['link'].items():
                if ip_data['type'] == 'LBK' :
                    if 'ip' in ip_data.keys():
                        if ip_data['ip'] not in lpbk_ip_list:
                            lpbk_ip_list.append(ip_data['ip'])

        return copy.deepcopy(lpbk_ip_list)


    @staticmethod
    def bgp_sp_get_dut_ip_address_list(dut, addr_family, vrf='default'):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            return []

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return []

        ip_addr_list = []
        for _, ip_data in sp_topo[dut][addr_family]['link'].items():
            if 'ip' in ip_data.keys():
                 ip_addr_list.append(ip_data['ip'])

        st.log("BGP SP - Dut {} has host ip {}".format(dut, ip_addr_list))
        return copy.deepcopy(ip_addr_list)


    @staticmethod
    def bgp_sp_get_dut_static_network_prefixes(dut, addr_family):

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return []

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return []

        snw_list = []
        for prefix, snw_data in sp_topo[dut][addr_family]['static_nw'].items() :
            prefix_subnet = "{}/{}".format(prefix, snw_data['subnet'])
            snw_list.append(prefix_subnet)

        return copy.deepcopy(snw_list)


    @staticmethod
    def bgp_sp_get_dut_static_route_prefixes(dut, addr_family):

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return []

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return []

        srtp_list = []
        for prefix, rt_data in sp_topo[dut][addr_family]['static_rt'].items() :
            prefix_subnet = "{}/{}".format(prefix, rt_data['subnet'])
            srtp_list.append(prefix_subnet)

        return copy.deepcopy(srtp_list)


    @staticmethod
    def bgp_sp_get_dut_null_nhop_static_route_prefixes(dut, addr_family):

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return []

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return []

        srtp_list = []
        for prefix, rt_data in sp_topo[dut][addr_family]['static_rt'].items() :
            if rt_data['nexthop'] == 'Null0' :
                 prefix_subnet = "{}/{}".format(prefix, rt_data['subnet'])
                 srtp_list.append(prefix_subnet)

        return copy.deepcopy(srtp_list)


    @staticmethod
    def bgp_sp_get_dut_static_route_prefix_data_list(dut, addr_family):

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return {}

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return {}

        srtp_data_list = {}
        for prefix, rt_data in sp_topo[dut][addr_family]['static_rt'].items() :
            srtp_data_list.update({prefix: rt_data})

        return copy.deepcopy(srtp_data_list)


    @staticmethod
    def bgp_sp_find_linear_topo_in_dut_list(dut_list=[], start_dut='', node_limit=0, save_path='yes'):

        st.log("BGP SP - Find Linear Topo in Dut list {} length {}".format(dut_list, node_limit))
        sp_topo_dut_list = BGPSP.bgp_sp_get_dut_list()

        found_path = {}
        found_path['found'] = False

        if not dut_list or len(dut_list) == 0 :
            dut_list = sp_topo_dut_list
        else :
            for dut in dut_list :
                if dut not in sp_topo_dut_list :
                    st.log("Dut {} not in Topo dut lidt {}".format(dut, sp_topo_dut_list))
                    return found_path

        if start_dut and start_dut != '' :
            if start_dut not in dut_list :
                st.log("Start dut {} not in dut list {}".format(start_dut, dut_list))
                return found_path

        if node_limit <= 0 :
            length_limit = len (dut_list)
        else :
            length_limit = node_limit

        st.log("Modified Dut list {} length_limit {}".format(dut_list, length_limit))

        longest_path = []

        for dut in dut_list :

            if start_dut and start_dut != '' and start_dut != dut :
               continue

            if BGPSP.bgp_sp_dut_is_tg(dut) :
               continue

            st.log(" Starting dut {} ".format(dut))

            sp_topo_stack = []
            sp_topo_path = []
            sp_topo_stack.append(dut)

            while sp_topo_stack and len(sp_topo_stack) :

                st.log("   sp stack {}".format(sp_topo_stack))
                st.log("   sp path {}".format(sp_topo_path))

                curr_dut = sp_topo_stack.pop()
                sp_topo_path.append(curr_dut)

                leaf_dut = True
                for _, link_data in sp_topo[curr_dut]['intf'].items():
                    if 'rmt_dut' in link_data.keys():
                        next_dut = link_data['rmt_dut']

                        if BGPSP.bgp_sp_dut_is_tg(next_dut):
                            continue

                        if next_dut in sp_topo_path :
                            continue

                        if next_dut not in dut_list :
                            continue

                        if next_dut not in sp_topo_stack :
                            sp_topo_stack.append(next_dut)

                        leaf_dut = False

                if len(sp_topo_path) == length_limit :
                    leaf_dut = True

                if leaf_dut is True :
                    st.log("      Linear found Dut {} ".format(curr_dut))
                    st.log("      Linear found sp path {} ".format(sp_topo_path))
                    st.log("      Linear found longest path {} ".format(longest_path))

                    if len(longest_path) < len(sp_topo_path) :
                        if node_limit > 0 :
                            if len(sp_topo_path) <= length_limit :
                                longest_path = copy.deepcopy(sp_topo_path)
                                st.log("          New longest path set as curr new linear path")
                        else :
                            longest_path = copy.deepcopy(sp_topo_path)
                            st.log("          New longest path set as curr new linear path")

                    if len(longest_path) >= length_limit :
                        st.log("         Path length limit provided {} and reached".format(length_limit))
                        break

                    sp_topo_path.pop()


                if  len(longest_path) == length_limit :
                    break

        st.log("BGP SP - Longest path len {} with path {}".format(len(longest_path), longest_path))

        path_length = len(longest_path)
        found_path['found'] = True if path_length else False

        path_length = len(longest_path)
        found_path['found'] = True if path_length else False
        found_path['dut_list'] = []
        found_path['segment'] = {}
        found_path['segment_count'] = 0
        found_path['type'] = 'Linear'

        if found_path['found'] :
            for dut in longest_path :
                found_path['dut_list'].append(dut)

            from_dut = longest_path[0]
            found_path['start_dut'] = from_dut
            dut_idx = 1
            while dut_idx < path_length :
                to_dut = longest_path[dut_idx]
                segt_link_idx = 0
                for link_name, link_data in sp_topo[from_dut]['intf'].items():
                    if 'rmt_dut' in link_data.keys():
                        if link_data['rmt_dut'] == to_dut :

                            rmt_link = link_data['rmt_link']
                            segt_link = { 'lcl_dut' : from_dut, 'lcl_link': link_name,
                                          'rmt_dut' : to_dut,   'rmt_link' : rmt_link }

                            if segt_link_idx == 0 : found_path['segment'][dut_idx - 1] = {}
                            found_path['segment'][dut_idx - 1].update({ segt_link_idx: segt_link})

                            if segt_link_idx == 0:
                                found_path['segment_count'] += 1
                            segt_link_idx += 1
                            #st.log("   Path node {} is {}".format(dut_idx - 1, segt_link))
                from_dut = to_dut
                dut_idx += 1

        if save_path == 'yes' :
            sp_topo['subtopo']['linear'] = copy.deepcopy(found_path)

        BGPSP.bgp_sp_show_topo_path(found_path)
        return found_path


    @staticmethod
    def bgp_sp_dut_get_saved_linear_topo():
        return copy.deepcopy(sp_topo['subtopo']['linear'])


    @staticmethod
    def bgp_sp_find_ring_topo_in_dut_list(dut_list=[], start_dut='', node_limit=0, save_path='yes'):

        st.log("BGP SP - Find Linear Topo in Dut list {} length {}".format(dut_list, node_limit))
        sp_topo_dut_list = BGPSP.bgp_sp_get_dut_list()

        found_path = {}
        found_path['found'] = False

        if not dut_list or len(dut_list) == 0 :
            dut_list = sp_topo_dut_list
        else :
            for dut in dut_list :
                if dut not in sp_topo_dut_list :
                    st.log("Dut {} not in Topo dut lidt {}".format(dut, sp_topo_dut_list))
                    return found_path

        if start_dut and start_dut != '' :
            if start_dut not in dut_list :
                st.log("Start dut {} not in dut list {}".format(start_dut, dut_list))
                return found_path

        if node_limit <= 0 :
            length_limit = len(dut_list) + 1
        else :
            length_limit = node_limit + 1

        st.log("Modified Dut list {} length_limit {}".format(dut_list, length_limit))

        longest_path = []
        loop_count = 0

        for dut in dut_list :

            if length_limit <= 3 :
               break

            if start_dut and start_dut != '' and start_dut != dut :
               continue

            if BGPSP.bgp_sp_dut_is_tg(dut) :
               continue

            st.log(" Starting at dut {} with longest path {}.".format(dut, longest_path))

            sp_topo_stack = []
            sp_topo_path = []
            sp_topo_stack.append(dut)

            while sp_topo_stack and len(sp_topo_stack) :

                loop_count += 1
                if loop_count > 100 :
                    break

                st.log("   sp stack {}".format(sp_topo_stack))
                st.log("   sp path {}".format(sp_topo_path))

                curr_dut = sp_topo_stack.pop()
                sp_topo_path.append(curr_dut)

                st.log("   modified sp path {}".format(sp_topo_path))

                leaf_dut = True
                ring_found = False

                for link_name, link_data in sp_topo[curr_dut]['intf'].items():
                    if 'rmt_dut' in link_data.keys():
                        next_dut = link_data['rmt_dut']

                        if next_dut == dut :
                            ring_found = True

                        if BGPSP.bgp_sp_dut_is_tg(next_dut):
                            continue

                        if next_dut not in dut_list :
                            continue

                        if next_dut in sp_topo_path :
                            continue

                        if next_dut not in sp_topo_stack :
                            sp_topo_stack.append(next_dut)

                        leaf_dut = False

                if ring_found :
                    st.log("      Ring found Dut {} ".format(curr_dut))
                    st.log("      Ring found sp path {} ".format(sp_topo_path))
                    st.log("      Ring found longest path {} ".format(longest_path))

                    if len(sp_topo_path) > 2 :

                        sp_topo_path.append(dut)

                        st.log("         new ring sp path {} ".format(sp_topo_path))
                        st.log("         ring longest path {} ".format(longest_path))

                        if len(longest_path) < len(sp_topo_path) :
                            if node_limit > 0 :
                                if len(sp_topo_path) <= length_limit :
                                    longest_path = copy.deepcopy(sp_topo_path)
                                    st.log("          New longest path set as curr new ring sp path")
                            else :
                                longest_path = copy.deepcopy(sp_topo_path)
                                st.log("          New longest path set as curr new ring sp path")

                        if len(longest_path) >= length_limit :
                            st.log("         Path length limit provided {} and reached".format(length_limit))
                            break

                        sp_topo_path.pop()

                    if leaf_dut is True :
                        sp_topo_path.pop()

                if  len(longest_path) == length_limit :
                    break

        st.log("BGP SP - Longest path len {} with path {}".format(len(longest_path), longest_path))

        path_length = len(longest_path)
        found_path['found'] = True if path_length else False
        found_path['dut_list'] = []
        found_path['segment'] = {}
        found_path['segment_count'] = 0
        found_path['type'] = 'Ring'

        if found_path['found'] :
            for dut in longest_path :
                found_path['dut_list'].append(dut)

            from_dut = longest_path[0]
            found_path['start_dut'] = from_dut
            dut_idx = 1
            while dut_idx < path_length :
                to_dut = longest_path[dut_idx]
                segt_link_idx = 0
                for link_name, link_data in sp_topo[from_dut]['intf'].items():
                    if 'rmt_dut' in link_data.keys():
                        if link_data['rmt_dut'] == to_dut :

                            rmt_link = link_data['rmt_link']
                            segt_link = { 'lcl_dut' : from_dut, 'lcl_link': link_name,
                                          'rmt_dut' : to_dut,   'rmt_link' : rmt_link }

                            if segt_link_idx == 0 : found_path['segment'][dut_idx - 1] = {}
                            found_path['segment'][dut_idx - 1].update({ segt_link_idx: segt_link})

                            if segt_link_idx == 0:
                                found_path['segment_count'] += 1
                            segt_link_idx += 1
                            #st.log("   Path node {} is {}".format(dut_idx - 1, segt_link))

                from_dut = to_dut
                dut_idx += 1
            found_path['dut_list'].pop()

        if save_path == 'yes' :
            sp_topo['subtopo']['ring'] = copy.deepcopy(found_path)

        BGPSP.bgp_sp_show_topo_path(found_path)
        return found_path


    @staticmethod
    def bgp_sp_dut_get_saved_ring_topo():
        return copy.deepcopy(sp_topo['subtopo']['ring'])


    @staticmethod
    def bgp_sp_find_star_topo_in_dut_list(dut_list=[], core_dut = "", path_spoke_limit=0, save_path='yes'):

        st.log("BGP SP - Find Star Topo in Dut list {} length {}".format(dut_list, path_spoke_limit))
        sp_topo_dut_list = BGPSP.bgp_sp_get_dut_list()

        found_path = {}
        found_path['found'] = False

        if not dut_list or len(dut_list) == 0 :
            dut_list = sp_topo_dut_list
        else :
            for dut in dut_list :
                if dut not in sp_topo_dut_list :
                    st.log("Dut {} not in Topo dut list {}".format(dut, sp_topo_dut_list))
                    return found_path

        if core_dut and core_dut != '' :
            if core_dut not in dut_list :
                st.log("Core dute {} not in dut list {}".format(core_dut, dut_list))
                return found_path

        if path_spoke_limit <= 0 :
            spoke_limit = len (dut_list)
        else :
            spoke_limit = path_spoke_limit

        st.log("Modified Dut list {} length_limit {}".format(dut_list, spoke_limit))

        largest_star = []

        for dut in dut_list :

            if core_dut and core_dut != '' and core_dut != dut :
               continue

            if BGPSP.bgp_sp_dut_is_tg(dut) :
               continue

            st.log(" Starting dut {} ".format(dut))

            sp_topo_path = []
            sp_topo_path.append(dut)

            excl_list = list(dut_list)
            excl_list.remove(dut)

            for next_dut in excl_list :

                st.log("   sp path {}".format(sp_topo_path))

                #leaf_dut = True
                for link_name, link_data in sp_topo[dut]['intf'].items():
                    if 'rmt_dut' in link_data.keys():
                        rmt_dut = link_data['rmt_dut']

                        if rmt_dut != next_dut :
                            continue

                        sp_topo_path.append(next_dut)
                        break

            if len(largest_star) < len(sp_topo_path) :
                largest_star = sp_topo_path

            path_spoke_count = len(largest_star) - 1
            if path_spoke_limit > 0 :
                if path_spoke_count == path_spoke_limit :
                    st.log("    Path spoke limit provided {} and reached".format(path_spoke_limit))
                    break
            else :
                if path_spoke_count == spoke_limit :
                    st.log("    Path max possible spoke {} reached".format(spoke_limit))
                    break

        st.log("BGP SP - {} Star with nodes {}".format(len(largest_star), largest_star))

        path_length = len(largest_star)

        found_path['found'] = True if path_length else False
        found_path['dut_list'] = []
        found_path['segment'] = {}
        found_path['segment_count'] = 0
        found_path['type'] = 'Star'

        if found_path['found'] :

            for dut in largest_star :
                found_path['dut_list'].append(dut)

            from_dut = largest_star[0]
            found_path['start_dut'] = from_dut

            dut_idx = 1
            while dut_idx < path_length :
                to_dut = largest_star[dut_idx]
                segt_link_idx = 0
                for link_name, link_data in sp_topo[from_dut]['intf'].items():
                    if 'rmt_dut' in link_data.keys():
                        if link_data['rmt_dut'] == to_dut :
                            rmt_link = link_data['rmt_link']
                            segt_link = { 'lcl_dut' : from_dut, 'lcl_link': link_name,
                                          'rmt_dut' : to_dut,   'rmt_link' : rmt_link }

                            if segt_link_idx == 0 : found_path['segment'][dut_idx - 1] = {}
                            found_path['segment'][dut_idx - 1].update({ segt_link_idx: segt_link})

                            if segt_link_idx == 0:
                                found_path['segment_count'] += 1
                            segt_link_idx += 1
                            #st.log("   Path node {} is {}".format(dut_idx - 1, segt_link))

                dut_idx += 1

        if save_path == 'yes' :
            sp_topo['subtopo']['star'] = copy.deepcopy(found_path)

        BGPSP.bgp_sp_show_topo_path(found_path)
        return found_path


    @staticmethod
    def bgp_sp_dut_get_saved_star_topo():
        return copy.deepcopy(sp_topo['subtopo']['star'])


    @staticmethod
    def bgp_sp_find_spine_leaf_topo_in_dut_list(spine_list=[], leaf_list=[], save_path='yes'):

        st.log("BGP SP - Find Spine Leaf paths in {} and {}.".format(spine_list, leaf_list))
        sp_topo_dut_list = BGPSP.bgp_sp_get_dut_list()

        found_path = {}
        found_path['found'] = False

        for dut in spine_list:
            if dut not in sp_topo_dut_list:
                st.log("Spine dut {} not in topo dut list {}".format(dut, sp_topo_dut_list))
                return found_path

        for dut in leaf_list:
            if dut not in sp_topo_dut_list:
                st.log("Leaf dut {} not in topo dut list {}".format(dut, sp_topo_dut_list))
                return found_path

        for dut in spine_list:
            if dut in leaf_list:
                st.log("Dut {} in both spine and leaf list {}".format(dut, spine_list))
                return found_path

        found_path['spine_list'] = spine_list
        found_path['leaf_list'] = leaf_list
        found_path['dut_list'] = []
        found_path['spine_path'] = {}
        found_path['type'] = 'SpineLeaf'

        for spine_dut in spine_list :

            dut_list = copy.deepcopy(leaf_list)
            dut_list.append(spine_dut)

            spine_path = BGPSP.bgp_sp_find_star_topo_in_dut_list(dut_list, spine_dut, save_path='no')

            st.log("Spine Leaf paths from {} is {}.\n".format(spine_dut, spine_path))

            if spine_path['found'] :
                found_path['found'] = True

                if spine_dut not in found_path['dut_list']:
                    found_path['dut_list'].append(spine_dut)

                for leaf_dut in spine_path['dut_list']:
                    if leaf_dut not in found_path['dut_list']:
                        found_path['dut_list'].append(leaf_dut)

            spine_path = copy.deepcopy(spine_path)
            found_path['spine_path'].update({ spine_dut : spine_path })

        if save_path == 'yes' :
            sp_topo['subtopo']['spine_leaf'] = copy.deepcopy(found_path)

        st.log("BGP SP - Spine Leaf paths {}\n".format(found_path))
        return found_path


    @staticmethod
    def bgp_sp_dut_get_saved_spine_leaf_topo():
        return copy.deepcopy(sp_topo['subtopo']['spine_leaf'])


    """ UNUSED AND CALLS UNDEFINED FUNCTION
    @staticmethod
    def bgp_sp_dut_get_connected_ip_links(from_dut, to_dut, addr_family):

        ip_link_list = []
        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
           return ip_link_list

        link_name_list = bgp_sp_dut_get_connected_link_names(from_dut, to_dut)
        if not link_name_list or len(link_name_list) == 0 :
            return ip_link_list

        ip_link_list = []
        for link_name in link_name_list:
            if link_name in sp_topo[dut][addr_family]['link'].keys():
                ip_data = sp_topo[dut][addr_family]['link'][link_name]
                if 'rmt_dut' in ip_data.keys():
                    if 'rmt_link' in ip_data.keys():
                        if ip_data['rmt_dut'] == to_dut :
                            ip_link_list.append(link_name)

        return ip_link_list
    """


    @staticmethod
    def bgp_sp_add_del_dut(dut, device_name, device_type='DUT', add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'

        if add == 'yes' :

            if BGPSP.bgp_sp_dut_present(dut):
               st.log("BGP SP - device {} exists as dut {}".format(device_name, dut))
               return False

            dut2 = BGPSP.bgp_sp_get_dut_from_device(device_name)
            if dut2 != "" and dut != dut2 :
               st.log("BGP SP - device {} exists as dut {}".format(device_name, dut2))
               return False

            st.log("BGP SP - {} {} {} {}".format(action_str, device_type, dut, device_name))
            if device_type == 'DUT' :
                sp_topo['dut_list'].append(dut)
                sp_topo['dut_list'].sort()
            else :
                sp_topo['tg_list'].append(dut)
                sp_topo['tg_list'].sort()

            sp_topo[dut] = {}
            sp_topo[dut]['type'] = device_type
            sp_topo[dut]['device'] = device_name
            sp_topo[dut]['intf'] = {}
            sp_topo[dut]['nwoctet'] = 0
            sp_topo[dut]['vrf'] = {}

            sp_topo[dut]['ipv4'] = {}
            sp_topo[dut]['ipv4']['static_nw'] = {}
            sp_topo[dut]['ipv4']['static_rt'] = {}
            sp_topo[dut]['ipv4']['link'] = {}
            sp_topo[dut]['ipv4']['nwoctet'] = 0

            sp_topo[dut]['ipv6'] = {}
            sp_topo[dut]['ipv6']['static_nw'] = {}
            sp_topo[dut]['ipv6']['static_rt'] = {}
            sp_topo[dut]['ipv6']['link'] = {}
            sp_topo[dut]['ipv6']['nwoctet'] = 0

            return True

        else :

            if not BGPSP.bgp_sp_dut_present(dut):
               st.log("BGP SP - dut doesnt exists {}".format(dut))
               return False

            if device_name != '' and device_name != sp_topo[dut]['device']:
               st.log("BGP SP - device {} isnot dut {}".format(device_name, dut))
               return False

            device_name = sp_topo[dut]['device']

            if len(sp_topo[dut]['intf']) != 0 :
                st.log("BGP SP - device {} {} interface exists".format(device_name, dut))
                return False

            st.log("BGP SP - Deleting device {} {} ".format(device_name, dut))
            del sp_topo[dut]
            if device_type == 'DUT' :
                del sp_topo['dut_list'][dut]
                sp_topo['dut_list'].sort()
            else :
                del sp_topo['tg_list'][dut]
                sp_topo['tg_list'].sort()

            return True

        #st.log("BGP SP - Dut {} FAILED".format(action_str))
        #return False


    @staticmethod
    def bgp_sp_add_del_link(dut, link_type, link_name, intf_name, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("BGP SP - Link {} for {} {}".format(action_str, dut, link_name))

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} doesnt exist".format(dut))
            return False

        if not BGPSP.bgp_sp_valid_link_type(link_type):
            st.log("BGP SP - Invalid intface type {}".format(link_type))
            return False

        if dut == "" or link_name=="" or intf_name == "" :
            st.log("BGP SP - Invalid dut {} or link {} or intf {}".format(dut, link_name, intf_name))
            return False

        if add == 'yes' :
            if BGPSP.bgp_sp_dut_link_present(dut, link_name):
                st.log("BGP SP - dut {} link {} already present".format(dut, link_name))
                return False

            if_data = { 'if': intf_name, 'type': link_type }
            sp_topo[dut]['intf'].update({link_name : if_data })

            return True

        else:
            if not BGPSP.bgp_sp_dut_link_present(dut, link_name):
                st.log("BGP SP - dut {} doesnt have intf {}".format(dut, link_name))
                return False

            if BGPSP.bgp_sp_dut_link_connected(dut, link_name):
               st.log("BGP SP - dut {} link {} connected".format(dut, link_name))
               return False

            if BGPSP.bgp_sp_dut_link_has_ip(dut, link_name, 'ipv4'):
               st.log("BGP SP - dut {} link {} has ipv4 addr".format(dut, link_name))
               return False

            if BGPSP.bgp_sp_dut_link_has_ip(dut, link_name, 'ipv6'):
               st.log("BGP SP - dut {} link {} has ipv6 addr".format(dut, link_name))
               return False

            st.log("BGP SP - dut {} deleting link {}".format(dut, link_name))
            del sp_topo[dut]['intf'][link_name]
            return True

        #st.log("BGP SP - Link {} FAILED".format(action_str))
        #return False


    @staticmethod
    def bgp_sp_connect_links(from_dut, from_link, to_dut, to_link, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("BGP SP - Link connect {} for {} {}".format(action_str, from_link, to_link))

        if not BGPSP.bgp_sp_dut_link_present(from_dut, from_link):
            st.log("BGP SP - dut {} link {} not present".format(from_dut, from_link))
            return False

        if not BGPSP.bgp_sp_dut_link_present(to_dut, to_link):
            st.log("BGP SP - dut {} link {} not present".format(to_dut, to_link))
            return False

        if add == 'yes' :

            if BGPSP.bgp_sp_dut_link_connected(from_dut, from_link):
                st.log("BGP SP - dut {} link {} already connected".format(from_dut, from_link))
                return False

            if BGPSP.bgp_sp_dut_link_connected(to_dut, to_link):
                st.log("BGP SP - dut {} link {} already connected".format(to_dut, to_link))
                return False

            sp_topo[from_dut]['intf'][from_link].update({'rmt_dut': to_dut})
            sp_topo[from_dut]['intf'][from_link].update({'rmt_link': to_link})

            sp_topo[to_dut]['intf'][to_link].update({'rmt_dut': from_dut})
            sp_topo[to_dut]['intf'][to_link].update({'rmt_link': from_link})

            if BGPSP.bgp_sp_dut_link_connected(from_dut, from_link):
               st.log("BGP SP - {} {} {} {} connected".format(from_dut, from_link, to_dut, to_link))
               return True

        else:

            if not BGPSP.bgp_sp_dut_link_connected_to_each_other(from_dut, from_link, to_dut, to_link):
                st.log("BGP SP - {} {} {} {} not connected".format(from_dut, from_link, to_dut, to_link))
                return False

            del sp_topo[from_dut]['intf'][from_link]['rmt_dut']
            del sp_topo[from_dut]['intf'][from_link]['rmt_link']
            del sp_topo[to_dut]['intf'][to_link]['rmt_dut']
            del sp_topo[to_dut]['intf'][to_link]['rmt_link']

            st.log("BGP SP - {} {} {} {} disconnected".format(from_dut, from_link, to_dut, to_link))
            return True

        return False


    @staticmethod
    def bgp_sp_add_del_link_ip(dut, link_name, ip_addr, subnet, rmt_ip, addr_family, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("BGP SP - Link ip {} for {} {} {}".format(action_str, dut, link_name, ip_addr))

        if not BGPSP.bgp_sp_dut_link_connected(dut, link_name):
            st.log("BGP SP - {} link not in connected state".format(link_name))

        if add == 'yes' :

            if BGPSP.bgp_sp_dut_ip_link_present(dut, link_name, addr_family) :
                st.log("BGP SP - {} {} already has {} address".format(dut, link_name, addr_family))
                return False

            if_data = sp_topo[dut]['intf'][link_name]
            ip_data = { "ip": ip_addr, "subnet": subnet, "if": if_data['if'], 'type': if_data['type']}

            if 'rmt_dut' in if_data.keys():
                ip_data.update({'rmt_dut': if_data['rmt_dut']})
                ip_data.update({'rmt_link': if_data['rmt_link']})

                if rmt_ip and rmt_ip != "":
                    ip_data.update({'rmt_ip': rmt_ip})

            sp_topo[dut][addr_family]['link'].update({link_name: ip_data})

            #st.log("BGP SP - Added IP link {} {}".format(link_name, ip_data))
            return True

        else:

            if not BGPSP.bgp_sp_dut_ip_link_present(dut, link_name, addr_family) :
                st.log("BGP SP - {} {} does not exist".format(dut, link_name))
                return True

            #if_data = sp_topo[dut]['intf'][link_name]
            #ip_data =  sp_topo[dut][addr_family]['link'][link_name]

            del sp_topo[dut][addr_family]['link'][link_name]

            #st.log("BGP SP - Deleted IP link {} {}".format(link_name, ip_data))
            return True

        #st.log("BGP SP - Link ip {} FAILED".format(action_str))
        #return False


    @staticmethod
    def bgp_sp_connect_all_ip_links():

        st.log("BGP SP - IP link connect all")

        nbr_visited = {}
        for dut in sp_topo['dut_list']:
            nbr_visited[dut] = False

        addr_family_list = BGPSP.bgp_sp_get_address_family_list("all")

        dut_list = BGPSP.bgp_sp_get_dut_list()
        dut_list += BGPSP.bgp_sp_get_tg_list()

        for lcl_dut in dut_list:
            for lcl_link, link_data in sp_topo[lcl_dut]['intf'].items():
                if 'rmt_dut' in link_data.keys():
                    rmt_dut = link_data['rmt_dut']
                    rmt_link = link_data['rmt_link']

                    for afmly in addr_family_list:
                        if lcl_link in sp_topo[lcl_dut][afmly]['link'].keys():
                            if rmt_link in sp_topo[rmt_dut][afmly]['link'].keys():

                                lcl_ip = sp_topo[lcl_dut][afmly]['link'][lcl_link]['ip']
                                rmt_ip = sp_topo[rmt_dut][afmly]['link'][rmt_link]['ip']

                                sp_topo[lcl_dut][afmly]['link'][lcl_link].update({'rmt_link': rmt_link})
                                sp_topo[lcl_dut][afmly]['link'][lcl_link].update({'rmt_dut': rmt_dut})
                                sp_topo[lcl_dut][afmly]['link'][lcl_link].update({'rmt_ip': rmt_ip})

                                sp_topo[rmt_dut][afmly]['link'][rmt_link].update({'rmt_link': lcl_link})
                                sp_topo[rmt_dut][afmly]['link'][rmt_link].update({'rmt_dut': lcl_dut})
                                sp_topo[rmt_dut][afmly]['link'][rmt_link].update({'rmt_ip': lcl_ip})

                    nbr_visited[lcl_dut] = True

        return True


    @staticmethod
    def bgp_sp_add_del_dut_static_network_prefix(dut, prefix, subnet, addr_family, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("BGP SP - Static nw {} for {} {}".format(action_str, dut, prefix))

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return False

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return False

        if add == 'yes' :
            snw_data = {'subnet': subnet}
            sp_topo[dut][addr_family]['static_nw'].update({prefix: snw_data})
        else :
            if prefix in sp_topo[dut][addr_family]['static_nw']:
                del sp_topo[dut][addr_family]['static_nw'][prefix]

        return True


    @staticmethod
    def bgp_sp_add_del_dut_static_route_prefix(dut, prefix, subnet, next_hop, addr_family, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("BGP SP - {} Static route {} pfx {} nhop {}.".format(action_str, dut, prefix, next_hop))

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return False

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return False

        if add == 'yes' :
            strt_data = {'nexthop' : next_hop , 'subnet': subnet}
            sp_topo[dut][addr_family]['static_rt'].update({prefix: strt_data})
        else :
            if prefix in sp_topo[dut][addr_family]['static_rt'].keys():
                del sp_topo[dut][addr_family]['static_rt'][prefix]

        return True


    @staticmethod
    def bgp_sp_add_del_dut_network_num(dut, nw_num, addr_family, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("BGP SP - Nw num {} for {} {}".format(action_str, dut, nw_num))

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return False

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return False

        if add == 'yes' :
            sp_topo[dut][addr_family]['nwoctet'] = nw_num
        else :
            sp_topo[dut][addr_family]['nwoctet'] = 0

        return True


    @staticmethod
    def bgp_sp_add_del_link_address_octate(link_name, addr_oct_list=[], add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("BGP SP - Addr octate {} for {} {}".format(action_str, link_name, addr_oct_list))

        if add == 'yes' :
           sp_topo['network'].update({link_name: addr_oct_list})
        else :
           if link_name in sp_topo['network'].keys():
               del sp_topo['network'][link_name]

        return True


    @staticmethod
    def bgp_sp_bgp_verify_routes_in_dut_list(dut_list=[], route_list=[], addr_family='ipv4', present='yes'):

        st.log("BGP SP - verify route list routes in list of duts")

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return False

        if len(dut_list) == 0 :
            st.log("BGP SP - Dut list List empty")
            return False

        if len(route_list) == 0 :
            st.log("BGP SP - Route List empty")
            if present == 'yes' :
                return True
            else :
                return False

        for dut in dut_list:
            tb_dut = BGPSP.bgp_sp_get_dut_device(dut)

            result = bgpapi.verify_ip_bgp_route_network_list(tb_dut, addr_family, route_list)
            if present == 'yes' :
                if not result :
                   st.log("BGP SP - {} doesnot have routes {} - failed result".format(dut, route_list))
                   return False
                else :
                   st.log("BGP SP - {} has routes {}".format(dut, route_list))
            else :
               if result :
                   st.log("BGP SP - {} has routes {} - failed result".format(dut, route_list))
                   return False
               else :
                   st.log("BGP SP - {} doesnot have routes {}".format(dut, route_list))

        if present == 'yes' :
            st.log("BGP SP - {} has routes {} - Success".format(dut_list, route_list))
        else:
            st.log("BGP SP - {} doesnot have routes {} - Success".format(dut_list, route_list))

        return True


    @staticmethod
    def bgp_sp_bgp_verify_static_route(dut_list=[], afmly_list=[], present='yes'):

        st.log("BGP SP - verify every has other  network due to root reflection")
        for dut in dut_list:
            other_dut_list = copy.deepcopy(dut_list)
            other_dut_list.remove(dut)

            for afmly in afmly_list:
                #strt_prefix_list = BGPSP.bgp_sp_get_dut_static_route_prefixes(dut, afmly)
                strt_prefix_list = BGPSP.bgp_sp_get_dut_null_nhop_static_route_prefixes(dut, afmly)
                strt_prefix_list = BGPSP.bgp_sp_ip_prefix_list_to_route_prefix_list(strt_prefix_list, afmly)

                st.log("BGP SP - {} static route prefixes {}".format(dut, strt_prefix_list))

                result = BGPSP.bgp_sp_bgp_verify_routes_in_dut_list(other_dut_list, strt_prefix_list, afmly, present=present)
                if not result :
                    st.log("BGP SP - Static route check FAILED")
                    return False

        st.log("BGP SP - Static route check Passed")
        return True


    @staticmethod
    def bgp_sp_get_matching_entries(entries=[], match=None):
         matched_entries = utils.filter_and_select(entries, None, match)
         if not matched_entries:
             st.log("\nBGP SP no match {} in\n {}\n".format(match, entries))
         else :
             st.log("\nBGP SP Matched {} entries\n {}\n".format(match, matched_entries))
         return matched_entries


    @staticmethod
    def bgp_sp_entries_are_matching(entries=[], match=None):
         matched_entries = BGPSP.bgp_sp_get_matching_entries(entries, match)
         if not matched_entries:
             return False
         return True


    @staticmethod
    def bgp_sp_get_matching_bgp_ip_routes(dut, route_prefix_list=[], addr_family='ipv4'):

        matched_entries = []
        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        show_output = bgpapi.show_ip_bgp_route(tb_dut, family=addr_family)
        #st.log("\nBGP SP ip bgp route  \n {}\n".format(show_output))

        if not route_prefix_list :
            return show_output

        for route_prefix in route_prefix_list:
            match = {'network': route_prefix}
            entries = utils.filter_and_select(show_output, None, match)
            #st.log("\nBGP SP filtered entries \n {}\n".format(entries))
            if entries:
                matched_entries += entries
            else :
                if len(matched_entries) :
                   st.log("BGP SP - Few entries dont match")
                return []

        #st.log("\nBGP SP route_prefixes Matched entries {}\n".format(matched_entries))
        return matched_entries


    @staticmethod
    def bgp_sp_bgp_ip_route_is_matching(dut, route_prefix_list=[], addr_family='ipv4', match=None):

        matched_entries = BGPSP.bgp_sp_get_matching_bgp_ip_routes(dut, route_prefix_list, addr_family)
        if not matched_entries :
           return False

        if not match:
           return True

        result = BGPSP.bgp_sp_entries_are_matching(matched_entries, match)
        return result


    @staticmethod
    def bgp_sp_bgp_ip_route_is_selected(dut, route_prefix_list=[], addr_family='ipv4', match=None):

        matched_entries = BGPSP.bgp_sp_get_matching_bgp_ip_routes(dut, route_prefix_list, addr_family)
        if not matched_entries :
           return False

        match_selected ={'status_code': '*>'}
        selected_entries = BGPSP.bgp_sp_get_matching_entries(matched_entries, match_selected)
        #if not matched_entries:
             #return False

        if not match:
           return True

        result = BGPSP.bgp_sp_entries_are_matching(selected_entries, match)
        return result


    @staticmethod
    def bgp_sp_bgp_ip_routes_matching(dut_list=[], route_prefix_list=[], addr_family='ipv4', match=None):

        fail_result_list = []
        for dut in dut_list :
            matched_entries = BGPSP.bgp_sp_get_matching_bgp_ip_routes(dut, route_prefix_list, addr_family)
            if not matched_entries :
                st.log("BGP SP - {} doesnt have all routes to {}".format(dut, route_prefix_list))
                fail_result = "BGP SP - {} doesnt have all matching routes ".format(dut)
                fail_result_list.append(fail_result)
                continue

            if not match:
                continue

            result = BGPSP.bgp_sp_entries_are_matching(matched_entries, match)
            if not result :
                st.log("BGP SP - {} routes do not match condition {}".format(dut, match))
                fail_result = "BGP SP - {} routes dont match route condition".format(dut)
                fail_result_list.append(fail_result)
                continue

        if len(fail_result_list):
            st.log("BGP SP - Dut List {}".format(dut_list))
            st.log("BGP SP - Route Prefix {}".format(route_prefix_list))
            st.log("BGP SP - Match condition {}".format(match))
            for fail_result in fail_result_list:
                st.log("{}".format(fail_result))
            st.log("BGP SP - IP routes not matching")
            return False

        st.log("BGP SP - IP routes matching")
        return True


    @staticmethod
    def bgp_sp_bgp_ip_routes_not_matching(dut_list=[], route_prefix_list=[], addr_family='ipv4', match=None):

        result = BGPSP.bgp_sp_bgp_ip_routes_matching(dut_list, route_prefix_list, addr_family, match)
        if result :
           return False
        else :
           return True


    @staticmethod
    def bgp_sp_dut_verify_bgp_ip_routes(dut, route_prefix_list=[], addr_family='ipv4', match=None):

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("Dut {} not present".format(dut))
            return False

        matched_entries = BGPSP.bgp_sp_get_matching_bgp_ip_routes(dut, route_prefix_list, addr_family)
        if not matched_entries :
            st.log("BGP SP - {} doesnt have all routes {}".format(dut, route_prefix_list))
            return False

        if match:
            result = BGPSP.bgp_sp_entries_are_matching(matched_entries, match)
            if not result :
                st.log("BGP SP - {} routes do not match condition {}".format(dut, match))
                return False

        st.log("BGP SP - {} IP routes matching".format(dut))
        return True


    @staticmethod
    def bgp_sp_verify_bgp_ip_routes(dut_list, route_prefix_list=[], addr_family='ipv4', match=None, threaded_run=True):

        st.log("BGP SP - Verify that {} has BGP routes {}".format(dut_list,route_prefix_list))

        result = True

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        dut_thread = []
        fail_result_list = []

        for dut in dut_list :
            dut_result = True
            if threaded_run:
                dut_thread.append([BGPSP.bgp_sp_dut_verify_bgp_ip_routes, dut, route_prefix_list, addr_family, match])
            else :
                dut_result = BGPSP.bgp_sp_dut_verify_bgp_ip_routes(dut, route_prefix_list, addr_family, match)

            if not dut_result:
                result = False
                st.log("BGP SP - {} routes do not match condition {}".format(dut, match))
                fail_result = "BGP SP - {} routes dont match route condition".format(dut)
                fail_result_list.append(fail_result)
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - BGP Route match Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result or len(fail_result_list):
            st.log("BGP SP - Dut List {}".format(dut_list))
            st.log("BGP SP - Route Prefix {}".format(route_prefix_list))
            st.log("BGP SP - Match condition {}".format(match))
            for fail_result in fail_result_list:
                st.log("{}".format(fail_result))
            st.log("BGP SP - IP routes not matching")
            return False

        st.log("BGP SP - IP routes matching")
        return True


    @staticmethod
    def bgp_sp_verify_no_bgp_ip_routes(dut_list, route_prefix_list=[], addr_family='ipv4', match=None, threaded_run=True):

        result = BGPSP.bgp_sp_verify_bgp_ip_routes(dut_list, route_prefix_list, addr_family, match, threaded_run)
        if not result :
           result = True
        else :
           result = False
        return result


    @staticmethod
    def bgp_sp_find_tb_connected_link(lcl_dut, lcl_if, rmt_tb, rmt_if):

        connected_link = { 'connected': False,
                           'lcl_dut' : lcl_dut,
                           'lcl_tb'  : '',
                           'lcl_link': '',
                           'lcl_if'  : lcl_if,
                           'rmt_dut' : '',
                           'rmt_tb'  : rmt_tb,
                           'rmt_link': '',
                           'rmt_if'  : rmt_if }

        connected_link['lcl_tb'] = BGPSP.bgp_sp_get_dut_device(lcl_dut)
        if connected_link['lcl_tb'] == '' :
            st.log("BGP SP - No lcl_tb, Link NOT connected {}".format(connected_link))
            return connected_link

        connected_link['rmt_dut'] = BGPSP.bgp_sp_get_dut_from_device(rmt_tb)
        if connected_link['rmt_dut'] == '' :
            st.log("BGP SP - No rmt dut, Link NOT connected {}".format(connected_link))
            return connected_link

        tb_vars = st.get_testbed_vars()
        tb_vars_keys = tb_vars.keys()

        for port_idx in range(1,20) :
            link_name = "{}{}P{}".format(connected_link['lcl_dut'],
                                         connected_link['rmt_dut'], port_idx)
            if link_name in tb_vars_keys :
                temp_lcl_if = tb_vars[link_name]
                if temp_lcl_if == lcl_if :
                    connected_link['lcl_link'] = link_name
                    break

        for port_idx in range(1,20) :
            link_name = "{}{}P{}".format(connected_link['rmt_dut'],
                                         connected_link['lcl_dut'], port_idx)
            if link_name in tb_vars_keys :
                temp_rmt_if = tb_vars[link_name]
                if temp_rmt_if == rmt_if :
                    connected_link['rmt_link'] = link_name
                    break

        if connected_link['lcl_link'] != '' and  connected_link['rmt_link'] != '' :
            connected_link['connected'] = True
            st.log("BGP SP - Link connected {}".format(connected_link))
            return copy.deepcopy(connected_link)

        st.log("BGP SP - Link NOT connected {}".format(connected_link))
        return {'connected': False }


    @staticmethod
    def bgp_sp_setup_testbed_topology(per_node_nw='no', nw_ip_octet='10'):
        st.banner("BGP SP - BUILD TOPOLOGY  - START")
        tb_vars = st.get_testbed_vars()
        tb_var_keys = tb_vars.keys()
        st.log("TestBed Vars => {}\n".format(tb_vars))

        sub_nw_idx = 32
        sp_topo['dut_list'] = []
        sp_topo['tg_list'] = []
        sp_topo['dut_map'] = {}
        sp_topo['tg_map']  = {}
        sp_topo['network'] = {}
        sp_topo['subtopo'] = {}
        sp_topo['subtopo']['linear'] = { 'found': False }
        sp_topo['subtopo']['ring'] = { 'found': False }
        sp_topo['subtopo']['star'] = {'found': False}
        sp_topo['subtopo']['spine_leaf'] = {'found': False}


        tb_dut_count = len(tb_vars.dut_list)
        for dut_idx in range(1, tb_dut_count+1) :
            dut = "D{}".format(dut_idx)
            if dut in tb_var_keys :
                sp_topo['dut_map'][dut] = tb_vars[dut]

        tb_tg_count = len(tb_vars.tgen_list)
        for tg_idx in range(1, tb_tg_count+1) :
            tgen = "T{}".format(tg_idx)
            if tgen in tb_var_keys :
                sp_topo['tg_map'][tgen] = tb_vars[tgen]

        st.log("BGP SP - Testbed Dut List {}".format(sp_topo['dut_map']))
        st.log("BGP SP - Testbed Tgen List {}".format(sp_topo['tg_map']))

        dut_idx = 0
        for dut, tb_dut_name in sp_topo['dut_map'].items():

            dut_idx += 1

            result = BGPSP.bgp_sp_add_del_dut(dut, tb_dut_name, add='yes')
            if not result:
               st.log("BGP SP - Dut {} add {} FAILED".format(dut, tb_dut_name))

            if per_node_nw == 'no' :
                nw_ipv4_octet = nw_ip_octet
            else :
                nw_ipv4_octet = int(nw_ip_octet) + dut_idx

            BGPSP.bgp_sp_add_del_dut_network_num(dut, nw_ipv4_octet, 'ipv4', 'yes')
            nw_ipv6_octet = "97{}".format(nw_ipv4_octet)
            BGPSP.bgp_sp_add_del_dut_network_num(dut, nw_ipv6_octet, 'ipv6', 'yes')


        for dut, tb_dut_name in sp_topo['tg_map'].items():

            dut_idx += 1

            result = BGPSP.bgp_sp_add_del_dut(dut, tb_dut_name, device_type='TG', add='yes')
            if not result:
               st.log("BGP SP - TG Dut {} add {} FAILED".format(dut, tb_dut_name))

            if per_node_nw == 'no' :
                nw_ipv4_octet = nw_ip_octet
            else :
                nw_ipv4_octet = int(nw_ip_octet) + dut_idx

            BGPSP.bgp_sp_add_del_dut_network_num(dut, nw_ipv4_octet, 'ipv4', 'yes')
            nw_ipv6_octet = "97{}".format(nw_ipv4_octet)
            BGPSP.bgp_sp_add_del_dut_network_num(dut, nw_ipv6_octet, 'ipv6', 'yes')


        sp_topo['dut_list'].sort()
        sp_topo['tg_list'].sort()
        #st.log("SP topo after dut add:\n{}\n".format(sp_topo))

        for from_dut_idx, from_dut in enumerate(sp_topo['dut_list'], start = 1):

            for count in range(0,2):
                intf_name = "Loopback{}".format(count)
                link_name = "{}L{}".format(from_dut, count)

                result = BGPSP.bgp_sp_add_del_link(from_dut, 'LBK', link_name, intf_name, add='yes')
                if not result:
                    st.log("Loopback interface {} add FAILED".format(link_name))

                nwoct4 = "{}".format(sp_topo[from_dut]['ipv4']['nwoctet'])
                nwoct3 = 8
                nwoct2 = count + 1

                lo_ip = "{}.{}.{}.{}".format(nwoct4, nwoct3, nwoct2, from_dut_idx)
                result = BGPSP.bgp_sp_add_del_link_ip(from_dut, link_name, lo_ip, 32, "", 'ipv4', add='yes')
                if not result:
                    st.log("Loopback interface IPv4 {} add FAILED".format(link_name))

                lo_ip = "{}:{}{}:{}{}::{}".format(nwoct4, from_dut_idx, nwoct3, nwoct2, count+1, from_dut_idx)
                result = BGPSP.bgp_sp_add_del_link_ip(from_dut, link_name, lo_ip, 128, "", 'ipv6', add='yes')
                if not result:
                    st.log("Loopback interface IPv6 {} add FAILED".format(link_name))

                addr_oct_list = [nwoct4, nwoct3, nwoct2, from_dut_idx]
                BGPSP.bgp_sp_add_del_link_address_octate(link_name, addr_oct_list, add='yes')

            #st.log("SP topo after dut loopback add :\n{}\n".format(sp_topo))

            lcl_dut = from_dut
            lcl_tb = BGPSP.bgp_sp_get_dut_device(lcl_dut)

            dut_links = st.get_dut_links(lcl_tb)
            tg_links = st.get_tg_links(lcl_tb)

            dut_all_links = dut_links + tg_links
            st.log("BGP SP - Dut {} links {}".format(lcl_dut, dut_all_links))

            for link_idx, link in enumerate(dut_all_links , start = 1):

                link_data = BGPSP.bgp_sp_find_tb_connected_link(lcl_dut, link[0], link[1], link[2])
                if not link_data['connected'] :
                        continue

                rmt_dut = link_data['rmt_dut']
                #rmt_tb = link_data['rmt_tb']

                lcl_if = link_data['lcl_if']
                rmt_if = link_data['rmt_if']

                lcl_link = link_data['lcl_link']
                rmt_link = link_data['rmt_link']

                BGPSP.bgp_sp_add_del_link(lcl_dut, 'ETH', lcl_link, lcl_if, add='yes')

                if BGPSP.bgp_sp_dut_is_tg(rmt_dut) :
                    BGPSP.bgp_sp_add_del_link(rmt_dut, 'ETH', rmt_link, rmt_if, add='yes')

                if BGPSP.bgp_sp_dut_link_present(rmt_dut, rmt_link):
                    BGPSP.bgp_sp_connect_links(lcl_dut, lcl_link, rmt_dut, rmt_link)

                if lcl_link in sp_topo['network'].keys() :
                    nwoct4 = sp_topo['network'][lcl_link][0]
                    nwoct3 = sp_topo['network'][lcl_link][1]
                    nwoct2 = sp_topo['network'][lcl_link][2]
                elif rmt_link in sp_topo['network'].keys():
                    nwoct4 = sp_topo['network'][rmt_link][0]
                    nwoct3 = sp_topo['network'][rmt_link][1]
                    nwoct2 = sp_topo['network'][rmt_link][2]
                else :
                    nwoct4 = "{}".format(sp_topo[lcl_dut]['ipv4']['nwoctet'])
                    nwoct3 = sub_nw_idx
                    sub_nw_idx += 2
                    nwoct2 = link_idx   #from_dut_idx

                if link_data['lcl_dut'] < link_data['rmt_dut'] :
                    lcl_host_num = 1
                    rmt_host_num = 2
                else:
                    lcl_host_num = 2
                    rmt_host_num = 1

                lcl_ip = "{}.{}.{}.{}".format(nwoct4, nwoct3, nwoct2, lcl_host_num)
                rmt_ip = "{}.{}.{}.{}".format(nwoct4, nwoct3, nwoct2, rmt_host_num)

                BGPSP.bgp_sp_add_del_link_ip(lcl_dut, lcl_link, lcl_ip, 24, rmt_ip, 'ipv4', add='yes')

                if BGPSP.bgp_sp_dut_is_tg(rmt_dut) :
                     BGPSP.bgp_sp_add_del_link_ip(rmt_dut, rmt_link, rmt_ip, 24, lcl_ip, 'ipv4', add='yes')

                lcl_ip = "{}:{}:{}::{}".format(nwoct4, nwoct3, nwoct2, lcl_host_num)
                rmt_ip = "{}:{}:{}::{}".format(nwoct4, nwoct3, nwoct2, rmt_host_num)

                BGPSP.bgp_sp_add_del_link_ip(lcl_dut, lcl_link, lcl_ip, 64, rmt_ip, 'ipv6', add='yes')

                if BGPSP.bgp_sp_dut_is_tg(rmt_dut) :
                     BGPSP.bgp_sp_add_del_link_ip(rmt_dut, rmt_link, rmt_ip, 64, lcl_ip, 'ipv6', add='yes')

                addr_oct_list = [nwoct4, nwoct3, nwoct2, lcl_host_num]
                BGPSP.bgp_sp_add_del_link_address_octate(lcl_link, addr_oct_list, add='yes')

                if BGPSP.bgp_sp_dut_is_tg(rmt_dut) :
                     BGPSP.bgp_sp_add_del_link_address_octate(rmt_link, addr_oct_list, add='yes')


            #st.log("SP topo after {} interface add :\n{}\n".format(from_dut, sp_topo))

            for count in range(1,3):
                link_name = "{}N{}".format(from_dut, count)
                nwoct4 = 216
                nwoct3 = 50 + count
                nwoct2 = from_dut_idx

                st_nw = "{}.{}.{}.{}".format(nwoct4, nwoct3, nwoct2, 0)
                BGPSP.bgp_sp_add_del_dut_static_network_prefix(from_dut,  st_nw, 24, 'ipv4', add='yes')

                st_nw = "{}:{}:{}::{}".format(nwoct4, nwoct3, nwoct2, 0)
                BGPSP.bgp_sp_add_del_dut_static_network_prefix(from_dut,  st_nw, 86, 'ipv6', add='yes')

                addr_oct_list = [nwoct4, nwoct3, nwoct2, 0]
                BGPSP.bgp_sp_add_del_link_address_octate(link_name, addr_oct_list, add='yes')

            for count in range(1,2):
                link_name = "{}RN{}".format(from_dut, count)
                nwoct4 = 209
                nwoct3 = 90 + count
                nwoct2 = from_dut_idx
                next_hop = "Null0"

                st_rt = "{}.{}.{}.{}".format(nwoct4, nwoct3, nwoct2, 0)
                BGPSP.bgp_sp_add_del_dut_static_route_prefix(from_dut, st_rt, 24, next_hop, 'ipv4', add='yes')

                st_rt = "{}:{}:{}::{}".format(nwoct4, nwoct3, nwoct2, 0)
                BGPSP.bgp_sp_add_del_dut_static_route_prefix(from_dut, st_rt, 64, next_hop, 'ipv6', add='yes')

                addr_oct_list = [nwoct4, nwoct3, nwoct2, 0]
                BGPSP.bgp_sp_add_del_link_address_octate(link_name, addr_oct_list, add='yes')

            for count in range(1,2):
                link_name = "{}RS{}".format(from_dut, count)
                nwoct4 = 208
                nwoct3 = 80 + count
                nwoct2 = from_dut_idx

                st_rt = "{}.{}.{}.{}".format(nwoct4, nwoct3, nwoct2, 0)
                #next_hop = BGPSP.bgp_sp_get_dut_loopback_ip(from_dut, 0, 'ipv4')
                next_hop = BGPSP.bgp_sp_get_unused_dut_interface(from_dut)
                BGPSP.bgp_sp_add_del_dut_static_route_prefix(from_dut, st_rt, 24, next_hop, 'ipv4', add='yes')

                st_rt = "{}:{}:{}::{}".format(nwoct4, nwoct3, nwoct2, 0)
                #next_hop = BGPSP.bgp_sp_get_dut_loopback_ip(from_dut, 0, 'ipv6')
                next_hop = BGPSP.bgp_sp_get_unused_dut_interface(from_dut)
                BGPSP.bgp_sp_add_del_dut_static_route_prefix(from_dut, st_rt, 64, next_hop, 'ipv6', add='yes')

                addr_oct_list = [nwoct4, nwoct3, nwoct2, 0]
                BGPSP.bgp_sp_add_del_link_address_octate(link_name, addr_oct_list, add='yes')

            #st.log("SP topo for {} :\n{}\n".format(from_dut, sp_topo))

        #st.log("SP topo at testbed topobuild complete:\n{}\n".format(sp_topo))

        BGPSP.bgp_sp_connect_all_ip_links()

        BGPSP.bgp_sp_show_dut_topo_data()

        st.banner("BGP SP - BUILD TOPOLOGY  - END")

        return True


    @staticmethod
    def bgp_sp_clear_testbed_topology(per_node_nw='no', nw_ip_octet='10'):
        sp_topo.clear()
        bgp_topo.clear()


    @staticmethod
    def bgp_sp_test_topo_present(topo_path=None, dut_count=None, segment_count=None):

        if dut_count :
            if BGPSP.bgp_sp_get_dut_count() < dut_count :
                st.log("BGP SP - Test case needs minimum {} duts in testbed".format(dut_count))
                return False

        if not topo_path :
            st.log("BGP SP - Testbed Topology path is Null")
            return False

        if 'found' not in topo_path.keys() :
            st.log("BGP SP - Invalid Path")
            return False

        if not topo_path['found'] :
            st.log("BGP SP - Required Topology path not found")
            return False

        if segment_count :
           if topo_path['segment_count'] < segment_count :
               st.log("BGP SP - Test case needs minimum {} segments in Topology path".format(segment_count))
               return False

        return True


    @staticmethod
    def bgp_sp_show_dut_topo_data(dut_list = []):

        if not dut_list :
            dut_list = BGPSP.bgp_sp_get_dut_list()
            dut_list += BGPSP.bgp_sp_get_tg_list()

            st.log("\n")
            st.log("BGP SP - Dut List: {}".format(sp_topo['dut_list']))
            st.log("BGP SP - Dut Dev Map: {}".format(sp_topo['dut_map']))
            st.log("BGP SP - TG List: {}".format(sp_topo['tg_list']))
            st.log("BGP SP - TG Dev Map: {}".format(sp_topo['tg_map']))

        for dut in dut_list:
            if not BGPSP.bgp_sp_dut_present(dut) :
               continue

            st.log("\n")
            st.log("BGP SP - Dut {} {} {}".format(dut, sp_topo[dut]['type'], sp_topo[dut]['device']))

            for intf, intf_data in sp_topo[dut]['intf'].items():
                st.log("           Intf {} {}".format(intf, intf_data))

            for link, link_data in sp_topo[dut]['ipv4']['link'].items():
                st.log("           Ipv4 Link {} {}".format(link, link_data))
            for link, link_data in sp_topo[dut]['ipv6']['link'].items():
                st.log("           Ipv6 Link {} {}".format(link, link_data))

            for stnw, stnw_data in sp_topo[dut]['ipv4']['static_nw'].items():
                st.log("           Static Ipv4 Nw {} {}".format(stnw, stnw_data))
            for stnw, stnw_data in sp_topo[dut]['ipv6']['static_nw'].items():
                st.log("           Static IPv6 Nw {} {}".format(stnw, stnw_data))

            for strt, strt_data in sp_topo[dut]['ipv4']['static_rt'].items():
                st.log("           Static Ipv4 Route {} {}".format(strt, strt_data))
            for strt, strt_data in sp_topo[dut]['ipv6']['static_rt'].items():
                st.log("           Static IPv6 Route {} {}".format(strt, strt_data))

            st.log("           Ipv4 Network Octates {}".format(sp_topo[dut]['ipv4']['nwoctet']))
            st.log("           IPv6 Network Octates {}".format(sp_topo[dut]['ipv6']['nwoctet']))

        st.log("\n")


    @staticmethod
    def bgp_sp_show_topo_path(path):

        if not path :
            st.log("BGP SP - Path Null")
            return

        if 'type' not in path.keys():
            st.log("BGP SP - Path Type Not found")
            return

        if 'found' not in path.keys():
            st.log("BGP SP - Path Invalid")
            return

        path_found = "Found" if path['found'] else "Not Found"

        st.log("BGP SP - {} Topo Path {}".format(path['type'], path_found))
        if not path['found'] : return

        st.log("     Dut List: {}".format(path['dut_list']))
        st.log("     Segt Count: {}".format(path['segment_count']))
        for segt_idx, segt_data in path['segment'].items():
            st.log("     Segment-{}: ".format(segt_idx))
            for link_idx, link_data in segt_data.items():
                 st.log("       Link-{}: {}".format(link_idx, link_data))
        st.log("\n")


    @staticmethod
    def bgp_sp_show_dut_if_cmd_logs(dut):
        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        st.show(tb_dut, "show ip interface")
        st.show(tb_dut, "show ipv6 interface")


    @staticmethod
    def bgp_sp_show_dut_route_cmd_logs(dut):
        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        st.vtysh_show(tb_dut, "show ip route")
        st.vtysh_show(tb_dut, "show ipv6 route")


    @staticmethod
    def bgp_sp_show_dut_bgp_cmd_logs(dut):
        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        st.vtysh_config(tb_dut, "do show running-config bgp")
        st.vtysh_show(tb_dut, "show ip bgp summary")
        st.vtysh_show(tb_dut, "show bgp ipv4")
        st.vtysh_show(tb_dut, "show bgp ipv6")


    @staticmethod
    def bgp_sp_show_dut_cmd_logs(dut):
        BGPSP.bgp_sp_show_dut_if_cmd_logs(dut)
        BGPSP.bgp_sp_show_dut_route_cmd_logs(dut)

    @staticmethod
    def bgp_sp_show_dut_bgp_running_config(dut_list=[]):
        for dut in dut_list :
            tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
            st.vtysh_config(tb_dut, "do show running-config bgp")

    @staticmethod
    def bgp_sp_loopback_interface_config_unconfig(config='yes', vrf='default', threaded_run=True):
        """

        :param config:
        :param vrf:
        :return:
        """
        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.banner("{}uring LOOPBACK Interface on all nodes.".format(action_str))

        result = True
        #threaded_run = True

        dut_list = BGPSP.bgp_sp_get_dut_list() #+ BGPSP.bgp_sp_get_tg_list()
        dut_thread = []

        for dut in dut_list :
            tb_dut = sp_topo[dut]['device']
            lpbk_if_data = {}

            if BGPSP.bgp_sp_dut_is_tg(dut) :
                st.log("BGP SP - TG {} Loopback config not done for now".format(dut))
                continue

            for _, link_data in sp_topo[dut]['intf'].items():
                if link_data['type'] != 'LBK':
                    continue

                if_name = link_data['if']
                lpbk_if_data[if_name] = 'default'


            loopback_names = list(lpbk_if_data.keys())
            if threaded_run:
                dut_thread.append(putils.ExecAllFunc(ipapi.config_loopback_interfaces, tb_dut, loopback_name=loopback_names, config=config))
            else :
                result = ipapi.config_loopback_interfaces(tb_dut, loopback_name=loopback_names, config=config)
                if not result :
                    st.log("{}uring {} loopback interfaces FAILED".format(action_str, dut))
                    return False

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        return result


    @staticmethod
    def bgp_sp_loopback_address_config_unconfig(config='yes', vrf='default', addr_family='all', threaded_run=True, debug_run=False):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """
        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.banner("{}uring LOOPBACK Addresses on all nodes.".format(action_str))

        if not BGPSP.bgp_sp_topology_data_present() :
            st.log("BGP SP Topology data not available")
            st.log("SP topo:\n{}\n".format(sp_topo))
            return False

        #threaded_run = True
        #debug_run = False
        result = True
        config = 'add' if config == 'yes' else 'remove'

        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)
        dut_thread = []

        dut_list = BGPSP.bgp_sp_get_dut_list() #+ BGPSP.bgp_sp_get_tg_list()

        for dut in dut_list :
            tb_dut = sp_topo[dut]['device']
            if_data_list = []

            if BGPSP.bgp_sp_dut_is_tg(dut) :
                st.log("BGP SP - TG {} Loopback IP config not done for now".format(dut))
                continue

            for afmly in addr_family_list:
                for _, link_data in sp_topo[dut][afmly]['link'].items():
                    if link_data['type'] != 'LBK':
                        continue

                    lpbk_if = link_data['if']
                    lpbk_ip = link_data['ip']
                    subnet  = link_data['subnet']

                    if_data_list.append({'name': lpbk_if, 'ip': lpbk_ip, 'subnet': subnet, 'family': afmly })
                    st.log("{}uring {} Loopback {}:{} {} {} ".format(action_str, afmly, dut, tb_dut, lpbk_if, lpbk_ip))

            if threaded_run:
                dut_thread.append([ipapi.config_unconfig_interface_ip_addresses, tb_dut, if_data_list, config])
            else :
                result = ipapi.config_unconfig_interface_ip_addresses(tb_dut, if_data_list, config=config)
                if not result:
                    BGPSP.bgp_sp_show_dut_cmd_logs(dut)
                    st.log("{}uring {} loopback address FAILED".format(action_str, dut))
                    return False

            if debug_run:
                BGPSP.bgp_sp_show_dut_if_cmd_logs(dut)

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        return result


    @staticmethod
    def bgp_sp_interface_address_all_config_unconfig(config='yes', vrf='default', addr_family='all', threaded_run=True, debug_run=False):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.banner("{}uring Interface Addresses on all nodes.".format(action_str))

        if not BGPSP.bgp_sp_topology_data_present() :
            st.log("BGP SP Topology data not available")
            st.log("SP topo:\n{}\n".format(sp_topo))
            return False

        #threaded_run = True
        #debug_run = False
        result = True

        config = 'add' if config == 'yes' else 'remove'

        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)
        dut_thread = []

        dut_list = BGPSP.bgp_sp_get_dut_list()

        for dut in dut_list :
            tb_dut = sp_topo[dut]['device']

            if_data_list = []

            for afmly in addr_family_list:
                for link_name, link_data in sp_topo[dut][afmly]['link'].items():
                    if link_data['type'] == 'LBK':
                        continue

                    link_ip = link_data['ip']
                    link_if = link_data['if']
                    subnet = link_data['subnet']

                    if_data_list.append({'name': link_if, 'ip': link_ip, 'subnet': subnet, 'family':afmly })

                    st.log("{}uring {} Interface {}:{} {}:{} {} ".format(action_str, afmly, dut,
                                                              tb_dut, link_name, link_if, link_ip))

            if threaded_run:
                dut_thread.append([ipapi.config_unconfig_interface_ip_addresses, tb_dut, if_data_list, config])
            else :
                result = ipapi.config_unconfig_interface_ip_addresses(tb_dut, if_data_list, config=config)
                if not result:
                    BGPSP.bgp_sp_show_dut_cmd_logs(dut)
                    st.log("{}uring {} Interface address FAILED".format(action_str, dut))
                    return False

            if debug_run:
                BGPSP.bgp_sp_show_dut_if_cmd_logs(dut)

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        return result


    @staticmethod
    def bgp_sp_tg_interface_ip_all_config_unconfig(config='yes', vrf='default', addr_family='all', threaded_run=True):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.banner("{}uring Interface Addresses on all TGENs.".format(action_str))

        if not BGPSP.bgp_sp_topology_data_present() :
            st.log("BGP SP Topology data not available")
            st.log("SP topo:\n{}\n".format(sp_topo))
            return False

        result = True
        #threaded_run = True
        dut_thread = []

        dut_list = BGPSP.bgp_sp_get_tg_list()

        for dut in dut_list :
            tb_dut = sp_topo[dut]['device']
            tg = tgen_obj_dict[tb_dut]

            for link_name, link_data in sp_topo[dut]['intf'].items():
                if link_data['type'] == 'LBK':
                   continue

                tb_if = link_data['if']
                tg_port_handle = tg.get_port_handle(tb_if)

                if config == 'yes' :
                    st.log("\n")
                    st.log("BGP SP - Resetting TG port {} {}".format(tb_dut, tb_if))
                    tg.tg_traffic_control(action="reset", port_handle=tg_port_handle)
                    st.log("\n")

                if threaded_run:
                    dut_thread.append([BGPSP.bgp_sp_tg_link_ip_config_unconfig, dut, link_name, addr_family, vrf, config])
                else :
                    result = BGPSP.bgp_sp_tg_link_ip_config_unconfig(dut, link_name, addr_family, vrf, config=config)
                    if not result:
                        BGPSP.bgp_sp_show_dut_cmd_logs(dut)
                        st.log("{}uring TG {} Interface address FAILED".format(action_str, dut))

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        return result


    @staticmethod
    def bgp_sp_dut_link_ip_config_unconfig(dut, link_name, addr_family='all', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring Interface Addresses on TG link.".format(action_str))

        result = True
        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)

        if not BGPSP.bgp_sp_dut_link_present(dut, link_name) :
            st.log("BGP SP - Dut {} link {} not present".format(dut, link_name))
            return False

        tb_dut = sp_topo[dut]['device']
        #link_data = sp_topo[dut]['intf'][link_name]
        #tb_if = link_data['if']

        for afmly in addr_family_list:

            if link_name not in sp_topo[dut][afmly]['link'].keys():
                st.log("BGP SP - {} {} {} address not assigned".format(dut, link_name, afmly))
                continue

            ip_data = sp_topo[dut][afmly]['link'][link_name]

            link_ip = ip_data['ip']
            link_if = ip_data['if']
            #rmt_ip  = ip_data['rmt_ip']
            subnet = ip_data['subnet']

            st.log("{}uring {} Interface {} {}:{} {} ".format(action_str, afmly,
                                                       tb_dut, link_name, link_if, link_ip))

            result = ipapi.config_ip_addr_interface(tb_dut, link_if, link_ip, subnet, afmly, config)

            if not result:
                BGPSP.bgp_sp_show_dut_cmd_logs(dut)
                st.log("{}uring {} Interface address FAILED".format(action_str, dut))
                break

        return result


    @staticmethod
    def bgp_sp_tg_link_ip_config_unconfig(dut, link_name, addr_family='all', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring Interface Addresses on TG link.".format(action_str))

        result = True

        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)

        if not BGPSP.bgp_sp_dut_link_present(dut, link_name) :
            st.log("BGP SP - Dut {} link {} not present".format(dut, link_name))
            return False

        tb_dut = sp_topo[dut]['device']
        link_data = sp_topo[dut]['intf'][link_name]
        tb_if = link_data['if']

        tg = tgen_obj_dict[tb_dut]
        tg_port_handle = tg.get_port_handle(tb_if)

        for afmly in addr_family_list:

            if link_name not in sp_topo[dut][afmly]['link'].keys():
                st.log("BGP SP - {} {} {} address not assigned".format(dut, link_name, afmly))
                continue

            ip_data = sp_topo[dut][afmly]['link'][link_name]

            link_ip = ip_data['ip']
            link_if = ip_data['if']
            rmt_ip  = ip_data['rmt_ip']
            subnet = ip_data['subnet']

            st.log("{}uring {} Interface {} {}:{} {} ".format(action_str, afmly,
                                                       tb_dut, link_name, link_if, link_ip))

            if config =='yes' :
                if afmly == 'ipv4':
                    tg_result = tg.tg_interface_config(port_handle=tg_port_handle, mode='config',
                                                       intf_ip_addr=link_ip,
                                                       gateway=rmt_ip, arp_send_req='1')
                else:
                    tg_result = tg.tg_interface_config(port_handle=tg_port_handle, mode='config',
                                                       ipv6_intf_addr=link_ip,
                                                       ipv6_prefix_length=subnet,
                                                       ipv6_gateway=rmt_ip, arp_send_req='1')

                st.log("BGP SP - Port ip config tg api result = {}".format(tg_result))

                if 'handle' in tg_result.keys():
                    sp_topo[dut][afmly]['link'][link_name]['tg_handle'] = tg_result['handle']
                else :
                    result = False
                    break

            else :
                handle = ''
                if 'tg_handle' in ip_data.keys():
                    handle = ip_data['tg_handle']

                if handle == '' :
                    st.log("BGP SP - {} {} {} tg handle invalid".format(dut, link_name, afmly))
                    continue

                if afmly == 'ipv4':
                    tg_result = tg.tg_interface_config(port_handle=tg_port_handle, handle=handle, mode='destroy')
                else:
                    tg_result = tg.tg_interface_config(port_handle=tg_port_handle, handle=handle, mode='destroy')

                st.log("BGP SP - Port ip Unconfig tg api result = {}".format(tg_result))

                sp_topo[dut][afmly]['link'][link_name]['tg_handle'] = ''

        if not result:
            BGPSP.bgp_sp_show_dut_cmd_logs(dut)
            st.log("{}uring TG {} Interface address FAILED".format(action_str, dut))

        return result


    @staticmethod
    def bgp_sp_static_route_config_unconfig(config='yes', vrf='default', addr_family='all', threaded_run=True, debug_run=False):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """
        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.banner("{}uring Static Route on all nodes.".format(action_str))

        if not BGPSP.bgp_sp_topology_data_present() :
            st.log("BGP SP Topology data not available")
            st.log("SP topo:\n{}\n".format(sp_topo))
            return False

        #threaded_run = True
        #debug_run = False
        result = True
        config = 'add' if config == 'yes' else 'remove'

        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)
        #thread_info = {'ipv4': [], 'ipv6': []}
        dut_thread = []

        for dut in sp_topo['dut_list'] :
            tb_dut = sp_topo[dut]['device']
            rt_data_list = []

            for afmly in addr_family_list:

                for prefix, strt_data in sp_topo[dut][afmly]['static_rt'].items():

                    nexthop = strt_data['nexthop']
                    subnet  = strt_data['subnet']
                    rt_data_list.append({ 'ip': prefix, 'subnet': subnet, 'nexthop': nexthop, 'family': afmly })

                    st.log("{}uring {} Static route {}:{} pfx {} nh {} .".format(action_str, afmly, dut, tb_dut, prefix, nexthop))

                    '''
                    prefix_sn = "{}/{}".format(prefix, subnet)
                    if config == 'add':
                        if threaded_run:
                             thread_info[afmly].append([ipapi.create_static_route, tb_dut, nexthop, prefix_sn, 'vtysh', afmly])
                        else:
                             result = ipapi.create_static_route(tb_dut, nexthop, prefix_sn, 'vtysh', afmly)
                    else:
                        if threaded_run:
                             thread_info[afmly].append([ipapi.delete_static_route, tb_dut, nexthop, prefix_sn, afmly, 'vtysh'])
                        else:
                             result = ipapi.delete_static_route(tb_dut, nexthop, prefix_sn, afmly, 'vtysh')
                    result = True
                    '''

            if threaded_run:
                dut_thread.append([ipapi.config_unconfig_static_routes, tb_dut, rt_data_list, "vtysh", config])
            else :
                result = ipapi.config_unconfig_static_routes(tb_dut, rt_data_list, shell="vtysh", config=config)
                if not result:
                    BGPSP.bgp_sp_show_dut_cmd_logs(dut)
                    st.log("{}uring {} Static route FAILED".format(action_str, dut))
                    return False

            if debug_run:
                BGPSP.bgp_sp_show_dut_route_cmd_logs(dut)

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        return result


    @staticmethod
    def bgp_sp_dut_interface_address_ping_test(dut, vrf='default', addr_family='all', ping_count=3):

        st.log("BGP SP - {} interface IP address Ping test".format(dut))

        #debug_run = False
        result = True

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("BGP SP - Dut {} not present".format(dut))
            return False

        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        BGPSP.bgp_sp_show_dut_route_cmd_logs(dut)

        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)

        for afmly in addr_family_list:
            for link_name, link_data in sp_topo[dut][afmly]['link'].items():
                if link_data['type'] == 'LBK' :
                    continue
                if 'rmt_ip' not in link_data.keys():
                    continue

                if BGPSP.bgp_sp_is_tg_connected_link(dut, link_name):
                    st.log("Not Trying Pinf test for TG connected link {}".format(link_name))
                    continue  #only for now

                lcl_ip = link_data['ip']
                rmt_ip = link_data['rmt_ip']
                st.log("Pingtest for {} {} {} --{}-> {} ".format(afmly, tb_dut, lcl_ip, link_name, rmt_ip))

                if not ipapi.ping(tb_dut, rmt_ip, family=afmly, count=ping_count):
                    st.log("Ping FAILED for {} {} {} --{}-> {} ".format(afmly, tb_dut, lcl_ip, link_name, rmt_ip))
                    st.log("ERROR Dut {} Ping to {} FAILED ".format(tb_dut, rmt_ip))
                    result = False
                    break

            if not result:
                st.log("{} Ping Test FAILED".format(dut))
                BGPSP.bgp_sp_show_dut_cmd_logs(dut)
                return False

        return result


    @staticmethod
    def bgp_sp_interface_address_ping_test(vrf='default', addr_family='all', ping_count=3):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """

        st.log("BGP SP network Ping test for interface IP addressess")

        if not BGPSP.bgp_sp_topology_data_present() :
            st.log("BGP SP Topology data not available")
            st.log("SP topo:\n{}\n".format(sp_topo))
            return False

        threaded_run = True
        result = True
        dut_thread = []

        dut_list = BGPSP.bgp_sp_get_dut_list()

        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :
            if threaded_run:
                dut_thread.append([BGPSP.bgp_sp_dut_interface_address_ping_test, dut, vrf, addr_family, ping_count])
            else :
                result = BGPSP.bgp_sp_dut_interface_address_ping_test(dut, vrf, addr_family, ping_count)

            if not result:
                BGPSP.bgp_sp_show_dut_if_cmd_logs(dut)
                st.log("BGP SP - Ping Test Failed for {}".format(dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Ping Test Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result:
            st.log("BGP SP - Interface Ping Test FAILED")

        return result


    @staticmethod
    def bgp_sp_dut_interface_shut_noshut(dut, link_name, shut='yes'):

        action_str = "Shut down" if shut == 'yes' else 'Startup'

        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        tb_intf =  BGPSP.bgp_sp_get_link_dut_interface(dut, link_name)

        if tb_dut == '' or tb_intf == '' :
            st.log("BGP SP - tb dut {} or if {} empty".format(tb_dut, tb_intf))
            return False

        st.log("BGP SP - {} {} {}".format(action_str, dut, link_name))

        if shut == 'yes':
            result = ifapi.interface_shutdown(tb_dut, tb_intf)
        else :
            result = ifapi.interface_noshutdown(tb_dut, tb_intf)

        if not result :
            st.log("BGP SP - {} {} {} Failed".format(action_str, dut, link_name))

        return result


    @staticmethod
    def bgp_sp_config_ip_topology_on_testbed():
        st.banner("BGP SP Base Class Pre CONFIG - START")
        BGPSP.bgp_sp_loopback_interface_config_unconfig(config='yes', vrf='default')
        BGPSP.bgp_sp_loopback_address_config_unconfig(config='yes', addr_family='all')
        BGPSP.bgp_sp_interface_address_all_config_unconfig(config='yes', addr_family='all')
        BGPSP.bgp_sp_static_route_config_unconfig(config='yes', addr_family='all')
        st.banner("BGP SP Base Class Pre CONFIG - END")


    @staticmethod
    def bgp_sp_unconfig_ip_topology_on_testbed():
        st.banner("BGP SP Base Class Pre CONFIG CLEANUP - START")
        BGPSP.bgp_sp_static_route_config_unconfig('no')
        BGPSP.bgp_sp_interface_address_all_config_unconfig(config='no')
        BGPSP.bgp_sp_loopback_address_config_unconfig(config='no')
        BGPSP.bgp_sp_loopback_interface_config_unconfig(config='no')
        st.banner("BGP SP Base Class Pre CONFIG CLEANUP - END")


    @staticmethod
    def bgp_sp_bgp_configured(dut, vrf='default'):

        if dut not in bgp_topo.keys():
            return False

        if vrf not in bgp_topo[dut].keys():
            return False

        if bgp_topo[dut][vrf]['asn'] == 0 :
            return False

        if bgp_topo[dut][vrf]['asn'] == '0' :
            return False

        if bgp_topo[dut][vrf]['asn'] == '' :
            return False

        return True


    @staticmethod
    def bgp_sp_get_bgp_asn(dut, vrf='default'):

        if not BGPSP.bgp_sp_bgp_configured(dut, vrf):
            return 0

        return int(bgp_topo[dut][vrf]['asn'])


    @staticmethod
    def bgp_sp_bgp_asn_match(dut, asn = 0, vrf='default'):

        if not BGPSP.bgp_sp_bgp_configured(dut, vrf):
            return 0

        bgp_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)

        if bgp_asn == asn :
            return True

        return False


    @staticmethod
    def bgp_sp_is_ip_bgp_neigbour(dut, nbr_ip, addr_family, vrf='default'):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return False

        if not BGPSP.bgp_sp_bgp_configured(dut, vrf):
            return False

        if nbr_ip in bgp_topo[dut][vrf][addr_family]['nbr'].keys():
            return True

        return False


    @staticmethod
    def bgp_sp_get_bgp_neigbour_ip_list(dut, addr_family, vrf='default'):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return []

        if not BGPSP.bgp_sp_bgp_configured(dut, vrf):
            return []

        nbr_ip_list = []
        for nbr_ip in bgp_topo[dut][vrf][addr_family]['nbr'].keys():
            nbr_ip_list.append(nbr_ip)

        return copy.deepcopy(nbr_ip_list)


    @staticmethod
    def bgp_sp_get_bgp_neigbour_list(dut, addr_family, vrf='default'):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return {}

        if not BGPSP.bgp_sp_bgp_configured(dut, vrf):
            return {}

        nbr_ip_data_list = {}
        for nbr_ip, nbr_data in bgp_topo[dut][vrf][addr_family]['nbr'].items():
            nbr_ip_data_list.update( { nbr_ip: nbr_data} )

        return copy.deepcopy(nbr_ip_data_list)


    @staticmethod
    def bgp_sp_get_bgp_neigbour_ip_between_duts(from_dut, to_dut, addr_family, from_vrf='default', to_vrf='default'):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return []

        from_asn = BGPSP.bgp_sp_get_bgp_asn(from_dut, from_vrf)
        to_asn = BGPSP.bgp_sp_get_bgp_asn(to_dut, to_vrf)
        to_dut_ip_list = BGPSP.bgp_sp_get_dut_ip_address_list(to_dut, addr_family, vrf=to_vrf)

        if from_asn == 0 or to_asn == 0 :
            return []

        nbr_ip_list = []
        for nbr_ip, nbr_data in bgp_topo[from_dut][from_vrf][addr_family]['nbr'].items():
            if nbr_data['rmt_asn'] == to_asn :
                if nbr_ip in to_dut_ip_list :
                    nbr_ip_list.append(nbr_ip)

        return copy.deepcopy(nbr_ip_list)


    @staticmethod
    def bgp_sp_get_bgp_network_prefix_list(dut, addr_family, vrf='default'):

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return {}

        if not BGPSP.bgp_sp_bgp_configured(dut, vrf):
            return {}

        nbr_nwip_list = {}
        for prefix, subnet in bgp_topo[dut][vrf][addr_family]['network'].items():
            nbr_nwip_list.update( {prefix: subnet} )

        return copy.deepcopy(nbr_nwip_list)


    @staticmethod
    def bgp_sp_bgp_config_unconfig(dut, local_asn, router_id='', vrf='default', config='yes', cli_type=""):
        """

        :param dut
        :param local_asn:
        :param vrf:
        :param config
        :return:
        """
        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP router.".format(action_str))

        if not BGPSP.bgp_sp_topology_data_present() :
            st.log("BGP SP Topology data not available")
            return False

        if not BGPSP.bgp_sp_dut_present(dut):
             st.log("BGP SP - Dut {} doesnt exist".format(dut))
             return False

        if not local_asn :
            st.log("BGP SP -  local asn not provided ")
            return False

        result = True

        if dut not in bgp_topo.keys():
            if config != 'yes' :
                st.log("BGP SP - {} BGP dut doesnt exist".format(dut))
                return False
            bgp_topo[dut] = {}

        if vrf not in bgp_topo[dut].keys():
            if config != 'yes' :
                st.log("BGP SP - {} vrf {} BGP router doesnt exist".format(dut, vrf))
                return True

            bgp_topo[dut][vrf] = {}
            bgp_topo[dut][vrf]['asn'] = int(local_asn)
            bgp_topo[dut][vrf]['rtrid'] = '0'
            bgp_topo[dut][vrf]['ipv4']={}
            bgp_topo[dut][vrf]['ipv4']['nbr']={}
            bgp_topo[dut][vrf]['ipv4']['unicast']={}
            bgp_topo[dut][vrf]['ipv4']['network'] = {}
            bgp_topo[dut][vrf]['ipv6']={}
            bgp_topo[dut][vrf]['ipv6']['nbr']={}
            bgp_topo[dut][vrf]['ipv6']['unicast']={}
            bgp_topo[dut][vrf]['ipv6']['network'] = {}

        if bgp_topo[dut][vrf]['asn'] != 0 :
            if bgp_topo[dut][vrf]['asn'] != local_asn:
                st.log("BGP SP - bgp asns {} {} dont match".format(bgp_topo[dut][vrf]['asn'], local_asn))
                return False

        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)

        if config == 'yes' :

            if not router_id or router_id == '' :
                router_id = BGPSP.bgp_sp_get_dut_loopback_ip(dut, 0, 'ipv4')

            st.log("BGP SP - {} vrf {} Configuring BGP with as {}".format(dut, vrf, local_asn))

            result = bgpapi.config_bgp_router(tb_dut, local_asn, router_id=router_id, keep_alive=30, hold=60, config='yes')
            if not result :
                st.log("BGP SP - {} vrf {} Configuring BGP with as {} FAILED".format(dut, vrf, local_asn))
                return False

            bgp_topo[dut][vrf]['asn'] = int(local_asn)
            bgp_topo[dut][vrf]['ipv4']['rtr_id'] = router_id

            bgpapi.config_bgp_default(tb_dut, local_asn, 'ipv4-unicast', config='no', cli_type=cli_type)

        else :

            st.log("BGP SP - {} vrf {} Unconfiguring BGP with as {}".format(dut, vrf, local_asn))

            result = bgpapi.config_bgp_router(tb_dut, local_asn, config='no')
            if not result :
                st.log("BGP SP - {} vrf {} UnConfiguring BGP with as {} FAILED".format(dut, vrf, local_asn))
                return False

            del bgp_topo[dut][vrf]

        #st.log("BGP SP - Bgp topo after {} router bgpn: {}".format(action_str, bgp_topo))
        return result


    @staticmethod
    def bgp_sp_dut_bgp_redistribute_connected_config_unconfig(dut, addr_family='all', tr_type='unicast', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP redistribute connected route on {}".format(action_str, dut))

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("Dut {} not present".format(dut))
            return False

        result = True
        afmly_list = BGPSP.bgp_sp_get_address_family_list(addr_family)

        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)

        if dut_asn == 0 :
            st.log("BGP SP - BGP bot configured in dut {}".format(dut))
            return False

        for afmly in afmly_list:
            bgpapi.config_address_family_redistribute(tb_dut, dut_asn, afmly, tr_type, "connected", config=config)

        return result


    @staticmethod
    def bgp_sp_bgp_redistribute_connected_config_unconfig(dut_list, addr_family='all', tr_type='unicast', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP redistribute connected route ".format(action_str))

        result = True
        threaded_run = True
        dut_thread = []

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :
            if threaded_run:
                dut_thread.append([BGPSP.bgp_sp_dut_bgp_redistribute_connected_config_unconfig,
                                         dut, addr_family, tr_type, vrf, config])
            else :
                result = BGPSP.bgp_sp_dut_bgp_redistribute_connected_config_unconfig(
                                         dut, addr_family, tr_type, vrf, config)

            if not result:
                st.log("BGP SP - Redistribute connected at {} failed".format(dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Redistribute connected Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result:
            st.log("BGP SP - {}uring Redistribute connected Static FAILED".format(action_str))

        return result


    @staticmethod
    def bgp_sp_dut_bgp_redistribute_static_config_unconfig(dut, addr_family='all', tr_type='unicast', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP redistribute static route on {}".format(action_str, dut))

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("Dut {} not present".format(dut))
            return False

        result = True
        afmly_list = BGPSP.bgp_sp_get_address_family_list(addr_family)
        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)

        dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)
        if dut_asn == 0 :
            st.log("BGP SP - BGP bot configured in dut {}".format(dut))
            return False

        for afmly in afmly_list:
            bgpapi.config_address_family_redistribute(tb_dut, dut_asn, afmly, tr_type, "static", config=config)

        return result


    @staticmethod
    def bgp_sp_bgp_redistribute_static_config_unconfig(dut_list, addr_family='all', tr_type='unicast', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP redistribute static route ".format(action_str))

        result = True
        threaded_run = True
        dut_thread = []

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :
            if threaded_run:
                dut_thread.append([BGPSP.bgp_sp_dut_bgp_redistribute_static_config_unconfig,
                                              dut, addr_family, tr_type, vrf, config])
            else :
                result = BGPSP.bgp_sp_dut_bgp_redistribute_static_config_unconfig(
                                              dut, addr_family, tr_type, vrf, config)

            if not result:
                st.log("BGP SP - Redistribute static at {} failed".format(dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Redistribute Static Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result:
            st.log("BGP SP - {}uring Redistribute Static FAILED".format(action_str))

        return result


    @staticmethod
    def bgp_sp_dut_bgp_network_advertise_config_unconfig(dut, network_list=[], addr_family='ipv4', vrf='default', config='yes', cli_type=""):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP network advertise on {}".format(action_str, dut))

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("Dut {} not present".format(dut))
            return False

        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return False

        result = True
        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)

        dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)
        if dut_asn == 0 :
            st.log("BGP SP - BGP bot configured in dut {}".format(dut))
            return False
        check_flag = True if config == "yes" else False
        for network_ip in network_list:
            result = bgpapi.config_bgp_network_advertise(tb_dut, dut_asn, network_ip, route_map='',
                                                         addr_family=addr_family, config=config, cli_type=cli_type, network_import_check=check_flag)

        return result


    @staticmethod
    def bgp_sp_bgp_network_advertise_config_unconfig(dut_list, network_list=[], addr_family='ipv4', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP network advertise ".format(action_str))

        result = True
        threaded_run = True
        dut_thread = []

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :
            if threaded_run:
                dut_thread.append([BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig,
                                         dut, network_list, addr_family, vrf, config])
            else :
                result = BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(
                                         dut, network_list, addr_family, vrf, config)

            if not result:
                st.log("BGP SP - Network advertise at {} failed".format(dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Network advertise Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result:
            st.log("BGP SP - {}uring Network advertise FAILED".format(action_str))

        return result


    @staticmethod
    def bgp_sp_bgp_deterministic_med_config_unconfig(dut_list, vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP deterministic Med".format(action_str))

        result = True
        threaded_run = True
        dut_thread = []

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :
            tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
            dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)

            if dut_asn == 0 :
                st.log("BGP SP - BGP not configured in dut {}".format(dut))
                return False

            if threaded_run:
                dut_thread.append([bgpapi.config_bgp_deterministic_med, tb_dut, dut_asn, config])
            else :
                result = bgpapi.config_bgp_deterministic_med(tb_dut, dut_asn, config=config)

            if not result:
                st.log("BGP SP - deterministic med at {} failed".format(dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Deterministic med Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result:
            st.log("BGP SP - {}uring Deterministic med FAILED".format(action_str))

        return result


    @staticmethod
    def bgp_sp_bgp_compare_med_config_unconfig(dut_list, vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP Always compare Med".format(action_str))

        result = True
        threaded_run = True
        dut_thread = []

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :
            tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
            dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)

            if dut_asn == 0 :
                st.log("BGP SP - BGP not configured in dut {}".format(dut))
                return False

            if threaded_run:
                dut_thread.append([bgpapi.config_bgp_always_compare_med, tb_dut, dut_asn, config])
            else :
                result = bgpapi.config_bgp_always_compare_med(tb_dut, dut_asn, config=config)

            if not result:
                st.log("BGP SP - compare med at {} failed".format(dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - compare med Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result:
            st.log("BGP SP - {}uring  Always compare med FAILED".format(action_str))

        return result


    @staticmethod
    def bgp_sp_bgp_ctoc_reflection_config_unconfig(dut_list, vrf='default', config='yes', cli_type=""):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP Client to Client Route Reflection".format(action_str))

        result = True
        threaded_run = True
        dut_thread = []

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :
            tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
            dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)

            if dut_asn == 0 :
                st.log("BGP SP - BGP not configured in dut {}".format(dut))
                return False

            if threaded_run:
                dut_thread.append([bgpapi.create_bgp_client_to_client_reflection, tb_dut, dut_asn, config, cli_type])
            else :
                result = bgpapi.create_bgp_client_to_client_reflection(tb_dut, dut_asn, config=config, cli_type= cli_type)

            if not result:
                st.log("BGP SP - Client to Client RR at {} failed".format(dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Client to Client RR Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result:
            st.log("BGP SP - {}uring Client to Client RR FAILED".format(action_str))

        return result


    @staticmethod
    def bgp_sp_bgp_neighbor_route_reflector_config_unconfig(dut, nbr_list=[], addr_family='ipv4', vrf='default', config='yes', cli_type="vtysh"):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP Neighbor Route Reflector clients ".format(action_str))

        result = True

        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)

        if dut_asn == 0 :
            st.log("BGP SP - dut {} doesnt have bgp configured".format(dut))
            return False

        if len(nbr_list) != 0:
            if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
                st.log("BGP SP - Invalid address family {}".format(addr_family))
                return False

        afmly_list = BGPSP.bgp_sp_get_address_family_list(addr_family)

        for afmly in afmly_list :
            dut_nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_list(dut, afmly, vrf=vrf)
            if len(nbr_list) == 0 :
                rr_nbr_list = dut_nbr_list
            else :
                rr_nbr_list = nbr_list

            for nbr_ip in rr_nbr_list :
                if nbr_ip not in dut_nbr_list :
                    st.log("BGP SP - nbr {} not in ngr list {} Failed".format(nbr_ip, dut_nbr_list))
                    continue

                st.log("BGP SP - {}uring {} route-reflector-client {}.".format(action_str, dut, nbr_ip))
                result = bgpapi.create_bgp_route_reflector_client(tb_dut, dut_asn, afmly, nbr_ip, config=config)
                if not result :
                    st.log("BGP SP - Configuring client reflection on {} {} bgp {} Failed".format(dut, afmly, dut_asn))
                    break

        return result


    @staticmethod
    def bgp_sp_route_map_config_unconfig(dut, rmap_name, condition='permit', sequence='', config='yes', **kwargs):

        cli_type = st.get_ui_type(dut, cli_type="")
        # cli_type = "vtysh" if cli_type in ['click', "vtysh"] else cli_type
        # cli_type = "vtysh" if cli_type in ["rest-patch", "rest-put"] else cli_type
        cli_type = "vtysh" if cli_type in ['click', "vtysh"] else ("klish" if cli_type in ["rest-patch", "rest-put"] else cli_type)
        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring route map".format(action_str))

        result = True
        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)

        no_params =  True if not kwargs else False
        cfg_action =  "no" if config == 'no' else ""
        cmd_str = ''

        if rmap_name == '' :
            st.log("BGP SP - Routemap name must")
            return False

        if no_params :
            if config == 'yes' :
                if sequence == '' :
                   st.log("BGP SP - Sequence value for rmap must")
                   return False
                else :
                   if condition == '':
                       st.log("BGP SP - routemap condition permit/deny is must")
                       return False
                   else :
                       cmd_str = "route-map {} {} {}".format(rmap_name, condition, sequence)

            elif config == 'no' :
                if sequence == '' :
                   cmd_str = "no route-map {}".format(rmap_name)
                else :
                   if condition == '':
                       st.log("BGP SP - routemap condition permit/deny is must")
                       return False
                   else :
                       cmd_str = "no route-map {} {} {}".format(rmap_name, condition, sequence)

        if no_params :
            #st.log("BGP SP - Route Map cmd without params is\n{}\n".format(cmd_str))
            st.config(tb_dut, cmd_str, type= cli_type)
            result =  True
            return result

        if condition == '':
            st.log("BGP SP - routemap condition permit/deny is must")
            return False

        cmd_str = "route-map {} {} {}".format(rmap_name, condition, sequence)

        if 'metric' in kwargs :
            metric = kwargs['metric']
            cmd_str += "\n   {} set metric {} ".format(cfg_action, metric)

        if 'community' in kwargs :
            community = kwargs['metric']
            cmd_str += "\n   {} set community {} ".format(cfg_action, community)

        #st.log("BGP SP - Route Map cmd is \n{}\n".format(cmd_str))
        st.config(tb_dut, cmd_str, type= cli_type)
        return result



    @staticmethod
    def bgp_sp_bgp_nexthop_self_config_unconfig(dut_list=[], addr_family='all', vrf='default', force='no', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP nexthop self ".format(action_str))

        result = True
        afmly_list = BGPSP.bgp_sp_get_address_family_list(addr_family)

        for dut in dut_list :
           tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
           dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)

           if dut_asn == 0 :
                st.log("BGP SP - BGP not configured on dut {}".format(dut))
                continue

           for afmly in afmly_list :
                dut_nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_list(dut, afmly, vrf=vrf)
                for bgp_nbr in dut_nbr_list :
                    st.log("BGP SP - {}uring {} nexthop self {}.".format(action_str, dut, bgp_nbr))
                    result = bgpapi.create_bgp_next_hop_self(tb_dut, dut_asn, afmly, bgp_nbr, force, config=config)
                    if not result :
                       st.log("BGP SP - Configuring nexthop self on {} {} bgp {} Failed".format(dut, afmly, dut_asn))
                       break
                    else :
                       if config == 'yes' :
                           bgp_topo[dut][vrf][afmly]['nbr'][bgp_nbr].update({'nh_self': True})
                       else :
                           del bgp_topo[dut][vrf][afmly]['nbr'][bgp_nbr]['nh_self']

        return result


    @staticmethod
    def bgp_sp_bgp_neighbor_route_map_config_unconfig(dut, nbr_list, route_map, direction, addr_family, vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP neighbor route map".format(action_str))

        result = True
        if not BGPSP.bgp_sp_addr_family_valid(addr_family) :
            st.log("BGP SP - Invalid address family {}".format(addr_family))
            return False

        if direction != 'in' and direction != 'out' :
            st.log("BGP SP - Invalid rmap direction {}".format(direction))
            return False

        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)
        dut_asn = BGPSP.bgp_sp_get_bgp_asn(dut, vrf)

        if dut_asn == 0 :
            st.log("BGP SP - dut {} doesnt have bgp configured".format(dut))
            return False

        dut_nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_list(dut, addr_family, vrf=vrf)

        for nbr_ip in nbr_list :
            if nbr_ip in dut_nbr_list :
                 bgpapi.config_bgp(dut=tb_dut, local_as=dut_asn, neighbor= nbr_ip,
                                    addr_family=addr_family, config_type_list =["routeMap"],
                                      routeMap=route_map,  diRection= direction, config = config)

                 result = True
                 if result :
                    if config == 'yes':
                        if direction == 'out' :
                            bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip].update({'route_map_out': route_map})
                        if direction == 'in' :
                            bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip].update({'route_map_in': route_map})
                    else :
                        if direction == 'out' :
                            if "route_map_out" in bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip]:
                                del bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip]['route_map_out']
                        if direction == 'in' :
                            if "route_map_in" in bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip]:
                                del bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip]['route_map_in']

        return result



    @staticmethod
    def bgp_sp_bgp_neighbor_config_unconfig(dut, nbr_ip, nbr_asn, addr_family, vrf='default', config='yes', cli_type=""):
        """

        :param dut
        :param nbr_ip:
        :param nbr_asn:
        :param addr_family
        :param vrf
        :param  config
        :return:
        """

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring BGP neighbor ".format(action_str))

        if not BGPSP.bgp_sp_topology_data_present() :
            st.log("BGP SP Topology data not available")
            st.log("SP topo:\n{}\n".format(sp_topo))
            return False

        if not nbr_ip or not nbr_asn :
            st.log("BGP SP - nbr_ip or asn not provided ")
            return False

        if not BGPSP.bgp_sp_addr_family_valid(addr_family):
            return False

        result = True

        if dut not in bgp_topo.keys():
            st.log("BGP SP - {} BGP dut not configured".format(dut))
            return False

        if vrf not in bgp_topo[dut].keys():
            st.log("BGP SP - {} BGP on vrf {} not configured".format(dut, vrf))
            return False

        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)

        lcl_asn = bgp_topo[dut][vrf]['asn']
        if lcl_asn == 0 :
            st.log("BGP SP - {} {} BGP lcl asn not set".format(dut, vrf))
            return False

        if config == 'yes' :

            if nbr_ip in bgp_topo[dut][vrf][addr_family]['nbr'].keys():

                st.log("BGP SP - {} vrf {} BGP nbr {} exists".format(dut, vrf, nbr_ip))

                nbr_data = bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip]
                if nbr_data['rmt_asn'] != nbr_asn :
                    st.log("BGP SP - {} vrf {} BGP nbr {} rmt asns {} wont match".format(dut, vrf, nbr_ip, nbr_asn))
                    return False

                result = True
                bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip].update({'nbr_ip' : nbr_ip})

            else :
                st.log("BGP SP - {} vrf {} Configuring BGP nbr {} asn {}".format(dut, vrf, nbr_ip, nbr_asn))

                result = bgpapi.config_bgp_neighbor(tb_dut, lcl_asn, nbr_ip, nbr_asn, addr_family, 3, 9, config='yes', cli_type=cli_type, connect_retry=1)
                if not result:
                    st.log("BGP SP - {} vrf {} Configuring BGP nbr {} asin {} FAILED".format(dut, vrf, nbr_ip, nbr_asn))
                    return False

                nbr_data = {'lcl_asn': lcl_asn, 'rmt_asn': nbr_asn, 'rmt_ip': nbr_ip }
                bgp_topo[dut][vrf][addr_family]['nbr'].update({nbr_ip : nbr_data})
        else :

            if nbr_ip not in bgp_topo[dut][vrf][addr_family]['nbr'].keys():
                st.log("BGP SP - {} vrf {} BGP nbr {} doesnt exists".format(dut, vrf, nbr_ip))
                return False

            st.log("BGP SP - {} vrf {} UnConfiguring BGP nbr {} asn {} ".format(dut, vrf, nbr_ip, nbr_asn))

            result = bgpapi.config_bgp_neighbor(tb_dut, lcl_asn, nbr_ip, nbr_asn, addr_family, config='no', cli_type=cli_type)
            if not result:
                st.log("BGP SP - {} vrf {} UnConfiguring BGP nbr {} asn {} FAILED".format(dut, vrf, nbr_ip, nbr_asn))

            del bgp_topo[dut][vrf][addr_family]['nbr'][nbr_ip]

        #st.log("BGP SP - Bgp topo after {} router bgp nbr: {}".format(action_str, bgp_topo))
        return result


    @staticmethod
    def bgp_sp_bgp_neighbor_segment_config_unconfig(segment_data={}, addr_family='all', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring Bgp segment".format(action_str))
        st.log("Input BGP Segment data : {}".format(segment_data))

        result = True
        threaded_run = False
        if config != 'yes' : threaded_run = True

        lcl_dut = segment_data['lcl_dut']
        lcl_asn = segment_data['lcl_asn']
        rmt_dut = segment_data['rmt_dut']
        rmt_asn = segment_data['rmt_asn']

        if 'lcl_vrf' in segment_data.keys():
            lcl_vrf = segment_data['lcl_vrf']
        else:
            lcl_vrf ='default'

        if 'rmt_vrf' in segment_data.keys():
            rmt_vrf = segment_data['rmt_vrf']
        else:
            rmt_vrf ='default'

        if 'lcl_link' in segment_data.keys():
            link = segment_data['lcl_link']
        else:
            link ='none'

        st.log("BGP SP - {}uring bgp nbr {}:{}--{}--{}:{}".format(
                                         action_str, lcl_dut, lcl_asn,
                                         link, rmt_asn, rmt_dut))


        for _ in range(0,1) :

            #ibgp_session = True if lcl_asn == rmt_asn else False

            if not BGPSP.bgp_sp_dut_present(lcl_dut) :
                st.log("BGP SP - Dut {} not in topology list ".format(lcl_dut))
                result = False
                break

            if not BGPSP.bgp_sp_dut_present(rmt_dut) :
                st.log("BGP SP - Dut {} not in topology list ".format(rmt_dut))
                result = False
                break

            addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)
            link_list = BGPSP.bgp_sp_dut_get_connected_links(lcl_dut, rmt_dut)

            if not link_list or len(link_list) == 0 :
                st.log("BGP SP - no links available between {} {}".format(lcl_dut, rmt_dut))

            bgp_configured = False

            for afmly in addr_family_list:
                lcl_ip = ''
                rmt_ip = ''
                link_name = ''

                if link == 'none' :
                    lcl_ip = BGPSP.bgp_sp_get_dut_loopback_ip(lcl_dut, 0, afmly)
                    rmt_ip = BGPSP.bgp_sp_get_dut_loopback_ip(rmt_dut, 0, afmly)
                elif link == 'any' :
                    if len(link_list) == 0 :
                        st.log("BGP SP - No link present between {} {}".format(lcl_dut, rmt_dut))
                        lcl_ip = BGPSP.bgp_sp_get_dut_loopback_ip(lcl_dut, 0, afmly)
                        rmt_ip = BGPSP.bgp_sp_get_dut_loopback_ip(rmt_dut, 0, afmly)
                    else :
                        link_name = link_list[0]
                else :
                    if link not in link_list :
                        st.log("BGP SP - Link {} not present between {} {}".format(link, lcl_dut, rmt_dut))
                        result = False
                        break

                    link_name = link

                    lcl_ip = BGPSP.bgp_sp_dut_get_link_local_ip(lcl_dut, link_name, afmly)
                    rmt_ip = BGPSP.bgp_sp_dut_get_link_remote_ip(lcl_dut, link_name, afmly)

                if lcl_ip == '' or rmt_ip == '' :
                    st.log("BGP SP - {} Link {} no have lcl/rmt {} {} ip assigned".format(afmly, link, lcl_ip, rmt_ip))
                    continue
                    #return False

                if not bgp_configured :

                    bgp_configured = True

                    dut_thread = []

                    if config == 'yes' :
                        if not BGPSP.bgp_sp_bgp_configured(lcl_dut, lcl_vrf):
                            st.log("BGP SP - {} BGP on vrf {} not configured".format(lcl_dut, lcl_vrf))

                            if threaded_run:
                                dut_thread.append([BGPSP.bgp_sp_bgp_config_unconfig,
                                                         lcl_dut, lcl_asn, '', lcl_vrf, config])
                            else :
                                result = BGPSP.bgp_sp_bgp_config_unconfig(
                                               lcl_dut, lcl_asn, router_id='', vrf=lcl_vrf, config=config)

                            if not result :
                                st.log("BGP SP - bgp config for {} {} FAILED".format(lcl_dut, lcl_asn))
                                result = False
                                break

                        if not BGPSP.bgp_sp_bgp_configured(rmt_dut, rmt_vrf) :
                            st.log("BGP SP - {} BGP on vrf {} not configured".format(rmt_dut, rmt_vrf))


                            if threaded_run:
                                dut_thread.append([BGPSP.bgp_sp_bgp_config_unconfig,
                                                         rmt_dut, rmt_asn, '', rmt_vrf, config])
                            else :
                                result = BGPSP.bgp_sp_bgp_config_unconfig(
                                               rmt_dut, rmt_asn, router_id='', vrf=rmt_vrf, config=config)

                            if not result :
                                st.log("BGP SP - bgp config for {} {} FAILED".format(rmt_dut, rmt_asn))
                                result = False
                                break

                        if threaded_run:
                            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
                            st.log("BGP SP - Bgp config Threaded Run result {}".format([out, exceptions]))
                            if False in out : result = False

                        if not result :
                            st.log("BGP SP - Neighbor BGP config FAILED")
                            return False


                dut_thread = []

                if threaded_run:
                    dut_thread.append([BGPSP.bgp_sp_bgp_neighbor_config_unconfig,
                                             lcl_dut, rmt_ip, rmt_asn, afmly, lcl_vrf, config])
                else :
                    result = BGPSP.bgp_sp_bgp_neighbor_config_unconfig(
                                   lcl_dut, rmt_ip, rmt_asn, afmly, vrf=lcl_vrf, config=config)

                if not result :
                    st.log("BGP SP - bgp nbr config for {} {} {} {} FAILED".format(lcl_dut, rmt_ip, rmt_asn, afmly))
                    result = False
                    break

                if threaded_run:
                    dut_thread.append([BGPSP.bgp_sp_bgp_neighbor_config_unconfig,
                                             rmt_dut, lcl_ip, lcl_asn, afmly, rmt_vrf, config])
                else :
                    result = BGPSP.bgp_sp_bgp_neighbor_config_unconfig(
                                   rmt_dut, lcl_ip, lcl_asn, afmly, vrf=rmt_vrf, config=config)

                if not result :
                    st.log("BGP SP - bgp nbr config for {} {} {} {} FAILED".format(rmt_dut, lcl_ip, lcl_asn, afmly))
                    result = False
                    break

            if threaded_run:
                [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
                st.log("BGP SP - Bgp Neighbor config Threaded Run result {}".format([out, exceptions]))
                if False in out : result = False

            if not result :
                break

            if not bgp_configured :
                result = False
                break

        result_str = "Success" if result else "FAILED"

        st.log("BGP SP - {}uring bgp nbr {}:{}--{}--{}:{} {}".format(
                                         action_str, lcl_dut, lcl_asn,
                                         link, rmt_asn, rmt_dut, result_str))
        return result



    @staticmethod
    def bgp_sp_bgp_asn_map_config_unconfig(dut_asn_map={}, config='yes', vrf='default', addr_family='all', max_adjacency='all', cli_type="vtysh", debug_run=False):
        """

        :param dut_asn_map
        :param config:
        :param vrf:
        :param addr_family
        :param max_adjacency
        :return:
        """
        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring list of bgp AS nodes.".format(action_str))

        if not BGPSP.bgp_sp_topology_data_present() :
            st.log("BGP SP Topology data not available")
            st.log("SP topo:\n{}\n".format(sp_topo))
            return False

        if not dut_asn_map :
            st.log("BGP SP DUT to AS Map not provided ")
            st.log("dut_asn_map:\n{}\n".format(dut_asn_map))
            return False

        #threaded_run = False
        #debug_run = False
        result = True

        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)
        dut_asn_map = {k: dut_asn_map[k] for k in sorted(dut_asn_map)}
        adj_limit = 10 if max_adjacency == 'all' else int(max_adjacency)

        st.log("BGP Dut Asn map: {}".format(dut_asn_map))

        for dut, as_num in dut_asn_map.items():
            if dut not in sp_topo['dut_list']:
               st.log("BGP SP - Dut {} not in BGP SP topology {}".format(dut, sp_topo['dut_list']))
               return False

        nbr_count = {}
        nbr_visited = {}
        for dut, as_num in dut_asn_map.items():
            nbr_visited[dut] = False

            result = BGPSP.bgp_sp_bgp_config_unconfig(dut, as_num, router_id='', vrf=vrf, config=config, cli_type=cli_type)
            if not result :
                st.log("BGP SP - bgp config for {} {} FAILED".format(dut, as_num))
                return False

        for dut, lcl_asn in dut_asn_map.items():
            #tb_dut = sp_topo[dut]['device']

            for link_name, link_data in sp_topo[dut]['intf'].items():

                if link_data['type'] == 'LBK':
                    continue

                rmt_dut = link_data['rmt_dut']
                if rmt_dut not in dut_asn_map.keys():
                    continue

                if nbr_visited[rmt_dut] :
                    continue

                rmt_asn = dut_asn_map[rmt_dut]

                from_node_adj = "{}{}".format(dut, rmt_dut)
                if from_node_adj not in nbr_count.keys():
                    nbr_count[from_node_adj] = 0

                to_node_adj = "{}{}".format(dut, rmt_dut)
                if to_node_adj not in nbr_count.keys():
                    nbr_count[to_node_adj] = 0

                if nbr_count[from_node_adj] >= adj_limit :
                    continue

                if nbr_count[to_node_adj] >= adj_limit :
                    continue

                nbr_added = False
                for afmly in addr_family_list:
                    if link_name in sp_topo[dut][afmly]['link'].keys():

                        ip_data = sp_topo[dut][afmly]['link'][link_name]

                        if 'rmt_ip' in ip_data.keys() :

                            lcl_ip = ip_data['ip']
                            rmt_ip = ip_data['rmt_ip']

                            result = BGPSP.bgp_sp_bgp_neighbor_config_unconfig(dut, rmt_ip, rmt_asn, afmly, vrf=vrf, config=config, cli_type=cli_type)
                            if not result :
                                st.log("BGP SP - bgp nbr config for {} {} {} {} FAILED".format(dut, rmt_ip, rmt_asn, afmly))
                                return False

                            result = BGPSP.bgp_sp_bgp_neighbor_config_unconfig(rmt_dut, lcl_ip, lcl_asn, afmly, vrf=vrf, config=config, cli_type=cli_type)
                            if not result :
                                st.log("BGP SP - bgp nbr config for {} {} {} {} FAILED".format(rmt_dut, lcl_ip, lcl_asn, afmly))
                                return False

                            nbr_added = True

                if nbr_added :
                    nbr_count[to_node_adj] += 1
                    nbr_count[from_node_adj] += 1

            nbr_visited[dut] = True

            if debug_run:
               BGPSP.bgp_sp_show_dut_bgp_cmd_logs(dut)

        return result



    @staticmethod
    def bgp_sp_clear_bgp(dut_list, addr_family='all'):

        if len(dut_list) == 0:
            dut_list = sp_topo['dut_list']

        st.log("BGP SP - Clearing BGP sessions {}".format(dut_list))

        result = True
        threaded_run = True
        dut_thread = []

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)

        for afmly in addr_family_list:
            dut_thread = []
            for dut in dut_list :
                if dut not in bgp_topo.keys():
                     continue

                if BGPSP.bgp_sp_dut_is_tg(dut) :
                    continue

                tb_dut = sp_topo[dut]['device']

                st.log("BGP SP - clearing {} bgp on {}".format(afmly , dut))
                if threaded_run:
                    if afmly == 'ipv4' :
                        dut_thread.append([bgpapi.clear_ip_bgp_vtysh, tb_dut])
                    else :
                        dut_thread.append([bgpapi.clear_ipv6_bgp_vtysh, tb_dut])
                else :
                    if afmly == 'ipv4' :
                        bgpapi.clear_ip_bgp_vtysh(tb_dut)
                    else :
                        bgpapi.clear_ipv6_bgp_vtysh(tb_dut)

            if threaded_run :
                [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
                st.log("BGP SP - Clear BGP Threaded Run result {}".format([out, exceptions]))
                if False in out : result = False

        return result


    @staticmethod
    def bgp_sp_cleanup_bgp_routers(dut_list = [], threaded_run=True):

        if len(dut_list) == 0:
            dut_list = sp_topo['dut_list']

        st.log("BGP SP - Unconfiguring BGP routers {}".format(dut_list))

        result = True
        #threaded_run = True
        device_list = []
        dut_thread = []

        for dut in dut_list :
            if dut not in bgp_topo.keys():
                st.log("BGP SP - BGP not in topo..force deleting bgp router on {}".format(dut))

            tb_dut = sp_topo[dut]['device']
            if not BGPSP.bgp_sp_dut_is_tg(dut) :
                device_list.append(tb_dut)
                dut_thread.append([bgpapi.unconfig_router_bgp, tb_dut])

            if dut in bgp_topo.keys():
                del bgp_topo[dut]

        if not device_list : return True

        st.log("BGP SP - clearing bgp on {}".format(device_list))

        if threaded_run :
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False
        else :
            result = bgpapi.cleanup_router_bgp(device_list)

        return result


    @staticmethod
    def bgp_sp_dut_verify_all_bgp_sessions(dut, addr_family='all', state='up'):

        st.log("BGP SP - Verify Bgp session {} on {}.".format(state, dut))

        if not BGPSP.bgp_sp_dut_present(dut):
            st.log("Dut {} not present".format(dut))
            return False

        if not bgp_topo[dut] :
            st.log("BGP SP - BGP not configured in {}".format(dut))
            return False

        result = True
        tb_dut = BGPSP.bgp_sp_get_dut_device(dut)

        addr_family_list = BGPSP.bgp_sp_get_address_family_list(addr_family)

        vrf_list = list(bgp_topo[dut].keys())

        for vrf in vrf_list :
            for afmly in addr_family_list:
                nbr_list = bgp_topo[dut][vrf][afmly]['nbr'].keys()

                loop_flag = 0
                for iter in range(6):
                    result_flag = 0
                    result = bgpapi.verify_bgp_summary(tb_dut, family=afmly, neighbor=nbr_list, state='Established')
                    if result :
                        if state == 'down' :
                            st.log("BGP SP - BGP session not down for nghbor {}".format(nbr_list))
                            BGPSP.bgp_sp_show_dut_route_cmd_logs(dut)
                            #break
                            result_flag = 1

                    if not result :
                        if state == 'up' :
                            st.log("BGP SP - BGP session not up for nghbor {}".format(nbr_list))
                            BGPSP.bgp_sp_show_dut_route_cmd_logs(dut)
                            #break
                            result_flag = 1

                    if result_flag == 0:
                        loop_flag = 0
                        break
                    else:
                        loop_flag = 1
                        st.wait(10, "Waiting or the connectios establishement")

                if loop_flag == 1:
                    break

            if not result :
                break

        result_str = "Success" if result else "Failed"
        st.log("BGP SP - BGP Session {} check {}".format(state, result_str))

        return result


    @staticmethod
    def bgp_sp_verify_all_bgp_sessions(dut_list=[], addr_family='all', state='up', threaded_run=True):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """

        if len(dut_list) == 0:
            dut_list = BGPSP.bgp_sp_get_dut_list()

        st.log("BGP SP - Verify {} Bgp Session {} on {}.".format(addr_family, state, dut_list))

        result = True
        dut_thread = []

        dut_list = list(dut_list) if isinstance(dut_list, list) else [dut_list]
        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :

            dut_result = True
            if threaded_run:
                dut_thread.append([BGPSP.bgp_sp_dut_verify_all_bgp_sessions, dut, addr_family, state])
            else :
                dut_result = BGPSP.bgp_sp_dut_verify_all_bgp_sessions(dut, addr_family, state)

            if not dut_result:
                result = False
                st.log("BGP SP - BGP session test at {} failed".format(dut))

        if threaded_run:
            [out, exceptions] = putils.exec_all(bgplib.fast_start, dut_thread)
            st.log("BGP SP - BGP session test Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        result_str = "Success" if result else "Failed"
        st.log("BGP SP - BGP Session {} check {}".format(state, result_str))

        return result


    @staticmethod
    def bgp_sp_linear_topo_bgp_config_unconfig(sess_type='eBGP', addr_family='all', ring='no', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        topology = "Linear" if ring == 'no' else "Ring"
        st.banner("{}uring {} topo {} session".format(action_str, topology, sess_type))

        if BGPSP.bgp_sp_get_dut_count() < 2 :
            st.log("BGP SP - Testbed doesnt have two duts")
            st.report_fail("test_case_passed")
            return False

        if config == 'yes' :
            if ring == 'no' :
                dut_linear_path = BGPSP.bgp_sp_find_linear_topo_in_dut_list()
            else :
                dut_linear_path = BGPSP.bgp_sp_find_ring_topo_in_dut_list()
        else :
            if ring == 'no' :
                dut_linear_path = BGPSP.bgp_sp_dut_get_saved_linear_topo()
            else :
                dut_linear_path = BGPSP.bgp_sp_dut_get_saved_ring_topo()

            BGPSP.bgp_sp_show_topo_path(dut_linear_path)

        if not dut_linear_path['found'] :
            st.log("BGP SP - Get linear path Failed")
            st.log("BGP SP - {} topo {} session test FAILED".format(sess_type, topology))
            st.report_fail("test_case_failed")
            return False

        dut_list = dut_linear_path['dut_list']
        path_segts = dut_linear_path['segment']

        result = True
        base_asn = 65001
        asn_index = 0

        segment_count = len(path_segts)

        form_ring_session = False
        if segment_count >= 2 and ring == 'yes' :
            form_ring_session = True

        for segt_idx, segt_data_links in path_segts.items():

            segt_data = segt_data_links[0]

            if form_ring_session and segt_idx == (segment_count - 1):
                # last node and first node segment
                lcl_asn = base_asn + asn_index
                rmt_asn = path_segts[0]['lcl_asn']

            elif sess_type == 'iBGP' :
                # all node i bgp
                lcl_asn = base_asn
                rmt_asn = base_asn

            elif sess_type == 'eBGP' :
                # all node ebgp
                lcl_asn = base_asn + asn_index
                asn_index += 1
                rmt_asn = base_asn + asn_index

            elif sess_type == 'eBGPiBGPeBGP' :
                # N--e--N--i--N--e--N...
                lcl_asn = base_asn + asn_index
                curr_sess = segt_idx % 3
                if curr_sess == 0 or curr_sess == 2:   #0-e 1=i 2=e
                    asn_index += 1
                rmt_asn = base_asn + asn_index

            elif sess_type == 'eBGPiBGPiBGP' :
                # N--e--N--i--N--i--N--i--N ...all i
                lcl_asn = base_asn + asn_index
                if segt_idx == 0:
                    asn_index += 1
                rmt_asn = base_asn + asn_index

            elif sess_type == 'eBGPeBGPiBGP' :
                # N--e--N--e--N--i--N--i--N ...all i
                lcl_asn = base_asn + asn_index
                if segt_idx <= 1:
                    asn_index += 1
                rmt_asn = base_asn + asn_index

            elif sess_type == 'iBGPeBGPiBGP' :
                # N--i--N--e--N--i--N--i--N ...all i
                lcl_asn = base_asn + asn_index
                if segt_idx == 1:
                    asn_index += 1
                rmt_asn = base_asn + asn_index

            else :
                st.log("BGP SP - Invalid BGP session Type passed {}".format(sess_type))
                return False

            segt_data.update({'lcl_asn': lcl_asn})
            segt_data.update({'rmt_asn': rmt_asn})

            result = BGPSP.bgp_sp_bgp_neighbor_segment_config_unconfig(segt_data, addr_family, config=config)
            if not result :
                 break

        if result and config == 'yes':
            st.wait(3)
            result = BGPSP.bgp_sp_verify_all_bgp_sessions(dut_list, addr_family='all')
            if not result :
                st.log("BGP SP - Linear topo session {} check Failed".format(sess_type))

        result_str = "Success" if result else "Failed"
        st.banner("BGP SP - {}uring {} topo {} session {}".format(action_str, topology, sess_type, result_str))

        return result


    @staticmethod
    def bgp_sp_star_topo_bgp_config_unconfig(bgp_asn=65008, sess_type='eBGP', addr_family='all', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.banner("{}uring Star topology {} session".format(action_str, sess_type))

        if BGPSP.bgp_sp_get_dut_count() < 3 :
            st.log("BGP SP - Testbed doesnt have minimum 3 duts")
            st.report_fail("test_case_passed")
            return False

        if config == 'yes' :
            dut_star_path = BGPSP.bgp_sp_find_star_topo_in_dut_list([],'', 0)
        else :
            dut_star_path = BGPSP.bgp_sp_dut_get_saved_star_topo()
            BGPSP.bgp_sp_show_topo_path(dut_star_path)

        if not dut_star_path['found'] :
            st.log("BGP SP - Get Star path Failed")
            st.report_fail("test_case_failed")
            return False

        dut_list = dut_star_path['dut_list']
        path_segts = dut_star_path['segment']

        result = True
        if len(path_segts) <  2 :
            st.log("BGP SP - Testbed doesnt have 3 connected nodes")
            st.report_fail("test_case_failed")
            return False

        core_asn = bgp_asn
        spoke_end_as = bgp_asn
        for _, segt_data_links in path_segts.items():

            segt_data = segt_data_links[0]

            if sess_type == 'eBGP' :
                spoke_end_as += 1

            segt_data.update({'lcl_asn': core_asn})
            segt_data.update({'rmt_asn': spoke_end_as})

            result = BGPSP.bgp_sp_bgp_neighbor_segment_config_unconfig(segt_data, addr_family, config=config)
            if not result :
                break

        if result and config == 'yes':
            st.wait(3)
            result = BGPSP.bgp_sp_verify_all_bgp_sessions(dut_list, addr_family='all')
            if not result :
                st.log("BGP SP - Star topology {} session check Failed".format(sess_type))

        result_str = "Success" if result else "Failed"
        st.banner("BGP SP - {}uring Star topology {} session {}".format(action_str, sess_type, result_str))

        return result


    @staticmethod
    def bgp_sp_spine_leaf_bgp_config_unconfig(spine_asn=65001, leaf_asn=65003, addr_family='all', config='yes', cli_type="vtysh"):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.banner("{}uring Spine Leaf BGP session".format(action_str))

        topo_dut_count = BGPSP.bgp_sp_get_dut_count()
        if topo_dut_count < 2 :
            st.log("BGP SP - Testbed doesnt have minimum 2 duts")
            st.report_fail("test_case_passed")
            return False

        topo_dut_list = BGPSP.bgp_sp_get_dut_list()

        st.log("BGP SP - dut count {} list {}".format(topo_dut_count, topo_dut_list))

        spine_list = []
        leaf_list = []
        dut_mid_index = topo_dut_count / 2
        dut_idx = 1

        for dut in topo_dut_list:
           if dut_idx <= dut_mid_index :
               spine_list.append(dut)
           else :
               leaf_list.append(dut)
           dut_idx += 1

        st.log("BGP SP - Spine List {} Leaf list {}".format(spine_list, leaf_list))

        if config == 'yes' :
            spine_leaf_path = BGPSP.bgp_sp_find_spine_leaf_topo_in_dut_list(spine_list, leaf_list, save_path='yes')
        else :
            spine_leaf_path = BGPSP.bgp_sp_dut_get_saved_spine_leaf_topo()

        st.log("BGP SP - Leaf Spine Path {}".format(spine_leaf_path))

        spine_leaf_session_count = 0

        for spine_dut, spine_path in spine_leaf_path['spine_path'].items():

            st.log("BGP SP - Spine Path \n")
            BGPSP.bgp_sp_show_topo_path(spine_path)

            if not spine_path['found'] :
                st.log("BGP SP - Spine {} doesnot have any leafs connected".format(spine_dut))
                continue

            dut_list = spine_path['dut_list']
            path_segts = spine_path['segment']

            result = True
            if len(path_segts) <  1 :
                st.log("BGP SP - Spine {} doesnt have connected leafs".format(spine_dut))
                continue

            for _, segt_data_links in path_segts.items():
                segt_data = segt_data_links[0]
                segt_data.update({'lcl_asn': spine_asn})
                segt_data.update({'rmt_asn': leaf_asn})

                result = BGPSP.bgp_sp_bgp_neighbor_segment_config_unconfig(segt_data, addr_family, config=config)
                if not result :
                    break

            spine_leaf_session_count += 1

        if result and spine_leaf_session_count < 1 :
            #result = False
            st.log("BGP SP - Zero spine leaf sessions")
            return False

        if result and config == 'yes' :
            st.wait(3)
            result = BGPSP.bgp_sp_verify_all_bgp_sessions(dut_list, addr_family='all')
            if not result :
                st.log("BGP SP - Spine Leaf BGP session check Failed")

        result_str = "Success" if result else "Failed"
        st.banner("BGP SP - {}uring Spine Leaf BGP session {}".format(action_str, result_str))

        return result


