#   Testbed Network Topology APIs
#   Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

import copy

from spytest import st, SpyTestDict, cutils, putils
from spytest.tgen.tg import tgen_obj_dict

import apis.routing.ip as ipapi
import apis.routing.vrf as vrfapi
import apis.system.interface as ifapi

nw_topo = SpyTestDict()
fast_start = True


class TOPOLOGY:

    @staticmethod
    def nw_topology_data_present():
        if nw_topo['inited'] :
            return True
        else :
            st.log("TOPOLOGY - ERROR - topology data not present - ERROR")
            return False

    @staticmethod
    def dut_present(dut):
        if not TOPOLOGY.nw_topology_data_present():
            return False
        if dut in nw_topo['dut_list'] :
            return True
        if dut in nw_topo['tg_list'] :
            return True
        return False


    @staticmethod
    def dut_list_present(dut_name_list = []):
        if not TOPOLOGY.nw_topology_data_present():
            return False
        if not dut_name_list or len(dut_name_list) == 0 :
            return False
        for dut_name in dut_name_list:
            if dut_name not in nw_topo['dut_list'] :
                return False
        return True


    @staticmethod
    def get_dut_count():
        if not TOPOLOGY.nw_topology_data_present():
            return 0
        return len (nw_topo['dut_list'])


    @staticmethod
    def get_dut_list():
        if not TOPOLOGY.nw_topology_data_present():
            return []
        return copy.deepcopy(nw_topo['dut_list'])


    @staticmethod
    def get_dut_from_device(device_name):
        if not TOPOLOGY.nw_topology_data_present():
            return False
        for dut in nw_topo['dut_list'] :
            if device_name == nw_topo[dut]['device'] :
                st.log("Topology - DUT device {} is dut {}".format(device_name, dut))
                return dut
        for dut in nw_topo['tg_list'] :
            if device_name == nw_topo[dut]['device'] :
                st.log("Topology - TG device {} is dut {}".format(device_name, dut))
                return dut
        st.log("Topology - device {} not in dut list".format(device_name))
        return ""


    @staticmethod
    def get_dut_device(dut):
        if not TOPOLOGY.nw_topology_data_present():
            return ''
        if dut in nw_topo['dut_list'] :
            return  nw_topo[dut]['device']
        return ''


    @staticmethod
    def get_tg_list():
        if not TOPOLOGY.nw_topology_data_present():
            return []
        return copy.deepcopy(nw_topo['tg_list'])


    @staticmethod
    def dut_is_tg(dut):
        if not TOPOLOGY.nw_topology_data_present():
            return False
        if dut in nw_topo['tg_list'] :
            if dut in nw_topo.keys() :
                if  nw_topo[dut]['type'] == 'TG' :
                    return True
        return False


    @staticmethod
    def get_dut_vrf_list(dut):
        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - Dut {} doesnt exist".format(dut))
            return False

        vrf_list = copy.deepcopy(nw_topo[dut]['vrf'].keys())
        return vrf_list


    @staticmethod
    def valid_link_type(link_type):
        if link_type in ["ETH", "LBK", "PCH", "VLN"] :
            return True
        return False


    @staticmethod
    def dut_link_present(dut, link_name):

        if not TOPOLOGY.dut_present(dut) :
            st.log("Topology - Link dut {} not in dut list".format(dut))
            return False

        if link_name not in nw_topo[dut]['intf'].keys():
            return False

        return True


    @staticmethod
    def dut_get_link_type(dut, link_name):

        if not TOPOLOGY.dut_link_present(dut, link_name) :
            st.log("Topology - Link dut {} link {} not present".format(dut, link_name))
            return False

        return nw_topo[dut]['intf'][link_name]['type']


    @staticmethod
    def get_dut_link_vrf(dut, link_name):

        if not TOPOLOGY.dut_link_present(dut, link_name):
            return ''

        link_data= nw_topo[dut]['intf'][link_name]
        if 'vrf' not in link_data.keys():
            st.log("Topology - Dut {} {} vrf assignment not present".format(dut, link_name))
            return ''

        return copy.deepcopy(link_data['vrf'])


    @staticmethod
    def link_present(link_name):

        if not link_name or link_name == '' :
            return False
        for dut in TOPOLOGY.get_dut_list():
            if link_name in nw_topo[dut]['intf'].keys():
                return True
        for dut in TOPOLOGY.get_tg_list():
            if link_name in nw_topo[dut]['intf'].keys():
                return True
        return False


    @staticmethod
    def dut_get_all_links(dut):

        if not TOPOLOGY.dut_present(dut):
            return []

        link_name_list = []
        for link_name, link_data in nw_topo[dut]['intf'].items():
            if link_data['type'] == 'LBK' :
                continue
            link_name_list.append(link_name)

        return copy.deepcopy(link_name_list)


    @staticmethod
    def get_link_dut_interface(dut, link_name):

        if TOPOLOGY.dut_link_present(dut, link_name):
            if_data = nw_topo[dut]['intf'][link_name]
            if 'if' in if_data.keys():
                return if_data['if']

        return ''


    @staticmethod
    def get_link_dut_interface_list(dut, link_name_list):

        dut_if_list = []
        for link_name in link_name_list:
            if_link = TOPOLOGY.get_link_dut_interface(dut, link_name)
            if if_link != '' :
                if if_link not in dut_if_list :
                    dut_if_list.append(if_link)

        return copy.deepcopy(dut_if_list)


    @staticmethod
    def dut_link_connected(dut, link_name):

        if TOPOLOGY.dut_link_present(dut, link_name):
            if_data = nw_topo[dut]['intf'][link_name]
            if 'rmt_dut' in if_data.keys():
                if 'rmt_link' in if_data.keys():
                    return True

        return False


    @staticmethod
    def dut_set_multipoint_remote_link(dut, link_name, rmt_dut, rmt_link):

        if not TOPOLOGY.dut_link_present(dut, link_name):
           st.log("Topology - dut {} link {} not present".format(dut, link_name))
           return {}

        if not TOPOLOGY.dut_link_present(rmt_dut, rmt_link):
           st.log("Topology - dut {} link {} not present".format(rmt_dut, rmt_link))

        if 'rmt_duts' not in nw_topo[dut]['intf'][link_name].keys():
            nw_topo[dut]['intf'][link_name]['rmt_duts'] = {rmt_dut : [rmt_link]}
            return True

        if rmt_dut not in nw_topo[dut]['intf'][link_name]['rmt_duts'].keys():
            nw_topo[dut]['intf'][link_name]['rmt_duts'].update({rmt_dut : [rmt_link]})
            return True

        if rmt_link not in nw_topo[dut]['intf'][link_name]['rmt_duts'][rmt_dut] :
            nw_topo[dut]['intf'][link_name]['rmt_duts'][rmt_dut].append(rmt_link)
            return True

        return False


    @staticmethod
    def dut_get_multipoint_remote_links(dut, link_name, rmt_dut='', rmt_link=''):

        if not TOPOLOGY.dut_link_present(dut, link_name):
            st.log("Topology - dut {} link {} not present".format(dut, link_name))
            return {}

        if_data = nw_topo[dut]['intf'][link_name]

        if 'rmt_duts' not in if_data.keys():
            return {}

        remote_links = copy.deepcopy(if_data['rmt_duts'])

        return remote_links


    @staticmethod
    def dut_get_remote_dut(dut, link_name):

        if TOPOLOGY.dut_link_present(dut, link_name):
            if_data = nw_topo[dut]['intf'][link_name]
            if 'rmt_dut' in if_data.keys():
                return nw_topo[dut]['intf'][link_name]['rmt_dut']

        return ''


    @staticmethod
    def dut_get_remote_link(dut, link_name):

        if TOPOLOGY.dut_link_present(dut, link_name):
            if_data = nw_topo[dut]['intf'][link_name]
            if 'rmt_dut' in if_data.keys():
                if 'rmt_link' in if_data.keys():
                    return nw_topo[dut]['intf'][link_name]['rmt_link']

        return ''


    @staticmethod
    def dut_link_has_link_member(dut, link_name, link_member=""):

        if not TOPOLOGY.dut_link_present(dut, link_name):
            st.log("Topology - dut {} link {} not present".format(dut, link_name))
            return False

        if link_member != "" :
            if link_member in nw_topo[dut]['intf'][link_name]['members'] :
                return True
        else :
            if len(nw_topo[dut]['intf'][link_name]['members']) :
                return True

        return False


    @staticmethod
    def dut_get_link_members(dut, link_name):

        if not TOPOLOGY.dut_link_present(dut, link_name):
            st.log("Topology - dut {} link {} not present".format(dut, link_name))
            return False

        if 'members' not in nw_topo[dut]['intf'][link_name].keys() :
            return []

        return copy.deepcopy(nw_topo[dut]['intf'][link_name]['members'])


    @staticmethod
    def dut_link_has_sub_ifs(dut, link_name, sub_if=""):

        if not TOPOLOGY.dut_link_present(dut, link_name):
            st.log("Topology - dut {} link {} not present".format(dut, link_name))
            return False

        if sub_if != "" :
            if sub_if in nw_topo[dut]['intf'][link_name]['sub_ifs'] :
                return True
        else :
            if len(nw_topo[dut]['intf'][link_name]['sub_ifs']) :
                return True

        return False


    @staticmethod
    def dut_get_link_sub_ifs(dut, link_name):

        if not TOPOLOGY.dut_link_present(dut, link_name):
            st.log("Topology - dut {} link {} not present".format(dut, link_name))
            return False

        if 'sub_ifs' not in nw_topo[dut]['intf'][link_name].keys() :
            return []

        return copy.deepcopy(nw_topo[dut]['intf'][link_name]['sub_ifs'])


    @staticmethod
    def dut_get_link_vrf(dut, link_name):

        if not TOPOLOGY.dut_link_present(dut, link_name):
            st.log("Topology - dut {} link {} not present".format(dut, link_name))
            return ''

        return nw_topo[dut]['intf'][link_name]['vrf']


    @staticmethod
    def dut_get_vrf_links(dut, vrf):

        if not TOPOLOGY.dut_present(dut):
            return []

        link_name_list = []
        for link_name, link_data in nw_topo[dut]['intf'].items():
            if 'vrf' in link_data.keys():
                if link_data['vrf'] == vrf:
                    link_name_list.append(link_name)

        return copy.deepcopy(link_name_list)


    @staticmethod
    def dut_get_vrf_loopbacks(dut, vrf):

        if not TOPOLOGY.dut_present(dut):
            return []

        link_name_list = []
        for link_name, link_data in nw_topo[dut]['intf'].items():
            if link_data['type'] == 'LBK':
                if 'vrf' in link_data.keys():
                   if link_data['vrf'] == vrf:
                       link_name_list.append(link_name)

        return copy.deepcopy(link_name_list)


    @staticmethod
    def dut_get_vrf_nonloopback_links(dut, vrf):

        if not TOPOLOGY.dut_present(dut):
            return []

        link_name_list = []
        for link_name, link_data in nw_topo[dut]['intf'].items():
            if link_data['type'] != 'LBK':
                if 'vrf' in link_data.keys():
                   if link_data['vrf'] == vrf:
                       link_name_list.append(link_name)

        return copy.deepcopy(link_name_list)


    @staticmethod
    def is_tg_connected_link(dut, link_name):

        rmt_dut = TOPOLOGY.dut_get_remote_dut(dut, link_name)
        if rmt_dut == '' :
            return False

        if TOPOLOGY.dut_is_tg(rmt_dut):
           return True

        return False


    @staticmethod
    def dut_get_tg_connected_links(dut):

        if not TOPOLOGY.dut_present(dut):
            return []

        link_name_list = []
        for link_name, link_data in nw_topo[dut]['intf'].items():
            if 'rmt_dut' in link_data.keys():
                rmt_dut = link_data['rmt_dut']
                if TOPOLOGY.dut_is_tg(rmt_dut):
                    link_name_list.append(link_name)

        return link_name_list


    @staticmethod
    def dut_get_tg_connected_link_data(dut, link_name):

        if not TOPOLOGY.is_tg_connected_link(dut, link_name):
            return {}

        link_data = nw_topo[dut]['intf'][link_name]
        rmt_dut = link_data['rmt_dut']
        if TOPOLOGY.dut_is_tg(rmt_dut):
            return copy.deepcopy(link_data)

        return {}


    @staticmethod
    def dut_get_connected_first_link(from_dut, to_dut):

        if not TOPOLOGY.dut_present(from_dut):
            return ''

        if not TOPOLOGY.dut_present(to_dut):
            return ''

        for link_name, link_data in nw_topo[from_dut]['intf'].items():
            if 'rmt_dut' in link_data.keys():
                if link_data['rmt_dut'] == to_dut :
                    if 'rmt_link' in link_data.keys():
                         return link_name

        return ''


    @staticmethod
    def dut_get_connected_links(from_dut, to_dut):

        if not TOPOLOGY.dut_present(from_dut):
            return []

        if not TOPOLOGY.dut_present(to_dut):
            return []

        link_name_list = []
        for link_name, link_data in nw_topo[from_dut]['intf'].items():
            if 'rmt_dut' in link_data.keys():
                if link_data['rmt_dut'] == to_dut :
                    if 'rmt_link' in link_data.keys():
                         link_name_list.append(link_name)

        return link_name_list


    @staticmethod
    def dut_link_connected_to_each_other(from_dut, from_link, to_dut, to_link):

        if not TOPOLOGY.dut_link_connected(from_dut, from_link):
            return False

        if not TOPOLOGY.dut_link_connected(to_dut, to_link):
            return False

        from_if_info = nw_topo[from_dut]['intf'][from_link]
        to_if_info = nw_topo[to_dut]['intf'][to_link]

        if from_if_info['rmt_dut'] != to_dut:
            return False
        if to_if_info['rmt_dut'] != from_dut:
            return False
        if from_if_info['rmt_link'] != to_link:
            return False
        if to_if_info['rmt_link'] != from_link :
            return False

        return True


    @staticmethod
    def get_unused_dut_interface(dut):

        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - {} not present".format(dut))
            return ''

        dut_if_list = []
        for _, link_data in nw_topo[dut]['intf'].items():
            if 'if' in link_data.keys():
                dut_if_list.append(link_data['if'])

        if_idx = 80
        while if_idx < 100:
            if_name = "Ethernet{}".format(if_idx)
            if if_name not in dut_if_list :
               st.log("Topology - Found unused interface {} in dut {}".format(if_name, dut))
               return copy.deepcopy(if_name)
            if_idx += 4

        st.log("Topology - No unused interfaces in {}".format(dut))
        return ''


    @staticmethod
    def addr_family_valid(addr_family):

        if addr_family != 'ipv4' and addr_family != 'ipv6' :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return False
        return True


    @staticmethod
    def get_address_family_list(addr_family):

        addr_family_list = []
        if addr_family == 'ipv4' or addr_family == 'all':
            addr_family_list.append('ipv4')
        if addr_family == 'ipv6' or addr_family == 'all':
            addr_family_list.append('ipv6')
        return addr_family_list


    @staticmethod
    def ip_prefix_to_route_prefix(prefix, addr_family):

        route_prefix = prefix

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return route_prefix

        if addr_family == 'ipv6' :
            temp_prefix = prefix.partition(":0/")
            if temp_prefix and len(temp_prefix) == 3 and temp_prefix[1] == ":0/" :
                route_prefix = "{}:/{}".format(temp_prefix[0], temp_prefix[2])

        return route_prefix


    @staticmethod
    def ip_prefix_list_to_route_prefix_list(prefix_list, addr_family):

        route_prefix_list = []

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return route_prefix_list

        for prefix in prefix_list :
            route_prefix = TOPOLOGY.ip_prefix_to_route_prefix(prefix, addr_family)
            if route_prefix != '':
                route_prefix_list.append(route_prefix)

        #st.log("Topology - route_prefix list {}".format(route_prefix_list))
        return copy.deepcopy(route_prefix_list)


    @staticmethod
    def dut_ip_link_present(dut, link_name, addr_family):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return False

        if TOPOLOGY.dut_link_present(dut, link_name):
            if link_name in nw_topo[dut][addr_family]['link'].keys():
                return True

        return False


    @staticmethod
    def dut_get_ip_link(dut, link_name, addr_family):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return {}

        if TOPOLOGY.dut_link_present(dut, link_name):
            if link_name in nw_topo[dut][addr_family]['link'].keys():
                ip_data = nw_topo[dut][addr_family]['link'][link_name]
                return copy.deepcopy(ip_data)

        return {}


    @staticmethod
    def dut_link_has_ip(dut, link_name, addr_family):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return False

        if TOPOLOGY.dut_link_present(dut, link_name):
            if link_name in nw_topo[dut][addr_family]['link'].keys():
                ip_data = nw_topo[dut][addr_family]['link'][link_name]
                if 'ip' in ip_data.keys():
                    return True

        st.log("Topology - {} {} doesnot have ip address".format(dut, link_name))
        return False


    @staticmethod
    def dut_get_link_ip_and_subnet(dut, link_name, addr_family):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return '', ''

        subnet = 32 if addr_family == 'ipv4' else 128

        #st.log("Topology - Find local ip {} {} {}".format(dut, link_name, addr_family))
        if TOPOLOGY.dut_link_present(dut, link_name):
            if link_name in nw_topo[dut][addr_family]['link'].keys():
                ip_data = nw_topo[dut][addr_family]['link'][link_name]
                if 'subnet' in ip_data.keys():
                    subnet = ip_data['subnet']
                if 'ip' in ip_data.keys():
                    return ip_data['ip'], subnet

        st.log("Topology - {} {} doesnot have link ip address".format(dut, link_name))
        return '', ''


    @staticmethod
    def dut_get_link_remote_ip_and_subnet(dut, link_name, addr_family):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return '', ''

        subnet = 32 if addr_family == 'ipv4' else 128

        st.log("Topology - Find link remote ip {} {} {}".format(dut, link_name, addr_family))
        if TOPOLOGY.dut_link_present(dut, link_name):
            if link_name in nw_topo[dut][addr_family]['link'].keys():
                ip_data = nw_topo[dut][addr_family]['link'][link_name]
                if 'subnet' in ip_data.keys():
                    subnet = ip_data['subnet']
                if 'rmt_ip' in ip_data.keys():
                    return ip_data['rmt_ip'], subnet

        st.log("Topology - {} {} doesnot have link remote ip address".format(dut, link_name))
        return '', ''


    @staticmethod
    def dut_get_link_local_ip(dut, link_name, addr_family):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return ''

        st.log("Topology - Find local ip {} {} {}".format(dut, link_name, addr_family))
        if TOPOLOGY.dut_link_present(dut, link_name):
            if link_name in nw_topo[dut][addr_family]['link'].keys():
                ip_data = nw_topo[dut][addr_family]['link'][link_name]
                if 'ip' in ip_data.keys():
                    return ip_data['ip']

        st.log("Topology - {} {} doesnot have local ip address".format(dut, link_name))
        return ""


    @staticmethod
    def dut_get_link_remote_ip(dut, link_name, addr_family):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return False

        if TOPOLOGY.dut_link_present(dut, link_name):
            if link_name in nw_topo[dut][addr_family]['link'].keys():
                ip_data = nw_topo[dut][addr_family]['link'][link_name]
                if 'rmt_ip' in ip_data.keys():
                    return ip_data['rmt_ip']

        st.log("Topology - {} {} doesnot have local remote address".format(dut, link_name))
        return ""


    @staticmethod
    def get_dut_loopback_ip(dut, lpbk_num, addr_family):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return ""

        link_name = "{}L{}".format(dut, lpbk_num)

        if not TOPOLOGY.dut_link_present(dut, link_name):
            st.log("Topology - Link {} not in intf list".format(link_name))
            return ''

        if link_name in nw_topo[dut][addr_family]['link'].keys():
            ip_data = nw_topo[dut][addr_family]['link'][link_name]
            if 'ip' not in ip_data.keys():
                st.log("Topology - {} doesnt have ip address".format(link_name))
                return ''

            return ip_data['ip']

        return ''


    @staticmethod
    def get_dut_loopback_ip_list(dut, addr_family, vrf=''):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            return []

        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - Dut {} not present".format(dut))
            return []

        lpbk_ip_list = []
        for _, ip_data in nw_topo[dut][addr_family]['link'].items():
            if ip_data['type'] == 'LBK' :
                if 'ip' in ip_data.keys():
                    lpbk_ip_list.append(ip_data['ip'])

        return copy.deepcopy(lpbk_ip_list)


    @staticmethod
    def get_loopback_ip_in_dut_list(dut_list=[], vrf='', addr_family='ipv4'):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            return []

        lpbk_ip_list = []

        for dut in dut_list:
            if not TOPOLOGY.dut_present(dut):
                continue

            for _, ip_data in nw_topo[dut][addr_family]['link'].items():
                if ip_data['type'] == 'LBK' :
                    if 'ip' in ip_data.keys():
                        if ip_data['ip'] not in lpbk_ip_list:
                            lpbk_ip_list.append(ip_data['ip'])

        return copy.deepcopy(lpbk_ip_list)


    @staticmethod
    def get_dut_vrf_loopback(dut, vrf, addr_family='ipv4'):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            return '', ''

        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - Dut {} not present".format(dut))
            return '', ''

        lpbk_link = ''
        lpbk_ip = ''

        for link_name, link_data in nw_topo[dut]['intf'].items():

            if link_data['type'] != 'LBK' :
               continue

            if 'vrf' not in link_data.keys():
               continue

            lpbk_link = link_name

            if addr_family not in nw_topo[dut].keys():
               continue

            if link_name not in nw_topo[dut][addr_family]['link'].keys():
               continue

            ip_data = nw_topo[dut][addr_family]['link'][link_name]

            if 'ip' not in ip_data.keys():
                continue

            lpbk_ip = ip_data['ip']
            break

        if lpbk_link != '' :
            st.log("Topology - No {} loopback found in dut {} vrf {}".format(
                                                        addr_family, dut, vrf))
        else :
            st.log("Topology - {} loopback {} found in dut {} vrf {} with addr {} ".format(
                                            addr_family, lpbk_link , dut, vrf, lpbk_ip))
        return lpbk_link, lpbk_ip


    @staticmethod
    def dut_get_connected_ip_links(from_dut, to_dut, addr_family):

        ip_link_list = []
        if not TOPOLOGY.addr_family_valid(addr_family):
           return ip_link_list

        link_name_list = TOPOLOGY.dut_get_connected_links(from_dut, to_dut)
        if not link_name_list or len(link_name_list) == 0 :
            return ip_link_list

        ip_link_list = []
        for link_name in link_name_list:
            if link_name in nw_topo[from_dut][addr_family]['link'].keys():
                ip_data = nw_topo[from_dut][addr_family]['link'][link_name]
                if 'rmt_dut' in ip_data.keys():
                    if 'rmt_link' in ip_data.keys():
                        if ip_data['rmt_dut'] == to_dut :
                            ip_link_list.append(link_name)

        return ip_link_list


    @staticmethod
    def get_dut_ip_address_list(dut, addr_family, vrf='default'):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            return []

        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - Dut {} not present".format(dut))
            return []

        ip_addr_list = []
        for _, ip_data in nw_topo[dut][addr_family]['link'].items():
            if 'ip' in ip_data.keys():
                 ip_addr_list.append(ip_data['ip'])

        st.log("Topology - Dut {} has host ip {}".format(dut, ip_addr_list))
        return copy.deepcopy(ip_addr_list)


    @staticmethod
    def get_dut_static_network_prefixes(dut, addr_family):

        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - Dut {} not present".format(dut))
            return []

        if not TOPOLOGY.addr_family_valid(addr_family):
            return []

        snw_list = []
        for prefix, snw_data in nw_topo[dut][addr_family]['static_nw'].items() :
            prefix_subnet = "{}/{}".format(prefix, snw_data['subnet'])
            snw_list.append(prefix_subnet)

        return copy.deepcopy(snw_list)


    @staticmethod
    def get_dut_static_route_prefixes(dut, addr_family):

        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - Dut {} not present".format(dut))
            return []

        if not TOPOLOGY.addr_family_valid(addr_family):
            return []

        srtp_list = []
        for prefix, rt_data in nw_topo[dut][addr_family]['static_rt'].items() :
            prefix_subnet = "{}/{}".format(prefix, rt_data['subnet'])
            srtp_list.append(prefix_subnet)

        return copy.deepcopy(srtp_list)


    @staticmethod
    def get_dut_null_nhop_static_route_prefixes(dut, addr_family):

        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - Dut {} not present".format(dut))
            return []

        if not TOPOLOGY.addr_family_valid(addr_family):
            return []

        srtp_list = []
        for prefix, rt_data in nw_topo[dut][addr_family]['static_rt'].items() :
            if rt_data['nexthop'] == 'Null0' :
                 prefix_subnet = "{}/{}".format(prefix, rt_data['subnet'])
                 srtp_list.append(prefix_subnet)

        return copy.deepcopy(srtp_list)


    @staticmethod
    def get_dut_static_route_prefix_data_list(dut, addr_family):

        if not TOPOLOGY.dut_present(dut):
            st.log("Topology - Dut {} not present".format(dut))
            return {}

        if not TOPOLOGY.addr_family_valid(addr_family):
            return {}

        srtp_data_list = {}
        for prefix, rt_data in nw_topo[dut][addr_family]['static_rt'].items() :
            srtp_data_list.update({prefix: rt_data})

        return copy.deepcopy(srtp_data_list)


    #-------------------------------------------------------------------------
    # Network topo add del functions


    @staticmethod
    def add_del_dut(dut, device_name, device_type='DUT', add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'

        if add == 'yes' :

            if TOPOLOGY.dut_present(dut):
                resstr = "Topology - device {} exists as dut {}".format(device_name, dut)
                st.log("{}".format(resstr))
                return False, resstr

            dut2 = TOPOLOGY.get_dut_from_device(device_name)
            if dut2 != "" and dut != dut2 :
                resstr = "Topology - device {} exists as dut {}".format(device_name, dut2)
                st.log("{}".format(resstr))
                return False, resstr

            st.log("Topology - {} {} {} {}".format(action_str, device_type, dut, device_name))
            if device_type == 'DUT' :
                nw_topo['dut_list'].append(dut)
                nw_topo['dut_list'].sort()
            else :
                nw_topo['tg_list'].append(dut)
                nw_topo['tg_list'].sort()

            nw_topo[dut] = {}
            nw_topo['port_channel_count'] = 0
            nw_topo['vlan_count'] = 1
            nw_topo['test_bed_configured'] = False
            nw_topo[dut]['type'] = device_type
            nw_topo[dut]['device'] = device_name
            nw_topo[dut]['intf'] = {}
            nw_topo[dut]['vrf'] = {}
            nw_topo[dut]['nwoctet'] = 0
            nw_topo[dut]['port_channel_count'] = 0
            nw_topo[dut]['vlan_count'] = 1

            nw_topo[dut]['vrf']['default'] = {'name': 'default'}
            nw_topo[dut]['ipv4'] = {}
            nw_topo[dut]['ipv4']['static_nw'] = {}
            nw_topo[dut]['ipv4']['static_rt'] = {}
            nw_topo[dut]['ipv4']['link'] = {}
            nw_topo[dut]['ipv4']['nwoctet'] = 0

            nw_topo[dut]['ipv6'] = {}
            nw_topo[dut]['ipv6']['static_nw'] = {}
            nw_topo[dut]['ipv6']['static_rt'] = {}
            nw_topo[dut]['ipv6']['link'] = {}
            nw_topo[dut]['ipv6']['nwoctet'] = 0

            return True, 'Success'

        else :

            if not TOPOLOGY.dut_present(dut):
                resstr = "Topology - dut doesnt exists {}".format(dut)
                st.log("{}".format(resstr))
                return False, resstr

            if device_name != '' and device_name != nw_topo[dut]['device']:
                resstr = "Topology - device {} isnot dut {}".format(device_name, dut)
                st.log("{}".format(resstr))
                return False, resstr

            device_name = nw_topo[dut]['device']

            if len(nw_topo[dut]['intf']) != 0 :
                resstr = "Topology - device {} {} interface exists".format(device_name, dut)
                st.log("{}".format(resstr))
                return False, resstr

            st.log("Topology - Deleting device {} {} ".format(device_name, dut))
            del nw_topo[dut]
            if device_type == 'DUT' :
                del nw_topo['dut_list'][dut]
                nw_topo['dut_list'].sort()
            else :
                del nw_topo['tg_list'][dut]
                nw_topo['tg_list'].sort()

            return True, 'Success'

        #st.log("Topology - Dut {} FAILED".format(action_str))
        #return False, 'Unknown error'


    @staticmethod
    def add_del_dut_vrf(dut, vrf_name, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'

        if not TOPOLOGY.dut_present(dut):
            resstr = "Topology - Dut {} doesnt exist".format(dut)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :
           if vrf_name not in nw_topo[dut]['vrf'].keys():
               nw_topo[dut]['vrf'][vrf_name] = { "name": vrf_name }
        else :
           if vrf_name in nw_topo[dut]['vrf'].keys():
               del nw_topo[dut]['vrf'][vrf_name]

        st.log("Topology - Dut {} vrf {} {} Success".format(dut, vrf_name, action_str))
        return True, 'Success'


    @staticmethod
    def add_del_link(dut, link_type, link_name, intf_name, if_id='', vrf='default', add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - Link {} for {} {}".format(action_str, dut, link_name))

        if not TOPOLOGY.dut_present(dut):
            resstr = "Topology - Dut {} doesnt exist".format(dut)
            st.log("{}".format(resstr))
            return False, resstr

        if not TOPOLOGY.valid_link_type(link_type):
            resstr = "Topology - Invalid intface type {}".format(link_type)
            st.log("{}".format(resstr))
            return False, resstr

        if dut == "" or link_name=="" or intf_name == "" :
            resstr = "Topology - Invalid dut {} or link {} or intf {}".format(dut, link_name, intf_name)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :
            if TOPOLOGY.dut_link_present(dut, link_name):
                resstr = "Topology - dut {} link {} already present".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            if_data = { 'if': intf_name, 'type': link_type , 'vrf':vrf, 'rmt_duts': {},
                         'sub_ifs' : [], 'members': [] }

            if link_type == 'VLN' and if_id != '' :
                vlan_id_name = "Vlan{}".format(if_id)
                if vlan_id_name != intf_name :
                    resstr = "Topology - Vlan Id {} doesnot match with interface name {}".format(if_id, intf_name)
                    st.log("{}".format(resstr))
                    return False, resstr

                if_data['if_id'] = if_id

            nw_topo[dut]['intf'].update({link_name : if_data })

            return True, 'Success'

        else:
            if not TOPOLOGY.dut_link_present(dut, link_name):
                resstr = "Topology - dut {} doesnt have intf {}".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            if TOPOLOGY.dut_link_connected(dut, link_name):
                resstr = "Topology - dut {} link {} connected".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            if TOPOLOGY.dut_link_has_ip(dut, link_name, 'ipv4'):
                resstr = "Topology - dut {} link {} has ipv4 addr".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            if TOPOLOGY.dut_link_has_ip(dut, link_name, 'ipv6'):
                resstr = "Topology - dut {} link {} has ipv6 addr".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            if TOPOLOGY.dut_link_has_link_member(dut, link_name):
                resstr = "Topology - dut {} link {} has link members".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            if TOPOLOGY.dut_link_has_sub_ifs(dut, link_name):
                resstr = "Topology - dut {} link {} has sub interfaces".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            st.log("Topology - dut {} deleting link {}".format(dut, link_name))
            del nw_topo[dut]['intf'][link_name]
            return True, 'Success'

        #st.log("Topology - Link {} FAILED".format(action_str))
        #return False, 'Unknown Fail'


    @staticmethod
    def add_del_link_vrf(dut, link_name, vrf='default', add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - {} {} Link {} vrf {} ".format(action_str, dut, link_name, vrf))

        if not TOPOLOGY.dut_link_present(dut, link_name):
            resstr = "Topology - dut {} link {} not present".format(dut, link_name)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :
            nw_topo[dut]['intf'][link_name]['vrf'] = vrf
        else:
            nw_topo[dut]['intf'][link_name]['vrf'] = 'default'

        st.log("Topology - Link {}".format(nw_topo[dut]['intf'][link_name]))
        st.log("Topology - Link vrf bind-{} Success".format(action_str))
        return True, 'Success'


    @staticmethod
    def add_del_link_member(dut, link_name, link_member, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - {} {} Link member {} to {}".format(action_str, dut, link_member, link_name))

        if not TOPOLOGY.dut_present(dut):
            resstr = " Topology - Dut {} doesnt exist".format(dut)
            st.log("{}".format(resstr))
            return False, resstr

        if not TOPOLOGY.dut_link_present(dut, link_name):
            resstr = "Topology - dut {} link {} not present".format(dut, link_name)
            st.log("{}".format(resstr))
            return False, resstr

        if not TOPOLOGY.dut_link_present(dut, link_member):
            resstr = "Topology - dut {} member link {} not present".format(dut, link_member)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :
            if link_member in nw_topo[dut]['intf'][link_name]['members'] :
                resstr = "Topology - dut {} link {} already member of {}".format(dut, link_member, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            nw_topo[dut]['intf'][link_name]['members'].append(link_member)

            if link_name not in nw_topo[dut]['intf'][link_member]['sub_ifs'] :
                nw_topo[dut]['intf'][link_member]['sub_ifs'].append(link_name)

            st.log("Topology - updated Link {}".format(nw_topo[dut]['intf'][link_name]))
            st.log("Topology - updated Memeber {}".format(nw_topo[dut]['intf'][link_member]))

            return True, 'Success'

        else:
            if link_member not in nw_topo[dut]['intf'][link_name]['members'] :
                resstr = "Topology - dut {} link {} not member of {}".format(dut, link_member, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            nw_topo[dut]['intf'][link_name]['members'].remove(link_member)

            if link_name in nw_topo[dut]['intf'][link_member]['sub_ifs'] :
                nw_topo[dut]['intf'][link_member]['sub_ifs'].remove(link_name)

            return True, 'Success'

        #st.log("Topology - Link member {} FAILED".format(action_str))
        #return False, 'Unknown error'


    @staticmethod
    def connect_links(from_dut, from_link, to_dut, to_link, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - Link connect {} for {} {}".format(action_str, from_link, to_link))

        if not TOPOLOGY.dut_link_present(from_dut, from_link):
            resstr = " Topology - dut {} link {} not present".format(from_dut, from_link)
            st.log("{}".format(resstr))
            return False, resstr

        if not TOPOLOGY.dut_link_present(to_dut, to_link):
            resstr = "Topology - dut {} link {} not present".format(to_dut, to_link)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :

            if TOPOLOGY.dut_link_connected(from_dut, from_link):
                resstr = "Topology - dut {} link {} already connected".format(from_dut, from_link)
                st.log("{}".format(resstr))
                return False, resstr

            if TOPOLOGY.dut_link_connected(to_dut, to_link):
                resstr = "Topology - dut {} link {} already connected".format(to_dut, to_link)
                st.log("{}".format(resstr))
                return False, resstr

            nw_topo[from_dut]['intf'][from_link].update({'rmt_dut': to_dut})
            nw_topo[from_dut]['intf'][from_link].update({'rmt_link': to_link})

            nw_topo[to_dut]['intf'][to_link].update({'rmt_dut': from_dut})
            nw_topo[to_dut]['intf'][to_link].update({'rmt_link': from_link})

            if TOPOLOGY.dut_link_connected(from_dut, from_link):
                resstr = "Topology - {} {} {} {} connected".format(from_dut, from_link, to_dut, to_link)
                st.log("{}".format(resstr))
                return True, 'Success'

        else:

            if not TOPOLOGY.dut_link_connected_to_each_other(from_dut, from_link, to_dut, to_link):
                resstr = "Topology - {} {} {} {} not connected".format(from_dut, from_link, to_dut, to_link)
                st.log("{}".format(resstr))
                return False, resstr

            del nw_topo[from_dut]['intf'][from_link]['rmt_dut']
            del nw_topo[from_dut]['intf'][from_link]['rmt_link']
            del nw_topo[to_dut]['intf'][to_link]['rmt_dut']
            del nw_topo[to_dut]['intf'][to_link]['rmt_link']

            st.log("Topology - {} {} {} {} disconnected".format(from_dut, from_link, to_dut, to_link))
            return True, 'Success'

        return False, 'Link connect Failed'


    @staticmethod
    def add_del_portchannel(dut, rmt_dut, portchannel_num='', member_links=[], add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - {} portchannel {} {}".format(action_str, dut, portchannel_num))
        st.log("           portchannel  members {} ".format(member_links))

        if not TOPOLOGY.dut_present(dut) :
            resstr = "Topology - dut {} not present".format(dut)
            st.log("{}".format(resstr))
            return False, resstr, []

        if not TOPOLOGY.dut_present(rmt_dut) :
            resstr = "Topology - remote dut {} not present".format(rmt_dut)
            st.log("{}".format(resstr))
            return False, resstr, []

        overlay_links = []

        if add == 'yes' :
            for member_link in member_links :
                if not TOPOLOGY.dut_link_present(dut, member_link):
                    resstr = "Topology - {} member link {} not present".format(dut, member_link)
                    st.log("{}".format(resstr))
                    return False, resstr, overlay_links

            if portchannel_num == '' :
                pc_id = 1
                while pc_id < 4094 :
                   link_name =  "{}C{}".format(dut, pc_id)

                   if TOPOLOGY.dut_link_present(dut, link_name):
                       pc_id += 1
                       continue

                   portchannel_num = pc_id
                   break

                if portchannel_num == '' :
                    resstr = "Topology - Cannot create requested portchannel"
                    st.log("{}".format(resstr))
                    return False, resstr

            link_name =  "{}C{}".format(dut, portchannel_num)
            if_name = "PortChannel{}".format(portchannel_num)

            st.log("Topology - Modified Portchannel {} {}".format(link_name, if_name))

            if not TOPOLOGY.dut_link_present(dut, link_name):
                result, resstr = TOPOLOGY.add_del_link(dut, "PCH", link_name, if_name, if_id=portchannel_num, add='yes')
                if not result :
                    resstr += "Topology - {} add portchannel {} {} Failed".format(dut, link_name, if_name)
                    st.log("{}".format(resstr))
                    return False, resstr, overlay_links

            overlay_links.append(link_name)

            for member_link in member_links :
                result, resstr = TOPOLOGY.add_del_link_member(dut, link_name, member_link, add='yes')
                if not result :
                    resstr += "Topology - {} add portchannel {} link memeber {} Failed".format(
                                                          dut, link_name, member_link)
                    st.log("{}".format(resstr))
                    return False, resstr, overlay_links

            st.log("Topology - {} add portchannel {} Success".format(dut, link_name))
            return True, 'Success', overlay_links

        else :  #if add == 'no' :

            if portchannel_num == '' :
                resstr = "Topology - portchannel number {} not present".format(portchannel_num)
                st.log("{}".format(resstr))
                return False, resstr

            link_name =  "{}C{}".format(dut, portchannel_num)
            if_name = "PortChannel{}".format(portchannel_num)

            if not TOPOLOGY.dut_link_present(dut, link_name):
                resstr = "Topology - {} vlan {} not present".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr, overlay_links

            pc_member_links = TOPOLOGY.dut_get_link_members(dut, link_name)
            for member_link in pc_member_links :
                result, resstr = TOPOLOGY.add_del_link_member(dut, link_name, member_link, add='no')
                if not result :
                    resstr += " - {} add vlan {} link member {} Failed".format(dut, link_name, member_link)
                    st.log("{}".format(resstr))
                    return False, resstr, overlay_links

            result, resstr = TOPOLOGY.add_del_link(dut, "PCH", link_name, if_name, if_id=portchannel_num, add='no')
            if not result :
                resstr += "Topology - {} add vlan {} {} Failed".format(dut, link_name, if_name)
                st.log("{}".format(resstr))
                return False, resstr, overlay_links

            st.log("Topology - {} del portchannel {} Success".format(dut, link_name))
            return True, 'Success', overlay_links


    @staticmethod
    def get_free_vlans_in_dut_list(dut_list, max_vlan_count=1):

        st.log("Topology - get_free_vlans {} {}".format(dut_list, max_vlan_count))
        vlan_list = []
        vlan_count = 0
        vlan_id = 1

        while vlan_id < 4094 and vlan_count < max_vlan_count:
            vlan_id += 1
            vlan_found = True
            for dut in dut_list :
                link_name =  "{}V{}".format(dut, vlan_id)
                if TOPOLOGY.dut_link_present(dut, link_name):
                    vlan_found = False
                    break

            if vlan_found :
                st.log("Topology - vlan index {} found free".format(vlan_id))
                vlan_list.append(vlan_id)
                vlan_count += 1

        if vlan_count < max_vlan_count :
             resstr = "Topology - get {} free vlan list in duts {} Failed".format(max_vlan_count, dut_list)
             st.log("{}".format(resstr))
             return False, resstr, []

        st.log("Topology - dutlist {} vlan list {}".format(dut_list, vlan_list))
        st.log("Topology - get {} free vlan list Success".format(max_vlan_count))
        return True, 'Success', vlan_list


    @staticmethod
    def get_free_portchannel_in_dut_list(dut_list, max_pch_count=1):

        st.log("Topology - get_free_portchannel {} {}".format(dut_list, max_pch_count))
        pch_list = []
        pch_count = 0
        pch_id = 0

        while pch_id < 4094 and pch_count < max_pch_count:
            pch_found = True
            pch_id += 1

            for dut in dut_list :
                link_name =  "{}C{}".format(dut, pch_id)
                if TOPOLOGY.dut_link_present(dut, link_name):
                    pch_found = False
                    break

            if pch_found :
                st.log("Topology - portchannel index {} found free".format(pch_id))
                pch_list.append(pch_id)
                pch_count += 1

        if pch_count < max_pch_count :
             resstr = "Topology - get {} free pch list in duts {} Failed".format(max_pch_count, dut_list)
             st.log("{}".format(resstr))
             return False, resstr, []

        st.log("Topology - dutlist {} pch list {}".format(dut_list, pch_list))
        st.log("Topology - get {} free portchannel list Success".format(max_pch_count))
        return True, 'Success', pch_list



    @staticmethod
    def add_del_vlans(dut, vlan_list=[], vlan_count=0, member_links=[], add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - {} vlan {} {}".format(action_str, dut, vlan_list))
        st.log("           vlan count {} members {} ".format(vlan_count, member_links))

        if not TOPOLOGY.dut_present(dut) :
            resstr = "Topology - dut {} not present".format(dut)
            st.log("{}".format(resstr))
            return False, resstr, []

        overlay_links = []

        if add == 'yes' :

            for member_link in member_links :
                if not TOPOLOGY.dut_link_present(dut, member_link):
                    resstr = "Topology - {} member link {} not present".format(dut, member_link)
                    st.log("{}".format(resstr))
                    return False, resstr, []

            if len(vlan_list) == 0 :

                if vlan_count == 0 :
                    resstr = "Topology - Both vlan list and count are zero - vlan create Failed"
                    st.log("{}".format(resstr))
                    return False, resstr, []

                vlan_id = 2
                while vlan_id < 4094 and len(vlan_list) < vlan_count:
                   link_name =  "{}V{}".format(dut, vlan_id)

                   if TOPOLOGY.dut_link_present(dut, link_name):
                       vlan_id += 1
                       continue

                   vlan_list.append(vlan_id)
                   vlan_id += 1

                if len(vlan_list) != vlan_count :
                    resstr = "Topology - Cannot create requested number {} of vlans".format(vlan_count)
                    st.log("{}".format(resstr))
                    return False, resstr, []


            #vlan_count = len(vlan_list)
            st.log("Topology - Modified Vlan List {}".format(vlan_list))

            for vlan_id in vlan_list :
                link_name =  "{}V{}".format(dut, vlan_id)
                if_name = "Vlan{}".format(vlan_id)

                if not TOPOLOGY.dut_link_present(dut, link_name):
                    result, resstr = TOPOLOGY.add_del_link(dut, "VLN", link_name, if_name, if_id=vlan_id, add='yes')
                    if not result :
                        resstr += "Topology - {} add vlan {} {} Failed".format(dut, link_name, if_name)
                        st.log("{}".format(resstr))
                        return False, resstr, overlay_links

                overlay_links.append(link_name)

                for member_link in member_links :
                    result, resstr = TOPOLOGY.add_del_link_member(dut, link_name, member_link, add='yes')
                    if not result :
                        resstr += "Topology - {} add vlan {} link member {} Failed".format(dut, link_name, member_link)
                        st.log("{}".format(resstr))
                        return False, resstr, overlay_links

            st.log("Topology - {} add vlans {} Success".format(dut, overlay_links))
            return True, 'Success', overlay_links

        else :  #if add == 'no' :

            for vlan_id in vlan_list :
                link_name =  "{}V{}".format(dut, vlan_id)
                if_name = "Vlan{}".format(vlan_id)

                if not TOPOLOGY.dut_link_present(dut, link_name):
                    st.log("Topology - {} vlan {} not present".format(dut, link_name))
                    continue

                vlan_member_links = TOPOLOGY.dut_get_link_members(dut, link_name)
                for member_link in vlan_member_links :
                    result, resstr = TOPOLOGY.add_del_link_member(dut, link_name, member_link, add='no')
                    if not result :
                        resstr += "Topology - {} add vlan {} link member {} Failed".format(dut, link_name, member_link)
                        st.log("{}".format(resstr))
                        return False, resstr, overlay_links

                result, resstr = TOPOLOGY.add_del_link(dut, "VLN", link_name, if_name, if_id=vlan_id, add='no')
                if not result :
                    resstr += "Topology - {} add vlan {} {} Failed".format(dut, link_name, if_name)
                    st.log("{}".format(resstr))
                    return False, resstr, overlay_links

                overlay_links.append(link_name)

            st.log("Topology - {} del vlans {} Success".format(dut, overlay_links))
            return True, 'Success'


    @staticmethod
    def add_del_link_ip(dut, link_name, ip_addr, subnet, rmt_ip, addr_family, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - Link ip {} for {} {} {}".format(action_str, dut, link_name, ip_addr))

        if add == 'yes' :

            if TOPOLOGY.dut_ip_link_present(dut, link_name, addr_family) :
                resstr = "Topology - {} {} already has {} address".format(dut, link_name, addr_family)
                st.log("{}".format(resstr))
                return False, resstr

            if TOPOLOGY.dut_link_has_sub_ifs(dut, link_name) :
                resstr = "Topology - {} {} sub interfaces - cannot assign ip address".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            if_data = nw_topo[dut]['intf'][link_name]
            ip_data = { "ip": ip_addr, "subnet": subnet, "if": if_data['if'], 'type': if_data['type']}

            if 'rmt_dut' in if_data.keys():
                ip_data.update({'rmt_dut': if_data['rmt_dut']})
                ip_data.update({'rmt_link': if_data['rmt_link']})

                if rmt_ip and rmt_ip != "":
                    ip_data.update({'rmt_ip': rmt_ip})

            nw_topo[dut][addr_family]['link'].update({link_name: ip_data})

            #st.log("Topology - Added IP link {} {}".format(link_name, ip_data))
            return True, 'Success'

        else:

            if not TOPOLOGY.dut_ip_link_present(dut, link_name, addr_family) :
                st.log("Topology - {} {} does not exist".format(dut, link_name))
                return True, 'Success'

            #if_data = nw_topo[dut]['intf'][link_name]
            #ip_data =  nw_topo[dut][addr_family]['link'][link_name]

            del nw_topo[dut][addr_family]['link'][link_name]

            #st.log("Topology - Deleted IP link {} {}".format(link_name, ip_data))
            return True, 'Success'

        #st.log("Topology - Link ip {} FAILED".format(action_str))
        #return False, 'Unknown error'


    @staticmethod
    def connect_ip_links(lcl_dut, lcl_link, rmt_dut, rmt_link, addr_family='ipv4', add='yes'):

        st.log("Topology - connect {} links {} {} -- {} {}".format(
                            addr_family, lcl_dut, lcl_link, rmt_dut, rmt_link))

        if not TOPOLOGY.dut_link_present(lcl_dut, lcl_link):
            st.log("Topology - link {} {} not present".format(lcl_dut, lcl_link))
            return False

        if not TOPOLOGY.dut_link_present(lcl_dut, lcl_link):
            st.log("Topology - link {} {} not present".format(rmt_dut, rmt_link))
            return False

        if 'rmt_dut' not in nw_topo[lcl_dut]['intf'][lcl_link].keys() :
            st.log("Topology - link {} {} remote dut not set".format(lcl_dut, lcl_link))
            return False

        if 'rmt_link' not in nw_topo[lcl_dut]['intf'][lcl_link].keys() :
            st.log("Topology - link {} {} remote link not set".format(lcl_dut, lcl_link))
            return False

        if 'rmt_dut' not in nw_topo[rmt_dut]['intf'][rmt_link].keys() :
            st.log("Topology - link {} {} remote dut not set".format(rmt_dut, rmt_link))
            return False

        if 'rmt_link' not in nw_topo[rmt_dut]['intf'][rmt_link].keys() :
            st.log("Topology - link {} {} remote link not set".format(rmt_dut, rmt_link))
            return False

        if lcl_link not in nw_topo[lcl_dut][addr_family]['link'].keys():
            st.log("Topology - link {} {} does not have ip set".format(lcl_dut, lcl_link))
            return False

        if rmt_link not in nw_topo[rmt_dut][addr_family]['link'].keys():
            st.log("Topology - link {} {} does not have ip set".format(rmt_dut, rmt_link))
            return False

        temp_rmt_dut = nw_topo[lcl_dut]['intf'][lcl_link]['rmt_dut']
        if temp_rmt_dut != rmt_dut :
            st.log("Topology - rmt dut {} {} remote dut not same".format(temp_rmt_dut, rmt_dut))
            return False

        temp_rmt_link = nw_topo[lcl_dut]['intf'][lcl_link]['rmt_link']
        if temp_rmt_link != rmt_link :
            st.log("Topology - rmt dut {} {} remote dut not same".format(temp_rmt_link, rmt_link))
            return False

        temp_rmt_dut = nw_topo[rmt_dut]['intf'][rmt_link]['rmt_dut']
        if temp_rmt_dut != lcl_dut :
            st.log("Topology - rmt dut {} {} remote dut not same".format(temp_rmt_dut, lcl_dut))
            return False

        temp_rmt_link = nw_topo[rmt_dut]['intf'][rmt_link]['rmt_link']
        if temp_rmt_link != lcl_link :
            st.log("Topology - rmt dut {} {} remote dut not same".format(temp_rmt_link, lcl_link))
            return False

        lcl_ip = nw_topo[lcl_dut][addr_family]['link'][lcl_link]['ip']
        rmt_ip = nw_topo[rmt_dut][addr_family]['link'][rmt_link]['ip']

        nw_topo[lcl_dut][addr_family]['link'][lcl_link].update({'rmt_link': rmt_link})
        nw_topo[lcl_dut][addr_family]['link'][lcl_link].update({'rmt_dut': rmt_dut})
        nw_topo[lcl_dut][addr_family]['link'][lcl_link].update({'rmt_ip': rmt_ip})

        nw_topo[rmt_dut][addr_family]['link'][rmt_link].update({'rmt_link': lcl_link})
        nw_topo[rmt_dut][addr_family]['link'][rmt_link].update({'rmt_dut': lcl_dut})
        nw_topo[rmt_dut][addr_family]['link'][rmt_link].update({'rmt_ip': lcl_ip})

        st.log("Topology - connect ip links {} {} {} -- {} {} {} connected".format(
                              lcl_dut, lcl_link, lcl_ip, rmt_ip, rmt_link, rmt_dut))
        return True


    @staticmethod
    def connect_all_ip_links():

        st.log("Topology - IP link connect all")

        nbr_visited = {}
        for dut in nw_topo['dut_list']:
            nbr_visited[dut] = False

        addr_family_list = TOPOLOGY.get_address_family_list("all")

        dut_list = TOPOLOGY.get_dut_list()
        dut_list += TOPOLOGY.get_tg_list()

        for lcl_dut in dut_list:
            st.log("Topology - dut {} ".format(lcl_dut))
            for lcl_link, link_data in nw_topo[lcl_dut]['intf'].items():
                st.log("Topology - link {}  data {}".format(lcl_link, link_data))
                if 'rmt_dut' in link_data.keys():
                    rmt_dut = link_data['rmt_dut']
                    rmt_link = link_data['rmt_link']

                    for afmly in addr_family_list:
                        TOPOLOGY.connect_ip_links(lcl_dut, lcl_link, rmt_dut, rmt_link, addr_family=afmly, add='yes')

        #TOPOLOGY.show_dut_topo_data()
        return True, 'Success'


    @staticmethod
    def add_del_dut_static_network_prefix(dut, prefix, subnet, addr_family, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - Static nw {} for {} {}".format(action_str, dut, prefix))

        if not TOPOLOGY.dut_present(dut):
            resstr = "Topology - Dut {} not present".format(dut)
            st.log("{}".format(resstr))
            return False, resstr

        if not TOPOLOGY.addr_family_valid(addr_family):
            resstr = "Topology - invalid address family {}".format(addr_family)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :
            snw_data = {'subnet': subnet}
            nw_topo[dut][addr_family]['static_nw'].update({prefix: snw_data})
        else :
            if prefix in nw_topo[dut][addr_family]['static_nw']:
                del nw_topo[dut][addr_family]['static_nw'][prefix]

        return True, 'Success'


    @staticmethod
    def add_del_dut_static_route_prefix(dut, prefix, subnet, next_hop, addr_family, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - {} Static route {} pfx {} nhop {}.".format(action_str, dut, prefix, next_hop))

        if not TOPOLOGY.dut_present(dut):
            resstr = "Topology - Dut {} not present".format(dut)
            st.log("{}".format(resstr))
            return False, resstr

        if not TOPOLOGY.addr_family_valid(addr_family):
            resstr = "Topology - invalid address family {}".format(addr_family)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :
            strt_data = {'nexthop' : next_hop , 'subnet': subnet}
            nw_topo[dut][addr_family]['static_rt'].update({prefix: strt_data})
        else :
            if prefix in nw_topo[dut][addr_family]['static_rt'].keys():
                del nw_topo[dut][addr_family]['static_rt'][prefix]

        return True, 'Success'


    @staticmethod
    def add_del_dut_network_num(dut, nw_num, addr_family, add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - Nw num {} for {} {}".format(action_str, dut, nw_num))

        if not TOPOLOGY.dut_present(dut):
            resstr = "Topology - Dut {} not present".format(dut)
            st.log("{}".format(resstr))
            return False, resstr

        if not TOPOLOGY.addr_family_valid(addr_family):
            resstr = "Topology - invalid address family {}".format(addr_family)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :
            nw_topo[dut][addr_family]['nwoctet'] = nw_num
        else :
            nw_topo[dut][addr_family]['nwoctet'] = 0

        return True, 'Success'


    @staticmethod
    def add_del_link_address_octate(link_name, addr_oct_list=[], add='yes'):

        action_str = "Add" if add == 'yes' else 'Delete'
        st.log("Topology - Addr octate {} for {} {}".format(action_str, link_name, addr_oct_list))

        if add == 'yes' :
           nw_topo['network'].update({link_name: addr_oct_list})
        else :
           if link_name in nw_topo['network'].keys():
               del nw_topo['network'][link_name]

        return True


    @staticmethod
    def find_tb_connected_link(lcl_dut, lcl_if, rmt_tb, rmt_if):

        connected_link = { 'connected': False,
                           'lcl_dut' : lcl_dut,
                           'lcl_tb'  : '',
                           'lcl_link': '',
                           'lcl_if'  : lcl_if,
                           'rmt_dut' : '',
                           'rmt_tb'  : rmt_tb,
                           'rmt_link': '',
                           'rmt_if'  : rmt_if }

        connected_link['lcl_tb'] = TOPOLOGY.get_dut_device(lcl_dut)
        if connected_link['lcl_tb'] == '' :
            st.log("Topology - No lcl_tb, Link NOT connected {}".format(connected_link))
            return connected_link

        connected_link['rmt_dut'] = TOPOLOGY.get_dut_from_device(rmt_tb)
        if connected_link['rmt_dut'] == '' :
            st.log("Topology - No rmt dut, Link NOT connected {}".format(connected_link))
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
            st.log("Topology - Link connected {}".format(connected_link))
            return copy.deepcopy(connected_link)

        st.log("Topology - Link NOT connected {}".format(connected_link))
        return {'connected': False }


    @staticmethod
    def setup_base_testbed_topology():
        TOPOLOGY.banner_log("Topology - BUILD BASE TESTBED TOPOLOGY  - START")

        if len(nw_topo) > 1 : #
            resstr = "TOPOLOGY - ERROR Topology Db already Present ERROR"
            st.log("{}".format(resstr))
            TOPOLOGY.show_dut_topo_data()
            st.log("{}".format(resstr))
            return False, resstr

        tb_vars = st.get_testbed_vars()
        tb_var_keys = tb_vars.keys()
        st.log("TestBed Vars => {}\n".format(tb_vars))

        nw_topo['inited'] = True

        nw_topo['dut_list'] = []
        nw_topo['tg_list'] = []
        nw_topo['dut_map'] = {}
        nw_topo['tg_map']  = {}
        nw_topo['network'] = {}
        nw_topo['subtopo'] = {}
        nw_topo['subtopo']['linear'] = { 'found': False }
        nw_topo['subtopo']['ring'] = { 'found': False }
        nw_topo['subtopo']['star'] = {'found': False}
        nw_topo['subtopo']['spine_leaf'] = {'found': False}
        nw_topo['subtopo']['fullmesh'] = {'found': False}
        nw_topo['subtopo']['current'] = {'found': False}

        tb_dut_count = len(tb_vars.dut_list)
        for dut_idx in range(1, tb_dut_count+1) :
            dut = "D{}".format(dut_idx)
            if dut in tb_var_keys :
                nw_topo['dut_map'][dut] = tb_vars[dut]

        tb_tg_count = len(tb_vars.tgen_list)
        for tg_idx in range(1, tb_tg_count+1) :
            tgen = "T{}".format(tg_idx)
            if tgen in tb_var_keys :
                nw_topo['tg_map'][tgen] = tb_vars[tgen]

        st.log("Topology - Testbed Dut List {}".format(nw_topo['dut_map']))
        st.log("Topology - Testbed Tgen List {}".format(nw_topo['tg_map']))

        dut_idx = 0
        for dut, tb_dut_name in nw_topo['dut_map'].items():

            dut_idx += 1

            result, resstr = TOPOLOGY.add_del_dut(dut, tb_dut_name, add='yes')
            if not result:
                resstr += "Topology - Dut {} add {} FAILED".format(dut, tb_dut_name)
                st.log("{}".format(resstr))
                return False, resstr

        for dut, tb_dut_name in nw_topo['tg_map'].items():
            dut_idx += 1

            result, resstr = TOPOLOGY.add_del_dut(dut, tb_dut_name, device_type='TG', add='yes')
            if not result:
               st.log("Topology - TG Dut {} add {} FAILED".format(dut, tb_dut_name))

        nw_topo['dut_list'].sort()
        nw_topo['tg_list'].sort()

        for _, from_dut in enumerate(nw_topo['dut_list'], start = 1):

            lcl_dut = from_dut
            lcl_tb = TOPOLOGY.get_dut_device(lcl_dut)

            dut_links = st.get_dut_links(lcl_tb)
            tg_links = st.get_tg_links(lcl_tb)

            dut_all_links = dut_links + tg_links
            st.log("Topology - Dut {} links {}".format(lcl_dut, dut_all_links))

            for _, link in enumerate(dut_all_links , start = 1):

                link_data = TOPOLOGY.find_tb_connected_link(lcl_dut, link[0], link[1], link[2])
                if not link_data['connected'] :
                        continue

                rmt_dut = link_data['rmt_dut']
                #rmt_tb = link_data['rmt_tb']

                lcl_if = link_data['lcl_if']
                rmt_if = link_data['rmt_if']

                lcl_link = link_data['lcl_link']
                rmt_link = link_data['rmt_link']

                TOPOLOGY.add_del_link(lcl_dut, 'ETH', lcl_link, lcl_if, add='yes')

                if TOPOLOGY.dut_is_tg(rmt_dut) :
                    TOPOLOGY.add_del_link(rmt_dut, 'ETH', rmt_link, rmt_if, add='yes')

                if TOPOLOGY.dut_link_present(rmt_dut, rmt_link):
                    TOPOLOGY.connect_links(lcl_dut, lcl_link, rmt_dut, rmt_link)

        st.log("Topology - Newly rebuild Topology data")
        TOPOLOGY.show_dut_topo_data()

        TOPOLOGY.banner_log("Topology - BUILD BASE TESTBED TOPOLOGY  - END")
        return True, 'Success'

    @staticmethod
    def clear_testbed_topology(per_node_nw='no', nw_ip_octet='10'):
        #This will delete all existing populated Testbed data
        st.log("Topology - Rebuild all testbed data")
        for nw_topo_key in nw_topo.keys():
            st.log("Topology - Delete nw_topo key {}".format(nw_topo_key))
            del nw_topo[nw_topo_key]
        nw_topo['inited'] = False


    @staticmethod
    def reset_testbed_topology(per_node_nw='no', nw_ip_octet='10'):
        #This will delete existing and repopulate base Testbed data
        st.log("Topology - Rebuild all testbed data")
        for nw_topo_key in nw_topo.keys():
            st.log("Topology - Delete nw_topo key {}".format(nw_topo_key))
            del nw_topo[nw_topo_key]
        nw_topo['inited'] = False
        result, resstr = TOPOLOGY.setup_base_testbed_topology()
        return result, resstr


    #-------------------------------------------------------------------------
    # Topology find functions

    @staticmethod
    def find_linear_topo_in_dut_list(dut_list=[], start_dut='', node_limit=0, save_path='yes'):

        st.log("Topology - Find Linear Topo in Dut list {} length {}".format(dut_list, node_limit))
        nw_topo_dut_list = TOPOLOGY.get_dut_list()

        found_path = {}
        found_path['found'] = False

        if not dut_list or len(dut_list) == 0 :
            dut_list = nw_topo_dut_list
        else :
            for dut in dut_list :
                if dut not in nw_topo_dut_list :
                    st.log("Dut {} not in Topo dut lidt {}".format(dut, nw_topo_dut_list))
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

            if TOPOLOGY.dut_is_tg(dut) :
               continue

            st.log(" Starting dut {} ".format(dut))

            nw_topo_stack = []
            nw_topo_path = []
            nw_topo_stack.append(dut)

            while nw_topo_stack and len(nw_topo_stack) :

                st.log("   sp stack {}".format(nw_topo_stack))
                st.log("   sp path {}".format(nw_topo_path))

                curr_dut = nw_topo_stack.pop()
                nw_topo_path.append(curr_dut)

                leaf_dut = True
                for link_name, link_data in nw_topo[curr_dut]['intf'].items():

                    if link_data['type'] in [ 'LBK', 'PCH', 'VLN'] :
                        continue

                    if 'rmt_dut' in link_data.keys():
                        next_dut = link_data['rmt_dut']

                        if TOPOLOGY.dut_is_tg(next_dut):
                            continue

                        if next_dut in nw_topo_path :
                            continue

                        if next_dut not in dut_list :
                            continue

                        if next_dut not in nw_topo_stack :
                            nw_topo_stack.append(next_dut)

                        leaf_dut = False

                if len(nw_topo_path) == length_limit :
                    leaf_dut = True

                if leaf_dut is True :
                    st.log("      Linear found Dut {} ".format(curr_dut))
                    st.log("      Linear found sp path {} ".format(nw_topo_path))
                    st.log("      Linear found longest path {} ".format(longest_path))

                    if len(longest_path) < len(nw_topo_path) :
                        if node_limit > 0 :
                            if len(nw_topo_path) <= length_limit :
                                longest_path = copy.deepcopy(nw_topo_path)
                                st.log("          New longest path set as curr new linear path")
                        else :
                            longest_path = copy.deepcopy(nw_topo_path)
                            st.log("          New longest path set as curr new linear path")

                    if len(longest_path) >= length_limit :
                        st.log("         Path length limit provided {} and reached".format(length_limit))
                        break

                    nw_topo_path.pop()


                if  len(longest_path) == length_limit :
                    break

        st.log("Topology - Longest path len {} with path {}".format(len(longest_path), longest_path))

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
                for link_name, link_data in nw_topo[from_dut]['intf'].items():

                    if link_data['type'] in [ 'LBK', 'PCH', 'VLN'] :
                        continue

                    if 'rmt_dut' in link_data.keys():
                        if link_data['rmt_dut'] == to_dut :

                            rmt_link = link_data['rmt_link']
                            lcl_if = TOPOLOGY.get_link_dut_interface(from_dut, link_name)
                            rmt_if = TOPOLOGY.get_link_dut_interface(to_dut, rmt_link)

                            segt_link = { 'lcl_dut' : from_dut, 'lcl_link': link_name, 'lcl_if': lcl_if,
                                          'rmt_dut' : to_dut,   'rmt_link': rmt_link, 'rmt_if': rmt_if }

                            lcl_if = TOPOLOGY.get_link_dut_interface(from_dut, link_name)
                            rmt_if = TOPOLOGY.get_link_dut_interface(to_dut, rmt_link)

                            if segt_link_idx == 0 : found_path['segment'][dut_idx - 1] = {}
                            found_path['segment'][dut_idx - 1].update({ segt_link_idx: segt_link})

                            if segt_link_idx == 0:
                                found_path['segment_count'] += 1
                            segt_link_idx += 1
                            #st.log("   Path node {} is {}".format(dut_idx - 1, segt_link))
                from_dut = to_dut
                dut_idx += 1

        if save_path == 'yes' :
            nw_topo['subtopo']['linear'] = copy.deepcopy(found_path)

        TOPOLOGY.show_topo_path(found_path)
        return found_path


    @staticmethod
    def dut_get_saved_linear_topo():
        return copy.deepcopy(nw_topo['subtopo']['linear'])


    @staticmethod
    def find_ring_topo_in_dut_list(dut_list=[], start_dut='', node_limit=0, save_path='yes'):

        st.log("Topology - Find Linear Topo in Dut list {} length {}".format(dut_list, node_limit))
        nw_topo_dut_list = TOPOLOGY.get_dut_list()

        found_path = {}
        found_path['found'] = False

        if not dut_list or len(dut_list) == 0 :
            dut_list = nw_topo_dut_list
        else :
            for dut in dut_list :
                if dut not in nw_topo_dut_list :
                    st.log("Dut {} not in Topo dut lidt {}".format(dut, nw_topo_dut_list))
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

            if TOPOLOGY.dut_is_tg(dut) :
               continue

            st.log(" Starting at dut {} with longest path {}.".format(dut, longest_path))

            nw_topo_stack = []
            nw_topo_path = []
            nw_topo_stack.append(dut)

            while nw_topo_stack and len(nw_topo_stack) :

                loop_count += 1
                if loop_count > 100 :
                    break

                st.log("   sp stack {}".format(nw_topo_stack))
                st.log("   sp path {}".format(nw_topo_path))

                curr_dut = nw_topo_stack.pop()
                nw_topo_path.append(curr_dut)

                st.log("   modified sp path {}".format(nw_topo_path))

                leaf_dut = True
                ring_found = False

                for link_name, link_data in nw_topo[curr_dut]['intf'].items():

                    if link_data['type'] in [ 'LBK', 'PCH', 'VLN'] :
                        continue

                    if 'rmt_dut' in link_data.keys():
                        next_dut = link_data['rmt_dut']

                        if next_dut == dut :
                            ring_found = True

                        if TOPOLOGY.dut_is_tg(next_dut):
                            continue

                        if next_dut not in dut_list :
                            continue

                        if next_dut in nw_topo_path :
                            continue

                        if next_dut not in nw_topo_stack :
                            nw_topo_stack.append(next_dut)

                        leaf_dut = False

                if ring_found :
                    st.log("      Ring found Dut {} ".format(curr_dut))
                    st.log("      Ring found sp path {} ".format(nw_topo_path))
                    st.log("      Ring found longest path {} ".format(longest_path))

                    if len(nw_topo_path) > 2 :

                        nw_topo_path.append(dut)

                        st.log("         new ring sp path {} ".format(nw_topo_path))
                        st.log("         ring longest path {} ".format(longest_path))

                        if len(longest_path) < len(nw_topo_path) :
                            if node_limit > 0 :
                                if len(nw_topo_path) <= length_limit :
                                    longest_path = copy.deepcopy(nw_topo_path)
                                    st.log("          New longest path set as curr new ring sp path")
                            else :
                                longest_path = copy.deepcopy(nw_topo_path)
                                st.log("          New longest path set as curr new ring sp path")

                        if len(longest_path) >= length_limit :
                            st.log("         Path length limit provided {} and reached".format(length_limit))
                            break

                        nw_topo_path.pop()

                    if leaf_dut is True :
                        nw_topo_path.pop()

                if  len(longest_path) == length_limit :
                    break

        st.log("Topology - Longest path len {} with path {}".format(len(longest_path), longest_path))

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
                for link_name, link_data in nw_topo[from_dut]['intf'].items():

                    if link_data['type'] in [ 'LBK', 'PCH', 'VLN'] :
                        continue

                    if 'rmt_dut' in link_data.keys():
                        if link_data['rmt_dut'] == to_dut :

                            rmt_link = link_data['rmt_link']
                            lcl_if = TOPOLOGY.get_link_dut_interface(from_dut, link_name)
                            rmt_if = TOPOLOGY.get_link_dut_interface(to_dut, rmt_link)

                            segt_link = { 'lcl_dut' : from_dut, 'lcl_link': link_name, 'lcl_if': lcl_if,
                                          'rmt_dut' : to_dut,   'rmt_link': rmt_link, 'rmt_if': rmt_if }

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
            nw_topo['subtopo']['ring'] = copy.deepcopy(found_path)

        TOPOLOGY.show_topo_path(found_path)
        return found_path


    @staticmethod
    def dut_get_saved_ring_topo():
        return copy.deepcopy(nw_topo['subtopo']['ring'])


    @staticmethod
    def find_star_topo_in_dut_list(dut_list=[], core_dut = "", path_spoke_limit=0, save_path='yes'):

        st.log("Topology - Find Star Topo in Dut list {} length {}".format(dut_list, path_spoke_limit))
        nw_topo_dut_list = TOPOLOGY.get_dut_list()

        found_path = {}
        found_path['found'] = False

        if not dut_list or len(dut_list) == 0 :
            dut_list = nw_topo_dut_list
        else :
            for dut in dut_list :
                if dut not in nw_topo_dut_list :
                    st.log("Dut {} not in Topo dut list {}".format(dut, nw_topo_dut_list))
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

            if TOPOLOGY.dut_is_tg(dut) :
               continue

            st.log(" Starting dut {} ".format(dut))

            nw_topo_path = []
            nw_topo_path.append(dut)

            excl_list = copy.deepcopy(dut_list)
            excl_list.remove(dut)
            st.log("  dut to traverse {}".format(excl_list))

            for next_dut in excl_list :
                st.log("   sp path {}".format(nw_topo_path))

                for link_name, link_data in nw_topo[dut]['intf'].items():

                    if link_data['type'] in [ 'LBK', 'PCH', 'VLN'] :
                        continue

                    if 'rmt_dut' in link_data.keys():
                        rmt_dut = link_data['rmt_dut']

                        if rmt_dut != next_dut :
                            continue

                        nw_topo_path.append(next_dut)
                        break

            if len(largest_star) < len(nw_topo_path) :
                largest_star = nw_topo_path

            path_spoke_count = len(largest_star) - 1
            if path_spoke_limit > 0 :
                if path_spoke_count == path_spoke_limit :
                    st.log("    Path spoke limit provided {} and reached".format(path_spoke_limit))
                    break
            else :
                if path_spoke_count == spoke_limit :
                    st.log("    Path max possible spoke {} reached".format(spoke_limit))
                    break

        st.log("Topology - {} Star with nodes {}".format(len(largest_star), largest_star))

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
                for link_name, link_data in nw_topo[from_dut]['intf'].items():

                    if link_data['type'] in [ 'LBK', 'PCH', 'VLN'] :
                        continue

                    if 'rmt_dut' in link_data.keys():
                        if link_data['rmt_dut'] == to_dut :
                            rmt_link = link_data['rmt_link']
                            lcl_if = TOPOLOGY.get_link_dut_interface(from_dut, link_name)
                            rmt_if = TOPOLOGY.get_link_dut_interface(to_dut, rmt_link)

                            segt_link = { 'lcl_dut' : from_dut, 'lcl_link': link_name, 'lcl_if': lcl_if,
                                          'rmt_dut' : to_dut,   'rmt_link': rmt_link, 'rmt_if': rmt_if }

                            if segt_link_idx == 0 : found_path['segment'][dut_idx - 1] = {}
                            found_path['segment'][dut_idx - 1].update({ segt_link_idx: segt_link})

                            if segt_link_idx == 0:
                                found_path['segment_count'] += 1
                            segt_link_idx += 1
                            #st.log("   Path node {} is {}".format(dut_idx - 1, segt_link))

                dut_idx += 1

        if save_path == 'yes' :
            nw_topo['subtopo']['star'] = copy.deepcopy(found_path)

        TOPOLOGY.show_topo_path(found_path)
        return found_path


    @staticmethod
    def dut_get_saved_star_topo():
        return copy.deepcopy(nw_topo['subtopo']['star'])


    @staticmethod
    def find_spine_leaf_topo_in_dut_list(spine_list=[], leaf_list=[], save_path='yes'):

        st.log("Topology - Find Spine Leaf paths in {} and {}.".format(spine_list, leaf_list))
        nw_topo_dut_list = TOPOLOGY.get_dut_list()

        found_path = {}
        found_path['found'] = False

        for dut in spine_list:
            if dut not in nw_topo_dut_list:
                st.log("Spine dut {} not in topo dut list {}".format(dut, nw_topo_dut_list))
                return found_path

        for dut in leaf_list:
            if dut not in nw_topo_dut_list:
                st.log("Leaf dut {} not in topo dut list {}".format(dut, nw_topo_dut_list))
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

        segment_index = 0
        found_path['segment'] = {}
        found_path['segment_count'] = 0

        for spine_dut in spine_list :

            dut_list = copy.deepcopy(leaf_list)
            dut_list.append(spine_dut)

            spine_path = TOPOLOGY.find_star_topo_in_dut_list(dut_list, spine_dut, save_path='no')

            st.log("Spine Leaf paths from {} is {}.\n".format(spine_dut, spine_path))

            if spine_path['found'] :
                found_path['found'] = True

                if spine_dut not in found_path['dut_list']:
                    found_path['dut_list'].append(spine_dut)

                for leaf_dut in spine_path['dut_list']:
                    if leaf_dut not in found_path['dut_list']:
                        found_path['dut_list'].append(leaf_dut)

                for _, seg_data in spine_path['segment'].items():
                    found_path['segment'][segment_index] = copy.deepcopy(seg_data)
                    found_path['segment_count'] += 1
                    segment_index += 1

            spine_path = copy.deepcopy(spine_path)
            found_path['spine_path'].update({ spine_dut : spine_path })

        if save_path == 'yes' :
            nw_topo['subtopo']['spine_leaf'] = copy.deepcopy(found_path)

        st.log("Topology - Spine Leaf paths {}\n".format(found_path))
        return found_path


    @staticmethod
    def dut_get_saved_spine_leaf_topo():
        return copy.deepcopy(nw_topo['subtopo']['spine_leaf'])


    @staticmethod
    def find_fullmesh_topo_in_dut_list(dut_list=[], start_dut='', save_path='yes'):

        st.log("Topology - Find Full Mesh Topo in Dut list {} start at {}.".format(dut_list, start_dut))
        nw_topo_dut_list = TOPOLOGY.get_dut_list()

        found_path = {}
        found_path['found'] = False

        if not dut_list or len(dut_list) == 0 :
            dut_list = nw_topo_dut_list
        else :
            for dut in dut_list :
                if dut not in nw_topo_dut_list :
                    st.log("Dut {} not in Topo dut list {}".format(dut, nw_topo_dut_list))
                    return found_path
        dut_list.sort()

        if start_dut != '' :
            if start_dut not in dut_list :
                st.log("Topology - Start dut {} not in dut list {}".format(start_dut, dut_list))
                return found_path

            adjusted_dut_list = []
            adjusted_dut_list.append(start_dut)
            for dut in dut_list :
                if dut == start_dut :
                    continue
                adjusted_dut_list.append(dut)

            dut_list = adjusted_dut_list
            st.log("Topology - Start dut {} adjusted dut list {}".format(start_dut, dut_list))


        #path_length = 0
        found_path['found'] = False
        found_path['dut_list'] = []
        found_path['segment'] = {}
        found_path['segment_count'] = 0
        found_path['type'] = 'fullmesh'

        visited_dut_list=[]
        dut_idx = 0
        st.log("Topology - Dut list {} for finding mesh topology".format(dut_list))

        for from_dut in dut_list :

            if from_dut in visited_dut_list :
                continue

            visited_dut_list.append(from_dut)

            segt_link_idx = 0

            for link_name, link_data in nw_topo[from_dut]['intf'].items():

                if link_data['type'] in [ 'LBK', 'PCH', 'VLN'] :
                    continue

                if 'rmt_dut' not in link_data.keys() :
                    continue

                if 'rmt_link' not in link_data.keys() :
                    continue

                to_dut = link_data['rmt_dut']
                rmt_link = link_data['rmt_link']

                if TOPOLOGY.dut_is_tg(to_dut):
                    continue

                if to_dut not in dut_list :
                    continue

                to_dut_visited = True if to_dut in visited_dut_list else False
                if to_dut in visited_dut_list :
                   continue

                lcl_if = TOPOLOGY.get_link_dut_interface(from_dut, link_name)
                rmt_if = TOPOLOGY.get_link_dut_interface(to_dut, rmt_link)

                segt_link = { 'lcl_dut' : from_dut, 'lcl_link' : link_name, 'lcl_if': lcl_if,
                              'rmt_dut' : to_dut,   'rmt_link' : rmt_link , 'rmt_if': rmt_if,
                              'rmt_visited' : to_dut_visited }

                if dut_idx not in found_path['segment'].keys():
                    found_path['segment'][dut_idx] = {}

                found_path['segment'][dut_idx].update({segt_link_idx: segt_link})

                segt_link_idx += 1
                #st.log("   Path node {} is {}".format(from_dut, segt_link))

            if segt_link_idx :
                found_path['segment_count'] += 1
                dut_idx += 1

        for _, segt_data in found_path['segment'].items():
            for _, link_data in segt_data.items():
                from_dut = link_data['lcl_dut']
                if from_dut not in found_path['dut_list'] :
                    found_path['dut_list'].append(from_dut)
                to_dut = link_data['rmt_dut']
                if to_dut not in found_path['dut_list'] :
                    found_path['dut_list'].append(to_dut)

        if found_path['segment_count'] :
            found_path['found'] = True

        if found_path['segment_count'] and start_dut != '' :
            if 0 in found_path['segment'].keys() :
                if 0 in found_path['segment'][0].keys() :
                    from_dut = found_path['segment'][0][0]['lcl_dut']
                    if from_dut != start_dut :
                        found_path = {}
                        found_path['found'] = False
                        st.log("Topology - Mesh top doesnt star with star dut {}".format(start_dut))
                        return found_path

        if save_path == 'yes' :
            nw_topo['subtopo']['fullmesh'] = copy.deepcopy(found_path)

        TOPOLOGY.show_topo_path(found_path)
        return found_path


    @staticmethod
    def dut_get_saved_fullmesh_topo():
        return copy.deepcopy(nw_topo['subtopo']['fullmesh'])


    @staticmethod
    def find_maxlink_segment_topo_in_dut_list(dut_list=[], start_dut='', save_path='yes'):

        st.log("Topology - Find Maxlink Segment Topo in Dut list {} length {}".format(dut_list, start_dut))
        nw_topo_dut_list = TOPOLOGY.get_dut_list()

        found_path = {}
        found_path['found'] = False

        if not dut_list or len(dut_list) == 0 :
            dut_list = nw_topo_dut_list
        else :
            for dut in dut_list :
                if dut not in nw_topo_dut_list :
                    st.log("Dut {} not in Topo dut lidt {}".format(dut, nw_topo_dut_list))
                    return found_path

        if start_dut and start_dut != '' :
            if start_dut not in dut_list :
                st.log("Start dut {} not in dut list {}".format(start_dut, dut_list))
                return found_path

        st.log("Modified Dut list {} start_dut {}".format(dut_list, start_dut))

        main_dut_list = copy.deepcopy(dut_list)
        main_dut_list.sort()
        rem_dut_list = copy.deepcopy(dut_list)

        max_from_dut = ''
        max_to_dut = ''
        max_link = 0

        for from_dut in main_dut_list :

            if start_dut and start_dut != '' :
                if start_dut != from_dut :
                    continue

            if from_dut in rem_dut_list:
                rem_dut_list.remove(from_dut)

            if TOPOLOGY.dut_is_tg(from_dut) :
               continue

            for to_dut in rem_dut_list :
                curr_link_count = 0

                for link_name, link_data in nw_topo[from_dut]['intf'].items():

                    if link_data['type'] in ['LBK'] :
                        continue

                    if 'rmt_dut' in link_data.keys():

                        next_dut = link_data['rmt_dut']

                        if next_dut !=  to_dut : continue
                        if next_dut not in dut_list : continue
                        if TOPOLOGY.dut_is_tg(next_dut): continue

                        curr_link_count += 1

                if curr_link_count > max_link:
                     max_from_dut = from_dut
                     max_to_dut = to_dut
                     max_link = curr_link_count

        st.log("Topology - Max Link segment {}--{} links {}".format(max_from_dut, max_to_dut, max_link))

        #path_length = 1
        found_path['found'] = True if max_link else False
        found_path['dut_list'] = []
        found_path['segment'] = {}
        found_path['segment_count'] = 0
        found_path['type'] = 'maxlink_segt'

        if found_path['found'] :

            found_path['dut_list'].append(max_from_dut)
            found_path['dut_list'].append(max_to_dut)
            found_path['start_dut'] = max_from_dut

            from_dut = max_from_dut
            to_dut = max_to_dut
            dut_idx = 1
            segt_link_idx = 0

            for link_name, link_data in nw_topo[from_dut]['intf'].items():

                if link_data['type'] in ['LBK'] :
                    continue

                if 'rmt_dut' in link_data.keys():

                    if link_data['rmt_dut'] == to_dut :

                        rmt_link = link_data['rmt_link']

                        lcl_if = TOPOLOGY.get_link_dut_interface(from_dut, link_name)
                        rmt_if = TOPOLOGY.get_link_dut_interface(to_dut, rmt_link)

                        segt_link = { 'lcl_dut' : from_dut, 'lcl_link': link_name, 'lcl_if': lcl_if,
                                      'rmt_dut' : to_dut,   'rmt_link' : rmt_link , 'rmt_if': rmt_if,
                                      'type': link_data['type'] }

                        if segt_link_idx == 0 : found_path['segment'][dut_idx - 1] = {}
                        found_path['segment'][dut_idx - 1].update({segt_link_idx: segt_link})

                        if segt_link_idx == 0:
                            found_path['segment_count'] += 1
                        segt_link_idx += 1
                        #st.log("   Path node {} is {}".format(dut_idx - 1, segt_link))

        if save_path == 'yes' :
            nw_topo['subtopo']['maxlink_segt'] = copy.deepcopy(found_path)

        TOPOLOGY.show_topo_path(found_path)
        return found_path


    @staticmethod
    def dut_get_saved_maxlink_segt_topo():
        return copy.deepcopy(nw_topo['subtopo']['maxlink_segt'])


    @staticmethod
    def get_saved_current_topology():
        return nw_topo['subtopo']['current']

    @staticmethod
    def save_current_topology(curr_topology):
        nw_topo['subtopo']['current'] = curr_topology


    @staticmethod
    def get_saved_named_topology(topo_name):
        if topo_name == '' :
            st.log("Topology - topology name cannot be empty string")
            return None

        return nw_topo['subtopo'][topo_name]


    @staticmethod
    def add_del_named_topology(topo_name, dut_topology, add='yes'):

        if topo_name == '' :
            resstr = "Topology - topology name cannot be empty string"
            st.log("{}".format(resstr))
            return False, resstr

        if topo_name in ['linear', 'ring', 'star', 'spine_leaf', 'fullmesh', 'current'] :
            resstr = "Topology - topology name cannot be {}".format(topo_name)
            st.log("{}".format(resstr))
            return False, resstr

        if add == 'yes' :
            dut_topology['topology_name'] = topo_name
            nw_topo['subtopo'][topo_name] = dut_topology
        else :
            if topo_name in nw_topo['subtopo'].keys() :
                del nw_topo['subtopo'][topo_name]

        return True, 'Success'


    @staticmethod
    def get_topology_dut_list(dut_topology):

        if not dut_topology['found'] :
            st.log("Topology  - topology path not found")
            return None

        return copy.deepcopy(dut_topology['dut_list'])


    @staticmethod
    def get_topology_all_segments(dut_topology):

        resstr = 'Success'
        if not dut_topology['found'] :
            resstr = "Topology  - topology path not found"
            st.log("{}".format(resstr))
            return False, resstr, {}

        if dut_topology['segment_count'] < 1 :
            st.log("Topology  - topology for doesnot have segments")
            return False, resstr, {}

        topo_segts = dut_topology['segment']
        return True, 'Success', copy.deepcopy(topo_segts)


    @staticmethod
    def get_topology_segment(dut_topology, segment_idx):

        if not dut_topology['found'] :
            st.log("Topology  - topology path not found")
            return None

        if dut_topology['segment_count'] < 1 :
            st.log("Topology  - topology for doesnot have segments")
            return None

        topo_segts = dut_topology['segment']
        for segt_idx, segt_data in topo_segts.items():
            if segt_idx == segment_idx :
                return segt_data

        st.log("Topology  - Invalid topology segt index {}".format(segment_idx))
        return None


    @staticmethod
    def get_topology_segment_links(segment_data, to_dut='', vrf=''):
        if not segment_data :
            st.log("Topology  - Null segment")
            return []

        segment_links = []
        for _, link_data in segment_data.items():
            link_name = link_data['lcl_link']
            if to_dut != '' :
                if to_dut == link_data['rmt_dut'] :
                    if vrf != '' :
                        if vrf == link_data['lcl_vrf'] :
                            segment_links.append(link_name)
                    else :
                        segment_links.append(link_name)
            else :
                segment_links.append(link_name)

        return copy.deepcopy(segment_links)


    @staticmethod
    def get_topology_segment_link_count(segment_data):
        if not segment_data :
            st.log("Topology  - Null segment")
            return ''

        link_count = 0
        for _, _ in segment_data.items():
             link_count += 1

        return link_count


    @staticmethod
    def get_topology_segment_lcl_dut(segment_data):
        if not segment_data :
            st.log("Topology  - Null segment")
            return ''

        for _, link_data in segment_data.items():
            lcl_dut = link_data['lcl_dut']
            return  lcl_dut

        return ''


    @staticmethod
    def get_topology_segment_remote_duts(segment_data):
        if not segment_data :
            st.log("Topology  - Null segment")
            return []

        rmt_dut_list = []
        for _, link_data in segment_data.items():
            rmt_dut = link_data['rmt_dut']
            if rmt_dut not in rmt_dut_list :
                rmt_dut_list.append(rmt_dut)

        return copy.deepcopy(rmt_dut_list)


    @staticmethod
    def get_topology_total_link_count(dut_topology):

        if not dut_topology['found'] :
            st.log("Topology  - topology path not found")
            return 0

        if dut_topology['segment_count'] < 1 :
            st.log("Topology  - topology for doesnot have segments")
            return 0

        link_count = 0
        topo_segts = dut_topology['segment']
        for _, segt_data in topo_segts.items():
            link_count += TOPOLOGY.get_topology_segment_link_count(segt_data)

        st.log("Topology  - Total link count {}".format(link_count))
        return link_count


    @staticmethod
    def get_dut_topology_links(dut_topology, dut_list=[]):

        #st.log("Topology - Get topology Links")
        #result, resstr = True, 'Success'

        result, resstr = TOPOLOGY.test_topo_present(topo_path=dut_topology, dut_count=2, segment_count=1)
        if not result :
            st.log("Topology - Topology doesnt have any segemnts")
            return False, resstr, {}

        topo_segts = dut_topology['segment']
        topology_links = {}

        for _, segt_data in topo_segts.items():
            for _, link_data in segt_data.items():
                if 'lcl_dut' not in link_data.keys() :
                    continue

                lcl_dut = link_data['lcl_dut']
                if len(dut_list) != 0 :
                    if lcl_dut not in dut_list :
                        continue

                if lcl_dut not in topology_links.keys() :
                    topology_links[lcl_dut] = []

                lcl_link = link_data['lcl_link']
                if lcl_link not in topology_links[lcl_dut] :
                    topology_links[lcl_dut].append(lcl_link)

        for _, segt_data in topo_segts.items():
            for _, link_data in segt_data.items():
                if 'rmt_dut' not in link_data.keys() :
                    continue

                rmt_dut = link_data['rmt_dut']
                if len(dut_list) != 0 :
                    if rmt_dut not in dut_list :
                        continue

                if rmt_dut not in topology_links.keys() :
                    topology_links[rmt_dut] = []

                rmt_link = link_data['rmt_link']
                if rmt_link not in topology_links[rmt_dut] :
                    topology_links[rmt_dut].append(rmt_link)

        st.log("Topology - Topology Links {}".format(topology_links))
        return True, 'Success', copy.deepcopy(topology_links)


    @staticmethod
    def get_dut_topology_link_ips(dut_topology, dut_list=[], addr_family='ipv4'):

        result, resstr, topo_links = TOPOLOGY.get_dut_topology_links(dut_topology, dut_list)
        if not result :
            resstr += "Topology  - get topology link Ips Failed"
            st.log("{}".format(resstr))
            return result, resstr, {}

        topology_link_ips = {}

        for dut, link_list in topo_links.items() :
            if dut not in topology_link_ips.keys() :
                topology_link_ips[dut] = []

            for link_name in link_list :
                link_ip, _ = TOPOLOGY.dut_get_link_ip_and_subnet(dut, link_name, addr_family)
                if link_ip != '' :
                    if link_ip not in topology_link_ips[dut]:
                        topology_link_ips[dut].append(link_ip)

        st.log("Topology - Topology Link IPs {}".format(topology_link_ips))
        return True, 'Success', copy.deepcopy(topology_link_ips)


    @staticmethod
    def get_dut_topology_link_ip_prefixes(dut_topology, dut_list=[], addr_family='ipv4'):

        result, resstr, topo_links = TOPOLOGY.get_dut_topology_links(dut_topology, dut_list)
        if not result :
            resstr += "Topology  - get topology link Ips Failed"
            st.log("{}".format(resstr))
            return result, resstr, {}

        topology_link_prefixes = {}

        for dut, link_list in topo_links.items() :
            if dut not in topology_link_prefixes.keys() :
                topology_link_prefixes[dut] = []

            for link_name in link_list :
                link_ip, subnet = TOPOLOGY.dut_get_link_ip_and_subnet(dut, link_name, addr_family)
                if link_ip != '' :
                    ip_prefix = '{}/{}'.format(link_ip, subnet)
                    if ip_prefix not in topology_link_prefixes[dut]:
                        topology_link_prefixes[dut].append(ip_prefix)

        st.log("Topology - Topology Link IP prefixes {}".format(topology_link_prefixes))
        return True, 'Success', copy.deepcopy(topology_link_prefixes)


    @staticmethod
    def get_dut_topology_link_nws(dut_topology, dut_list=[], addr_family='ipv4'):

        result, resstr, topo_links = TOPOLOGY.get_dut_topology_links(dut_topology, dut_list)
        if not result :
            resstr += "Topology  - get topology link Ips Failed"
            st.log("{}".format(resstr))
            return result, resstr, {}

        topology_link_nws = {}

        for dut, link_list in topo_links.items() :
            if dut not in topology_link_nws.keys() :
                topology_link_nws[dut] = []

            for link_name in link_list :
                link_ip, subnet = TOPOLOGY.dut_get_link_ip_and_subnet(dut, link_name, addr_family)
                link_ip_nw = TOPOLOGY.get_ip_network(link_ip, subnet, addr_family)
                if link_ip_nw != '' :
                    if link_ip_nw not in topology_link_nws[dut]:
                        topology_link_nws[dut].append(link_ip_nw)

        st.log("Topology - Topology Link Network IPs {}".format(topology_link_nws))
        return True, 'Success', copy.deepcopy(topology_link_nws)


    @staticmethod
    def get_dut_topology_link_nw_prefixes(dut_topology, dut_list=[], addr_family='ipv4'):

        result, resstr, topo_links = TOPOLOGY.get_dut_topology_links(dut_topology, dut_list)
        if not result :
            resstr += "Topology  - get topology link Ips Failed"
            st.log("{}".format(resstr))
            return result, resstr, {}

        topology_link_nw_prefixes = {}

        for dut, link_list in topo_links.items() :
            if dut not in topology_link_nw_prefixes.keys() :
                topology_link_nw_prefixes[dut] = []

            for link_name in link_list :
                link_ip, subnet = TOPOLOGY.dut_get_link_ip_and_subnet(dut, link_name, addr_family)
                link_ip_nw = TOPOLOGY.get_ip_network_prefix(link_ip, subnet, addr_family)
                if link_ip_nw != '' :
                    if link_ip_nw not in topology_link_nw_prefixes[dut]:
                        topology_link_nw_prefixes[dut].append(link_ip_nw)

        st.log("Topology - Topology Link Network IP prefixes {}".format(topology_link_nw_prefixes))
        return True, 'Success', copy.deepcopy(topology_link_nw_prefixes)



    #-------------------------------------------------------------------------
    # Topology segment modification functions


    @staticmethod
    def limit_segment_links(segment_data, max_link=0):
        if not segment_data :
            resstr = "Topology - Null segemnt received"
            st.log("{}".format(resstr))
            return False, resstr, {}

        if max_link == 0 :
            st.log("Topology - segment link limiting no change")
            return True, 'Success', copy.deepcopy(segment_data)

        new_segt_data = {}
        new_link_idx = 0

        rmt_dut_list = TOPOLOGY.get_topology_segment_remote_duts(segment_data)
        for rmt_dut in rmt_dut_list :
            link_count = 0
            for _, link_data in segment_data.items():
                if link_data['rmt_dut'] != rmt_dut :
                    continue

                if link_count >= max_link :
                    break

                new_segt_data[new_link_idx] = copy.deepcopy(link_data)
                new_link_idx += 1
                link_count += 1

        if new_link_idx == 0 :
            resstr = "Topology - segment link limiting to {} Failed".format(max_link)
            st.log("{}".format(resstr))
            return False, resstr, {}

        TOPOLOGY.show_topo_segment(new_segt_data)
        st.log("Topology - segment link limiting Success")
        return True, 'Success', copy.deepcopy(new_segt_data)


    @staticmethod
    def create_overlay_segment(segt_data, params={}):

        st.log("Topology - Create overlay segment params {}".format(params))
        TOPOLOGY.show_topo_segment(segt_data)
        #import pdb; pdb.set_trace()

        if 'if_type' not in params.keys():
            resstr = "Topology - Create overlay if type param not present"
            return False, resstr, {}

        if_type = params['if_type']
        if if_type not in ["VLN", "PCH", "BCD"]:
            resstr = "Topology - create Invalid if type {}".format(if_type)
            st.log("{}".format(resstr))
            return False, resstr, copy.deepcopy(segt_data)

        vlan_list = []
        if if_type == 'BCD' :
            if 'vlan_list' not in params.keys() :
                resstr = "Topology - broadcast domain vlan list param not present"
                st.log("{}".format(resstr))
                return False, resstr, {}

            vlan_list = copy.deepcopy(params['vlan_list'])
            if len(vlan_list) == 0 :
                resstr = "Topology - broadcast domain vlan list param empty"
                st.log("{}".format(resstr))
                return False, resstr, {}

        if_count = 1
        if 'if_count' in  params.keys():
            if_count = params['if_count']

        new_segt_data = {}
        new_link_idx = 0

        lcl_dut = TOPOLOGY.get_topology_segment_lcl_dut(segt_data)
        rmt_dut_list = TOPOLOGY.get_topology_segment_remote_duts(segt_data)

        st.log("Topology - segment lcl_dut {} rmt_dut_list {}".format(lcl_dut, rmt_dut_list))

        for rmt_dut in rmt_dut_list :

            lcl_member_links = []
            rmt_member_links = []
            lcl_created_if = []
            rmt_created_if = []

            for _, link_data in segt_data.items():
                if link_data['rmt_dut'] != rmt_dut :
                    continue

                lcl_link = link_data['lcl_link']
                rmt_link = link_data['rmt_link']

                lcl_member_links.append(lcl_link)
                rmt_member_links.append(rmt_link)

            if if_type == 'PCH' :

                result, resstr, pch_list = TOPOLOGY.get_free_portchannel_in_dut_list([lcl_dut, rmt_dut], 1)
                if not result :
                    st.log("{}".format(resstr))
                    return False, resstr, {}

                result, resstr, lcl_created_if = TOPOLOGY.add_del_portchannel(lcl_dut, rmt_dut, portchannel_num=pch_list[0],
                                                                              member_links=lcl_member_links, add='yes')
                if not result :
                    resstr += "Topology - {} add local portchannel for {} Failed".format(lcl_dut, lcl_member_links)
                    st.log("{}".format(resstr))
                    return False, resstr, {}

                result, resstr, rmt_created_if = TOPOLOGY.add_del_portchannel(rmt_dut, lcl_dut, portchannel_num=pch_list[0],
                                                                              member_links=rmt_member_links, add='yes')
                if not result :
                    resstr += "Topology - {} add remote portchannel for {} Failed".format(rmt_dut, rmt_member_links)
                    st.log("{}".format(resstr))
                    return False,  resstr,{}

            if if_type in ['VLN', 'BCD' ]:

                if if_type == 'VLN' :
                    result, resstr, vlan_list = TOPOLOGY.get_free_vlans_in_dut_list([lcl_dut, rmt_dut], if_count)
                    if not result :
                        st.log("{}".format(resstr))
                        return False, resstr, {}

                result, resstr, lcl_created_if = TOPOLOGY.add_del_vlans(lcl_dut, vlan_list=vlan_list, vlan_count=if_count,
                                                                        member_links=lcl_member_links, add='yes')
                if not result :
                    resstr += "Topology - {} add local vlan for {} Failed".format(lcl_dut, lcl_member_links)
                    st.log("{}".format(resstr))
                    return False, resstr, {}

                result, resstr, rmt_created_if = TOPOLOGY.add_del_vlans(rmt_dut, vlan_list=vlan_list, vlan_count=if_count,
                                                                        member_links=rmt_member_links, add='yes')
                if not result :
                    resstr += "Topology - {} add local vlan for {} Failed".format(rmt_dut, rmt_member_links)
                    st.log("{}".format(resstr))
                    return False, resstr, {}

            st.log("Topology - Local {} created interfaces {}".format(lcl_dut, lcl_created_if))
            st.log("Topology - Remote {} created interfaces {}".format(rmt_dut, rmt_created_if))

            if len(lcl_created_if) == len(rmt_created_if) :
                if_idx = 0
                while if_idx < len(lcl_created_if) :
                    TOPOLOGY.connect_links(lcl_dut, lcl_created_if[if_idx], rmt_dut, rmt_created_if[if_idx], add='yes')
                    if_idx += 1
            else :
                resstr = "Topology - newly created local remote overlay link counts differ {} {}".format(
                                           len(lcl_created_if), len(rmt_created_if))
                st.log("{}".format(resstr))
                return False,  resstr,{}

            if_idx = 0
            while if_idx < len(lcl_created_if) :
                new_segt_link = { 'lcl_dut' : lcl_dut, 'rmt_dut' : rmt_dut, 'type': if_type,
                                  'lcl_link': lcl_created_if[if_idx], 'rmt_link' : rmt_created_if[if_idx] }

                new_segt_data[new_link_idx] = copy.deepcopy(new_segt_link)
                st.log("Topology - Adding new link at index {}->{}".format(new_link_idx, new_segt_link))
                new_link_idx += 1
                if_idx += 1

        TOPOLOGY.show_topo_segment(new_segt_data)
        st.log("Topology - Create overlay segment {} Success".format(if_type))
        return True, 'Success', copy.deepcopy(new_segt_data)


    @staticmethod
    def create_overlay_segment_all_if_types(segt_data, params={}):

        st.log("Topology - Create overlay segment all intf params {}".format(params))
        TOPOLOGY.show_topo_segment(segt_data)

        #import pdb; pdb.set_trace()
        new_segt_data = {}
        new_link_idx = 0

        lcl_dut = TOPOLOGY.get_topology_segment_lcl_dut(segt_data)
        rmt_dut_list = TOPOLOGY.get_topology_segment_remote_duts(segt_data)
        st.log("Topology - segment lcl_dut {} rmt_dut_list {}".format(lcl_dut, rmt_dut_list))

        for rmt_dut in rmt_dut_list :

            lcl_member_links = []
            rmt_member_links = []
            lcl_created_if = []
            rmt_created_if = []

            for link_idx, link_data in segt_data.items():

                st.log("Topology - Link {} link_data {}".format(link_idx, link_data))
                if link_data['rmt_dut'] != rmt_dut :
                    continue

                lcl_link = link_data['lcl_link']
                rmt_link = link_data['rmt_link']
                lcl_created_if = []
                rmt_created_if = []

                if link_idx in [ 0 ]: #ETH
                    if_type = 'ETH'
                    lcl_created_if = [lcl_link]
                    rmt_created_if = [rmt_link]

                elif link_idx in [ 1 ] : #VLN
                    if_type = 'VLN'
                    if 'vlan_count' in params.keys() :
                        vlan_count = params['vlan_count']
                    else :
                        vlan_count = 2

                    lcl_member_links = [lcl_link]
                    rmt_member_links = [rmt_link]

                    result, resstr, vlan_list = TOPOLOGY.get_free_vlans_in_dut_list([lcl_dut, rmt_dut], vlan_count)
                    if not result :
                        st.log("{}".format(resstr))
                        return False, resstr, {}

                    result, resstr, lcl_created_if = TOPOLOGY.add_del_vlans(lcl_dut, vlan_list=vlan_list, vlan_count=vlan_count,
                                                            member_links=lcl_member_links, add='yes')
                    if not result :
                        resstr += "Topology - {} add local vlan for {} Failed".format(lcl_dut, lcl_member_links)
                        st.log("{}".format(resstr))
                        return False, resstr, {}

                    result, resstr, rmt_created_if = TOPOLOGY.add_del_vlans(rmt_dut, vlan_list=vlan_list, vlan_count=vlan_count,
                                                            member_links=rmt_member_links, add='yes')
                    if not result :
                        resstr += "Topology - {} add local vlan for {} Failed".format(rmt_dut, rmt_member_links)
                        st.log("{}".format(resstr))
                        return False, resstr, {}

                elif link_idx in [ 2 ] : #PCH
                    if_type = 'PCH'
                    lcl_member_links = [lcl_link]
                    rmt_member_links = [rmt_link]

                    result, resstr, pch_list = TOPOLOGY.get_free_portchannel_in_dut_list([lcl_dut, rmt_dut], 1)
                    if not result :
                        st.log("{}".format(resstr))
                        return False, resstr, {}

                    result, resstr, lcl_created_if = TOPOLOGY.add_del_portchannel(lcl_dut, rmt_dut, portchannel_num=pch_list[0],
                                                                  member_links=lcl_member_links, add='yes')
                    if not result :
                        resstr += "Topology - {} add local portchannel for {} Failed".format(lcl_dut, lcl_member_links)
                        st.log("{}".format(resstr))
                        return False, resstr, {}

                    result, resstr, rmt_created_if = TOPOLOGY.add_del_portchannel(rmt_dut, lcl_dut, portchannel_num=pch_list[0],
                                                                  member_links=rmt_member_links, add='yes')
                    if not result :
                        resstr += "Topology - {} add remote portchannel for {} Failed".format(rmt_dut, rmt_member_links)
                        st.log("{}".format(resstr))
                        return False, resstr,  {}
                else :
                    st.log("Topology - Ignoring link index {} for perlink overlay".format(link_idx))
                    lcl_created_if = []
                    rmt_created_if = []
                    continue

                st.log("Topology - Local {} created interfaces {}".format(lcl_dut, lcl_created_if))
                st.log("Topology - Remote {} created interfaces {}".format(rmt_dut, rmt_created_if))

                if len(lcl_created_if) == len(rmt_created_if) :
                    if_idx = 0
                    while if_idx < len(lcl_created_if) :
                        TOPOLOGY.connect_links(lcl_dut, lcl_created_if[if_idx], rmt_dut, rmt_created_if[if_idx], add='yes')
                        if_idx += 1
                else :
                    resstr = "Topology - newly created local remote overlay link counts differ {} {}".format(
                                             len(lcl_created_if), len(rmt_created_if))
                    st.log("{}".format(resstr))
                    return False,  resstr,{}

                if_idx = 0
                while if_idx < len(lcl_created_if) :
                    new_segt_link = { 'lcl_dut' : lcl_dut,
                                      'rmt_dut' : rmt_dut,
                                      'type': if_type,
                                      'lcl_link': lcl_created_if[if_idx],
                                      'rmt_link' : rmt_created_if[if_idx] }

                    new_segt_data[new_link_idx] = copy.deepcopy(new_segt_link)
                    st.log("Topology - Adding new link at index {}->{}".format(new_link_idx, new_segt_link))
                    new_link_idx += 1
                    if_idx += 1

        TOPOLOGY.show_topo_segment(new_segt_data)
        st.log("Topology - Create overlay segment all intf types Success")
        return True, 'Success', copy.deepcopy(new_segt_data)


    @staticmethod
    def create_broadcast_overlay_topology(dut_topology, params={}):

        st.log("Topology - Create Broadcast domain topology with params {}".format(params))
        TOPOLOGY.show_topo_path(dut_topology)

        #result, resstr = True, 'Success'
        new_topology = {}
        new_topology['found'] = False

        result, resstr = TOPOLOGY.test_topo_present(dut_topology, dut_count=2, segment_count=1)
        if not result:
            st.log("{}".format(resstr))
            return False, resstr, new_topology

        #overlay_type = 'broadcast_overlay'
        if 'overlay_type' in params.keys() :
            if params['overlay_type'] != 'broadcast_overlay' :
                resstr = "Topology - Invalid overlay type {} param".format(params['overlay_type'])
                st.log("{}".format(resstr))
                return False, resstr, {}

        max_peer_links = 4
        if 'max_peer_links' in params.keys():
            max_peer_links = params['max_peer_links']

        topo_segts = dut_topology['segment']
        dut_list = dut_topology['dut_list']

        new_topology['found'] = True
        new_topology['dut_list'] = copy.deepcopy(dut_list)
        new_topology['segment'] = {}
        new_topology['segment_count'] = 0
        new_topology['type'] = 'Broacast'

        new_topology['base_segment'] = {}
        new_topology['base_segment_count'] = 0

        result, resstr, vlan_list = TOPOLOGY.get_free_vlans_in_dut_list(new_topology['dut_list'], 1)
        if not result :
           st.log("{}".format(resstr))
           return False, resstr, {}

        for segt_idx, segt_data in topo_segts.items():
            result, resstr, lmtd_segt = TOPOLOGY.limit_segment_links(segt_data, max_peer_links)

            new_topology['base_segment'][segt_idx] = copy.deepcopy(lmtd_segt)
            new_topology['base_segment_count'] += 1

            st.log("Topology - Segment index {} for BD".format(segt_idx))
            segt_ovl_params = { 'if_type' : 'BCD', 'vlan_list': vlan_list, 'if_count': 1 }
            result, resstr, new_segment = TOPOLOGY.create_overlay_segment(lmtd_segt, params=segt_ovl_params)

            new_topology['segment'][segt_idx] = copy.deepcopy(new_segment)
            new_topology['segment_count'] += 1

        st.log("Topology - topology after converting to vlan segt domain")
        TOPOLOGY.show_topo_path(new_topology)

        st.log("Topology - find from dut in vlan topology")

        from_dut = ''
        for segt_idx, segt_data in new_topology['segment'].items():
            for _, link_data in segt_data.items():
                from_dut = link_data['lcl_dut']
                from_link_data = copy.deepcopy(link_data)
                break
            if from_dut != '' :
                break

        if from_dut == '' :
            resstr = "Topology - BD topology from dut not found"
            st.log("{}".format(resstr))
            return False, resstr, {}

        st.log("Topology - generate BD topology star segment")
        bd_segt_data = {}
        bd_link_idx = 0
        to_dut_list = []
        for segt_idx, segt_data in new_topology['segment'].items():
            st.log("Topology - Vlan segment index for BD {} ".format(segt_idx))
            for _, link_data in segt_data.items():
                lcl_dut = link_data['lcl_dut']
                rmt_dut = link_data['rmt_dut']

                if rmt_dut not in to_dut_list :
                    bd_link_data = {
                                     'lcl_dut' : from_link_data['lcl_dut'],
                                     'rmt_dut' : link_data['rmt_dut'],
                                     'type'    : from_link_data['type'],
                                     'lcl_link': from_link_data['lcl_link'],
                                     'rmt_link': link_data['rmt_link']
                                   }

                    st.log("Topology - Adding BD linkdata {}:{}".format(bd_link_idx, bd_link_data))
                    bd_segt_data[bd_link_idx] = copy.deepcopy(bd_link_data)
                    bd_link_idx += 1
                    to_dut_list.append(rmt_dut)

                if lcl_dut != from_dut and lcl_dut not in to_dut_list :
                    bd_link_data = {
                                     'lcl_dut' : from_link_data['lcl_dut'],
                                     'rmt_dut' : link_data['lcl_dut'],
                                     'type'    : from_link_data['type'],
                                     'lcl_link': from_link_data['lcl_link'],
                                     'rmt_link': link_data['lcl_link']
                                   }

                    st.log("Topology - Adding BD linkdata {}:{}".format(bd_link_idx, bd_link_data))
                    bd_segt_data[bd_link_idx] = copy.deepcopy(bd_link_data)
                    bd_link_idx += 1
                    to_dut_list.append(lcl_dut)

        st.log("Topology - BD Segment data")
        TOPOLOGY.show_topo_segment(bd_segt_data)

        if len(bd_segt_data) == 0 :
            resstr = "Topology - BD topology couldnot be found"
            st.log("{}".format(resstr))
            return False, resstr, {}

        new_topology['parent_segment'] = new_topology['segment']
        new_topology['parent_segment_count'] = new_topology['segment_count']
        new_topology['segment'] = { 0 : copy.deepcopy(bd_segt_data) }
        new_topology['segment_count'] = 1
        new_topology['found'] = True

        #st.log("Topology - Modified testbed nw topo after creating broadcast domain")
        #TOPOLOGY.show_dut_topo_data()

        st.log("Topology - New topology after creating broadcast domain")
        TOPOLOGY.show_topo_path(new_topology)

        #import pdb; pdb.set_trace()
        result_str = "Success" if result else "Failed"
        st.log("Topology - Create Broadcast domain topology {}".format(result_str))
        return True, 'Success', new_topology


    @staticmethod
    def create_overlay_topology(dut_topology, params={}):

        st.log("Topology - Create overlay topology with params {}".format(params))
        #TOPOLOGY.show_dut_topo_data()
        TOPOLOGY.show_topo_path(dut_topology)

        #result, resstr = True, 'Success'
        new_topology = {}
        new_topology['found'] = False

        result, resstr = TOPOLOGY.test_topo_present(dut_topology, dut_count=2, segment_count=1)
        if not result:
            st.log("{}".format(resstr))
            return False, resstr, new_topology

        overlay_type = 'per_segt_overlay'
        if 'overlay_type' in params.keys() :
            if params['overlay_type'] != '' :
                overlay_type = params['overlay_type']

        if overlay_type not in ['per_segt_overlay', 'per_link_overlay', 'broadcast_overlay'] :
            resstr = "Topology - Invalid overlay type {}".format(overlay_type)
            st.log("{}".format(resstr))
            return False, resstr, new_topology

        if overlay_type == 'broadcast_overlay' :
            return TOPOLOGY.create_broadcast_overlay_topology(dut_topology, params)

        max_peer_links = 4
        if 'max_peer_links' in params.keys():
            max_peer_links = params['max_peer_links']

        segt_type_list = {}
        segt_link_count_list = {}
        if 'segt_type_list' in params.keys():
            segt_type_list = params['segt_type_list']
        if 'segt_link_count_list' in params.keys():
            segt_link_count_list = params['segt_link_count_list']

        topo_segts = dut_topology['segment']
        dut_list = dut_topology['dut_list']

        new_topology['found'] = True
        new_topology['dut_list'] = copy.deepcopy(dut_list)
        new_topology['segment'] = {}
        new_topology['segment_count'] = 0
        new_topology['type'] = dut_topology['type']

        for segt_idx, segt_data in topo_segts.items():
            st.log("Topology - Segment to overlay segtindex {}".format(segt_idx))
            TOPOLOGY.show_topo_segment(segt_data)
            #import pdb; pdb.set_trace()

            #if_type = 'None'
            #new_segment = segt_data
            result, resstr, new_segment = TOPOLOGY.limit_segment_links(segt_data, max_peer_links)

            if segt_idx not in segt_link_count_list.keys():
                result, resstr, new_segment = TOPOLOGY.limit_segment_links(segt_data, max_peer_links)
                if not result :
                    resstr += "Topology - Limit segment links for segment {} Failed".format(segt_idx)
                    st.log("{}".format(resstr))
                    return False, resstr, {}

            if overlay_type == 'per_segt_overlay' :
                st.log("Topology - Persegt Overlay")
                if segt_idx in segt_type_list.keys():
                    if_type = segt_type_list[segt_idx]
                    st.log("Topology - Overlay to be done {}".format(if_type))
                    if if_type in ['PCH', 'VLN'] :
                        overlay_if_count = 1
                        if if_type == 'VLN' :
                            if segt_idx in segt_link_count_list.keys():
                                overlay_if_count = segt_link_count_list[segt_idx]

                        segt_ovl_params = { 'if_type' : if_type, 'if_count': overlay_if_count }
                        result, resstr, new_segment = TOPOLOGY.create_overlay_segment(new_segment, params=segt_ovl_params)
                        if not result :
                            resstr += "Topology - Overlay segment create Failed for type {}".format(if_type)
                            st.log("{}".format(resstr))
                            return False, resstr, {}

            elif overlay_type == 'per_link_overlay' :
                    st.log("Topology - Perlink overlay")
                    result, resstr, new_segment = TOPOLOGY.create_overlay_segment_all_if_types(new_segment)
                    if not result :
                        resstr += "Topology - Perlink Overlay segment create Failed"
                        st.log("{}".format(resstr))
                        return False, resstr, {}

            new_topology['segment'][segt_idx] = copy.deepcopy(new_segment)
            new_topology['segment_count'] += 1

        st.log("Topology - Modified testbed nw topo after overlay")
        TOPOLOGY.show_dut_topo_data()

        st.log("Topology - New topology after overlay")
        TOPOLOGY.show_topo_path(new_topology)

        result_str = "Success" if result else "Failed"
        st.log("Topology - Create overlay topology {}".format(result_str))
        return True, 'Success', new_topology


    @staticmethod
    def bind_vrf_to_segment(segt_data, lcl_vrf, rmt_vrf, link_name=''):

        st.log("Topology - Bind vrf to segement {} {}".format(lcl_vrf, rmt_vrf))

        #result, resstr = True, 'Success'

        for _, link_data in segt_data.items():

            lcl_dut = link_data['lcl_dut']
            rmt_dut = link_data['rmt_dut']

            lcl_link = link_data['lcl_link']
            rmt_link = link_data['rmt_link']

            if link_name != '' and link_name != lcl_link :
                continue

            result, resstr = TOPOLOGY.add_del_link_vrf(lcl_dut, lcl_link, lcl_vrf, add='yes')
            if not result :
                resstr += "Topology - Local dut {} link {} bind vrf {} Failed".format(lcl_dut, lcl_link, lcl_vrf)
                st.log("{}".format(resstr))
                return False, resstr

            result, resstr = TOPOLOGY.add_del_link_vrf(rmt_dut, rmt_link, rmt_vrf, add='yes')
            if not result :
                resstr += "Topology - Remote dut {} link {} bind vrf {} Failed".format(rmt_dut, rmt_link, rmt_vrf)
                st.log("{}".format(resstr))
                return False, resstr

            link_data['lcl_vrf'] = lcl_vrf
            link_data['rmt_vrf'] = rmt_vrf

            TOPOLOGY.add_del_dut_vrf(lcl_dut, lcl_vrf, add='yes')
            TOPOLOGY.add_del_dut_vrf(rmt_dut, rmt_vrf, add='yes')

        st.log("Topology - Bind vrf {} {} to segement Success".format(lcl_vrf, rmt_vrf))
        return True, 'Success'


    @staticmethod
    def bind_vrf_to_topology(dut_topology, vrf_list={}):

        st.log("Topology - Bind vrf to topology segements {}".format(vrf_list))
        TOPOLOGY.show_topo_path(dut_topology)

        #result, resstr = True, 'Success'

        result, resstr = TOPOLOGY.test_topo_present(dut_topology, dut_count=2, segment_count=1)
        if not result :
            st.log("Topology  - topology path not found")
            return False, resstr

        topo_segts = dut_topology['segment']

        for segt_idx, segt_data in topo_segts.items():

            lcl_vrf = 'default'
            rmt_vrf = 'default'

            if vrf_list and segt_idx in vrf_list.keys() :
                if len(vrf_list[segt_idx]) :
                    lcl_vrf = vrf_list[segt_idx][0]
                if len(vrf_list[segt_idx]) >= 2 :
                    rmt_vrf = vrf_list[segt_idx][1]

            result, resstr = TOPOLOGY.bind_vrf_to_segment(segt_data, lcl_vrf, rmt_vrf)
            if not result :
                st.log("Topology - Bind vrf to segment Failed")
                return False, resstr

        TOPOLOGY.generate_topology_vrf_list(dut_topology)

        st.log("Topology - vrf bound topology")
        TOPOLOGY.show_topo_path(dut_topology)

        result_str = "Success" if result else "Failed"
        st.log("Topology - Bind vrf to topology segements {}".format(result_str))

        return True, 'Success'


    @staticmethod
    def bind_per_interface_vrf_to_topology(dut_topology, vrf_prefix=''):

        st.log("Topology - Bind perinterface vrf to topology segements {}".format(vrf_prefix))
        TOPOLOGY.show_topo_path(dut_topology)

        #result, resstr = True, 'Success'

        result, resstr = TOPOLOGY.test_topo_present(dut_topology, dut_count=2, segment_count=1)
        if not result :
            st.log("Topology  - topology path not found")
            return False, resstr

        topo_segts = dut_topology['segment']

        for _, segt_data in topo_segts.items():
            vrf_count = 0
            segt_links = TOPOLOGY.get_topology_segment_links(segt_data)
            for link_name in segt_links :
                vrf_count += 1
                lcl_vrf = "Vrf-{}".format(vrf_count)
                rmt_vrf = "Vrf-{}".format(vrf_count)
                result, resstr = TOPOLOGY.bind_vrf_to_segment(segt_data, lcl_vrf, rmt_vrf, link_name)
                if not result :
                    st.log("Topology - Bind vrf to segment Failed")
                    return False, resstr

        TOPOLOGY.generate_topology_vrf_list(dut_topology)

        st.log("Topology - vrf bound topology")
        TOPOLOGY.show_topo_path(dut_topology)

        result_str = "Success" if result else "Failed"
        st.log("Topology - Bind perinterface vrf vrf to topology segements {}".format(result_str))

        return True, 'Success'


    @staticmethod
    def generate_topology_vrf_list(dut_topology):

        st.log("Topology - Add vrf list to topology")
        TOPOLOGY.show_topo_path(dut_topology)

        result, resstr = TOPOLOGY.test_topo_present(dut_topology, dut_count=2, segment_count=1)
        if not result :
            st.log("Topology  - topology path not found")
            return False, resstr

        topo_segts = dut_topology['segment']
        dut_vrf_list = {}

        for _, segt_data in topo_segts.items():
            for _, link_data in segt_data.items():

                 lcl_dut = link_data['lcl_dut']
                 lcl_vrf = link_data['lcl_vrf']

                 TOPOLOGY.add_del_dut_vrf(lcl_dut, lcl_vrf, add='yes')

                 if lcl_dut not in dut_vrf_list.keys():
                      dut_vrf_list[lcl_dut] = [lcl_vrf]
                 else :
                      if lcl_vrf not in dut_vrf_list[lcl_dut] :
                          dut_vrf_list[lcl_dut].append(lcl_vrf)

                 if 'rmt_dut' in link_data.keys() :
                    rmt_dut = link_data['rmt_dut']
                    rmt_vrf = link_data['rmt_vrf']

                    TOPOLOGY.add_del_dut_vrf(rmt_dut, rmt_vrf, add='yes')

                    if rmt_dut not in dut_vrf_list.keys():
                        dut_vrf_list[rmt_dut] = [rmt_vrf]
                    else :
                        if rmt_vrf not in dut_vrf_list[rmt_dut] :
                            dut_vrf_list[rmt_dut].append(lcl_vrf)

        st.log("Topology - dut vrf list {} ".format(dut_vrf_list))
        dut_topology['vrf_list'] = copy.deepcopy(dut_vrf_list)

        st.log("Topology - Add vrf list to topology Success")
        return True, 'Success'


    @staticmethod
    def bind_ip_address_to_segment(segt_data, addr_list, addr_idx, nw_mask, addr_family, single_subnet='no'):

        st.log("Topology - Bind ip address {} to segement".format(addr_idx))

        #result, resstr = True, 'Success'
        link_number = 0
        ip_add_count = 0

        if not isinstance(addr_list, list):
            resstr = "Topology - IP address list invalid {}".format(addr_list)
            st.log("{}".format(resstr))
            return 0, resstr

        if addr_idx < 0 or addr_idx > (len(addr_list) - 1) :
            resstr = "Topology - IP address list invalid index {} {}".format(addr_idx, addr_list)
            st.log("{}".format(resstr))
            return 0, resstr

        for _, link_data in segt_data.items():

            rmt_dut = link_data['rmt_dut']
            lcl_dut = link_data['lcl_dut']

            lcl_link = link_data['lcl_link']
            rmt_link = link_data['rmt_link']

            if TOPOLOGY.dut_link_has_sub_ifs(lcl_dut, lcl_link) :
                continue

            connect_links = True
            lcl_ip_present = TOPOLOGY.dut_ip_link_present(lcl_dut, lcl_link, addr_family)
            rmt_ip_present = TOPOLOGY.dut_ip_link_present(rmt_dut, rmt_link, addr_family)

            if single_subnet == 'no' :
                if lcl_ip_present :
                    resstr = "Topology - Duplicate IP add request to {} {}".format(lcl_dut, lcl_link)
                    st.log("{}".format(resstr))
                    return 0, resstr
                if rmt_ip_present :
                    resstr = "Topology - Duplicate IP add request to {} {}".format(rmt_dut, rmt_link)
                    st.log("{}".format(resstr))
                    return 0, resstr

            if addr_family == 'ipv4' :

                if single_subnet == 'yes' :
                    if not addr_list[addr_idx] :
                        resstr = "Topology - Not enough IP addressess in address list {} {}".format(addr_idx, addr_list)
                        st.log("{}".format(resstr))
                        return ip_add_count, resstr

                    if not addr_list[addr_idx + 1] :
                        resstr = "Topology - Not enough IP addressess in address list {} {}".format(addr_idx+1, addr_list)
                        st.log("{}".format(resstr))
                        return ip_add_count, resstr

                    lcl_addr_octet = copy.deepcopy(addr_list[addr_idx])
                    addr_idx += 1
                    rmt_addr_octet = copy.deepcopy(addr_list[addr_idx])
                    addr_idx += 1
                    ip_add_count +=2

                else :
                    if not addr_list[addr_idx] :
                        resstr = "Topology - Not enough IP Networks in address list {} {}".format(addr_idx, addr_list)
                        st.log("{}".format(resstr))
                        return ip_add_count, resstr

                    link_ip_addr_list = TOPOLOGY.get_ip_subnet_address_list(addr_list[addr_idx], nw_mask, addr_family, 4)
                    addr_idx += 1

                    lcl_addr_octet = copy.deepcopy(link_ip_addr_list[1])
                    rmt_addr_octet = copy.deepcopy(link_ip_addr_list[2])
                    link_number += 1

                lcl_ip = "{}.{}.{}.{}".format(lcl_addr_octet[0], lcl_addr_octet[1],
                                              lcl_addr_octet[2], lcl_addr_octet[3])

                rmt_ip = "{}.{}.{}.{}".format(rmt_addr_octet[0], rmt_addr_octet[1],
                                              rmt_addr_octet[2], rmt_addr_octet[3])

                if not lcl_ip_present :
                    result, resstr = TOPOLOGY.add_del_link_ip(lcl_dut, lcl_link, lcl_ip, nw_mask, rmt_ip, addr_family, add='yes')
                    if not result :
                        resstr += "Topology - {} Local Link {} {} ip add Failed".format(lcl_dut, lcl_link, lcl_ip)
                        st.log("{}".format(resstr))
                        return 0, resstr
                else :
                    lcl_ip = TOPOLOGY.dut_get_link_local_ip(lcl_dut, lcl_link, addr_family)
                    lcl_addr_octet = [int(item) for item in lcl_ip.split('.')]
                    connect_links = False

                result = TOPOLOGY.add_del_link_address_octate(lcl_link, lcl_addr_octet, add='yes')

                if not rmt_ip_present :
                    result, resstr = TOPOLOGY.add_del_link_ip(rmt_dut, rmt_link, rmt_ip, nw_mask, lcl_ip, addr_family, add='yes')
                    if not result :
                        resstr += "Topology - {} Remote Link {} {} ip add Failed".format(rmt_dut, rmt_link, rmt_ip)
                        st.log("{}".format(resstr))
                        return 0, resstr
                else :
                    rmt_ip = TOPOLOGY.dut_get_link_local_ip(rmt_dut, rmt_link, addr_family)
                    rmt_addr_octet = [int(item) for item in rmt_ip.split('.')]
                    connect_links = False

                result = TOPOLOGY.add_del_link_address_octate(lcl_link, rmt_addr_octet, add='yes')

                if connect_links :
                    result = TOPOLOGY.connect_ip_links(lcl_dut, lcl_link, rmt_dut, rmt_link, addr_family, add='yes')
                    if not result :
                        resstr = "Topology - {} link {} {}  {} {} connect Failed".format(
                                          addr_family, lcl_dut, lcl_link, rmt_dut, rmt_link)
                        st.log("{}".format(resstr))
                        return 0, resstr

                link_data['lcl_ipv4'] = lcl_ip
                link_data['rmt_ipv4'] = rmt_ip
                link_data['ipv4_mask'] = nw_mask


        if single_subnet != 'yes' :
            ip_add_count = link_number

        if ip_add_count == 0 :
            resstr = "Topology - Bind ip address to segement Failed no valid ifs"
            st.log("{}".format(resstr))
            return ip_add_count, resstr

        st.log("Topology - Bind ip address to segement {} links Success".format(ip_add_count))
        return ip_add_count, 'Success'


    @staticmethod
    def bind_ip_address_to_topology(dut_topology, nw_oct_list, nw_mask, addr_family='ipv4', single_subnet='no'):

        st.log("Topology - Bind ip address {} to topology".format(nw_oct_list))
        TOPOLOGY.show_topo_path(dut_topology)

        result, resstr = TOPOLOGY.test_topo_present(dut_topology, dut_count=2, segment_count=1)
        if not result :
            st.log("Topology  - topology path not found")
            return False, resstr

        topo_segts = dut_topology['segment']

        ip_addr_count =  0
        address_index = 1
        #link_count = 0
        total_links = TOPOLOGY.get_topology_total_link_count(dut_topology)

        if single_subnet == 'yes' :
            address_list = TOPOLOGY.get_ip_subnet_address_list(nw_oct_list, nw_mask, addr_family, total_links * 2)
        else :
            network_list = TOPOLOGY.get_ip_network_list(nw_oct_list, nw_mask, addr_family, total_links * 2)

        for segt_idx, segt_data in topo_segts.items():

            st.log("Topology - Segment {} {}".format(segt_idx, segt_data))

            if single_subnet == 'yes' :
                ip_addr_count, resstr = TOPOLOGY.bind_ip_address_to_segment(segt_data, address_list, address_index,
                                                                    nw_mask, addr_family, single_subnet)
            else :
                #curr_nw_oct_list = copy.deepcopy(network_list[address_index])
                ip_addr_count, resstr = TOPOLOGY.bind_ip_address_to_segment(segt_data, network_list, address_index,
                                                                    nw_mask, addr_family, single_subnet)

            if ip_addr_count == 0 :
                st.log("Topology - Bind ip address to segment Failed")
            else :
                address_index += ip_addr_count

            st.log("Topology - Segment after ip bind {} {}".format(segt_idx, segt_data))

        if 'ip_octet' not in dut_topology.keys() :
            dut_topology['ip_octet'] = [ nw_oct_list ]
        else :
            dut_topology['ip_octet'].append(nw_oct_list)

        #TOPOLOGY.connect_all_ip_links()

        st.log("Topology - topology after ip bind")
        TOPOLOGY.show_topo_path(dut_topology)
        st.log("Topology - Bind ip address to topology Success")
        return True, 'Success'


    @staticmethod
    def add_loopback_to_topo_dut(dut_topology, dut, vrf, lbk_number,
                                 nw_oct_list, addr_family='ipv4'):

        st.log("Topology - Add topology dut loopback interfaces ")

        link_name = "{}L{}".format(dut, lbk_number)
        intf_name = "Loopback{}".format(lbk_number)
        st.log("Topology - {} {} {} {}".format(dut, vrf, link_name, intf_name))

        result = TOPOLOGY.dut_link_present(dut, link_name)
        if not result :
            result, resstr = TOPOLOGY.add_del_link(dut, 'LBK', link_name, intf_name, vrf=vrf, add='yes')
            if not result:
                resstr += "Topology - {} {} loopback interface add FAILED".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

        if addr_family == 'ipv4' :
            nw_mask = 32
            lbk_ip = "{}.{}.{}.{}".format(nw_oct_list[0], nw_oct_list[1], nw_oct_list[2], nw_oct_list[3])

        if addr_family == 'ipv6' :
            nw_mask = 128
            lbk_ip = "{}:{}:{}::{}".format(nw_oct_list[0], nw_oct_list[1], nw_oct_list[2], nw_oct_list[3])

        result = TOPOLOGY.dut_link_has_ip(dut, link_name, addr_family)
        if not result :
            result, resstr = TOPOLOGY.add_del_link_ip(dut, link_name, lbk_ip, nw_mask, "", addr_family, add='yes')
            if not result:
                resstr += "Topology - {} {} loopback interface ipv4 add  FAILED".format(dut, link_name)
                st.log("{}".format(resstr))
                return False, resstr

            TOPOLOGY.add_del_link_address_octate(link_name, nw_oct_list, add='yes')

        st.log("Topology - Add topology dut loopback interface and ip Success")
        return True, 'Success'


    @staticmethod
    def add_loopbacks_to_topology(dut_topology, nw_oct_list, nw_mask=24, addr_family='ipv4'):

        st.log("Topology - Add loopback interfaces {} to topology".format(nw_oct_list))
        TOPOLOGY.show_topo_path(dut_topology)

        result, resstr = TOPOLOGY.test_topo_present(dut_topology, dut_count=2, segment_count=1)
        if not result :
            st.log("Topology  - topology path not found")
            return False, resstr

        result, resstr = TOPOLOGY.generate_topology_vrf_list(dut_topology)
        if not result :
            resstr += "Topology - Adding vrf list to topopoly Failed"
            st.log("{}".format(resstr))
            return False, resstr

        #topo_segts = dut_topology['segment']
        dut_vrf_list = copy.deepcopy(dut_topology['vrf_list'])
        dut_list = copy.deepcopy(dut_vrf_list.keys())
        dut_list.sort()

        lbk_ip_count = 0
        dut_lbk_count = 0

        lpbk_addr_list = TOPOLOGY.get_ip_subnet_address_list(nw_oct_list, nw_mask, addr_family='ipv4')

        for dut in dut_list:
            vrf = 'default'

            vrf_lbks = TOPOLOGY.dut_get_vrf_loopbacks(dut, vrf)
            if len(vrf_lbks) :
                  continue

            dut_lbk_count = 0
            lbk_ip_count += 1
            addr_oct_list = copy.deepcopy(lpbk_addr_list[lbk_ip_count])

            result, resstr = TOPOLOGY.add_loopback_to_topo_dut(dut_topology, dut, vrf, dut_lbk_count,
                                                               addr_oct_list, addr_family)
            if not result:
                resstr += "Topology - default loopback add to topo dut {} FAILED".format(dut)
                st.log("{}".format(resstr))
                return False, resstr

        for dut, vrf_list in dut_vrf_list.items():

            dut_lbk_count = 0

            for vrf in vrf_list :

                if vrf == 'default' :
                    continue

                vrf_lbks = TOPOLOGY.dut_get_vrf_loopbacks(dut, vrf)
                if len(vrf_lbks) :
                    continue

                dut_lbk_count += 1
                lbk_ip_count += 1

                addr_oct_list = copy.deepcopy(lpbk_addr_list[lbk_ip_count])

                result, resstr = TOPOLOGY.add_loopback_to_topo_dut(dut_topology, dut, vrf, dut_lbk_count,
                                                                   addr_oct_list, addr_family)
                if not result:
                    resstr = "Topology - loopback add to topo dut {} vrf {} ".format(dut, vrf)
                    st.log("{}".format(resstr))
                    return False, resstr

        TOPOLOGY.show_topo_path(dut_topology)
        st.log("Topology - Add loopback interfaces Success")
        return True, 'Success'


    #-------------------------------------------------------------------------
    # Utility functions

    @staticmethod
    def get_threaded_result(out, exceptions, prefixstr=''):
        result, resstr = True, 'Success'

        prefixstr = 'TOPOLOGY - ' if prefixstr == '' else prefixstr
        #st.log("{} Threaded result {} {}".format(prefixstr, out, exceptions))

        index = 0
        for res, err in out :
            if res is False :
               if result :
                   resstr = "{}".format(err)
                   result = False
               else :
                   resstr += " - {}".format(err)

               st.log("{} thread {} Failed with result:{} errstr:{} except Exception:{}".format(
                                        prefixstr, index, res, err, exceptions[index]))
            index += 1

        return result, resstr

    @staticmethod
    def test_topo_present(topo_path=None, dut_count=None, segment_count=None):

        if dut_count :
            if TOPOLOGY.get_dut_count() < dut_count :
                TOPOLOGY.show_dut_topo_data()
                resstr = "Needed minimum {} duts in testbed topology".format(dut_count)
                st.log("{}".format(resstr))
                return False, resstr

        if not topo_path :
            resstr = "Empty(null) Topology path"
            st.log("{}".format(resstr))
            return False, resstr

        if 'found' not in topo_path.keys() :
            resstr = "Invalid topology, found key not present"
            st.log("{}".format(resstr))
            return False, resstr

        if not topo_path['found'] :
            resstr = "Topolgy path not found"
            st.log("{}".format(resstr))
            return False, resstr

        if len(topo_path['dut_list']) < dut_count:
            TOPOLOGY.show_topo_path(topo_path)
            resstr = "Needed minimum {} duts in topology".format(dut_count)
            st.log("{}".format(resstr))
            return False, resstr

        if segment_count :
            if topo_path['segment_count'] < segment_count :
                TOPOLOGY.show_topo_path(topo_path)
                resstr = "Needed minimum {} segments in Topology".format(segment_count)
                st.log("{}".format(resstr))
                return False, resstr

        return True, 'Success'


    @staticmethod
    def show_dut_topo_data(dut_list = []):

        if not dut_list :
            dut_list = TOPOLOGY.get_dut_list()
            dut_list += TOPOLOGY.get_tg_list()

            st.log("\n")
            st.log("Topology - Dut List: {}".format(nw_topo['dut_list']))
            st.log("Topology - Dut Dev Map: {}".format(nw_topo['dut_map']))
            st.log("Topology - TG List: {}".format(nw_topo['tg_list']))
            st.log("Topology - TG Dev Map: {}".format(nw_topo['tg_map']))

        for dut in dut_list:
            if not TOPOLOGY.dut_present(dut) :
               continue

            st.log("\n")
            st.log("Topology - Dut {} {} {}".format(dut, nw_topo[dut]['type'], nw_topo[dut]['device']))

            for vrf, vrf_data  in nw_topo[dut]['vrf'].items():
                st.log("           Vrf {} {}".format(vrf, vrf_data))
            for intf, intf_data in nw_topo[dut]['intf'].items():
                st.log("           Intf {} {}".format(intf, intf_data))

            for link, link_data in nw_topo[dut]['ipv4']['link'].items():
                st.log("           Ipv4 Link {} {}".format(link, link_data))
            for link, link_data in nw_topo[dut]['ipv6']['link'].items():
                st.log("           Ipv6 Link {} {}".format(link, link_data))

            for stnw, stnw_data in nw_topo[dut]['ipv4']['static_nw'].items():
                st.log("           Static Ipv4 Nw {} {}".format(stnw, stnw_data))
            for stnw, stnw_data in nw_topo[dut]['ipv6']['static_nw'].items():
                st.log("           Static IPv6 Nw {} {}".format(stnw, stnw_data))

            for strt, strt_data in nw_topo[dut]['ipv4']['static_rt'].items():
                st.log("           Static Ipv4 Route {} {}".format(strt, strt_data))
            for strt, strt_data in nw_topo[dut]['ipv6']['static_rt'].items():
                st.log("           Static IPv6 Route {} {}".format(strt, strt_data))

            st.log("           Ipv4 Network Octates {}".format(nw_topo[dut]['ipv4']['nwoctet']))
            st.log("           IPv6 Network Octates {}".format(nw_topo[dut]['ipv6']['nwoctet']))

        st.log("\n")


    @staticmethod
    def show_topo_segment(segt_data, idx=''):
        if idx != '' :
            st.log("     Segment-{}: ".format(idx))
        for link_idx, link_data in segt_data.items():
            st.log("       Link-{}: {}".format(link_idx, link_data))

    @staticmethod
    def show_topo_path(path):

        if not path :
            st.log("Topology - Path Null")
            return

        if 'type' not in path.keys():
            st.log("Topology - Path Type Not found")
            return

        if 'found' not in path.keys():
            st.log("Topology - Path Invalid")
            return

        path_found = "Found" if path['found'] else "Not Found"

        st.log("Topology - {} Topo Path {}".format(path['type'], path_found))
        if not path['found'] : return

        if 'topology_name' in path.keys():
            st.log("     Name : {}".format(path['topology_name']))
        else :
            st.log("     Name : not assigned")

        st.log("     Dut List: {}".format(path['dut_list']))
        if 'vrf_list' in path.keys():
            st.log("     Dut vrf List {}".format(path['vrf_list']))

        st.log("     Segt Count: {}".format(path['segment_count']))
        for segt_idx, segt_data in path['segment'].items():
            st.log("     Segment-{}: ".format(segt_idx))
            for link_idx, link_data in segt_data.items():
                 st.log("       Link-{}: {}".format(link_idx, link_data))

        if 'loopbacks' in path.keys():
            st.log("     Loopbacks")
            for dut, lbk_list in path['loopbacks'].items() :
                st.log("     Dut-{}:".format(dut))
                for _, lbk_data in lbk_list.items():
                    st.log("        {}: {}".format(lbk_data['lcl_if'], lbk_data))

        st.log("\n")


    @staticmethod
    def banner_log(msg, width=80, delimiter="#" ,wrap=True):
        import textwrap
        if wrap:
            output = ["{0} {1} {0}".format(delimiter,each.center(width-4)) for each in textwrap.wrap(msg, width=width-4)]
        else:
            output = ["{0} {1:{2}} {0}".format(delimiter,each,(width-4)) for each in textwrap.wrap(msg, width=width-4)]
        msg_full = "\n"+"{}".format(delimiter)*width+"\n"+"{}".format('\n'.join(output))+'\n'+"{}".format(delimiter)*width+"\n"
        for each_line in msg_full.split("\n"):
            st.log(each_line)


    @staticmethod
    def get_ip_network(ip_addr, subnet, addr_family='ipv4'):

        if not TOPOLOGY.addr_family_valid(addr_family) :
            st.log("Topology - Invalid address family {}".format(addr_family))
            return ''

        oct_mask = int('0x0ff', 16)
        subnet = int(subnet)

        if addr_family == 'ipv4' :

            if subnet > 32  :
                st.log("Topology - Invalid ipv4 subnet mask {}".format(subnet))
                return ''

            host_bits =  32 - subnet

            ip_octet = [int(item) for item in ip_addr.split('.')]
            if len(ip_octet) < 4 :
                st.log("Topology - Invalid ipv4 address {}".format(ip_addr))
                return ''

            ip_num = ip_octet[3] | ip_octet[2] << 8 | ip_octet[1] << 16 | ip_octet[0] << 24
            nw_num = (ip_num >> host_bits) << host_bits

            nw_octet = {}
            nw_octet[0] = nw_num & oct_mask
            nw_octet[1] = (nw_num >> 8) & oct_mask
            nw_octet[2] = (nw_num >> 16) & oct_mask
            nw_octet[3] = (nw_num >> 24) & oct_mask

            nw_addr = "{}.{}.{}.{}".format(nw_octet[3], nw_octet[2], nw_octet[1], nw_octet[0])
            #st.log("Topology - Ipv4 address {}/{} network is {}".format(ip_addr, subnet, nw_addr))
            return nw_addr

        else :
            st.log("Topology - ipv6 ip to nw prefix not supported yet")
            return ''


    @staticmethod
    def get_ip_network_prefix(ip_addr, subnet, addr_family='ipv4'):

        nw_prefix = ''
        ip_nw = TOPOLOGY.get_ip_network(ip_addr, subnet, addr_family)
        if ip_nw != '' :
            nw_prefix = "{}/{}".format(ip_nw, subnet)
            #st.log("Topology - {} {}/{} network prefix is {}".format(addr_family, ip_addr, subnet, nw_prefix))
        return nw_prefix


    @staticmethod
    def get_ip_subnet_address_list(subnet_octet=[], subnet_mask=0, addr_family='ipv4', addr_count=4096):

        st.log("Topology - Get subnet addresses of {}/{}".format(subnet_octet, subnet_mask))

        if len(subnet_octet) != 4 :
           st.log("Topology - Invalid subnet_octet {}".format(subnet_octet))
           return []

        address_size = 64 if addr_family == 'ipv6' else 32
        oct_count = address_size - 8
        oct_mask = int('0x0ff', 16)

        if address_size == 32 and len(subnet_octet) != 4 :
           st.log("Topology - Invalid ipv4 subnet_octet {}".format(subnet_octet))
           return []

        if address_size == 64 :
           if len(subnet_octet) < 4 :
               st.log("Topology - Invalid ipv6 subnet_octet {}".format(subnet_octet))
               return []

        subnet_num = 0
        for nw_byte in subnet_octet :
            if nw_byte < 0 or nw_byte > int('0xff', 16) :
                st.log("Topology - Invalid octet {} in subnet {}".format(nw_byte, subnet_octet))
                return []

            subnet_num = subnet_num + ( int(nw_byte) << oct_count)
            oct_count = oct_count - 8

        subnet_mask = int(subnet_mask)
        if subnet_mask < 1 or subnet_mask >= address_size :
           st.log("Topology - Invalid Subnet mask {}".format(subnet_mask))
           return []

        host_bits = address_size  - subnet_mask
        start_ip_addr = (subnet_num >> host_bits) << (host_bits)
        end_ip_addr = start_ip_addr | ((1 << host_bits) - 1)

        #st.log("Topology - Subnet start IP {} end IP {} ".format(start_ip_addr, end_ip_addr))
        host_count = ((1 << host_bits) - 1) - 2

        if addr_count > host_count :
            addr_count = host_count

        if (end_ip_addr - start_ip_addr) > (addr_count + 2) :
            end_ip_addr = start_ip_addr + addr_count + 2

        address_list = []
        ip_idx = 0

        for ip in range (start_ip_addr, end_ip_addr + 1) :
            ip_oct_list = [0, 0, 0, 0]
            oct_count = address_size - 8
            byte_count = 0
            while oct_count >= 0 :
                ip_oct_list[byte_count] = (ip >> oct_count) & oct_mask
                oct_count -= 8
                byte_count += 1

            address_list.append(ip_oct_list)
            ip_idx += 1

        st.log("Topology - {}.{}.{}.{}/{} has {} adresses".format(
                                                  subnet_octet[0], subnet_octet[1],
                                                  subnet_octet[2], subnet_octet[3],
                                                  subnet_mask, ip_idx))
        #st.log("Topology - Subnet addresses: {} ".format(address_list))
        return copy.deepcopy(address_list)


    @staticmethod
    def get_ip_network_list(subnet_octet=[], subnet_mask=0, addr_family='ipv4', nw_count=50):

        st.log("Topology - Get Network addresses of {}/{}".format(subnet_octet, subnet_mask))

        if len(subnet_octet) != 4 :
           st.log("Topology - Invalid subnet_octet {}".format(subnet_octet))
           return []

        address_size = 64 if addr_family == 'ipv6' else 32
        oct_count = address_size - 8
        oct_mask = int('0x0ff', 16)

        if address_size == 32 and len(subnet_octet) != 4 :
           st.log("Topology - Invalid ipv4 subnet_octet {}".format(subnet_octet))
           return []

        if address_size == 64 :
           if len(subnet_octet) < 4 :
               st.log("Topology - Invalid ipv6 subnet_octet {}".format(subnet_octet))
               return []

        subnet_num = 0
        for nw_byte in subnet_octet :
            if nw_byte < 0 or nw_byte > oct_mask :
                st.log("Topology - Invalid octet {} in subnet {}".format(nw_byte, subnet_octet))
                return []

            subnet_num = subnet_num + ( int(nw_byte) << oct_count)
            oct_count = oct_count - 8

        subnet_mask = int(subnet_mask)
        if subnet_mask < 1 or subnet_mask >= address_size :
           st.log("Topology - Invalid Subnet mask {}".format(subnet_mask))
           return []

        host_bits = address_size  - subnet_mask
        start_ip_addr = (subnet_num >> host_bits)
        end_ip_addr = start_ip_addr + nw_count

        address_list = []
        ip_idx = 0

        for nw_ip in range (start_ip_addr, end_ip_addr + 1) :
            ip_oct_list = [0, 0, 0, 0]
            ip = nw_ip << (host_bits)
            oct_count = address_size - 8
            byte_count = 0
            while oct_count >= 0 :
                ip_oct_list[byte_count] = (ip >> oct_count) & oct_mask
                oct_count -= 8
                byte_count += 1

            address_list.append(ip_oct_list)
            ip_idx += 1

        st.log("Topology - Network addresses: {} ".format(address_list))
        return copy.deepcopy(address_list)

    @staticmethod
    def lists_are_matching(list1, list2):
        if len(list1) != len(list2):
            return False
        for entry in list1:
            if entry not in list2 :
               return False
        return True


    @staticmethod
    def find_vlan_ranges(in_vlan_data):

        new_vlan_data = {}
        for vlan_if, vlan_data in in_vlan_data.items() :
            vlan_id = int(vlan_data['vlan_id'])
            members = copy.deepcopy(vlan_data['members'])
            new_vlan_data[vlan_id] = { 'if_name': vlan_if, 'members': members}

        '''
        st.log("Topology - Find Vlan ranges")
        for vlan_if, vlan_data in new_vlan_data.items():
            st.log("  Vlan {} --> {}".format(vlan_if, vlan_data))
        '''

        prev_vlan_id = 0
        prev_members = []
        range_start = 0
        range_end = 0

        range_vlan_data = {}
        base_vlan_if = ''
        for vlan_id, vlan_data in new_vlan_data.items():
            if prev_vlan_id == 0 :
                prev_vlan_id = vlan_id
                prev_members = vlan_data['members']
                base_vlan_if = vlan_data['if_name']
                range_start = vlan_id
                range_end = vlan_id
                continue

            range_found = False
            if (prev_vlan_id + 1) == vlan_id :
                range_found = TOPOLOGY.lists_are_matching(prev_members, vlan_data['members'])

            if range_found :
                range_end = vlan_id
                prev_vlan_id = vlan_id
            else:
                range_id = [range_start, range_end]
                members = copy.deepcopy(prev_members)
                range_vlan_data[base_vlan_if] = { 'range' : range_id , 'members': members, 'vlan_id':0 }

                prev_vlan_id = vlan_id
                prev_members = vlan_data['members']
                base_vlan_if = vlan_data['if_name']
                range_start = vlan_id
                range_end = vlan_id

        if prev_vlan_id and range_start and range_end:
            range_id = [range_start, range_end]
            members = copy.deepcopy(prev_members)
            range_vlan_data[base_vlan_if] = { 'range' : range_id , 'members': members, 'vlan_id':0 }

        #st.log("Topology - Find Vlan ranges result")
        #for range_idx, vlan_data in range_vlan_data.items():
        #    st.log("   VLAN range {} --> {}".format(range_idx, vlan_data))

        return copy.deepcopy(range_vlan_data)



    @staticmethod
    def show_dut_if_cmd_logs(dut):
        tb_dut = TOPOLOGY.get_dut_device(dut)
        #st.show(tb_dut,"show interface status")
        st.show(tb_dut,"show vrf")
        st.show(tb_dut,"show interfaces loopback")
        st.show(tb_dut,"show interfaces portchannel")
        st.show(tb_dut,"show vlan config")
        st.show(tb_dut,"show ip interface")
        st.show(tb_dut,"show ipv6 interface")
        return True, 'Success'


    @staticmethod
    def show_dut_route_cmd_logs(dut):
        tb_dut = TOPOLOGY.get_dut_device(dut)
        st.show(tb_dut, "show ip route vrf all", type='vtysh')
        st.show(tb_dut, "show ipv6 route vrf all", type='vtysh')
        return True, 'Success'


    @staticmethod
    def show_one_dut_cmd_logs(dut):
        TOPOLOGY.show_dut_if_cmd_logs(dut)
        #TOPOLOGY.show_dut_route_cmd_logs(dut)
        return True, 'Success'


    @staticmethod
    def show_dut_cmd_logs(dut_list, threaded_run=True):
        if not isinstance(dut_list, list):
            dut_list = [dut_list]

        result, resstr = True, 'Success'

        dut_thread = []
        for dut in dut_list :
            if threaded_run :
                dut_thread.append([TOPOLOGY.show_one_dut_cmd_logs, dut])
            else :
                result, resstr = TOPOLOGY.show_one_dut_cmd_logs(dut)

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            result, resstr = TOPOLOGY.get_threaded_result(out, exceptions)

        return result, resstr


    @staticmethod
    def show_all_dut_cmd_logs(threaded_run=True):
        dut_list = TOPOLOGY.get_dut_list()
        result, resstr = TOPOLOGY.show_dut_cmd_logs(dut_list, threaded_run)
        return result, resstr


    @staticmethod
    def show_dut_running_config(dut_list):
        if not isinstance(dut_list, list):
            dut_list = [dut_list]
        for dut in dut_list :
            tb_dut = TOPOLOGY.get_dut_device(dut)
            st.show(tb_dut, "show running-config all")
        return True, 'Success'


    @staticmethod
    def get_matching_entries(entries=[], match=None):
         matched_entries = cutils.filter_and_select(entries, None, match)
         if not matched_entries:
             st.log("\nTopology no match {} in\n {}\n".format(match, entries))
         else :
             st.log("\nTopology Matched {} entries\n {}\n".format(match, matched_entries))
         return matched_entries


    @staticmethod
    def entries_are_matching(entries=[], match=None):
         matched_entries = TOPOLOGY.get_matching_entries(entries, match)
         if not matched_entries:
             return False
         return True


    @staticmethod
    def get_all_values_in_list(dict_data):

        if not isinstance(dict_data, dict):
           st.log("Topology - input data {} not dictionary object".format(dict_data))
           return []

        out_list = []
        for key, list_data in dict_data.items():
            if not isinstance(list_data, list):
                st.log("Topology - input key {} value {} not list object".format(key, list_data))
                continue
            for item in list_data :
                if item not in out_list :
                    out_list.append(item)

        return out_list

    #-------------------------------------------------------------------------
    # Testbed config functions

    @staticmethod
    def config_all_vrfs(config='yes', threaded_run=True):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring VRFs on all nodes.".format(action_str))

        result, resstr = True, 'Success'

        dut_list = TOPOLOGY.get_dut_list()
        dut_thread = []

        for dut in dut_list :
            tb_dut = nw_topo[dut]['device']
            vrf_data_list = {}

            if TOPOLOGY.dut_is_tg(dut) :
                st.log("Topology - TG {} vrf config not done for now".format(dut))
                continue

            for vrf_name, _ in nw_topo[dut]['vrf'].items():
                if vrf_name != 'default' :
                    vrf_data_list[vrf_name] = { 'name' : vrf_name }

            if threaded_run :
                dut_thread.append([vrfapi.config_vrfs, tb_dut, vrf_data_list, config])
            else :
                result = vrfapi.config_vrfs(tb_dut, vrf_data_list, config)

            if not result :
                st.log("{}uring {} VRFs FAILED".format(action_str, dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "{}uring vrf FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr


    @staticmethod
    def config_all_loopback_interfaces(config='yes', threaded_run=True):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring LOOPBACK Interface on all nodes.".format(action_str))

        result, resstr = True, 'Success'

        dut_list = TOPOLOGY.get_dut_list()
        dut_thread = []

        for dut in dut_list :
            tb_dut = nw_topo[dut]['device']
            lpbk_if_data = {}

            if TOPOLOGY.dut_is_tg(dut) :
                st.log("Topology - TG {} Loopback config not done for now".format(dut))
                continue

            for _, link_data in nw_topo[dut]['intf'].items():
                if link_data['type'] != 'LBK':
                    continue

                if_name = link_data['if']
                lpbk_if_data[if_name] = link_data['vrf']

            loopback_names = list(lpbk_if_data.keys())
            if threaded_run :
                dut_thread.append(putils.ExecAllFunc(ipapi.config_loopback_interfaces, tb_dut, loopback_name=loopback_names, config=config))
            else :
                result = ipapi.config_loopback_interfaces(tb_dut, loopback_name=loopback_names, config=config)

            if not result :
                st.log("{}uring {} loopback interfaces FAILED".format(action_str, dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "{}uring loopback interfaces FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr


    @staticmethod
    def config_all_portchanel_interfaces(config='yes', threaded_run=True):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring Portchannel Interface on all nodes.".format(action_str))

        result, resstr = True, 'Success'

        dut_list = TOPOLOGY.get_dut_list()
        dut_thread = []

        for dut in dut_list :
            tb_dut = nw_topo[dut]['device']
            portchannel_data = {}

            if TOPOLOGY.dut_is_tg(dut) :
                st.log("Topology - TG {} Portchannel config not done for now".format(dut))
                continue

            for _, link_data in nw_topo[dut]['intf'].items():
                if link_data['type'] != 'PCH':
                    continue

                pch_if =  link_data['if']
                portchannel_data[pch_if] = { 'members': [] }

                for link_member in link_data['members'] :
                   mem_if = TOPOLOGY.get_link_dut_interface(dut, link_member)
                   portchannel_data[pch_if]['members'].append(mem_if)

            if threaded_run :
                dut_thread.append([ifapi.config_portchannel_interfaces, tb_dut, portchannel_data, config])
            else :
                result = ifapi.config_portchannel_interfaces(tb_dut, portchannel_data, config)

            if not result :
                st.log("{}uring {} Portchannel interfaces FAILED".format(action_str, dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "Topology - {}uring Portchannel interfaces FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr


    @staticmethod
    def config_all_vlan_interfaces(config='yes', threaded_run=True):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring Vlan Interface on all nodes.".format(action_str))

        result, resstr = True, 'Success'

        dut_list = TOPOLOGY.get_dut_list()
        dut_thread = []

        for dut in dut_list :
            tb_dut = nw_topo[dut]['device']
            vlan_data = {}

            if TOPOLOGY.dut_is_tg(dut) :
                st.log("Topology - TG {} interface config not done for now".format(dut))
                continue

            for _, link_data in nw_topo[dut]['intf'].items():
                if link_data['type'] != 'VLN':
                    continue

                vlan_if = link_data['if']
                vlan_id = link_data['if_id']
                vlan_data[vlan_if] = {'members': [], 'vlan_id': vlan_id}

                for link_member in link_data['members'] :
                   mem_if = TOPOLOGY.get_link_dut_interface(dut, link_member)
                   vlan_data[vlan_if]['members'].append(mem_if)

            vlan_range_data = {}
            if len(vlan_data):
                vlan_range_data = TOPOLOGY.find_vlan_ranges(vlan_data)
                st.log("Topology - {} Vlan Ranges".format(dut))
                for range_idx, vlan_rdata in vlan_range_data.items():
                    st.log("   range {} --> {}".format(range_idx, vlan_rdata))

            if threaded_run :
                dut_thread.append([ifapi.config_vlan_interfaces, tb_dut, vlan_range_data, config])
            else :
                result = ifapi.config_vlan_interfaces(tb_dut, vlan_range_data, config)

            if not result :
                st.log("{}uring {} Vlan interfaces FAILED".format(action_str, dut))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "Topology - {}uring Vlan interfaces FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result , resstr


    @staticmethod
    def config_all_interface_vrf_binds(config='yes', threaded_run=True):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring Interface vrf bind on all nodes.".format(action_str))

        result, resstr = True, 'Success'

        dut_list = TOPOLOGY.get_dut_list()
        dut_thread = []

        for dut in dut_list :
            tb_dut = nw_topo[dut]['device']
            if_vrf_data = {}

            if TOPOLOGY.dut_is_tg(dut) :
                st.log("Topology - TG {} interface config not done for now".format(dut))
                continue

            for link_name, link_data in nw_topo[dut]['intf'].items():

                if TOPOLOGY.dut_link_has_sub_ifs(dut, link_name) :
                    continue

                if_vrf = link_data['vrf']
                if_name = link_data['if']

                if if_vrf == 'default' :
                    continue

                if_vrf_data[if_name] = { 'vrf' : if_vrf }

            if threaded_run :
               if len(if_vrf_data):
                   dut_thread.append([ifapi.config_interface_vrf_binds, tb_dut, if_vrf_data, config])
            else :
               if len(if_vrf_data):
                   result = ifapi.config_interface_vrf_binds(tb_dut, if_vrf_data, config)

            if not result :
                st.log("{}uring {} Interface bind FAILED".format(action_str, dut))
                break

        if threaded_run and len(dut_thread) :
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "Topology - {}uring bind interfaces to vrfs FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr


    @staticmethod
    def config_all_loopback_ips(config='yes', addr_family='all', threaded_run=True, debug_run=False):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """
        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring LOOPBACK Addresses on all nodes.".format(action_str))

        result, resstr = True, 'Success'
        config = 'add' if config == 'yes' else 'remove'

        addr_family_list = TOPOLOGY.get_address_family_list(addr_family)
        dut_thread = []

        dut_list = TOPOLOGY.get_dut_list() #+ TOPOLOGY.get_tg_list()

        for dut in dut_list :
            tb_dut = nw_topo[dut]['device']
            if_data_list = []

            if TOPOLOGY.dut_is_tg(dut) :
                st.log("Topology - TG {} Loopback IP config not done for now".format(dut))
                continue

            for afmly in addr_family_list:
                for _, link_data in nw_topo[dut][afmly]['link'].items():
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
                TOPOLOGY.show_dut_cmd_logs(dut)
                st.log("{}uring {} loopback address FAILED".format(action_str, dut))
                break

            if debug_run:
                TOPOLOGY.show_dut_if_cmd_logs(dut)

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "{}uring loopback addresses FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr


    @staticmethod
    def config_all_ip_interfaces(config='yes', addr_family='all', threaded_run=True, debug_run=False):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring Interface Addresses on all nodes.".format(action_str))

        if not TOPOLOGY.nw_topology_data_present() :
            resstr = "Topology Topology data not available"
            st.log("{}".format(resstr))
            return False, resstr

        result, resstr = True, 'Success'
        config = 'add' if config == 'yes' else 'del'

        addr_family_list = TOPOLOGY.get_address_family_list(addr_family)
        dut_thread = []

        dut_list = TOPOLOGY.get_dut_list()

        for dut in dut_list :
            tb_dut = nw_topo[dut]['device']

            if_data_list = {}

            for afmly in addr_family_list:
                for link_name, link_data in nw_topo[dut][afmly]['link'].items():

                    if TOPOLOGY.dut_link_has_sub_ifs(dut, link_name) :
                        continue

                    link_ip = link_data['ip']
                    link_if = link_data['if']
                    subnet = link_data['subnet']

                    if_data_list[link_if] = {'name': link_if, 'ip': link_ip, 'subnet': subnet, 'family':afmly }

                    st.log("{}uring {} Interface {}:{} {}:{} {} ".format(action_str, afmly, dut,
                                                              tb_dut, link_name, link_if, link_ip))

            if threaded_run:
                dut_thread.append([ipapi.config_interface_ip_addresses, tb_dut, if_data_list, config])
            else :
                result = ipapi.config_interface_ip_addresses(tb_dut, if_data_list, config=config)

            if not result:
                TOPOLOGY.show_dut_cmd_logs(dut)
                resstr = "Topology - {}uring {} Interface address FAILED".format(action_str, dut)
                st.log("{}".format(resstr))
                return False, resstr

            if debug_run:
                TOPOLOGY.show_dut_if_cmd_logs(dut)

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "Topology - {}uring all interface ip addresses FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr


    @staticmethod
    def config_all_tg_ip_interfaces(config='yes', addr_family='all'):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring Interface Addresses on all TGENs.".format(action_str))

        if not TOPOLOGY.nw_topology_data_present() :
            resstr = "Topology Topology data not available"
            st.log("{}".format(resstr))
            return False, resstr

        result, resstr = True, 'Success'
        threaded_run = True
        dut_thread = []
        dut_list = TOPOLOGY.get_tg_list()

        for dut in dut_list :
            tb_dut = nw_topo[dut]['device']
            tg = tgen_obj_dict[tb_dut]

            for _, link_data in nw_topo[dut]['intf'].items():
                if link_data['type'] == 'LBK':
                   continue

                tb_if = link_data['if']
                tg_port_handle = tg.get_port_handle(tb_if)

                if config == 'yes' :
                    st.log("\n")
                    st.log("Topology - Resetting TG port {} {}".format(tb_dut, tb_if))
                    tg.tg_traffic_control(action="reset", port_handle=tg_port_handle)
                    st.log("\n")

                '''
                vrf = ''
                if threaded_run:
                    dut_thread.append([TOPOLOGY.tg_link_ip_config_unconfig, dut, link_name, addr_family, vrf, config])
                else :
                    result = TOPOLOGY.tg_link_ip_config_unconfig(dut, link_name, addr_family, vrf, config=config)
                '''

            if not result:
                TOPOLOGY.show_dut_cmd_logs(dut)
                st.log("{}uring TG {} Interface address FAILED".format(action_str, dut))

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "Topology - {}uring TG interface ip addresses FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr


    @staticmethod
    def config_ip_interface(dut, link_name, addr_family='all', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring Interface Addresses on link {}.".format(action_str, link_name))

        result, resstr = True, 'Success'
        addr_family_list = TOPOLOGY.get_address_family_list(addr_family)

        if not TOPOLOGY.dut_link_present(dut, link_name) :
            resstr = "Topology - Dut {} link {} not present".format(dut, link_name)
            st.log("{}".format(resstr))
            return False, resstr

        tb_dut = nw_topo[dut]['device']
        #link_data = nw_topo[dut]['intf'][link_name]
        #tb_if = link_data['if']

        config = 'add' if config == 'yes' else 'remove'

        for afmly in addr_family_list:

            if link_name not in nw_topo[dut][afmly]['link'].keys():
                st.log("Topology - {} {} {} address not assigned".format(dut, link_name, afmly))
                continue

            ip_data = nw_topo[dut][afmly]['link'][link_name]

            link_ip = ip_data['ip']
            link_if = ip_data['if']
            subnet = ip_data['subnet']

            st.log("{}uring {} Interface {} {}:{} {} ".format(action_str, afmly,
                                                       tb_dut, link_name, link_if, link_ip))

            result = ipapi.config_ip_addr_interface(tb_dut, link_if, link_ip, subnet, afmly, config)

            if not result:
                TOPOLOGY.show_dut_cmd_logs(dut)
                st.log("{}uring {} Interface address FAILED".format(action_str, dut))
                break

        if not result :
            resstr = "Topology - {}uring Interface address FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr


    @staticmethod
    def config_tg_ip_interface(dut, link_name, addr_family='all', vrf='default', config='yes'):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring Interface Addresses on TG link.".format(action_str))

        result, resstr = True, 'Success'
        addr_family_list = TOPOLOGY.get_address_family_list(addr_family)

        if not TOPOLOGY.dut_link_present(dut, link_name) :
            resstr = "Topology - Dut {} link {} not present".format(dut, link_name)
            st.log("{}".format(resstr))
            return False, resstr

        tb_dut = nw_topo[dut]['device']
        link_data = nw_topo[dut]['intf'][link_name]
        tb_if = link_data['if']

        tg = tgen_obj_dict[tb_dut]
        tg_port_handle = tg.get_port_handle(tb_if)

        for afmly in addr_family_list:

            if link_name not in nw_topo[dut][afmly]['link'].keys():
                st.log("Topology - {} {} {} address not assigned".format(dut, link_name, afmly))
                continue

            ip_data = nw_topo[dut][afmly]['link'][link_name]

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

                st.log("Topology - Port ip config tg api result = {}".format(tg_result))

                if 'handle' in tg_result.keys():
                    nw_topo[dut][afmly]['link'][link_name]['tg_handle'] = tg_result['handle']
                else :
                    result = False
                    break

            else :
                handle = ''
                if 'tg_handle' in ip_data.keys():
                    handle = ip_data['tg_handle']

                if handle == '' :
                    st.log("Topology - {} {} {} tg handle invalid".format(dut, link_name, afmly))
                    continue

                if afmly == 'ipv4':
                    tg_result = tg.tg_interface_config(port_handle=tg_port_handle, handle=handle, mode='destroy')
                else:
                    tg_result = tg.tg_interface_config(port_handle=tg_port_handle, handle=handle, mode='destroy')

                st.log("Topology - Port ip Unconfig tg api result = {}".format(tg_result))

                nw_topo[dut][afmly]['link'][link_name]['tg_handle'] = ''

        if not result:
            TOPOLOGY.show_dut_cmd_logs(dut)
            st.log("{}uring TG {} Interface address FAILED".format(action_str, dut))

        if not result :
            resstr = "Topology - {}uringi TG Interface address FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr



    @staticmethod
    def config_all_static_routes(config='yes', vrf='default', addr_family='all', threaded_run=True, debug_run=False):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """
        action_str = 'Config' if config == 'yes' else 'Unconfig'
        TOPOLOGY.banner_log("{}uring Static Route on all nodes.".format(action_str))

        if not TOPOLOGY.nw_topology_data_present() :
            resstr = "Topology - Topology data not available"
            st.log("{}".format(resstr))
            return False, resstr

        result, resstr = True, 'Success'
        config = 'add' if config == 'yes' else 'remove'

        addr_family_list = TOPOLOGY.get_address_family_list(addr_family)
        #thread_info = {'ipv4': [], 'ipv6': []}
        dut_thread = []

        for dut in nw_topo['dut_list'] :
            tb_dut = nw_topo[dut]['device']
            rt_data_list = []

            for afmly in addr_family_list:

                for prefix, strt_data in nw_topo[dut][afmly]['static_rt'].items():

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
                TOPOLOGY.show_dut_cmd_logs(dut)
                resstr = "Topology - {}uring {} Static route FAILED".format(action_str, dut)
                st.log("{}".format(resstr))
                return False, resstr

            if debug_run:
                TOPOLOGY.show_dut_route_cmd_logs(dut)

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Threaded Run result {}".format([out, exceptions]))
            if False in out : result = False

        if not result :
            resstr = "Topology - {}uringi Static route FAILED".format(action_str)
            st.log("{}".format(resstr))

        return result, resstr



    @staticmethod
    def dut_interface_address_ping_test(dut, addr_family='all', ping_count=3, retry_count=3):

        st.log("Topology - {} interface {} address Ping test".format(dut, addr_family))
        result, resstr = True, 'Success'

        if not TOPOLOGY.dut_present(dut):
            resstr = "Topology - Dut {} not present".format(dut)
            st.log("{}".format(resstr))
            return False, resstr

        tb_dut = TOPOLOGY.get_dut_device(dut)
        #TOPOLOGY.show_dut_route_cmd_logs(dut)

        addr_family_list = TOPOLOGY.get_address_family_list(addr_family)

        for afmly in addr_family_list:
            for link_name, link_data in nw_topo[dut][afmly]['link'].items():
                if link_data['type'] == 'LBK' :
                    continue

                if 'rmt_ip' not in link_data.keys():
                    st.log("Topology - Remote ip not configured for {}".format(link_name))
                    continue

                if TOPOLOGY.is_tg_connected_link(dut, link_name):
                    st.log("Topology - Not Trying Pinf test for TG connected link {}".format(link_name))
                    continue  #only for now

                lcl_ip = link_data['ip']
                rmt_ip = link_data['rmt_ip']
                lcl_if = link_data['if']

                link_vrf = TOPOLOGY.dut_get_link_vrf(dut, link_name)
                if link_vrf != '' and link_vrf != 'default':
                    lcl_if = link_vrf

                native_if = ifapi.get_native_interface_name(tb_dut, lcl_if)
                if native_if != '' and lcl_if != native_if :
                    st.log("Topology - Port name {} changed to native format {}".format(lcl_if, native_if))
                    lcl_if = native_if

                for retry in range (0, retry_count):

                    st.log("Topology - Pingtest for {} {} {} --{}-> {} ".format(afmly, tb_dut, lcl_ip, link_name, rmt_ip))

                    result = ipapi.ping(tb_dut, rmt_ip, family=afmly, count=ping_count, interface=lcl_if)
                    if not result :
                        st.log("Topology - Ping Failed at attempt {} for {} {} {} --{}-> {} ".format(
                                                     retry, afmly, tb_dut, lcl_ip, link_name, rmt_ip))
                    else :
                        break

                if not result:
                    resstr = "Topology - Ping FAILED for {} {} {} --{}-> {} ".format(
                                                     afmly, tb_dut, lcl_ip, link_name, rmt_ip)
                    st.log("{}".format(resstr))
                    st.log("ERROR Dut {} Ping to {} FAILED ".format(tb_dut, rmt_ip))
                    TOPOLOGY.show_dut_route_cmd_logs(dut)
                    break

            if not result:
                break

        if not result:
            st.log("Topology - {} Ping Test FAILED".format(dut))
            TOPOLOGY.show_dut_cmd_logs(dut)
            TOPOLOGY.show_dut_route_cmd_logs(dut)
            return False, resstr

        return result, resstr


    @staticmethod
    def interface_address_ping_test(addr_family='all', ping_count=3):
        """

        :param config:
        :param vrf:
        :param addr_family:
        :return:
        """

        st.log("Topology network Ping test for interface IP addressess")

        if not TOPOLOGY.nw_topology_data_present() :
            resstr = "Topology - Topology data not available"
            st.log("{}".format(resstr))
            return False, resstr

        threaded_run = True
        result, resstr = True, 'Success'
        dut_thread = []
        dut_list = TOPOLOGY.get_dut_list()

        if not dut_list or len(dut_list) < 2: threaded_run = False

        for dut in dut_list :
            if threaded_run:
                dut_thread.append([TOPOLOGY.dut_interface_address_ping_test, dut, addr_family, ping_count])
            else :
                result = TOPOLOGY.dut_interface_address_ping_test(dut, addr_family, ping_count)

            if not result:
                TOPOLOGY.show_dut_if_cmd_logs(dut)
                resstr = "Topology - Ping Test Failed for {}".format(dut)
                st.log("{}".format(resstr))
                break

        if threaded_run:
            [out, exceptions] = putils.exec_all(fast_start, dut_thread)
            st.log("Topology - Ping Test Threaded Run result {}".format([out, exceptions]))
            result, resstr = TOPOLOGY.get_threaded_result(out, exceptions)

        if not result:
            st.log("{}".format(resstr))
            #import pdb; pdb.set_trace()
            st.log("Topology - Interface Ping Test FAILED")
        else :
            st.log("Topology - Interface Ping Test Passed")

        return result, resstr


    @staticmethod
    def dut_interface_shut_noshut(dut, link_name, shut='yes'):

        action_str = "Shut down" if shut == 'yes' else 'Startup'

        tb_dut = TOPOLOGY.get_dut_device(dut)
        tb_intf =  TOPOLOGY.get_link_dut_interface(dut, link_name)

        if tb_dut == '' or tb_intf == '' :
            st.log("Topology - tb dut {} or if {} empty".format(tb_dut, tb_intf))
            return False

        st.log("Topology - {} {} {}".format(action_str, dut, link_name))

        if shut == 'yes':
            result = ifapi.interface_shutdown(tb_dut, tb_intf)
        else :
            result = ifapi.interface_noshutdown(tb_dut, tb_intf)

        if not result :
            st.log("Topology - {} {} {} Failed".format(action_str, dut, link_name))

        return result


    @staticmethod
    def config_topology_on_testbed(config='yes', ping_test='yes', force=False):

        action_str = 'Config' if config == 'yes' else 'Unconfig'
        st.log("{}uring topolgy into testbed nodes.".format(action_str))

        #TOPOLOGY.show_dut_topo_data()
        result, resstr = True, 'Success'

        if config == 'yes' :
            #TOPOLOGY.show_all_dut_cmd_logs()

            if result :
                result, resstr = TOPOLOGY.config_all_vrfs(config='yes')
                if not result :
                    resstr += "Topology - config all vrf Failed"
                    st.log("{}".format(resstr))
                else :
                   nw_topo['test_bed_configured'] = True

            if result :
                result, resstr = TOPOLOGY.config_all_loopback_interfaces(config='yes')
                if not result :
                    resstr += "Topology - config all loopback interfaces Failed"
                    st.log("{}".format(resstr))
                else :
                   nw_topo['test_bed_configured'] = True

            if result :
                result, resstr = TOPOLOGY.config_all_portchanel_interfaces(config='yes')
                if not result :
                    resstr += "Topology - config port channel interfaces vrf Failed"
                    st.log("{}".format(resstr))

            if result :
                result, resstr = TOPOLOGY.config_all_vlan_interfaces(config='yes')
                if not result :
                    resstr += "Topology - config all Vlan interfaces Failed"
                    st.log("{}".format(resstr))
                else :
                   nw_topo['test_bed_configured'] = True

            if result :
                result, resstr = TOPOLOGY.config_all_interface_vrf_binds(config='yes')
                if not result :
                    resstr += "Topology - config all interface vrf bind Failed"
                    st.log("{}".format(resstr))
                else :
                   nw_topo['test_bed_configured'] = True

            if result :
                result, resstr = TOPOLOGY.config_all_ip_interfaces(config='yes', addr_family='ipv4')
                if not result :
                    resstr += "Topology - config all interface ip address Failed"
                    st.log("{}".format(resstr))
                else :
                   nw_topo['test_bed_configured'] = True

            if result and ping_test == 'yes':
                nw_topo['test_bed_configured'] = True
                result, resstr = TOPOLOGY.interface_address_ping_test(addr_family='ipv4', ping_count=3)
                if not result :
                    resstr += "Topology - ping test Failed on testbed configured interfaces"
                    st.log("{}".format(resstr))

            if not result :
                st.log("Topology - one or more config Failed")
                TOPOLOGY.show_dut_topo_data()
                TOPOLOGY.show_all_dut_cmd_logs()

        elif config == 'no' :

            unconfig_failed = False
            unconfig_err = 'Success'

            if nw_topo['test_bed_configured']:

                result, resstr = TOPOLOGY.config_all_ip_interfaces(config='no', addr_family='ipv4')
                if not result :
                    resstr += "Topology - Unconfig all vrf Failed"
                    st.log("{}".format(resstr))
                    unconfig_failed = True
                    unconfig_err = resstr

                result, resstr = TOPOLOGY.config_all_interface_vrf_binds(config='no')
                if not result :
                    resstr += "Topology - Unconfig all interface vrf bind Failed"
                    st.log("{}".format(resstr))
                    unconfig_failed = True
                    unconfig_err += resstr

                result, resstr = TOPOLOGY.config_all_vlan_interfaces(config='no')
                if not result :
                    resstr += "Topology - Unconfig all Vlan interfaces Failed"
                    st.log("{}".format(resstr))
                    unconfig_failed = True
                    unconfig_err += resstr

                result, resstr = TOPOLOGY.config_all_portchanel_interfaces(config='no')
                if not result :
                    resstr += "Topology - Unconfig all port channel interfaces Failed"
                    st.log("{}".format(resstr))
                    unconfig_failed = True
                    unconfig_err += resstr

                result, resstr = TOPOLOGY.config_all_loopback_interfaces(config='no')
                if not result :
                    resstr += "Topology - Unconfig all loopback interfaces Failed"
                    st.log("{}".format(resstr))
                    unconfig_failed = True
                    unconfig_err += resstr

                result, resstr = TOPOLOGY.config_all_vrfs(config='no')
                if not result :
                    resstr += "Topology - Unconfig all vrf Failed"
                    st.log("{}".format(resstr))
                    unconfig_failed = True
                    unconfig_err += resstr

            if unconfig_failed :
                TOPOLOGY.show_all_dut_cmd_logs()
                result, resstr = False, unconfig_err
            else :
                nw_topo['test_bed_configured'] = False
                result, resstr = True, 'Success'

            #TOPOLOGY.show_all_dut_cmd_logs()

        result_str = "Success" if result else "Failed"
        st.log("{}uring topolgy into testbed nodes {}.".format(action_str, result_str))
        return result, resstr


    @staticmethod
    def cleanup_testbed_config():
        if nw_topo :
            if nw_topo['inited'] :
                TOPOLOGY.config_topology_on_testbed(config='no', force=True)


