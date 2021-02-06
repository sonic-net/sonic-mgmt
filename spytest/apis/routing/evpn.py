import re

from spytest.utils import filter_and_select
from spytest import st, utils

import apis.system.port as port1
from apis.system.rest import get_rest,delete_rest,config_rest

from utilities.utils import get_interface_number_from_name

def config_bgp_evpn(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    config_bgp_evpn(dut=data.dut1,neighbor ='21.1.1.2',remote_as='20',config='yes',config_type_list =["activate"])
    config_bgp_evpn(dut=dut1,config = 'yes',config_type_list=["advertise_all_vni"],local_as="10")
    config_bgp_evpn(dut=dut1,config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",l3_rd="8:8",config="yes",local_as=evpn_dict["leaf3"]['local_as'])
    config_bgp_evpn(dut=dut1,config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",l3_both_rt="50:50",config="no", local_as=evpn_dict["leaf3"]['local_as'])
    config_bgp_evpn(dut=dut1,config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",l3_import_rt="51:50",config="yes", local_as=evpn_dict["leaf3"]['local_as'])
    config_bgp_evpn(dut=dut1,config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",l3_export_rt="52:50",config="yes", local_as=evpn_dict["leaf3"]['local_as'])
    config_bgp_evpn(dut=dut1,config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",l3_rd="8:8",config="no", local_as=evpn_dict["leaf3"]['local_as'])
    config_bgp_evpn(dut=dut1,config_type_list=["vrf_rd_rt"],vrf_name="Vrf1",l3_rd="9:9",l3_both_rt="50:50",config="no",local_as=evpn_dict["leaf3"]['local_as'])

    config_bgp_evpn(dut=data.dut1,neighbor ='21.1.1.2',remote_as='20',config='yes',config_type_list =["activate"], cli_type='klish')
    config_bgp_evpn(dut=dut1,config = 'yes',config_type_list=["advertise_all_vni"],local_as="10", cli_type='klish')

    Configure bgp l2vpn evpn specific commands
    :param dut:
    :param neighbor:
    :param local_as:
    :param config_type_list:
    :param allowas_in:
    :param attribute_unchanged:
    :param route_map:
    :param direction:
    :param network:
    :param rd:
    :param vni:
    :param vrf_name:
    :param l3_vni_id:
    :param ethtag:
    :param bgp_label:
    :param esi_id:
    :param gw_ip:
    :param router_mac:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if cli_type == 'click':  cli_type = "vtysh"
    skip_rest_cfg_type_list = [ 'nexthop_self', 'route_map', 'allowas_in', 'network', 'route_target', 'autort',
                               'attribute_unchanged', 'default_originate_ipv4', 'default_originate_ipv6',
                               'default_originate_ipv4_vrf', 'default_originate_ipv6_vrf',
                               'dup_addr_detection', 'flooding_disable', 'flooding_head_end_replication',
                               "route_server_client", "route_reflector_client" ]

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if 'vrf_name' in kwargs:
        vrf_name = kwargs['vrf_name']
    else:
        vrf_name = "default"

    if 'l3_vni_id' in kwargs:
        l3_vni_id = kwargs['l3_vni_id']
    if 'vtep_name' in kwargs:
        vtep_name = kwargs['vtep_name']

    if 'config_type_list' in kwargs:
        config_type_list = kwargs['config_type_list']
    if 'neighbor' in kwargs:
        neighbor = kwargs['neighbor']
    if 'peergroup' in kwargs and 'neighbor' not in kwargs:
        neighbor = kwargs['peergroup']

    if 'addr_family' in kwargs:
        addr_family = kwargs['addr_family']
    else:
        addr_family = 'l2vpn'

    if 'addr_family_modifier' in kwargs:
        addr_family_modifier = kwargs['addr_family_modifier']
    else:
        addr_family_modifier = "evpn"
        st.log('Configure BGP L2VPN address family')

    addr_family_str = addr_family.upper() + '_' + addr_family_modifier.upper()

    if cli_type in ['rest-put','rest-patch']:
        st.banner("CFG list: {}, cli_type:{}".format(config_type_list,cli_type))
        for cfg_type in config_type_list:
            if cfg_type in skip_rest_cfg_type_list:
                cli_type = 'klish'
                st.banner("CFG type skipped: {}, cli_type:{}".format(cfg_type, cli_type))
                break


    if cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if config.lower() == 'yes' and 'vrf_vni' not in config_type_list:
            if 'local_as' in kwargs:
                ### AS URI
                url = rest_urls['bgp_as_config'].format(vrf_name)
                payload = {'openconfig-network-instance:as': int(kwargs['local_as'])}
                response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
                if not response:
                    st.banner('FAIL-OCYANG: BGP local-as config Failed')
                    return False

            ### L2VPN global URI
            url = rest_urls['bgp_l2vpn_global_config'].format(vrf_name)
            payload = { 'openconfig-network-instance:afi-safis': {
                        'afi-safi': [
                           {'afi-safi-name': addr_family_str,
                            'config':{
                                'afi-safi-name': addr_family_str,
                            }
                            }
                       ]
                    }}
            response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
            if not response:
                st.banner('FAIL-OCYANG: BGP {} address-family global config Failed'.format(addr_family_str))
                return False
    else:
        if 'local_as' in kwargs:
            my_cmd = 'router bgp {}\n'.format(kwargs['local_as'])
        else:
            my_cmd = 'router bgp\n'

        my_cmd += 'address-family {} {}\n'.format(addr_family,addr_family_modifier)

    if 'allowas_in' in kwargs:
        allowas_in = kwargs['allowas_in']
    if 'attribute_unchanged' in kwargs:
        attribute_unchanged = kwargs['attribute_unchanged']
    if 'route_map' in kwargs:
        route_map = kwargs['route_map']
    if 'direction' in kwargs:
        direction = kwargs['direction']
    else:
        direction = 'in'

    if 'advertise_ipv4' in kwargs:
        advertise_ipv4 = kwargs['advertise_ipv4']
    if 'advertise_ipv6' in kwargs:
        advertise_ipv6 = kwargs['advertise_ipv6']

    if 'advertise_ipv4_vrf' in kwargs:
        advertise_ipv4 = kwargs['advertise_ipv4_vrf']
    if 'advertise_ipv6_vrf' in kwargs:
        advertise_ipv6 = kwargs['advertise_ipv6_vrf']

    if 'dup_addr_detection' in kwargs:
        dup_addr_detection = kwargs['dup_addr_detection']
    if 'network' in kwargs:
        network = kwargs['network']
        rd = kwargs['rd']
        ethtag = kwargs['ethtag']
        bgp_label = kwargs['bgp_label']
        esi_id = kwargs['esi_id']
        gw_ip = kwargs['gw_ip']
        router_mac = kwargs['router_mac']

    if config.lower() == 'yes':
        config_cmd = ''
    elif config.lower() == 'remove_vrf':
        config_cmd = 'remove_vrf'
    elif config.lower() == 'remove_vni':
        config_cmd = 'remove_vni'
    else:
        config_cmd = 'no'

    if 'vni_unconfig' not in kwargs:
        vni_unconfig = ''
    elif kwargs['vni_unconfig'] == "yes":
        vni_unconfig = 'no'

    for type1 in config_type_list:
        cur_type = type1
        if type1 == 'vrf_vni' and config_cmd == '':
            if cli_type in ['klish','rest-put','rest-patch']:
                map_vrf_vni(dut, vrf_name, l3_vni_id, config='yes', vtep_name=vtep_name, cli_type=cli_type)
                my_cmd = ''
            else:
                my_cmd = ''
                my_cmd += 'vrf {} \n'.format(vrf_name)
                my_cmd += 'vni {} \n'.format(l3_vni_id)

        elif type1 == 'vrf_vni' and config_cmd != '':
            my_cmd = ''
            if cli_type in ['klish','rest-put','rest-patch']:
                if config_cmd == 'remove_vrf' or config_cmd == 'remove_vni' or config_cmd == 'no':
                    map_vrf_vni(dut, vrf_name, l3_vni_id, config='no', vtep_name=vtep_name, cli_type=cli_type)
                    my_cmd = ''
            else:
                if config_cmd == 'remove_vrf':
                    my_cmd += 'no vrf {} \n'.format(vrf_name)
                if config_cmd == 'remove_vni' or config_cmd == 'no':
                    my_cmd += 'vrf {} \n'.format(vrf_name)
                    my_cmd += 'no vni {} \n'.format(l3_vni_id)

        elif type1 == 'activate':
            if cli_type == 'klish':
                neigh_name = get_interface_number_from_name(neighbor)
                if isinstance(neigh_name, dict):
                    my_cmd += "neighbor interface {} {}\n".format(neigh_name["type"],neigh_name["number"])
                else:
                    my_cmd += "neighbor {}\n".format(neigh_name)
                my_cmd += "remote-as {}\n".format(kwargs['remote_as'])
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += "{} activate\n".format(config_cmd)
                my_cmd += "exit\n"
                my_cmd += "exit\n"
            elif cli_type in ['click','vtysh']:
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += '{} neighbor {} activate\n'.format(config_cmd, neighbor)
            elif cli_type in ['rest-put','rest-patch']:
                if config.lower() == 'yes':
                    st.log("BGP EVPN neigh config")
                    url = rest_urls['bgp_neighbor_config'].format(vrf_name)
                    if kwargs['remote_as'] == 'external':
                        payload = {'openconfig-network-instance:neighbors':
                                       {'neighbor': [
                                           {'neighbor-address': neighbor,
                                            'config': {
                                                'neighbor-address': neighbor,
                                                'peer-type': kwargs['remote_as'].upper(),
                                                'enabled': bool(1)
                                                }
                                            }
                                       ]}
                                    }
                    else:
                        payload = {'openconfig-network-instance:neighbors':
                            {'neighbor': [
                                {'neighbor-address': neighbor,
                                 'config': {
                                     'neighbor-address': neighbor,
                                     'peer-as': int(kwargs['remote_as']),
                                     'enabled': bool(1)
                                 }
                                 }
                            ]}
                        }
                    response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
                    if not response:
                        st.banner('FAIL-OCYANG: BGP EVPN neighbor configuration Failed')
                        return False

                    url = rest_urls['bgp_l2vpn_neighbor_config'].format(vrf_name,neighbor)
                    payload = {'openconfig-network-instance:afi-safis': {
                                    'afi-safi':[
                                        {
                                            'afi-safi-name': addr_family_str,
                                            'config':{
                                                'afi-safi-name': addr_family_str,
                                                'enabled': True
                                            }
                                        }
                                    ]}
                                }
                    response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
                    if not response:
                        st.banner('FAIL-OCYANG: BGP {} address-family configuration Failed'.format(addr_family_str))
                        return False
                else:
                    url = rest_urls['bgp_l2vpn_neighbor_config'].format(vrf_name, neighbor)
                    payload = {'openconfig-network-instance:afi-safis': {
                                    'afi-safi':[
                                        {
                                            'afi-safi-name': addr_family_str,
                                            'config':{
                                                'afi-safi-name': addr_family_str,
                                                'enabled': False
                                            }
                                        }
                                    ]}
                                }
                    response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
                    if not response:
                        st.banner('FAIL-OCYANG: BGP {} address-family no activate Failed'.format(addr_family_str))
                        return False
        elif type1 == 'allowas_in':
            #convert to REST as and when used
            if cli_type == 'klish':
                my_cmd += "neighbor {}\n".format(neighbor)
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += "{} allowas-in\n".format(config_cmd)
                my_cmd += "exit\n"
                my_cmd += "exit\n"
            else:
                my_cmd += '{} neighbor {} allowas-in {}\n'.format(config_cmd,neighbor,allowas_in)

        elif type1 == 'attribute_unchanged':
            #convert to REST as and when used
            if cli_type == 'klish':
                my_cmd += "neighbor {}\n".format(neighbor)
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += "{} attribute-unchanged\n".format(config_cmd)
                my_cmd += "exit\n"
                my_cmd += "exit\n"
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            else:
                my_cmd += '{} neighbor {} attribute-unchanged {}\n'.format(config_cmd,neighbor,attribute_unchanged)

        elif type1 == 'nexthop_self':
            #convert to REST as and when used
            if cli_type == 'klish':
                my_cmd += "neighbor {}\n".format(neighbor)
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += "{} next-hop-self\n".format(config_cmd)
                my_cmd += "exit\n"
                my_cmd += "exit\n"
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            else:
                my_cmd += '{} neighbor {} next-hop-self\n'.format(config_cmd, neighbor)

        elif type1 == 'route_map':
            # convert to REST as and when used
            if cli_type == 'klish':
                my_cmd += "neighbor {}\n".format(neighbor)
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += "{} route-map {} {}\n".format(config_cmd,route_map,direction)
                my_cmd += "exit\n"
                my_cmd += "exit\n"
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            else:
                my_cmd += '{} neighbor {} route-map {} {}\n'.format(config_cmd,neighbor,route_map,direction)
            my_cmd += 'exit\n'

        elif type1 == 'route_reflector_client':
            # convert to REST as and when used
            if cli_type == 'klish':
                my_cmd += "neighbor {}\n".format(neighbor)
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += "{} route-reflector-client\n".format(config_cmd)
                my_cmd += "exit\n"
                my_cmd += "exit\n"
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            else:
                my_cmd += '{} neighbor {} route-reflector-client\n'.format(config_cmd, neighbor)

        elif type1 == 'route_server_client':
            # convert to REST as and when used
            if cli_type == 'klish':
                my_cmd += "neighbor {}\n".format(neighbor)
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += "{} route-server-client\n".format(config_cmd)
                my_cmd += "exit\n"
                my_cmd += "exit\n"
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            else:
                my_cmd += '{} neighbor {} route-server-client\n'.format(config_cmd, neighbor)

        elif type1 == 'disable_ebgp_connected_route_check':
            if cli_type == 'klish':
                my_cmd += '{} disable-ebgp-connected-route-check \n'.format(config_cmd)
                my_cmd += "exit\n"
            elif cli_type in ['click','vtysh']:
                my_cmd += '{} bgp disable-ebgp-connected-route-check \n'.format(config_cmd)
            elif cli_type in ['rest-put','rest-patch']:
                url = rest_urls['ebgp_connected_route_check'].format(vrf_name)
                if config.lower() == 'yes':
                    payload = {'openconfig-bgp-ext:disable-ebgp-connected-route-check': True}
                elif config.lower() == 'no':
                    payload = {'openconfig-bgp-ext:disable-ebgp-connected-route-check': False}
                response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload)
                if not response:
                    st.banner('FAIL-OCYANG: disable-ebgp-connected-route-check configuration:{} Failed'.format(config_cmd))
                    return False
            else:
                st.error("Invalid CLI type - {}".format(cli_type))
                return False

        elif type1 == 'advertise_ipv4':
            if cli_type in ["rest-put", "rest-patch"]:
                if config.lower() == 'yes':
                    url = rest_urls['bgp_advertise_config'].format(vrf_name)
                    payload = {'openconfig-bgp-evpn-ext:advertise-list': ['IPV4_UNICAST']}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-ipv4 in vrf:{} config Failed'.format(vrf_name))
                        return False
                elif config.lower() == 'no':
                    url = rest_urls['bgp_advertise_config'].format(vrf_name)
                    if not delete_rest(dut, rest_url=url):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-ipv4 in vrf:{} delete Failed'.format(vrf_name))
                        return False
            else:
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += '{} advertise ipv4 {}\n'.format(config_cmd,advertise_ipv4)
                if cli_type == 'klish':
                    my_cmd += "exit\n"

        elif type1 == 'advertise_ipv6':
            if cli_type in ["rest-put", "rest-patch"]:
                if config.lower() == 'yes':
                    url = rest_urls['bgp_advertise_config'].format(vrf_name)
                    payload = {'openconfig-bgp-evpn-ext:advertise-list': ['IPV6_UNICAST']}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-ipv6 in vrf:{} config Failed'.format(vrf_name))
                        return False
                elif config.lower() == 'no':
                    url = rest_urls['bgp_advertise_config'].format(vrf_name)
                    if not delete_rest(dut, rest_url=url):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-ipv6 in vrf:{} delete Failed'.format(vrf_name))
                        return False
            else:
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += '{} advertise ipv6 {}\n'.format(config_cmd,advertise_ipv6)
                if cli_type == 'klish':
                    my_cmd += "exit\n"

        elif type1 == 'default_originate_ipv4_vrf':
                # convert to REST as and when used
                my_cmd = 'router bgp {} vrf {}\n'.format(kwargs['local_as'],vrf_name)
                my_cmd += 'address-family l2vpn evpn\n'
                my_cmd += '{} default-originate ipv4\n'.format(config_cmd)
                if cli_type == 'klish':
                    my_cmd += "exit\n"
        elif type1 == 'default_originate_ipv6_vrf':
                # convert to REST as and when used
                my_cmd = 'router bgp {} vrf {}\n'.format(kwargs['local_as'],vrf_name)
                my_cmd += 'address-family l2vpn evpn\n'
                my_cmd += '{} default-originate ipv6\n'.format(config_cmd)
                if cli_type == 'klish':
                    my_cmd += "exit\n"
        elif type1 == 'advertise_ipv4_vrf':
            if cli_type in ["rest-put", "rest-patch"]:
                if config.lower() == 'yes':
                    url = rest_urls['bgp_advertise_config'].format(vrf_name)
                    payload = {'openconfig-bgp-evpn-ext:advertise-list':['IPV4_UNICAST']}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-ipv4 in vrf:{} config Failed'.format(vrf_name))
                        return False
                elif config.lower() == 'no':
                    url = rest_urls['bgp_advertise_config'].format(vrf_name)
                    if not delete_rest(dut, rest_url=url):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-ipv4 in vrf:{} delete Failed'.format(vrf_name))
                        return False
            else:
                my_cmd = 'router bgp {} vrf {}\n'.format(kwargs['local_as'],vrf_name)
                my_cmd += 'address-family l2vpn evpn\n'
                my_cmd += '{} advertise ipv4 {}\n'.format(config_cmd,advertise_ipv4)
                if cli_type == 'klish':
                    my_cmd += "exit\n"
        elif type1 == 'advertise_ipv6_vrf':
            if cli_type in ["rest-put", "rest-patch"]:
                if config.lower() == 'yes':
                    url = rest_urls['bgp_advertise_config'].format(vrf_name)
                    payload = {'openconfig-bgp-evpn-ext:advertise-list': ['IPV6_UNICAST']}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-ipv6 in vrf:{} config Failed'.format(vrf_name))
                        return False
                elif config.lower() == 'no':
                    url = rest_urls['bgp_advertise_config'].format(vrf_name)
                    if not delete_rest(dut, rest_url=url):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-ipv6 in vrf:{} delete Failed'.format(vrf_name))
                        return False
            else:
                my_cmd = 'router bgp {} vrf {}\n'.format(kwargs['local_as'],vrf_name)
                my_cmd += 'address-family l2vpn evpn\n'
                my_cmd += '{} advertise ipv6 {}\n'.format(config_cmd,advertise_ipv6)
                if cli_type == 'klish':
                    my_cmd += "exit\n"
        elif type1 == 'vrf_rd_rt':
            if cli_type in ["rest-put", "rest-patch"]:
                if 'l3_rd' in kwargs:
                    url = rest_urls['bgp_route_distinguisher'].format(vrf_name)
                    if config.lower() == 'yes':
                        payload = {'openconfig-bgp-evpn-ext:route-distinguisher': kwargs['l3_rd']}
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN route-distinguisher config Failed')
                            return False
                    elif config.lower() == 'no':
                        if not delete_rest(dut, rest_url=url):
                            st.banner('FAIL-OCYANG: BGP EVPN route-distinguisher delete Failed')
                            return False
                if 'l3_both_rt' in kwargs:
                    url_i = rest_urls['bgp_import_rt'].format(vrf_name)
                    url_e = rest_urls['bgp_export_rt'].format(vrf_name)
                    if config.lower() == 'yes':
                        payload = {'openconfig-bgp-evpn-ext:import-rts': [kwargs['l3_both_rt']]}
                        if not config_rest(dut, http_method=cli_type, rest_url=url_i, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN import rt config Failed')
                            return False
                        payload = {'openconfig-bgp-evpn-ext:export-rts': [kwargs['l3_both_rt']]}
                        if not config_rest(dut, http_method=cli_type, rest_url=url_e, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN export rt config Failed')
                            return False
                    elif config.lower() == 'no':
                        if not delete_rest(dut, rest_url=url_i):
                            st.banner('FAIL-OCYANG: BGP EVPN import rt delete Failed')
                            return False
                        if not delete_rest(dut, rest_url=url_e):
                            st.banner('FAIL-OCYANG: BGP EVPN export rt delete Failed')
                            return False
                if 'l3_import_rt' in kwargs:
                    url = rest_urls['bgp_import_rt'].format(vrf_name)
                    if config.lower() == 'yes':
                        payload = {'openconfig-bgp-evpn-ext:import-rts': [kwargs['l3_import_rt']]}
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN import rt config Failed')
                            return False
                    elif config.lower() == 'no':
                        if not delete_rest(dut, rest_url=url):
                            st.banner('FAIL-OCYANG: BGP EVPN import rt delete Failed')
                            return False
                if 'l3_export_rt' in kwargs:
                    url = rest_urls['bgp_export_rt'].format(vrf_name)
                    if config.lower() == 'yes':
                        payload = {'openconfig-bgp-evpn-ext:export-rts': [kwargs['l3_export_rt']]}
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN export rt config Failed')
                            return False
                    elif config.lower() == 'no':
                        if not delete_rest(dut, rest_url=url):
                            st.banner('FAIL-OCYANG: BGP EVPN export rt delete Failed')
                            return False
            else:
                my_cmd = 'router bgp {} vrf {}\n'.format(kwargs['local_as'],vrf_name)
                my_cmd += 'address-family l2vpn evpn\n'
                if 'l3_rd' in kwargs:
                    my_cmd += '{} rd {}\n'.format(config_cmd,kwargs['l3_rd'])
                if 'l3_both_rt' in kwargs:
                    my_cmd += '{} route-target both {}\n'.format(config_cmd,kwargs['l3_both_rt'])
                if 'l3_import_rt' in kwargs:
                    my_cmd += '{} route-target import {}\n'.format(config_cmd,kwargs['l3_import_rt'])
                if 'l3_export_rt' in kwargs:
                    my_cmd += '{} route-target export {}\n'.format(config_cmd,kwargs['l3_export_rt'])
                if cli_type == 'klish':
                    my_cmd += "exit\n"
        elif type1 == 'advertise_all_vni':
            if cli_type in ["rest-put", "rest-patch"]:
                if config.lower() == 'yes':
                    url = rest_urls['bgp_advertise_all_vni'].format(vrf_name)
                    payload = { 'openconfig-bgp-evpn-ext:advertise-all-vni': True}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-all-vni config Failed')
                        return False
                elif config.lower() == 'no':
                    url = rest_urls['bgp_advertise_all_vni'].format(vrf_name)
                    if not delete_rest(dut, rest_url=url):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-all-vni delete Failed')
                        return False
            else:
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += '{} advertise-all-vni\n'.format(config_cmd)
                if cli_type == 'klish':
                    my_cmd += "exit\n"
        elif type1 == 'advertise_default_gw':
            if cli_type in ["rest-put", "rest-patch"]:
                if config.lower() == 'yes':
                    url = rest_urls['bgp_advertise_default_gw'].format(vrf_name)
                    payload = {'openconfig-bgp-evpn-ext:advertise-default-gw': True}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-default-gw config Failed')
                        return False
                elif config.lower() == 'no':
                    url = rest_urls['bgp_advertise_default_gw'].format(vrf_name)
                    if not delete_rest(dut, rest_url=url):
                        st.banner('FAIL-OCYANG: BGP EVPN advertise-default-gw delete Failed')
                        return False
            else:
                my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
                my_cmd += '{} advertise-default-gw\n'.format(config_cmd)
                if cli_type == 'klish':
                    my_cmd += "exit\n"
        elif type1 == 'autort':
            # convert to REST as and when used
            my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            my_cmd += '{} autort rfc8365-compatible\n'.format(config_cmd)
            if cli_type == 'klish':
                my_cmd += "exit\n"
        elif type1 == 'default_originate_ipv4':
            # convert to REST as and when used
            my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            my_cmd += '{} default-originate ipv4\n'.format(config_cmd)
            if cli_type == 'klish':
                my_cmd += "exit\n"
        elif type1 == 'default_originate_ipv6':
            # convert to REST as and when used
            my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            my_cmd += '{} default-originate ipv6\n'.format(config_cmd)
            if cli_type == 'klish':
                my_cmd += "exit\n"
        elif type1 == 'dup_addr_detection':
            # convert to REST as and when used
            my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            my_cmd += '{} dup-addr-detection {}\n'.format(config_cmd,dup_addr_detection)
            if cli_type == 'klish':
                my_cmd += "exit\n"
        elif type1 == 'flooding_disable':
            # convert to REST as and when used
            my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            my_cmd += '{} flooding disable\n'.format(config_cmd)
            if cli_type == 'klish':
                my_cmd += "exit\n"
        elif type1 == 'flooding_head_end_replication':
            # convert to REST as and when used
            my_cmd += "address-family l2vpn {}\n".format(addr_family_modifier)
            my_cmd += '{} flooding head-end-replication\n'.format(config_cmd)
            if cli_type == 'klish':
                my_cmd += "exit\n"
        elif type1 == 'network' and config_cmd == '':
            # convert to REST as and when used
            if cli_type not in ['klish']:
                my_cmd += 'network {} rd {} ethtag {} label {} esi {} gwip {} routermac {}\n'.format(network,rd,ethtag,bgp_label,esi_id,gw_ip,router_mac)
            else:
                st.error("Support not added to config - 'network'")
        elif type1 == 'network' and config_cmd == 'no':
            # convert to REST as and when used
            if cli_type not in ['klish']:
                my_cmd += '{} network {} rd {} ethtag {} label {} esi {} gwip {}\n'.format(config_cmd,network,rd,ethtag,bgp_label,esi_id,gw_ip)
            else:
                st.error("Support not added to config - 'network'")
        elif type1 == 'route_target':
            # convert to REST as and when used
            if 'both_rt' in kwargs:
                my_cmd += '{} route-target both {}\n'.format(config_cmd,kwargs['both_rt'])
            if 'import_rt' in kwargs:
                my_cmd += '{} route-target import {}\n'.format(config_cmd,kwargs['import_rt'])
            if 'export_rt' in kwargs:
                my_cmd += '{} route-target export {}\n'.format(config_cmd,kwargs['export_rt'])
            if cli_type == 'klish':
                my_cmd += "exit\n"
        elif type1 == 'vni':
            if cli_type in ["rest-put", "rest-patch"]:
                if config.lower() == 'yes':
                    url_vni = rest_urls['bgp_vni_config'].format(vrf_name)
                    payload = {'openconfig-bgp-evpn-ext:vni': [{
                                'vni-number': int(kwargs['vni']) ,
                                'config':{
                                    'vni-number': int(kwargs['vni']) ,
                                    'advertise-default-gw': True
                                }
                                }]
                            }
                    if not config_rest(dut, http_method=cli_type, rest_url=url_vni, json_data=payload):
                        st.banner('FAIL-OCYANG: BGP EVPN vni config Failed')
                        return False
                if vni_unconfig == 'no':
                    url_vni = rest_urls['bgp_vni_unconfig'].format(vrf_name,kwargs['vni'])
                    if not delete_rest(dut, rest_url=url_vni):
                        st.banner('FAIL-OCYANG: BGP EVPN vni delete Failed')
                        return False
                if 'vni_rd' in kwargs and vni_unconfig == '':
                    url = rest_urls['bgp_vni_route_distinguisher'].format(vrf_name,kwargs['vni'])
                    if config.lower() == 'yes':
                        payload = {'openconfig-bgp-evpn-ext:route-distinguisher': kwargs['vni_rd']}
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN vni route-distinguisher config Failed')
                            return False
                    elif config.lower() == 'no':
                        if not delete_rest(dut, rest_url=url):
                            st.banner('FAIL-OCYANG: BGP EVPN vni route-distinguisher delete Failed')
                            return False
                if 'vni_both_rt' in kwargs and vni_unconfig == '':
                    url_i = rest_urls['bgp_vni_import_rt'].format(vrf_name,kwargs['vni'])
                    url_e = rest_urls['bgp_vni_export_rt'].format(vrf_name,kwargs['vni'])
                    if config.lower() == 'yes':
                        payload = {'openconfig-bgp-evpn-ext:import-rts': [kwargs['vni_both_rt']]}
                        if not config_rest(dut, http_method=cli_type, rest_url=url_i, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN vni import rt config Failed')
                            return False
                        payload = {'openconfig-bgp-evpn-ext:export-rts': [kwargs['vni_both_rt']]}
                        if not config_rest(dut, http_method=cli_type, rest_url=url_e, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN vni export rt config Failed')
                            return False
                    elif config.lower() == 'no':
                        if not delete_rest(dut, rest_url=url_i):
                            st.banner('FAIL-OCYANG: BGP EVPN vni import rt delete Failed')
                            return False
                        if not delete_rest(dut, rest_url=url_e):
                            st.banner('FAIL-OCYANG: BGP EVPN vni export rt delete Failed')
                            return False
                if 'vni_import_rt' in kwargs and vni_unconfig == '':
                    url_i = rest_urls['bgp_vni_import_rt'].format(vrf_name, kwargs['vni'])
                    if config.lower() == 'yes':
                        payload = {'openconfig-bgp-evpn-ext:import-rts': [kwargs['vni_import_rt']]}
                        if not config_rest(dut, http_method=cli_type, rest_url=url_i, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN vni import rt config Failed')
                            return False
                    elif config.lower() == 'no':
                        if not delete_rest(dut, rest_url=url_i):
                            st.banner('FAIL-OCYANG: BGP EVPN vni import rt delete Failed')
                            return False
                if 'vni_export_rt' in kwargs and vni_unconfig == '':
                    url_e = rest_urls['bgp_vni_export_rt'].format(vrf_name, kwargs['vni'])
                    if config.lower() == 'yes':
                        payload = {'openconfig-bgp-evpn-ext:export-rts': [kwargs['vni_export_rt']]}
                        if not config_rest(dut, http_method=cli_type, rest_url=url_e, json_data=payload):
                            st.banner('FAIL-OCYANG: BGP EVPN vni export rt config Failed')
                            return False
                    elif config.lower() == 'no':
                        if not delete_rest(dut, rest_url=url_e):
                            st.banner('FAIL-OCYANG: BGP EVPN vni export rt delete Failed')
                            return False
            else:
                my_cmd += '{} vni {}\n'.format(vni_unconfig,kwargs['vni'])
                if 'vni_rd' in kwargs and vni_unconfig == '':
                    my_cmd += '{} rd {}\n'.format(config_cmd,kwargs['vni_rd'])
                if 'vni_both_rt' in kwargs and vni_unconfig == '':
                    my_cmd += '{} route-target both {}\n'.format(config_cmd,kwargs['vni_both_rt'])
                if 'vni_import_rt' in kwargs and vni_unconfig == '':
                    my_cmd += '{} route-target import {}\n'.format(config_cmd,kwargs['vni_import_rt'])
                if 'vni_export_rt' in kwargs and vni_unconfig == '':
                    my_cmd += '{} route-target export {}\n'.format(config_cmd,kwargs['vni_export_rt'])
                if vni_unconfig != 'no':
                    my_cmd += 'exit\n'
                if cli_type == 'klish':
                    my_cmd += "exit\n"
        else:
            st.error("config_type_list is not matching - {}".format(type1))
            return False
    if cli_type in ['klish'] and cur_type != 'vrf_vni':
        #my_cmd += 'exit\n'
        my_cmd += 'exit\n'

    if cli_type not in ['rest-put', 'rest-patch']:
        st.debug('\n'+my_cmd+'\n')
        st.debug(my_cmd.split("\n"))

        st.config(dut, my_cmd.split("\n") if cli_type == 'klish' else my_cmd, type=cli_type)

def parse_rest_output_l2vpn_evpn_vni(response):
    dict = {}
    vni_data = response['output'].get('openconfig-bgp-evpn-ext:vni',[])
    if vni_data:
        vni_item = vni_data[0]
        dict['vni'] = str(vni_item.get('state',{}).get('vni-number',0))
        dict['type'] = vni_item.get('state',{}).get('type','')
        dict['vrfname'] =  ''
        dict['rd'] = vni_item.get('state',{}).get('route-distinguisher','')
        dict['originip'] = vni_item.get('state',{}).get('originator','')
        dict['gwmac'] = vni_item.get('state',{}).get('advertise-gw-mac',False)
        dict['rt'] = vni_item.get('state',{}).get('import-rts',[])
        dict['rt'] = dict['rt']  + vni_item.get('state', {}).get('export-rts', [])
        return [dict]
    else:
        return []

def verify_bgp_l2vpn_evpn_vni_id(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_vni_id(dut=dut1,vni="100",rd="11:11",type="L2",vrfname="default",originip="1.1.1.1",gwmac="No",rt=['20:20','20:20'])

    To verify bgp l2vpn evpn vni <vni-id>
    :param dut:
    :param vni:
    :param type:
    :param vrfname:
    :param rd:
    :param rt:
    :param gwmac:
    :param originip:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "vtysh" if cli_type == 'click' else cli_type
    #cli_type = 'klish'
    if 'vni' not in kwargs:
        st.error("Mandatory arg vni is not present")
        return False

    if cli_type in ['rest-put', 'rest-patch']:
        st.log('KLISH output for debugging REST')
        st.show(dut, "show bgp l2vpn evpn vni {}".format(kwargs['vni']), type='klish')
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['bgp_vni_unconfig'].format('default',kwargs['vni'])
        response = get_rest(dut, rest_url=url)
        if response['output']:
            result = parse_rest_output_l2vpn_evpn_vni(response)
        else:
            st.error("OCYANG-FAIL: verify bgp l2vpn evpn vni <id> - Get Response is empty")
            return False
    else:
        result = st.show(dut, "show bgp l2vpn evpn vni {}".format(kwargs['vni']), type=cli_type)

    if len(result) == 0:
        st.error("Output is Empty")
        return False

    ret_val = False

    for rlist in result:
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key]:
                count = count + 1
        if len(kwargs) == count:
            ret_val = True
            for key in kwargs:
                st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
            break
        else:
            for key in kwargs:
                if rlist[key] == kwargs[key]:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                else:
                    st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

    if ret_val is False:
        st.log("Fail: Not Matched all args in passed dict {} from parsed dict".format(kwargs))

    return ret_val


def verify_bgp_l2vpn_evpn_summary(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_summary(dut=dut1,identifier="1.1.1.1",local_as="10",vrf_id="0",neighbor="21.1.1.2",version="4",pfxrcd="1",inq="0",outq="0",tblver="0",msgrcvd="3552")
    verify_bgp_l2vpn_evpn_summary(dut=dut1,neighbor=["21.1.1.2","2001::2"],version=["4","4"],pfxrcd=["1","1"],inq=["0","0"],outq=["0","0"],tblver=["0","0"],as_no=["20","20"])

    To verify bgp l2vpn evpn summary
    :param dut:
    :param identifier:
    :param local_as:
    :param vrf_id:
    :param neighbor:
    :param version:
    :return:
    :reteturn:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type == 'click':
        cli_type = "vtysh"
    if cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["get_evpn_neigh"]
        rest_out = get_rest(dut, rest_url=url, timeout=30)
        if rest_out["status"] == 200:
            no_match=match=False
            for key, val in kwargs.items():
                if type(val) is not list:
                    kwargs[key] = [val]
            rest_out = rest_out["output"]["openconfig-network-instance:neighbors"]["neighbor"]
            for elem in rest_out:
                neigh_list = elem['afi-safis']['afi-safi']
                for neigh in neigh_list:
                    if neigh["state"]['afi-safi-name'] == "openconfig-bgp-types:L2VPN_EVPN":
                        evpn_neigh = elem['neighbor-address']
                        if 'neighbor' in kwargs:
                            try:
                                index_num = kwargs["neighbor"].index(evpn_neigh)
                                exp_status=kwargs["updown"][index_num]
                                if neigh['state']['prefixes']['received'] >= 0:
                                    status="up"
                                else:
                                    status="down"
                                if exp_status==status:
                                    st.log("Match found for neighbor {} with status as {}".format(evpn_neigh,status))
                                    match=True
                                else:
                                    st.log("Match NOT found for neighbor {}; expected status: {}"
                                           " but found: {}".format(evpn_neigh,exp_status,status))
                                    no_match=True
                            except Exception:
                                continue
                        else:
                                st.log("specify the neighbor argument to be verified ")
                                return False
            if no_match:
                st.log("At least one of the neighbor status is wrong;"
                       "kindly check above logs")
                return False
            if match:
                return True
            else:
                st.log("Neighbors {} not present in show output".format(kwargs["neighbor"]))
                return False
    else:
        output = st.show(dut,"show bgp l2vpn evpn summary",type=cli_type)
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        for i in range (len(output)):
            pfx = output[i]['pfxrcd']
            if pfx.isdigit():
                if int(output[i]['pfxrcd']) > 0 or int(output[i]['pfxrcd']) == 0:
                    output[i]['updown'] = 'up'
                else:
                    output[i]['updown'] = 'down'
            else:
                output[i]['updown'] = 'down'

        count = 0
        no_common_key = 0
        ret_val1 = False
        dict1 = {}
        common_key_list = ['identifier','local_as','vrf_id','rib_entries','no_peers']

        for key in kwargs:
            if key in common_key_list:
                no_common_key = no_common_key + 1

        if no_common_key > 0:
            rlist = output[0]
            count = 0
            for key in kwargs:
                if rlist[key] == kwargs[key] and key in common_key_list:
                    count = count + 1
            if no_common_key == count:
                ret_val1 = True
                for key in kwargs:
                    if key in common_key_list:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
            else:
                for key in kwargs:
                    if key in common_key_list:
                        if rlist[key] == kwargs[key]:
                            st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                        else:
                            st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
                st.log("\n")

            for key in common_key_list:
                if key in kwargs:
                    dict1[key] = kwargs[key]
                    del kwargs[key]

        if no_common_key > 0 and ret_val1 is False:
            st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
            return ret_val1

        ret_val = "True"
        #Converting all kwargs to list type to handle single or list of instances
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        input_dict_list =[]
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

        return ret_val

def parse_rest_output_l2vpn_evpn_route(route):
    dict = {}
    dict['evpn_prefix'] = route.get('prefix','')
    rd_str = route.get('route-distinguisher','')
    regexp_match = re.search(r"\d+\:\d+|\d+\.\d+\.\d+\.\d+", rd_str)
    dict['rd'] = regexp_match.group() if regexp_match else ''
    dict['status_code'] = '*' if route.get("state",{}).get('valid-route',False) else ''
    if route.get("state",{}).get('openconfig-rib-bgp-ext:best-path',False):
        dict['status_code'] += '>'
    dict['next_hop'] = route.get("attr-sets",{}).get("next-hop",'')
    route_as_list = route.get("attr-sets",{}).get('as-path',{}).get('as-segment',[])
    as_list = route_as_list[0].get('state',[]).get('member',[]) if route_as_list else []
    as_path = ''
    for as_num in as_list:
        as_path = as_path + str(as_num) + " "
    as_path = as_path.strip()
    dict["path"] = as_path

    return dict



def verify_bgp_l2vpn_evpn_route(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_route(dut=dut1,evpn_prefix="[5]:[0]:[24]:[15.1.1.0]",rd="13:2",status_code="*>",metric="0",next_hop="0.0.0.0",weight="32768",path="",origin_code="i",displayed_prefixes="5",no_of_paths="5",bgp_version="1",router_id="1.1.1.1")
    verify_bgp_l2vpn_evpn_route(dut=dut1,evpn_prefix="[3]:[0]:[32]:[11.1.1.1]",rd="1.1.1.1:2",status_code="*>",metric="3276",next_hop="11.1.1.1",weight="8",path="",origin_code="i",displayed_prefixes="5",no_of_paths="5",bgp_version="1",router_id="1.1.1.1")
    verify_bgp_l2vpn_evpn_route(dut=dut1,evpn_prefix="[2]:[0]:[48]:[00:21:ee:00:10:17]:[32]:[59.1.1.7]",rd="1.1.1.1:2",status_code="*>",metric="",next_hop="11.1.1.1",weight="32768",path="",origin_code="i")

    To verify bgp l2vpn evpn route
    :param dut:
    :param bgp_verion:
    :param router_id:
    :param evpn_prefix:
    :param rd:
    :param path:
    :param status_code:
    :param weight:
    :param metric:
    :param next_hop:
    :param origin_code:
    :param displayed_prefixes:
    :param no_of_paths:
    :return:
    :reteturn:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "vtysh" if cli_type == 'click' else cli_type
    #cli_type = 'klish'
    if cli_type in ['rest-put', 'rest-patch']:
        st.log('KLISH output for debugging REST')
        st.show(dut, "show bgp l2vpn evpn route", type='klish')
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['get_evpn_routes']
        response = get_rest(dut, rest_url=url)
        if response['output']:
            route_list = response["output"].get("openconfig-bgp-evpn-ext:routes",{}).get("route",[])
            output = []
            for route in route_list:
                out_dict = {}
                try:
                    if 'evpn_prefix' in kwargs:
                        if kwargs['evpn_prefix'] == route['prefix']:
                            out_dict = parse_rest_output_l2vpn_evpn_route(route)
                    elif 'rd' in kwargs:
                        rd_str = route.get('route-distinguisher', '')
                        regexp_match = re.search(r"\d+\:\d+|\d+\.\d+\.\d+\.\d+", rd_str)
                        current_rd =  regexp_match.group() if regexp_match else ''
                        if kwargs['rd'] == current_rd :
                            out_dict = parse_rest_output_l2vpn_evpn_route(route)
                    output.append(out_dict)
                except Exception as e:
                    st.log("{}".format(e))
                    continue
        else:
            st.error("OCYANG-FAIL: show bgp l2vpn evpn route - Get Response is empty")
            return False
        skip_key_list = ['bgp_version', 'router_id', 'metric', 'weight', 'origin_code', 'rt', 'et', 'rmac',
                         'displayed_prefixes', 'no_of_paths']
        for skip_key in skip_key_list:
            if skip_key in kwargs:
                del kwargs[skip_key]
    else:
        output = st.show(dut, "show bgp l2vpn evpn route", type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    for a in output:
        for key in a:
            output[output.index(a)][key]=output[output.index(a)][key].lstrip()
            output[output.index(a)][key]=output[output.index(a)][key].rstrip()

    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['bgp_version','router_id','displayed_prefixes','no_of_paths']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val


def verify_bgp_l2vpn_evpn_vni(dut,**kwargs):
    ### NOT USED
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_vni(dut=dut1,vni="100",rd="11:11",type="L2",tenant_vrf="default",import_rt='20:20',export_rt='20:20',gw_macip="Enabled")
    verify_bgp_l2vpn_evpn_vni(dut=dut1,vni="200",rd="15:15",type="L2",tenant_vrf="default",import_rt='5:5',export_rt='6:6',gw_macip="Enabled")
    verify_bgp_l2vpn_evpn_vni(dut=dut1,vni=["100","200"],rd=["11:11","15:15"],type=["L2","L2"],tenant_vrf=["default","default"],import_rt=['20:20','5:5'],export_rt=['20:20','6:6'])

    To verify bgp l2vpn evpn vni
    :param dut:
    :param vni:
    :param type:
    :param tenant_vrf:
    :param rd:
    :param bum_flooding:
    :param all_vni_flag:
    :param no_l2vni:
    :param no_l3vni:
    :param gw_macip:
    :param import_rt:
    :param export_rt:
    :return:
    :reteturn:
    """
    output = st.show(dut,"show bgp l2vpn evpn  vni",type="vtysh")
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['gw_macip','all_vni_flag','bum_flooding','no_l2vni','no_l3vni']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val


def verify_bgp_l2vpn_evpn_rd(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_rd(dut=dut1,evpn_type_5_prefix="[5]:[0]:[24]:[15.1.1.0]",rd="13:1",rd_name="as2",status_code="*>",metric="0",next_hop="0.0.0.0",weight="32768",origin_code="i",displayed_prefixes="1")

    To verify bgp l2vpn evpn rd <rd-value>
    :param dut:
    :param evpn_type_2_prefix:
    :param evpn_type_3_prefix:
    :param evpn_type_4_prefix:
    :param evpn_type_5_prefix:
    :param rd:
    :param rd_name:
    :param status_code:
    :param metric:
    :param next_hop:
    :param origin_code:
    :param displayed_prefixes:
    :param total_prefixes:
    :return:
    :reteturn:
    """
    if 'rd' not in kwargs:
        st.error("Mandetory arg rd is not present")
        return False

    output = st.show(dut,"show bgp l2vpn evpn rd {}".format(kwargs['rd']),type="vtysh")
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    for a in output:
        for key in a:
            output[output.index(a)][key]=output[output.index(a)][key].lstrip()
            output[output.index(a)][key]=output[output.index(a)][key].rstrip()

    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['rd_name','rd','displayed_prefixes','total_prefixes']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val


def verify_bgp_l2vpn_evpn_route_type_prefix(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_route_type_prefix(dut=dut1,evpn_type_5_prefix="[5]:[0]:[24]:[15.1.1.0]",rd="13:1",rd_name="as2",status_code="*>",metric="0",next_hop="0.0.0.0",weight="32768",origin_code="i",displayed_prefixes="1")
    evpn.verify_bgp_l2vpn_evpn_route_type_prefix(dut=data.dut1,evpn_type_5_prefix="[5]:[0]:[24]:[26.1.1.0]",rd="13:2",status_code="*>",metric="0",next_hop="0.0.0.0",weight="0",path="20",origin_code="i",displayed_prefixes="4",no_of_paths="6")

    To verify bgp l2vpn evpn route type prefix
    :param dut:
    :param evpn_type_5_prefix:
    :param rd:
    :param path:
    :param status_code:
    :param weight:
    :param metric:
    :param next_hop:
    :param origin_code:
    :param displayed_prefixes:
    :param no_of_paths:
    :return:
    :reteturn:
    """
    output = st.show(dut,"show bgp l2vpn evpn route type prefix",type="vtysh")
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['bgp_version','router_id','displayed_prefixes','no_of_paths']

    for a in output:
        for key in a:
            output[output.index(a)][key]=output[output.index(a)][key].lstrip()
            output[output.index(a)][key]=output[output.index(a)][key].rstrip()

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val




def create_overlay_intf(dut, vtep_name, ip_addr, config='yes', skip_error=False, cli_type=''):
    """
    purpose:
            This definition is used to create overlay interface

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param vtep_name: VTEP name to be created
    :type vtep_name: string
    :param ip_addr: ip address to be bound to overlay gateway
    :type ip_addr: string
    :param config: it takes value as 'yes' or 'no' to configure or remove overlay respectively
    :type config: string
    :param : cli_type
    :return: None

    usage:
        create_overlay_intf(dut1, "dut1VTEP", "1.1.1.1", cli_type='click')
        create_overlay_intf(dut1, "dut1VTEP", "1.1.1.1", config='no', cli_type='klish')

    Created by: Julius <julius.mariyan@broadcom.com
    """
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    if config == 'yes':
        conf_str = ''
        action = 'add'
    else:
        conf_str = 'no'
        ip_addr = ''
        action = 'del'

    if cli_type == 'click':
        command = "config vxlan {} {} {}".format(action, vtep_name, ip_addr)

    elif cli_type == 'klish':
        command = []
        command.append('interface vxlan {}'.format(vtep_name))
        command.append('{} source-ip {}'.format(conf_str, ip_addr))
        command.append('exit')
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")

        if config == 'yes':
            url = rest_urls['config_vxlan_with_ip']
            payload = { "openconfig-interfaces:interface":
                        [ {  "name": vtep_name,
                             "config": {  "name": vtep_name,  "type": "IF_NVE" },
                             "openconfig-vxlan:vxlan-if": { "config": { "source-vtep-ip": ip_addr } }
                             } ]
                     }
            ### PUT and PATCH doesn't work for this URI hence use POST
            ### PUT and PATCH URIs does config similar to klish clis
            if not config_rest(dut, http_method='post', rest_url=url, json_data=payload):
                st.banner('FAIL-OCYANG: Create Vxlan Interface with src vtep IP failed')
                return False
        else:
            url = rest_urls['delete_vxlan_ip'].format(vtep_name)
            if not delete_rest(dut, rest_url=url):
                st.banner('FAIL-OCYANG')
            url = rest_urls['delete_vxlan'].format(vtep_name)
            if not delete_rest(dut, rest_url=url):
                st.banner('FAIL-OCYANG')
        return
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    st.debug(command)
    return st.config(dut, command, type=cli_type, skip_error_check=skip_error)


def create_evpn_instance(dut, nvo_name, vtep_name, config='yes', skip_error=False, cli_type=''):
    """
    purpose:
            This definition is used to create EVPN instance

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param nvo_name: evpn instance name to be created
    :type nvo_name: string
    :param vtep_name: vtep name to be bound to evpn instance
    :type vtep_name: string
    :param config: it takes value as 'yes' or 'no' to configure or remove evpn instance respectively
    :type config: string
    :param : cli_type
    :param : skip_error
    :return: None

    usage:
        create_evpn_instance(dut1, "dut1EVPN", "dut1VTEP", cli_type='click')
        create_evpn_instance(dut1, "dut1EVPN", "dut1VTEP", config='no', cli_type='klish')

    Created by: Julius <julius.mariyan@broadcom.com
    """
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    if config == 'yes':
        action = 'add'
    else:
        vtep_name = ''
        action = 'del'

    if cli_type == 'click':
        command = "config vxlan evpn_nvo {} {} {}".format(action, nvo_name, vtep_name)
        st.debug(command)
        return st.config(dut, command, skip_error_check=skip_error, type=cli_type)
    elif cli_type == 'klish':
        st.error("NVO command is not supported in klish")
        return False
    elif cli_type in ['rest-put','rest-patch']:
        st.error("NVO config through OCYANG URI not supported")
        return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False



def map_vlan_vni(dut, vtep_name, vlan_id, vni_id, range_val='1', config='yes', skip_error=False, cli_type=''):
    """
    purpose:
            This definition is used to create VLAN to VNI mapping under EVPN instance

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param vtep_name: VTEP name where VLAN to VNI mapping needs to be done
    :type vtep_name: string
    :param vlan_id: vlan id to be mapped to VNI
    :type vlan_id: string
    :param vni_id: VNI id where vlan to be mapped
    :type vni_id: string
    :param range_val: range of vlans to be mapped to VNI
    :type range_val: string
    :param config: it takes value as 'yes' or 'no' to configure or remove evpn instance respectively
    :type config: string
    :param : cli_type
    :param : skip_error
    :return: None

    usage:
        map_vlan_vni(dut1, "dut1VTEP", "100", "100", cli_type='click')
        map_vlan_vni(dut1, "dut1VTEP", "100", "100", config="no", cli_type='click')
        map_vlan_vni(dut1, "dut1VTEP", "100", "100", range="10")
        map_vlan_vni(dut1, "dut1VTEP", "100", "100", range="10", config="no")

    Created by: Julius <julius.mariyan@broadcom.com
    """
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    range_val = int(range_val)
    if config == 'yes':
        conf_str = ''
        action = 'add'
    else:
        conf_str = 'no'
        action = 'del'

    if cli_type == 'click':
        if range_val > 1:
            vlan_end = int(vlan_id) + range_val - 1
            command = "config vxlan map_range {} {} {} {} {}".format(action, vtep_name, vlan_id, vlan_end, vni_id)
        elif range_val == 1:
            command = "config vxlan map {} {} {} {}".format(action, vtep_name, vlan_id, vni_id)

    elif cli_type == 'klish':
        command = []
        command.append('interface vxlan {}'.format(vtep_name))
        if range_val == 1:
            command.append('{} map vni {} vlan {}'.format(conf_str, vni_id, vlan_id))
        elif range_val > 1:
            command.append('{} map vni {} vlan {} count {}'.format(conf_str, vni_id, vlan_id, range_val))
        command.append('exit')

    elif cli_type in ['rest-put','rest-patch']:

        if range_val == 1:
            rest_urls = st.get_datastore(dut, "rest_urls")
            vlan_data = str(vlan_id) if type(vlan_id) is not str else vlan_id
            vlan_str = 'Vlan'+vlan_data
            vni_id = int(vni_id) if type(vni_id) is not int else vni_id
            if config == 'yes':
                url = rest_urls['config_vlan_vni_mapping'].format(vlan_str)
                payload = { "openconfig-vxlan:vni-instance":
                            [{"vni-id": vni_id,
                              "source-nve": vtep_name,
                              "config": {"vni-id": vni_id, "source-nve": vtep_name}
                                }]
                            }
                response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload,get_response=True)
                error_list = response['output'].get('ietf-restconf:errors', {}).get('error', [])
                if error_list:
                    err_msg = error_list[0].get('error-message', '')
                    st.banner('FAIL-OCYANG: vlan-vni map failed')
                    return err_msg
            else:
                url = rest_urls['delete_vlan_vni_mapping'].format(vlan_str,vni_id,vtep_name)
                if not delete_rest(dut, rest_url=url):
                    st.banner('FAIL-OCYANG')
                    return False
            return
        elif range_val > 1:
            ### In case of range , need to call above URI multiple times, instead fallback to klish
            cli_type = 'klish'
            command = []
            command.append('interface vxlan {}'.format(vtep_name))
            command.append('{} map vni {} vlan {} count {}'.format(conf_str, vni_id, vlan_id, range_val))
            command.append('exit')
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    st.debug(command)
    return st.config(dut, command, skip_error_check=skip_error, type=cli_type)



def parse_rest_output_vxlan_tunnel(response):
    tunnel_list = response['output'].get('openconfig-vxlan:vxlan-tunnel-infos',{}).get('vxlan-tunnel-info',[])
    tunnel_count = len(tunnel_list)
    result = []
    for tunnel in tunnel_list:
        dict = {}
        dict['total_count'] = tunnel_count
        dict['src_vtep'] = tunnel.get('state',{}).get('source-ip',"")
        dict['rem_vtep'] = tunnel.get('state',{}).get('peer-ip',"")
        tunnel_status = tunnel.get('state',{}).get('status',"")
        if tunnel_status == 'UP':
            dict['tun_status'] = 'oper_up'
        elif tunnel_status == 'DOWN':
            dict['tun_status'] = 'oper_down'
        else:
            ## To handle later for any other type
            dict['tun_status'] = tunnel['state']['status']
        result.append(dict)
    return result

def verify_vxlan_tunnel_status(dut, src_vtep, rem_vtep_list, exp_status_list, cli_type=''):
    '''
    purpose:
            This definition is used to verify operational status of VxLAN tunnel

    Arguments:
    :param dut: Device name where the command to be executed
    :type dut: string
    :param src_vtep: ip address of local VTEP
    :type src_vtep: string
    :param rem_vtep_list: list of remote VTEP ip address
    :type rem_vtep_list: string
    :param exp_status_list: list of expected operational status of VTEP's; example ['oper_down','oper_up']
    :type exp_status_list: list
    :return: True/False  True - success case; False - Failure case

    usage:  verify_vxlan_tunnel_status(dut1,'1.1.1.1',['2.2.2.2','3.3.3.3'],['oper_up','oper_up'])
            verify_vxlan_tunnel_status(dut1,'1.1.1.1',['2.2.2.2','3.3.3.3'],['oper_down','oper_up'])

    Created by: Julius <julius.mariyan@broadcom.com
    '''
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    success = True
    if cli_type in ['click','klish']:
        cli_out = st.show(dut, 'show vxlan tunnel', type=cli_type)
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['vxlan_tunnel_info']
        response = get_rest(dut, rest_url=url)
        if response['output']:
            cli_out = parse_rest_output_vxlan_tunnel(response)
        else:
            st.error("OCYANG-FAIL: verify vxlan tunnel - Get Response is empty")
            return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    for rem_vtep,status in zip(rem_vtep_list,exp_status_list):
        fil_out = filter_and_select(cli_out, ["tun_status"], {"src_vtep" : src_vtep,
                                                              "rem_vtep" : rem_vtep})
        if not fil_out:
            st.error('No entry found for source VTEP: {} and remote VTEP: {} in '
                     'output: {}'.format(src_vtep,rem_vtep,cli_out))
            success = False
            continue
        else:
            fil_out = fil_out[0]
            if fil_out["tun_status"] == status:
                st.log('Match found; remote VTEP {} status {}; expected '
                                        '{}'.format(rem_vtep,fil_out["tun_status"],status))
            else:
                st.error('Match NOT found; expected status for remote VTEP: {} is : {} '
                    'but found: {}'.format(rem_vtep,status,fil_out["tun_status"]))
                success = False

    return True if success else False

def verify_bgp_l2vpn_evpn_route_type_macip(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_route_type_macip(dut=data.dut1,evpn_type_2_prefix="[2]:[0]:[48]:[00:21:ee:00:10:16]",rd="1.1.1.1:2",status_code="*>",metric="",next_hop="11.1.1.1",weight="32768",path="",origin_code="i")
verify_bgp_l2vpn_evpn_route_type_macip(dut=data.dut1,evpn_type_2_prefix="[2]:[0]:[48]:[00:21:ee:00:10:16]:[32]:[59.1.1.6]",rd="1.1.1.1:2",status_code="*>",metric="",next_hop="11.1.1.1",weight="32768",path="",origin_code="i")
    To verify bgp l2vpn evpn route type macip
    :param dut:
    :param evpn_type_2_prefix:
    :param rd:
    :param path:
    :param status_code:
    :param weight:
    :param metric:
    :param next_hop:
    :param origin_code:
    :param displayed_prefixes:
    :param no_of_paths:
    :return:
    :reteturn:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "vtysh" if cli_type == 'click' else cli_type

    if cli_type in ["rest-put", "rest-patch"]:
        ret_val=True
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["get_evpn_routes"]
        rest_out = get_rest(dut, rest_url=url, timeout=30)
        if rest_out["status"] == 200:
            out_dict = {}
            rest_out = rest_out["output"]["openconfig-bgp-evpn-ext:routes"]["route"]
            match = False
            for i in rest_out:
                try:
                    prefix = i["prefix"]
                    if prefix == kwargs["evpn_type_2_prefix"] and i["state"]['valid-route']:
                        out_dict["next_hop"]=i["attr-sets"]["next-hop"]
                        if 'rd' in kwargs:
                            out_dict["rd"]=i["route-distinguisher"]
                        if 'origin_code' in kwargs and i['attr-sets']['origin'] == "IGP":
                            out_dict["origin_code"]= "i"
                        if 'origin_code' in kwargs and i['attr-sets']['origin'] == "EGP":
                            out_dict["origin_code"]= "e"
                        if 'origin_code' in kwargs and i['attr-sets']['origin'] == "incomplete":
                            out_dict["origin_code"]= "?"
                        if 'path' in kwargs:
                            as_path = ""
                            for as1 in i['attr-sets']['as-path']['as-segment'][0]['state']['member']:
                               as_path = as_path + str(as1) + " "
                            as_path = as_path.strip()
                            out_dict["path"]= as_path
                        for key in out_dict.keys():
                            if key in kwargs:
                                if out_dict[key] == kwargs[key]:
                                    st.log("Expected value {} found for key: {} for route {}".format(out_dict[key], key,prefix))
                                    match = True
                                else:
                                    st.log("Match NOT found; expected value {} but got"
                                               " {}".format(kwargs[key], out_dict[key]))
                                    ret_val = False
                        if match:
                            break
                except Exception:
                    continue
            if not match:
                st.log("MAC IP Route {} was not found in the rest output".format(kwargs["evpn_type_2_prefix"]))
                return False
            elif not ret_val:
                return False
            else:
                return True
        else:
            st.log("REST command execution failed")
            ret_val = False
    else:
        output = st.show(dut,"show bgp l2vpn evpn route type macip",type=cli_type)
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        count = 0
        no_common_key = 0
        ret_val1 = False
        dict1 = {}
        common_key_list = ['bgp_version','router_id','displayed_prefixes','no_of_paths']

        for a in output:
            for key in a:
                output[output.index(a)][key]=output[output.index(a)][key].lstrip()
                output[output.index(a)][key]=output[output.index(a)][key].rstrip()

        for key in kwargs:
            if key in common_key_list:
                no_common_key = no_common_key + 1

        if no_common_key > 0:
            rlist = output[0]
            count = 0
            for key in kwargs:
                if rlist[key] == kwargs[key] and key in common_key_list:
                    count = count + 1
            if no_common_key == count:
                ret_val1 = True
                for key in kwargs:
                    if key in common_key_list:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
            else:
                for key in kwargs:
                    if key in common_key_list:
                        if rlist[key] == kwargs[key]:
                            st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                        else:
                            st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
                st.log("\n")

            for key in common_key_list:
                if key in kwargs:
                    dict1[key] = kwargs[key]
                    del kwargs[key]

        if no_common_key > 0 and ret_val1 is False:
            st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
            return ret_val1

        ret_val = "True"
        #Converting all kwargs to list type to handle single or list of instances
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        input_dict_list =[]
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                st.log("output is {}".format(output))
                st.log("input_dict is {}".format(input_dict))
                ret_val = False

    return ret_val


def map_vrf_vni(dut, vrf_name, vni, config='yes', vtep_name='', skip_error=False, cli_type=''):
    """
    purpose:
            This API is used to configure VRF to VNI mapping

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param vrf_name: name of the vrf to be mapped to VNI
    :type vrf_name: string
    :param vni: VNI to be mapped to the VRF
    :type vni: string
    :param config: it takes value as 'yes' or 'no' to configure or remove the mapping
    :type config: string
    :param : cli_type
    :param : vtep_name
    :param : skip_error
    :return: None

    usage:

        map_vrf_vni(dut1, "Vrf-1", "100", cli_type='click')
        map_vrf_vni(dut1, "Vrf-1", "100", config='no', cli_type='click')

    Created by: Gangadhara Sahu <gangadhara.sahu@broadcom.com>
    """
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    if config == 'yes':
        conf_str = ''
        action = 'add_vrf_vni_map'
    else:
        conf_str = 'no'
        if cli_type == 'click':
            vni = ''
        action = 'del_vrf_vni_map'

    if cli_type == 'click':
        command = "config vrf {} {} {}".format(action, vrf_name, vni)
    elif cli_type == 'klish':
        if not vtep_name:
            st.error('Mandatory argument vtep_name MISSING')
            return False
        command = []
        command.append('interface vxlan {}'.format(vtep_name))
        command.append('{} map vni {} vrf {}'.format(conf_str, vni, vrf_name))
        command.append('exit')
    elif cli_type in ['rest-put','rest-patch']:
        if not vtep_name:
            st.error('Mandatory argument vtep_name MISSING')
            return False
        rest_urls = st.get_datastore(dut, "rest_urls")
        vni = int(vni) if type(vni) is not int else vni
        if config == 'yes':
            url = rest_urls['config_vlan_vni_mapping'].format(vrf_name)
            payload = { "openconfig-vxlan:vni-instance":
                        [{"vni-id": vni,
                            "source-nve": vtep_name,
                            "config": {"vni-id": vni, "source-nve": vtep_name}
                            }]
                        }
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                st.banner('FAIL-OCYANG')
                return False
        else:
            url = rest_urls['delete_vlan_vni_mapping'].format(vrf_name,vni,vtep_name)
            if not delete_rest(dut, rest_url=url):
                st.banner('FAIL-OCYANG')
                return False
        return
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    st.debug(command)
    return st.config(dut, command, skip_error_check=skip_error, type=cli_type)

def parse_rest_output_remote_vni(response):
    tunnel_vni_list = response['output'].get('openconfig-vxlan:vxlan-vni-peer-infos', {}).get('vxlan-vni-peer-info', [])
    tunnel_vni_count = len(tunnel_vni_list)
    result = []
    for tunnel in tunnel_vni_list:
        dict = {}
        dict['total_count'] = str(tunnel_vni_count)
        ### vlan missing in ocyang output
        dict['vlan'] = ''
        dict['rvtep'] = tunnel.get('peer-ip',"")
        dict['vni'] = tunnel.get('state',{}).get('vni-id',0)
        result.append(dict)
    return result

def verify_vxlan_evpn_remote_vni_id(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_vxlan_evpn_remote_vni_id(dut=dut1,vni="100",vlan="Vlan100",rvtep="11.1.1.1",type="dynamic",identifier="all")

    To verify show vxlan evpn_remote_vni <vni-id|all>
    :param dut:
    :param vni:
    :param vlan:
    :param rvtep:
    :param type:
    :param total_count:
    :param identifier: all | specific vni id which we want to parse using show command
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'identifier' not in kwargs:
        st.error("Mandetory arg identifier is not present")
        return False

    if cli_type == 'klish':
        if kwargs['identifier'] == 'all':
            kwargs['identifier'] = ''

    cmd = 'evpn_remote_vni' if cli_type == 'click' else 'remote vni'
    command = 'show vxlan {}'.format(cmd)
    if kwargs['identifier']:
        command += " {}".format(kwargs['identifier'])

    if cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['vxlan_vni_peer_info']
        response = get_rest(dut, rest_url=url)
        st.log('KLISH output for debugging REST')
        st.show(dut, 'show vxlan remote vni', type='klish')
        if response['output']:
            output = parse_rest_output_remote_vni(response)
        else:
            st.error("OCYANG-FAIL: verify vxlan remote vni - Get Response is empty")
            return False
        if 'vlan' in kwargs:
            del kwargs['vlan']
    else:
        output = st.show(dut, command, type=cli_type)

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    del kwargs['identifier']
    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['total_count']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val


def verify_vxlan_evpn_remote_mac_id(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_vxlan_evpn_remote_mac_id(dut=dut1,vni="100",vlan="Vlan100",rvtep="11.1.1.1",type="dynamic",identifier="all",mac="00:21:ee:00:10:33")

    To verify show vxlan evpn_remote_mac <mac|all>
    :param dut:
    :param vni:
    :param vlan:
    :param rvtep:
    :param type:
    :param mac:
    :param total_count:
    :param identifier: all | specific mac which we want to parse using show command
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    ### NO ocyang URI support for <show vxlan remote mac". Hence fallback to klish
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if 'identifier' not in kwargs:
        st.error("Mandatory arg identifier is not present")
        return False

    if cli_type == 'klish':
        if kwargs['identifier'] == 'all':
            kwargs['identifier'] = ''

    cmd = 'evpn_remote_mac' if cli_type == 'click' else 'remote mac'
    command = 'show vxlan {}'.format(cmd)
    if kwargs['identifier']:
        command += " {}".format(kwargs['identifier'])
    output = st.show(dut, command, type=cli_type)

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    del kwargs['identifier']
    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['total_count','min_total_count']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if key != 'min_total_count':
                if rlist[key] == kwargs[key] and key in common_key_list:
                    count = count + 1
            elif key == 'min_total_count':
                if rlist['total_count'] >= kwargs[key] and key in common_key_list:
                    count = count + 1
                    st.log("Match: Match key {} found => {} out of {}".format(key,kwargs[key],rlist['total_count']))
        if 'min_total_count' in kwargs:
            del kwargs['min_total_count']
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val

def parse_rest_output_vlanvni_map(dut,vlan_data,url):
        response = get_rest(dut, rest_url=url)
        if response['output']:
            dict = {}
            dict['vlan'] = vlan_data
            vni_map = response['output'].get('openconfig-vxlan:vni-instance', [])
            if vni_map:
                vni_id = vni_map[0].get('state', {}).get('vni-id', 0)
            else:
                vni_id = 0
            dict['vni']  = str(vni_id) if type(vni_id) is int else vni_id
            return dict
        else:
            st.error("OCYANG-FAIL: verify vxlan vlanvnimap - Get Response is empty for vlan:{}".format(vlan_data))
            return False

def verify_vxlan_vlanvnimap(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_vxlan_vlanvnimap(dut=dut1,vni=["100","101'],vlan=["Vlan100","Vlan100"],total_count="2")

    To verify show vxlan vlanvnimap
    :param dut:
    :param vni:
    :param vlan:
    :param total_count:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    ### There is no direct vlan-vni mapping output in ocyang.
    #cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if "return_output" in kwargs:
        cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if cli_type in ['rest-put', 'rest-patch']:
        st.log('KLISH output for debugging REST')
        st.show(dut, 'show vxlan vlanvnimap', type='klish')
        rest_urls = st.get_datastore(dut, "rest_urls")
        result = []
        vlan_list = [kwargs['vlan']] if type(kwargs['vlan']) is not list else kwargs['vlan']
        for vlan_id in vlan_list:
            vlan_data = str(vlan_id) if type(vlan_id) is not str else vlan_id
            vlan_str = 'Vlan' + vlan_data if 'Vlan' not in vlan_data else vlan_data
            url = rest_urls['config_vlan_vni_mapping'].format(vlan_str)
            dict = parse_rest_output_vlanvni_map(dut,vlan_data,url)
            if dict:
                result.append(dict)
        count = len(result)
        for dict in result:
            dict.update({'total_count':  count})
        output = result
        st.log("parsed output:{}".format(result))
        kwargs.pop('total_count')
    else:
        output = st.show(dut, "show vxlan vlanvnimap", type=cli_type)

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['total_count']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val

def parse_rest_output_vrfvni_map(dut, vrf_str, url):
    response = get_rest(dut, rest_url=url)
    if response['output']:
        dict = {}
        dict['vrf'] = vrf_str
        vni_map = response['output'].get('openconfig-vxlan:vni-instance', [])
        if vni_map:
            vni_id = vni_map[0].get('state', {}).get('vni-id', 0)
        else:
            vni_id = 0
        dict['vni'] = str(vni_id) if type(vni_id) is int else vni_id
        return dict
    else:
        st.error("OCYANG-FAIL: verify vxlan vlanvnimap - Get Response is empty for vrf:{}".format(vrf_str))
        return False

def verify_vxlan_vrfvnimap(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_vxlan_vrfvnimap(dut=dut1,vni=["500","501'],vrf=["Vrf1","Vrf2"],total_count="2")

    To verify show vxlan vrfvnimap
    :param dut:
    :param vni:
    :param vlan:
    :param total_count:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    ### There is no direct vrf-vni mapping output in ocyang.
    if "return_output" in kwargs:
        cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if cli_type in ['rest-put', 'rest-patch']:
        st.log('KLISH output for debugging REST')
        st.show(dut, 'show vxlan vrfvnimap', type='klish')
        rest_urls = st.get_datastore(dut, "rest_urls")
        result = []
        vrf_list = [kwargs['vrf']] if type(kwargs['vrf']) is str else kwargs['vrf']
        for vrf in vrf_list:
            vrf_str = str(vrf) if type(vrf) is not str else vrf
            url = rest_urls['config_vlan_vni_mapping'].format(vrf_str)
            dict = parse_rest_output_vrfvni_map(dut, vrf_str, url)
            if dict:
                result.append(dict)
        count = len(result)
        for dict in result:
            dict.update({'total_count': count})
        output = result
        st.log("parsed output:{}".format(result))
        kwargs.pop('total_count')
    else:
        output = st.show(dut, "show vxlan vrfvnimap", type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['total_count']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val

def verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_route_detail_type_prefix(dut=evpn_dict["leaf_node_list"][3],
          prefix="[5]:[0]:[24]:[55.55.1.0]",rd="9:9",rt="500:500",rvtep="5.5.5.2")
    To verify show bgp l2vpn evpn route detail type prefix
    :param dut:
    :param rd:
    :param as_path:
    :param vni_id:
    :param prefix:
    :param rvtep:
    :param bgp_peer:
    :param origin:
    :param rt:
    :param et:
    :param rmac:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    ret_val = True
    if cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["get_evpn_routes"]
        rest_out = get_rest(dut, rest_url=url, timeout=30)
        if rest_out["status"] == 200:
            out_dict={}
            rest_out=rest_out["output"]["openconfig-bgp-evpn-ext:routes"]["route"]
            for i in rest_out:
                try:
                    if "rmac" in kwargs:
                        rmac = i["attr-sets"]["ext-community"][2]
                        rmac=":".join(rmac.split(":")[1:7])
                        rt=i["attr-sets"]["ext-community"][0]
                        rt=":".join(rt.split(":")[1:3])
                        out_dict["rt"]=rt
                        prefix = i["prefix"]
                        nexthop = i["attr-sets"]["next-hop"]
                        if prefix == kwargs["prefix"] and nexthop == kwargs["rvtep"] and rmac == kwargs["rmac"]:
                            if i["state"]["openconfig-rib-bgp-ext:best-path"]:
                                vni=i["attr-sets"]["tag"]
                                out_dict["vni_id"] = vni
                                rd=i["route-distinguisher"]
                                rd=rd.split(":")[0]
                                out_dict["rd"]=rd
                            for key in out_dict.keys():
                                if key in kwargs:
                                    if out_dict[key]==kwargs[key]:
                                        st.log("Expected value {} found for key: {}".format(out_dict[key],key))
                                    else:
                                        st.log("Match NOT found; expected value {} but got"
                                               " {}".format(kwargs[key],out_dict[key]))
                                        ret_val = False
                            if ret_val:
                                return True
                except Exception:
                    continue
        else:
            st.log("REST command execution failed")
            ret_val=False
    else:
        cli_type = "vtysh" if cli_type == 'click' else "klish"
        output = st.show(dut,"show bgp l2vpn evpn route detail type prefix",type=cli_type)
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        ret_val = "True"
        #Converting all kwargs to list type to handle single or list of instances
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        input_dict_list =[]
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False
    return ret_val


def clear_bgp_evpn(dut,clear_type,**kwargs):
    '''
    :param dut:
    :type dut: string
    :param clear_type:
    :type clear_type: string
    :param kwargs:
    :type kwargs: dictionary
    :return: None

    Usage:
    to clear all neighbors:
    clear_bgp_evpn(dut1,"*")
    clear_bgp_evpn(dut1,"*",dir="in")
    clear_bgp_evpn(dut1,"*",dir="in",prefix="yes")
    clear_bgp_evpn(dut1,"*",dir="out")
    clear_bgp_evpn(dut1,"*",soft_dir="in")
    clear_bgp_evpn(dut1,"*",soft_dir="out")

    to clear specific neighbors:
    clear_bgp_evpn(dut1,"1.1.1.1")
    clear_bgp_evpn(dut1,"1.1.1.1",dir="in")
    clear_bgp_evpn(dut1,"1.1.1.1",dir="in",prefix="yes")
    clear_bgp_evpn(dut1,"1.1.1.1",dir="out")
    clear_bgp_evpn(dut1,"1.1.1.1",soft_dir="in")
    clear_bgp_evpn(dut1,"1.1.1.1",soft_dir="out")
    '''

    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "vtysh" if cli_type == 'click' else "klish"

    cmd = "clear bgp l2vpn evpn {}".format(clear_type)

    supported_args = ["dir","prefix","soft_dir","cli_type"]
    for key in kwargs.keys():
        if key not in supported_args:
            st.error("kindly specify the supported argument among {}".format(supported_args))
            return None

    if "dir" in kwargs:
        cmd += " {}".format(kwargs["dir"])
        if kwargs["dir"] == "in" and "prefix" in kwargs:
            cmd += " prefix-filter"

    if "soft_dir" in kwargs:
        cmd += " soft {}".format(kwargs["soft_dir"])

    return st.config(dut,cmd,type=cli_type,skip_tmpl=True,conf=False)


def fetch_evpn_neigh_output(dut,**kwargs):
    '''
    :param dut:
    :type dut: string
    :return: cli output in success case; False in failure case

    Usage:
        fetch_evpn_neigh_output(dut1)
    '''
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "vtysh" if cli_type == 'click' else "klish"
    output = st.show(dut,"show bgp l2vpn evpn summary",type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    else:
        return output

def verify_bgp_l2vpn_evpn_route_type_multicast(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_l2vpn_evpn_route_type_multicast(dut=dut1,evpn_type_3_prefix="[3]:[0]:[32]:[11.1.1.1]",rd="1.1.1.1:2",status_code="*>",metric="3276",next_hop="11.1.1.1",weight="8",path="",origin_code="i",displayed_prefixes="5",no_of_paths="5",bgp_version="1",router_id="1.1.1.1")

    To verify bgp l2vpn evpn route type multicast
    :param dut:
    :param bgp_verion:
    :param router_id:
    :param evpn_type_3_prefix:
    :param rd:
    :param path:
    :param status_code:
    :param weight:
    :param metric:
    :param next_hop:
    :param origin_code:
    :param displayed_prefixes:
    :param no_of_paths:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in ["rest-put", "rest-patch"]:
        ret_val=True
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["get_evpn_routes"]
        rest_out = get_rest(dut, rest_url=url, timeout=30)
        if rest_out["status"] == 200:
            out_dict = {}
            rest_out = rest_out["output"]["openconfig-bgp-evpn-ext:routes"]["route"]
            for i in rest_out:
                try:
                    prefix = i["prefix"]
                    if prefix == kwargs["evpn_type_3_prefix"] and i["state"]["openconfig-rib-bgp-ext:best-path"]:
                        nexthop = i["attr-sets"]["next-hop"]
                        out_dict["next_hop"]=nexthop
                        for key in out_dict.keys():
                            if key in kwargs:
                                if out_dict[key] == kwargs[key]:
                                    st.log("Expected value {} found for key: {}".format(out_dict[key], key))
                                else:
                                    st.log("Match NOT found; expected value {} but got"
                                               " {}".format(kwargs[key], out_dict[key]))
                                    ret_val = False
                        if ret_val:
                            return True
                except Exception:
                    continue
        else:
            st.log("REST command execution failed")
            ret_val = False
    else:
        cli_type = "vtysh" if cli_type == 'click' else "klish"
        output = st.show(dut,"show bgp l2vpn evpn route type multicast",type=cli_type)
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        for a in output:
            for key in a:
                output[output.index(a)][key]=output[output.index(a)][key].lstrip()
                output[output.index(a)][key]=output[output.index(a)][key].rstrip()
        count = 0
        no_common_key = 0
        ret_val1 = False
        dict1 = {}
        common_key_list = ['bgp_version','router_id','displayed_prefixes','no_of_paths']
        for key in kwargs:
            if key in common_key_list:
                no_common_key = no_common_key + 1
        if no_common_key > 0:
            rlist = output[0]
            count = 0
            for key in kwargs:
                if rlist[key] == kwargs[key] and key in common_key_list:
                    count = count + 1
            if no_common_key == count:
                ret_val1 = True
                for key in kwargs:
                    if key in common_key_list:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
            else:
                for key in kwargs:
                    if key in common_key_list:
                        if rlist[key] == kwargs[key]:
                            st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                        else:
                            st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
                st.log("\n")
            for key in common_key_list:
                if key in kwargs:
                    dict1[key] = kwargs[key]
                    del kwargs[key]
        if no_common_key > 0 and ret_val1 is False:
            st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
            return ret_val1
        ret_val = "True"
        #Converting all kwargs to list type to handle single or list of instances
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]
        #convert kwargs into list of dictionary
        input_dict_list =[]
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)
        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False
    return ret_val


def verify_vxlan_tunnel_count(dut, exp_count, cli_type=''):
    """

    :param dut:
    :param exp_count:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    if cli_type == "click":
        command = 'show vxlan tunnel | grep "Total count "'
        output = st.show(dut, command, skip_tmpl=True, type=cli_type)
        x = re.search(r"\d+", output)
    elif cli_type == "klish":
        command = 'show vxlan tunnel | grep "EVPN"'
        output = st.show(dut, command, skip_tmpl=True, type=cli_type)
        x = output.count("EVPN_")
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['vxlan_tunnel_info']
        response = get_rest(dut, rest_url=url)
        st.log('KLISH output for debugging REST')
        st.show(dut, 'show vxlan tunnel', type='klish')
        tunnel_list = response['output']['openconfig-vxlan:vxlan-tunnel-infos']['vxlan-tunnel-info']
        x = len(tunnel_list)
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False
    if x:
        if cli_type == "click":
            if int(x.group()) == exp_count:
                return True
            else:
                st.log('FAIL: Expected tunnel count not found.')
                return False
        elif cli_type in  ["klish", "rest-put", "rest-patch"]:
            if x == exp_count:
                return True
            else:
                st.log('FAIL: Expected tunnel count not found.')
                return False
    else:
        return -1

def create_linktrack(dut, track_group_name, config='yes', **kwargs):
    '''
    purpose:
            This definition is used to create link track

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param track_group_name: interface track group name name to be created
    :param config: it takes value as 'yes' or 'no' to configure or remove interface link tracking
    :type config: string
    :return: None

    usage:
        create_linktrack(dut1, "group1")
        create_linktrack(dut1, "group1",config='no')

    Created by: Gangadhara <gangadhara.sahu@broadcom.com>
    '''

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if cli_type == 'click':
        if config=='yes':
            command = "config linktrack add {}".format(track_group_name)
        else:
            command = "config linktrack del {}".format(track_group_name)
        return st.config(dut=dut,cmd=command)
    elif cli_type == 'klish':
        config = 'no ' if config != 'yes' else ''
        exit_cmd = '\nexit' if config == '' else ''
        command = '{}link state track {}{}'.format(config, track_group_name, exit_cmd)
        return st.config(dut=dut,cmd=command, type="klish", conf=True)
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if config == 'yes':
            url = rest_urls['config_link_track']
            payload = {"openconfig-lst-ext:lst-group":[{"name":track_group_name}]}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                st.banner('FAIL-OCYANG: Config Link track group Failed')
                return False
        elif config == 'no':
            url = rest_urls['delete_link_track'].format(track_group_name)
            if not delete_rest(dut, rest_url=url):
                st.banner('FAIL-OCYANG: Delete Link track group Failed')
                return False
        return
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
    return False

def update_linktrack_interface(dut, track_group_name, upinterface, timeout, config='yes', **kwargs):
    '''
    purpose:
            This definition is used to update link track interface

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param track_group_name: interface track group name name to be created or deleted
    :param upinterface: upstream interface to be added or removed
    :param config: it takes value as 'yes' or 'no' to configure or remove interface link tracking
    :param upinterface: upinterface to be added or removed
    :param description: downinterface to be added or removed
    :param downinterface: timeout value to be configured
    :type config: string
    :return: None

    usage:
        update_linktrack_interface(dut1, "Ethernet0,Vlan10","10")
        update_linktrack_interface(dut1, "Ethernet0,Vlan10","",config='no')

    Created by: Gangadhara <gangadhara.sahu@broadcom.com>
    '''

    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    description = kwargs.get('description', '')

    downinterface = kwargs.get('downinterface', 'all-mclag')

    if cli_type == 'click':
        if config=='yes':
            if description == '':
                command = "config linktrack update {} --upstream {} --downstream {} --timeout {}".format(track_group_name,upinterface,downinterface,timeout)
            else:
                command = "config linktrack update {} --upstream {} --downstream {} --timeout {} --description {}".format(track_group_name,upinterface,downinterface,timeout,description)
        else:
            command = "config linktrack update {} -nu {} -nd {}".format(track_group_name,upinterface,downinterface)
        return st.config(dut=dut,cmd=command)

    elif cli_type == 'klish':
        config = 'no ' if config != 'yes' else ''
        command = 'link state track {}'.format(track_group_name)
        intf = get_interface_number_from_name(upinterface)
        dintf = get_interface_number_from_name(downinterface)
        if config == '':
            if downinterface == 'all-mclag':
                command = command + "\n" + "downstream {}".format(downinterface)
            if timeout != '':
                command = command + "\n" + "timeout {}".format(timeout)
            if description != '':
                command = command + "\n" + "description {}".format(description)
            command = command + "\n" + "exit"
            command = command + "\n" + "interface {} {}".format(intf["type"], intf["number"])
            command = command + "\n" + "link state track {} upstream".format(track_group_name)
            command = command + "\n" + "exit"
            if downinterface != 'all-mclag':
                command = command + "\n" + "interface {} {}".format(dintf["type"], dintf["number"])
                command = command + "\n" + "link state track {} downstream".format(track_group_name)
                command = command + "\n" + "exit"
        else:
            if downinterface == 'all-mclag':
                command = command + "\n" + "{}downstream {}".format(config,downinterface)
            if timeout != '':
                command = command + "\n" + "{}timeout".format(config)
            if description != '':
                command = command + "\n" + "{}description".format(config)
            command = command + "\n" + "exit"
            command = command + "\n" + "interface {} {}".format(intf["type"], intf["number"])
            command = command + "\n" + "{}link state track {} upstream".format(config, track_group_name)
            command = command + "\n" + "exit"
            if downinterface != 'all-mclag':
                command = command + "\n" + "interface {} {}".format(dintf["type"], dintf["number"])
                command = command + "\n" + "{}link state track {} downstream".format(config,track_group_name)
                command = command + "\n" + "exit"
        return st.config(dut, command, type="klish", conf=True)

    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if config == 'yes':
            url = rest_urls['config_link_track_params'].format(track_group_name)
            #up_intf = get_interface_number_from_name(upinterface)
            #dw_intf = get_interface_number_from_name(downinterface)
            payload = {"openconfig-lst-ext:config":
                           {"name": track_group_name}
                       }
            if downinterface == 'all-mclag':
                payload["openconfig-lst-ext:config"].update({'all-mclags-downstream':True})
            if timeout != '':
                payload["openconfig-lst-ext:config"].update({'timeout':int(timeout)})
            if description != '':
                payload["openconfig-lst-ext:config"].update({'description':description})
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                st.banner('FAIL-OCYANG: Config Link track group parameters Failed')
                return False
            if downinterface != 'all-mclag':
                url = rest_urls['add_rem_link_track_downstream'].format(downinterface)
                payload = { "openconfig-lst-ext:group-name": track_group_name }
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    st.banner('FAIL-OCYANG: Assign Link track to downstream interface Failed')
                    return False
            url = rest_urls['add_rem_link_track_upstream'].format(upinterface)
            payload = {"openconfig-lst-ext:upstream-groups":
                        {"upstream-group":
                            [{"group-name":track_group_name,
                              "config":{"group-name":track_group_name}
                            }]
                        }
                        }
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                st.banner('FAIL-OCYANG: Assign Link track to upstream interface Failed')
                return False
        elif config == 'no':
            url = rest_urls['add_rem_link_track_upstream'].format(upinterface)
            if not delete_rest(dut, rest_url=url):
                st.banner('FAIL-OCYANG: Remove Link track from upstream interface Failed')
                return False

            if downinterface == 'all-mclag':
                url = rest_urls['link_track_all_mclag'].format(track_group_name)
                if not delete_rest(dut, rest_url=url):
                    st.banner('FAIL-OCYANG: Remove all-mclag downstream Failed')
                    return False
            else:
                url = rest_urls['add_rem_link_track_downstream'].format(upinterface)
                if not delete_rest(dut, rest_url=url):
                    st.banner('FAIL-OCYANG: Remove Link track from downstream interface Failed')
                    return False
            if timeout != '':
                url = rest_urls['link_track_timeout'].format(track_group_name)
                if not delete_rest(dut, rest_url=url):
                    st.banner('FAIL-OCYANG: Remove Link track group timeout Failed')
                    return False
            if description != '':
                url = rest_urls['link_track_description'].format(track_group_name)
                if not delete_rest(dut, rest_url=url):
                    st.banner('FAIL-OCYANG: Remove Link track group description Failed')
                    return False
        return
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

def verify_mac(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_mac(dut=dut1,mac="00:11:00:22:00:11",total="1")

    To verify mac
    :param dut:
    :param macaddress:
    :param vlan:
    :param port:
    :param type:
    :param dest_ip:
    :param total:
    :return:
    :reteturn:
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if cli_type == "click":
        cmd = "show mac"
    elif cli_type == "klish":
        cmd = "show mac address-table"
    output = st.show(dut,cmd,type=cli_type)

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if cli_type == "klish":
        if 'type' in kwargs:
            if not kwargs['type'].isupper():
                kwargs['type']=kwargs['type'].upper()

    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['total']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val

def _clear_vxlan_config_helper(dut_list, cli_type='click'):
    """
    Helper routine to cleanup vxlan config from devices.
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        st.log("############## {} : VxLAN Config Cleanup ################".format(dut))
        output = st.show(dut, "show vxlan interface")
        st.log("##### VXLAN INTERFACE: {}".format(output))
        if len(output) == 0:
            continue

        entry = output[0]
        if entry['vtep_name']:
            vtep_name = entry['vtep_name']
            nvo_name = entry['nvo_name']

            vrf_vni = st.show(dut, "show vxlan vrfvnimap", type=cli_type)
            st.log("##### [{}] VXLAN VRF L3VNI MAP: {}".format(dut, vrf_vni))
            for entry in vrf_vni:
                if not entry['vrf'] or not entry['vni'] or entry['vni'] == '0':
                    continue
                vrf = entry['vrf']
                map_vrf_vni(dut, vrf, entry['vni'], config="no")

            vlan_vni = st.show(dut, "show vxlan vlanvnimap", type=cli_type)
            st.log("##### [{}] VXLAN VLAN VNI MAP: {}".format(dut, vlan_vni))
            for entry in vlan_vni:
                if not entry['vlan'] or not entry['vni']:
                    continue
                vlan = entry['vlan']
                if vlan[:4] == "Vlan":
                    vlan = vlan[4:]
                map_vlan_vni(dut, vtep_name, vlan, entry['vni'], config='no', cli_type=cli_type)

            if nvo_name:
                create_evpn_instance(dut, nvo_name, vtep_name, config='no', cli_type=cli_type)
            create_overlay_intf(dut, vtep_name, '0.0.0.0', config='no', cli_type=cli_type)

    return True


def clear_vxlan_configuration(dut_list, thread=True, cli_type='click'):
    """
    Find and cleanup all vxlan configuration.

    :param dut_list
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    [out, exceptions] = utils.exec_foreach(thread, dut_li, _clear_vxlan_config_helper, cli_type)
    st.log(exceptions)
    return False if False in out else True

def parse_rest_output_linktrack_summary(response):
    lst_group = response['output']['openconfig-lst-ext:state']
    dict = {}
    dict['timeout'] = str(lst_group.get('timeout',""))
    dict['name'] = lst_group.get('name',"")
    dict['description'] =  lst_group.get('description',"")
    return [dict]

def verify_linktrack_summary(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_linktrack_summary(dut=dut1,name="group1",description="MLAG_LINK_TRACK",timeout="10")

    To verify linktrack summary
    :param dut:
    :param name:
    :param description:
    :param timeout:
    :return: True or False
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'name' not in kwargs:
        st.error("Mandatory arg name is not present")
        return False

    if cli_type == 'click':
        result = st.show(dut,"show linktrack summary")
    elif cli_type == 'klish':
        result = st.show(dut, 'show link state tracking', type='klish')
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['get_link_track_summary'].format(kwargs['name'])
        response = get_rest(dut,rest_url=url)
        st.log('KLISH output for debugging REST')
        st.show(dut, 'show link state tracking', type='klish')
        if response['output']:
            result = parse_rest_output_linktrack_summary(response)
        else:
            st.error("OCYANG-FAIL: verify link track summary - Get Response is empty")
            return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    if len(result) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    ret_val = False

    for rlist in result:
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key]:
                count = count + 1
        if len(kwargs) == count:
            ret_val = True
            for key in kwargs:
                st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
            break
        else:
            for key in kwargs:
                if rlist[key] == kwargs[key]:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                else:
                    st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

    if ret_val is False:
        st.log("Fail: Not Matched all args in passed dict {} from parsed dict".format(kwargs))

    return ret_val

def parse_rest_output_linktrack_group(dut,response,timeout,description='',lst_bringup_time='0'):
    lst_interfaces = response['output']['openconfig-lst-ext:interface']
    result = []
    for interface in lst_interfaces:
        lst_dict = {}
        lst_dict['description'] = description
        lst_dict['timeout'] = timeout
        lst_dict['startup_remain_time'] = lst_bringup_time
        if 'upstream-groups' in interface.keys():
            lst_dict['name'] = interface.get('upstream-groups',{}).get('upstream-group',[])[0].get('group-name',"")
            lst_dict['direction'] = "Upstream"
            lst_dict['interface'] = interface.get('id',"")
            port1.get_interface_status(dut, lst_dict['interface'],cli_type='click')
            interface_state = str(port1.get_interface_status(dut,lst_dict['interface']))
            st.log("DEBUG==>Interface:{}, Inf state from Rest:{}".format(lst_dict['interface'],interface_state))
            if interface_state.lower() == 'up':
                lst_dict['direction_state'] = 'Up'
            elif interface_state.lower() == 'down':
                lst_dict['direction_state'] = 'Down'
            else:
                lst_dict['direction_state'] = interface_state
        elif 'downstream-group' in interface.keys():
            lst_dict['name'] = interface.get('downstream-group',{}).get('state',{}).get('group-name',"")
            lst_dict['direction'] = "Downstream"
            lst_dict['interface'] = interface.get('id',"")
            if interface.get('downstream-group',{}).get('state',{}).get('disabled',""):
                lst_dict['direction_state'] = 'Disabled'
            else:
                port1.get_interface_status(dut, lst_dict['interface'], cli_type='click')
                interface_state = str(port1.get_interface_status(dut, lst_dict['interface']))
                st.log("DEBUG==>Interface:{}, Inf state from Rest:{}".format(lst_dict['interface'], interface_state))
                if interface_state.lower() == 'up':
                    lst_dict['direction_state'] = 'Up'
                elif interface_state.lower() == 'down':
                    lst_dict['direction_state'] = 'Down'
                else:
                    lst_dict['direction_state'] = interface_state
        result.append(lst_dict)
    return result


def verify_linktrack_group_name(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_linktrack_group_name(dut=dut1,name="group1",description="MLAG_LINK_TRACK",timeout="10",
                                upstream_plist=["Ethernet3","Ethernet9"],downstream_plist=["PortChannel10"])

    To verify linktrack group <group-name>
    :param dut:
    :param name:
    :param description:
    :param timeout:
    :param upstream_plist: List of upstream interfaces
    :param downstream_plist: List of downstream portchannels
    :return: True or False
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'name' not in kwargs:
        st.error("Mandatory arg name is not present")
        return False

    if cli_type == 'click':
        output = st.show(dut,"show linktrack group {}".format(kwargs['name']))
    elif cli_type == 'klish':
        output = st.show(dut,"show link state tracking {}".format(kwargs['name']), type='klish')
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        lst_name = kwargs['name']
        url = rest_urls['get_link_track_description'].format(lst_name)
        lst_description = get_rest(dut, rest_url=url)['output']['openconfig-lst-ext:description']

        url = rest_urls['get_link_track_timeout'].format(lst_name)
        lst_timeout = str(get_rest(dut, rest_url=url)['output']['openconfig-lst-ext:timeout'])

        url = rest_urls['get_link_track_bringup_remain_time'].format(lst_name)
        lst_bringup_time = str(get_rest(dut, rest_url=url)['output']['openconfig-lst-ext:bringup-remaining-time'])

        url = rest_urls['get_link_track_interfaces']
        response = get_rest(dut, rest_url=url)
        st.log('KLISH output for debugging REST')
        st.show(dut, 'show link state tracking {}'.format(kwargs['name']), type='klish')

        if response['output']:
            output = parse_rest_output_linktrack_group(dut,response,lst_timeout,lst_description,lst_bringup_time)
        else:
            st.error("OCYANG-FAIL: verify link track group - Get Response is empty")
            return False

    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['name','description','timeout','startup_remain_time']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    if len(kwargs.keys()) > 0:
        #Converting all kwargs to list type to handle single or list of instances
        input_dict_list =[]
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val

def get_port_counters(dut, port, counter,**kwargs):
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    port1.clear_interface_counters(dut,cli_type=cli_type)
    port_range_list = list(port) if isinstance(port, list) else [port]
    cntr_range_list = list(counter) if isinstance(counter, list) else [counter]
    if cli_type == 'click':
        st.wait(3)
    else:
        st.wait(1)
    list1 = []
    for prt, cntr in zip (port_range_list, cntr_range_list):
        if cli_type == "click":
            if '/' in prt:
                prt = st.get_other_names(dut,[prt])[0]
            st.show(dut, "show interface counters -i {}".format(prt),type=cli_type)
            output = st.show(dut, "show interface counters -i {}".format(prt),type=cli_type)
            entries = filter_and_select(output, (cntr,), {'iface': prt})
            list1.append(entries[0])
        if cli_type == "klish":
            output = port1.get_interface_counters_all(dut,port=prt,cli_type=cli_type)
            entries = filter_and_select(output, (cntr,), {'iface': prt})
            if output == [] or entries == []:
                st.log("interface {} is not found in the show interface counters O/P".format(prt))
                dict1 = {}
                dict1.update({"rx_bps":"0.0 KB/s"})
                list1.append(dict1)
            else:
                if float(entries[0][cntr]) >= 1.0:
                    value = float(entries[0][cntr])
                    entries[0][cntr] = str(value) + " MB/s"
                elif float(entries[0][cntr]) < 1.0 and float(entries[0][cntr]) >= 0.001:
                    value = float(entries[0][cntr])*1024
                    entries[0][cntr] = str(value) + " KB/s"
                elif float(entries[0][cntr]) < 0.001:
                    entries[0][cntr] = get_port_rate_inklish(dut,prt=prt,cntr=cntr)
                list1.append(entries[0])
        return list1

def get_port_rate_inklish(dut,prt,cntr):
    for i in range(4):
        st.wait(5,"\n\n###### Retry attempt {} for interface {} {} check #### \n".format(i,prt,cntr))
        output = port1.get_interface_counters_all(dut,port=prt,cli_type="klish")
        entries = filter_and_select(output, (cntr,), {'iface': prt})
        st.log("\n\n###### interface {} {} shows {} #####\n".format(prt,cntr,float(entries[0][cntr])))
        if output == [] or entries == []:
            st.log("interface {} is not found in the show interface counters O/P".format(prt))
            return "0.0 B/s"
        else:
            if float(entries[0][cntr]) >= 1.0:
                value = float(entries[0][cntr])
                entries[0][cntr] = str(value) + " MB/s"
                return str(value) + " MB/s"
            elif float(entries[0][cntr]) < 1.0 and float(entries[0][cntr]) >= 0.001:
                value = float(entries[0][cntr])*1024
                entries[0][cntr] = str(value) + " KB/s"
                return str(value) + " KB/s"
            elif float(entries[0][cntr]) < 0.001:
                continue
    return "0.0 B/s"

def neigh_suppress_config(dut, vlan, config='yes', skip_error=False, cli_type=''):
    """
    purpose:
            This API used to enable or disable neighbor suppression on vlan

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param vlan: VLAN name
    :type vlan: string
    :type action: enable|disable
    :return: None

    usage:
        neigh_suppress_config(dut1, "Vlan100", config="yes", cli_type='click')
        neigh_suppress_config(dut1, "Vlan100", config="yes", cli_type='klish')
        neigh_suppress_config(dut1, "Vlan100", config="no", cli_type='click')

    Created by: Ganagadhar <gangadhara.sahu@broadcom.com>
    """
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    if config == 'yes':
        conf_str = ''
        action = 'enable'
    else:
        conf_str = 'no'
        action = 'disable'

    if cli_type == 'click':
        command = "config neigh_suppress {} {}".format(action,vlan)

    elif cli_type == 'klish':
        command = []
        command.append('interface Vlan {}'.format(vlan))
        command.append('{} neigh-suppress'.format(conf_str))
        command.append('exit')
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        vlan_data = str(vlan) if type(vlan) is not str else vlan
        vlan_str = 'Vlan' + vlan_data if 'Vlan' not in vlan_data else vlan_data
        payload = {"openconfig-vxlan:config":{
                    "arp-and-nd-suppress":"ENABLE"}
                    }
        if config == 'yes':
            url = rest_urls['vxlan_arp_nd_suppress'].format(vlan_str)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                st.banner('FAIL-OCYANG: ARP and ND suppress config on vlan Failed')
                return False
        else:
            url = rest_urls['vxlan_arp_nd_suppress_delete'].format(vlan_str)
            if not delete_rest(dut, rest_url=url):
                st.banner('FAIL-OCYANG: ARP and ND suppress UnConfig on vlan Failed')
                return False
        return
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    st.debug(command)
    return st.config(dut, command, skip_error_check=skip_error, type=cli_type)

def verify_neigh_suppress(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_neigh_suppress(dut=dut1,identifier="all",cli_type="click",vlan="Vlan450",status="Configured",netdevice="vtepLeaf4-450")
    verify_neigh_suppress(dut=dut1,identifier="450",cli_type="click",vlan="Vlan450",status="Configured",netdevice="vtepLeaf4-450")
    verify_neigh_suppress(dut=dut1,identifier="all",cli_type="click",vlan="Vlan100",
                          status="Not Configured",netdevice="vtepLeaf4-100")
    verify_neigh_suppress(dut=dut1,identifier="450",cli_type="klish",vlan="Vlan450",status="on")

    To verify neighbour suppress for <vlan|all>
    :param dut:
    :param total_count:
    :param identifier: all | specific vlan id
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'identifier' not in kwargs:
        st.error("Mandetory arg identifier is not present")
        return False

    cmd = 'neigh-suppress' if cli_type == 'click' else 'neighbor-suppress-status'
    command = 'show {}'.format(cmd)
    if kwargs['identifier'] == "all" and cli_type == 'click':
        command += " all"
    elif kwargs['identifier'] != "all" and cli_type == 'click':
        command += " vlan {}".format(kwargs['identifier'])
    elif kwargs['identifier'] != "all" and cli_type == 'klish':
        command += " {}".format(kwargs['identifier'])
    elif kwargs['identifier'] == "all" and cli_type == 'klish':
        command += ""
    elif cli_type in ['rest-put','rest-patch']:
        st.log('KLISH output for debugging REST')
        output = st.show(dut, 'show neighbor-suppress-status', type='klish')
        ### URI to be used only if neighbor-suppression is enabled for the VLAN -SONIC-31990
        ## So When expected status is off, verification wil continue based on above klish output
        if kwargs['status'].lower() == 'on':
            rest_urls = st.get_datastore(dut, "rest_urls")
            vlan = kwargs['vlan']
            vlan_data = str(vlan) if type(vlan) is not str else vlan
            vlan_str = 'Vlan' + vlan_data if 'Vlan' not in vlan_data else vlan_data
            url = rest_urls['vxlan_arp_nd_suppress_state'].format(vlan_str)
            response = get_rest(dut,rest_url=url)
            output = {}
            if response['output']:
                output['vlan'] = vlan_str
                if response.get('output',{}).get('openconfig-vxlan:arp-and-nd-suppress',"") == "ENABLE":
                    output['status'] ='on'
                elif response.get('output',{}).get('openconfig-vxlan:arp-and-nd-suppress',"") == "DISABLE":
                    output['status'] ='off'
                output = [output]
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    if cli_type not in ['rest-put', 'rest-patch']:
        output = st.show(dut, command, type=cli_type)

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    del kwargs['identifier']
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['total_count']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key,kwargs[key],rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key,kwargs[key],rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut,dict1))
        return ret_val1

    ret_val = "True"
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val


def show_mclag_uniqueip(dut, **kwargs):
    """
    API to display the mclag unique ip
    :param dut:
    :param cli_type:
    :param mclag_id:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if cli_type == "klish":
        command = "show mclag separate-ip-interfaces"
    elif cli_type == "click":
        command = "mclagdctl -i {} dump unique_ip".format(kwargs['mclag_id'])
    st.show(dut, command,skip_tmpl=True,type=cli_type)

def show_ip_neigh(dut, **kwargs):
    """
    API to display ip neighbor
    :param dut:
    :param cli_type:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if cli_type == "klish":
        command1 = "show ip arp"
        command2 = "show ipv6 neighbors"
        st.show(dut, command1,skip_tmpl=True,type=cli_type)
        st.show(dut, command2,skip_tmpl=True,type=cli_type)
    elif cli_type == "click":
        command = "ip neigh show"
        st.show(dut, command,skip_tmpl=True,type=cli_type)

def get_tunnel_list(dut,**kwargs):
    """
    API to return the list if tunnels present in the dut
    :param dut:
    :param cli_type:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    res=st.show(dut, 'show vxlan tunnel',type=cli_type)
    tun_lst=[]
    for l1 in res:
        tun_lst.append(l1['rem_vtep'])
    return tun_lst


def config_vxlan_qos_mode(dut, vtep_name,**kwargs):
    """
    purpose:
            This definition is used to configure VxLAN QOS mode

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param vtep_name: VTEP name to be created
    :type vtep_name: string
    :param : cli_type
    :type cli_type: string
    :param kwargs["qos_mode"]: qos mode to be configured either uniform/pipe
    :type kwargs["qos_mode"]: dict
    :param kwargs["pipe_dscp"]: dscp value to be set for PIPE mode
    :type kwargs["pipe_dscp"]: dict
    :return: None

    usage:
        config_vxlan_qos_mode(dut1, "dut1VTEP", qos_mode="uniform")
        config_vxlan_qos_mode(dut1, "dut1VTEP", qos_mode="pipe",pipe_dscp="10")

    Created by: Julius <julius.mariyan@broadcom.com
    """
    cli_type = st.get_ui_type(dut,**kwargs)
    qosMode = kwargs.get("qos_mode", "pipe dscp 0")
    if cli_type == "klish":
        command = []
        command.append('interface vxlan {}'.format(vtep_name))
        if qosMode == "pipe" and "pipe_dscp" in kwargs:
            command.append("qos-mode pipe dscp {}".format(kwargs["pipe_dscp"]))
        elif qosMode == "uniform":
            command.append("qos-mode uniform")
        else:
            command.append("qos-mode {}".format(qosMode))
        command.append('exit')
        return st.config(dut, command, type=cli_type)
    elif cli_type == "rest-put":
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["config_vxlan_qos"]
        if qosMode == "uniform":
            payload = {"openconfig-interfaces:interface" : [{"name": vtep_name,"config":{"name": vtep_name,
                       "type": "IF_NVE"}, "openconfig-vxlan:vxlan-if": {"config": {"qos-mode": "UNIFORM"}}}]}
        elif qosMode == "pipe" and "pipe_dscp" in kwargs:
            payload = {"openconfig-interfaces:interface" : [{"name": vtep_name,"config":{"name": vtep_name,
                       "type": "IF_NVE"}, "openconfig-vxlan:vxlan-if": {"config": {"qos-mode": "PIPE",
                           "dscp" : int(kwargs["pipe_dscp"])}}}]}
        else:
            payload = {"openconfig-interfaces:interface" : [{"name": vtep_name,"config":{"name": vtep_name,
                       "type": "IF_NVE"}, "openconfig-vxlan:vxlan-if": {"config": {"qos-mode": "PIPE",
                       "dscp" : 0}}}]}
        return config_rest(dut, http_method='post', rest_url=url, json_data=payload,timeout=10)
    elif cli_type == "rest-patch":
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls["modify_vxlan_qos"].format(vtep_name)
        if qosMode == "uniform":
            payload = {"openconfig-vxlan:config":{"qos-mode": qosMode.upper()}}
        elif qosMode == "pipe" and "pipe_dscp" in kwargs:
            payload = {"openconfig-vxlan:config": {"qos-mode": qosMode.upper(),"dscp": int(kwargs["pipe_dscp"])}}
        else:
            payload = {"openconfig-vxlan:config": {"qos-mode": qosMode.upper(),"dscp": 0}}
        return config_rest(dut, http_method='patch', rest_url=url, json_data=payload,timeout=10)
    else:
        st.error("Nothing configured for this UI-TYPE {}").format(cli_type)
        return False

def verify_vxlan_qos_mode(dut, vtep_name, qos_mode,**kwargs):
    '''
    purpose:
            This definition is used to verify VxLAN interface QOS mode

    Arguments:
    :param dut: Device name where the command to be executed
    :type dut: string
    :param vtep_name: vtep name to be verified
    :type vtep_name: string
    :param qos_mode: qos mode name to be verified
    :type qos_mode: string
    :param kwargs["pipe_dscp"]:PIPE DSCP value to be verified
    :type kwargs["pipe_dscp"]: dict
    :return: True/False  True - success case; False - Failure case

    usage:  verify_vxlan_qos_mode(dut1,qos_mode="uniform")
            verify_vxlan_qos_mode(dut1,qos_mode="pipe",pipe_dscp=10)

    Created by: Julius <julius.mariyan@broadcom.com
    '''
    success = True
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "klish":
        if qos_mode == "pipe" and "pipe_dscp" in kwargs:
            verify_dict = {"qos_mode" : "pipe", "pipe_dscp" : kwargs["pipe_dscp"]}
        elif qos_mode == "uniform":
            verify_dict = {"qos_mode" : "uniform"}
        else:
            verify_dict = {"qos_mode" : "pipe", "pipe_dscp" : "0"}
        cli_out = st.show(dut, 'show vxlan interface', type=cli_type)
        fil_out = filter_and_select(cli_out, verify_dict.keys(), {"vtep_name": vtep_name})
        if len(fil_out) == 0:
            st.error("QOS details {} not found in show output".format(verify_dict.keys()))
            return False
        else:
            dut_out = fil_out[0]
        for key in verify_dict.keys():
            if dut_out[key] == verify_dict[key]:
                st.log("Match found for key {}; expected val: {} and "
                       "obtained val: {}".format(key, verify_dict[key], dut_out[key]))
            else:
                st.error("Match NOT found for key {}; expected val: {} but "
                         "obtained val: {}".format(key, verify_dict[key], dut_out[key]))
                success = False
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if "pipe_dscp" not in kwargs:
            url = rest_urls["get_vxlan_qos_mode"].format(vtep_name)
            rest_out = get_rest(dut,rest_url=url,timeout=30)
            if rest_out["status"] == 200:
                if qos_mode == rest_out["output"]["openconfig-vxlan:qos-mode"].lower():
                    st.log("Match found for QOS mode; expected val: {} and "
                           "obtained val: {}".format(qos_mode,
                                                     rest_out["output"]["openconfig-vxlan:qos-mode"].lower()))
                else:
                    st.error("Match NOT found for QOS mode; expected val: {} "
                             "but got: {}".format(qos_mode,
                                                  rest_out["output"]["openconfig-vxlan:qos-mode"].lower()))
                    success = False
            else:
                st.error("VxLAN QOS mode value NOT found in rest output")
                return False
        else:
            url = rest_urls["get_vxlan_qos_pipe_val"].format(vtep_name)
            rest_out = get_rest(dut,rest_url=url,timeout=30)
            if rest_out["status"] == 200:
                if int(kwargs["pipe_dscp"]) == rest_out["output"]["openconfig-vxlan:dscp"]:
                    st.log("Match found for PIPE DSCP; expected val: {} and "
                           "obtained val: {}".format(int(kwargs["pipe_dscp"]),
                                                     rest_out["output"]["openconfig-vxlan:dscp"]))
                else:
                    st.error("Match NOT found for PIPE DSCP; expected val: {} "
                             "but got: {}".format(int(kwargs["pipe_dscp"]),
                                                  rest_out["output"]["openconfig-vxlan:dscp"]))
                    success = False
            else:
                st.error("PIPE DSCP value not found in rest output")
                return False
    return success
