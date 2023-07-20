from utilities.common import filter_and_select,get_query_params
from spytest import st
from apis.routing.bgp import show_bgp_ipv4_summary_vtysh, show_bgp_ipv6_summary_vtysh, \
    show_bgp_ipv4_neighbor_vtysh, show_bgp_ipv6_neighbor_vtysh, verify_bgp_neigh_umf, _parse_ip_bgp_data
from utilities.utils import get_supported_ui_type_list

try:
    import apis.yang.codegen.messages.network_instance as umf_ni
except ImportError:
    pass

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def verify_bgp_neighbor(dut,**kwargs):
    """
    Author:naveen.nagaraju@broadcom.com
    :param neighbor_address:
    :type bgp-neighbor-address (list or string)
    :param remoteasn:
    :type bgp-remote-as
    :param localasn:
    :type bgp-local-as
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    bgp.verify_bgp_neighbor(dut1,neighborip="10.1.1.12",remoteasn='12',localasn='10')

    Example output in dictionary forms
    [{'neighborip': '10.1.1.12', 'peergroup': 'ava', 'updatercvd': '0', 'inqdepth': '0', 'opensent': '31', 'bgpversion': '4', 'bfdrxintr': '300', 'capabilityrcvd': '0', 'lastwrite': '00:00:40', 'keepalivesent': '7351', 'keepalive': '60', 'outqdepth': '0', 'uptime': '5d00h25m', 'lastread': '00:00:27', 'bfdmultiplier': '3', 'bfdstatus': 'Down', 'state': 'Established,', 'routerefreshrcvd': '0', 'remrouterid': '23.23.23.23', 'bfdtxintr': '300', 'grcapability': 'advertised', 'bfdlastupdate': '5:00:37:18', 'routerefreshsent': '0', 'senttotal': '7404', 'notificationrcvd': '2', 'bfdtype': 'single', 'rcvdtotal': '8601', 'notificationsent': '22', 'remoteasn': '12', 'openrcvd': '14', 'localasn': '10', 'keepalivercvd': '8585', 'asbyte': '4', 'localrouterid': '1.1.1.1', 'capablitysent': '0', 'updatesent': '0', 'holdtime': '180'}]


    """
    cli_type = kwargs.pop('cli_type',st.get_ui_type(dut, **kwargs))
    cli_type = 'vtysh' if cli_type in ['vtysh', 'click'] else cli_type
    result = False

    st.log("verify show bgp neighbor")

    if 'neighborip' not in kwargs:
        st.error("Mandatory parameter neighborip is not found")
        return result
    
    if 'vrf' in kwargs:
        vrf = kwargs['vrf']
        del kwargs['vrf']
    else:
        if cli_type in get_supported_ui_type_list():
            vrf='default'
        else:
            vrf = 'default-vrf'

    family = kwargs.pop('family','ipv4')
    return_output = kwargs.pop('return_output', False)
    router_id = kwargs.pop('router_id', '0.0.0.0')
    #Converting all kwargs to list type to handle single or multiple BGP neighbors
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    if cli_type in get_supported_ui_type_list():
        gnmi_result=True
        ret_val = {}
        vrf = 'default' if vrf == 'default-vrf' else vrf
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        afi_safi_mapping = {
            'ipv4': 'IPV4_UNICAST',
            'ipv6': 'IPV6_UNICAST',
            'l2vpn': 'L2VPN_EVPN',
        }
        umf_ni.GlobalAfiSafi(AfiSafiName=afi_safi_mapping[family], Protocol=proto_obj)
        for neigh in kwargs['neighborip']:
            nbr_index = kwargs['neighborip'].index(neigh)
            nbr_attr_list = {
                'keep_alive': ['KeepaliveInterval', int(kwargs['keep_alive'][nbr_index]) if 'keep_alive' in kwargs else None],
                'hold': ['HoldTime', int(kwargs['hold'][nbr_index]) if 'hold' in kwargs else None],
                'remote_asn': ['PeerAs', kwargs['remote_asn'][nbr_index] if 'remote_asn' in kwargs else None],
                'password': ['Password', kwargs['password'][nbr_index] if 'password' in kwargs else None],
                'connect': ['ConnectRetry', int(kwargs['connect'][nbr_index]) if 'connect' in kwargs else None],
                'ebgp_multihop': ['MultihopTtl', int(kwargs['ebgp_multihop'][nbr_index]) if 'ebgp_multihop' in kwargs else None],
                'update_src': ['LocalAddress', kwargs['update_src'][nbr_index] if 'update_src' in kwargs else None],
                'update_src_intf': ['LocalAddress', kwargs['update_src_intf'][nbr_index] if 'update_src_intf' in kwargs else None],
                'enforce_first_as': ['EnforceFirstAs', True if 'enforce_first_as' in kwargs else None],
                'local_as': ['LocalAs', kwargs['local_as'][nbr_index] if 'local_as' in kwargs else None],
                'local_as_no_prepend': ['LocalAsNoPrepend', True if 'local_as_no_prepend' in kwargs else None],
                'local_as_replace_as': ['LocalAsReplaceAs', True if 'local_as_replace_as' in kwargs else None],
                'bfd': ['EnableBfdEnabled', True if 'bfd' in kwargs else None],
                'bfd_profile': ['BfdProfile', kwargs['bfd_profile'][nbr_index] if 'bfd_profile' in kwargs else None],
                'state': ['SessionState', kwargs['state'][nbr_index] if 'state' in kwargs else None],
                'bgpdownreason' : ['LastResetReason', kwargs['bgpdownreason'][nbr_index] if 'bgpdownreason' in kwargs else None],
            }
            if nbr_attr_list['bgpdownreason'][1] in ['BFD down received','Interface down','Hold Timer Expired']:
                nbr_attr_list['bgpdownreason'] = ['LastResetReason', 'Waiting for NHT']
            if nbr_attr_list['remote_asn'][1] is not None:
                if str(nbr_attr_list['remote_asn'][1]).isdigit():
                    nbr_attr_list['remote_asn'][1] = int(nbr_attr_list['remote_asn'][1])
                elif str(nbr_attr_list['remote_asn'][1]) == 'internal':
                    nbr_attr_list['remote_asn'] = ['PeerType', 'INTERNAL']
                else:
                    nbr_attr_list['remote_asn'] = ['PeerType', 'EXTERNAL']
            if nbr_attr_list['state'][1] is not None:
                nbr_attr_list['state'] = ['SessionState', nbr_attr_list['state'][1].upper()]
            nbr_obj = umf_ni.BgpNeighbor(NeighborAddress=neigh, Protocol=proto_obj)
            for key in kwargs.keys():
                if key != 'neighborip' :
                    if key in nbr_attr_list:
                        if nbr_attr_list[key][1] is not None:
                            setattr(nbr_obj, nbr_attr_list[key][0], nbr_attr_list[key][1])
                    else:
                        st.error("Kindly add Argument {} to this variable \"nbr_attr_list\" "
                                 "in API \"verify_bgp_neighbor\"".format(key))
                        return False
            if not return_output:
                result = nbr_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
                if not result.ok():
                    gnmi_result=False
                    st.log("Match NOT found for neighbor {}; kindly check actual and expected fields above".format(neigh))
                else:
                    st.log("Match found for neighbor {}".format(neigh))
            else:
                result = nbr_obj.get_payload(dut, query_param=query_param_obj, cli_type=cli_type)
                ret = result.payload.get("openconfig-network-instance:neighbor", '')
                if ret:
                    ret_val["openconfig-network-instance:neighbors"] = {}
                    ret_val["openconfig-network-instance:neighbors"]['neighbor'] = []
                    ret_val["openconfig-network-instance:neighbors"]['neighbor'].extend(ret)
        if return_output:
            return _parse_ip_bgp_data(ret_val, family, router_id)
        return gnmi_result
    else:
        if vrf != 'default-vrf':
            if cli_type == 'vtysh':
                if len(kwargs['neighborip']) == 1:
                    cmd = "show bgp vrf {} neighbors {}".format(vrf, kwargs['neighborip'][0])
                else:
                    cmd = "show bgp vrf {} neighbors ".format(vrf)
            elif cli_type == 'klish':
                if len(kwargs['neighborip']) == 1:
                    cmd = "show bgp {} unicast vrf {} neighbors {}".format(family, vrf, kwargs['neighborip'][0])
                else:
                    cmd = "show bgp {} unicast vrf {} neighbors".format(family, vrf)
            elif cli_type in ["rest-patch", "rest-put"]:
                if family == "ipv4":
                    if len(kwargs['neighborip']) == 1:
                        output = show_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip=kwargs['neighborip'][0], vrf=vrf,
                                                              cli_type=cli_type)
                    else:
                        output = show_bgp_ipv4_neighbor_vtysh(dut, vrf=vrf, cli_type=cli_type)
                else:
                    if len(kwargs['neighborip']) == 1:
                        output = show_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip=kwargs['neighborip'][0], vrf=vrf,
                                                              cli_type=cli_type)
                    else:
                        output = show_bgp_ipv6_neighbor_vtysh(dut, vrf=vrf, cli_type=cli_type)
        else:
            if cli_type == 'vtysh':
                if len(kwargs['neighborip']) == 1:
                    cmd = "show bgp neighbors {}".format(kwargs['neighborip'][0])
                else:
                    cmd = "show bgp neighbors"
            elif cli_type == 'klish':
                if len(kwargs['neighborip']) == 1:
                    cmd = "show bgp {} unicast neighbors {}".format(family, kwargs['neighborip'][0])
                else:
                    cmd = "show bgp {} unicast neighbors".format(family)
            elif cli_type in ["rest-patch", "rest-put"]:
                if family == "ipv4":
                    if len(kwargs['neighborip']) == 1:
                        output = show_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip=kwargs['neighborip'][0], vrf="default",
                                                              cli_type=cli_type)
                    else:
                        output = show_bgp_ipv4_neighbor_vtysh(dut, vrf="default", cli_type=cli_type)
                else:
                    if len(kwargs['neighborip']) == 1:
                        output = show_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip=kwargs['neighborip'][0], vrf="default",
                                                              cli_type=cli_type)
                    else:
                        output = show_bgp_ipv6_neighbor_vtysh(dut, vrf="default", cli_type=cli_type)
        if cli_type not in ["rest-patch", "rest-put"]:
            output = st.show(dut, cmd, type=cli_type)
        if return_output: return output
    # Get the index of peer from list of parsed output
    for i in range(len(kwargs['neighborip'])):
        nbr_index = None
        st.log("Validation for BGP Neighbor : %s" % kwargs['neighborip'][i])
        for peer_info in output:
            if peer_info['neighborip'] == kwargs['neighborip'][i]:
                nbr_index = output.index(peer_info)
        if nbr_index is not None:
            # Iterate through the user parameters
            for k in kwargs.keys():
                if k != 'neighborip':
                    if output[nbr_index][k] == kwargs[k][i] or output[nbr_index][k] == kwargs[k][i].upper():
                        st.log(
                            'Match Found for %s :: Expected: %s  Actual : %s' % (k, kwargs[k][i], output[nbr_index][k]))
                        result = True
                    else:
                        if kwargs[k][i] in ['BFD down received', 'Interface down',
                                            'Hold Timer Expired'] and 'Waiting for NHT' in output[nbr_index][k]:
                            st.log(
                                'Match checking for Waiting for NHT and Found for %s :: Expected: %s  Actual : %s' % (
                                    k, output[nbr_index][k], output[nbr_index][k]))
                            result = True
                        else:
                            st.error('Match Not Found for %s :: Expected: %s  Actual : %s' % (
                            k, kwargs[k][i], output[nbr_index][k]))
                            return False
        else:
            st.error(" BGP neighbor %s not found in output" % kwargs['neighborip'][i])
            return False
    return result


def check_bgp_session(dut,nbr_list=[],state_list=[],vrf_name='default',**kwargs):
    """
    Author:sooriya.gajendrababu@broadcom.com
    :param nbr_list:
    :type list of BGPneighbors
    :param state_list:
    :type list of states
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    ret_val = True
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if kwargs.get("scale_env", ""):
        cli_type="klish"
        kwargs.pop("scale_env")
    if cli_type in get_supported_ui_type_list():
        family = kwargs.pop('family', 'ipv4')
        return verify_bgp_neigh_umf(dut, vrf=vrf_name, family=family, neighborip=nbr_list,
                                    state=state_list, cli_type=cli_type)
    else:
        output=[]
        if cli_type == 'click':
            if vrf_name == 'default':
                output = st.show(dut,'show ip bgp summary', type='vtysh')
            else:
                output = st.show(dut, 'show ip bgp vrf {} summary'.format(vrf_name), type='vtysh')
        elif cli_type == 'klish':
            family = kwargs.pop('family','ipv4')
            if vrf_name == 'default':
                output = st.show(dut,'show bgp {} unicast summary'.format(family), type='klish')
            else:
                output = st.show(dut, 'show bgp {} unicast vrf {} summary'.format(family,vrf_name), type='klish')
        elif cli_type in ["rest-put", "rest-patch"]:
            family = kwargs.pop('family', 'ipv4')
            if family == "ipv4":
                output = show_bgp_ipv4_summary_vtysh(dut, vrf_name, cli_type=cli_type)
            else:
                output = show_bgp_ipv6_summary_vtysh(dut, vrf_name, cli_type=cli_type)

        if len(output)!=0:
            for nbr,state in zip(nbr_list,state_list):
                match = {'neighbor': nbr}
                entry = filter_and_select(output, None, match)
                if not bool(entry):
                    st.log("BGP Neighbor entry {} is not found".format(nbr))
                    ret_val = False
                for entries in entry:
                    if state=='Established':
                        if entries['state'].isdigit() or entries['state'] == "ESTABLISHED":
                            st.log("BGP Neighbor {} in Established state".format(nbr))
                        else:
                            st.error("BGP Neighbor {} state check Failed. Expected:{} Actual :{} ".format(nbr,state,entries['state']))
                            ret_val=False
                    else:
                        if str(state).upper() == str(entries['state']).upper():
                            st.log("BGP Neighbor {} check passed. Expected : {} Actual {}".format(nbr,state,entries['state']))
                        else:
                            st.error("BGP Neighbor {} state check Failed. Expected:{} Actual :{} ".format(nbr, state, entries['state']))
                            ret_val=False
        else:
            st.error("Output is empty")
            ret_val=False

        return ret_val