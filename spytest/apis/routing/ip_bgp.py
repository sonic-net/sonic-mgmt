from spytest.utils import filter_and_select
from spytest import st
from apis.routing.bgp import show_bgp_ipv4_summary_vtysh, show_bgp_ipv6_summary_vtysh, show_bgp_ipv4_neighbor_vtysh, show_bgp_ipv6_neighbor_vtysh


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
        vrf = 'default-vrf'

    family = kwargs.pop('family','ipv4')
    #Converting all kwargs to list type to handle single or multiple BGP neighbors
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    if vrf != 'default-vrf':
        if cli_type == 'vtysh':
            if len(kwargs['neighborip']) == 1:
                cmd = "show bgp vrf {} neighbors {}".format(vrf,kwargs['neighborip'][0])
            else:
                cmd = "show bgp vrf {} neighbors ".format(vrf)
        elif cli_type == 'klish':
            if len(kwargs['neighborip']) == 1:
                cmd = "show bgp {} unicast vrf {} neighbors {}".format(family,vrf,kwargs['neighborip'][0])
            else:
                cmd = "show bgp {} unicast vrf {} neighbors".format(family,vrf)
        elif cli_type in ["rest-patch", "rest-put"]:
            if family == "ipv4":
                if len(kwargs['neighborip']) == 1:
                    output = show_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip=kwargs['neighborip'][0], vrf=vrf, cli_type=cli_type)
                else:
                    output = show_bgp_ipv4_neighbor_vtysh(dut, vrf=vrf, cli_type=cli_type)
            else:
                if len(kwargs['neighborip']) == 1:
                    output = show_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip=kwargs['neighborip'][0], vrf=vrf, cli_type=cli_type)
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
                cmd = "show bgp {} unicast neighbors {}".format(family,kwargs['neighborip'][0])
            else:
                cmd = "show bgp {} unicast neighbors".format(family)
        elif cli_type in ["rest-patch", "rest-put"]:
            if family == "ipv4":
                if len(kwargs['neighborip']) == 1:
                    output = show_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip=kwargs['neighborip'][0], vrf="default", cli_type=cli_type)
                else:
                    output = show_bgp_ipv4_neighbor_vtysh(dut, vrf=vrf, cli_type=cli_type)
            else:
                if len(kwargs['neighborip']) == 1:
                    output = show_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip=kwargs['neighborip'][0], vrf="default", cli_type=cli_type)
                else:
                    output = show_bgp_ipv6_neighbor_vtysh(dut, vrf=vrf, cli_type=cli_type)
    if cli_type not in ["rest-patch", "rest-put"]:
        output = st.show(dut, cmd, type=cli_type)

    #Get the index of peer from list of parsed output
    for i in range(len(kwargs['neighborip'])):
        nbr_index = None
        st.log("Validation for BGP Neighbor : %s"%kwargs['neighborip'][i])
        for peer_info in output:
            if peer_info['neighborip'] == kwargs['neighborip'][i]:
                nbr_index = output.index(peer_info)
        if nbr_index is not None:
            #Iterate through the user parameters
            for k in kwargs.keys():
                if k != 'neighborip':
                    if output[nbr_index][k] == kwargs[k][i]:
                        st.log('Match Found for %s :: Expected: %s  Actual : %s'%(k,kwargs[k][i],output[nbr_index][k]))
                        result=True
                    else:
                        if kwargs[k][i] in ['BFD down received','Interface down','Hold Timer Expired'] and 'Waiting for NHT' in output[nbr_index][k]:
                            st.log('Match checking for Waiting for NHT and Found for %s :: Expected: %s  Actual : %s' % (
                            k, output[nbr_index][k], output[nbr_index][k]))
                            result = True
                        else:
                            st.error('Match Not Found for %s :: Expected: %s  Actual : %s'%(k,kwargs[k][i],output[nbr_index][k]))
                            return False
        else:
            st.error(" BGP neighbor %s not found in output"%kwargs['neighborip'][i])
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
    # if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
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
