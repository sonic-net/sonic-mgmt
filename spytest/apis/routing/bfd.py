
import datetime

from spytest import st
import apis.common.asic as asicapi
from apis.system.interface import clear_interface_counters, show_interface_counters_all
from apis.routing.arp import show_arp, show_ndp
from apis.system.rest import config_rest, get_rest, delete_rest
from apis.routing import ip as ip_api
from utilities.common import filter_and_select, make_list, exec_all, is_valid_ipv4

def verify_bfd_counters(dut,**kwargs):
    """
    Author:gangadhara.sahu@broadcom.com
    :param peeraddress:
    :type bfd-peer-address
    :param localaddr:
    :type bfd-local-address
    :param interface:
    :type interface
    :param cntrlpktOut:
    :type control-packet-out
    :param cntrlpktIn:
    :type control-acket-in
    :param echopktin:
    :type echo-packet-in
    :param echopktout:
    :type echo-packet-out
    :param sessionupev:
    :type session-up-event
    :param sessiondownev:
    :type session-down-event
    :param zebranotifys:
    :type Zebra-notifications
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    bfd.verify_bfd_counters(dut1,cntrlpktout="100",cntrlpktin="100",peeraddress="5000::2")
    bfd.verify_bfd_counters(dut1,cntrlpktout="200",cntrlpktin="200",peeraddress="50.1.1.2")
    """
    cli_type = st.get_ui_type(dut, **kwargs)

    result = False
    st.log("verify show bfd peers counters")

    if 'vrf_name' in kwargs:
        vrf = kwargs['vrf_name']
        if vrf == 'default':
            vrf = 'default-vrf'
        del kwargs['vrf_name']
    else:
        vrf = 'default-vrf'

    cmd = "show bfd"
    if vrf != 'default-vrf':
        if cli_type == 'click':
            cmd = cmd + ' vrf ' + vrf + ' peers counters'
        elif cli_type == 'klish':
            cmd = cmd + ' peers' + ' vrf ' + vrf +' counters'
    else:
        cmd = cmd + ' peers counters'

    output = []
    if cli_type in ['click', 'klish']:
        cli_type = "vtysh" if cli_type == "click" else cli_type
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        # st.show(dut, "show bfd peers counters", type='klish')
        output = rest_get_bfd_peer_info(dut, 'counters')
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return False

    match_dict = {}
    if 'peeraddress' in kwargs:
        match_dict['peeraddress'] = kwargs['peeraddress']
    else:
        st.error("Mandatory parameter peeraddress is not found")
        return result

    out_param = []
    for key in kwargs:
        out_param.append(key)
    entries = filter_and_select(output,out_param, match_dict)

    if bool(entries):
        if 'cntrlpktout' in out_param:
            if int(entries[0]['cntrlpktout']) >= int(kwargs['cntrlpktout']):
                result = True
                st.log("Number of output BFD Control packet is {} for peer {} Test Passed".format(int(entries[0]['cntrlpktout']),kwargs['peeraddress']))
            else:
                result = False
                st.error("Number of output BFD Control packet is {} for peer {} Test Failed as less than expected".format(int(entries[0]['cntrlpktout']),kwargs['peeraddress']))
        if 'cntrlpktin' in out_param:
            if int(entries[0]['cntrlpktin']) >= int(kwargs['cntrlpktin']):
                result = True
                st.log("Number of input BFD Control packet is {} for peer {} Test Passed".format(int(entries[0]['cntrlpktin']),kwargs['peeraddress']))
            else:
                result = False
                st.error("Number of input BFD Control packet is {} for peer {} Test Failed as less than expected".format(int(entries[0]['cntrlpktin']),kwargs['peeraddress']))
        if 'cntrlpktout' not in out_param and 'cntrlpktin' not in out_param:
            result = True
            st.log("BFD Peer IP {} exist in the output - Test Passed".format(kwargs['peeraddress']))
        if 'SessionUpEv' in out_param:
            if int(entries[0]['SessionUpEv']) == int(kwargs['SessionUpEv']):
                result = True
                st.log("Number of BFD UP event is {} for peer {} Test Passed".format(int(entries[0]['SessionUpEv']), kwargs['peeraddress']))
            else:
                result = False
                st.log("Number of BFD UP event is {} for peer {} Test Failed".format(int(entries[0]['SessionUpEv']), kwargs['peeraddress']))
        if 'SessionDownEv' in out_param:
            if int(entries[0]['SessionDownEv']) == int(kwargs['SessionDownEv']):
                result = True
                st.log("Number of BFD Down event is {} for peer {} Test Passed".format(int(entries[0]['SessionDownEv']), kwargs['peeraddress']))
            else:
                result = False
                st.log("Number of BFD Down event is {} for peer {} Test Failed".format(int(entries[0]['SessionDownEv']), kwargs['peeraddress']))
    else:
        st.error("Either BFD Peer IP {} or other passed arguments does not exist".format(kwargs['peeraddress']))

    return result


def configure_bfd(dut, **kwargs):
    """
    Author:gangadhara.sahu@broadcom.com
    :param local_asn:
    :type local-as-number:
    :param interface:
    :type interface:
    :param config:
    :type yes-or-no:
    :param neighbor_ip:
    :type neighbor-ip:
    :param multiplier:
    :type detect-multiplier:
    :param rx_intv:
    :type rx-interval:
    :param tx_intv:
    :type tx-interval:
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    configure_bfd(dut1, local_asn="10",neighbor_ip="50.1.1.2",config="yes")
    configure_bfd(dut1, local_asn="10",neighbor_ip="50.1.1.2",config="no")
    configure_bfd(dut1, local_asn="10",neighbor_ip="5000::2",config="yes")
    configure_bfd(dut1, interface="Ethernet0",neighbor_ip="50.1.1.2",multiplier="100",rx_intv="200",tx_intv="300" )
    configure_bfd(dut1, interface="Ethernet0",local_address="5000::1",neighbor_ip="5000::2",multiplier="100",rx_intv="200",tx_intv="300")
    configure_bfd(dut1, interface="Ethernet0",local_address="5000::1",neighbor_ip="5000::2",multiplier="100",rx_intv="200",tx_intv="300",multihop="yes")
    configure_bfd(dut1,local_address="10.1.1.1",neighbor_ip="20.1.1.1",multihop="yes",noshut="yes",label="abcd")
    configure_bfd(dut1,local_address="10.1.1.1",neighbor_ip="20.1.1.1",multihop="yes",shutdown="yes")
    """

    if 'vrf_name' in kwargs:
        vrf = kwargs['vrf_name']
        if vrf == 'default':
            vrf = 'default-vrf'
        del kwargs['vrf_name']
    else:
        vrf = 'default-vrf'

    cli_type = st.get_ui_type(dut, **kwargs)

    if 'neighbor_ip' not in kwargs:
        st.error("Mandatory parameter - neighbor_ip not found")
        return False

    peergroup = kwargs.get('peergroup', None)
    nbr_cmd = 'peer-group' if peergroup else 'neighbor'

    if 'config' in kwargs and kwargs['config'] == 'no':
        config=kwargs['config']
        del kwargs['config']
    else:
        config=''

    if 'multihop' in kwargs:
        multihop_cmd = 'multihop'
        del kwargs['multihop']
    else:
        multihop_cmd = ''

    #Converting all kwargs to list type to handle single or multiple peers
    for key in kwargs:
        if key != 'local_asn':
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

    #if 'local_asn' in kwargs and 'interface' not in kwargs:
    if 'local_asn' in kwargs:
        st.log("Entering router BGP..")
        if cli_type in ['click', 'klish']:
            if vrf == 'default-vrf':
                cmd = "router bgp {}\n".format(kwargs['local_asn'])
            else:
                cmd = "router bgp {} vrf {}\n".format(kwargs['local_asn'], vrf)
            for nbr in kwargs['neighbor_ip']:
                if cli_type == 'click':
                    cmd1 = cmd + "{} neighbor {} bfd \n".format(config, nbr)
                    st.config(dut, cmd1, type='vtysh')
                elif cli_type == 'klish':
                    if 'interface' in kwargs:
                        cmd1 = cmd + "{} interface {} \n {} bfd \n exit \n exit \n".format(nbr_cmd, nbr, config)
                    else:
                        cmd1 = cmd + "{} {} \n {} bfd \n exit \n exit \n".format(nbr_cmd, nbr, config)
                    st.config(dut, cmd1, type=cli_type)
        elif cli_type in ['rest-patch', 'rest-put']:
            vrf_str = 'default' if vrf == 'default-vrf' else vrf
            rest_urls = st.get_datastore(dut, "rest_urls")
            neigh_list = []
            for nbr in kwargs['neighbor_ip']:
                if not config:
                    neighbor_cmd = "neighbor-address" if nbr_cmd == 'neighbor' else "peer-group-name"
                    temp = {
                            neighbor_cmd: nbr,
                            "openconfig-bfd:enable-bfd": {"config": {"enabled": True, "openconfig-bgp-ext:bfd-check-control-plane-failure": True}}
                            }
                    neigh_list.append(temp)
                else:
                    neighbor_url = ["delete_bgp_neighbor_bfd_enabled", "delete_bgp_neighbor_bfd_cnpl_failure"] if nbr_cmd == 'neighbor' else ["delete_bgp_peergroup_bfd_enabled", "delete_bgp_peergroup_bfd_cnpl_failure"]
                    for url in neighbor_url:
                        url = rest_urls[url].format(vrf_str, nbr)
                        if not delete_rest(dut, http_method='delete', rest_url=url):
                            return False
            if not config:
                neighbor_url = "config_bgp_neighbor_list" if nbr_cmd == 'neighbor' else "config_bgp_peergroup_list"
                url = rest_urls[neighbor_url].format(vrf_str)
                data = {"openconfig-network-instance:{}".format(nbr_cmd): neigh_list}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False
    else:
        st.log("Entering BFD..")
        if cli_type in ['click', 'klish']:
            cmd ='bfd\n'
            for peer_index,nbr in zip(range(len(kwargs['neighbor_ip'])),kwargs['neighbor_ip']):
                if not multihop_cmd:
                    cmd += "{} peer {} ".format(config, nbr)
                else:
                    cmd += "{} peer {} {} ".format(config, nbr, multihop_cmd)

                if vrf == 'default-vrf':
                    if 'interface' in kwargs and "local_address" not in kwargs:
                        cmd += "interface {} \n".format(kwargs['interface'][peer_index])
                    elif 'interface' not in kwargs and "local_address" in kwargs:
                        cmd += "local-address {} \n".format(kwargs['local_address'][peer_index])
                    elif 'interface' in kwargs and "local_address" in kwargs:
                        cmd += "local-address {} interface {} \n".format(kwargs['local_address'][peer_index], kwargs['interface'][peer_index])
                else:
                    if 'interface' in kwargs and "local_address" not in kwargs:
                        cmd += "interface {} vrf {}\n".format(kwargs['interface'][peer_index], vrf)
                    elif 'interface' not in kwargs and "local_address" in kwargs:
                        cmd += "local-address {} vrf {}\n".format(kwargs['local_address'][peer_index], vrf)
                    elif 'interface' in kwargs and "local_address" in kwargs:
                        cmd += "local-address {} interface {} vrf {}\n".format(kwargs['local_address'][peer_index], kwargs['interface'][peer_index], vrf)

                if 'multiplier' in kwargs and config != 'no':
                    cmd += "detect-multiplier {} \n".format(kwargs['multiplier'][peer_index])
                if 'rx_intv' in kwargs and config != 'no':
                    cmd += "receive-interval {} \n".format(kwargs['rx_intv'][peer_index])
                if 'tx_intv' in kwargs and config != 'no':
                    cmd += "transmit-interval {} \n".format(kwargs['tx_intv'][peer_index])
                if 'noshut' in kwargs and config != 'no':
                    cmd += "no shutdown \n"
                if 'shutdown' in kwargs and config != 'no':
                    cmd += "shutdown \n"
                if 'echo_mode_enable' in kwargs and config != 'no':
                    cmd += "echo-mode \n"
                if 'echo_mode_disable' in kwargs and config != 'no':
                    cmd += "no echo-mode \n"
                if 'echo_intv' in kwargs and config != 'no':
                    cmd += "echo-interval {} \n".format(kwargs['echo_intv'][peer_index])
                if 'label' in kwargs and config != 'no':
                    cmd += "label {} \n".format(kwargs['label'][peer_index])
                if config != 'no':
                    cmd += 'exit \n'
            cmd += 'exit \n'
            if cli_type == 'click':
                st.config(dut,cmd, type='vtysh')
            elif cli_type == 'klish':
                st.config(dut, cmd, type=cli_type, faster_cli=False)
        elif cli_type in ['rest-patch', 'rest-put']:
            rest_urls = st.get_datastore(dut, "rest_urls")
            peer_type = 'multi' if multihop_cmd else 'single'
            vrf_str = 'default' if vrf == 'default-vrf' else vrf
            peer_list = []
            for peer_index, nbr in enumerate(kwargs['neighbor_ip']):
                temp = dict()
                temp['remote-address'] = nbr
                if 'interface' in kwargs: temp['interface'] = kwargs['interface'][peer_index]
                if 'multiplier' in kwargs: temp['detection-multiplier'] = int(kwargs['multiplier'][peer_index])
                if 'rx_intv' in kwargs: temp['required-minimum-receive'] = int(kwargs['rx_intv'][peer_index])
                if 'tx_intv' in kwargs: temp['desired-minimum-tx-interval'] = int(kwargs['tx_intv'][peer_index])
                if 'echo_mode_enable' in kwargs: temp['echo-active'] = True
                if 'echo_mode_disable' in kwargs: temp['echo-active'] = False
                if 'echo_intv' in kwargs: temp['desired-minimum-echo-receive'] = int(kwargs['echo_intv'][peer_index])
                if 'shutdown' in kwargs: temp['enabled'] = False
                if 'noshut' in kwargs: temp['enabled'] = True
                if 'local_address' in kwargs:
                    temp['local-address'] = kwargs['local_address'][peer_index]
                else:
                    temp['local-address'] = 'null'
                temp['vrf'] = vrf_str
                temp['enabled'] = temp.get('enabled', True)
                data = dict()

                data["remote-address"] = temp["remote-address"]
                data["vrf"] = temp["vrf"]
                data["interface"] = temp.get("interface", 'null')
                data["local-address"] = temp["local-address"]
                data['config'] = temp
                peer_list.append(data)
                if config == 'no':
                    hop_type = 'mhop' if peer_type == 'multi' else 'shop'
                    url = rest_urls['delete_bfd_peer'].format(hop_type, peer_type, data["remote-address"], data["interface"], data['vrf'], data["local-address"])
                    if not delete_rest(dut, http_method='delete', rest_url=url):
                        return False
            if not config:
                url = rest_urls['config_bfd_shop_peer_list'] if peer_type == 'single' else rest_urls['config_bfd_mhop_peer_list']
                data = {"openconfig-bfd-ext:{}-hop".format(peer_type): peer_list}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False


def verify_bfd_peers_brief(dut,**kwargs):
    """
    Author:gangadhara.sahu@broadcom.com
    :param peeraddress:
    :type bfd-peer-address
    :param ouraddress:
    :type bfd-local-address
    :param status:
    :type up-or-down
    :param scount:
    :type session-count
    :param sessionid:
    :type bfd-session-id
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    bfd.verify_bfd_peers_brief(dut1,peeraddress="50.1.1.2",ouraddress="50.1.1.1",status="Up")
    bfd.verify_bfd_peers_brief(dut1,peeraddress="50.1.1.2",ouraddress="50.1.1.1",status="Shutdown")
    bfd.verify_bfd_peers_brief(dut1,peeraddress="5000::2",ouraddress="5000::1",status="Up")
    bfd.verify_bfd_peers_brief(dut1,peeraddress="5000::2",ouraddress="5000::1",status="Down")
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type == 'click' else cli_type

    result = False
    st.log("Verify show bfd peers brief")
    output = get_bfd_peers_brief(dut, cli_type=cli_type)

    if len(output) == 0:
        st.error("Show OUTPUT is Empty")
        return result

    match_dict = {}
    if 'ouraddress' not in kwargs or 'peeraddress' not in kwargs:
        st.error("Mandatory parameters like ouraddress or/and peeraddress not passed")
        return result
    else:
        match_dict['peeraddress'] = kwargs['peeraddress']

    out_param = ['sessionid','status','scount','ouraddress']
    entries = filter_and_select(output,out_param, match_dict)

    if bool(entries):
        if 'status' in kwargs:
            if entries[0]['status'].lower() == kwargs['status'].lower() and entries[0]['ouraddress'] == kwargs['ouraddress']:
                result = True
                st.log("BFD session status is {} for peer {} Test Passed".format(entries[0]['status'],kwargs['peeraddress']))
            else:
                result = False
                st.error("BFD session status is not matching for src {} & peer {} Test Failed".format(kwargs['ouraddress'],kwargs['peeraddress']))
        if 'scount' in kwargs:
            if entries[0]['scount'] == kwargs['scount'] and entries[0]['ouraddress'] == kwargs['ouraddress']:
                result = True
                st.log("BFD session scount is {} for peer {} Test Passed".format(entries[0]['scount'],kwargs['peeraddress']))
            else:
                result = False
                st.error("BFD session scount is not matching for src {} & peer {} Test Failed".format(kwargs['ouraddress'],kwargs['peeraddress']))
        if 'status' not in kwargs and 'scount' not in kwargs:
            st.error("No arguments passed to be verified..")
    else:
        st.error("BFD session does not exist for peer address {} Test Failed".format(kwargs['peeraddress']))

    return result


def verify_bfd_peer(dut,**kwargs):
    """
    author:sooriya.gajendrababu@broadcom.com
    :param  :peer
    :type   :peer_ip address (list or string)
    :param  :local_addr
    :type   :local_address (list or string)
    :param  :interface
    :type   :bfd interface (list or string)
    :param  :local_id
    :type   :bfd local session-id (list or string)
    :param  :remote_id
    :type   :bfd remote session-d (list or string)
    :param  :status
    :type   :bfd session status (list or string)
    :param  :uptimeday
    :type   :uptime value in days (list or string)
    :param  :uptimehr
    :type   :uptime value in hours (list or string)
    :param  :uptimemin
    :type   :uptime value in minutes (list or string)
    :param  :uptimesec
    :type   :uptime value  in seconds (list or string)
    :param  :diagnostics
    :type   :diagnostics state (list or string)
    :param  :remote_diagnostics
    :type   :remote_diagnostics_state (list or string)
    :param  :rx_interval
    :type   :list of local_rx and remote_rx interval (list (or) list of lists)
    :param  :tx_interval
    :type   :list of local_rx and remote_tx interval (list (or) list of lists)
    :param  :echo_tx_interval
    :type   :list of local_echo_tx and remote_echo_tx interval (list (or) list of lists)
    :return :true/false
    :rtype  : boolean

    :Usage:
    bfd.verify_bfd_peer(dut1,peer='10.10.10.2',interface='Ethernet0',rx_interval=[['300','300']])
    bfd.verify_bfd_peer(dut1,peer=['10.10.10.2','20.20.20.2'],interface=['Ethernet0','Ethernet4'],status=['up','up'],diagnostics=['ok','nok'],rx_interval=[['300','300'],['300','300']])

    """
    if 'peer' not in kwargs:
        st.log("Mandatory parameter -peer not found")
        return False

    if 'vrf_name' in kwargs:
        vrf = kwargs['vrf_name']
        if vrf == 'default-vrf':
            vrf = 'default'
        del kwargs['vrf_name']
    else:
        vrf = 'default'

    cli_type = st.get_ui_type(dut, **kwargs)

    if 'multihop' in kwargs:
        is_mhop = True
        del kwargs['multihop']
        if 'local_addr' not in kwargs:
            st.error("-local_addr argument missing")
            return False
    else:
        is_mhop = False

    ping_verify = True if 'ping_verify' in kwargs else False
    kwargs.pop('ping_verify', '')

    rv = False
    #Converting all kwargs to list type to handle single or multiple peers
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #handling for multiple peers or single peer
    if len(kwargs['peer']) == 1:
        if is_mhop is False:
            if vrf == 'default':
                if 'local_addr' in kwargs and 'interface' in kwargs :
                    for peer_ip,local_addr,intf in zip(kwargs['peer'],kwargs['local_addr'],kwargs['interface']):
                        cmd = "show bfd peer " + peer_ip + " local-address "+ local_addr + " interface " + intf
                elif 'interface' in kwargs and 'local_addr' not in kwargs:
                    for peer_ip,intf in zip(kwargs['peer'],kwargs['interface']):
                        cmd = "show bfd peer " + peer_ip + " interface " + intf
                else:
                    for peer_ip,local_addr in zip(kwargs['peer'],kwargs['local_addr']):
                        cmd = "show bfd peer " + peer_ip + " local-address "+ local_addr
            else:
                if 'local_addr' in kwargs and 'interface' in kwargs :
                    if cli_type == 'click':
                        for peer_ip,local_addr,intf in zip(kwargs['peer'],kwargs['local_addr'],kwargs['interface']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " local-address "+ local_addr + " interface " + intf
                    else:
                        for peer_ip,local_addr,intf in zip(kwargs['peer'],kwargs['local_addr'],kwargs['interface']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " local-address "+ local_addr + " interface " + intf
                elif 'interface' in kwargs and 'local_addr' not in kwargs:
                    if cli_type == 'click':
                        for peer_ip,intf in zip(kwargs['peer'],kwargs['interface']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " interface " + intf
                    else:
                        for peer_ip, intf in zip(kwargs['peer'], kwargs['interface']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " interface " + intf
                else:
                    if cli_type == 'click':
                        for peer_ip,local_addr in zip(kwargs['peer'],kwargs['local_addr']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " local-address "+ local_addr
                    else:
                        for peer_ip, local_addr in zip(kwargs['peer'], kwargs['local_addr']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " local-address " + local_addr
        else:
            if vrf == 'default':
                for peer_ip, localaddress in zip(kwargs['peer'], kwargs['local_addr']):
                    cmd = "show bfd peer " + peer_ip + " multihop local-address " + localaddress
            else:
                if 'interface' not in kwargs and 'local_addr' in kwargs:
                    if cli_type == 'click':
                        for peer_ip, localaddress in zip(kwargs['peer'], kwargs['local_addr']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " multihop local-address " + localaddress
                    else:
                        for peer_ip, localaddress in zip(kwargs['peer'], kwargs['local_addr']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " multihop local-address " + localaddress
                elif 'interface' in kwargs and 'local_addr' in kwargs:
                    if cli_type == 'click':
                        for peer_ip, localaddress, intf in zip(kwargs['peer'], kwargs['local_addr'], kwargs['interface']):
                            cmd = "show bfd" + " vrf " + vrf + " peer " + peer_ip + " multihop local-address " + localaddress + " interface " + intf
                    else:
                        for peer_ip, localaddress, intf in zip(kwargs['peer'], kwargs['local_addr'], kwargs['interface']):
                            cmd = "show bfd" + " peer " + peer_ip + " vrf " + vrf + " multihop local-address " + localaddress + " interface " + intf
    else:
        if vrf == 'default':
            cmd = "show bfd peers"
        else:
            if cli_type == 'click':
                cmd = "show bfd" + " vrf " + vrf + " peers"
            else:
                cmd = "show bfd" + " peers" + " vrf " + vrf
    #Execute appropriate BFD CLI
    parsed_output = []
    if cli_type in ['click', 'klish']:
        cli_type = "vtysh" if cli_type == "click" else cli_type
        try:
            parsed_output = st.show(dut, cmd, type=cli_type)
        except Exception as e:
            st.error("The BFD session is not exist either deleted or not configured: exception is {} ".format(e))
            if ping_verify: debug_bfd_ping(dut, kwargs['peer'], vrf_name=vrf, cli_type=cli_type)
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        # st.show(dut, cmd, type='klish')
        bfd_type = 'multi' if is_mhop else 'single'
        if len(kwargs['peer']) > 1:
            parsed_output = rest_get_bfd_peer_info(dut, 'peers', bfd_type=bfd_type)
        else:
            st.log('Verifying single peer info')
            peer_ip = kwargs['peer'][0] if 'peer' in kwargs else ''
            local_addr = kwargs['local_addr'][0] if 'local_addr' in kwargs else ''
            st.log('peer_ip: {}, local_addr: {}'.format(peer_ip, local_addr))
            interface = kwargs['interface'][0] if 'interface' in kwargs else ''
            parsed_output = rest_get_bfd_peer_info(dut, 'peers', bfd_type=bfd_type, peer_list=False, vrf=vrf,
                                                   peer=peer_ip, local_addr=local_addr, interface=interface)
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

    if is_mhop: kwargs.pop('local_addr', '')

    if cli_type in ['klish', 'rest-patch', 'rest-put']:
        if 'status' in kwargs:
            kwargs['status'] = ['admin_down' if status == 'shutdown' else status for status in kwargs['status']]

    if 'return_dict' in kwargs:
        return parsed_output

    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        if ping_verify: debug_bfd_ping(dut, kwargs['peer'], vrf_name=vrf, cli_type=cli_type)
        return False
    #Get the index of peer from list of parsed output
    for i in range(len(kwargs['peer'])):
        peer_index = None
        st.log("Validation for BFD Peer : %s"%kwargs['peer'][i])
        for peer_info in parsed_output:
            if (peer_info['peer'] == kwargs['peer'][i]) and (peer_info['vrf_name'] == vrf and peer_info['status'] != ''):
                peer_index = parsed_output.index(peer_info)
        if peer_index is not None:
            #Iterate through the user parameters
            for k in kwargs.keys():
                if parsed_output[peer_index][k] == kwargs[k][i]:
                    st.log('Match Found for %s :: Expected: %s  Actual : %s'%(k,kwargs[k][i],parsed_output[peer_index][k]))
                    rv=True
                else:
                    st.error('Match Not Found for %s :: Expected: %s  Actual : %s'%(k,kwargs[k][i],parsed_output[peer_index][k]))
                    if ping_verify: debug_bfd_ping(dut, kwargs['peer'][i], vrf_name=vrf, enable_debug=False, cli_type=cli_type)
                    return False
        else:
            st.error(" BFD Peer %s not in output"%kwargs['peer'][i])
            if ping_verify: debug_bfd_ping(dut, kwargs['peer'], vrf_name=vrf, cli_type=cli_type)
            return False
    return rv


def get_bfd_peer_counters(dut,**kwargs):
    """
    author:sooriya.gajendrababu@broadcom.com
    :param  :peer
    :type   :peer_ip address (list or string)
    :param  :local_addr
    :type   :local_address (list or string)
    :param  :interface
    :type   :bfd interface (list or string)
    """

    cli_type = st.get_ui_type(dut, **kwargs)

    if 'vrf_name' in kwargs:
        vrf = kwargs['vrf_name']
        if vrf == 'default-vrf':
            vrf = 'default'
        del kwargs['vrf_name']
    else:
        vrf = 'default'

    if 'peer' not in kwargs:
        kwargs['peer'] = 'all'

    if 'multihop' in kwargs:
        is_mhop = True
        if 'local_addr' not in kwargs:
            st.error("-local_addr argument missing")
            return False
    else:
        is_mhop = False

    if kwargs['peer'] == 'all' and vrf == 'default':
        cmd = "show bfd peers counters"
    elif kwargs['peer'] == 'all' and vrf != 'default':
        if cli_type == 'click':
            cmd = "show bfd vrf {} peers counters".format(vrf)
        else:
            cmd = "show bfd peers vrf {} counters".format(vrf)
    else:
        if is_mhop is False:
            if vrf == 'default':
                if 'local_addr' in kwargs and 'interface' in kwargs :
                    if cli_type == 'click':
                        cmd = "show bfd peer " + kwargs['peer'] + " local-address "+ kwargs['local_addr'] + " interface " + kwargs['interface'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " local-address " + kwargs['local_addr'] + " interface " + kwargs['interface']
                elif 'interface' in kwargs and 'local_addr' not in kwargs:
                    if cli_type == 'click':
                        cmd = "show bfd peer " + kwargs['peer'] + " interface " + kwargs['interface'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " interface " + kwargs['interface']
                else:
                    if cli_type == 'click':
                        cmd = "show bfd peer " + kwargs['peer'] + " local-address "+ kwargs['local_addr'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " local-address " + kwargs['local_addr']
            else:
                if 'local_addr' in kwargs and 'interface' in kwargs :
                    if cli_type == 'click':
                        cmd = "show bfd vrf {} peer ".format(vrf) + kwargs['peer'] + " local-address "+ kwargs['local_addr'] + " interface " + kwargs['interface'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " vrf " + vrf + " local-address " + kwargs['local_addr'] + " interface " + kwargs['interface']
                elif 'interface' in kwargs and 'local_addr' not in kwargs:
                    if cli_type == 'click':
                        cmd = "show bfd vrf {} peer ".format(vrf) + kwargs['peer'] + " interface " + kwargs['interface'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " vrf " + vrf + " interface " + kwargs['interface']
                else:
                    if cli_type == 'click':
                        cmd = "show bfd vrf {} peer ".format(vrf) + kwargs['peer'] + " local-address "+ kwargs['local_addr'] + " counters"
                    else:
                        cmd = "show bfd peer counters " + kwargs['peer'] + " vrf " + vrf + " local-address " + kwargs['local_addr']

        else:
            if vrf == 'default':
                if cli_type == 'click':
                    cmd = "show bfd peer " + kwargs['peer'] + " multihop local-address " + kwargs['local_addr'] + " counters"
                else:
                    cmd = "show bfd peer counters " + kwargs['peer'] + " multihop local-address " + kwargs['local_addr']
            else:
                if cli_type == 'click':
                    cmd = "show bfd vrf {} peer ".format(vrf) + kwargs['peer'] + " multihop local-address " + kwargs['local_addr'] + " counters"
                else:
                    cmd = "show bfd peer counters " + kwargs['peer'] + " vrf " + vrf + " multihop local-address " + kwargs['local_addr']

    parsed_output =[]
    if cli_type in ['click', 'klish']:
        cli_type = "vtysh" if cli_type == "click" else cli_type
        try:
            parsed_output = st.show(dut, cmd, type=cli_type)
        except Exception as e:
            st.error("The BFD session is not existing either deleted or not configured: exception is {} ".format(e))
            return []
    elif cli_type in ['rest-patch', 'rest-put']:
        # st.show(dut, cmd, type='klish')
        bfd_type = 'multi' if is_mhop else 'single'
        parsed_output = rest_get_bfd_peer_info(dut, 'counters', bfd_type=bfd_type)
        if kwargs['peer'] == 'all':
            return parsed_output
        else:
            return filter_and_select(parsed_output, None, {'peeraddress': kwargs['peer'], 'vrfname': vrf})
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False
    return parsed_output


def verify_bgp_bfd_down(dut, neighbor, interface, check_reason='no', vrf_name='default-vrf', cli_type=''):
    """
    author:sooriya.gajendrababu@broadcom.com
    :param  :neighbor
    :type   :neighbor address (string)
    :param  :check_reason
    :type   : str
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'

    ret_val=True
    if vrf_name in ['default-vrf', 'default']:
        if cli_type == 'click':
            output=st.show(dut,'show bgp neighbors {}'.format(neighbor), type='vtysh')
        elif cli_type == 'klish':
            output = st.show(dut, 'show bgp ipv4 unicast neighbors {}'.format(neighbor), type=cli_type)
    else:
        if cli_type == 'click':
            output = st.show(dut, 'show bgp vrf {} neighbors {}'.format(vrf_name, neighbor), type='vtysh')
        elif cli_type == 'klish':
            output = st.show(dut, 'show bgp ipv4 unicast vrf {} neighbors {}'.format(vrf_name, neighbor), type=cli_type)
    bgp_state = output[0]['state']
    bgp_down_reason = output[0]['bgpdownreason']

    bfd_state = ''
    output = verify_bfd_peer(dut, peer=neighbor, interface=interface, status='down', vrf_name=vrf_name, return_dict=True)
    if not bool(output) or output[0]['status'] != 'up':
        bfd_state = 'Down'

    if check_reason == 'yes':
        if bgp_state != 'Established' and bfd_state == 'Down' and  bgp_down_reason == "BFD down received":
            st.log('BGP state and BFD state went down as expected for {}'.format(neighbor))
        else:
            st.error('BGP or BFD state did not go down for {}. Actual BGP state :{} ,BFD state: {}'.format(neighbor, bgp_state,bfd_state))
            ret_val = False
    else:
        if bgp_state != 'Established' and bfd_state == 'Down':
            st.log('BGP state and BFD state went down as expected for {}'.format(neighbor))
        else:
            st.error('BGP or BFD state did not go down for {}. Actual BGP state :{} ,BFD state: {}'.format(neighbor,bgp_state,bfd_state))
            ret_val=False
    return ret_val


def clear_bfd_peer_counters(dut,**kwargs):
    """
    author:vishnuvardhan.talluri@broadcom.com
    :param  :peer
    :type   :peer_ip address (list or string)
    :param  :local_addr
    :type   :local_address (list or string)
    :param  :interface
    :type   :bfd interface (list or string)
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type == 'click' else cli_type
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'

    if 'multihop' in kwargs:
        cmd_mhop = " multihop"
    else:
        cmd_mhop = ""

    if 'vrf_name' in kwargs:
        if kwargs['vrf_name'] in ['default-vrf', 'default']:
            cmd_vrf = ""
        else:
            cmd_vrf = ' vrf {}'.format(kwargs['vrf_name'])
    else:
        cmd_vrf = ""

    cmd = "clear bfd peer " + kwargs['peer']
    if cmd_vrf:
        cmd += cmd_vrf
    if cmd_mhop:
        cmd += cmd_mhop

    if 'local_addr' in kwargs and 'interface' in kwargs :
        cmd += " local-address "+ kwargs['local_addr'] + " interface " + kwargs['interface'] + " counters"
    elif 'interface' in kwargs and 'local_addr' not in kwargs:
        cmd += " interface " + kwargs['interface'] + " counters"
    else:
        cmd += " local-address "+ kwargs['local_addr'] + " counters"
    cmd = 'do ' + cmd
    st.config(dut, cmd, type=cli_type)


def get_bfd_peers_brief(dut, cli_type=''):
    """
    :param dut: DUT name where the CLI needs to be executed
    :type dut: string
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'vtysh' if cli_type == 'click' else cli_type
    if cli_type in ['vtysh', 'klish']:
        return st.show(dut, "show bfd peers brief", type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        # st.show(dut, "show bfd peers brief", type='klish')
        return rest_get_bfd_peer_info(dut, 'brief')
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def debug_bfd_ping(dut, addresses, vrf_name='default', enable_debug=True, cli_type=''):
    st.banner("********* Ping Dubug commands starts ************")
    for addr in addresses:
        family = 'ipv4' if is_valid_ipv4(addr) else 'ipv6'
        if vrf_name in ['default', 'default-vrf']:
            ip_api.ping(dut, addr, family, cli_type=cli_type)
        else:
            ip_api.ping(dut, addr, family, interface=vrf_name, cli_type=cli_type)
    if enable_debug: debug_bgp_bfd(dut)


def debug_bgp_bfd(dut):
    dut_list = make_list(dut)
    st.banner("********* Dubug commands starts ************")
    func_list = [clear_interface_counters, show_arp, show_ndp, show_interface_counters_all,
                 asicapi.dump_l3_ip6route, asicapi.dump_l3_defip]
    for func in func_list:
        api_list = [[func, dut] for dut in dut_list]
        exec_all(True, api_list)
    st.banner(" ******** End of Dubug commands ************")


def rest_get_bfd_peer_info(dut, type, bfd_type=None, peer_list=True, **kwargs):
    """
    Author: Lakshminarayana D(lakshminarayana.d@broadcom.com)
    :param dut:
    :type bfd_type: None, single, multi
    :param type: brief, counters, peers
    :param peer_list: True: get all peer info, False: get particular peer info
    :return:
    """

    rest_urls = st.get_datastore(dut, "rest_urls")
    bfd_peer_state=[]
    if peer_list:
        if not bfd_type:
            uri = rest_urls['config_bfd_peer_list']
            result = get_rest(dut, rest_url=uri)
            if not result: return []
            if result['output']['openconfig-bfd:bfd'].get('openconfig-bfd-ext:bfd-shop-sessions', ''):
                shop_state = result['output']['openconfig-bfd:bfd']['openconfig-bfd-ext:bfd-shop-sessions'].get('single-hop', '')
                if shop_state: bfd_peer_state.extend(shop_state)
            if result['output']['openconfig-bfd:bfd'].get('openconfig-bfd-ext:bfd-mhop-sessions', ''):
                mhop_state = result['output']['openconfig-bfd:bfd']['openconfig-bfd-ext:bfd-mhop-sessions'].get('multi-hop', '')
                if mhop_state: bfd_peer_state.extend(mhop_state)
        elif bfd_type == 'single':
            uri = rest_urls['config_bfd_shop_peer_list']
            result = get_rest(dut, rest_url=uri)
            if not result: return []
            if result['output'].get('openconfig-bfd-ext:single-hop', ''):
                shop_state = result['output'].get('openconfig-bfd-ext:single-hop', '')
                if shop_state: bfd_peer_state.extend(shop_state)
        elif bfd_type == 'multi':
            uri = rest_urls['config_bfd_mhop_peer_list']
            result = get_rest(dut, rest_url=uri)
            if not result: return []
            if result['output'].get('openconfig-bfd-ext:multi-hop', ''):
                mhop_state = result['output'].get('openconfig-bfd-ext:multi-hop', '')
                if mhop_state: bfd_peer_state.extend(mhop_state)
    else:
        if type == 'peers':
            peer_data = dict()
            hop_type = 'shop' if bfd_type == 'single' else 'mhop'
            if not kwargs.get('peer', '') or not kwargs.get('vrf', ''):
                st.error('Mandatory params not provided to perform a rest operation')
                return []

            intf = kwargs['interface'] if kwargs.get('interface', '') else 'null'
            local_addr = kwargs['local_addr'] if kwargs.get('local_addr', '') else 'null'
            peer_data['vrf'] = kwargs.get('vrf', 'default')
            peer_data['remote-address'] = kwargs.get('peer')
            peer_data['interface'] = kwargs.get('interface', '')
            peer_data['local-address'] = kwargs.get('local_addr', '')

            key_map = {'uptime': 'last-up-time', 'downtime': 'last-failure-time', 'local_id': 'local-discriminator',
                        'remote_id': 'remote-discriminator', 'status': 'session-state',
                        'diagnostics': 'local-diagnostic-code',
                        'remote_diagnostics': 'remote-diagnostic-code', 'peer_type': 'session-type',
                        'multiplier_local': 'detection-multiplier', 'multiplier_remote': 'remote-multiplier',
                        'tx_interval_local': 'desired-minimum-tx-interval',
                        'tx_interval_remote': 'remote-desired-transmission-interval',
                        'rx_interval_local': 'required-minimum-receive',
                        'rx_interval_remote': 'remote-minimum-receive-interval',
                        'echo_tx_interval_local': 'desired-minimum-echo-receive',
                        'echo_tx_interval_remote': 'remote-echo-receive-interval'}
            if bfd_type == 'multi':
                key_map.pop('echo_tx_interval_local', '')
                key_map.pop('echo_tx_interval_remote', '')

            peer_data['state'] = dict()
            for key, map in key_map.items():
                cmd = 'get_bfd_peer_state_{}'.format(key)
                uri = rest_urls[cmd].format(hop_type, bfd_type, peer_data['remote-address'], intf, peer_data['vrf'], local_addr)
                result = get_rest(dut, rest_url=uri)
                if result:
                    peer_data['state'][map] = result['output'].get('openconfig-bfd-ext:{}'.format(map), '')
                else:
                    st.error('Rest response failed for uri type: {}'.format(map))
                    peer_data['state'][map] = ''
            bfd_peer_state.append(peer_data)

    if not bfd_peer_state: return []

    bfd_rest_data = []
    for peer_info in bfd_peer_state:
        temp=dict()
        if not peer_info.get('state'): continue
        if type == 'brief':
            temp['scount'] = str(len(bfd_peer_state))
            temp['sessionid'] = peer_info['state'].get('local-discriminator', '')
            temp['ouraddress'] = peer_info.get('local-address') if peer_info.get('local-address') != 'null' else 'unknown'
            temp['peeraddress'] = peer_info.get('remote-address', '')
            temp['status'] = peer_info['state'].get('session-state', '').lower()
            temp['vrf'] = peer_info.get('vrf', '')
            bfd_rest_data.append(temp)
        elif type == 'counters':
            temp['peeraddress'] = peer_info.get('remote-address', '')
            temp['vrfname'] = peer_info.get('vrf', '')
            temp['localaddr'] = peer_info.get('local-address', '')
            temp['interface'] = peer_info.get('interface', '')
            temp['cntrlpktin'] = peer_info['state']['async'].get('received-packets', '')
            temp['cntrlpktout'] = peer_info['state']['async'].get('transmitted-packets', '')
            temp['sessionupev'] = peer_info['state']['async'].get('up-transitions', '')
            temp['echopktin'] = peer_info['state']['echo'].get('received-packets', '0') if 'echo' in peer_info['state'] else ''
            temp['echopktout'] = peer_info['state']['echo'].get('transmitted-packets', '0') if 'echo' in peer_info['state'] else ''
            temp['zebranotifys'] = '0'
            temp['sessiondownev'] = peer_info['state'].get('failure-transitions', '')
            bfd_rest_data.append(temp)
        elif type == 'peers':
            temp['peer'] = peer_info.get('remote-address', '')
            temp['vrf_name'] = peer_info.get('vrf', '')
            temp['local_addr'] = peer_info.get('local-address') if peer_info.get('local-address') != 'null' else ''
            temp['interface'] = peer_info.get('interface', '')
            temp['label'] = ''
            uptime = peer_info['state'].get('last-up-time', '')
            uptime = calc_date_time(uptime)
            temp['uptimeday'] = uptime[0]
            temp['uptimehr'] = uptime[1]
            temp['uptimemin'] = uptime[2]
            temp['uptimesec'] = uptime[3]
            downtime = peer_info['state'].get('last-failure-time', '')
            downtime = calc_date_time(downtime)
            temp['downtimeday'] = downtime[0]
            temp['downtimehr'] = downtime[1]
            temp['downtimemin'] = downtime[2]
            temp['downtimesec'] = downtime[3]
            temp['local_id'] = peer_info['state'].get('local-discriminator', '')
            temp['remote_id'] = peer_info['state'].get('remote-discriminator', '')
            temp['status'] = peer_info['state'].get('session-state', '').lower()
            temp['diagnostics'] = peer_info['state'].get('local-diagnostic-code', '')
            temp['remote_diagnostics'] = peer_info['state'].get('remote-diagnostic-code', '')
            temp['peer_type'] = peer_info['state'].get('session-type', '').lower()
            temp['multiplier'] = [str(peer_info['state'].get('detection-multiplier', '')), str(peer_info['state'].get('remote-multiplier', ''))]
            temp['tx_interval'] = [str(peer_info['state'].get('desired-minimum-tx-interval', '')), str(peer_info['state'].get('remote-desired-transmission-interval', ''))]
            temp['rx_interval'] = [str(peer_info['state'].get('required-minimum-receive', '')), str(peer_info['state'].get('remote-minimum-receive-interval', ''))]
            temp['echo_tx_interval'] = [str(peer_info['state'].get('desired-minimum-echo-receive', '')), str(peer_info['state'].get('remote-echo-receive-interval', ''))]
            temp['err'] = ''
            bfd_rest_data.append(temp)
    st.banner("Rest Output")
    st.log('REST OUTPUT: {}'.format(bfd_rest_data))
    return bfd_rest_data


def calc_date_time(val):
    if not val:
        return [''] * 4
    data = str(datetime.timedelta(seconds=int(val)))
    days = '0'
    if 'days' in data:
        days, _, data = data.split(' ')
    hour, minute, second = data.split(':')
    return (days, str(int(hour)), str(int(minute)), str(int(second)))

