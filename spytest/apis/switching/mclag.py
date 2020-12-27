##########################################
#MCLAG apis
##########################################
from spytest import st
import spytest.utils as utils
from apis.common import redis
from utilities.utils import get_interface_number_from_name
from apis.system.rest import get_rest, config_rest, delete_rest

def config_domain(dut,domain_id,**kwargs):
    '''
    Author: sneha.mathew@broadcom.com
    :param dut:
    :param domain_id: Mclag domain_id
    :param local_ip: Mclag peer1 IP
    :param peer_ip: Mclag peer2 IP
    :param kwargs: optional parameters can be <local_ip|peer_ip|peer_interface|config|cli_type>
    :return:

    usage:
    config_domain(dut1,10, local_ip="10.10.10.1", peer_ip="10.10.10.2", delay_restore_timer="60")
    config_domain(dut1,10, local_ip="10.10.10.1", peer_ip="10.10.10.2", peer_interface='Ethernet0001')
    config_domain(dut1,10, config='del')
    '''
    ### Optional parameters processing
    local_ip = kwargs.get('local_ip', None)
    peer_ip = kwargs.get('peer_ip', None)
    peer_intf = kwargs.get('peer_interface', None)
    delay_restore_timer = kwargs.get('delay_restore_timer', None)
    config = kwargs.get('config', 'add')
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))

    if cli_type == 'click':
        cmd = "config mclag {} {}".format(config, domain_id)
        if config == 'add':
            if 'local_ip' not in kwargs or 'peer_ip' not in kwargs:
                st.error("Mandatory parameters local_ip and peer_ip not found")
                return False
            cmd += " {} {}".format(local_ip, peer_ip)
            if 'peer_interface' in kwargs:
                cmd += ' {}'.format(peer_intf)
        #cmd += ' \n'
        output = st.config(dut, cmd)
        if "Missing argument" in output:
            st.error("Argument Missing")
            return False
        if "invalid peer ip address" in output:
            st.error("Invalid peer_ip address")
            return False
        if "invalid local ip address" in output:
            st.error("Invalid local_ip address")
            return False
        if "interface name is invalid" in output:
            st.error("Invalid peer interface")
            return False
    elif cli_type == 'klish':
        config = 'no ' if config == 'del' else ''
        if config == '':
            cmd = "mclag domain {}".format(domain_id)
            if 'local_ip' in kwargs:
                cmd = cmd + "\n" + "source-ip {}".format(local_ip)
            if 'peer_ip' in kwargs:
                cmd = cmd + "\n" + "peer-ip {}".format(peer_ip)
            if 'peer_interface' in kwargs:
                pintf = get_interface_number_from_name(peer_intf)
                cmd = cmd + "\n" + "peer-link {} {}".format(pintf['type'], pintf['number'])
            if 'delay_restore_timer' in kwargs:
                cmd = cmd + "\n" + "delay-restore {}".format(delay_restore_timer)
            cmd = cmd + "\n" + "exit"
        elif config == 'no ':
            if 'local_ip' in kwargs or 'peer_ip' in kwargs or 'peer_interface' in kwargs or 'delay_restore_timer' in kwargs:
                cmd = "mclag domain {}".format(domain_id)
                if 'local_ip' in kwargs:
                    cmd = cmd + "\n" + "{}source-ip".format(config)
                if 'peer_ip' in kwargs:
                    cmd = cmd + "\n" + "{}peer-ip".format(config)
                if 'peer_interface' in kwargs:
                    cmd = cmd + "\n" + "{}peer-link".format(config)
                if 'delay_restore_timer' in kwargs:
                    cmd = cmd + "\n" + "{}delay-restore".format(config)
                cmd = cmd + "\n" + "exit"
            else:
                cmd = "{}mclag domain {}".format(config, domain_id)
        output = st.config(dut, cmd, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    elif cli_type in ["rest-put", "rest-patch"]:
        if config == 'del':
            rest_urls = st.get_datastore(dut,'rest_urls')
            rest_url_del = rest_urls['mclag_config_domain'].format(int(domain_id))
            output = st.rest_delete(dut, rest_url_del)
            if not output["status"] in [200, 204]:
                st.error("Failed to delete the mclag domain using REST in {} due to bad request {}".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest delete mclag domain return status {}".format(output['status']))
                return True
        if 'local_ip' in kwargs:
            rest_urls = st.get_datastore(dut,'rest_urls')
            rest_url = rest_urls['mclag_config_all']
            rest_data={"openconfig-mclag:mclag-domains":{"mclag-domain":[{"domain-id":int(domain_id),"config":{"domain-id":int(domain_id),"source-address":local_ip}}]}}
            output=st.rest_create(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure using POST source-address in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation using POST for source-address return status {}".format(output['status']))
        if 'peer_ip' in kwargs:
            rest_urls = st.get_datastore(dut,'rest_urls')
            rest_url = rest_urls['mclag_config_peer_ip'].format(int(domain_id))
            rest_data={"openconfig-mclag:peer-address":peer_ip}
            output=st.rest_modify(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure peer-address in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for peer-address return status {}".format(output['status']))
        if 'peer_interface' in kwargs:
            rest_urls = st.get_datastore(dut,'rest_urls')
            rest_url = rest_urls['mclag_config_peer_link'].format(int(domain_id))
            rest_data={"openconfig-mclag:peer-link":peer_intf}
            output=st.rest_modify(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure peer-link in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for peer-link return status {}".format(output['status']))
        if 'delay_restore_timer' in kwargs:
            rest_urls = st.get_datastore(dut,'rest_urls')
            rest_url = rest_urls['mclag_config_delay_restore'].format(int(domain_id))
            rest_data={"openconfig-mclag:delay-restore":int(delay_restore_timer)}
            output=st.rest_modify(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure delay_restore_timer in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for delay_restore_timer return status {}".format(output['status']))
        if 'keepalive_interval' in kwargs:
            rest_urls = st.get_datastore(dut,'rest_urls')
            rest_url = rest_urls['mclag_config_keepalive'].format(int(domain_id))
            rest_data={"openconfig-mclag:keepalive-interval":int(kwargs['keepalive_interval'])}
            output=st.rest_modify(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure keepalive-interval in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for keepalive-interval return status {}".format(output['status']))
        if 'session_timeout' in kwargs:
            rest_url = rest_urls['mclag_config_session_timeout'].format(int(domain_id))
            rest_data={"openconfig-mclag:session-timeout":int(kwargs['session_timeout'])}
            output=st.rest_modify(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure session-timeout in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for session-timeout return status {}".format(output['status']))
        if 'mclag_system_mac' in kwargs:
            rest_url = rest_urls['mclag_config_mclag_system_mac'].format(int(domain_id))
            rest_data={"openconfig-mclag:mclag-system-mac":kwargs['mclag_system_mac']}
            output=st.rest_modify(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure mclag-system-mac in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for mclag-system-mac return status {}".format(output['status']))
        for arg1 in kwargs:
            if arg1 not in ['mclag_system_mac','session_timeout','keepalive_interval','delay_restore_timer','peer_interface','peer_ip','local_ip']:
                st.error("ARG {} is not supported through REST".format(arg1))
    return True


def config_interfaces(dut,domain_id,interface_list,**kwargs):
    '''
    Author: sneha.mathew@broadcom.com
    :param dut:
    :param domain_id: Mclag domain_id
    :param interface_list: list of mclag interfaces (portchannels) in the dut for the given domain
    :param kwargs: optional parameters can be <config|cli_type>
    :return:

    usage:
    config_mclag_interface(dut1,10,['PortChannel001','PortChannel002'])
    config_mclag_interface(dut1,10,['PortChannel001','PortChannel002'],config='del')
    '''
    ### Optional parameters processing
    config = kwargs.get('config', 'add')
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if not interface_list:
        st.error("interfaces not found for  Mclag interface configuration")
        return False
    interface_list = interface_list if isinstance(interface_list,list) else [interface_list]

    if cli_type == 'click':
        cmd = "config mclag member {} {} ".format(config,domain_id)
        for intf in interface_list:
            cmd += '{},'.format(intf)
        cmd = cmd.strip(',')
        output = st.config(dut, cmd)
        if "Domain doesn't exist" in output:
            st.error(" Mclag domain:{} doesn't exist".format(domain_id))
            return False
        if "name should have prefix 'PortChannel' " in output:
            st.error(" Mclag interface has to be PortChannel")
            return False
    elif cli_type == 'klish':
        cmd = ''
        config = 'no ' if config == 'del' else ''
        for intf in interface_list:
            pintf = get_interface_number_from_name(intf)
            cmd = cmd + "\n" + "interface {} {}".format(pintf['type'], pintf['number'])
            cmd = cmd + "\n" + "{}mclag {}".format(config, domain_id)
            cmd = cmd + "\n" + "exit"
        output = st.config(dut, cmd, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    return True

def config_timers(dut, domain_id,**kwargs):
    '''
    Author: sneha.mathew@broadcom.com

    Configures< Keep-alive | session timeout> values for Mclag domain
    To revert configure the default values <1 sec | 15 sec>

    :param dut:
    :param domain_id:  Mclag domain_id
    :param kwargs: optional parameters can be <keep_alive|session_timeout|cli_type>
    :return:

    Usage:
    config_mclag_timers(dut1,10, keep_alive=5)
    config_mclag_timers(dut1,10, session_timeout=10)
    config_mclag_timers(dut1,10, keep_alive=10, session_timeout=30)
    '''
    ### Optional parameters processing
    keep_alive_val = kwargs.get('keep_alive', None)
    session_timeout_val = kwargs.get('session_timeout', None)
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))

    if cli_type == 'click':
        cmd = []
        if 'keep_alive' in kwargs:
            cmd.append("config mclag keepalive-interval {} {}".format(domain_id, keep_alive_val))
        if 'session_timeout' in kwargs:
            cmd.append("config mclag session-timeout {} {}".format(domain_id, session_timeout_val))
        output = st.config(dut, cmd)
        if "configure mclag domain first" in output:
            st.error("Domain_id doesn't exist")
            return False
    elif cli_type == 'klish':
        cmd = "mclag domain {}".format(domain_id)
        if 'keep_alive' in kwargs:
            cmd = cmd + "\n" + "keepalive-interval {}".format(keep_alive_val)
        if 'session_timeout' in kwargs:
            cmd = cmd + "\n" + "session-timeout {}".format(session_timeout_val)
        cmd = cmd + "\n" + "exit"
        output = st.config(dut, cmd, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    return True

def config_uniqueip(dut, skip_error=False, **kwargs):
    '''
    Configures< unique-ip add | del> vlan for Mclag
    Author: sunil.rajendra@broadcom.com
    :param dut:
    :param kwargs: optional parameters can be <op_type|vlan|cli_type>
    :return:

    Usage:
    config_uniqueip(dut1, op_type='add', vlan='Vlan10')
    config_uniqueip(dut1, op_type='del', vlan='Vlan10')
    '''
    ### Optional parameters processing
    type_val = kwargs.get('op_type', None)
    vlan_val = kwargs.get('vlan', None)
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))

    if cli_type == 'click':
        cmd = ""
        if 'op_type' in kwargs and 'vlan' in kwargs:
            cmd += "config mclag unique-ip {} {}\n".format(type_val, vlan_val)
        output = st.config(dut, cmd)
        if "configure mclag domain first" in output:
            st.error("Domain_id doesn't exist")
            return False
    elif cli_type == 'klish':
        if 'op_type' in kwargs and 'vlan' in kwargs:
            vval = get_interface_number_from_name(vlan_val)
            cmd = "interface {} {}".format(vval['type'], vval['number'])
            type_val = 'no ' if type_val == 'del' else ''
            cmd = cmd + "\n" + "{}mclag-separate-ip".format(type_val)
            cmd = cmd + "\n" + "exit"
        output = st.config(dut, cmd, type="klish", conf=True,skip_error_check=skip_error)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    return True

def config_mclag_router_mac(dut, **kwargs):
    '''
    Configures <gw_mac for mclag
    :param dut:
    :param kwargs: op_type/gw_mac>
    :return:

    Usage:
    config_mclag_router_mac(dut1, op_type='add', gw_mac='00:11:22:33:44:55')
    config_mclag_router_mac(dut1, op_type='del', gw_mac='00:11:22:33:44:55')
    '''
    ### Optional parameters processing
    type_val = kwargs.get('op_type', None)
    gw_mac_val = kwargs.get('gw_mac', None)
    ##TODO enable below after adding Klish support as of now overriding with click
    #cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = 'click'

    if cli_type == 'click':
        cmd = ""
        if 'op_type' in kwargs and 'gw_mac' in kwargs:
            cmd += "config mclag gw-mac {} {}\n".format(type_val, gw_mac_val)
        else:
            st.error("Mandatory argument gw_mac Not Found")
            return False
        st.config(dut, cmd)
    return True

def config_gw_mac(dut,skip_error=False, **kwargs):
    '''
    Configures< gw mac add | del> for Mclag
    Author: nagappa.chincholi@broadcom.com
    :param dut:
    :param kwargs: optional parameters can be <config|mac|cli_type>
    :return:

    Usage:
    config_gw_mac(dut1, config='add', mac='xx:xx:xx:xx:xx:xx')
    config_gw_mac(dut1, config='del', mac='xx:xx:xx:xx:xx:xx')
    '''
    config = kwargs.get('config', 'add')
    if 'mac' not in kwargs:
        st.error("Mandatory parameter mac address not found")
        return False
    mac_val = kwargs.get('mac')
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))

    if cli_type == 'click':
        cmd = "config mclag gw-mac {} {}\n".format(config, mac_val)
        st.config(dut, cmd)
    elif cli_type == 'klish':
        config = 'no ' if config == 'del' else ''
        cmd = "{}mclag gateway-mac {}".format(config, mac_val)
        output = st.config(dut, cmd, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    return True

def config_mclag_system_mac(dut,skip_error=False, **kwargs):
    '''
    Configures< mclag system-mac <add|del> <domain-id> mac > for Mclag
    Author: nagappa.chincholi@broadcom.com
    :param dut:
    :param kwargs: optional parameters can be <config|domain_id|mac|cli_type>
    :return:

    Usage:
    config_mclag_system_mac(dut1, domain_id= 1, config='add', mac='xx:xx:xx:xx:xx:xx')
    config_mclag_system_mac(dut1, domain_id= 1, config='del')
    '''
    ### Optional parameters processing
    config = kwargs.get('config', 'add')
    if config == 'add' and 'mac' not in kwargs:
        st.error("Mandatory parameter mac address not found for config = add")
        return False
    if 'domain_id' not in kwargs:
        st.error("Mandatory parameter domain_id  not found")
        return False
    mac_val = kwargs.get('mac')
    domain_id = kwargs.get('domain_id')
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    mac_val = '' if config == 'del' else mac_val
    if cli_type == 'click':
        cmd = "config mclag system-mac {} {} {}\n".format(config,domain_id, mac_val)
        output = st.config(dut, cmd)
        if "configure mclag domain first" in output:
            st.error("Domain_id doesn't exist")
            return False
    elif cli_type == 'klish':
        config = 'no' if config == 'del' else ''
        cmd = "mclag domain {} \n{} mclag-system-mac {}".format(domain_id,config, mac_val)
        cmd = cmd + "\n" + "exit"
        output = st.config(dut, cmd, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['mclag_config_mclag_system_mac'].format(int(domain_id))
        if config == "add":
            payload = {"openconfig-mclag:mclag-system-mac": mac_val}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                return False
        else:
            if not delete_rest(dut, rest_url=url):
                return False
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False
    return True

def verify_domain(dut,**kwargs):
    '''
    Author: sneha.mathew@broadcom.com
    Verify mclag domain output
    :param dut:
    :param kwargs: Parameters can be <domain_id|session_status|local_ip|peer_ip|peer_link_inf|node_role|mclag_intfs|cli_type>
    :return:
    Usage:
    verify_mclag_domain(dut1,domain_id=10, session_status='OK', local_ip="10.10.10.1", peer_ip="10.10.10.2", \
                            peer_link_inf='Ethernet0001',node_role='Standby', mclag_intfs=2)
    '''
    ret_val = True
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))

    if cli_type == 'click':
        cmd = 'mclagdctl dump state '
        if 'domain_id' in kwargs:
            domain_id = kwargs['domain_id']
            del kwargs['domain_id']
            cmd += '-i {}'.format(domain_id)
        else:
            st.error("Mandatory argument domain id Not Found")
            return False

        output = st.show(dut, cmd)
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        if "return_output" in kwargs:
            return output

        if 'mclag_intfs' in kwargs:
            mclag_count = kwargs['mclag_intfs']
            del kwargs['mclag_intfs']
            mclag_intf_list = str(output[0]['mclag_intfs']).split(',')
            if mclag_count == len(mclag_intf_list):
                st.log("Match FOUND for Mclag Interface Count:  Expected -<{}> Actual-<{}> ".format(mclag_count, len(mclag_intf_list)))
            else:
                st.error("Match NOT FOUND for Mclag Interface Count:  Expected -<{}> Actual-<{}> ".format(mclag_count, len(mclag_intf_list)))
                ret_val = False
    elif cli_type == 'klish':
        cmd = 'show mclag brief'
        output = st.show(dut, cmd, type='klish')
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        if "return_output" in kwargs:
            return output

        if 'mclag_intfs' in kwargs:
            mclag_count = kwargs['mclag_intfs']
            del kwargs['mclag_intfs']
            mclag_intf_list = output[0]['num_mclag_intfs']
            if str(mclag_count) == mclag_intf_list:
                st.log("Match FOUND for Mclag Interface Count:  Expected -<{}> Actual-<{}> ".format(mclag_count, mclag_intf_list))
            else:
                st.error("Match NOT FOUND for Mclag Interface Count:  Expected -<{}> Actual-<{}> ".format(mclag_count, mclag_intf_list))
                ret_val = False

        # Replacing 'OK' with 'up' & 'ERROR' with 'down
        if 'session_status' in kwargs:
            if kwargs['session_status'] == 'OK':
                kwargs['session_status'] = 'up'
            if kwargs['session_status'] == 'ERROR':
                kwargs['session_status'] = 'down'
        if 'node_role' in kwargs:
            kwargs['node_role'] = kwargs['node_role'].lower()

    elif cli_type in ['rest-put','rest-patch']:
        if 'domain_id' in kwargs:
            domain_id = kwargs['domain_id']
            del kwargs['domain_id']
        else:
            st.error("Mandatory argument domain id Not Found")
            return False
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['show_mclag_brief_config'].format(domain_id)
        response = get_rest(dut, rest_url=url)
        output = parse_show_mclag_brief_config(response)
        if output == []:
            st.error("MCLAG is not enabled in the DUT")
            return False
        url = rest_urls['show_mclag_brief_state'].format(domain_id)
        response = get_rest(dut, rest_url=url)
        state = parse_show_mclag_brief_state(response)
        output[0].update(state[0])
        if "return_output" in kwargs:
            return output
        if 'mclag_intfs' in kwargs:
            ### Mclag interfaces count is not part of this URI. Skip verification.
            del kwargs['mclag_intfs']
        if 'session_status' in kwargs:
            if kwargs['session_status'] == 'OK':
                kwargs['session_status'] = 'up'
            if kwargs['session_status'] == 'ERROR':
                kwargs['session_status'] = 'down'
        if 'node_role' in kwargs:
            kwargs['node_role'] = kwargs['node_role'].lower()

    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
            ret_val = False
        else:
            st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))

    return ret_val


def verify_interfaces(dut,**kwargs):
    '''
    Author: sneha.mathew@broadcom.com
    Verify mclag interfaces output
    :param dut:
    :param kwargs: Parameters can be <domain_id|mclag_intf|mclag_intf_local_state|mclag_intf_peer_state|
                        'mclag_intf_l3_status'|'isolate_peer_link'|'traffic_disable'|cli_type>
    :return:
    Usage:
    verify_mclag_interfaces(dut1,domain_id=10, mclag_intf='PortChannel20', mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            isolate_peer_link='Yes', traffic_disable='No')
    verify_mclag_interfaces(dut1,domain_id=10, mclag_intf='PortChannel20', mclag_intf_local_state="Up", mclag_intf_peer_state="Up", \
                            mclag_intf_l3_status='No',isolate_peer_link='Yes', traffic_disable='No')
    '''
    ret_val = True
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if 'cli_type' in kwargs:
        del kwargs['cli_type']

    if 'domain_id' not in kwargs or 'mclag_intf' not in kwargs:
        st.error("Mandatory arguments Not Found Expect domain_id & mclag_intf")
        return False
    else:
        domain_id = kwargs['domain_id']
        del kwargs['domain_id']
        mclag_intf = kwargs['mclag_intf']
        del kwargs['mclag_intf']

    if cli_type == 'click':
        st.banner("Getting Mclag Interface Local state for: {}".format(mclag_intf),delimiter='-')
        cmd1 = 'mclagdctl dump portlist local'
        cmd1 += ' -i {}'.format(domain_id)
        output1 = st.show(dut, cmd1)
        if len(output1) == 0:
            st.error("Output is Empty")
            return False
        ### Process Local Mclag Interface output
        entries = utils.filter_and_select(output1,None,match={'mclag_intf':mclag_intf})
        args1 = ['mclag_intf_local_state', 'mclag_intf_l3_status', 'isolate_peer_link', 'traffic_disable', 'mclag_mac']
        for key in args1:
            if key in kwargs.keys():
                if str(kwargs[key]) != str(entries[0][key]):
                    st.error("{}:==> Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(mclag_intf, key, kwargs[key], entries[0][key]))
                    ret_val = False
                else:
                    st.log("{}:==> Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(mclag_intf, key, kwargs[key], entries[0][key]))


        st.banner("Getting Mclag Interface Peer state for: {}".format(mclag_intf),delimiter='-')
        cmd2 = 'mclagdctl dump portlist peer'
        cmd2 += ' -i {}'.format(domain_id)
        output2 = st.show(dut, cmd2)
        if len(output2) == 0:
            st.error("Output is Empty")
            return False
        ### Process Local Mclag Interface output
        entries = utils.filter_and_select(output2, None, match={'mclag_intf':mclag_intf})
        args2 = ['mclag_intf_peer_state']
        for key in args2:
            if key in kwargs.keys():
                if str(kwargs[key]) != str(entries[0][key]):
                    st.error("{}:==> Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(mclag_intf, key, kwargs[key], entries[0][key]))
                    ret_val = False
                else:
                    st.log("{}:==> Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(mclag_intf, key, kwargs[key], entries[0][key]))
    elif cli_type == 'klish':
        mintf = get_interface_number_from_name(mclag_intf)
        cmd = 'show mclag interface {} {}'.format(mintf['number'], domain_id)
        output = st.show(dut, cmd, type='klish')
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        # In klish, the value is always lowercase - changing from 'Up' to 'up'.
        args_modif = ['mclag_intf_local_state', 'mclag_intf_peer_state']
        for key in args_modif:
            if key in kwargs:
                kwargs[key] = kwargs[key].lower()
        args1 = ['mclag_intf_local_state', 'mclag_intf_peer_state', 'isolate_peer_link', 'traffic_disable']
        for key in args1:
            if key in kwargs.keys():
                if str(kwargs[key]) != str(output[0][key]):
                    st.error(":==> Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
                    ret_val = False
                else:
                    st.log(":==> Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))

    return ret_val


def verify_iccp_macs(dut,**kwargs):
    '''
    Klish support not available

    Author: sneha.mathew@broadcom.com
    Verify MACs learned in Mclag peers in ICCP cache
    :param dut:
    :param kwargs:
    :return:
    '''
    ret_val = True
    ### This is ICCP dump for mac and no equivalent klish command, hence keep cli_type as click
    cli_type = 'click'
    #cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    #cli_type = kwargs.get('cli_type', 'click')
    if 'cli_type' in kwargs:
        del kwargs['cli_type']

    return_type = kwargs.get('return_type', 'BOOL')
    if 'return_type' in kwargs:
        del kwargs['return_type']

    if cli_type == 'click':
        cmd = 'mclagdctl dump mac '
        if 'domain_id' in kwargs:
            domain_id = kwargs['domain_id']
            del kwargs['domain_id']
            cmd += '-i {}'.format(domain_id)
        else:
            st.error("Mandatory argument domain id Not Found")
            return False
        output = st.show(dut, cmd)

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if return_type == 'NULL':
        ### Just display command output
        return

    mac_count = len(output) - 1
    ### Create match dictionary from kargs,vlaue pair
    match = {}
    for key  in kwargs:
        if kwargs.get(key, None) != None:
            match[key] = kwargs[key]

    if match != {}:
        ### Filter matching entries
        entries = utils.filter_and_select(output, None, match=match)
        if entries == []:
            ret_val = False
            mac_count = 0
            st.error("Match NOT FOUND for {}.".format(match))
        else:
            st.log("Match FOUND for {}.\n Output:{}".format(match,entries))
            mac_count = len(entries)
    ### Return count if count in keywords
    if return_type == 'NUM':
        return mac_count
    if return_type == 'BOOL':
        return ret_val


def show_stateDB_macs(dut):
    '''
    Klish support not needed

        Author: sneha.mathew@broadcom.com
        Display MACs in stateDB
        :param dut:
        :param kwargs:
        :return:
        '''
    ### Collect stateDB
    st.log("StateDB MAC Entries:")
    st.show(dut, redis.build(dut, redis.STATE_DB, 'keys *FDB*'), skip_tmpl=True)


def show_appDB_macs(dut):
    '''
    Klish support not needed

        Author: sneha.mathew@broadcom.com
        Display MACs in appDB
        :param dut:
        :param kwargs:
        :return:
        '''

    ### Collect appDB
    st.log("AppDB MAC Entries:")
    st.show(dut, redis.build(dut, redis.APPL_DB, 'keys *FDB*'), skip_tmpl=True)

def show_asicDB_macs(dut):
    '''
    Klish support not needed

        Author: sneha.mathew@broadcom.com
        Display MACs in asicDB
        :param dut:
        :param kwargs:
        :return:
        '''

    ### Collect asicDB
    st.log("AsicDB MAC Entries:")
    st.show(dut, redis.build(dut, redis.ASIC_DB, 'keys *FDB*'), skip_tmpl=True)

def show_iccp_arp(dut,**kwargs):
    '''
    Klish support not needed

    Author: sunil.rajendra@broadcom.com
    Show ARPs learned in Mclag peers in ICCP cache
    :param dut:
    :param kwargs: domain_id
    :return:
    '''
    ret_val = True
    ### This is ICCP dump for arp and no equivalent klish command, hence keep cli_type as click
    cli_type = 'click'
    #cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    if 'cli_type' in kwargs:
        del kwargs['cli_type']

    if cli_type == 'click':
        cmd = 'mclagdctl dump arp '
        if 'domain_id' in kwargs:
            domain_id = kwargs['domain_id']
            del kwargs['domain_id']
            cmd += '-i {}'.format(domain_id)
        else:
            st.error("Mandatory argument domain id Not Found")
            return False
        output = st.show(dut, cmd, skip_tmpl=True)
        return output
    return ret_val

def show_iccp_nd(dut,**kwargs):
    '''
    Klish support not needed

    Author: sunil.rajendra@broadcom.com
    Show NDs learned in Mclag peers in ICCP cache
    :param dut:
    :param kwargs: domain_id
    :return:
    '''
    ret_val = True
    ### This is ICCP dump for ndp and no equivalent klish command, hence keep cli_type as click
    cli_type = 'click'
    #cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    if 'cli_type' in kwargs:
        del kwargs['cli_type']

    if cli_type == 'click':
        cmd = 'mclagdctl dump nd '
        if 'domain_id' in kwargs:
            domain_id = kwargs['domain_id']
            del kwargs['domain_id']
            cmd += '-i {}'.format(domain_id)
        else:
            st.error("Mandatory argument domain id Not Found")
            return False
        output = st.show(dut, cmd, skip_tmpl=True)
        return output
    return ret_val

def _cleanup_mclag_config_helper(dut_list, cli_type=''):
    """
    Helper routine to cleanup MCLAG config from devices.
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    for dut in dut_li:
        st.log("############## {} : MCLAG config cleanup ################".format(dut))
        if cli_type == 'click':
            output = st.show(dut, "mclagdctl dump state")
        elif cli_type == 'klish':
            output = st.show(dut, "show mclag brief",type=cli_type)
        st.log("##### MCLAG : {}".format(output))
        if len(output) == 0:
            continue

        for entry in output:
            if not entry['domain_id']:
                continue

            domain_id = entry['domain_id']
            if cli_type == 'click':
                st.config(dut, "sudo config mclag del {}".format(domain_id))
            elif cli_type == 'klish':
                cmd = "no mclag domain {}".format(domain_id)
                st.config(dut, cmd, type="klish", conf=True)

    return True


def cleanup_mclag_configuration(dut_list, thread=True, cli_type=''):
    """
    Find and cleanup MCLAG config

    :param dut_list
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    [out, exceptions] = utils.exec_foreach(thread, dut_li, _cleanup_mclag_config_helper,cli_type=cli_type)
    st.log(exceptions)
    return False if False in out else True

def get_syslog_init_time(dut, **kwargs):
    cmd="sudo tail -1 /var/log/syslog"
    output = st.show(dut, cmd, skip_error_check=True, skip_tmpl=True)
    output = str(' '.join(output.split()[0:3]))
    st.log("Inside get_syslog_init_time: Time = {}, dut = {}.".format(output, dut))
    return output

def lib_get_bridge_mac(dut):
    output = st.show(dut, 'mclagdctl dump state')
    if len(output) == 1:
        return output[0]['peer_link_mac']
    return None


def lib_is_dut_mc_lag_active(dut):
    output = st.show(dut, 'mclagdctl dump state')
    if len(output) == 1 and output[0]['node_role'] == 'Active':
        return True
    return False

def lib_get_active_bridge(dut_list):
    for dut in dut_list:
        if lib_is_dut_mc_lag_active(dut):
            return dut
    return None

def parse_show_mclag_brief_config(response):
    dict1 = response["output"]
    if 'openconfig-mclag:config' not in dict1:
        return []
    dict1 = dict1['openconfig-mclag:config']
    output = {}
    for arg in ["domain-id","source-address","peer-address","peer-link","keepalive-interval","session-timeout","delay-restore","mclag-system-mac"]:
        if arg == "source-address" and arg in dict1:
            arg1 = "local_ip"
            output[arg1] = dict1[arg]
        elif arg == "source-address" and arg not in dict1:
            arg1 = "local_ip"
            output[arg1] = ""
        elif arg == "peer-address" and arg in dict1:
            arg1 = "peer_ip"
            output[arg1] = dict1[arg]
        elif arg == "peer-address" and arg not in dict1:
            arg1 = "peer_ip"
            output[arg1] = ""
        elif arg == "peer-link" and arg in dict1:
            arg1 = "peer_link_inf"
            output[arg1] = dict1[arg]
        elif arg == "peer-link" and arg not in dict1:
            arg1 = "peer_link_inf"
            output[arg1] = ""
        elif arg == "domain-id" and arg in dict1:
            arg1 = "domain_id"
            output[arg1] = dict1[arg]
        elif arg == "domain-id" and arg not in dict1:
            arg1 = "domain_id"
            output[arg1] = ""
        elif arg == "keepalive-interval" and arg in dict1:
            arg1 = "keepalive_timer"
            output[arg1] = dict1[arg]
        elif arg == "keepalive-interval" and arg not in dict1:
            arg1 = "keepalive_timer"
            output[arg1] = ""
        elif arg == "session-timeout" and arg in dict1:
            arg1 = "session_timer"
            output[arg1] = dict1[arg]
        elif arg == "session-timeout" and arg not in dict1:
            arg1 = "session_timer"
            output[arg1] = ""
        elif arg == "delay-restore" and arg in dict1:
            arg1 = "delay_restore_timer"
            output[arg1] = dict1[arg]
        elif arg == "delay-restore" and arg not in dict1:
            arg1 = "delay_restore_timer"
            output[arg1] = ""
        elif arg == "mclag-system-mac" and arg in dict1:
            arg1 = "mclag_sys_mac"
            output[arg1] = dict1[arg]
        elif arg == "mclag-system-mac" and arg not in dict1:
            arg1 = "mclag_sys_mac"
            output[arg1] = ""
        if arg in dict1:
            if isinstance(dict1[arg],int):
                output[arg1] = str(dict1[arg])
            elif "portchannel" in output[arg1]:
                value = output[arg1]
                output[arg1] = value.replace("portchannel","PortChannel")
    return [output]

def parse_show_mclag_brief_state(response):
    dict1 = response["output"]
    if 'openconfig-mclag:state' not in dict1:
        return []
    dict1 = dict1['openconfig-mclag:state']
    output = {}
    for arg in ["oper-status","role","system-mac"]:
        if arg == "oper-status" and arg in dict1:
            arg1 = "session_status"
            if dict1[arg] == "OPER_DOWN":
                output[arg1] = "down"
            elif dict1[arg] == "OPER_UP":
                output[arg1] = "up"
        elif arg == "role" and arg in dict1:
            arg1 = "node_role"
            if dict1[arg] == "ROLE_ACTIVE":
                output[arg1] = "active"
            elif dict1[arg] == "ROLE_STANDBY":
                output[arg1] = "standby"
        elif arg == "system-mac" and arg in dict1:
            arg1 = "gw_mac"
            output[arg1] = dict1[arg]
    return [output]

