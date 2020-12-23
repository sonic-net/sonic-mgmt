from spytest import st
from spytest.utils import filter_and_select
from apis.system.rest import config_rest, delete_rest, get_rest

def config_remote_syslog_server(dut, **kwargs):
    """
    Configuring syslog server
    :param dut:
    :param host:
    :param source_intf:
    :param remote_port:
    :param vrf:
    :param skip_error:
    :param config:
    :return:
    log_obj.config_remote_syslog_server(dut = dut1, host = '10.59.130.43', config = 'yes')
    log_obj.config_remote_syslog_server(dut = data.dut1_client, host = dut1_dut2_ip[0], config = 'yes',source_intf = 'Ethernet48')
    log_obj.config_remote_syslog_server(dut = data.dut1_client, host = dut1_dut2_ip[0], config = 'yes',source_intf = 'Ethernet48', remote_port = 514)
    log_obj.config_remote_syslog_server(dut = data.dut1_client, host = dut2_dut1_ip[0], source_intf = 'Ethernet48',config = 'yes',cli_type='rest-put')
    log_obj.config_remote_syslog_server(dut = data.dut1_client, host = dut2_dut1_ip[0], source_intf = 'Ethernet48',config = 'yes',vrf = 'mgmt',cli_type='rest-put')
    """
    st.log('Config Syslog server')
    config =  kwargs.get('config','')
    host =  kwargs.get('host',None)
    source_intf =  kwargs.get('source_intf',None)
    remote_port =  kwargs.get('remote_port',None)
    vrf =  kwargs.get('vrf',None)
    skip_error = kwargs.get('skip_error',False)
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if config.lower() == 'yes':
        config = ''
    if host is None:
        st.error("Mandatory parameter hostname/IP address not found")
        return False
    if cli_type == 'klish':
        command = "{} logging server {}".format(config, host)
        if source_intf != None and config == '':
            command = command + " source-interface {}".format(source_intf)
        if remote_port != None and config == '':
            command = command + " remote-port {}".format(remote_port)
        if vrf != None and config == '':
            command = command + " vrf {}".format(vrf)
        output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        if "Error" in output:
            st.error("Error during configuration")
            return False
        return True
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        if config == '':
            rest_url = rest_urls['config_remote_server'].format(str(host))
            ocdata = {"openconfig-system:config":{"host":str(host)}}
            if source_intf != None:
                ocdata["openconfig-system:config"]["openconfig-system-ext:source-interface"] = str(source_intf)
            if remote_port != None:
                ocdata["openconfig-system:config"]["remote-port"] = int(remote_port)
            if vrf != None:
                ocdata["openconfig-system:config"]["openconfig-system-ext:vrf-name"] = str(vrf)
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
                if not response:
                    st.log(response)
                    return False
            return True
        else:
            rest_url = rest_urls['delete_remote_server'].format(str(host))
            response = delete_rest(dut, http_method='delete', rest_url=rest_url)
            if not response:
                st.log(response)
                return False
            return True
    else:
        st.log("Unsupported cli")


def verify_remote_syslog_server(dut, **kwargs):
    """
    Verifying syslog server
    :param dut:
    :param host:
    :param source_intf:
    :param remote_port:
    :param vrf:
    :return:
    log_obj.verify_remote_syslog_server(dut = dut1, host = '10.59.130.43')
    log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = dut1_dut2_ip[0], source_intf = 'Ethernet48')
    log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = dut1_dut2_ip[0], source_intf = 'Ethernet48', remote_port = 514)
    log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = dut2_dut1_ip[0], source_intf = 'Ethernet48', cli_type='rest-put')
    log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = dut2_dut1_ip[0], source_intf = 'Ethernet48', vrf = 'mgmt', cli_type='rest-put')
    """
    st.log('Verify Syslog server')
    host =  kwargs.get('host',None)
    source_intf =  kwargs.get('source_intf',None)
    remote_port =  kwargs.get('remote_port',None)
    vrf =  kwargs.get('vrf',None)
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if host is None:
        st.error("Mandatory parameter hostname/IP address not sent")
        return False
    if cli_type == 'klish':
        st.log("show logging servers")
        command = "show logging servers"
        output = st.show(dut,command,type = "klish",config = "false",skip_error_check = "True")
        entry = filter_and_select(output, None, {"host": host})
        for val in entry:
            if val['host'] != host:
                st.log("Host is not as expected {}".format(host))
                return False
            if source_intf != None and val['srcintf'] != source_intf:
                st.log("Source Interface is not as expected {}".format(source_intf))
                return False
            if remote_port != None and val['port'] != remote_port:
                st.log("Remote port is not as expected {}".format(remote_port))
                return False
            if vrf != None and val['vrf'] != vrf:
                st.log("Vrf is not as expected {}".format(vrf))
                return False
        return True
    elif cli_type == ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['config_remote_server'].format(str(host))
        payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-system:config']
        if payload['host'] != str(host):
            st.log("Host is not as expected {}".format(host))
            return False
        if source_intf != None:
            if payload['openconfig-system-ext:source-interface'] != str(source_intf):
                st.log("Source Interface is not as expected {}".format(source_intf))
                return False
        if remote_port != None:
            if payload['remote-port'] != int(remote_port):
                st.log("Remote port is not as expected {}".format(remote_port))
                return False
        if vrf != None:
            if payload['openconfig-system-ext:vrf-name'] != str(vrf):
                st.log("Vrf is not as expected {}".format(vrf))
                return False
        return True
    else:
        st.log("Unsupported cli")

