# This file contains the list of API's which performs TACSCS operations.
# @author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest.utils import filter_and_select
from spytest import st
import re
import json
from apis.system.rest import config_rest, delete_rest,get_rest

##timeout set to 125 sec due defect sonic-24329.once fixed will change to lower limit.
time_out=125

def set_aaa_authentication_properties(dut,property,value, cli_type="", **kwargs):
    '''
    Configuring aaa authentication properties.
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "config aaa  authentication {} {}".format(property,value)
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        if property == "login":
            value = "local" if value == "default" else value
            if value == "local":
                command = "aaa authentication {} default {}".format(property, value)
            else:
                values = re.split(" +", value)
                if len(values) == 2 and values[0] == "local":
                    command = "aaa authentication {} default {} group {}".format(property, values[0], values[1])
                else:
                    command = "aaa authentication {} default group {}".format(property, value)
        elif property == "failthrough":
            value = "disable" if value == "default" else value
            command = "aaa authentication failthrough {}".format(value)
        else:
            st.log("UNSUPPORTED AUTHENTICATION PROPERTY -- {}".format(property))
            return False
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['aaa_autentication_method']
        url1 =rest_urls['aaa_autentication_failthrough']
        if property == "login" and value == "radius local":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method": [
                              "radius",
                              "local"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
        elif property == "login" and value == "local radius":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method": [
                              "local",
                              "radius"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
        elif property == "login" and value == "default":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method": [
                              "local"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
        elif property == "login" and value == "radius":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method": [
                              "radius"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
        elif property == "failthrough" and value == "enable":
            data = json.loads("""
                        {
                            "openconfig-system-ext:failthrough": "True"
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=data, timeout=time_out, **kwargs):
                return False
        elif property == "failthrough" and value == "default":
            if not delete_rest(dut, rest_url=url1, timeout=time_out):
                return False
        elif property == "login" and value == "tacacs+ local":
            data = json.loads("""
                            {
                              "openconfig-system:authentication-method": [
                                  "tacacs+",
                                  "local"
                                ]
                            }
                        """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, **kwargs):
                return False
        elif property == "login" and value == "local tacacs+":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method": [
                              "local",
                              "tacacs+"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, **kwargs):
                return False
        elif property == "login" and value == "tacacs+":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method":[
                              "tacacs+"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        elif property == "login" and value == "ldap":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method":[
                              "ldap"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        elif property == "login" and value == "ldap local":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method":[
                              "ldap",
                              "local"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        elif property == "login" and value == "local ldap":
            data = json.loads("""
                        {
                          "openconfig-system:authentication-method":[
                              "local",
                              "ldap"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False

    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def set_aaa_authorization_properties(dut,property,value, cli_type=""):
    '''
    Configuring aaa authorization properties.
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "config aaa  authorization {} {}".format(property,value)
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        value = "local" if value == "default" else value
        if value == "local":
            command = "aaa authorization {} default {}".format(property, value)
        else:
            command = "aaa authorization {} default group {}".format(property, value)
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['aaa_authorization_method']
        if property == "login" and value == "ldap":
            data = json.loads("""
                        {
                          "openconfig-system:authorization-method": [
                              "ldap"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
        if property == "login" and value == "local":
            data = json.loads("""
                        {
                          "openconfig-system:authorization-method": [
                              "local"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False

    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def set_aaa_name_service_properties(dut,property,value, cli_type=""):
    '''
    Configuring aaa name_service properties.
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "config aaa nss {} {}".format(property,value)
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        value = "group ldap" if value == "ldap" else value
        command = "aaa name-service {} {}".format(property, value)
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['aaa_nameservice_method']
        if property == "passwd" and value == "ldap":
            data = json.loads("""
                        {
                          "openconfig-system:passwd-method": [
                              "ldap"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
        if property == "group" and value == "ldap":
            data = json.loads("""
                        {
                          "openconfig-system:group-method": [
                              "ldap"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
        if property == "shadow" and value == "ldap":
            data = json.loads("""
                        {
                          "openconfig-system:shadow-method": [
                              "ldap"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
        if property == "sudoers" and value == "ldap":
            data = json.loads("""
                        {
                          "openconfig-system:sudoers-method": [
                              "ldap"
                            ]
                        }
                    """)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out):
                return False
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def set_tacacs_properties(dut,property,value, cli_type="", **kwargs):
    '''
    Configuring tacacs properties.
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    property_mapping = {"authtype":"auth-type","passkey":"key","timeout":"timeout",
                        "sourceip":"host","source-interface":"source-interface"}
    if cli_type == "click":
        command = "config tacacs {} {}".format(property, value)
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        if property != "default":
            property = property_mapping[property]
            command = "tacacs-server {} {}".format(property, value)
        else:
            property = property_mapping[value]
            command = "no tacacs-server {}".format(property)
        st.config(dut, command, type=cli_type)
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        property_mapping = {"authtype": "openconfig-system-ext:auth-type", "passkey": "openconfig-system-ext:secret-key",
                        "timeout": "openconfig-system-ext:timeout"}
        url_mapping = {"authtype":"tacacs_global_authtype_config",  "passkey":"tacacs_global_passkey_config" ,
                        "timeout":"tacacs_global_timeout_config" }
        if property != 'default':
            url = rest_urls[url_mapping[property]].format("TACACS")
            data= {property_mapping[property]: value}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data= data, timeout=time_out, **kwargs):
                st.error("Failed to configure tacacs global params")
                return False
        else:
            url = rest_urls[url_mapping[value]].format("TACACS")
            if not delete_rest(dut, rest_url=url, timeout=time_out, **kwargs):
                st.error("Failed to delete tacacs global params")
                return False
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def set_tacacs_server(dut,mode,address,tcp_port=None,timeout=None,passkey=None,auth_type=None,
                      priority=None,use_mgmt_vrf= False, cli_type="", **kwargs):
    '''
    Configuring tacacs server properties.
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        sub_opts = []
        if mode.lower() == 'add':
            command = "config tacacs {} {} ".format('add',address)
            if tcp_port:
                sub_opts.append('{} {}'.format('-o',tcp_port))
            if timeout:
                sub_opts.append('{} {}'.format('-t',timeout))
            if passkey:
                sub_opts.append('{} {}'.format('-k',passkey))
            if auth_type:
                sub_opts.append('{} {}'.format('-a',auth_type))
            if priority:
                sub_opts.append('{} {}'.format('-p',priority))
            if use_mgmt_vrf:
                sub_opts.append('{}'.format('-m'))
            command = command + ' '.join(sub_opts)
        elif mode.lower() == 'delete':
            command = "config tacacs {} {} ".format('delete',address)
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        no_form = "no" if mode.lower() == "delete" else ""
        if not no_form:
            command = "tacacs-server host {}".format(address)
            if timeout:
                command += " timeout {}".format(timeout)
            if passkey:
                command += " key {}".format(passkey)
            if auth_type:
                command += " type {}".format(auth_type)
            if tcp_port:
                command += " port {}".format(tcp_port)
            if priority:
                command += " priority {}".format(priority)
            if use_mgmt_vrf:
                command += " vrf mgmt"
        else:
            command = "{} tacacs-server host {}".format(no_form, address)
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if mode.lower() == 'add':
            url = rest_urls['tacacs_authtype_config']
            data ={
                  "openconfig-system:server-group": [
                    {
                      "name": "TACACS",
                      "config": {
                        "name": "TACACS",
                        "openconfig-system-ext:auth-type": str(auth_type),
                        "openconfig-system-ext:secret-key": str(passkey),
                        "openconfig-system-ext:timeout":  int(timeout)
                      },
                      "servers": {
                        "server": [
                          {
                            "address":  str(address),
                            "config": {
                              "name": "TACACS",
                              "address":  str(address),
                              "timeout":  int(timeout),
                              "openconfig-system-ext:auth-type": str(auth_type),
                              "openconfig-system-ext:priority": int(priority)
                            },
                            "tacacs": {
                              "config": {
                                "port": int(tcp_port),
                                "secret-key": str(passkey)
                              }
                            }
                          }
                        ]
                      }
                    }
                  ]
                }
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out, **kwargs):
                st.error("Failed to configure auth_type for {} server".format(address))
                return False
            if use_mgmt_vrf:
                url = rest_urls['tacacs_vrf_config'].format('TACACS', address)
                data = {"openconfig-system-ext:vrf": "mgmt"}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data, timeout=time_out, **kwargs):
                    st.error("Failed to configure VRF for {} server".format(address))
                    return False
        if mode.lower() == 'delete':
            url = rest_urls['delete_tacacs_server'].format('TACACS', address)
            if not delete_rest(dut, rest_url=url, timeout=time_out, **kwargs):
                st.error('Failed to delete the server {}'. format(address))
                return False
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True

def show_aaa(dut,cli_type):
    '''
    To get the show aaa command output as list of dict
    '''
    command = "show aaa"
    return st.show(dut,command,cli_type=cli_type,skip_error_check="True")


def show_tacacs(dut, cli_type=""):
    '''
    To get the show tacacs command output as list of dict
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    rv = {'global': [], 'servers': []}
    if cli_type == "click":
        command = "show tacacs"
        out =  st.show(dut,command)
        rv['global']= [{'auth_type':out[0]['global_auth_type']\
                                        ,'passkey':out[0]['global_passkey']\
                                        ,'timeout':out[0]['global_timeout']}]
        for each_dict in out:
            if each_dict['address'] != '' and  each_dict['priority'] != '':
                temp_dic = {
                        'address':each_dict['address']\
                        ,'priority':each_dict['priority']\
                        ,'tcp_port':each_dict['tcp_port'] \
                        ,'passkey': each_dict['passkey']\
                        ,'auth_type':each_dict['auth_type']\
                        ,'timeout':each_dict['timeout']
                                        }

                rv['servers'].append(temp_dic)
    elif cli_type == "klish":
        command = "show tacacs-server global"
        output = st.show(dut, command, type=cli_type)
        if output:
            rv['global'] = [{'auth_type': output[0]['global_auth_type'] \
                                , 'passkey': output[0]['global_passkey'] \
                                , 'timeout': output[0]['global_timeout'],
                                    'src_intf': output[0]["global_src_intf"]}]
        command = "show tacacs-server host"
        output = st.show(dut, command, type=cli_type)
        if output:
            for each_dict in output:
                temp_dic = {
                    'address': each_dict['host'] \
                    , 'priority': each_dict['priority'] \
                    , 'tcp_port': each_dict['port'] \
                    , 'passkey': each_dict['passkey'] \
                    , 'auth_type': each_dict['auth_type'] \
                    , 'timeout': each_dict['timeout']
                }

                rv['servers'].append(temp_dic)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['tacacs_server_show'].format("TACACS")
        #url1= rest_urls['radius_server_config'].format("TACACS")
        server_output = get_rest(dut, rest_url=url, timeout=time_out)
        rv = process_tacacs_output(server_output['output'])
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
    return rv

def convert_aaa_rest_output(output1):
    transformed_output_list =[]
    transformed_output = {}
    transformed_output['login'] = output1.get('openconfig-system:aaa',{}).get('authentication',{}).get('state',{}).get('authentication-method',{})
    transformed_output['failthrough'] = output1.get('openconfig-system:aaa',{}).get('authentication',{}).get('state',{}).get('openconfig-system-ext:failthrough',{})
    authorization_login = output1.get('openconfig-system:aaa',{}).get('authorization',{}).get('openconfig-aaa-ext:login',{}).get('state',{}).get('authorization-method',[])
    if len(authorization_login) > 0 : transformed_output['authorization_login'] = authorization_login[0]
    nss_passwd = output1.get('openconfig-system:aaa',{}).get('openconfig-aaa-ext:name-service',{}).get('state',{}).get('passwd-method',[])
    if len(nss_passwd) > 0 : transformed_output['nss_passwd'] = nss_passwd[0]
    nss_shadow = output1.get('openconfig-system:aaa',{}).get('openconfig-aaa-ext:name-service',{}).get('state',{}).get('shadow-method',[])
    if len(nss_shadow) > 0 : transformed_output['nss_shadow'] = nss_shadow[0]
    nss_group = output1.get('openconfig-system:aaa',{}).get('openconfig-aaa-ext:name-service',{}).get('state',{}).get('group-method',[])
    if len(nss_group) > 0 : transformed_output['nss_group'] = nss_group[0]
    nss_sudoers = output1.get('openconfig-system:aaa',{}).get('openconfig-aaa-ext:name-service',{}).get('state',{}).get('sudoers-method',[])
    if len(nss_sudoers) > 0 : transformed_output['nss_sudoers'] = nss_sudoers[0]
    transformed_output_list.append(transformed_output)
    return transformed_output_list

def verify_aaa(dut,login=None,failthrough=None,fallback=None, **kwargs):
    '''
    To verify the 'show aaa' parameters
    '''

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    output = ''
    if  cli_type == "click" or cli_type == "klish":
        output = show_aaa(dut, cli_type=cli_type)
        st.log("output===================started")
        st.log(output)
        st.log("output===================End")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url1 = rest_urls['show_aaa']
        output1 = get_rest(dut,rest_url=rest_url1, timeout=time_out)
        st.log("Before output1===================started")
        st.log(output1)
        st.log("Before output1===================End")
        out1 = output1.get('output',{})
        st.log("output1===================started")
        st.log(output1)
        st.log("output1===================End")
        output = convert_aaa_rest_output(out1)
        st.log("output===================started")
        st.log(output)
        st.log("output===================End")
    if 'cli_type' in kwargs:
        del kwargs['cli_type']

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if  cli_type == "click":
        if login and not filter_and_select(output, ['login'], {"login": login}):
            st.error("Provided and Configured login  values are not match.")
            return False
        if failthrough and not filter_and_select(output, ['failthrough'], {"failthrough": failthrough}):
            st.error("Provided and Configured failthrough  values are not match.")
            return False
        if fallback and not filter_and_select(output, ['fallback'], {"fallback": fallback}):
            st.error("Provided and Configured fallback values are not match.")
            return False
    elif cli_type == "klish" or cli_type == "rest-patch" or cli_type == "rest-put":
        for key in kwargs:
            if str(kwargs[key]) != str(output[0][key]):
                st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
                return False
            else:
                st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
    return True

def verify_tacacs_global(dut,auth_type=None,timeout=None,passkey=None, cli_type=""):
    '''
    To verify the 'show tacacs' global parameters
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = show_tacacs(dut, cli_type=cli_type)
    output = output['global']
    if auth_type and not filter_and_select(output, ['auth_type'], {"auth_type": auth_type}):
        st.error("Global:Provided and Configured auth_type values are not match.")
        return False
    if timeout and not filter_and_select(output, ['timeout'], {"timeout": timeout}):
        st.error("Global:Provided and Configured timeout values are not match.")
        return False
    if passkey and not filter_and_select(output, ['passkey'], {"passkey": passkey}):
        st.error("Global:Provided and Configured passkey values are not match.")
        return False
    return True


def verify_tacacs_server(dut,address,tcp_port=None,timeout=None,passkey=None,auth_type=None,priority=None, cli_type=""):
    '''
    To verify the 'show tacacs' server parameters
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = show_tacacs(dut, cli_type=cli_type)
    output = output['servers']
    if address and not filter_and_select(output, ['address'], {"address": address}):
        st.error("Provided and configured address values are not matching.")
        return False
    if tcp_port and not filter_and_select(output, ['tcp_port'], {"tcp_port": tcp_port}):
        st.error("Provided and configured tcp_port values are not matching.")
        return False
    if priority and not filter_and_select(output, ['priority'], {"priority": priority}):
        st.error("Provided and configured priority values are not matching.")
        return False
    if timeout and not filter_and_select(output, ['timeout'], {"timeout": timeout}):
        st.error("Provided and configured timeout values are not matching.")
        return False
    if passkey and not filter_and_select(output, ['passkey'], {"passkey": passkey}):
        st.error("Provided and configured passkey values are not matching.")
        return False
    if auth_type and not filter_and_select(output, ['auth_type'], {"auth_type": auth_type}):
        st.error("Provided and configured auth_type values are not matching.")
        return False
    return True


def verify_tacacs_details(dut, tacacs_params, cli_type=""):
    """
    API to verify the tacacs details
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param tacacs_params:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if tacacs_params:
        output = show_tacacs(dut, cli_type=cli_type)
        if output and "servers" in output:
            output = output['servers']
            for params in tacacs_params:
                if params["ip"] and not filter_and_select(output, ['address'], {"address": params["ip"]}):
                    st.error("Provided and configured address values are not matching.")
                    return False
                if params["tcp_port"] and not filter_and_select(output, ['tcp_port'], {"tcp_port": params["tcp_port"]}):
                    st.error("Provided and configured tcp_port values are not matching.")
                    return False
                if params["priority"] and not filter_and_select(output, ['priority'], {"priority": params["priority"]}):
                    st.error("Provided and configured priority values are not matching.")
                    return False
                if params["timeout"] and not filter_and_select(output, ['timeout'], {"timeout": params["timeout"]}):
                    st.error("Provided and configured timeout values are not matching.")
                    return False
                if params["passkey"] and not filter_and_select(output, ['passkey'], {"passkey": params["passkey"]}):
                    st.error("Provided and configured passkey values are not matching.")
                    return False
                if params["auth_type"] and not filter_and_select(output, ['auth_type'], {"auth_type": params["auth_type"]}):
                    st.error("Provided and configured auth_type values are not matching.")
                    return False
            return True
        else:
            st.log("servers index not found in output ...")
            return False
    else:
        st.log("tacacs params not provided ...")
        return False

def process_tacacs_output(server_output):

    all_servers_output = dict()
    all_servers_output["servers"] = list()

    if server_output and server_output.get("openconfig-system:servers"):
        for server_data in server_output.get("openconfig-system:servers")["server"]:
            servers = dict()
            servers["address"] = server_data.get("address", "")
            if server_data.get("config"):
                serve_config = server_data.get("config")
                servers["auth_type"] = serve_config.get("openconfig-system-ext:auth-type", "")
                servers["priority"] = serve_config.get("openconfig-system-ext:priority", "")
                servers["timeout"] = serve_config.get("timeout", "")
            elif server_data.get("state"):
                serve_state = server_data.get("config")
                servers["auth_type"] = serve_state.get("openconfig-system-ext:auth-type", "")
                servers["priority"] = serve_state.get("openconfig-system-ext:priority", "")
                servers["timeout"] = serve_state.get("timeout", "")
            if server_data.get("tacacs"):
                serve_tacacs = server_data.get("tacacs")["config"]
                servers["tcp_port"] = serve_tacacs.get("port", "")
                servers["passkey"] = serve_tacacs.get("secret-key", "")
            all_servers_output["servers"].append(servers)
    print("All Tacacs server output : {}".format(all_servers_output))
    return all_servers_output
