# This file contains the list of API's which performs LDAP operations.
from spytest import st
from spytest.utils import filter_and_select
from apis.system.rest import config_rest, get_rest, delete_rest


debug = False
time_out = 125

def config_ldap_server(dut, no_form=False, skip_error_check=False, **kwargs):
    """
    Config / Unconfig ldap server using provided parameters

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log("Configuring LDAP SERVER Parameters ...")
    if "ip_address" not in kwargs:
        st.log("IP Address not provided")
        return False
    cmd = "ldap-server host {}".format(kwargs["ip_address"])
    if "use_type" in kwargs:
        cmd += " use-type {}".format(kwargs["use_type"])
    if "port" in kwargs:
        cmd += " port {}".format(kwargs["port"])
    if "priority" in kwargs:
        cmd += " priority {}".format(kwargs["priority"])
    if "ssl" in kwargs:
        cmd += " ssl {}".format(kwargs["ssl"])
    if no_form:
        cmd = "no " + cmd
    st.log(cmd)
    st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)

def config_ldap_server_map(dut, no_form=False, skip_error_check=False, **kwargs):
    """
    Config / Unconfig ldap server map using provided parameters

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log("Configuring LDAP server map parameters")
    cmd = ""
    if no_form:
        cmd = "no ldap-server map attribute "+ kwargs["keyName"]
    else:
        cmd = "ldap-server map attribute "+ kwargs["keyName"] + " to " + kwargs["toName"]
    st.log(cmd)
    st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
def config_ldap_server_global(dut, no_form=False, skip_error_check=False, **kwargs):
    """
    Config / Unconfig ldap server global using provided parameters

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log("Configuring LDAP server global parameters")
    cmd = ""
    if no_form:
        cmd = "no ldap-server "+ kwargs["attrName"]
    else:
        cmd = "ldap-server "+ kwargs["attrName"] + " " + str(kwargs["attrVal"])
    st.log(cmd)
    st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)

def config_ldap_server_nss(dut, no_form=False, skip_error_check=False, **kwargs):
    """
    Config / Unconfig ldap server NSS using provided parameters

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log("Configuring LDAP server global parameters")
    cmd = ""
    if no_form:
        cmd = "no ldap-server nss "+ kwargs["attrName"]
    else:
        cmd = "ldap-server nss "+ kwargs["attrName"] + " " + str(kwargs["attrVal"])
    st.log(cmd)
    st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)

def config_ldap_server_sudo(dut, no_form=False, skip_error_check=False, **kwargs):
    """
    Config / Unconfig ldap server SUDO using provided parameters

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log("Configuring LDAP server global parameters")
    cmd = ""
    if no_form:
        cmd = "no ldap-server sudo "+ kwargs["attrName"]
    else:
        cmd = "ldap-server sudo "+ kwargs["attrName"] + " " + str(kwargs["attrVal"])
    st.log(cmd)
    st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
def config_ldap_server_pam(dut, no_form=False, skip_error_check=False, **kwargs):
    """
    Config / Unconfig ldap server PAM using provided parameters

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log("Configuring LDAP PAM server parameters")
    cmd = ""
    if no_form:
        cmd = "no ldap-server pam "+ kwargs["attrName"]
    else:
        cmd = "ldap-server pam "+ kwargs["attrName"] + " " + str(kwargs["attrVal"])
    st.log(cmd)
    st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)

def verify_command (dut, url, expResp):
    """
    To verify the command

    """
    resp = st.rest_read(dut, path=url)
    st.log(resp)
    return (expResp.items() == resp["output"].items())

def config_ldap_server_host(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_ldap_server_host(dut=data.dut1,server='IPV4 Address',use_type='all',port= '400',
    priority='2',ssl='start_tls',retry='1',config='yes')
    config_ldap_server_host(dut=data.dut1,server='IPV6 Address',use_type='nss',priority='3',
    ssl='on',retry='5',config='yes')
    config_ldap_server_host(dut=data.dut1,server='DNS Name',use_type='sudo',priority='4',
    retry='4',config='yes')
    config_ldap_server_host(dut=data.dut1,server='IPV4 Address'use_type='pam',priority='5',
    ssl='start_tls',retry='3',config='yes')
    config_ldap_server_host(dut=data.dut1,server='IPV4 Address'use_type='all',port= '400',
    priority='2',ssl='start_tls',retry='1',config='no')
    config_ldap_server_host(dut=data.dut1,server='IPV6 Address'use_type='nss',priority='3',
    ssl='on',retry='5',config='no')
    config_ldap_server_host(dut=data.dut1,server='DNS Name'use_type='sudo',priority='4',
    retry='4',config='no')
    config_ldap_server_host(dut=data.dut1,server='IPV4 Address'use_type='pam',priority='5',
    ssl='start_tls',retry='3',config='no')

    Configure ldap sever details
    :param dut:
    :param server: <name|IPV4|IPV6 address>
    :param use_type: all|nss|sudo|pam (Default value is "all")
    :param port: 1-665535 (Default value is 389)
    :param priority: 1 - 99 (Default value is 1)
    :param ssl: on|off|start_tls (Default value is "off")
    :param retry: 1-10 (Default value is 0)
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    base_cmd = ''
    my_cmd = ''
    final_cmd = ''
    if cli_type == "klish":
        if 'server' in kwargs:
            st.log("in side server")
            base_cmd = '{} ldap-server host {}'.format(config_cmd, kwargs['server'])
        else:
            st.error("Mandatory arguments server should set to <name|IPV4|IPV6 address>")
            return False
        if config == 'yes':
            if 'use_type' in kwargs:
                my_cmd += '{} use-type {} \n'.format(base_cmd, kwargs['use_type'])
            if 'port' in kwargs:
                my_cmd += '{} port {} \n'.format(base_cmd, kwargs['port'])
            if 'priority' in kwargs:
                my_cmd += '{} priority {} \n'.format(base_cmd, kwargs['priority'])
            if 'ssl' in kwargs:
                my_cmd += '{} ssl {} \n'.format(base_cmd, kwargs['ssl'])
            if 'retry' in kwargs:
                my_cmd += '{} retry {} \n'.format(base_cmd, kwargs['retry'])
            final_cmd = my_cmd
        else:
            final_cmd = base_cmd
        st.config(dut, final_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url1 = rest_urls['ldap_server_global']
        url2 = rest_urls['ldap_server_delete'].format(kwargs['server'])
        if 'server' in kwargs:
            server_data = {"openconfig-system:server-group": [{"config": {"name": "LDAP"}, "name": "LDAP", "servers": \
                {"server": [{"openconfig-aaa-ldap-ext:ldap": {"config": {}}, "config": {"address": kwargs['server']}, \
                "address": kwargs['server']}]}}]}

            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_data, timeout = time_out):
                    st.error("Failed to configure ldap server {}".format(kwargs['server']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url2, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server {}".format(kwargs['server']))
                    return False
        else:
            st.error("Mandatory arguments server should set to <name|IPV4|IPV6 address>")
            return False
        if config == 'yes':
            type_data = {}
            temp_dict ={}
            server_dict ={}
            type_data['openconfig-system:server-group'] = []
            temp_dict['config'] = {'name': "LDAP"}
            temp_dict['name'] = "LDAP"
            temp_dict['servers'] = {}
            temp_dict['servers']['server'] = []
            server_dict['openconfig-aaa-ldap-ext:ldap'] = {}
            server_dict['openconfig-aaa-ldap-ext:ldap']['config'] = {}
            server_dict['address'] = kwargs['server']
            server_dict['config'] = {'address':kwargs['server']}
            if 'use_type' in kwargs:
                server_dict['openconfig-aaa-ldap-ext:ldap']['config']['use-type'] = kwargs['use_type']
            if 'port' in kwargs:
                server_dict['openconfig-aaa-ldap-ext:ldap']['config']['port'] = kwargs['port']
            if 'priority' in kwargs:
                server_dict['openconfig-aaa-ldap-ext:ldap']['config']['priority'] = kwargs['priority']
            if 'ssl' in kwargs:
                server_dict['openconfig-aaa-ldap-ext:ldap']['config']['ssl'] = kwargs['ssl']
            if 'retry' in kwargs:
                server_dict['openconfig-aaa-ldap-ext:ldap']['config']['retransmit-attempts'] = kwargs['retry']
            temp_dict['servers']['server'].append(server_dict)
            type_data['openconfig-system:server-group'].append(temp_dict)
            st.log(type_data)
            if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=type_data, timeout = time_out):
                st.error("Failed to configure ldap server params")
                return False
    return True

def config_ldap_server_global_attributes(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_ldap_server_global_attributes(dut=data.dut1,timelimit='30',bind_timelimit='10',idle_timelimit= '10',
    retry='2',port='400',scope='base',ldap_version='2',base_dn='dc=brcm,dc=com',ssl='on',
    bind_dn='cn=admin,dc=brcm,dc=com',bind_pwd='brcm123',config='yes')
    config_ldap_server_global_attributes(dut=data.dut1,timelimit='30',bind_timelimit='10',idle_timelimit= '10',
    retry='2',port='400',scope='base',ldap_version='2',base_dn='dc=brcm,dc=com',ssl='on',
    bind_dn='cn=admin,dc=brcm,dc=com',bind_pwd='brcm123',config='no')

    Configure ldap server attributes globally
    :param dut:
    :param timelimit: <0 - 65535> (Default value is 0 seconds)
    :param bind_timelimit: <0 - 65535> (Default value is 10 seconds)
    :param idle_timelimit: <0 - 65535> (Default value is 0 seconds)
    :param retry: 0-10 (Default value is 0)
    :param port: 0-665535 (Default value is 389)
    :param scope: sub|one|base (Default value is "sub")
    :param ldap_version: 2|3 (Default value is "3")
    :param base_dn: "dc=brcm,dc=com"
    :param ssl: on|off|start_tls (Default value is "off")
    :param bind_dn: "cn=admin,dc=brcm,dc=com"
    :param bind_pwd: "brcm123"
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'timelimit' in kwargs:
            my_cmd += '{} ldap-server timelimit {} \n'.format(config_cmd, kwargs['timelimit'])
        if 'bind_timelimit' in kwargs:
            my_cmd += '{} ldap-server bind-timelimit {} \n'.format(config_cmd, kwargs['bind_timelimit'])
        if 'idle_timelimit' in kwargs:
            my_cmd += '{} ldap-server idle-timelimit {} \n'.format(config_cmd, kwargs['idle_timelimit'])
        if 'retry' in kwargs:
            my_cmd += '{} ldap-server retry {} \n'.format(config_cmd, kwargs['retry'])
        if 'port' in kwargs:
            my_cmd += '{} ldap-server port {} \n'.format(config_cmd, kwargs['port'])
        if 'scope' in kwargs:
            my_cmd += '{} ldap-server scope {} \n'.format(config_cmd, kwargs['scope'])
        if 'ldap_version' in kwargs:
            my_cmd += '{} ldap-server version {} \n'.format(config_cmd, kwargs['ldap_version'])
        if 'base_dn' in kwargs:
            my_cmd += '{} ldap-server base {} \n'.format(config_cmd, kwargs['base_dn'])
        if 'ssl' in kwargs:
            my_cmd += '{} ldap-server ssl {} \n'.format(config_cmd, kwargs['ssl'])
        if 'bind_dn' in kwargs:
            my_cmd += '{} ldap-server binddn {} \n'.format(config_cmd, kwargs['bind_dn'])
        if 'bind_pwd' in kwargs:
            my_cmd += '{} ldap-server bindpw {} \n'.format(config_cmd, kwargs['bind_pwd'])
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if 'timelimit' in kwargs:
            url1 = rest_urls['ldap_server_time']
            server_time = {"openconfig-aaa-ldap-ext:search-time-limit": kwargs['timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_time, timeout = time_out):
                    st.error("Failed to configure ldap server search time limit {}".format(kwargs['timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server search time limit {}".format(kwargs['timelimit']))
                    return False
        if 'bind_timelimit' in kwargs:
            url1 = rest_urls['ldap_server_bindtime']
            server_bindtime = {"openconfig-aaa-ldap-ext:bind-time-limit": kwargs['bind_timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_bindtime, timeout = time_out):
                    st.error("Failed to configure ldap server bind time limit {}".format(kwargs['bind_timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server bind time limit {}".format(kwargs['bind_timelimit']))
                    return False
        if 'idle_timelimit' in kwargs:
            url1 = rest_urls['ldap_server_idletime']
            server_idletime = {"openconfig-aaa-ldap-ext:idle-time-limit": kwargs['idle_timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_idletime, timeout = time_out):
                    st.error("Failed to configure ldap server idle time limit {}".format(kwargs['idle_timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server idle time limit {}".format(kwargs['idle_timelimit']))
                    return False
        if 'retry' in kwargs:
            url1 = rest_urls['ldap_server_retry']
            server_retry = {"openconfig-aaa-ldap-ext:retransmit-attempts": kwargs['retry']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_retry, timeout = time_out):
                    st.error("Failed to configure ldap server retransmit attempt {}".format(kwargs['retry']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server retransmit attempt {}".format(kwargs['retry']))
                    return False
        if 'port' in kwargs:
            url1 = rest_urls['ldap_server_port']
            server_port = {"openconfig-aaa-ldap-ext:port": kwargs['port']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_port, timeout = time_out):
                    st.error("Failed to configure ldap server port {}".format(kwargs['port']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server port {}".format(kwargs['port']))
                    return False
        if 'scope' in kwargs:
            url1 = rest_urls['ldap_server_scope']
            server_scope = {"openconfig-aaa-ldap-ext:scope": kwargs['scope']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_scope, timeout = time_out):
                    st.error("Failed to configure ldap server scope {}".format(kwargs['scope']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server scope {}".format(kwargs['scope']))
                    return False
        if 'ldap_version' in kwargs:
            url1 = rest_urls['ldap_server_version']
            server_version = {"openconfig-aaa-ldap-ext:version": kwargs['ldap_version']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_version, timeout = time_out):
                    st.error("Failed to configure ldap server version {}".format(kwargs['ldap_version']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server version {}".format(kwargs['ldap_version']))
                    return False
        if 'base_dn' in kwargs:
            url1 = rest_urls['ldap_server_basedn']
            server_basedn = {"openconfig-aaa-ldap-ext:base": kwargs['base_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_basedn, timeout = time_out):
                    st.error("Failed to configure ldap server base DN {}".format(kwargs['base_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server base DN {}".format(kwargs['base_dn']))
                    return False
        if 'ssl' in kwargs:
            url1 = rest_urls['ldap_server_ssl']
            server_ssl = {"openconfig-aaa-ldap-ext:ssl": kwargs['ssl']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_ssl, timeout = time_out):
                    st.error("Failed to configure ldap server SSL {}".format(kwargs['ssl']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server SSL {}".format(kwargs['ssl']))
                    return False
        if 'bind_dn' in kwargs:
            url1 = rest_urls['ldap_server_binddn']
            server_binddn = {"openconfig-aaa-ldap-ext:bind-dn": kwargs['bind_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_binddn, timeout = time_out):
                    st.error("Failed to configure ldap server bind DN {}".format(kwargs['bind_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server bind DN {}".format(kwargs['bind_dn']))
                    return False
        if 'bind_pwd' in kwargs:
            url1 = rest_urls['ldap_server_bindpw']
            server_bindpwd = {"openconfig-aaa-ldap-ext:bind-pw": kwargs['bind_pwd']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_bindpwd, timeout = time_out):
                    st.error("Failed to configure ldap server bind password {}".format(kwargs['bind_pwd']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server bind password {}".format(kwargs['bind_pwd']))
                    return False
    return True

def config_ldap_server_pam_global_attributes(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_ldap_server_pam_global_attributes(dut=data.dut1,pam_filter='objectclass=posixAccount',pam_login-attribute='uid',\
    pam_group_dn= "cn=sudo,ou=Group,dc=brcm,dc=com",pam_member_attribute= "memberUid",config='yes')
    config_ldap_server_pam_global_attributes(dut=data.dut1,pam_filter='objectclass=posixAccount',pam_login-attribute='uid',\
    pam_group_dn= "cn=sudo,ou=Group,dc=brcm,dc=com",pam_member_attribute= "memberUid",config='no')


    Configure ldap server pam attributes globally
    :param dut:
    :param pam_filter='objectclass=posixAccount'
    :param pam_login_attribute='uid'
    :param pam_group_dn= "cn=sudo,ou=Group,dc=brcm,dc=com"
    :param pam_member_attribute= "memberUid"
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'pam_filter' in kwargs:
            my_cmd += '{} ldap-server pam-filter {} \n'.format(config_cmd, kwargs['pam_filter'])
        if 'pam_login_attribute' in kwargs:
            my_cmd += '{} ldap-server pam-login-attribute {} \n'.format(config_cmd, kwargs['pam_login_attribute'])
        if 'pam_group_dn' in kwargs:
            my_cmd += '{} ldap-server pam-group-dn {} \n'.format(config_cmd, kwargs['pam_group_dn'])
        if 'pam_member_attribute' in kwargs:
            my_cmd += '{} ldap-server pam-member-attribute {} \n'.format(config_cmd, kwargs['pam_member_attribute'])
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if 'pam_filter' in kwargs:
            url1 = rest_urls['ldap_server_pam_filter']
            server_pam_filter = {"openconfig-aaa-ldap-ext:pam-filter": kwargs['pam_filter']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_pam_filter, timeout = time_out):
                    st.error("Failed to configure ldap server pam filter {}".format(kwargs['pam_filter']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server pam filter {}".format(kwargs['pam_filter']))
                    return False
        if 'pam_login_attribute' in kwargs:
            url1 = rest_urls['ldap_server_pam_login_attri']
            server_pam_login_attri = {"openconfig-aaa-ldap-ext:pam-login-attribute": kwargs['pam_login_attribute']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_pam_login_attri, timeout = time_out):
                    st.error("Failed to configure ldap server pam login attribute {}".format(kwargs['pam_login_attribute']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server pam login attribute {}".format(kwargs['pam_login_attribute']))
                    return False
        if 'pam_group_dn' in kwargs:
            url1 = rest_urls['ldap_server_pam_groupdn']
            server_pam_login_groupdn = {"openconfig-aaa-ldap-ext:pam-group-dn": kwargs['pam_group_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_pam_login_groupdn, timeout = time_out):
                    st.error("Failed to configure ldap server pam group DN {}".format(kwargs['pam_group_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server pam group DN {}".format(kwargs['pam_group_dn']))
                    return False
        if 'pam_member_attribute' in kwargs:
            url1 = rest_urls['ldap_server_pam_mem_attri']
            server_pam_member_attri = {"openconfig-aaa-ldap-ext:pam-member-attribute": kwargs['pam_member_attribute']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_pam_member_attri, timeout = time_out):
                    st.error("Failed to configure ldap server pam member attribute {}".format(kwargs['pam_member_attribute']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server pam pam member attribute {}".format(kwargs['pam_member_attribute']))
                    return False
    return True

def config_ldap_server_nss_sudo_global_attributes(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_ldap_server_nss_sudo_global_attributes(dut=data.dut1,nss_base_passwd = "ou=People,dc=brcm,dc=com?one",\
    nss_base_group = "ou=Group,dc=brcm,dc=com?one",nss_base_shadow = "ou=People,dc=brcm,dc=com?one",\
    nss_base_netgroup = "ou=Netgroups,dc=brcm,dc=com?one",dc=com",nss_base_sudoers = "dc=Sudoers,dc-brcm,dc=com",\
    nss_initgroups_ignoreusers="user1,user2",sudoers_base= "dc=Sudoers,dc-brcm,dc=com",config='yes')

    config_ldap_server_nss_sudo_global_attributes(dut=data.dut1,nss_base_passwd = "ou=People,dc=brcm,dc=com?one",\
    nss_base_group = "ou=Group,dc=brcm,dc=com?one",nss_base_shadow = "ou=People,dc=brcm,dc=com?one",\
    nss_base_netgroup = "ou=Netgroups,dc=brcm,dc=com?one",dc=com",nss_base_sudoers = "dc=Sudoers,dc-brcm,dc=com",\
    nss_initgroups_ignoreusers="user1,user2",sudoers_base= "dc=Sudoers,dc-brcm,dc=com",config='no')


    Configure ldap server nss and sudo attributes globally
    :param dut:
    :param nss_base_passwd = "ou=People,dc=brcm,dc=com?one"
    :param nss_base_group = "ou=Group,dc=brcm,dc=com?one"
    :param nss_base_shadow = "ou=People,dc=brcm,dc=com?one"
    :param nss_base_netgroup = "ou=Netgroups,dc=brcm,dc=com?one"
    :param nss_base_sudoers = "dc=Sudoers,dc-brcm,dc=com"
    :param nss_initgroups_ignoreusers <list the user skip ldap search seperate by comma>
    :param sudoers_base= "dc=Sudoers,dc-brcm,dc=com"
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'nss_base_passwd' in kwargs:
            my_cmd += '{} ldap-server nss-base-passwd {} \n'.format(config_cmd, kwargs['nss_base_passwd'])
        if 'nss_base_group' in kwargs:
            my_cmd += '{} ldap-server nss-base-group {} \n'.format(config_cmd, kwargs['nss_base_group'])
        if 'nss_base_shadow' in kwargs:
            my_cmd += '{} ldap-server nss-base-shadow {} \n'.format(config_cmd, kwargs['nss_base_shadow'])
        if 'nss_base_netgroup' in kwargs:
            my_cmd += '{} ldap-server nss-base-netgroup {} \n'.format(config_cmd, kwargs['nss_base_netgroup'])
        if 'nss_base_sudoers' in kwargs:
            my_cmd += '{} ldap-server nss-base-sudoers {} \n'.format(config_cmd, kwargs['nss_base_sudoers'])
        if 'nss_initgroups_ignoreusers' in kwargs:
            my_cmd += '{} ldap-server nss-initgroups-ignoreusers {} \n'.format(config_cmd, kwargs['nss_initgroups_ignoreusers'])
        if 'sudoers_base' in kwargs:
            my_cmd += '{} ldap-server sudoers-base {} \n'.format(config_cmd, kwargs['sudoers_base'])
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url2 = rest_urls['ldap_server_group']
        ldap_sudo_parent = {"openconfig-system:server-groups":{"server-group":[{"name": "LDAP_SUDO", "config": {"name": "LDAP_SUDO"}}]}}
        if not config_rest(dut, http_method=cli_type, rest_url=url2, json_data=ldap_sudo_parent, timeout = time_out):
            st.error("Failed to configure ldap sudo server parent object")
            return False
        if 'nss_base_passwd' in kwargs:
            url1 = rest_urls['ldap_server_nss_basepwd']
            server_nss_basepwd = {"openconfig-aaa-ldap-ext:nss-base-passwd": kwargs['nss_base_passwd']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_basepwd, timeout = time_out):
                    st.error("Failed to configure ldap server NSS based password {}".format(kwargs['nss_base_passwd']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server NSS based password {}".format(kwargs['nss_base_passwd']))
                    return False
        if 'nss_base_group' in kwargs:
            url1 = rest_urls['ldap_server_nss_base_group']
            server_nss_basegrp = {"openconfig-aaa-ldap-ext:nss-base-group": kwargs['nss_base_group']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_basegrp, timeout = time_out):
                    st.error("Failed to configure ldap server NSS based group {}".format(kwargs['nss_base_group']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server NSS based group {}".format(kwargs['nss_base_group']))
                    return False
        if 'nss_base_shadow' in kwargs:
            url1 = rest_urls['ldap_server_nss_base_shadow']
            server_nss_baseshadow = {"openconfig-aaa-ldap-ext:nss-base-shadow": kwargs['nss_base_shadow']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_baseshadow, timeout = time_out):
                    st.error("Failed to configure ldap server NSS based shadow {}".format(kwargs['nss_base_shadow']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server NSS based shadow {}".format(kwargs['nss_base_shadow']))
                    return False
        if 'nss_base_netgroup' in kwargs:
            url1 = rest_urls['ldap_server_nss_base_netgroup']
            server_nss_bases_netgrp = {"openconfig-aaa-ldap-ext:nss-base-netgroup": kwargs['nss_base_netgroup']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_bases_netgrp, timeout = time_out):
                    st.error("Failed to configure ldap server NSS based net group {}".format(kwargs['nss_base_netgroup']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server NSS based net group {}".format(kwargs['nss_base_netgroup']))
                    return False
        if 'nss_base_sudoers' in kwargs:
            url1 = rest_urls['ldap_server_nss_base_sudoers']
            server_nss_bases_sudoers = {"openconfig-aaa-ldap-ext:nss-base-sudoers": kwargs['nss_base_sudoers']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_bases_sudoers, timeout = time_out):
                    st.error("Failed to configure ldap server NSS based sudoers {}".format(kwargs['nss_base_sudoers']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server NSS based sudoers {}".format(kwargs['nss_base_sudoers']))
                    return False
        if 'nss_initgroups_ignoreusers' in kwargs:
            url1 = rest_urls['ldap_server_nss_ignore_group']
            server_nss_initgrp_ignoreusr = {"openconfig-aaa-ldap-ext:nss-initgroups-ignoreusers": kwargs['nss_initgroups_ignoreusers']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_initgrp_ignoreusr, timeout = time_out):
                    st.error("Failed to configure ldap server NSS init Group ignore users {}".format(kwargs['nss_initgroups_ignoreusers']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server NSS init Group ignore users {}".format(kwargs['nss_initgroups_ignoreusers']))
                    return False
        if 'sudoers_base' in kwargs:
            url1 = rest_urls['ldap_server_sudoers_base']
            server_sudoer_base = {"openconfig-aaa-ldap-ext:sudoers-base": kwargs['sudoers_base']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_sudoer_base, timeout = time_out):
                    st.error("Failed to configure ldap server sudoer base {}".format(kwargs['sudoers_base']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server sudoer base {}".format(kwargs['sudoers_base']))
                    return False
    return True

def config_ldap_client_srcintf_vrf(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_ldap_client_srcintf_vrf(dut=data.dut1,port = "0/1",loopback = "1",
    management = "0",portchannel = "2",vlan = "10",vrf = "vrf_name",config='yes')
    config_ldap_client_srcintf_vrf(dut=data.dut1,port = "0/1",loopback = "1",
    management = "0",portchannel = "2",vlan = "10",vrf = "vrf_name",config='no')

    Configure ldap client ip address and vrf name
    :param dut:
    :param port
    :param loopback
    :param management
    :param portchannel
    :param vlan
    :param vrf
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'port' in kwargs:
            if config_cmd == '':
                port_cmd = 'Ethernet'
            else:
                port_cmd = ''
            my_cmd += '{} ldap-server source-interface {} {} \n'.format(config_cmd,port_cmd, kwargs['port'])
        if 'loopback' in kwargs:
            if config_cmd == '':
                loop_cmd = 'Loopback'
            else:
                loop_cmd = ''
            my_cmd += '{} ldap-server source-interface {} {} \n'.format(config_cmd,loop_cmd, kwargs['loopback'])
        if 'management' in kwargs:
            if config_cmd == '':
                mgmt_cmd = 'Management'
            else:
                mgmt_cmd = ''
            my_cmd += '{} ldap-server source-interface {} {} \n'.format(config_cmd,mgmt_cmd, kwargs['management'])
        if 'portchannel' in kwargs:
            if config_cmd == '':
                pchan_cmd = 'PortChannel'
            else:
                pchan_cmd = ''
            my_cmd += '{} ldap-server source-interface {} {} \n'.format(config_cmd,pchan_cmd, kwargs['portchannel'])
        if 'vlan' in kwargs:
            if config_cmd == '':
                vlan_cmd = 'Vlan'
            else:
                vlan_cmd = ''
            my_cmd += '{} ldap-server source-interface {} {} \n'.format(config_cmd,vlan_cmd, kwargs['vlan'])
        if 'vrf' in kwargs:
            my_cmd += '{} ldap-server vrf {} \n'.format(config_cmd, kwargs['vrf'])
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url1 = rest_urls['ldap_server_srcintf']
        if 'port' in kwargs:
            server_srcint_eth = {"openconfig-aaa-ldap-ext:source-interface": 'Ethernet'+kwargs['port']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_srcint_eth, timeout = time_out):
                    st.error("Failed to configure ldap server source interface Ethernet {}".format(kwargs['port']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server source interface Ethernet {}".format(kwargs['port']))
                    return False
        if 'loopback' in kwargs:
            server_srcint_loop = {"openconfig-aaa-ldap-ext:source-interface": 'Loopback'+kwargs['loopback']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_srcint_loop, timeout = time_out):
                    st.error("Failed to configure ldap server source interface loopback {}".format(kwargs['loopback']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server source interface loopback {}".format(kwargs['loopback']))
                    return False
        if 'management' in kwargs:
            server_srcint_mgmt = {"openconfig-aaa-ldap-ext:source-interface": 'eth'+kwargs['management']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_srcint_mgmt, timeout = time_out):
                    st.error("Failed to configure ldap server source interface mgmt eth {}".format(kwargs['management']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server source interface mgmt eth {}".format(kwargs['management']))
                    return False
        if 'vlan' in kwargs:
            server_srcint_vlan = {"openconfig-aaa-ldap-ext:source-interface": 'Vlan'+kwargs['vlan']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_srcint_vlan, timeout = time_out):
                    st.error("Failed to configure ldap server source interface vlan {}".format(kwargs['vlan']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server source interface vlan {}".format(kwargs['vlan']))
                    return False
        if 'portchannel' in kwargs:
            server_srcint_po = {"openconfig-aaa-ldap-ext:source-interface": 'PortChannel'+kwargs['portchannel']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_srcint_po, timeout = time_out):
                    st.error("Failed to configure ldap server source interface portchannel {}".format(kwargs['portchannel']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server source interface portchannel {}".format(kwargs['portchannel']))
                    return False
        if 'vrf' in kwargs:
            url2 = rest_urls['ldap_server_vrf']
            server_vrf = {"openconfig-aaa-ldap-ext:vrf-name": kwargs['vrf']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url2, json_data=server_vrf, timeout = time_out):
                    st.error("Failed to configure ldap server vrf {}".format(kwargs['vrf']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server vrf {}".format(kwargs['vrf']))
                    return False
    return True

def config_ldap_server_nss_specific_attributes(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com

    config_ldap_server_nss_specific_attributes(dut=data.dut1,timelimit='30',bind_timelimit='10',idle_timelimit= '10',\
    retry='2',port='400',scope='base',ldap_version='2',base_dn='dc=brcm,dc=com',ssl='on',\
    bind_dn='cn=admin,dc=brcm,dc=com',bind_pwd='brcm123',nss_base_passwd = "ou=People,dc=brcm,dc=com?one",\
    nss_base_group = "ou=Group,dc=brcm,dc=com?one",nss_base_shadow = "ou=People,dc=brcm,dc=com?one",\
    nss_base_netgroup = "ou=Netgroups,dc=brcm,dc=com?one",dc=com",nss_base_sudoers = "dc=Sudoers,dc-brcm,dc=com",\
    nss_initgroups_ignoreusers="user1,user2",config='yes')

    config_ldap_server_nss_specific_attributes(dut=data.dut1,timelimit='30',bind_timelimit='10',idle_timelimit= '10',\
    retry='2',port='400',scope='base',ldap_version='2',base_dn='dc=brcm,dc=com',ssl='on',\
    bind_dn='cn=admin,dc=brcm,dc=com',bind_pwd='brcm123',nss_base_passwd = "ou=People,dc=brcm,dc=com?one",\
    nss_base_group = "ou=Group,dc=brcm,dc=com?one",nss_base_shadow = "ou=People,dc=brcm,dc=com?one",\
    nss_base_netgroup = "ou=Netgroups,dc=brcm,dc=com?one",dc=com",nss_base_sudoers = "dc=Sudoers,dc-brcm,dc=com",\
    nss_initgroups_ignoreusers="user1,user2",config='no')


    Configure ldap server nss and sudo attributes globally
    :param dut:
    :param timelimit: <0 - 65535> (Default value is 0 seconds)
    :param bind_timelimit: <0 - 65535> (Default value is 10 seconds)
    :param idle_timelimit: <0 - 65535> (Default value is 0 seconds)
    :param retry: 0-10 (Default value is 0)
    :param port: 0-665535 (Default value is 389)
    :param scope: sub|one|base (Default value is "sub")
    :param ldap_version: 2|3 (Default value is "3")
    :param base_dn: "dc=brcm,dc=com"
    :param ssl: on|off|start_tls (Default value is "off")
    :param bind_dn: "cn=admin,dc=brcm,dc=com"
    :param bind_pwd: "brcm123"
    :param nss_base_passwd = "ou=People,dc=brcm,dc=com?one"
    :param nss_base_group = "ou=Group,dc=brcm,dc=com?one"
    :param nss_base_shadow = "ou=People,dc=brcm,dc=com?one"
    :param nss_base_netgroup = "ou=Netgroups,dc=brcm,dc=com?one"
    :param nss_base_sudoers = "dc=Sudoers,dc-brcm,dc=com"
    :param nss_initgroups_ignoreusers <list the user skip ldap search seperate by comma>
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'timelimit' in kwargs:
            my_cmd += '{} ldap-server nss timelimit {} \n'.format(config_cmd, kwargs['timelimit'])
        if 'bind_timelimit' in kwargs:
            my_cmd += '{} ldap-server nss bind-timelimit {} \n'.format(config_cmd, kwargs['bind_timelimit'])
        if 'idle_timelimit' in kwargs:
            my_cmd += '{} ldap-server nss idle-timelimit {} \n'.format(config_cmd, kwargs['idle_timelimit'])
        if 'retry' in kwargs:
            my_cmd += '{} ldap-server nss retry {} \n'.format(config_cmd, kwargs['retry'])
        if 'port' in kwargs:
            my_cmd += '{} ldap-server nss port {} \n'.format(config_cmd, kwargs['port'])
        if 'scope' in kwargs:
            my_cmd += '{} ldap-server nss scope {} \n'.format(config_cmd, kwargs['scope'])
        if 'ldap_version' in kwargs:
            my_cmd += '{} ldap-server nss version {} \n'.format(config_cmd, kwargs['ldap_version'])
        if 'base_dn' in kwargs:
            my_cmd += '{} ldap-server nss base {} \n'.format(config_cmd, kwargs['base_dn'])
        if 'ssl' in kwargs:
            my_cmd += '{} ldap-server nss ssl {} \n'.format(config_cmd, kwargs['ssl'])
        if 'bind_dn' in kwargs:
            my_cmd += '{} ldap-server nss binddn {} \n'.format(config_cmd, kwargs['bind_dn'])
        if 'bind_pwd' in kwargs:
            my_cmd += '{} ldap-server nss bindpw {} \n'.format(config_cmd, kwargs['bind_pwd'])
        if 'nss_base_passwd' in kwargs:
            my_cmd += '{} ldap-server nss nss-base-passwd {} \n'.format(config_cmd, kwargs['nss_base_passwd'])
        if 'nss_base_group' in kwargs:
            my_cmd += '{} ldap-server nss nss-base-group {} \n'.format(config_cmd, kwargs['nss_base_group'])
        if 'nss_base_shadow' in kwargs:
            my_cmd += '{} ldap-server nss nss-base-shadow {} \n'.format(config_cmd, kwargs['nss_base_shadow'])
        if 'nss_base_netgroup' in kwargs:
            my_cmd += '{} ldap-server nss nss-base-netgroup {} \n'.format(config_cmd, kwargs['nss_base_netgroup'])
        if 'nss_base_sudoers' in kwargs:
            my_cmd += '{} ldap-server nss nss-base-sudoers {} \n'.format(config_cmd, kwargs['nss_base_sudoers'])
        if 'nss_initgroups_ignoreusers' in kwargs:
            my_cmd += '{} ldap-server nss nss-initgroups-ignoreusers {} \n'.format(config_cmd, kwargs['nss_initgroups_ignoreusers'])
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url2 = rest_urls['ldap_server_group']
        ldap_nss_parent = {"openconfig-system:server-groups":{"server-group":[{"name": "LDAP_NSS", "config": {"name": "LDAP_NSS"}}]}}
        if not config_rest(dut, http_method=cli_type, rest_url=url2, json_data=ldap_nss_parent, timeout = time_out):
            st.error("Failed to configure ldap nss server parent object")
            return False
        if 'timelimit' in kwargs:
            url1 = rest_urls['ldap_nss_server_time']
            server_time = {"openconfig-aaa-ldap-ext:search-time-limit": kwargs['timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_time, timeout = time_out):
                    st.error("Failed to configure ldap nss server search time limit {}".format(kwargs['timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server search time limit {}".format(kwargs['timelimit']))
                    return False
        if 'bind_timelimit' in kwargs:
            url1 = rest_urls['ldap_nss_server_bindtime']
            server_bindtime = {"openconfig-aaa-ldap-ext:bind-time-limit": kwargs['bind_timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_bindtime, timeout = time_out):
                    st.error("Failed to configure ldap nss server bind time limit {}".format(kwargs['bind_timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server bind time limit {}".format(kwargs['bind_timelimit']))
                    return False
        if 'idle_timelimit' in kwargs:
            url1 = rest_urls['ldap_nss_server_idletime']
            server_idletime = {"openconfig-aaa-ldap-ext:idle-time-limit": kwargs['idle_timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_idletime, timeout = time_out):
                    st.error("Failed to configure ldap nss server idle time limit {}".format(kwargs['idle_timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server idle time limit {}".format(kwargs['idle_timelimit']))
                    return False
        if 'retry' in kwargs:
            url1 = rest_urls['ldap_nss_server_retry']
            server_retry = {"openconfig-aaa-ldap-ext:retransmit-attempts": kwargs['retry']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_retry, timeout = time_out):
                    st.error("Failed to configure ldap nss server retransmit attempt {}".format(kwargs['retry']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server retransmit attempt {}".format(kwargs['retry']))
                    return False
        if 'port' in kwargs:
            url1 = rest_urls['ldap_nss_server_port']
            server_port = {"openconfig-aaa-ldap-ext:port": kwargs['port']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_port, timeout = time_out):
                    st.error("Failed to configure ldap nss server port {}".format(kwargs['port']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server port {}".format(kwargs['port']))
                    return False
        if 'scope' in kwargs:
            url1 = rest_urls['ldap_nss_server_scope']
            server_scope = {"openconfig-aaa-ldap-ext:scope": kwargs['scope']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_scope, timeout = time_out):
                    st.error("Failed to configure ldap nss server scope {}".format(kwargs['scope']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server scope {}".format(kwargs['scope']))
                    return False
        if 'ldap_version' in kwargs:
            url1 = rest_urls['ldap_nss_server_version']
            server_version = {"openconfig-aaa-ldap-ext:version": kwargs['ldap_version']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_version, timeout = time_out):
                    st.error("Failed to configure ldap nss server version {}".format(kwargs['ldap_version']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap server version {}".format(kwargs['ldap_version']))
                    return False
        if 'base_dn' in kwargs:
            url1 = rest_urls['ldap_nss_server_basedn']
            server_basedn = {"openconfig-aaa-ldap-ext:base": kwargs['base_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_basedn, timeout = time_out):
                    st.error("Failed to configure ldap nss server base DN {}".format(kwargs['base_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server base DN {}".format(kwargs['base_dn']))
                    return False
        if 'ssl' in kwargs:
            url1 = rest_urls['ldap_nss_server_ssl']
            server_ssl = {"openconfig-aaa-ldap-ext:ssl": kwargs['ssl']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_ssl, timeout = time_out):
                    st.error("Failed to configure ldap nss server SSL {}".format(kwargs['ssl']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server SSL {}".format(kwargs['ssl']))
                    return False
        if 'bind_dn' in kwargs:
            url1 = rest_urls['ldap_nss_server_binddn']
            server_binddn = {"openconfig-aaa-ldap-ext:bind-dn": kwargs['bind_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_binddn, timeout = time_out):
                    st.error("Failed to configure ldap nss server bind DN {}".format(kwargs['bind_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server bind DN {}".format(kwargs['bind_dn']))
                    return False
        if 'bind_pwd' in kwargs:
            url1 = rest_urls['ldap_nss_server_bindpw']
            server_bindpwd = {"openconfig-aaa-ldap-ext:bind-pw": kwargs['bind_pwd']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_bindpwd, timeout = time_out):
                    st.error("Failed to configure ldap nss server bind password {}".format(kwargs['bind_pwd']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server bind password {}".format(kwargs['bind_pwd']))
                    return False
        if 'nss_base_passwd' in kwargs:
            url1 = rest_urls['ldap_nss_server_nss_basepwd']
            server_nss_basepwd = {"openconfig-aaa-ldap-ext:nss-base-passwd": kwargs['nss_base_passwd']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_basepwd, timeout = time_out):
                    st.error("Failed to configure ldap nss server NSS based password {}".format(kwargs['nss_base_passwd']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server NSS based password {}".format(kwargs['nss_base_passwd']))
                    return False
        if 'nss_base_group' in kwargs:
            url1 = rest_urls['ldap_nss_server_nss_base_group']
            server_nss_basegrp = {"openconfig-aaa-ldap-ext:nss-base-group": kwargs['nss_base_group']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_basegrp, timeout = time_out):
                    st.error("Failed to configure ldap nss server NSS based group {}".format(kwargs['nss_base_group']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server NSS based group {}".format(kwargs['nss_base_group']))
                    return False
        if 'nss_base_shadow' in kwargs:
            url1 = rest_urls['ldap_nss_server_nss_base_shadow']
            server_nss_baseshadow = {"openconfig-aaa-ldap-ext:nss-base-shadow": kwargs['nss_base_shadow']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_baseshadow, timeout = time_out):
                    st.error("Failed to configure ldap nss server NSS based shadow {}".format(kwargs['nss_base_shadow']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server NSS based shadow {}".format(kwargs['nss_base_shadow']))
                    return False
        if 'nss_base_netgroup' in kwargs:
            url1 = rest_urls['ldap_nss_server_nss_base_netgroup']
            server_nss_bases_netgrp = {"openconfig-aaa-ldap-ext:nss-base-netgroup": kwargs['nss_base_netgroup']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_bases_netgrp, timeout = time_out):
                    st.error("Failed to configure ldap nss server NSS based net group {}".format(kwargs['nss_base_netgroup']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server NSS based net group {}".format(kwargs['nss_base_netgroup']))
                    return False
        if 'nss_base_sudoers' in kwargs:
            url1 = rest_urls['ldap_nss_server_nss_base_sudoers']
            server_nss_bases_sudoers = {"openconfig-aaa-ldap-ext:nss-base-sudoers": kwargs['nss_base_sudoers']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_bases_sudoers, timeout = time_out):
                    st.error("Failed to configure ldap nss server NSS based sudoers {}".format(kwargs['nss_base_sudoers']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server NSS based sudoers {}".format(kwargs['nss_base_sudoers']))
                    return False
        if 'nss_initgroups_ignoreusers' in kwargs:
            url1 = rest_urls['ldap_nss_server_nss_ignore_group']
            server_nss_initgrp_ignoreusr = {"openconfig-aaa-ldap-ext:nss-initgroups-ignoreusers": kwargs['nss_initgroups_ignoreusers']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_nss_initgrp_ignoreusr, timeout = time_out):
                    st.error("Failed to configure ldap nss server NSS init Group ignore users {}".format(kwargs['nss_initgroups_ignoreusers']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1, timeout = time_out):
                    st.error("Failed to Unconfigure ldap nss server NSS init Group ignore users {}".format(kwargs['nss_initgroups_ignoreusers']))
                    return False
    return True

def config_ldap_server_pam_specific_attributes(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_ldap_server_pam_specific_attributes(dut=data.dut1,timelimit='30',bind_timelimit='10',idle_timelimit= '10',\
    retry='2',port='400',scope='base',ldap_version='2',base_dn='dc=brcm,dc=com',ssl='on',\
    bind_dn='cn=admin,dc=brcm,dc=com',bind_pwd='brcm123',pam_filter='objectclass=posixAccount',pam_login_attribute='uid',\
    pam_group_dn= "cn=sudo,ou=Group,dc=brcm,dc=com",pam_member_attribute= "memberUid",nss_base_passwd = "ou=People,dc=brcm,dc=com?one",config='yes')

    config_ldap_server_pam_specific_attributes(dut=data.dut1,timelimit='30',bind_timelimit='10',idle_timelimit= '10',\
    retry='2',port='400',scope='base',ldap_version='2',base_dn='dc=brcm,dc=com',ssl='on',\
    bind_dn='cn=admin,dc=brcm,dc=com',bind_pwd='brcm123',pam_filter='objectclass=posixAccount',pam_login_attribute='uid',\
    pam_group_dn= "cn=sudo,ou=Group,dc=brcm,dc=com",pam_member_attribute= "memberUid",nss_base_passwd = "ou=People,dc=brcm,dc=com?one",config='no')

    Configure ldap server pam attributes globally
    :param dut:
    :param timelimit: <0 - 65535> (Default value is 0 seconds)
    :param bind_timelimit: <0 - 65535> (Default value is 10 seconds)
    :param retry: 0-10 (Default value is 0)
    :param port: 0-665535 (Default value is 389)
    :param scope: sub|one|base (Default value is "sub")
    :param ldap_version: 2|3 (Default value is "3")
    :param base_dn: "dc=brcm,dc=com"
    :param ssl: on|off|start_tls (Default value is "off")
    :param bind_dn: "cn=admin,dc=brcm,dc=com"
    :param bind_pwd: "brcm123"
    :param pam_filter='objectclass=posixAccount'
    :param pam_login_attribute='uid'
    :param pam_group_dn= "cn=sudo,ou=Group,dc=brcm,dc=com"
    :param pam_member_attribute= "memberUid"
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'timelimit' in kwargs:
            my_cmd += '{} ldap-server pam timelimit {} \n'.format(config_cmd, kwargs['timelimit'])
        if 'bind_timelimit' in kwargs:
            my_cmd += '{} ldap-server pam bind-timelimit {} \n'.format(config_cmd, kwargs['bind_timelimit'])
        if 'retry' in kwargs:
            my_cmd += '{} ldap-server pam retry {} \n'.format(config_cmd, kwargs['retry'])
        if 'port' in kwargs:
            my_cmd += '{} ldap-server pam port {} \n'.format(config_cmd, kwargs['port'])
        if 'scope' in kwargs:
            my_cmd += '{} ldap-server pam scope {} \n'.format(config_cmd, kwargs['scope'])
        if 'ldap_version' in kwargs:
            my_cmd += '{} ldap-server pam version {} \n'.format(config_cmd, kwargs['ldap_version'])
        if 'base_dn' in kwargs:
            my_cmd += '{} ldap-server pam base {} \n'.format(config_cmd, kwargs['base_dn'])
        if 'ssl' in kwargs:
            my_cmd += '{} ldap-server pam ssl {} \n'.format(config_cmd, kwargs['ssl'])
        if 'bind_dn' in kwargs:
            my_cmd += '{} ldap-server pam binddn {} \n'.format(config_cmd, kwargs['bind_dn'])
        if 'bind_pwd' in kwargs:
            my_cmd += '{} ldap-server pam bindpw {} \n'.format(config_cmd, kwargs['bind_pwd'])
        if 'pam_filter' in kwargs:
            my_cmd += '{} ldap-server pam pam-filter {} \n'.format(config_cmd, kwargs['pam_filter'])
        if 'pam_login_attribute' in kwargs:
            my_cmd += '{} ldap-server pam pam-login-attribute {} \n'.format(config_cmd, kwargs['pam_login_attribute'])
        if 'pam_group_dn' in kwargs:
            my_cmd += '{} ldap-server pam pam-group-dn {} \n'.format(config_cmd, kwargs['pam_group_dn'])
        if 'pam_member_attribute' in kwargs:
            my_cmd += '{} ldap-server pam pam-member-attribute {} \n'.format(config_cmd, kwargs['pam_member_attribute'])
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url2 = rest_urls['ldap_server_group']
        ldap_pam_parent = {"openconfig-system:server-groups":{"server-group":[{"name": "LDAP_PAM", "config": {"name": "LDAP_PAM"}}]}}
        if not config_rest(dut, http_method=cli_type, rest_url=url2, json_data=ldap_pam_parent, timeout = time_out):
            st.error("Failed to configure ldap pam server parent object")
            return False
        if 'timelimit' in kwargs:
            url1 = rest_urls['ldap_pam_server_time']
            server_time = {"openconfig-aaa-ldap-ext:search-time-limit": kwargs['timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_time,timeout = time_out):
                    st.error("Failed to configure ldap pam server search time limit {}".format(kwargs['timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server search time limit {}".format(kwargs['timelimit']))
                    return False
        if 'bind_timelimit' in kwargs:
            url1 = rest_urls['ldap_pam_server_bindtime']
            server_bindtime = {"openconfig-aaa-ldap-ext:bind-time-limit": kwargs['bind_timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_bindtime,timeout = time_out):
                    st.error("Failed to configure ldap pam server bind time limit {}".format(kwargs['bind_timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server bind time limit {}".format(kwargs['bind_timelimit']))
                    return False
        if 'retry' in kwargs:
            url1 = rest_urls['ldap_pam_server_retry']
            server_retry = {"openconfig-aaa-ldap-ext:retransmit-attempts": kwargs['retry']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_retry,timeout = time_out):
                    st.error("Failed to configure ldap pam server retransmit attempt {}".format(kwargs['retry']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server retransmit attempt {}".format(kwargs['retry']))
                    return False
        if 'port' in kwargs:
            url1 = rest_urls['ldap_pam_server_port']
            server_port = {"openconfig-aaa-ldap-ext:port": kwargs['port']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_port,timeout = time_out):
                    st.error("Failed to configure ldap pam server port {}".format(kwargs['port']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server port {}".format(kwargs['port']))
                    return False
        if 'scope' in kwargs:
            url1 = rest_urls['ldap_pam_server_scope']
            server_scope = {"openconfig-aaa-ldap-ext:scope": kwargs['scope']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_scope,timeout = time_out):
                    st.error("Failed to configure ldap pam server scope {}".format(kwargs['scope']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server scope {}".format(kwargs['scope']))
                    return False
        if 'ldap_version' in kwargs:
            url1 = rest_urls['ldap_pam_server_version']
            server_version = {"openconfig-aaa-ldap-ext:version": kwargs['ldap_version']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_version,timeout = time_out):
                    st.error("Failed to configure ldap pam server version {}".format(kwargs['ldap_version']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server version {}".format(kwargs['ldap_version']))
                    return False
        if 'base_dn' in kwargs:
            url1 = rest_urls['ldap_pam_server_basedn']
            server_basedn = {"openconfig-aaa-ldap-ext:base": kwargs['base_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_basedn,timeout = time_out):
                    st.error("Failed to configure ldap pam server base DN {}".format(kwargs['base_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server base DN {}".format(kwargs['base_dn']))
                    return False
        if 'ssl' in kwargs:
            url1 = rest_urls['ldap_pam_server_ssl']
            server_ssl = {"openconfig-aaa-ldap-ext:ssl": kwargs['ssl']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_ssl,timeout = time_out):
                    st.error("Failed to configure ldap pam server SSL {}".format(kwargs['ssl']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server SSL {}".format(kwargs['ssl']))
                    return False
        if 'bind_dn' in kwargs:
            url1 = rest_urls['ldap_pam_server_binddn']
            server_binddn = {"openconfig-aaa-ldap-ext:bind-dn": kwargs['bind_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_binddn,timeout = time_out):
                    st.error("Failed to configure ldap pam server bind DN {}".format(kwargs['bind_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server bind DN {}".format(kwargs['bind_dn']))
                    return False
        if 'bind_pwd' in kwargs:
            url1 = rest_urls['ldap_pam_server_bindpw']
            server_bindpwd = {"openconfig-aaa-ldap-ext:bind-pw": kwargs['bind_pwd']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_bindpwd,timeout = time_out):
                    st.error("Failed to configure ldap pam server bind password {}".format(kwargs['bind_pwd']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server bind password {}".format(kwargs['bind_pwd']))
                    return False
        if 'pam_filter' in kwargs:
            url1 = rest_urls['ldap_pam_server_pam_filter']
            server_pam_filter = {"openconfig-aaa-ldap-ext:pam-filter": kwargs['pam_filter']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_pam_filter,timeout = time_out):
                    st.error("Failed to configure ldap pam server pam filter {}".format(kwargs['pam_filter']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server pam filter {}".format(kwargs['pam_filter']))
                    return False
        if 'pam_login_attribute' in kwargs:
            url1 = rest_urls['ldap_pam_server_pam_login_attri']
            server_pam_login_attri = {"openconfig-aaa-ldap-ext:pam-login-attribute": kwargs['pam_login_attribute']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_pam_login_attri,timeout = time_out):
                    st.error("Failed to configure ldap pam server pam login attribute {}".format(kwargs['pam_login_attribute']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server pam login attribute {}".format(kwargs['pam_login_attribute']))
                    return False
        if 'pam_group_dn' in kwargs:
            url1 = rest_urls['ldap_pam_server_pam_groupdn']
            server_pam_login_groupdn = {"openconfig-aaa-ldap-ext:pam-group-dn": kwargs['pam_group_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_pam_login_groupdn,timeout = time_out):
                    st.error("Failed to configure ldap pam server pam group DN {}".format(kwargs['pam_group_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server pam group DN {}".format(kwargs['pam_group_dn']))
                    return False
        if 'pam_member_attribute' in kwargs:
            url1 = rest_urls['ldap_pam_server_pam_mem_attri']
            server_pam_member_attri = {"openconfig-aaa-ldap-ext:pam-member-attribute": kwargs['pam_member_attribute']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_pam_member_attri,timeout = time_out):
                    st.error("Failed to configure ldap pam server pam member attribute {}".format(kwargs['pam_member_attribute']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap pam server pam member attribute {}".format(kwargs['pam_member_attribute']))
                    return False
    return True

def config_ldap_server_sudo_specific_attributes(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com

    config_ldap_server_sudo_specific_attributes(dut=data.dut1,timelimit='30',bind_timelimit='10',idle_timelimit= '10',\
    retry='2',port='400',scope='base',ldap_version='2',base_dn='dc=brcm,dc=com',ssl='on',\
    bind_dn='cn=admin,dc=brcm,dc=com',bind_pwd='brcm123',base_sudoers = "dc=Sudoers,dc-brcm,dc=com",config='yes')

    config_ldap_server_sudo_specific_attributes(dut=data.dut1,timelimit='30',bind_timelimit='10',idle_timelimit= '10',\
    retry='2',port='400',scope='base',ldap_version='2',base_dn='dc=brcm,dc=com',ssl='on',\
    bind_dn='cn=admin,dc=brcm,dc=com',bind_pwd='brcm123',base_sudoers = "dc=Sudoers,dc-brcm,dc=com",config='no')


    Configure ldap server nss and sudo attributes globally
    :param dut:
    :param timelimit: <0 - 65535> (Default value is 0 seconds)
    :param bind_timelimit: <0 - 65535> (Default value is 10 seconds)
    :param retry: 0-10 (Default value is 0)
    :param port: 0-665535 (Default value is 389)
    :param scope: sub|one|base (Default value is "sub")
    :param ldap_version: 2|3 (Default value is "3")
    :param base_dn: "dc=brcm,dc=com"
    :param ssl: on|off|start_tls (Default value is "off")
    :param bind_dn: "cn=admin,dc=brcm,dc=com"
    :param bind_pwd: "brcm123"
    :param base_sudoers = "dc=Sudoers,dc-brcm,dc=com"
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'timelimit' in kwargs:
            my_cmd += '{} ldap-server sudo timelimit {} \n'.format(config_cmd, kwargs['timelimit'])
        if 'bind_timelimit' in kwargs:
            my_cmd += '{} ldap-server sudo bind-timelimit {} \n'.format(config_cmd, kwargs['bind_timelimit'])
        if 'retry' in kwargs:
            my_cmd += '{} ldap-server sudo retry {} \n'.format(config_cmd, kwargs['retry'])
        if 'port' in kwargs:
            my_cmd += '{} ldap-server sudo port {} \n'.format(config_cmd, kwargs['port'])
        if 'scope' in kwargs:
            my_cmd += '{} ldap-server sudo scope {} \n'.format(config_cmd, kwargs['scope'])
        if 'ldap_version' in kwargs:
            my_cmd += '{} ldap-server sudo version {} \n'.format(config_cmd, kwargs['ldap_version'])
        if 'base_dn' in kwargs:
            my_cmd += '{} ldap-server sudo base {} \n'.format(config_cmd, kwargs['base_dn'])
        if 'ssl' in kwargs:
            my_cmd += '{} ldap-server sudo ssl {} \n'.format(config_cmd, kwargs['ssl'])
        if 'bind_dn' in kwargs:
            my_cmd += '{} ldap-server sudo binddn {} \n'.format(config_cmd, kwargs['bind_dn'])
        if 'bind_pwd' in kwargs:
            my_cmd += '{} ldap-server sudo bindpw {} \n'.format(config_cmd, kwargs['bind_pwd'])
        if 'base_sudoers' in kwargs:
            my_cmd += '{} ldap-server sudo sudoers-base {} \n'.format(config_cmd, kwargs['base_sudoers'])
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url2 = rest_urls['ldap_server_group']
        ldap_sudo_parent = {"openconfig-system:server-groups":{"server-group":[{"name": "LDAP_SUDO", "config": {"name": "LDAP_SUDO"}}]}}
        if not config_rest(dut, http_method=cli_type, rest_url=url2, json_data=ldap_sudo_parent, timeout = time_out):
            st.error("Failed to configure ldap sudo server parent object")
            return False
        if 'timelimit' in kwargs:
            url1 = rest_urls['ldap_sudo_server_time']
            server_time = {"openconfig-aaa-ldap-ext:search-time-limit": kwargs['timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_time,timeout = time_out):
                    st.error("Failed to configure ldap sudo server search time limit {}".format(kwargs['timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server search time limit {}".format(kwargs['timelimit']))
                    return False
        if 'bind_timelimit' in kwargs:
            url1 = rest_urls['ldap_sudo_server_bindtime']
            server_bindtime = {"openconfig-aaa-ldap-ext:bind-time-limit": kwargs['bind_timelimit']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_bindtime,timeout = time_out):
                    st.error("Failed to configure ldap sudo server bind time limit {}".format(kwargs['bind_timelimit']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server bind time limit {}".format(kwargs['bind_timelimit']))
                    return False
        if 'retry' in kwargs:
            url1 = rest_urls['ldap_sudo_server_retry']
            server_retry = {"openconfig-aaa-ldap-ext:retransmit-attempts": kwargs['retry']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_retry,timeout = time_out):
                    st.error("Failed to configure ldap sudo server retransmit attempt {}".format(kwargs['retry']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server retransmit attempt {}".format(kwargs['retry']))
                    return False
        if 'port' in kwargs:
            url1 = rest_urls['ldap_sudo_server_port']
            server_port = {"openconfig-aaa-ldap-ext:port": kwargs['port']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_port,timeout = time_out):
                    st.error("Failed to configure ldap sudo server port {}".format(kwargs['port']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server port {}".format(kwargs['port']))
                    return False
        if 'scope' in kwargs:
            url1 = rest_urls['ldap_sudo_server_scope']
            server_scope = {"openconfig-aaa-ldap-ext:scope": kwargs['scope']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_scope,timeout = time_out):
                    st.error("Failed to configure ldap sudo server scope {}".format(kwargs['scope']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server scope {}".format(kwargs['scope']))
                    return False
        if 'ldap_version' in kwargs:
            url1 = rest_urls['ldap_sudo_server_version']
            server_version = {"openconfig-aaa-ldap-ext:version": kwargs['ldap_version']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_version,timeout = time_out):
                    st.error("Failed to configure ldap sudo server version {}".format(kwargs['ldap_version']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server version {}".format(kwargs['ldap_version']))
                    return False
        if 'base_dn' in kwargs:
            url1 = rest_urls['ldap_sudo_server_basedn']
            server_basedn = {"openconfig-aaa-ldap-ext:base": kwargs['base_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_basedn,timeout = time_out):
                    st.error("Failed to configure ldap sudo server base DN {}".format(kwargs['base_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server base DN {}".format(kwargs['base_dn']))
                    return False
        if 'ssl' in kwargs:
            url1 = rest_urls['ldap_sudo_server_ssl']
            server_ssl = {"openconfig-aaa-ldap-ext:ssl": kwargs['ssl']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_ssl,timeout = time_out):
                    st.error("Failed to configure ldap sudo server SSL {}".format(kwargs['ssl']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server SSL {}".format(kwargs['ssl']))
                    return False
        if 'bind_dn' in kwargs:
            url1 = rest_urls['ldap_sudo_server_binddn']
            server_binddn = {"openconfig-aaa-ldap-ext:bind-dn": kwargs['bind_dn']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_binddn,timeout = time_out):
                    st.error("Failed to configure ldap sudo server bind DN {}".format(kwargs['bind_dn']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server bind DN {}".format(kwargs['bind_dn']))
                    return False
        if 'bind_pwd' in kwargs:
            url1 = rest_urls['ldap_sudo_server_bindpw']
            server_bindpwd = {"openconfig-aaa-ldap-ext:bind-pw": kwargs['bind_pwd']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_bindpwd,timeout = time_out):
                    st.error("Failed to configure ldap sudo server bind password {}".format(kwargs['bind_pwd']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1,timeout = time_out):
                    st.error("Failed to Unconfigure ldap sudo server bind password {}".format(kwargs['bind_pwd']))
                    return False
        if 'base_sudoers' in kwargs:
            url1 = rest_urls['ldap_server_sudoers_base']
            server_sudoer_base = {"openconfig-aaa-ldap-ext:sudoers-base": kwargs['base_sudoers']}
            if config == 'yes':
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=server_sudoer_base):
                    st.error("Failed to configure ldap sudo server sudoer base {}".format(kwargs['base_sudoers']))
                    return False
            else:
                if not delete_rest(dut, rest_url=url1):
                    st.error("Failed to Unconfigure ldap sudo server sudoer base {}".format(kwargs['base_sudoers']))
                    return False
    return True

def config_ldap_server_map_attributes(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com

    config_ldap_server_map_attributes(dut=data.dut1,key_list=[uid,shadowLastChange], \
    value_list=[sAMAccountName,pwdLastSet]config='yes')
    config_ldap_server_map_attributes(dut=data.dut1,key_list=[uid,shadowLastChange], \
    value_list=[sAMAccountName,pwdLastSet]config='no')

    Configure ldap server map attributes
    :param dut:
    :param key_list: [key1,key2,...]
    :param value_list: [value1,value2...]
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'key_list' in kwargs and 'value_list' in kwargs:
            for key, value in zip(kwargs['key_list'], kwargs['value_list']):
                my_cmd += '{} ldap-server map attribute {} to {}\n'.format(config_cmd, key, value)
        else:
            st.error("Mandatory arguments key_list and Value list should pass")
            return False
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if 'key_list' in kwargs and 'value_list' in kwargs:
            for key, value in zip(kwargs['key_list'], kwargs['value_list']):
                url1 = rest_urls['ldap_server_map_attribute'].format(key)
                attri_value = {"openconfig-aaa-ldap-ext:to": value}
                if config == 'yes':
                    if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=attri_value,timeout = time_out):
                        st.error("Failed to configure ldap server map attribute {} {}".format(key,value))
                        return False
                else:
                    if not delete_rest(dut, rest_url=url1):
                        st.error("Failed to Unconfigure ldap server map attribute {} {}".format(key,value))
                        return False
    return True

def config_ldap_server_map_objectclass(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com

    config_ldap_server_map_objectclass(dut=data.dut1,key_list=[posixAccount,shadowAccount], \
    value_list=[user,user]config='yes')
    config_ldap_server_map_objectclass(dut=data.dut1,key_list=[posixAccount,shadowAccount], \
    value_list=[user,user]config='no')


    Configure ldap server map objectClass
    :param dut:
    :param key_list: [key1,key2,...]
    :param value_list: [value1,value2...]
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'key_list' in kwargs and 'value_list' in kwargs:
            for key, value in zip(kwargs['key_list'], kwargs['value_list']):
                my_cmd += '{} ldap-server map objectclass {} to {}\n'.format(config_cmd, key, value)
        else:
            st.error("Mandatory arguments key_list and Value list should pass")
            return False
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if 'key_list' in kwargs and 'value_list' in kwargs:
            for key, value in zip(kwargs['key_list'], kwargs['value_list']):
                url1 = rest_urls['ldap_server_map_objectclass'].format(key)
                attri_value = {"openconfig-aaa-ldap-ext:to": value}
                if config == 'yes':
                    if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=attri_value,timeout = time_out):
                        st.error("Failed to configure ldap server map objectclass {} {}".format(key,value))
                        return False
                else:
                    if not delete_rest(dut, rest_url=url1):
                        st.error("Failed to Unconfigure ldap server map objectclass {} {}".format(key,value))
                        return False
    return True

def config_ldap_server_map_default_attribute_value(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com

    config_ldap_server_map_default_attribute_value(dut=data.dut1,key_list=[userShell], \
    value_list=["/bin/bash"],config='yes')
    config_ldap_server_map_default_attribute_value(dut=data.dut1,key_list=[userShell], \
    value_list=["/bin/bash"],config='no')


    Configure ldap server map default attribute value
    :param dut:
    :param key_list: [key1,key2,...]
    :param value_list: [value1,value2...]
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'key_list' in kwargs and 'value_list' in kwargs:
            for key, value in zip(kwargs['key_list'], kwargs['value_list']):
                my_cmd += '{} ldap-server map default-attribute-value {} to {}\n'.format(config_cmd, key, value)
        else:
            st.error("Mandatory arguments key_list and Value list should pass")
            return False
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if 'key_list' in kwargs and 'value_list' in kwargs:
            for key, value in zip(kwargs['key_list'], kwargs['value_list']):
                url1 = rest_urls['ldap_server_map_objectclass'].format(key)
                attri_value = {"openconfig-aaa-ldap-ext:to": value}
                if config == 'yes':
                    if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=attri_value,timeout = time_out):
                        st.error("Failed to configure ldap server map objectclass {} {}".format(key,value))
                        return False
                else:
                    if not delete_rest(dut, rest_url=url1):
                        st.error("Failed to Unconfigure ldap server map objectclass {} {}".format(key,value))
                        return False
    return True

def config_ldap_server_map_override_attribute_value(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com

    config_ldap_server_map_override_attribute_value(dut=data.dut1,key_list=[userShell], \
    value_list=["/bin/rbash"],config='yes')
    config_ldap_server_map_override_attribute_value(dut=data.dut1,key_list=[userShell], \
    value_list=["/bin/rbash"],config='no')


    Configure ldap server map override attribute value
    :param dut:
    :param key_list: [key1,key2,...]
    :param value_list: [value1,value2...]
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    my_cmd = ''
    if cli_type == "klish":
        if 'key_list' in kwargs and 'value_list' in kwargs:
            for key, value in zip(kwargs['key_list'], kwargs['value_list']):
                my_cmd += '{} ldap-server map default-attribute-value {} to {}\n'.format(config_cmd, key, value)
        else:
            st.error("Mandatory arguments key_list and Value list should pass")
            return False
        st.config(dut, my_cmd,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if 'key_list' in kwargs and 'value_list' in kwargs:
            for key, value in zip(kwargs['key_list'], kwargs['value_list']):
                url1 = rest_urls['ldap_server_map_override_attribute'].format(key)
                attri_value = {"openconfig-aaa-ldap-ext:to": value}
                if config == 'yes':
                    if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=attri_value,timeout = time_out):
                        st.error("Failed to configure ldap server map override attribute {} {}".format(key,value))
                        return False
                else:
                    if not delete_rest(dut, rest_url=url1):
                        st.error("Failed to Unconfigure ldap server map override attribute {} {}".format(key,value))
                        return False
    return True

def convert_ldap_rest_output(output1,output2,output3):
    transformed_output_list =[]
    for item in output2['server']:
        transformed_output = {}
        transformed_output['address'] = item.pop('address', '')
        transformed_output['use_type'] = item.get('openconfig-aaa-ldap-ext:ldap','').get('state','').get('use-type','')
        transformed_output['port'] = item.get('openconfig-aaa-ldap-ext:ldap','').get('state','').get('port','')
        transformed_output['ssl'] = item.get('openconfig-aaa-ldap-ext:ldap','').get('state','').get('ssl','')
        transformed_output['priority'] = item.get('openconfig-aaa-ldap-ext:ldap','').get('state','').get('priority','')
        transformed_output['retry'] = item.get('openconfig-aaa-ldap-ext:ldap','').get('state','').get('retransmit-attempts','')
        transformed_output['global_search_time_limit'] = output1.get('search-time-limit','')
        transformed_output['global_bind_time_limit'] = output1.get('bind-time-limit','')
        transformed_output['global_idle_time_limit'] = output1.get('idle-time-limit','')
        transformed_output['global_base_dn'] = output1.get('base','')
        transformed_output['global_bind_dn'] = output1.get('bind-dn','')
        transformed_output['global_bind_pw'] = output1.get('bind-pw','')
        transformed_output['global_pam_group_dn'] = output1.get('pam-group-dn','')
        transformed_output['global_pam_mem_attri'] = output1.get('pam-member-attribute','')
        transformed_output['global_sudoer_base'] = output3.get('sudoers-base','')
        transformed_output['global_port'] = output1.get('port','')
        transformed_output['global_retry'] = output1.get('retransmit-attempts','')
        transformed_output['global_scope'] = output1.get('scope','')
        transformed_output['global_ssl'] = output1.get('ssl','')
        transformed_output['global_ldap_version'] = output1.get('version','')
        transformed_output_list.append(transformed_output)
    return transformed_output_list

def verify_ldap_server_details(dut, **kwargs):
    """
    Author: Chandra Sekhar Reddy
    email : chandra.vedanaparthi@broadcom.com
    :param dut:
    :param global_base_dn:type string or list
    :param nss_base_dn:type string or list
    :param global_sudo_base_dn:type string or list
    :param nss_sudo_base_dn:type string or list
    :param pam_member_attribute:type string or list
    :param pam_groupdn:type string or list
    :param Address:type string or list
    :param use_type:type string or list
    :param Priority:type string or list
    :param ssl:type string or list
    :param retry:type string or list
    :return:

    Usage
    verify_ldap_server_details(dut1,global_base_dn=['dc=example,dc=com','dc=brcm,dc=com'],\
                                nss_base_dn=['dc=example,dc=com','dc=brcm,dc=com'],
                                global_sudo_base_dn=['ou=Sudoers,dc=example,dc=com','ou=Sudoers,dc=brcm,dc=com'],\
                                remote_port=['389','400'],\
                                global_sudo_base_dn=['ou=Sudoers,dc=example,dc=com','ou=Sudoers,dc=brcm,dc=com'],\
                                nss_sudo_base_dn=['ou=Sudoers,dc=example,dc=com','ou=Sudoers,dc=brcm,dc=com'],\
                                pam_member_attribute=['memberUid','memberUid'],\
                                pam_groupdn=['cn=docker,ou=Group,dc=example,dc=com','cn=docker,ou=Group,dc=brcm,dc=com'],\
                                Address=['10.59.143.229','10.59.143.230'],\
                                use_type=['all','nss'],\
                                Priority=['1','2'],\
                                ssl=['on,'start_tls'],\
                                retry=['1','2'])
    """
    ret_val = True
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    output = ''
    if cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url1 = rest_urls['show_ldap_server']
        rest_url2 = rest_urls['show_ldap_server_global']
        rest_url3 = rest_urls['show_ldap_server_sudo']
        output1 = get_rest(dut,rest_url=rest_url1)
        output2 = get_rest(dut,rest_url=rest_url2)
        output3 = get_rest(dut,rest_url=rest_url3)
        out1 = output1.get('output',{}).get('openconfig-aaa-ldap-ext:config',{})
        out2 = output2.get('output',{}).get('openconfig-system:servers',{})
        out3 = output3.get('output',{}).get('openconfig-aaa-ldap-ext:config',{})
        output = convert_ldap_rest_output(out1,out2,out3)
        st.log("output===================started")
        st.log(output)
        st.log("output===================End")
    else:
        cmd = 'show ldap-server'
        output = st.show(dut,cmd,type=cli_type,skip_error_check="True")
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    #Converting all kwargs to list type to handle single or list of ldap servers and its attributes
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
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False
    return ret_val

