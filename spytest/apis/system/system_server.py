import re
import traceback
from spytest import st

from utilities.utils import get_supported_ui_type_list
import utilities.common as cutils

try:
    import apis.yang.codegen.messages.system as umf_sys
    import apis.yang.codegen.messages.platform.Platform as umf_plat
    import apis.yang.codegen.messages.file_mgmt_private as umf_file_private
except ImportError:
    pass

# below  time_out is for Rest/Gnmi url timeout
time_out = 125


def config_system_properites(dut, **kwargs):
    st.log('config_system_properties kwargs: {}'.format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    if cli_type in get_supported_ui_type_list():
        sys_obj = umf_sys.System()
        sys_attr_list = {
            'time_zone': ['TimezoneName', kwargs.get('time_zone', None)],
        }
        for key, attr_value in sys_attr_list.items():
            if key in kwargs and attr_value[1] is not None:
                setattr(sys_obj, attr_value[0], attr_value[1])

        if 'resource_name' in kwargs:
            res_obj = umf_sys.Resource(Name=kwargs['resource_name'].upper())
            if 'flows' in kwargs:
                setattr(res_obj, 'Flows', kwargs['flows'].upper())
            sys_obj.add_Resource(res_obj)

        if 'username' in kwargs:
            user_attr_list = {}
            user_attr_list['password'] = ['Password', kwargs['password'] if 'password' in kwargs else None]
            user_attr_list['role'] = ['Role', kwargs['role'] if 'role' in kwargs else None]
            user_obj = umf_sys.User(Username=kwargs['username'])
            for key, attr_value in user_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(user_obj, attr_value[0], attr_value[1])
            setattr(user_obj, 'PasswordHashed', '')
            sys_obj.add_User(user_obj)

        if config == 'yes':
            result = sys_obj.configure(dut, cli_type=cli_type, timeout=time_out)
        else:
            target_attr_list = list()
            if 'username' in kwargs:
                result = user_obj.unConfigure(dut, cli_type=cli_type)
                # Current API doesnt support removing just role, so commenting this codeA
                '''
                for key, attr_value in user_attr_list.items():
                    if key in kwargs:
                        target_attr_list.append(getattr(user_obj, attr_value[0]))
                if target_attr_list:
                    result = user_obj.unConfigure(dut, target_attr=target_attr_list, cli_type=cli_type)
                else:
                    result = user_obj.unConfigure(dut, cli_type=cli_type)
                '''
            else:
                for key, attr_value in sys_attr_list.items():
                    if key in kwargs:
                        target_attr_list.append(getattr(sys_obj, attr_value[0]))

                if target_attr_list:
                    result = sys_obj.unConfigure(dut, target_attr=target_attr_list, cli_type=cli_type)
                else:
                    result = sys_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config System Properties {}'.format(result.message))
            return False

        return True
    else:
        st.error("Invalid UI type {}".format(cli_type))
        return False


def config_aaa_properties(dut, service_type, **kwargs):
    st.log('config_aaa_properties kwargs: {}'.format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    if cli_type in get_supported_ui_type_list():
        sys_obj = umf_sys.System()

        if service_type == 'authentication':
            aaa_attr_list = {
                'auth_method': ['AuthenticationMethod', kwargs.get('auth_method', None)],
                'failthrough': ['Failthrough', True if kwargs.get('failthrough') == 'enable' else False],
            }

            if kwargs.get('auth_method'):
                auth_method = kwargs['auth_method'].split(' ')
                aaa_attr_list['auth_method'] = ['AuthenticationMethod', auth_method]

        if service_type == 'authorization_login':
            aaa_attr_list = {
                'auth_method': ['LoginAuthorizationMethod', kwargs.get('auth_method', None)],
            }

            if kwargs.get('auth_method'):
                auth_method = kwargs['auth_method'].split(' ')
                aaa_attr_list['auth_method'] = ['LoginAuthorizationMethod', auth_method]

        if service_type == 'authorization_commands':
            aaa_attr_list = {
                'auth_method': ['CommandsAuthorizationMethod', kwargs.get('auth_method', None)],
            }

            if kwargs.get('auth_method'):
                auth_method = kwargs['auth_method'].split(' ')
                aaa_attr_list['auth_method'] = ['CommandsAuthorizationMethod', auth_method]

        if service_type == 'name-service':
            aaa_attr_list = {
                'passwd_method': ['PasswdMethod', kwargs.get('passwd_method', None)],
                'shadow_method': ['ShadowMethod', kwargs.get('shadow_method', None)],
                'group_method': ['GroupMethod', kwargs.get('group_method', None)],
                'netgroup_method': ['NetgroupMethod', kwargs.get('netgroup_method', None)],
                'sudoers_method': ['SudoersMethod', kwargs.get('sudoers_method', None)],
            }

        if config == 'yes':
            kwargs.pop('cli_type', '')
            for key, attr_value in aaa_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(sys_obj, attr_value[0], attr_value[1])
            result = sys_obj.configure(dut, cli_type=cli_type, timeout=time_out, **kwargs)
            if not result.ok():
                st.log('test_step_failed: Config AAA Properties {}'.format(result.data))
                return False
        return True
    else:
        st.error("Invalid UI type {}".format(cli_type))
        return False


def config_system_server_properties(dut, server_name, **kwargs):
    st.log('config_system_server_properties kwargs: {}'.format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    if cli_type in get_supported_ui_type_list():
        sys_obj = umf_sys.System()
        server_name = server_name.upper()
        if server_name == 'SSH-SERVER':
            vrf_name = kwargs['vrf_name']
            server_obj = umf_sys.SshServerVrf(VrfName=vrf_name)
            if 'port' in kwargs:
                setattr(server_obj, 'Port', int(kwargs['port']))
            sys_obj.add_SshServerVrf(server_obj)
            if config == 'yes':
                result = sys_obj.configure(dut, cli_type=cli_type, **kwargs)
            else:
                result = server_obj.unConfigure(dut, cli_type=cli_type, **kwargs)

            if not result.ok():
                st.log('test_step_failed: Config SSH Server Properties {}'.format(result.message))
                return False
            return True
        if server_name == 'LOGGING-SERVER':
            log_server_obj = umf_sys.RemoteServer(Host=str(kwargs['server_address']))
            server_attr_list = {
                'src_intf': ['SourceInterface', str(kwargs.get('src_intf', None))],
                'vrf_name': ['VrfName', kwargs.get('vrf_name', None)],
                'remote_port': ['RemotePort', int(kwargs['remote_port']) if 'remote_port' in kwargs else None],
                'message_type': ['MessageType', kwargs.get('message_type', None)]
            }
            if 'severity' in kwargs:
                if kwargs['severity'] == 'info':
                    kwargs['severity'] = 'informational'
                setattr(log_server_obj, 'Severity', kwargs['severity'].upper())
            if config == 'yes':
                for key, attr_value in server_attr_list.items():
                    if key in kwargs and attr_value[1] is not None:
                        setattr(log_server_obj, attr_value[0], attr_value[1])
                sys_obj.add_RemoteServer(log_server_obj)
                result = sys_obj.configure(dut, cli_type=cli_type, **kwargs)
            else:
                result = log_server_obj.unConfigure(dut, cli_type=cli_type, **kwargs)

            if not result.ok():
                st.log('test_step_failed: Config Logging Server Properties {}'.format(result.message))
                return False
            return True

        if server_name == 'NTP-SERVER':
            server_attr_list = {
                'src_intf': ['NtpSourceInterface', kwargs.get('src_intf', None)],
                'vrf_name': ['NetworkInstance', kwargs.get('vrf_name', None)],
                'enable_auth': ['EnableNtpAuth', True if 'enable_auth' in kwargs else False],
                'trusted_key': ['TrustedKey', int(kwargs['trusted_key']) if 'trusted_key' in kwargs else None],
            }

            for key, attr_value in server_attr_list.items():
                if config == 'yes':
                    if key in kwargs and attr_value[1] is not None:
                        setattr(sys_obj, attr_value[0], attr_value[1])
                else:
                    if key in kwargs:
                        target_attr = getattr(sys_obj, attr_value[0])
                        result = sys_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type, **kwargs)

            if 'server_address' in kwargs:
                server_obj = umf_sys.NtpServer(Address=kwargs['server_address'])
                if kwargs.get('prefer'):
                    setattr(server_obj, 'Prefer', kwargs.get('prefer'))
                if kwargs.get('minpoll') and kwargs.get('maxpoll'):
                    setattr(server_obj, 'Minpoll', int(kwargs['minpoll']))
                    setattr(server_obj, 'Maxpoll', int(kwargs['maxpoll']))
                if kwargs.get('server_key'):
                    setattr(server_obj, 'KeyId', int(kwargs['server_key']))
                sys_obj.add_NtpServer(server_obj)
                if config != 'yes':
                    result = server_obj.unConfigure(dut, cli_type=cli_type, **kwargs)
            if 'auth_key_id' in kwargs:
                keymap = {"md5": "NTP_AUTH_MD5", 'sha1': 'NTP_AUTH_SHA1', 'sha2-256': 'NTP_AUTH_SHA2_256'}
                ntp_key_obj = umf_sys.NtpKey(KeyId=int(kwargs['auth_key_id']))
                if kwargs.get('auth_type') and kwargs.get('auth_string'):
                    setattr(ntp_key_obj, 'KeyType', keymap[kwargs['auth_type']])
                    setattr(ntp_key_obj, 'KeyValue', kwargs['auth_string'])
                sys_obj.add_NtpKey(ntp_key_obj)
                if config != 'yes':
                    result = ntp_key_obj.unConfigure(dut, cli_type=cli_type, **kwargs)

            if config == 'yes':
                result = sys_obj.configure(dut, cli_type=cli_type, **kwargs)

            if not result.ok():
                st.log('test_step_failed: Config NTP Server Properties {}'.format(result.message))
                return False

            return True


def config_aaa_server_properties(dut, server_name, **kwargs):
    st.log('config_aaa_server_properties kwargs: {}'.format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    if cli_type in get_supported_ui_type_list():
        sys_obj = umf_sys.System()
        server_name = server_name.upper()
        server_group_obj = umf_sys.ServerGroup(Name=server_name)
        timeout = kwargs.get('timeout', None)  # timeout is for radius feature timeout
        server_gbl_attr_list = {
            'auth_type': ['AuthType', kwargs.get('auth_type', None)],
            'key': ['SecretKey', kwargs.get('key', None)],
            'encrypted': ['ServerGroupEncrypted', True if 'encrypted' in kwargs else False],
            'timeout': ['Timeout', int(timeout) if timeout else None],
            'src_intf': ['SourceInterface', kwargs.get('src_intf', None)],
        }
        if server_name == 'RADIUS':
            server_gbl_attr_list['nas_ip'] = ['NasIpAddress', kwargs['nas_ip'] if 'nas_ip' in kwargs else None]
            server_gbl_attr_list['statistics'] = ['Statistics', int(kwargs['statistics']) if 'statistics' in kwargs else None]
            server_gbl_attr_list['retransmit'] = ['RadiusRetransmitAttempts', int(kwargs['retransmit']) if 'retransmit' in kwargs else None]

        if server_name in ['LDAP', 'LDAP_NSS', 'LDAP_PAM']:
            server_gbl_attr_list['vrf_name'] = ['VrfName', kwargs['vrf_name'] if 'vrf_name' in kwargs else None]
            server_gbl_attr_list['timelimit'] = ['SearchTimeLimit', int(kwargs['timelimit']) if 'timelimit' in kwargs and kwargs['timelimit'] != '' else None]
            server_gbl_attr_list['bind_timelimit'] = ['BindTimeLimit', int(kwargs['bind_timelimit']) if 'bind_timelimit' in kwargs and kwargs['bind_timelimit'] != '' else None]
            server_gbl_attr_list['retry'] = ['LdapRetransmitAttempts', int(kwargs['retry']) if 'retry' in kwargs and kwargs['retry'] != '' else None]
            server_gbl_attr_list['port'] = ['Port', kwargs['port'] if 'port' in kwargs else None]
            server_gbl_attr_list['ldap_version'] = ['Version', int(kwargs['ldap_version']) if 'ldap_version' in kwargs and kwargs['ldap_version'] != '' else None]
            server_gbl_attr_list['base_dn'] = ['Base', kwargs['base_dn'] if 'base_dn' in kwargs else None]
            server_gbl_attr_list['ssl'] = ['Ssl', kwargs['ssl'] if 'ssl' in kwargs else None]
            server_gbl_attr_list['bind_dn'] = ['BindDn', kwargs['bind_dn'] if 'bind_dn' in kwargs else None]
            server_gbl_attr_list['bind_pwd'] = ['BindPw', kwargs['bind_pwd'] if 'bind_pwd' in kwargs else None]
            server_gbl_attr_list['ldap_encrypted'] = ['LdapEncrypted', True if 'ldap_encrypted' in kwargs else False]
            server_gbl_attr_list['idle_timelimit'] = ['IdleTimeLimit', int(kwargs['idle_timelimit']) if 'idle_timelimit' in kwargs and kwargs['idle_timelimit'] != '' else None]
            server_gbl_attr_list['scope'] = ['Scope', kwargs['scope'] if 'scope' in kwargs else None]
            server_gbl_attr_list['nss_base_group'] = ['NssBaseGroup', kwargs['nss_base_group'] if 'nss_base_group' in kwargs else None]
            server_gbl_attr_list['nss_base_passwd'] = ['NssBasePasswd', kwargs['nss_base_passwd'] if 'nss_base_passwd' in kwargs else None]
            server_gbl_attr_list['nss_base_shadow'] = ['NssBaseShadow', kwargs['nss_base_shadow'] if 'nss_base_shadow' in kwargs else None]
            server_gbl_attr_list['nss_base_netgroup'] = ['NssBaseNetgroup', kwargs['nss_base_netgroup'] if 'nss_base_netgroup' in kwargs else None]
            server_gbl_attr_list['nss_base_sudoers'] = ['NssBaseSudoers', kwargs['nss_base_sudoers'] if 'nss_base_sudoers' in kwargs else None]
            server_gbl_attr_list['nss_initgroups_ignoreusers'] = ['NssInitgroupsIgnoreusers', kwargs['nss_initgroups_ignoreusers'] if 'nss_initgroups_ignoreusers' in kwargs else None]
            server_gbl_attr_list['pam_filter'] = ['PamFilter', kwargs['pam_filter'] if 'pam_filter' in kwargs else None]
            server_gbl_attr_list['pam_login_attribute'] = ['PamLoginAttribute', kwargs['pam_login_attribute'] if 'pam_login_attribute' in kwargs else None]
            server_gbl_attr_list['pam_group_dn'] = ['PamGroupDn', kwargs['pam_group_dn'] if 'pam_group_dn' in kwargs else None]
            server_gbl_attr_list['pam_member_attribute'] = ['PamMemberAttribute', kwargs['pam_member_attribute'] if 'pam_member_attribute' in kwargs else None]
            server_gbl_attr_list['sudoers_base'] = ['SudoersBase', kwargs['sudoers_base'] if 'sudoers_base' in kwargs else None]
            server_gbl_attr_list['nss_skip_members'] = ['NssSkipmembers', kwargs['nss_skip_members'] if 'nss_skip_members' in kwargs else None]

        if config in ['yes', 'verify']:
            for key, attr_value in server_gbl_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(server_group_obj, attr_value[0], attr_value[1])
            kwargs.pop('timeout', None)
            if config == 'yes':
                sys_obj.add_ServerGroup(server_group_obj)
                result = sys_obj.configure(dut, cli_type=cli_type, timeout=time_out, **kwargs)
            elif config == 'verify':
                depth = kwargs.get("depth", 3)
                filter_type = kwargs.get('filter_type', 'NON_CONFIG')
                query_params_obj = cutils.get_query_params(yang_data_type=filter_type, depth=depth, cli_type=cli_type)
                result = server_group_obj.verify(dut, query_param=query_params_obj, match_subset=True, cli_type=cli_type)
        else:
            target_attr_list = list()
            for key, attr_value in server_gbl_attr_list.items():
                if key in kwargs:
                    target_attr_list.append(getattr(server_group_obj, attr_value[0]))
            kwargs.pop('timeout', None)
            result = server_group_obj.unConfigure(dut, target_attr=target_attr_list, cli_type=cli_type, timeout=time_out, **kwargs)
        if not result.ok():
            st.log('test_step_failed: Config Radius Server {}'.format(result.data))
            return False

        return True
    else:
        st.error("Invalid UI type {}".format(cli_type))
        return False


def config_aaa_server(dut, server_name, server_address, **kwargs):
    st.log('config_aaa_server kwargs: {}'.format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    if cli_type in get_supported_ui_type_list():
        sys_obj = umf_sys.System()
        server_name = server_name.upper()
        server_group_obj = umf_sys.ServerGroup(Name=server_name)
        server_obj = umf_sys.ServerGroupServer(Address=server_address)
        timeout = kwargs.get('timeout', None)  # timeout is for radius feature timeout
        server_attr_list = {
            'timeout': ['Timeout', int(timeout) if timeout else None],
            'auth_type': ['AuthType', kwargs.get('auth_type', None)],
            'priority': ['ServerPriority', int(kwargs['priority']) if 'priority' in kwargs else None],
            'vrf': ['Vrf', kwargs.get('vrf', None)],
        }

        if server_name == 'RADIUS':
            server_attr_list['auth_port'] = ['AuthPort', int(kwargs['auth_port']) if 'auth_port' in kwargs else None]
            server_attr_list['acct_port'] = ['AcctPort', int(kwargs['acct_port']) if 'acct_port' in kwargs else None]
            server_attr_list['key'] = ['RadiusSecretKey', kwargs.get('key', None)]
            server_attr_list['encrypted'] = ['RadiusEncrypted', True if 'encrypted' in kwargs else False]
            server_attr_list['src_intf'] = ['SourceInterface', kwargs.get('src_intf', None)]
            server_attr_list['retransmit'] = ['RadiusRetransmitAttempts', int(kwargs['retransmit']) if 'retransmit' in kwargs else None]

        if server_name == 'TACACS':
            server_attr_list['auth_port'] = ['TacacsPort', int(kwargs['auth_port']) if 'auth_port' in kwargs else None]
            server_attr_list['key'] = ['TacacsSecretKey', kwargs.get('key', None)]
            server_attr_list['encrypted'] = ['TacacsEncrypted', True if 'encrypted' in kwargs else False]

        if server_name == 'LDAP':
            server_attr_list['use_type'] = ['UseType', kwargs.get('use_type', None)]
            server_attr_list['ldap_port'] = ['LdapPort', int(kwargs['ldap_port']) if 'ldap_port' in kwargs else None]
            server_attr_list['ldap_priority'] = ['LdapPriority', int(kwargs['ldap_priority']) if 'ldap_priority' in kwargs else None]
            server_attr_list['ssl'] = ['Ssl', kwargs['ssl'] if 'ssl' in kwargs else None]
            server_attr_list['ldap_retransmit'] = ['LdapRetransmitAttempts', int(kwargs['ldap_retransmit']) if 'ldap_retransmit' in kwargs else None]

        server_group_obj.add_ServerGroupServer(server_obj)
        sys_obj.add_ServerGroup(server_group_obj)

        if config in ['yes', 'verify']:
            for key, attr_value in server_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(server_obj, attr_value[0], attr_value[1])
                kwargs.pop('timeout', None)
            if config == 'yes':
                result = sys_obj.configure(dut, cli_type=cli_type, timeout=time_out, **kwargs)
            elif config == 'verify':
                st.log('Inside verify')
                depth = kwargs.get("depth", 3)
                filter_type = kwargs.get('filter_type', 'ALL')
                query_params_obj = cutils.get_query_params(yang_data_type=filter_type, depth=depth, cli_type=cli_type)
                result = server_obj.verify(dut, query_param=query_params_obj, match_subset=True, cli_type=cli_type)
        else:
            target_attr_list = list()
            for key, attr_value in server_attr_list.items():
                if key in kwargs:
                    target_attr_list.append(getattr(server_obj, attr_value[0]))
                kwargs.pop('timeout', None)
            if len(target_attr_list) == 0:
                result = server_obj.unConfigure(dut, cli_type=cli_type, timeout=time_out, **kwargs)
            else:
                result = server_obj.unConfigure(dut, target_attr=target_attr_list, cli_type=cli_type, timeout=time_out, **kwargs)
        if not result.ok():
            st.log('test_step_failed: Config Radius Server {}'.format(result.data))
            return False

        return True
    else:
        st.error("Invalid UI type {}".format(cli_type))
        return False


def verify_rsyslog_server(dut, **kwargs):
    st.log('verify_rsyslog_server kwargs: {}'.format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = cutils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        sys_obj = umf_sys.RemoteServer(Host=kwargs['host'])
        rsyslog_attr_list = {
            'srcintf': ['SourceInterface', kwargs.get('srcintf', None)],
            'remote_port': ['RemotePort', kwargs.get('remote_port', None)],
            'vrf': ['VrfName', kwargs.get('vrf', None)],
            'msgtype': ['MessageType', kwargs.get('msgtype', None)]}
        if 'severity' in kwargs:
            if kwargs['severity'] == 'info':
                kwargs['severity'] = 'informational'
            setattr(sys_obj, 'Severity', kwargs['severity'].upper())
        for key, attr_value in rsyslog_attr_list.items():
            if key in kwargs and attr_value[1] is not None:
                setattr(sys_obj, attr_value[0], attr_value[1])
        st.log('***IETF_JSON***: {}'.format(sys_obj.get_ietf_json()))
        result = sys_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verification of VRRP state {}'.format(result.data))
            return False
        return True
    else:
        st.error("Invalid UI type {}".format(cli_type))
        return False


def system_show_version(dut, **kwargs):
    st.log('system_show_version kwargs: {}'.format(kwargs))
    report = kwargs.get('report', True)
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        try:
            plat_obj = umf_plat.Component(Name='SoftwareModule')
            result = plat_obj.get_payload(dut, cli_type=cli_type, timeout=time_out)
            if not result.ok():
                st.log('test_step_failed: Failed to read version on: {}'.format(dut))
                cli_type = 'click'
            else:
                output = result.payload
                version = output['openconfig-platform:component'][0]['software-module']['state']
                ret_version = {}
                ret_version.update({'version': version['openconfig-platform-software-ext:software-version']})
                ret_version.update({'product': version['openconfig-platform-software-ext:product-description']})
                ret_version.update({'kernel': version['openconfig-platform-software-ext:kernel-version']})
                ret_version.update({'db_version': version['openconfig-platform-software-ext:config-db-version']})
                ret_version.update({'distribution': version['openconfig-platform-software-ext:distribution-version']})
                ret_version.update({'build_commit': version['openconfig-platform-software-ext:build-commit']})
                ret_version.update({'build_date': version['openconfig-platform-software-ext:build-date']})
                ret_version.update({'built_by': version['openconfig-platform-software-ext:built-by']})
                ret_version.update({'platform': version['openconfig-platform-software-ext:platform-name']})
                ret_version.update({'hwsku': version['openconfig-platform-software-ext:hwsku-version']})
                ret_version.update({'asic': version['openconfig-platform-software-ext:asic-version']})
                ret_version.update({'hw_version': version['openconfig-platform-software-ext:hardware-version']})
                ret_version.update({'serial_number': version['openconfig-platform-software-ext:serial-number']})
                ret_version.update({'mfg': version['openconfig-platform-software-ext:mfg-name']})

                out = re.findall(r'(.*),\s+(\d+)\s+\S+,\s+load average:\s+(.*)\s*', version['openconfig-platform-software-ext:up-time'])
                if out and len(out[0]) == 3:
                    ret_version.update({"uptime": out[0][0]})
                    ret_version.update({"load_average": out[0][2]})
                    ret_version.update({"user": out[0][1]})

                # ret_version = {k: v.replace("'", '').strip() for k, v in ret_version.items()}
                return ret_version
        except Exception as e:
            st.error('Failed to read version on: {}'.format(dut))
            st.error(e)
            traceback.print_exc()
            cli_type = 'click'

    if cli_type in ['click', 'klish']:
        command = 'show version'
        output = st.show(dut, command, type=cli_type, **kwargs)
        if not output:
            st.error("Failed to read version", dut=dut)
            if cli_type in ['klish']:
                output = st.show(dut, command, type='click', **kwargs)
                if not output:
                    st.error("Failed to read version even from click", dut=dut)
            if not output:
                if report:
                    st.report_fail("version_data_not_found", dut)
                return {}
        exclude_keys = ['repository', 'tag', 'image_id', 'size']
        rv = {each_key: output[0][each_key] for each_key in output[0] if each_key not in exclude_keys}
        return rv


def verify_reload_stats(dut, **kwargs):
    st.log('system_verify_reload kwargs: {}'.format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    return_flag = True
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    file_obj = umf_file_private.ConfigReload()
    query_params_obj = cutils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
    out = file_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
    if not out.ok():
        st.log("test_step_failed: config-reload stats output is not showing")
    output = process_file_output(out.payload)
    return_output = kwargs.pop('return_output', False)

    st.log("output={}, kwargs={}".format(output, kwargs))
    if return_output:
        return output

    for key in ['cli_type', 'skip_template', 'return_output', 'skip_error']:
        kwargs.pop(key, None)

    if output == []:
        output = [{}]
    for key in kwargs.keys():
        if key in output[0]:
            if kwargs[key] != output[0][key]:
                st.error(
                    "key: {} Input value: {}, Output value: {} are not same".format(key, kwargs[key], output[0][key]))
                return_flag = False
            else:
                st.log('Found for key: {}, val:{}'.format(key, kwargs[key]))
        else:
            st.error("{} not found in the output.".format(key))
            return_flag = False
    return return_flag


def process_file_output(data):
    """
    Api to process the gnmi/rest output
    :param payload:
    :return:
    """
    retval = []
    if data.get("openconfig-file-mgmt-private:config-reload") and isinstance(data["openconfig-file-mgmt-private:config-reload"], dict):
        file_info = data["openconfig-file-mgmt-private:config-reload"]['state']
        temp = dict()
        temp['state'] = file_info['state']
        temp['statedetail'] = file_info['state-detail']
        temp['starttime'] = file_info['start-time']
        temp['endtime'] = file_info['end-time']
        retval.append(temp)
    else:
        st.log("output is not found: {}".format(data))
        return False
    st.debug(retval)
    return retval
