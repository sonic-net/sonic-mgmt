from spytest import st
from utilities.utils import get_supported_ui_type_list
from utilities.common import get_query_params
try:
    import apis.yang.codegen.messages.system as umf_system
    from apis.yang.utils.common import Operation
except ImportError:
    pass


def verify_name_server(dut, **kwargs):
    """
    :param name_servers:
    :type name server ip address:
    :param src_intf:
    :type source interface:
    :param vrf:
    :type vrf name:
    :param dut:
    :type dut:

    usage:
    verify_name_server(vars.D1, src_intf='Management0', name_server_list=['10.0.0.1'])
    verify_name_server(vars.D1, name_server_list=['10.0.0.2'], vrf='mgmt')
    verify_name_server(vars.D1, src_intf='Management0', name_server_list=['10.0.0.2', '10.0.0.3'], vrf='mgmt')
    """

    result = True
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type
    filter_type = kwargs.get('filter_type', 'ALL')
    query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)

    if cli_type in get_supported_ui_type_list():
        sys_obj = umf_system.System()
        if "src_intf" in kwargs:
            setattr(sys_obj, 'DnsSourceInterface', kwargs['src_intf'])
        if "name_server_list" in kwargs:
            for name_server in kwargs['name_server_list']:
                dns_obj = umf_system.DnsServer(Address=name_server)
                if 'vrf' in kwargs:
                    dns_obj.VrfName = kwargs['vrf']
                sys_obj.add_DnsServer(dns_obj)

        result = sys_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        result = result.ok()

    elif cli_type == 'klish':
        output = st.show(dut, 'show hosts', type=cli_type)
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        if 'return_output' in kwargs:
            return output

        if "src_intf" in kwargs:
            st.log("src_intf: {}".format(output[0]['src_intf']))
            if not kwargs['src_intf'] == output[0]['src_intf']:
                st.log("{} : {} is not match ".format('src_intf', kwargs['src_intf']))
                result = False

        if "name_server_list" in kwargs:
            st.log("name_servers: {} ".format(output[0]['name_servers']))
            for name_server in kwargs['name_server_list']:
                if "vrf" in kwargs:
                    if '{}(vrf: {})'.format(name_server, kwargs['vrf']) not in output[0]['name_servers']:
                        st.log("{} : {} is not match ".format('vrf', kwargs['vrf']))
                        result = False
                elif name_server not in output[0]['name_servers']:
                    st.log("{} : {} is not match ".format('name_servers', kwargs['name_server_list']))
                    result = False

    return result


def config_name_server(dut, **kwargs):
    """
    :param name_servers:
    :type name server ip address:
    :param src_intf:
    :type source interface:
    :param vrf:
    :type vrf name:
    :param dut:
    :type dut:

    usage:
    config_name_server(vars.D1, src_intf='Management0', name_servers='10.0.0.1')
    config_name_server(vars.D1, name_servers='10.0.0.2', vrf='mgmt')
    config_name_server(vars.D1, name_servers='10.0.0.2', config='no')
    config_name_server(vars.D1, src_intf='Management0', config='no')
    """

    config = kwargs.get("config", 'yes')
    skip_error_check = kwargs.get("skip_error_check", False)
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type

    if cli_type in get_supported_ui_type_list():
        if config == 'yes':
            sys_obj = umf_system.System()
            operation = Operation.CREATE
            if 'src_intf' in kwargs:
                sys_obj.DnsSourceInterface = kwargs['src_intf']
            if 'name_servers' in kwargs:
                dns_obj = umf_system.DnsServer(Address=kwargs['name_servers'])
                if 'vrf' in kwargs:
                    dns_obj.VrfName = kwargs['vrf']
                sys_obj.add_DnsServer(dns_obj)
            sys_obj.configure(dut, operation=operation, cli_type=cli_type)
        else:
            if 'src_intf' in kwargs:
                sys_obj = umf_system.System(DnsSourceInterface=kwargs['src_intf'])
                target_attr = getattr(sys_obj, 'DnsSourceInterface')
                sys_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if 'name_servers' in kwargs:
                dns_obj = umf_system.DnsServer(Address=kwargs['name_servers'])
                dns_obj.unConfigure(dut, cli_type=cli_type)

    elif cli_type == 'klish':
        command = []
        if config == 'yes':
            if 'src_intf' in kwargs:
                command = command + ['ip name-server source-interface {}'.format(kwargs['src_intf'])]
            if 'name_servers' in kwargs:
                if 'vrf' in kwargs:
                    command = command + ['ip name-server {} vrf {}'.format(kwargs['name_servers'], kwargs['vrf'])]
                else:
                    command = command + ['ip name-server {}'.format(kwargs['name_servers'])]
        else:
            if 'src_intf' in kwargs:
                command = command + ['no ip name-server source-interface']
            if 'name_servers' in kwargs:
                command = command + ['no ip name-server {}'.format(kwargs['name_servers'])]
        if command:
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
            return True
    else:
        st.error("Unsupported CLI Type {}".format(cli_type))
        return False
