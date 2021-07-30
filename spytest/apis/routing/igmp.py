from spytest.utils import filter_and_select
from spytest import st


def config_igmp(dut, **kwargs):
    """
    config_igmp(dut=data.dut1,intf ='Ethernet10',igmp_enable='yes',join='yes',group='225.1.1.1',source='10.10.10.2',version='2',
                query_interval=10,query_max_response='34',oil_prefix='prefix1',config='yes', cli_type='vtysh')

    Configure interface with pim configurations
    :param dut:
    :param intf:
    :param igmp_enable:
    :param join:
    :param verson:
    :param query_interval:
    :param query_max_response:
    :param cli type
    :return:
    """

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    cli_type=kwargs.pop('cli_type','click')
    if 'intf' in kwargs:
        if type(kwargs['intf']) is list:
            kwargs['intf'] = list(kwargs['intf'])
        else:
            kwargs['intf'] = [kwargs['intf']]

    my_cmd = ''
    for intf in kwargs['intf']:
        my_cmd += 'interface {}\n'.format(intf)

        if config_cmd != 'no':
            if 'igmp_enable' in kwargs:
                my_cmd += 'ip igmp \n'

        if 'version' in kwargs:
            my_cmd += '{} ip igmp version {} \n'.format(config_cmd, kwargs['version'])

        if 'query_max_response' in kwargs:
            if config_cmd == 'no' : kwargs['query_max_response'] = ''
            my_cmd += '{} ip igmp query-max-response-time {} \n'.format(config_cmd, kwargs['query_max_response'])

        if 'query_interval' in kwargs:
            if config_cmd == 'no': kwargs['query_interval'] = ''
            my_cmd += '{} ip igmp query-interval {} \n'.format(config_cmd, kwargs['query_interval'])

        if 'last_member_query_interval' in kwargs:
            if config_cmd == 'no': kwargs['last_member_query_interval'] = ''
            my_cmd += '{} ip igmp last-member-query-interval {} \n'.format(config_cmd, kwargs['last_member_query_interval'])

        if 'last_member_query_count' in kwargs:
            if config_cmd == 'no': kwargs['last_member_query_count'] = ''
            my_cmd += '{} ip igmp last-member-query-count {} \n'.format(config_cmd, kwargs['last_member_query_count'])

        if 'join' in kwargs:
            if type(kwargs['source']) is list:
                for source in kwargs['source']:
                    my_cmd += '{} ip igmp join {} {}\n'.format(config_cmd, kwargs['group'], source)
            else:
                my_cmd += '{} ip igmp join {} {}\n'.format(config_cmd,kwargs['group'],kwargs['source'])

        if config_cmd == 'no':
            if 'igmp_enable' in kwargs:
                my_cmd += 'no ip igmp \n'
        #my_cmd += 'exit\n'
    if cli_type == 'click':
        st.config(dut, my_cmd, type='vtysh')
    elif cli_type == "klish":
        st.config(dut, my_cmd, type='klish')
        st.config(dut, "exit", type='klish')

def verify_ip_igmp(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut
    :type string
    :param vrf
    :type string
    :param cmd_type
    :type string (CLI type)
    :param cli_type
    :type string


    :API type: "show ip igmp groups"
    :arg_list: 'interface', 'address', 'group', 'mode', 'timer', 'source_count', 'version', 'uptime'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='groups',interface='Ethernet45',address='10.1.1.1',mode='INCL',group='225.1.1.1',version='2')


    :API type: "show ip igmp sources"
    :arg_list:  'interface', 'address', 'source', 'group', 'timer', 'fwd', 'uptime'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='sources',interface='Ethernet45',address='10.1.1.1',source='20.1.1.1',group='225.1.1.1',vrf='RED')

    :API type: "show ip igmp groups retransmissions"
    :arg_list: 'interface', 'address', 'group', 'ret_timer', 'counter', 'ret_sources'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='groups retransmissions',interface='Ethernet45',address='10.1.1.1',counter='0',group='225.1.1.1',ret_sources='3')


    :API type: "show ip igmp sources retransmissions"
    :arg_list: 'interface', 'address', 'group', 'source', 'counter'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='sources retransmissions',interface='Ethernet45',address='10.1.1.1',source='20.1.1.2',group='225.1.1.1',counter=10)

    :API type: "show ip igmp join"
    :arg_list: 'interface', 'address', 'source', 'group', 'socket', 'uptime'
    :arg_type: String or list
    :Usage:
    verify_ip_igmp(dut=data.dut1,cmd_type='join',interface='Ethernet45',address='10.1.1.1',source='20.1.1.2',group='225.1.1.1')

    """

    ret_val = True
    if 'cmd_type' in kwargs:
        cmd_type = kwargs['cmd_type']
        del kwargs['cmd_type']
    else:
        cmd_type = 'groups'

    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    if vrf_name != 'default':
        cmd = 'show ip igmp vrf {} {}'.format(vrf_name,cmd_type)
    else:
        cmd = "show ip igmp {}".format(cmd_type)

    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False

    cli_type = kwargs.pop('cli_type','click')
    if cli_type == 'click':
        cli_type = 'vtysh'

    output = st.show(dut,cmd,skip_error_check=skip_error, type=cli_type)

    if 'return_output' in kwargs:
        return output

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'entry' in kwargs:
        entry_list = kwargs['entry']
        del kwargs['entry']
    else:
        entry_list = [True]*len(kwargs['group'])
    #Converting all kwargs to list type to handle single or list of mroute instances
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

    for input_dict,entry in zip(input_dict_list,entry_list):
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            if entry is False:
                st.error("DUT {} -> Match Found {} which is not expected".format(dut,input_dict))
                ret_val = False
        else:
            if entry is False:
                st.log("DUT {} -> Match Not Found {} as expected".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val


def verify_igmp_stats(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param interface
    :type string
    :param query_v1
    :type string
    :param query_v2
    :type string
    :param query_v3
    :type string
    :param leave_v2
    :type string
    :param report_v1
    :type string
    :param report_v2
    :type string
    :param report_v3
    :type string
    :param mtrace_response
    :type string
    :param mtrace_request
    :type string
    :param unsupported
    :type string
    :param vrf
    :type string
    :param cli_type
    :type string
    :return:
    """
    ret_val = True

    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
    else:
        vrf_name = 'default'

    if vrf_name != 'default':
        cmd = 'show ip igmp vrf {} statistics '.format(vrf_name)
    else:
        cmd = 'show ip igmp statistics '

    if 'interface' in kwargs:
        cmd += 'interface {}'.format(kwargs['interface'])

    skip_error = kwargs.pop('skip_error',False)
    skip_tmpl = kwargs.pop('skip_tmpl',False)

    cli_type = kwargs.pop('cli_type','click')
    if cli_type == 'click':
        cli_type = 'vtysh'

    output = st.show(dut,cmd, type=cli_type,skip_tmpl=skip_tmpl,skip_error_check=skip_error)

    if len(output) == 0 :
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match not Found for {} :  Expected - {} Actual-{} ".format(key,kwargs[key],output[0][key]))
            ret_val = False
        else:
            st.log("Match Found for {} :  Expected - {} Actual-{} ".format(key,kwargs[key],output[0][key]))

    return ret_val



def verify_igmp_interface(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param interface
    :type string
    :param state
    :type string
    :param address
    :type string
    :param uptime
    :type string
    :param version
    :type string
    :param querier
    :type string
    :param start_count
    :type string
    :param query_timer
    :type string
    :param other_timer
    :type string
    :param gmi
    :type string
    :param last_member_query_time
    :type string
    :param old_host_present_interval
    :type string
    :param other_querier_present_interval
    :type string
    :param query_interval
    :type string
    :param query_response_interval
    :type string
    :param robustness
    :type string
    :param startup_query_interval
    :type string
    :param all_multicast
    :type string
    :param broadcast
    :type string
    :param deleted
    :type string
    :param ifindex
    :type string
    :param multicast
    :type string
    :param multicast_loop
    :type string
    :param promiscuous
    :type string
    :param vrf
    :type string
    :param cli_type
    :type string
    :return:
    """
    ret_val = True

    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    if vrf_name != 'default':
        cmd = 'show ip igmp vrf {} interface {}'.format(vrf_name,kwargs['interface'])
    else:
        cmd = 'show ip igmp interface {}'.format(kwargs['interface'])

    skip_tmpl = kwargs.pop('skip_tmpl',False)
    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False

    cli_type = kwargs.pop('cli_type','click')
    if cli_type == 'click':
        cli_type = 'vtysh'

    output = st.show(dut, cmd, skip_error_check=skip_error,skip_tmpl=skip_tmpl, type=cli_type)

    if len(output) == 0 :
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match not Found for {} :  Expected - {} Actual-{} ".format(key,kwargs[key],output[0][key]))
            ret_val = False
        else:
            st.log("Match Found for {} :  Expected - {} Actual-{} ".format(key,kwargs[key],output[0][key]))

    return ret_val


def clear_igmp_interfaces(dut,vrf='default'):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """

    if vrf == 'default':
        cmd = "clear ip igmp interfaces"
    else:
        cmd = "clear ip igmp vrf {} interfaces".format(vrf)

    st.config(dut, cmd, type='vtysh', conf=False)


def debug_igmp(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :return:
    """
    if 'config' in kwargs:
        config= kwargs['config']
    else:
        config = 'yes'

    if config == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    cmd = "{} debug igmp packets\n".format(config_cmd)
    cmd += "{} debug igmp events\n".format(config_cmd)
    cmd += "{} debug igmp trace\n".format(config_cmd)
    cmd += "{} debug igmp\n".format(config_cmd)
    cmd += '{} log syslog debugging\n {} log stdout\n'.format(config_cmd, config_cmd)
    st.config(dut,cmd, type='vtysh')

def config_ip_igmp(dut, **kwargs):
    """
    Config IP IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        commands.append("{} ip igmp".format(config_cmd))
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include ip igmp", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_join(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    print(kwargs)
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'mcastgrpaddr' not in kwargs:
        st.error("Mandatory parameter mcastgrpaddr not found")
        return False

    if 'srcaddr' not in kwargs:
        st.error("Mandatory parameter srcaddr not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        commands.append("{} ip igmp join {} {}".format(config_cmd,
                                          kwargs['mcastgrpaddr'],
                                          kwargs['srcaddr']))
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp join", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_qinterval(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'qinterval' not in kwargs:
        st.error("Mandatory parameter query interval not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'


    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        if config.lower() == 'yes':
            commands.append("ip igmp query-interval {}".format(kwargs.get('qinterval')))
        else:
            commands.append("no ip igmp query-interval")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include query-interval", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_version(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'version' not in kwargs:
        st.error("Mandatory parameter version is not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        if config.lower() == 'yes':
            commands.append("ip igmp version {}".format(kwargs.get('version')))
        else:
            commands.append("no ip igmp version")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp version", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_qmrestime(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'qmrestime' not in kwargs:
        st.error("Mandatory parameter query max response time not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))

        if config.lower() == 'yes':
            commands.append("ip igmp query-max-response-time {}".format(kwargs.get('qmrestime')))
        else:
            commands.append("no ip igmp query-max-response-time")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp query-max-response-time", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_lmqcount(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'lmqcount' not in kwargs:
        st.error("Mandatory parameter last member query count not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        if config.lower() == 'yes':
            commands.append("ip igmp last-member-query-count {}".format(kwargs.get('lmqcount')))
        else:
            commands.append("no ip igmp last-member-query-count")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp last-member-query-count", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False

def config_igmp_lmqinterval(dut, **kwargs):
    """
    Config IGMP.
    Author: Sathishkumar Sivashanmugam (sathish.s@broadcom.com)

    :param :dut:
    :param :cli_type: click|klish
    :return:
    """
    if 'port_alias' not in kwargs:
        st.error("Mandatory parameter port_alias not found")
        return False

    if 'lmqinterval' not in kwargs:
        st.error("Mandatory parameter last-member-query-interval not found")
        return False

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    cli_type = st.get_ui_type(dut, **kwargs)

    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(kwargs.get('port_alias')))
        if config.lower() == 'yes':
            commands.append("ip igmp last-member-query-interval {}".format(kwargs.get('lmqinterval')))
        else:
            commands.append("no ip igmp last-member-query-interval")
        commands.append("exit")
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    # Here handling the error while passing invalid parameters
    if kwargs.get('skip_error'):
        output = st.config(dut, commands, skip_error_check=kwargs.get('skip_error'), type=cli_type)
        errstr = ''
        if errstr in output or '% Error: Illegal parameter.' in output:
            return True
        else:
            return False
    else:
        try:
            st.config(dut, commands, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    #Verify FRR DB
    try:
        output = st.vtysh_show(dut, "show running-config | include igmp last-member-query-interval", skip_tmpl=True)
        return bool(len(output))
    except Exception as e:
        st.log(e)
        return False
