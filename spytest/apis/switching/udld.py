from spytest import st
from spytest.utils import filter_and_select
from tabulate import tabulate
import apis.system.basic as basic_obj
import time
from apis.system.rest import config_rest, delete_rest, get_rest
from utilities.utils import get_interface_number_from_name

def print_log(message,alert_type="LOW"):
    '''
    Uses st.log procedure with some formatting to display proper log messages
    :param message: Message to be printed
    :param alert_level:
    :return:
    '''
    log_start = "\n======================================================================================\n"
    log_end =   "\n======================================================================================"
    log_delimiter ="\n###############################################################################################\n"

    if alert_type == "HIGH":
        st.log("{} {} {}".format(log_delimiter,message,log_delimiter))
    elif alert_type == "MED":
        st.log("{} {} {}".format(log_start,message,log_end))
    elif alert_type == "LOW":
        st.log(message)
    elif alert_type == "ERROR":
        st.error("{} {} {}".format(log_start,message,log_start))

def config_udld_global(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_global(dut=data.dut1,udld_enable='yes',config='yes')
    config_udld_global(dut=data.dut1,udld_enable='yes')
    config_udld_global(dut=data.dut1,udld_enable='',config='no')
    udld.config_udld_global(dut=dut1,udld_enable='yes',config='yes',cli_type='rest-put')
    Configure udld global
    :param dut:
    :param udld_enable:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    st.log("Starting UDLD Module Configurations1...")
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    udld_enable =  kwargs.get('udld_enable',None)
    if cli_type == 'klish' or cli_type == 'click':
        if 'udld_enable' in kwargs:
            my_cmd = '{} udld enable \n'.format(config_cmd)
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['udld_admin_config']
        if config_cmd == '' and udld_enable != None:
            ocdata = {"openconfig-udld-ext:admin-enable":bool(1)}
        else:
            ocdata = {"openconfig-udld-ext:admin-enable":bool(0)}
        response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
        if not response:
            st.log('UDLD global config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_udld_mode(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_mode(dut=data.dut1,udld_mode='yes',config='yes')
    config_udld_mode(dut=data.dut1,udld_mode='yes')
    config_udld_mode(dut=data.dut1,udld_mode='',config='yes')
    udld.config_udld_mode(dut=dut1,udld_mode='yes',config='yes',cli_type='rest-put')
    Configure udld mode to Agressive
    :param dut:
    :param udld_mode:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    udld_mode =  kwargs.get('udld_mode',None)
    if cli_type == 'klish' or cli_type == 'click':
        if 'udld_mode' in kwargs:
            my_cmd = '{} udld aggressive \n'.format(config_cmd)
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['udld_aggressive_config']
        if config_cmd == '' and udld_mode != None:
            ocdata = {"openconfig-udld-ext:aggressive":bool(1)}
        else:
            ocdata = {"openconfig-udld-ext:aggressive":bool(0)}
        response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
        if not response:
            st.log('UDLD global mode config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_udld_message_time(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_message_time(dut=data.dut1,udld_message_time='3',config='yes')
    config_udld_message_time(dut=data.dut1,udld_message_time='3')
    config_udld_message_time(dut=data.dut1,udld_message_time='3',config='no')
    udld.config_udld_message_time(dut=dut1,udld_message_time='3',config='yes',cli_type='rest-put')
    Configure udld message time globally
    :param dut:
    :param udld_message_time:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    udld_message_time =  kwargs.get('udld_message_time',None)
    if cli_type == 'klish' or cli_type == 'click':
        if 'udld_message_time' in kwargs:
            my_cmd = '{} udld message-time {} \n'.format(config_cmd, kwargs['udld_message_time'])
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['udld_msgtime_config']
        ocdata = {"openconfig-udld-ext:msg-time":int(kwargs['udld_message_time'])}
        if config_cmd == '' and udld_message_time != None:
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
        else:
            response = delete_rest(dut, http_method='delete', rest_url=rest_url, json_data=ocdata)
        if not response:
            st.log('UDLD global message time config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_udld_multiplier(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_multiplier(dut=data.dut1,udld_multiplier='4',config='yes')
    config_udld_multipier(dut=data.dut1,udld_multiplier='4')
    config_udld_multipier(dut=data.dut1,udld_multiplier='4',config='no')
    udld.config_udld_multiplier(dut=dut1,udld_multiplier='3',config='yes',cli_type='rest-put')
    Configure udld multipllier globally
    :param dut:
    :param udld_multipier:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    udld_multiplier =  kwargs.get('udld_multiplier',None)
    if cli_type == 'klish' or cli_type == 'click':
        if 'udld_multiplier' in kwargs:
            my_cmd = '{} udld multiplier {} \n'.format(config_cmd, kwargs['udld_multiplier'])
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['udld_multiplier_config']
        ocdata = {"openconfig-udld-ext:multiplier":int(kwargs['udld_multiplier'])}
        if config_cmd == '' and udld_multiplier != None:
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
        else:
            response = delete_rest(dut, http_method='delete', rest_url=rest_url, json_data=ocdata)
        if not response:
            st.log('UDLD global message time config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_intf_udld(dut, **kwargs):
    """
    config_intf_udld(dut=data.dut1,intf ='Ethernet10',udld_enable='yes',config='yes')
    config_intf_udld(dut=data.dut1,intf ='Ethernet10',udld_enable='yes')
    config_intf_udld(dut=data.dut1,intf ='Ethernet10',udld_enable='',config='no')
    udld.config_intf_udld(dut=dut2,intf ='Ethernet37',udld_enable='yes',config='yes',cli_type='rest-put')
    Author: Chandra.vedanaparthi@broadcom.com
    Enable UDLD at interface level
    :param dut:
    :param intf:
    :param udld_enable:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    if 'intf' in kwargs:
        if type(kwargs['intf']) is list:
            kwargs['intf'] = list(kwargs['intf'])
        else:
            kwargs['intf'] = [kwargs['intf']]
    my_cmd= ''
    if cli_type == 'klish' or cli_type == 'click':
        for intf1 in kwargs['intf']:
            intf_details = get_interface_number_from_name(intf1)
            my_cmd += 'interface {} {}\n'.format(intf_details['type'],intf_details['number'])
            if 'udld_enable' in kwargs:
                my_cmd += '{} udld enable\n'.format(config_cmd)
                my_cmd += 'exit\n'
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        for intf1 in kwargs['intf']:
            rest_url = rest_urls['udld_interface_admin_config'].format(intf1)
            url2 = rest_urls['udld_interface']
            udld_int_data = {"openconfig-udld-ext:interfaces": {"interface": [{"name": intf1,"config": \
                {"name": intf1,"admin-enable": False,"aggressive": False}}]}}
            if not config_rest(dut, http_method=cli_type, rest_url=url2, json_data=udld_int_data):
                st.error("Failed to create udld interface container {}".format(intf1))
                return False
            if config_cmd == '':
                ocdata = {"openconfig-udld-ext:admin-enable":bool(1)}
            else:
                ocdata = {"openconfig-udld-ext:admin-enable":bool(0)}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log('UDLD interface config/unconfig failed')
                st.log(response)
                return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_intf_udld_mode(dut, **kwargs):
    """
    config_intf_udld_mode(dut=data.dut1,intf ='Ethernet10',udld_mode='yes',config='yes')
    config_intf_udld_mode(dut=data.dut1,intf ='Ethernet10',udld_mode='yes')
    config_intf_udld_mode(dut=data.dut1,intf ='Ethernet10',udld_mode='',config='no')
    udld.config_intf_udld_mode(dut=dut2,intf ='Ethernet37',udld_mode='yes',config='yes',cli_type='rest-put')
    Author: Chandra.vedanaparthi@broadcom.com
    Enable UDLD mode Aggressive at interface level
    :param dut:
    :param intf:
    :param udld_mode:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    if 'intf' in kwargs:
        if type(kwargs['intf']) is list:
            kwargs['intf'] = list(kwargs['intf'])
        else:
            kwargs['intf'] = [kwargs['intf']]
    my_cmd= ''
    if cli_type == 'klish' or cli_type == 'click':
        for intf in kwargs['intf']:
            intf_details = get_interface_number_from_name(intf)
            my_cmd += 'interface {} {}\n'.format(intf_details['type'],intf_details['number'])
            if 'udld_mode' in kwargs:
                my_cmd += '{} udld aggressive\n'.format(config_cmd)
                my_cmd += 'exit\n'
        st.config(dut, my_cmd,type='klish')
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        for intf in kwargs['intf']:
            rest_url = rest_urls['udld_interface_aggressive_config'].format(intf)
            if config_cmd == '':
                ocdata = {"openconfig-udld-ext:aggressive":bool(1)}
            else:
                ocdata = {"openconfig-udld-ext:aggressive":bool(0)}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log('UDLD mode for interface config/unconfig failed')
                st.log(response)
                return False
            return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_udld_recover(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_recover(dut=data.dut1,udld_recover='enable',module="udld")
    config_udld_recover(dut=data.dut1,udld_recover='disable',module="udld")
    udld.config_udld_recover(dut=dut1,udld_recover='enable',module="udld",cli_type = 'klish')
    udld.config_udld_recover(dut=dut1,udld_recover='enable',module="udld",cli_type = 'rest-put')
    Configure udld recover global
    :param dut:
    :param udld_recover:
    :module:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    module = kwargs.get('module',None)
    udld_recover = kwargs.get('udld_recover',None)
    st.log("Starting UDLD recover Configurations1...")
    my_cmd= ''
    if cli_type == 'click':
        if 'udld_recover' in kwargs and 'module' in kwargs:
            my_cmd = 'config errdisable recovery cause {} {}'.format(kwargs['udld_recover'],kwargs['module'])
        else:
            st.error("Mandatory arguments udld enable or disable and module name should be given")
            return False
        st.config(dut,my_cmd,type=cli_type)
    elif cli_type == 'klish':
        if udld_recover != None and module != None:
            if udld_recover == 'enable':
                my_cmd = 'errdisable recovery cause {}'.format(kwargs['module'])
            elif udld_recover == 'disable':
                my_cmd = 'no errdisable recovery cause {}'.format(kwargs['module'])
        else:
            st.error("Mandatory arguments udld recover and module name should be given")
            return False
        st.config(dut,my_cmd,type=cli_type)
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['errdisable_recover_cause_config']
        if module != None and udld_recover != None:
            ocdata = {"openconfig-errdisable-ext:cause":[module.upper()]}
            if udld_recover.lower() == 'enable':
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            elif udld_recover.lower() == 'disable':
                response = delete_rest(dut, http_method='delete', rest_url=rest_url, json_data=ocdata)
        else:
            st.error("Mandatory arguments udld recover and module name should be given")
            return False
        if not response:
            st.log('Errdisable recovery cause config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def config_udld_recover_timer(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    config_udld_recover_timer(dut=data.dut1,udld_recover_timer='30')
    config_udld_recover_timer(dut=data.dut1,udld_recover_timer='300')
    udld.config_udld_recover_timer(dut=dut1,udld_recover_timer='30',cli_type = 'klish')

    Configure udld recover timer
    :param dut:
    :param udld_recover_timer: 300 default in sec
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    udld_recover_timer = kwargs.get('udld_recover_timer',None)
    config = kwargs.get('config','')
    st.log("Starting UDLD recover timer Configurations1...")
    my_cmd= ''
    if cli_type == 'click':
        if 'udld_recover_timer' in kwargs:
            my_cmd = 'config errdisable recovery interval {}'.format(kwargs['udld_recover_timer'])
        else:
            st.error("Mandatory argument udld recover timer should be given")
            return False
        st.config(dut,my_cmd,type=cli_type)
    elif cli_type == 'klish':
        if udld_recover_timer != None:
            if config == '':
                my_cmd = 'errdisable recovery interval {}'.format(kwargs['udld_recover_timer'])
            else:
                my_cmd = 'no errdisable recovery interval'
        else:
            st.error("Mandatory argument udld recover timer should be given")
            return False
        st.config(dut,my_cmd,type=cli_type)
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['errdisable_recover_interval_config']
        if udld_recover_timer != None:
            ocdata = {"openconfig-errdisable-ext:interval":int(udld_recover_timer)}
            if config == '':
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            else:
                response = delete_rest(dut, http_method='delete', rest_url=rest_url, json_data=ocdata)
        else:
            st.error("Mandatory arguments udld recover interval should be given")
            return False
        if not response:
            st.log('Errdisable recovery interval config/unconfig failed')
            st.log(response)
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def udld_reset(dut):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    udld_reset(dut=data.dut1)

    Reset the UDLD at exec level
    :param dut:
    :return:
    """
    my_cmd = 'udld reset'
    st.config(dut,my_cmd,type="click")

def udld_clear_stats(dut):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    udld_clear_stats(dut=data.dut1)

    Reset the UDLD stats at global level
    :param dut:
    :return:
    """
    my_cmd = 'clear udld statistics'
    st.config(dut,my_cmd,type="click")

def udld_clear_stats_intf(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    udld_clear_stats_intf(dut=data.dut1,intf ='Ethernet10')

    Reset the UDLD stats at interface level
    :param dut:
    :param intf:
    :return:
    """
    if 'intf' in kwargs:
        if type(kwargs['intf']) is list:
            kwargs['intf'] = list(kwargs['intf'])
        else:
            kwargs['intf'] = [kwargs['intf']]
    my_cmd= ''
    for intf in kwargs['intf']:
        if '/' in intf:
            intf = st.get_other_names(dut,[intf])[0]
        my_cmd += 'clear udld statistics {}\n'.format(intf)
    st.config(dut,my_cmd,type="click")

def udld_block(dut, **kwargs):
    """
    Author: Chandra.vedanaparthi@broadcom.com
    udld_blockf(dut=data.dut1,intf ='Ethernet10')

    Block the UDLD packtets at interface level
    :param dut:
    :param intf:
    :return:
    """
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = 'enable'
    else:
        config_cmd = 'disable'

    if 'intf' in kwargs:
        if type(kwargs['intf']) is list:
            kwargs['intf'] = list(kwargs['intf'])
        else:
            kwargs['intf'] = [kwargs['intf']]
        my_cmd= ''
        for intf in kwargs['intf']:
            if '/' in intf:
                intf = st.get_other_names(dut,[intf])[0]
            my_cmd += 'udldctl rx_drop {} {}\n'.format(config_cmd,intf)
    else:
        st.error("Mandatory argument interface name Not Found")
        return False
    st.config(dut,my_cmd,type="click")

def udld_cfg_ebtables_rule(dut, **kwargs):
    if 'add' in kwargs:
        if kwargs['add']:
            cmd = "sudo ebtables -A FORWARD "
        else:
            cmd = "sudo ebtables -D FORWARD "
    else:
        print_log('Missing keyword')
        return
    cmd = cmd + "-d 1:0:c:cc:cc:cc -j DROP"
    st.show(dut, cmd, skip_tmpl=True)

def verify_udld_global(dut,**kwargs):
    """
    Author: Chandra Sekhar Reddy
    email : chandra.vedanaparthi@broadcom.com
    Verify show udld global output
    :param dut:
    :param kwargs: Parameters can be <udld_admin_state|udld_mode|udld_message_time|udld_multiplier|All>
    :return:
    Usage:
    udld.verify_udld_global(data.dut1,udld_admin_state="enabled", udld_mode='Normal', udld_message_time="1", udld_multiplier="3",cli_type = 'rest-put')
    verify_udld_global(dut1,udld_message_time="1", udld_multiplier="3")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    ret_val = True
    udld_admin_state = kwargs.get('udld_admin_state',None)
    udld_mode = kwargs.get('udld_mode',None)
    udld_message_time = kwargs.get('udld_message_time',None)
    udld_multiplier = kwargs.get('udld_multiplier',None)
    if cli_type == 'klish' or cli_type == 'click':
        cmd = 'show udld global'
        output = st.show(dut,cmd,type="klish",config="false",skip_error_check="True")
        st.log("Before output......................")
        st.log("{}".format(tabulate(output, headers="keys", tablefmt='psql')))
        st.log("After output......................")
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        for key in kwargs:
            if str(kwargs[key]) != str(output[0][key]):
                st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
                ret_val = False
            else:
                st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
        return ret_val
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['show_udld_global_get']
        output = get_rest(dut, rest_url=rest_url)['output']
        if output:
            payload = output['openconfig-udld-ext:udld']['state']
            if udld_mode != None and udld_mode != 'Normal':
                if (payload[udld_mode.lower()]) != True and 'aggressive' in payload:
                    ret_val = False
            if udld_admin_state != None  and 'admin-enable' in payload:
                if udld_admin_state.lower() == 'enabled':
                    if (payload['admin-enable']) != True:
                        ret_val = False
            if udld_message_time != None and 'msg-time' in payload:
                if payload['msg-time'] != int(udld_message_time):
                    ret_val = False
            if udld_multiplier != None and 'multiplier' in payload:
                if payload['multiplier'] != int(udld_multiplier):
                    ret_val = False
        else:
            st.log("Rest output empty")
            ret_val = False
        return ret_val

def verify_udld_neighbors(dut,**kwargs):
    """
    Author: Chandra Sekhar Reddy
    email : chandra.vedanaparthi@broadcom.com
    :param dut:
    :param local_port:
    :type string or list
    :param device_name:
    :type string or list
    :param remote_device_id:
    :type mac in string or list
    :param remote_port:
    :type string or list
    :param neighbor_state:
    :type string or list
    :return:

    Usage
    verify_udld_neighbors(dut1,local_port=['Ethernet1','Ethernet3'],device_name=['Sonic','Sonic'],
                             remote_device_id=['3c2c.992d.8201','3c2c.992d.8202'],remote_port=['Ethernet0','Ethernet3'],\
                             neighbor_state=['Bidirectional','Bidirectional'])
    verify_udld_neighbors(dut1,local_port='Ethernet3',neighbor_state='Bidirectional')
    udld.verify_udld_neighbors(dut1,local_port='Ethernet32',neighbor_state='Bidirectional', device_name='Sonic' ,remote_device_id ='3C2C.99A6.FBA0' ,remote_port ='Ethernet24',cli_type = 'rest-put')
    """
    ret_val = True
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    remote_port = kwargs.get('remote_port',None)
    device_name = kwargs.get('device_name',None)
    neighbor_state = kwargs.get('neighbor_state',None)
    local_port = kwargs.get('local_port',None)
    if cli_type == 'klish' or cli_type == 'click':
        output = st.show(dut,'show udld neighbors',type="klish",config="false",skip_error_check="True")
        st.log("Before output......................")
        st.log("{}".format(tabulate(output, headers="keys", tablefmt='psql')))
        st.log("After output......................")
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        if 'return_output' in kwargs:
            return output
        #Converting all kwargs to list type to handle single or list of udld neighbors
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
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        if type(local_port) is list:
            local_port = list(local_port)
        else:
            local_port = [local_port]
        for port,rport,dname,nstate in zip (local_port,remote_port,device_name,neighbor_state):
            rest_url = rest_urls['show_udld_interface_state_get'].format(port)
            payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-udld-ext:state']['neighbors-info']['neighbor']
            for neighbor in payload:
                if remote_port != None:
                    if neighbor['state']['port-id'] != str(rport):
                        ret_val = False
                if device_name != None:
                    if neighbor['state']['device-name'] != str(dname).lower():
                        ret_val = False
                if neighbor_state != None:
                    if neighbor['state']['status'].split(':')[1] != str(nstate).upper():
                        ret_val = False
        return ret_val

def get_udld_intf_state(dut, **kwargs):
    cmd = 'show udld interface '
    if 'udld_intf' in kwargs:
        udld_intf = kwargs['udld_intf']
        del kwargs['udld_intf']
        cmd += '{}'.format(udld_intf)
    else:
        st.error("Mandatory argument interface name Not Found")
        return None

    output = st.show(dut, cmd,type="klish",config="false")
    if output and  len(output) > 0:
        if 'udld_status' in output[0].keys():
            return output[0]['udld_status']
        else:
            return None

def verify_udld_interface(dut,**kwargs):
    """
    Author: Chandra Sekhar Reddy
    email: chandra.vedanaparthi@broadcom.com
    Verify show udld interface ouput
    :param dut:
    :param kwargs: Parameters can be <udld_intf|udld_admin_state|udld_mode|udld_status|local_device_id|local_port
    :                                |local_device_name|local_udld_message_time|local_udld_multiplier
    :                                |neighbor_device_id|neighbor_port|neighbor_device_name|neighbor_udld_message_time
    :                                |neighbor_udld_multiplier|neighbor_udld_multiplier>
    :return:
    Usage:
    verify_udld_interface(dut1,udld_intf='Ethernet1", udld_admin_state='Enabled', udld_mode='Aggressive', udld_status='Bidirectional', \
                            local_device_id="3c2c.992d.8201",local_port='Ethernet1', local_device_name='Sonic' \
                            local_udld_message_time=1, local_udld_multiplier=3, neighbor_device_id="3c2c.992d.8235" \
                            neighbor_port='Ethernet2', neighbor_device_name='Sonic', neighbor_udld_message_time=1, neighbor_udld_multiplier=3)
    udld.verify_udld_interface(data.dut1,udld_intf='Ethernet32", udld_admin_state='Enabled', udld_mode='Normal', udld_status='Bidirectional', neighbor_port='Ethernet24', neighbor_device_name='Sonic', neighbor_udld_message_time=1, neighbor_udld_multiplier=3, cli_type = 'rest-put')
    """
    ret_val = True
    cmd = 'show udld interface '
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    udld_admin_state = kwargs.get('udld_admin_state',None)
    udld_mode = kwargs.get('udld_mode',None)
    udld_status = kwargs.get('udld_status',None)
    neighbor_device_id = kwargs.get('neighbor_device_id',None)
    neighbor_port = kwargs.get('neighbor_port',None)
    neighbor_device_name = kwargs.get('neighbor_device_name',None)
    neighbor_udld_message_time = kwargs.get('neighbor_udld_message_time',None)
    neighbor_udld_multiplier = kwargs.get('neighbor_udld_multiplier',None)
    if 'udld_intf' in kwargs:
        udld_intf = kwargs['udld_intf']
        del kwargs['udld_intf']
        cmd += '{}'.format(udld_intf)
    else:
        st.error("Mandatory argument interface name Not Found")
        return False
    if cli_type == 'klish' or cli_type == 'click':
        output = st.show(dut, cmd,type="klish",config="false",skip_error_check="True")
        st.log("Before output......................")
        st.log("{}".format(cmd))
        st.log("{}".format(tabulate(output, headers="keys", tablefmt='psql')))
        st.log("After output......................")
        if len(output) == 0:
            st.error("Output is Empty")
            return False
        for key in kwargs:
            if str(kwargs[key]) != str(output[0][key]):
                st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
                ret_val = False
            else:
                st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
        return ret_val
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url = rest_urls['show_udld_interface_state_get'].format(udld_intf)
        payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-udld-ext:state']
        if udld_mode != None and udld_mode != 'Normal':
            if (payload[udld_mode.lower()]) != True:
                ret_val = False
        if udld_admin_state != None:
            if udld_admin_state.lower() == 'enabled':
                if (payload['admin-enable']) != True:
                    ret_val = False
        if udld_status != None:
            if payload['local-info']['status'].split(':')[1] != str(udld_status).upper():
                ret_val = False
        if udld_status == 'Bidirectional':
            for neigh in payload['neighbors-info']['neighbor']:
                if neighbor_device_id != None:
                    if neigh['state']['device-id'] != str(neighbor_device_id):
                        ret_val = False
                if neighbor_port != None:
                    if neigh['state']['port-id'] != str(neighbor_port):
                        ret_val = False
                if neighbor_device_name != None:
                    if neigh['state']['device-name'] != str(neighbor_device_name).lower():
                        ret_val = False
                if neighbor_udld_message_time != None:
                    if neigh['state']['msg-time'] != int(neighbor_udld_message_time):
                        ret_val = False
                if neighbor_udld_multiplier != None:
                    if neigh['state']['timeout-interval'] != int(neighbor_udld_multiplier):
                        ret_val = False
        return ret_val

def verify_udld_statistics(dut,**kwargs):
    """
    Author: Chandra Sekhar Reddy
    email : chandra.vedanaparthi@broadcom.com
    :param dut:
    :param udld_interface:
    :type  String or list
    :param udld_tx
    :type integer or list of integers
    :param udld_rx
    :type integer or list of integers
    :param udld_errors
    :type integer or list of integers
    :return:

    Usage
    verify_udld_statistics(dut1,udld_interface=['Ethernet24','Ethernet32'],udld_tx=[10,10],udld_rx=[10,10],udld_errors=[10,10])

    verify_udld_statistics(dut1,udld_interface='Ethernet24','Ethernet32',udld_tx=10,udld_rx=10,udld_errors=10)
    udld.verify_udld_statistics(dut1,udld_interface='Ethernet41',udld_tx=5708,udld_rx=5708,udld_errors=0,cli_type='rest-put')

    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    udld_interface = kwargs.get('udld_interface',None)
    udld_tx = kwargs.get('udld_tx',None)
    udld_rx = kwargs.get('udld_rx',None)
    #udld_errors = kwargs.get('udld_errors',None)
    #Converting all kwargs to list type to handle single or list of udld stats
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    if cli_type == 'klish' or cli_type == 'click':
        if len(kwargs['udld_interface']) > 1:
            cmd = "show udld statistics"
        else:
            cmd = "show udld statistics interface {}".format(kwargs['udld_interface'])
        output = st.show(dut, cmd,type="klish",config="false")
        if 'return_output' in kwargs:
            return output
        if len(output) == 0:
            st.error("Output is Empty")
            return False
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
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        if type(udld_interface) is list:
            udld_interface = list(udld_interface)
        else:
            udld_interface = [udld_interface]
        for intf in udld_interface:
            rest_url = rest_urls['show_udld_interface_counters_get'].format(intf)
            payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-udld-ext:counters']
            if udld_tx != None:
                if payload['pdu-sent'] != int(udld_tx):
                    ret_val = False
            if udld_rx != None:
                if payload['pdu-received'] != int(udld_rx):
                    ret_val = False
        return ret_val

def check_udld_status_after_restart(dut):
    ret = False
    max_wait_time = 300 # 5 mins, reason, cold reboot might take upto 5mins
    wait_start_time = time.time()
    total_wait_time = 0
    while not ret:
        st.wait(2)
        total_wait_time = int(time.time() - wait_start_time)
        st.log("Verify UDLD service status after {} sec".format(total_wait_time))
        if total_wait_time > max_wait_time:
            st.error('UDLD is NOT READY even after {} seconds'.format(total_wait_time))
            return False
        ret = basic_obj.verify_service_status(dut, "udld")

    st.log('UDLD is READY after {} seconds'.format(total_wait_time))
    return True


