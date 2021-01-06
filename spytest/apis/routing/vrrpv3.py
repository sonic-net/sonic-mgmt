from spytest.utils import filter_and_select
from spytest import st, utils
from utilities.utils import get_interface_number_from_name


def verify_vrrpv3(dut,**kwargs):
    """
    Author:raghukumar.thimmareddy@broadcom.com

    :param interface:
    :type string
    :param vrid:
    :type string or integer
    :param version:
    :type string or interger
    :param vip:
    :type virtual-ip in string
    :param vmac:
    :type virtual-mac as string
    :param state:
    :type vrrp state as string
    :param config_prio:
    :type configured vrrp priority as integer or string
    :param current_prio:
    :type Current vrrp priority as integer or string
    :param adv_interval:
    :type  advertrisement interval as integer or string
    :param track_interface_list:
    :type List of uplink track interfaces
    :param track_priority_list
    :type List of priorities for uplink tracking ports
    :param track_state_list
    :type List of states for uplink tracking ports
    :param preempt
    :type preempt state as string

    usage:
     verify_vrrpv3(dut1,vrid='1',interface='Vlan1000',state='Master',vip='10.0.0.10',track_interface_list=['Vlan10'],track_state_list=['Up'],
     track_priority_list=['10'],adv_interval=1,vmac='0000.5e00.0201',config_prio=90,current_prio=100,version=3,preempt='disabled')
    """
    if 'interface' not in kwargs or 'vrid' not in kwargs:
        st.error("Mandatory arguments \'interface\' or \'vrid \' missing")
        return False

    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    
    if cli_type == 'click':
        cmd = "show vrrp6 {} {}".format(kwargs['interface'],kwargs['vrid'])
    else:
        cmd = "show vrrp6 interface {} vrid {}".format(kwargs['interface'],kwargs['vrid'])
    
    parsed_output = st.show(dut,cmd,type=cli_type)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return parsed_output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each],parsed_output[0][each]))
            return False
    return True
    
  
def configure_vrrpv3(dut,config="yes",addr_family='ipv6',skip_error = False, **kwargs):
    """
    author:raghukumar.thimmareddy@broadcom.com
    :param vrid:
    :type virtual router id:
    :param interface:
    :type interface:
    :param adv_interval:
    :type advertisement interval:
    :param priority:
    :type vrrp priority:
    :param pre_empt:
    :type pre_empt:
    :param version:
    :type version:  
    :param vip:
    :type virtual ip:
    :param dut:
    :type dut:
    :return:
    :rtype:

    usage:
    configure_vrrpv3(dut1, vrid="10",vip="50.1.1.2",interface="Ethernet0",config="yes",version ="3")
    configure_vrrpv3(dut1, vrid="11",vip="60.1.1.2",interface="Ethernet10",adv_interval="10",priority="101",track_interface_list=["Ethernet0",Ethernet4"],track_priority_list=[10,20])
    """
    
    if 'interface' not in kwargs or 'vrid' not in kwargs:
        st.error("Mandatory parameter - interface or vrid is missing")
        return False
    
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    
    cmd =''
    if cli_type == 'click':
        VRRP_CMD = 'sudo config interface vrrp6'
        if config.lower() == "yes":
            if 'version' in kwargs:
                cmd = "sudo config interface vrrp version {} {} {}\n".format(kwargs['interface'],kwargs['vrid'], kwargs['version'])
            if 'enable' in kwargs:
                cmd = "{} add {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'])

            if  'adv_interval' in kwargs:
                cmd = " {} adv_interval {} {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'], kwargs['adv_interval'])

            if  'priority' in kwargs:
                cmd += "{} priority {} {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'], kwargs['priority'])

            if  'preempt' in kwargs:
                cmd += "{} pre_empt enable {} {} \n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'])

            if  'vip' in kwargs:
                cmd += "{} vip add {} {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'], kwargs['vip'])

            if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                    st.error("Please check the track interface list and track priority list, number of entries should be same")
                    return False
                for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                    cmd += "{} track_interface add {} {} {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'],track_intf,track_prio)

        elif config.lower() == "no":
            if 'disable' in kwargs:
                cmd = "{} remove {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'])

            if 'vip' in kwargs:
                cmd += "{} vip remove {} {} {}\n".format(VRRP_CMD, kwargs['interface'], kwargs['vrid'], kwargs['vip'])

            if 'adv_interval' in kwargs or 'priority' in kwargs:
                st.log("Cannot remove/delete the adv_interval or priority, please set it to default value")
        
            if  'preempt' in kwargs:
                cmd += "{} pre_empt disable {} {}\n".format(VRRP_CMD,kwargs['interface'],kwargs['vrid'])

            if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                    st.error("Please check the track interface list and track priority list, number of entries should be same")
                    return False
                for track_intf, track_prio in zip(kwargs['track_interface_list'], kwargs['track_priority_list']):
                    cmd += "{} track_interface remove {} {} {} \n".format(VRRP_CMD, kwargs['interface'],kwargs['vrid'], track_intf )
        output = st.config(dut, cmd, skip_error_check=skip_error,type=cli_type)
        return output
    elif cli_type == "klish":
        pintf = get_interface_number_from_name(kwargs['interface'])
        cmd ="interface {} {}".format(pintf['type'], pintf['number'])
        if config.lower() == "yes": 
            if 'vrid' in kwargs:
                cmd += "\n" +  " vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)           
            if 'priority' in kwargs:
                cmd += "priority {}\n".format(kwargs['priority'])
            if 'adv_interval' in kwargs:
                cmd += "advertisement-interval {}\n".format(kwargs['adv_interval'])
            if  'vip' in kwargs:
                cmd += "vip {}\n".format(kwargs['vip'])
            if  'preempt' in kwargs:
                cmd +=  "preempt\n"
            if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                    st.error("lease check the track interface list and track priority list, number of entries should be same")
                    return False
                for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):
                    cmd += "track-interface {} weight {}\n".format(track_intf,track_prio)
            cmd += "exit\n"
        elif config.lower() == "no":
            if  'vip' in kwargs:
                cmd += "\n" +  " vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
                cmd += "no vip {}\n".format(kwargs['vip'])
            if  'preempt' in kwargs:
                cmd += "\n" +  " vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
                cmd +=  "no preempt\n"
            if 'track_interface_list' in kwargs and 'track_priority_list' in kwargs:
                if len(kwargs['track_interface_list']) != len(kwargs['track_priority_list']):
                    st.error("Please check the track interface list and track priority list, number of entries should be same")
                    return False
                cmd += "\n" +  " vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
                for track_intf,track_prio in zip(kwargs['track_interface_list'],kwargs['track_priority_list']):                    
                    cmd += "no track-interface {}\n".format(track_intf)               
            if 'vrid' in kwargs and 'disable' in kwargs:
                cmd += "\n" + "no vrrp {} address-family {}\n".format(kwargs['vrid'],addr_family)
        cmd += " exit\n"                
        output =st.config(dut, cmd, skip_error_check=skip_error, type=cli_type)
        return output        
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False



def debug_vrrpv3(dut_list):
    """
    Author : Raghukumar Rampur
    email : raghukumar.thimmareddy@broadcom.com
    :param dut_list:
    :return:
    """
    st.log("### Start of Debug commands #####")
    cmd_list = ['show vrrp6','teamshow','show mac','show ip route','show ipv6 route' ,'show vlan brief','bcmcmd \'l2 show \'', 'bcmcmd \'l3 defip show\'','bcmcmd \'l3 l3table show\'']
    arg_list = [[st.apply_script,dut,cmd_list] for dut in dut_list]
    utils.exec_all(True,arg_list)
    st.log(" End of Dubug commands")



def verify_vrrpv3_summary(dut,**kwargs):
    """
    Author: Raghukumar Rampur
    email : raghukumar.thimmareddy@broadcom.com
    :param dut:
    :param interface:
    :type string or list
    :param vrid:
    :type string or list
    :param vip:
    :type virtual-ip in string or list
    :param state:
    :type vrrp state as string or list
    :param config_prio:
    :type configured vrrp priority as list or string
    :param current_prio:
    :type Current vrrp priority as list or string
    :return:

    Usage
    verify_vrrpv3_summary(dut1,vrid=['49','85'],state=['Master','Backup'],
                             interface=['Vlan2996','Vlan2998'],vip=['73.73.73.66','85.85.85.71'],
                             config_prio=[222,97],current_prio=[222,99])
    verify_vrrpv3_summary(dut1,vrid='49',state='Master')
    """

    ret_val = True
    
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    
    output = st.show(dut,'show vrrp6',type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    #Converting all kwargs to list type to handle single or list of vrrp instances
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

