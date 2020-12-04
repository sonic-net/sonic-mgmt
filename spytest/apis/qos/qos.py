import re
import json
from spytest import st
import apis.system.interface as Intf
from utilities.utils import get_interface_number_from_name

def verify_qos_queue_counters(dut,port,queue_name,param_list,val_list,tol_list,**kwargs):
    '''
    verifies QOS queue counters in the CLI show qos queue counters
    :param dut: Device name where the command to be executed
    :type dut: string
    :param port: interface name to be checked
    :type dut: string
    :param queue_name: queue name to be checked
    :type dut: string
    :param param_list: list of params to be verified; example ['pkts_count', 'pkts_drop']
    :param val_list: list of expected values for the params specified; example ['10000','5000']
    :param tol_list: tolerence value for each param while comparing; for example ['1000', '500']
    :return: True/False  True - success case; False - Failure case

    usage:  verify_qos_queue_counters(dut1,'Ethernet0','UC0',['pkts_count', 'pkts_drop'],
                                                       ['10000','5000'],['1000', '500'])
            verify_qos_queue_counters(dut1,'Ethernet0','UC0',['pkts_count'],['10000'],['1000'])

    Created by: Julius <julius.mariyan@broadcom.com
    '''

    success = True
    cli_type = st.get_ui_type(dut,**kwargs)
    fil_out = Intf.show_queue_counters(dut, port, queue_name, cli_type=cli_type)
    if not fil_out:
        st.error('queue: {} not found in show output'.format(queue_name))
        return False
    else:
        fil_out = fil_out[0]

    for param,val,tol in zip(param_list,val_list,tol_list):
        try:
            fil_out[param] = re.sub(",","",fil_out[param])
            int(fil_out[param])
        except ValueError:
            st.error('cannot get integer value from obtained string: {}'.format(fil_out[param]))
            return False
        if int(fil_out[param])<=int(val)+int(tol) and int(fil_out[param])>=int(val)-int(tol):
            st.log('obtained value: {} is in the range b/w {} and {} as expected for param: {}'
                    'in queue: {}'.format(int(fil_out[param]),int(val)-int(tol),
                        int(val)+int(tol),param,queue_name))
        else:
            st.error('obtained value: {} is NOT in the range b/w {} and {} for param: {}'
                   'in queue: {}'.format(int(fil_out[param]), int(val) - int(tol),
                                         int(val) + int(tol), param, queue_name))
            success = False
    return True if success else False

def clear_qos_queue_counters(dut):
    '''
    :param dut: DUT name where CLI to be executed
    :type dut: string
    :return: True/False  True - Success ; False - Failure
    usage:
        clear_qos_queue_counters(dut1)

    Created by: Julius <julius.mariyan@broadcom.com
    '''
    return True if st.show(dut,'show queue counters --clear',skip_tmpl=True) else False


def bind_qos_map_port(dut, map_name, obj_name, interface):
    '''
    :param dut: device to be configured
    :type dut: string
    :param map_name: qos map name for example dscp_to_tc_map, tc_to_queue_map
    :type map_name: string
    :param obj_name: object name for example AZURE
    :type obj_name: string
    :param interface: interface to be associated for example Ethernet1
    :type interface: string
    :return: True/False  True - Success ; False - Failure
    usage:
        bind_qos_map_port(dut1, "tc_to_queue_map", "Azure", "Ethernet0")
        bind_qos_map_port(dut1, "dscp_to_tc_map", "Azure", "Ethernet2")
        bind_qos_map_port(dut1, "tc_to_pg_map", "Azure", "Ethernet72")

    Created by: Julius <julius.mariyan@broadcom.com
    '''

    final_data, temp_data = dict(), dict()
    data = { map_name : "[" + map_name.upper() + "|" + obj_name + "]"}
    temp_data[interface] = data
    final_data['PORT_QOS_MAP'] = temp_data
    data_json = json.dumps(final_data)
    return st.apply_json(dut, data_json)


def clear_qos_config(dut):
    '''
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Clears all the QOS realted config from the device
    :param dut:
    :return:
    '''
    command = "config qos clear"
    st.config(dut, command)

def show_qos_config(dut, map_name, **kwargs):
    '''
    :param dut:
    :param map_name: qos map name for example dscp-tc, dot1p-tc
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "klish":
        command = "show qos map {}".format(map_name)
        st.show(dut, command, type=cli_type)
    return True

def show_qos_interface(dut, portname, **kwargs):
    '''
    :param dut:
    :param port: port_name
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "klish":
        command = "show qos interface {}".format(portname)
        st.show(dut, command, type=cli_type)
    return True

def create_qos_json(dut, block_name, sub_block, dict_input):
    '''
    :param dut: device to be configured
    :type dut: string
    :param block_name: name of the field in json, for eg: dscp_to_tc_map, tc_to_queue_map, wred_profile etc
    :type block_name: string
    :param sub_block: sub field name, for eg: AZURE, AZURE_LOSSLESS etc
    :type sub_block: string
    :param dict_input: input values in dictionary
    :type dict_input: string
    :return: True/False  True - Success ; False - Failure
    usage:
        create_qos_json(dut1, "tc_to_queue_map", "Azure", {"wred_green_enable"      : "true"})

    Created by: Julius <julius.mariyan@broadcom.com
    '''

    final_data, temp_data = dict(), dict()
    temp_data[sub_block] = dict_input
    final_data[block_name.upper()] = temp_data
    final_data = json.dumps(final_data)
    return st.apply_json(dut, final_data)


def config_qos_dscp_tc(dut, map_name, config="yes", **kwargs):
    """
    purpose:
            This definition is used to configure QOS map dscp-tc

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param map_name: qos map name
    :type map_name: string
    :param config: whether to configure or delete
    :type config: string
    :param dscp: DSCP value to be mapped
    :type dscp: string
    :param tc: traffic class to be binded to DSCP
    :type tc: string
    :return: None/False; False for unsupported UI type

    usage:
          config_qos_dscp_tc(dut1,"qos_test",dscp="10",tc="1")
          config_qos_dscp_tc(dut1,"qos_test",config="no", dscp="10")
          config_qos_dscp_tc(dut1,"qos_test",map_del="yes")
    Created by: Julius <julius.mariyan@broadcom.com
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == "klish":
        if "map_del" in kwargs:
            cmd = "no qos map dscp-tc {} \n".format(map_name)
            return st.config(dut, cmd, type=cli_type)
        else:
            cmd = "qos map dscp-tc {} \n".format(map_name)
        if config.lower() == "yes":
            cmd += "dscp {} traffic-class {} \n".format(kwargs["dscp"],kwargs["tc"])
        else:
            cmd += "no dscp {} \n".format(kwargs["dscp"])
        cmd += "exit"
    else:
        st.log("support for UI type {} yet to be added".format(cli_type))
        return False
    return st.config(dut, cmd, type=cli_type)


def bind_qos_map(dut, intf_name,config="yes",**kwargs):
    """
    purpose:
            This definition is used to bind QOS map to an interface

    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param intf_name: interface name to be binded with qos map
    :type intf_name: string
    :param config: whether to configure or delete
    :type config: string
    :param map_type: qos map type like dscp-tc, dot1p-tc etc
    :type map_type: string
    :param map_name: qos map name
    :type map_name: string
    :return: None/False; False for unsupported UI type

    usage:
          bind_qos_map(dut1,"Ethernet15",map_type="dscp-tc",map_name="dscpToTc")
          bind_qos_map(dut1,"PortChannel12",map_type="dscp-tc",map_name="dscpToTc")
          bind_qos_map(dut1,"PortChannel12",config="no",map_type="dscp-tc")
    Created by: Julius <julius.mariyan@broadcom.com
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == "klish":
        intf_details = get_interface_number_from_name(intf_name)
        cmd = "interface {} {} \n".format(intf_details["type"],intf_details["number"])
        if config.lower() == "yes":
            if "map_type" in kwargs and "map_name" in kwargs:
                cmd += "qos-map {} {} \n".format(kwargs["map_type"],kwargs["map_name"])
        else:
            if "map_type" in kwargs:
                cmd += "no qos-map {} \n".format(kwargs["map_type"])
        cmd += "exit"
    else:
        st.log("support for UI type {} yet to be added".format(cli_type))
        return False
    return st.config(dut, cmd, type=cli_type)
