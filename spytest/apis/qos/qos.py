import re
import os
import json
from spytest import st
from apis.system.rest import get_rest
import apis.system.interface as Intf
import apis.system.basic as basic_obj
from apis.system.switch_configuration import show_running_config
from utilities.common import filter_and_select, kwargs_to_dict_list
from utilities.utils import get_interface_number_from_name, get_supported_ui_type_list
from apis.system.rest import config_rest, delete_rest
from utilities.common import get_query_params
errors = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']

try:
    import apis.yang.codegen.messages.qos as umf_qos
    import apis.yang.codegen.messages.qos_private.QosPrivateRpc as umf_qosp
    from apis.yang.utils.common import Operation
    from apis.yang.codegen.yang_rpc_service import YangRpcService
except ImportError:
    pass


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def verify_qos_queue_counters(dut, port, queue_name, param_list, val_list, tol_list, **kwargs):
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
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        qos_obj = umf_qos.Qos()
        intf_obj = umf_qos.Interface(InterfaceId=port, Qos=qos_obj)
        queue_name = re.findall('[0-9]+', queue_name)
        queue_name = port + ":" + queue_name[0]
        queue_obj = umf_qos.OutputQueue(Name=queue_name, Interface=intf_obj)
        output = queue_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        output = output.payload['openconfig-qos:queue']
        return parse_qos_queue_counters(output, queue_name, param_list, val_list, tol_list)
    else:
        fil_out = Intf.show_queue_counters(dut, port, queue_name, cli_type=cli_type)
        if not fil_out:
            st.error('queue: {} not found in show output'.format(queue_name))
            return False
        else:
            fil_out = fil_out[0]
        for param, val, tol in zip(param_list, val_list, tol_list):
            try:
                fil_out[param] = re.sub(",", "", fil_out[param])
                int(fil_out[param])
            except ValueError:
                st.error('cannot get integer value from obtained string: {}'.format(fil_out[param]))
                return False
            if int(fil_out[param]) <= int(val) + int(tol) and int(fil_out[param]) >= int(val) - int(tol):
                st.log('obtained value: {} is in the range b/w {} and {} as expected for param: {}'
                       'in queue: {}'.format(int(fil_out[param]), int(val) - int(tol),
                                             int(val) + int(tol), param, queue_name))
            else:
                st.error('obtained value: {} is NOT in the range b/w {} and {} for param: {}'
                         'in queue: {}'.format(int(fil_out[param]), int(val) - int(tol),
                                               int(val) + int(tol), param, queue_name))
                success = False
        return True if success else False


def parse_qos_queue_counters(output, queue_name, param_list, val_list, tol_list):
    result = True
    for param in param_list:
        param_dict = {'pkts_count': 'transmit-pkts', 'pkts_drop': 'dropped-pkts',
                      'pkts_rate': 'transmit-pkts-per-second'}
    for elem in output:
        if elem['name'] == queue_name:
            index = output.index(elem)
            for param, val, tol in zip(param_list, val_list, tol_list):
                if param in param_dict:
                    key = param_dict[param]
                    obt_val = output[index]['state'][key]
                    if int(obt_val) <= int(val) + int(tol) and int(obt_val) >= int(val) - int(tol):
                        st.log('obtained value: {} is in the range b/w {} and {} as expected for param: {} '
                               'in queue: {}'.format(int(obt_val), int(val) - int(tol),
                                                     int(val) + int(tol), param_dict[param], queue_name))
                    else:
                        st.error('obtained value: {} is NOT in the range b/w {} and {} for param: {} '
                                 'in queue: {}'.format(int(obt_val), int(val) - int(tol),
                                                       int(val) + int(tol), param_dict[param], queue_name))
                        result = False
                else:
                    st.error("kindly add argument {} in API \"parse_qos_queue_counters\"".format(param))
                    return False
        else:
            st.error("Output NOT found for queue {}".format(queue_name))
            return False
    return result


def clear_qos_queue_counters(dut):
    '''
    :param dut: DUT name where CLI to be executed
    :type dut: string
    :return: True/False  True - Success ; False - Failure
    usage:
        clear_qos_queue_counters(dut1)

    Created by: Julius <julius.mariyan@broadcom.com
    '''
    return True if st.show(dut, 'show queue counters --clear', skip_tmpl=True) else False


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
    data = {map_name: "[" + map_name.upper() + "|" + obj_name + "]"}
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


def show_qos_config(dut, map_name, table=None, **kwargs):
    '''
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param map_name: qos map type for example dscp-tc, dot1p-tc
    :param table: qos map name for example "ROCE"
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "klish":
        command = "show qos map {}".format(map_name)
        output = st.show(dut, command, type=cli_type)
        if table:
            return filter_and_select(output, None, match={'table': table})
        return output
    return []


def show_qos_interface(dut, portname, **kwargs):
    '''
    :param dut:
    :param port: port_name
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "klish":
        command = "show qos interface {}".format(portname)
        output = st.show(dut, command, type=cli_type)

    if 'arg' in kwargs and kwargs['arg'] == 'all':
        return output[0]
    elif 'arg' in kwargs:
        for k in ['scheduler_policy', 'dscp_to_tc_map', 'dot1p_to_tc_map', 'tc_to_queue_map',
                  'tc_to_pg_map', 'tc_to_dscp_map', 'tc_to_dot1p_map', 'pfc_to_queue_map',
                  'pfc_asymmetric', 'pfc_priority', 'action', 'detectiontime', 'restorationtime']:
            if kwargs['arg'] == k:
                return {k: output[0][k]}
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
    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos()
        dscp_obj = umf_qos.DscpMap(Name=map_name, Qos=qos_obj)
        if "map_del" in kwargs:
            return dscp_obj.unConfigure(dut, cli_type=cli_type)
        else:
            dscp_obj.configure(dut, operation=Operation.CREATE, cli_type=cli_type)
            dscp_obj.DscpMap = dscp_obj
            if config.lower() == "yes":
                for dscp, tc in kwargs['dscp_tc'].items():
                    dscp_tc_dict = {"Dscp": int(dscp), "FwdGroup": str(tc)}
                    dscp_entry_obj = umf_qos.DscpMapEntry(**dscp_tc_dict)
                    dscp_obj.add_DscpMapEntry(dscp_entry_obj)
                dscp_obj.configure(dut, cli_type=cli_type)
                dscp_entry_obj.configure(dut, operation=Operation.CREATE, cli_type=cli_type)
            else:
                for dscp in kwargs['dscp_list']:
                    dscp_entry_obj = umf_qos.DscpMapEntry(Dscp=int(dscp), DscpMap=dscp_obj)
                    dscp_entry_obj.unConfigure(dut, cli_type=cli_type)
    elif cli_type == "klish":
        if "map_del" in kwargs:
            cmd = "no qos map dscp-tc {} \n".format(map_name)
            return st.config(dut, cmd, type=cli_type)
        else:
            cmd = "qos map dscp-tc {} \n".format(map_name)
        if config.lower() == "yes":
            for dscp, tc in kwargs['dscp_tc'].items():
                cmd += "dscp {} traffic-class {} \n".format(dscp, tc)
        else:
            for dscp in kwargs['dscp_list']:
                cmd += "no dscp {} \n".format(dscp)
        cmd += "exit"
        return st.config(dut, cmd, type=cli_type)
    else:
        st.log("support for UI type {} yet to be added".format(cli_type))
        return False


def bind_qos_map(dut, intf_name, config="yes", **kwargs):
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
    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos()
        qosbind_obj = umf_qos.Interface(InterfaceId=intf_name, Qos=qos_obj)
        if config.lower() == "yes":
            if kwargs["map_type"] == "dot1p-tc":
                qosbind_obj.Dot1pToForwardingGroup = kwargs["map_name"]
            elif kwargs["map_type"] == "dscp-tc":
                qosbind_obj.DscpToForwardingGroup = kwargs["map_name"]
            elif kwargs["map_type"] == "tc-dot1p":
                qosbind_obj.ForwardingGroupToDot1p = kwargs["map_name"]
            elif kwargs["map_type"] == "tc-dscp":
                qosbind_obj.ForwardingGroupToDscp = kwargs["map_name"]
            qosbind_obj.configure(dut, operation=Operation.CREATE, cli_type=cli_type)
        else:
            qosbind_obj.unConfigure(dut, cli_type=cli_type)
    elif cli_type == "klish":
        intf_details = get_interface_number_from_name(intf_name)
        cmd = "interface {} {} \n".format(intf_details["type"], intf_details["number"])
        if config.lower() == "yes":
            if "map_type" in kwargs and "map_name" in kwargs:
                cmd += "qos-map {} {} \n".format(kwargs["map_type"], kwargs["map_name"])
        else:
            if "map_type" in kwargs:
                cmd += "no qos-map {} \n".format(kwargs["map_type"])
        cmd += "exit"
        return st.config(dut, cmd, type=cli_type)
    else:
        st.log("support for UI type {} yet to be added".format(cli_type))
        return False


def config_buffer_init(dut, **kwargs):
    '''
    Author: Anguluri Saikrishna (anguluri.saikrishna@broadcom.com)
    Purpose:Initialize the buffer defaults based on platform specific values (ingress/ingress buffer pools size, buffer profile, priority-group, queue)
    :param dut:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    chip = basic_obj.get_hwsku(dut)
    if "Z9432f" in chip or "AS9736" in chip:
        wait_time = "130"
    else:
        wait_time = "40"
    min_time = kwargs.pop('min_time', int(os.getenv("SONIC_ROCE_ENABLE_MIN_TIME", wait_time)))
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if 'return_output' in kwargs:
        cli_type = 'klish'
    result = show_running_config(dut, module="| grep lossless")
    if "buffer init lossless" in result and 'return_output' not in kwargs and config == 'yes':
        st.banner("WARNING: buffer init is already configured on the box so skipping re-config")
        return True
    elif "buffer init lossless" not in result and 'return_output' not in kwargs and config == 'no':
        st.banner("WARNING: buffer init is not enabled on the box so skipping roce disable application")
        return True
    if cli_type in get_supported_ui_type_list():
        service = YangRpcService()
        rpc = umf_qosp.QosBufferConfigRpc()
        rpc.Input.operation = "INIT" if config == 'yes' else "CLEAR"
        result = service.execute(dut, rpc, timeout=60, cli_type=cli_type, expect_reboot=True, min_time=min_time)
        if not result.ok():
            st.log('test_step_failed: BUFFER INIT failed : {}'.format(result.data))
            return False
        else:
            return True
    elif cli_type == 'klish':
        command = "buffer init lossless" if config == 'yes' else 'no buffer init'
        response = st.config(dut, command, type=cli_type, confirm='y', expect_reboot=True, min_time=min_time)
        if 'return_output' in kwargs:
            return response
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls["buffer_init"]
        operation = "INIT" if config == "yes" else "CLEAR"
        config_data = {"openconfig-qos-private:input": {"operation": operation}}
        if not config_rest(dut, rest_url=url, http_method="post", json_data=config_data):
            st.error("Failed to {} qos buffer confiuration".format(operation))
            return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True


def config_roce(dut, **kwargs):
    '''
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    Purpose: Configuring roce enable or roce disable command globaly
    :param dut:
    :param config: 'yes' for 'roce enable' CLI OR 'no' for 'no roce enable' CLI
    :param config: 'yes' & force_defaults (optional arg) : 'y' for 'roce enable force-defaults' CLI
    :return:
    Example: config_roce(dut, config="yes")
             config_roce(dut, config="yes",force_defaults="y")
             config_roce(dut, config="no")
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    skip_error_check = kwargs.pop('skip_error_check', True)
    expect_reboot = kwargs.pop('expect_reboot', True)
    chip = basic_obj.get_hwsku(dut)
    if "Z9432f" in chip or "AS9736" in chip:
        wait_time = "130"
    else:
        wait_time = "40"
    min_time = kwargs.pop('min_time', int(os.getenv("SONIC_ROCE_ENABLE_MIN_TIME", wait_time)))
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if 'return_output' in kwargs:
        cli_type = 'klish'
    result = show_running_config(dut, module="| grep roce")
    if "roce enable" in result and 'return_output' not in kwargs and config == 'yes':
        st.banner("WARNING: roce enable is already configured on the box so skipping re-config")
        return True
    elif "roce enable" not in result and 'return_output' not in kwargs and config == 'no':
        st.banner("WARNING: roce is not enabled on the box so skipping roce disable application")
        return True

    if cli_type in get_supported_ui_type_list():
        service = YangRpcService()
        rpc = umf_qosp.QosRoceConfigRpc()
        rpc.Input.force = True if config == 'yes' and 'force_defaults' in kwargs else False
        rpc.Input.operation = "ENABLE" if config == 'yes' else "DISABLE"
        result = service.execute(dut, rpc, timeout=60, cli_type=cli_type, expect_reboot=True, min_time=min_time)
        if not result.ok():
            st.log('test_step_failed: ROCE ENABLE failed : {}'.format(result.data))
            return False
        else:
            return True
    elif cli_type == 'klish':
        commands = list()
        if config == 'yes':
            if 'force_defaults' in kwargs:
                commands.append("roce enable force-defaults")
            else:
                commands.append('roce enable')
        else:
            commands.append('no roce enable')
        response = st.config(dut, commands, type=cli_type, confirm='y',
                             expect_reboot=expect_reboot, min_time=min_time,
                             skip_error_check=skip_error_check)
        if 'return_output' in kwargs:
            return response
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls["roce_config"]
        roce_obj = {}
        roce_obj['operation'] = "ENABLE" if config == 'yes' else "DISABLE"
        if 'force_defaults' in kwargs and config == 'yes':
            roce_obj["force"] = True
        config_data = {"openconfig-qos-private:input": roce_obj}
        if not config_rest(dut, rest_url=url, http_method="post", json_data=config_data):
            st.error("Failed to {} ROCE".format(roce_obj['operation']))
            return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True


def config_qos_buffer_pool(dut, **kwargs):
    '''
    Author: Anguluri Saikrishna (anguluri.saikrishna@broadcom.com)
    Purpose:Configuring buffer pool for lossless or lossy.
    This api will apply the default buffer pool config specific to platfrom saved in spyest datastore
    :param dut:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    pool_name = kwargs.get('pool_name', 'ingress_lossless_pool')
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if 'user_shared_hr_size' in kwargs:
        shared_hr_size = kwargs['user_shared_hr_size']
    else:
        constants = st.get_datastore(dut, "constants", kwargs['hwsku'].lower())
        if not constants.get('INGRESS_LOSSLESS_POOL_SIZE'):
            st.error("INGRESS_LOSSLESS_POOL_SIZE is not found in constants for hwsku: {}".format(kwargs['hwsku']))
            return False
        shared_hr_size = constants['INGRESS_LOSSLESS_POOL_SIZE']
    if cli_type == 'klish':
        command = "buffer pool {} shared-headroom-size {}".format(pool_name, shared_hr_size) if config == 'yes' else 'no buffer pool {}'.format('pool_name')
        response = st.config(dut, command, type=cli_type)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if config == "yes":
            url = rest_urls["buffer_pool"]
            config_data = {"openconfig-qos-buffer:buffer-pools": {"buffer-pool": [{"config": {"xoff": str(shared_hr_size)}, "name": pool_name}]}}
            if not config_rest(dut, rest_url=url, http_method="post", json_data=config_data):
                st.error("Failed to configure qos buffer pool")
                return False
        else:
            url = rest_urls["delete_buffer_pool"].format(pool_name)
            if not delete_rest(dut, rest_url=url):
                st.error("Failed to delete qos buffer pool")
                return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True


def config_buffer_pool(dut, **kwargs):
    '''
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    Purpose:Configuring buffer pool for lossless or lossy.
    This api will apply the user defined buffer pool config specified by the user
    :param dut:
    :param shared_hr_size:
    :param xoff:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    config = kwargs.get('config', 'yes')
    pool_name = kwargs.get('pool_name', 'ingress_lossless_pool')

    if cli_type in get_supported_ui_type_list():
        bf_obj = {}
        if 'shared_hr_size' in kwargs:
            bf_obj['Size'] = kwargs['shared_hr_size']
        if 'xoff' in kwargs:
            bf_obj['Xoff'] = kwargs['xoff']
        b_obj = umf_qos.BufferBufferPool(Name=pool_name, **bf_obj)
        if config == 'yes':
            result = b_obj.configure(dut, operation=Operation.CREATE, cli_type=cli_type)
        else:
            result = b_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Buffer Pool config failed : {}'.format(result.data))
            return False
        else:
            return True
    elif cli_type == 'klish':
        command = "buffer pool {} shared-headroom-size {}".format(pool_name,
                                                                  kwargs['shared_hr_size']) if config == 'yes' else 'no buffer pool {}'.format('pool_name')
        response = st.config(dut, command, type=cli_type)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False


def config_buffer_profile(dut, profile_name, **kwargs):
    '''
    Author: Anguluri Saikrishna (anguluri.saikrishna@broadcom.com)
    Changed by: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    Purpose:Configuring buffer profile for lossless-buffer-profile or lossy-buffer-profile.
    :param dut:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    size = kwargs.get('size', '0')
    pool_name = kwargs.get('pool_name', 'ingress_lossless_pool')
    if config == 'yes':
        if not (kwargs.get('threshold_value')):
            st.error("Mandatory paramters threshold_value is missing with config mode 'yes'")
            return False
    threshold_mode = kwargs.get('threshold_mode', 'static')
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if threshold_mode == 'static':
        threshold_value = 'static-threshold ' + kwargs.get('threshold_value')
    elif threshold_mode == 'dynamic':
        threshold_value = 'dynamic-threshold ' + kwargs.get('threshold_value')
        if 'pause_threshold' in kwargs:
            threshold_value += ' pause-threshold ' + kwargs.get('pause_threshold')
        if 'resume_threshold' in kwargs:
            threshold_value += ' resume-threshold ' + kwargs.get('resume_threshold')
        if 'resume_offset_threshold' in kwargs:
            threshold_value += ' resume-offset-threshold ' + kwargs.get('resume_offset_threshold')
    else:
        st.error("Unsupported threshold-mode: {}".format(threshold_mode))
        return False

    if cli_type in get_supported_ui_type_list():
        bf_obj = {}
        if threshold_mode == 'static':
            bf_obj['StaticThreshold'] = kwargs['threshold_value']
        if threshold_mode == 'dynamic':
            bf_obj['DynamicThreshold'] = kwargs.get('threshold_value')
            if 'pause_threshold' in kwargs:
                bf_obj['PauseThreshold'] = kwargs['pause_threshold']
            if 'resume_threshold' in kwargs:
                bf_obj['ResumeThreshol'] = kwargs['resume_threshold']
            if 'resume_offset_threshold' in kwargs:
                bf_obj['ResumeOffsetThreshold'] = kwargs['resume_offset_threshold']
        b_obj = umf_qos.BufferProfile(Name=profile_name, Pool=pool_name, Size=size, Type="INGRESS", **bf_obj)
        if config == 'yes':
            result = b_obj.configure(dut, operation=Operation.CREATE, cli_type=cli_type)
        else:
            result = b_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Buffer Profile config failed : {}'.format(result.data))
            return False
        else:
            return True
    elif cli_type == 'klish':
        command = "buffer profile {} {} {} {}".format(profile_name, pool_name, size,
                                                      threshold_value) if config == 'yes' else 'no buffer profile {}'.format(profile_name)
        response = st.config(dut, command, type=cli_type)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False


def config_buffer_profile_map(dut, interface, maptype=None, **kwargs):
    '''
    Author: Anguluri Saikrishna (anguluri.saikrishna@broadcom.com)
    Purpose: This will help in association and dissociation of queue with buffer profile.
    :param dut:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    profile_name = kwargs.get('profile_name')
    pg_value_range = kwargs.get('pg_value_range')
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type == 'klish':
        commands = list()
        if maptype == "queue":
            commands.append("interface {}".format(interface))
            commands.append("buffer queue {} {}".format(pg_value_range, profile_name) if config == 'yes' else 'no buffer queue {}'.format(pg_value_range))
            commands.append("exit")
        else:
            commands.append("interface {}".format(interface))
            commands.append("buffer priority-group {} {}".format(pg_value_range, profile_name) if config == 'yes' else 'no buffer priority-group {}'.format(pg_value_range))
            commands.append("exit")
        response = st.config(dut, commands, type=cli_type)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        operation = "INIT" if config == "yes" else "CLEAR"
        url = rest_urls["buffer_pg"].format(interface, pg_value_range)
        config_data = {"openconfig-qos-buffer:buffer-priority-group": [{"ifname": interface, "priority-group": pg_value_range, "config": {"ifname": interface, "priority-group": pg_value_range, "profile": profile_name}}]}
        if not config_rest(dut, rest_url=url, http_method="post", json_data=config_data):
            st.error("Failed to {} qos buffer confiuration".format(operation))
            return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True


def enable_disable_default_lossless_profile(dut, interface, **kwargs):
    '''
    Author: Anguluri Saikrishna (anguluri.saikrishna@broadcom.com)
    Purpose:This avoids creation of buffer profile based on cable length and speed by introducing default_lossless_buffer_profile in PORT table.
    :param dut:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type == 'klish':
        commands = list()
        commands.append("interface {}".format(interface))
        command = "buffer default-lossless-buffer-profile" if config == 'yes' else 'no buffer default-lossless-buffer-profile'
        commands.append(command)
        commands.append("exit")
        response = st.config(dut, commands, type=cli_type)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        pass  # This code will be added after the REST URIs and payload details available
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True


def show_buffer_pool(dut, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    result = list()
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'NON_CONFIG')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        if 'buffer_pool' not in kwargs:
            kwargs['buffer_pool'] = 'ingress_lossless_pool'
        b_obj = umf_qos.BufferBufferPool(Name=kwargs['buffer_pool'])
        output = b_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        response = output.payload['openconfig-qos-buffer:buffer-pool']
        result = parse_qos_buffer_pool(response)
    elif cli_type == 'klish':
        show_command = "show buffer pool"
        result = st.show(dut, show_command, type=cli_type)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return result


def verify_buffer_pool(dut, **kwargs):
    """
    :param dut:
    :param kwargs: buffer_pool : ingress_lossless_pool | egress_lossless_pool
    :param kwargs: mode : static | dynamic
    :param kwargs: type : ingress | egress
    :param kwargs: size : numeric value
    :param kwargs: shared_head_room : numeric value
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos()
        bp_obj = {}
        if 'type' in kwargs:
            bp_obj['Type'] = kwargs['type'].upper()
        if 'mode' in kwargs:
            bp_obj['Mode'] = kwargs['mode'].upper()
        if 'size' in kwargs:
            bp_obj['Size'] = kwargs['size']
        if 'shared_headroom_size' in kwargs:
            bp_obj['Xoff'] = kwargs['shared_headroom_size']
        bp_obj['Qos'] = qos_obj
        b_obj = umf_qos.BufferBufferPool(Name=kwargs['buffer_pool'], **bp_obj)
        result = b_obj.verify(dut, match_subset=True, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify interface WRED Profile: {}'.format(result.data))
            return False
        return True
    elif cli_type == 'klish':
        output = show_buffer_pool(dut, **kwargs)
        ret_val = True
        input_dict_list = kwargs_to_dict_list(**kwargs)
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False
        return ret_val


def show_buffer_profile(dut, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    result = list()
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type == 'klish':
        show_command = "show buffer profile"
        result = st.show(dut, show_command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        pass  # This code will be added after the REST URIs and payload details available
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return result


def verify_buffer_profile(dut, **kwargs):
    """
    :param dut:
    :param kwargs: buffer_profile : egress_lossless_profile | pg_lossless_10000_40m_profile
    :param kwargs: dynamic_threshold : 2 | -2
    :param kwargs: pool : egress_lossless_pool | ingress_lossless_pool
    :param kwargs: size : numeric value
    :param kwargs: static_threshold : numeric value
    :param kwargs: dynamic_threshold : numeric value
    :param kwargs: pause_threshold : numeric value
    :param kwargs: resume_threshold : numeric value
    :param kwargs: resume_offset_threshold : numeric value
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos()
        bf_obj = {}
        if 'type' in kwargs:
            bf_obj['Type'] = kwargs['type'].upper()
        if 'size' in kwargs:
            bf_obj['Size'] = kwargs['size']
        if 'pool' in kwargs:
            bf_obj['Pool'] = kwargs['pool']
        if 'static_threshold' in kwargs:
            bf_obj['StaticThreshold'] = kwargs['static_threshold']
        if 'dynamic_threshold' in kwargs:
            bf_obj['DynamicThreshold'] = kwargs['dynamic_threshold']
        if 'pause_threshold' in kwargs:
            bf_obj['PauseThreshold'] = kwargs['pause_threshold']
        if 'resume_threshold' in kwargs:
            bf_obj['ResumeThreshold'] = kwargs['resume_threshold']
        if 'resume_offset_threshold' in kwargs:
            bf_obj['ResumeOffsetThreshold'] = kwargs['resume_offset_threshold']
        bf_obj['Qos'] = qos_obj
        b_obj = umf_qos.BufferProfile(Name=kwargs['buffer_profile'], **bf_obj)
        result = b_obj.verify(dut, match_subset=True, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify interface WRED Profile: {}'.format(result.data))
            return False
        return True
    elif cli_type == 'klish':
        output = show_buffer_profile(dut, **kwargs)
        ret_val = True
        input_dict_list = kwargs_to_dict_list(**kwargs)
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False
        return ret_val


def show_buffer_interface_priority_group(dut, **kwargs):
    """
    :param dut:
    :param kwargs: intf_name
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    result = list()
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type == 'klish':
        if 'intf_name' in kwargs:
            show_command = "show buffer interface {} priority-group".format(kwargs['intf_name'])
        else:
            show_command = "show buffer interface Ethernet all priority-group"
        result = st.show(dut, show_command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        pass  # This code will be added after the REST URIs and payload details available
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return result


def verify_buffer_interface_priority_group(dut, intf_name, **kwargs):
    """
    :param dut:
    :param intf_name: Ethernet12
    :param kwargs: 'pgroup='0',profile='ingress_lossy_profile'
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list():
        if 'pgroup' in kwargs:
            p_list = []
            for p1 in kwargs['pgroup'].split("-"):
                p_list.append(p1)
            st.banner("Priority-group list to be verified for show buffer interface priority-group {}".format(p_list))
            for pu in p_list:
                if int(pu) > 9:
                    st.banner("show buffer interface priority-group {} not supporting this PG so skipping..".format(pu))
                    return True
                qos_obj = umf_qos.Qos()
                bpg_obj = {}
                if 'profile' in kwargs:
                    bpg_obj['Profile'] = kwargs['profile']
                bpg_obj['PriorityGroup'] = pu
                bpg_obj['Qos'] = qos_obj
                b_obj = umf_qos.BufferPriorityGroup(Ifname=intf_name, **bpg_obj)
                result = b_obj.verify(dut, match_subset=True, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Verify interface WRED Profile: {}'.format(result.data))
                    return False
            return True
        else:
            st.log("priority-group arg pgroup was not so failing.")
            return False
    elif cli_type == 'klish':
        output = show_buffer_interface_priority_group(dut, intf_name=intf_name, **kwargs)
        ret_val = True
        input_dict_list = kwargs_to_dict_list(**kwargs)
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False
        return ret_val


def show_buffer_interface_queue(dut, **kwargs):
    """
    :param dut:
    :param kwargs: intf_name
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    result = list()
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type == 'klish':
        if 'intf_name' in kwargs:
            show_command = "show buffer interface {} queue".format(kwargs['intf_name'])
        else:
            show_command = "show buffer interface Ethernet all queue"
        result = st.show(dut, show_command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        pass  # This code will be added after the REST URIs and payload details available
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return result


def verify_buffer_interface_queue(dut, intf_name, **kwargs):
    """
    :param dut:
    :param intf_name: Ethernet12
    :param kwargs: 'queue': '0-2', 'profile': 'egress_lossy_profile'
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos()
        biq_obj = {}
        if 'profile' in kwargs:
            biq_obj['Profile'] = kwargs['profile']
        if 'queue' in kwargs:
            if "-" in kwargs['queue'] or "," in kwargs['queue']:
                q_list = []
                for q1 in kwargs['queue'].split(","):
                    for q2 in q1.split("-"):
                        q_list.append(q2)
                st.log("Queue list to be verified for show buffer interface queue is {}".format(q_list))
                for qu in q_list:
                    if int(qu) > 9:
                        st.banner("show buffer interface queue {} not supporting multicast queue so skipping..".format(qu))
                        return True
                    biq_obj['Queue'] = qu
                    biq_obj['Qos'] = qos_obj
                    b_obj = umf_qos.BufferQueue(Ifname=intf_name, **biq_obj)
                    result = b_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Verify interface WRED Profile: {}'.format(result.data))
                        return False
                return True
            else:
                if int(kwargs['queue']) > 9:
                    st.banner("show buffer interface queue {} not supporting multicast queue so skipping..".format(kwargs['queue']))
                    return True
                biq_obj['Queue'] = kwargs['queue']
        biq_obj['Qos'] = qos_obj
        b_obj = umf_qos.BufferQueue(Ifname=intf_name, **biq_obj)
        result = b_obj.verify(dut, match_subset=True, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify interface WRED Profile: {}'.format(result.data))
            return False
        return True
    elif cli_type == 'klish':
        output = show_buffer_interface_queue(dut, intf_name=intf_name, **kwargs)
        ret_val = True
        input_dict_list = kwargs_to_dict_list(**kwargs)
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False
        return ret_val


def clear_queue_wred_ecn_counters(dut, intf_name=""):
    '''
    :param dut: DUT name where CLI to be executed
    :type dut: string
    :param intf_name: interface where wred policy counters to be cleared
    :return: True/False  True - Success ; False - Failure
    usage: clear_queue_wred_ecn_counters(dut1)
    GNMI support is not there for this clear command so far so forced to klish
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    '''
    intf_details = get_interface_number_from_name(intf_name)
    cmd = "clear queue wred-ecn counters"
    if intf_name != "":
        cmd += " interface {} {}".format(intf_details["type"], intf_details["number"])
    return st.show(dut, cmd, type="klish", skip_tmpl=True)


def verify_queue_wred_ecn_counters_interface(dut, intf_name, **kwargs):
    '''
    verifies QOS queue counters in the CLI show qos queue counters
    :param dut: Device name where the command to be executed
    :param intf_name: interface where wred policy counters to be verified
    :return: True/False  True - success case; False - Failure case

    usage:  verify_queue_wred_ecn_counters_interface(dut1,'Ethernet0',txq="UC2",ecn_mpkt_bytes="107207451904")
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    '''
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if "return_output" in kwargs:
        cli_type = 'klish'

    intf_details = get_interface_number_from_name(intf_name)
    cmd = "interface {} {}".format(intf_details["type"], intf_details["number"])

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'NON_CONFIG')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        qos_obj = umf_qos.Qos()
        intf_obj = umf_qos.Interface(InterfaceId=intf_name, Qos=qos_obj)
        queue = kwargs['txq'].split('UC')[1] if "UC" in kwargs['txq'] else kwargs['txq']
        queue_name = intf_name + ":" + queue
        queue_obj = umf_qos.OutputQueue(Name=queue_name, Interface=intf_obj)
        result = queue_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        response = result.payload['openconfig-qos:queue']
        output = parse_qos_queue_wred_counters(response, "UC" + queue)
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        queue = kwargs['txq'].split('UC')[1] if "UC" in kwargs['txq'] else kwargs['txq']
        url = rest_urls['show_intf_txq'].format(intf_name, intf_name, queue)
        response = get_rest(dut, rest_url=url)
        output = parse_show_intf_txq(response)
        output[0]['txq'] = kwargs['txq']
    elif cli_type in ['klish']:
        output = st.show(dut, "show queue wred-ecn counters {}".format(cmd), type=cli_type)

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        for out in output:
            if out['txq'] == kwargs['txq']:
                return out

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            for output_dict in output:
                for key in input_dict:
                    if key not in ["ecn_mpkt_bytes", "wred_dpkt_count", "ecn_mpkt_count", "txq"]:
                        st.error("Arg {} not matched".format(key))
                        return False
                    if key != "txq":
                        if input_dict["txq"] == output_dict["txq"]:
                            if int(input_dict[key]) <= int(output_dict[key]):
                                st.log("PASS DUT {} -> No of {} observed {} >= expected {} in txq {}".format(dut,
                                                                                                             key, output_dict[key], input_dict[key], input_dict["txq"]))
                            else:
                                st.log("FAIL DUT {} -> No of {} observed {} not >= expected {} in txq {}".format(dut,
                                                                                                                 key, output_dict[key], input_dict[key], input_dict["txq"]))
                                ret_val = False

    return ret_val


def verify_interface_queue_wred_profile(dut, intf_name, queue, **kwargs):
    '''
    verifies QOS queue counters in the CLI show qos queue counters
    :param dut: Device name where the command to be executed
    :param intf_name: interface where wred policy counters to be verified
    :return: True/False  True - success case; False - Failure case

    usage:  verify_interface_queue_wred_profile(dut1,'Ethernet0',queue="2",wred_policy="WRED")
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    '''
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    intf_details = get_interface_number_from_name(intf_name)
    cmd = "interface {} {} queue {}".format(intf_details["type"], intf_details["number"], queue)
    if "return_output" in kwargs:
        cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos()
        queue_obj = {}
        if 'wred_policy' in kwargs:
            queue_obj['WredProfile'] = str(kwargs['wred_policy'])
        queue_obj = umf_qos.QosQueue(Name='{}:{}'.format(intf_name, queue), Qos=qos_obj, **queue_obj)
        result = queue_obj.verify(dut, match_subset=True, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify interface WRED Profile: {}'.format(result.data))
            return False
        return True
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        native_intf_name = Intf.get_native_interface_name(dut, if_name=intf_name, cli_type="klish")
        url = rest_urls['show_queue_wred'].format(native_intf_name, queue)
        response = get_rest(dut, rest_url=url)
        output = parse_queue_wred(response)
    elif cli_type in ['klish']:
        output = st.show(dut, "show qos {}".format(cmd), type=cli_type)

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return output

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    for input_dict in input_dict_list:
        entries = filter_and_select(output, None, match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            ret_val = False

    return ret_val


def verify_qos_wred_policy(dut, policy_name, **kwargs):
    '''
    verifies QOS queue counters in the CLI show qos queue counters
    :param dut: Device name where the command to be executed
    :param policy_name: Name of WRED policy
    :param green_min_threshold: green pkt minimum threshold in KB
    :param green_max_threshold: green pkt maximum threshold in KB
    :param green_drop_probability: Maximum drop rate
    :param ecn_mode: green|none
    :return: True/False  True - success case; False - Failure case

    usage:  verify_qos_wred_policy(dut1,'policy1',ecn_mode="ecn_none",green_min_threshold="100")
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    '''
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if "return_output" in kwargs:
        cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos()
        wred_dict = {}
        if 'green_min_threshold' in kwargs:
            if int(kwargs['green_min_threshold']) == 1048:
                wred_dict['GreenMinThreshold'] = str(int(kwargs['green_min_threshold']) * 1000 + 576)
            else:
                wred_dict['GreenMinThreshold'] = str(int(kwargs['green_min_threshold']) * 1000)
        if 'green_max_threshold' in kwargs:
            if int(kwargs['green_max_threshold']) == 2097:
                wred_dict['GreenMaxThreshold'] = str(int(kwargs['green_max_threshold']) * 1000 + 152)
            else:
                wred_dict['GreenMaxThreshold'] = str(int(kwargs['green_max_threshold']) * 1000)
        if 'green_drop_probability' in kwargs:
            wred_dict['GreenDropProbability'] = str(kwargs['green_drop_probability'])
        if 'ecn_mode' in kwargs:
            wred_dict['WredGreenEnable'] = True
            wred_dict['Ecn'] = "ECN_GREEN" if kwargs['ecn_mode'] == 'ecn_green' else "ECN_NONE"
        wred_obj = umf_qos.WredProfile(Name=policy_name, Qos=qos_obj, **wred_dict)
        result = wred_obj.verify(dut, match_subset=True, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify WRED Profile: {}'.format(result.data))
            return False
        return True
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['show_wred_config'].format(policy_name)
        response = get_rest(dut, rest_url=url)
        result = parse_show_wred_config(response)
    elif cli_type in ['klish']:
        result = st.show(dut, "show qos wred-policy {}".format(policy_name), type=cli_type)

    if len(result) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return result

    ret_val = False
    for rlist in result:
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key]:
                count = count + 1
        if len(kwargs) == count:
            ret_val = True
            for key in kwargs:
                st.log("Match: Match key {} found => {} : {}".format(key, kwargs[key], rlist[key]))
            break
        else:
            for key in kwargs:
                if rlist[key] == kwargs[key]:
                    st.log("Match: Match key {} found => {} : {}".format(key, kwargs[key], rlist[key]))
                else:
                    st.log("No-Match: Match key {} NOT found => {} : {}".format(key, kwargs[key], rlist[key]))
            st.log("\n")

    if ret_val is False:
        st.log("Fail: Not Matched all args in passed dict {} from parsed dict".format(kwargs))

    return ret_val


def parse_show_wred_config(response):
    dict1 = response["output"]
    if 'openconfig-qos:config' not in dict1:
        return []
    dict1 = dict1['openconfig-qos:config']
    dict2 = {'green-drop-probability': 'green_drop_probability', 'ecn': 'ecn_mode', 'green-min-threshold': 'green_min_threshold',
             'green-max-threshold': 'green_max_threshold', 'name': 'policy_name'}
    if 'wred-green-enable' in dict1:
        del dict1['wred-green-enable']
    output = {}
    for key in dict2.keys():
        if key in dict1:
            if key == 'ecn':
                dict1[key] = dict1[key].lower()
            if key in ['green-min-threshold', 'green-max-threshold']:
                dict1[key] = str(int(int(dict1[key]) / 1000))
            output[dict2[key]] = dict1[key]
    return [output]


def parse_show_intf_txq(response):
    dict1 = response["output"]
    if 'openconfig-qos:queue' not in dict1:
        return []
    dict1 = dict1['openconfig-qos:queue'][0]['state']
    dict2 = {'wred-dropped-pkts': 'wred_dpkt_count', 'ecn-marked-pkts': 'ecn_mpkt_count',
             'ecn-marked-octets': 'ecn_mpkt_bytes'}
    output = {}
    for key in dict2.keys():
        if key in dict1:
            output[dict2[key]] = dict1[key]
    return [output]


def parse_queue_wred(response):
    dict1 = response["output"]
    if 'openconfig-qos:config' not in dict1:
        return []
    output = {}
    if 'openconfig-qos:config' in dict1 and 'wred-profile' in dict1['openconfig-qos:config']:
        output['wred_policy'] = dict1['openconfig-qos:config']['wred-profile']
    return [output]


def parse_qos_queue_wred_counters(response, queue):
    dict1 = response[0]['state']
    dict2 = {'wred-dropped-pkts': 'wred_dpkt_count', 'ecn-marked-pkts': 'ecn_mpkt_count', 'ecn-marked-octets': 'ecn_mpkt_bytes'}
    output = {}
    for key in dict2.keys():
        if key in dict1:
            output[dict2[key]] = dict1[key]
        else:
            output[dict2[key]] = '0'
    output['txq'] = queue
    return [output]


def parse_qos_buffer_pool(response):
    dict1 = response[0]['state']
    dict2 = {'xoff': 'shared_headroom_size', 'name': 'buffer_pool'}
    output = {}
    for key in dict1.keys():
        if key in dict2.keys():
            output[dict2[key]] = dict1[key]
        else:
            if isinstance(dict1[key], str):
                output[key] = dict1[key].lower()
            else:
                output[key] = dict1[key]
    return [output]


def verify_qos_interface_Ethernet_all(dut, interface, **kwargs):
    """
    :param dut:
    :param interface (mandetory)
    :param kwargs: scheduler_policy, dscp_fg, fg_queue etc.
    :return:
    """
    port = 'Eth all' if st.get_ifname_type(dut) in ['alias', 'std-ext'] else 'Ethernet all'
    output = st.show(dut, "show qos interface {}".format(port), type="klish")
    for entry in output:
        for k in entry:
            if entry[k].isspace():
                i = output.index(entry)
                output[i][k] = ""
    ret_val = True
    kwargs['interface'] = interface
    input_dict_list = kwargs_to_dict_list(**kwargs)
    for input_dict in input_dict_list:
        entries = filter_and_select(output, None, match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            ret_val = False
    return ret_val


def init_default_config(dut):
    if st.is_feature_supported("base-config-roce", dut):
        config_roce(dut, config='yes', skip_error_check=True)
