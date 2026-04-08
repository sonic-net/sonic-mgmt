# This file contains the list of API's which performs VLAN operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
import re
import json

from spytest import st

from apis.system.rest import config_rest, delete_rest, get_rest, rest_status

from utilities.common import random_vlan_list, filter_and_select, make_list, get_query_params
from utilities.utils import get_interface_number_from_name, get_portchannel_name_for_rest
from utilities.utils import is_a_single_intf, segregate_intf_list_type, get_supported_ui_type_list, convert_intf_name_to_component
from utilities.utils import get_random_space_string

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.vlan_ext.VlanExt as umf_vlan_ext
    import apis.yang.codegen.messages.network_instance as umf_ni
    import apis.yang.codegen.bulk as umf_bulk
    from apis.yang.utils.common import Operation
except ImportError:
    pass

http_method = "patch"


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def _has_vlan_range(dut):
    if not st.is_feature_supported("vlan-range", dut):
        return False
    return True


def create_vlan(dut, vlan_list, cli_type='', **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To create list of VLANs.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_list:
    :param cli_type:
    :return:
    """
    conn_index = kwargs.get("conn_index", None)
    st.log("Creating vlan {}".format(vlan_list))
    vlan_li = map(str, vlan_list) if isinstance(vlan_list, list) else [vlan_list]
    commands = list()
    cmd_edit_list = list()
    for each_vlan in vlan_li:
        if cli_type in get_supported_ui_type_list():
            #            operation = Operation.UPDATE
            # operation = Operation.CREATE
            intf_obj = umf_intf.Interface(Name='Vlan' + str(each_vlan))
            cmd_edit_list.append(umf_bulk.Edit(intf_obj, operation=Operation.CREATE))
            '''
            result = intf_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Creation of Vlan {}'.format(result.data))
                return False
            '''
        elif cli_type == "click":
            commands.append("config vlan add {}".format(each_vlan))
        elif cli_type == "klish":
            commands.append("interface Vlan {}".format(each_vlan))
            commands.append('exit')
        elif cli_type in ["rest-put", "rest-patch"]:
            vlan_data = dict()
            vlan_data["openconfig-interfaces:interface"] = list()
            vlan_data["openconfig-interfaces:interface"].append({"name": "Vlan{}".format(each_vlan), "config": {"name": "Vlan{}".format(each_vlan)}})
            url = st.get_datastore(dut, "rest_urls")["config_interface"]
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=vlan_data):
                return False
        else:
            st.log("Unsupported CLI TYPE {}".format(cli_type))
            return False
    if cmd_edit_list:
        result = umf_bulk.bulkRequest(dut, edits=cmd_edit_list, cli_type=cli_type, **kwargs)
        if not result.ok():
            st.log('test_step_failed: Creation of Vlan {}'.format(result.data))
            return False
    if commands:
        st.config(dut, commands, type=cli_type, conn_index=conn_index)
    return True


def delete_vlan(dut, vlan_list, cli_type='', remove_vlan_mapping=True, verify_delete=True, **kwargs):
    """
    To delete list of VLANs.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_list:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Delete vlan {}".format(vlan_list), dut=dut)
    vlan_li = map(str, vlan_list) if isinstance(vlan_list, list) else [vlan_list]
    cmd_edit_list = list()
    commands = list()
    rest_fail_status = False
    skip_error_report = kwargs.pop("skip_error_report", False)
    try:
        for each_vlan in vlan_li:
            if remove_vlan_mapping:
                tmp_cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
                st.warn('Need to delete the vlan-port mapping before deleting vlans to avoid cleanup issue - rel320')
                show_vlan_op = show_vlan_config(dut, vlan_id=each_vlan, cli_type=tmp_cli_type)
                for vlan_port in show_vlan_op:
                    if vlan_port['member'] and str(vlan_port['vid']) == str(each_vlan):
                        tagging_mode = True if vlan_port['mode'] == 'T' or vlan_port['mode'] == 'tagged' else False
                        delete_vlan_member(dut, vlan=each_vlan, port_list=vlan_port['member'], tagging_mode=tagging_mode, cli_type=tmp_cli_type)
            if cli_type in get_supported_ui_type_list():
                intf_obj = umf_intf.Interface(Name='Vlan' + str(each_vlan))
                cmd_edit_list.append(umf_bulk.Edit(intf_obj, operation=Operation.DELETE))
                '''
                result = intf_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.error("Failed to Unconfigure VLAN: {}".format(result.data))
                    return False
                '''
            elif cli_type == "click":
                commands.append("config vlan del {}".format(each_vlan))
            elif cli_type == "klish":
                commands.append("no interface Vlan {}".format(each_vlan))
            elif cli_type in ["rest-put", "rest-patch"]:
                rest_url = st.get_datastore(dut, "rest_urls")["per_interface_details"].format("Vlan{}".format(each_vlan))
                output = delete_rest(dut, rest_url=rest_url, get_response=True)
                if not output:
                    st.error("OUTPUT IS EMPTY FROM DELETE VLAN REST CALL")
                    return False
                st.log("STATUS: {}".format(output["status"]))
                if not rest_status(output["status"]):
                    rest_fail_status = True
            else:
                st.log("Unsupported CLI type")
                return False
        if rest_fail_status:
            st.log("One of VLAN DELETE REST call failed")
            return False
        if cmd_edit_list:
            result = umf_bulk.bulkRequest(dut, edits=cmd_edit_list, cli_type=cli_type, **kwargs)
            if not result.ok():
                st.log('test_step_failed: Deletion of Vlan {}'.format(result.data))
                return False
        if commands:
            response = st.config(dut, commands, skip_error_check=True, type=cli_type, skip_error_report=skip_error_report)
            if "Error" in response:
                st.log(response)
                return False
            else:
                if verify_delete:
                    vlan_list = get_vlan_list(dut, cli_type=cli_type)
                    for each_vlan in vlan_li:
                        if each_vlan in vlan_list:
                            st.error(" Vlan{} is not deleted".format(each_vlan))
                            return False
        return True
    except Exception as e1:
        st.log(e1)
        st.error(" Vlan is not deleted due to other reasons")
        return False


def delete_all_vlan(dut, cli_type='', delete_members=True, **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To delete All VLANs.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param cli_type:
    :return:
    """
    st.log("delete all vlan")
    if cli_type == "click":
        return config_vlan_range(dut, '1 4093', config='del', skip_verify=True, cli_type=cli_type, **kwargs)
    elif cli_type in ["klish", "rest-put", "rest-patch"] or cli_type in get_supported_ui_type_list():
        tmp_cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
        # vlan_list = get_vlan_list(dut, cli_type=tmp_cli_type)
        if delete_members:
            tagged_port_list = list()
            untagged_port_list = list()
            not_used_in_api = 4095
#            show_vlan_op = show_vlan_config(dut, cli_type=tmp_cli_type)
            show_vlan_op = show_vlan_config(dut, cli_type='klish')
            for vlan_port in show_vlan_op:
                if vlan_port['member']:
                    if vlan_port['mode'] == 'T' and vlan_port['member'] not in tagged_port_list:
                        tagged_port_list.append(vlan_port['member'])
                    if vlan_port['mode'] == 'A' and vlan_port['member'] not in untagged_port_list:
                        untagged_port_list.append(vlan_port['member'])
            if tagged_port_list:
                config_vlan_range_members(dut, vlan_range='none', port=tagged_port_list, config='none', cli_type=cli_type)
            if untagged_port_list:
                delete_vlan_member(dut, vlan=not_used_in_api, port_list=untagged_port_list, cli_type=cli_type, participation_mode="allowed")
        return config_vlan_range(dut, '1 4093', config='del', skip_verify=True, cli_type=tmp_cli_type, **kwargs)
    else:
        st.log("Unsupported CLI type")
        return False


def show_vlan_config(dut, vlan_id=None, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """
    To get vlan config from 'show vlan config'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan_id:
    :param cli_type:
    :return:
    """
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    yang_data_type = kwargs.get("filter_type", "ALL")
    if cli_type in get_supported_ui_type_list():
        if not vlan_id or kwargs.get("autostate"):
            cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        result = list()
        vlan_name = "Vlan{}".format(vlan_id)
        ni_obj = umf_ni.NetworkInstance(Name=vlan_name)
        vlan_obj = umf_ni.Vlan(VlanId=vlan_id, Name=vlan_name, NetworkInstance=ni_obj)
        query_params_obj = get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
        rv = vlan_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        if rv.ok():
            output = rv.payload.get("openconfig-network-instance:vlan")
            if not output:
                return result
            if not output[0].get("config") or not output[0].get("state"):
                st.error("CONFIG node not found in the output .")
                return result
            vlan_data_output = output[0].get("config") if output[0].get("config") else output[0].get("state")
            if output[0].get("members"):
                intf_obj1 = umf_intf.Interface(Name=vlan_name)
                rv = intf_obj1.get_payload(dut, cli_type=cli_type)
                vlan_status = {'status': 'Inactive'}
                if rv.ok():
                    intf_state = rv.payload.get("openconfig-interfaces:interface")
                    if intf_state:
                        state = "Active" if intf_state[0].get("state").get("oper-status") == "UP" else "Inactive"
                        vlan_status = {'status': state}
                if output[0].get("members").get("member"):
                    for member_data in output[0].get("members").get("member"):
                        vlan_data = dict()
                        vlan_data.update(vlan_status)
                        vid = vlan_data_output.get("vlan-id")
                        vlan_data.update(
                            {"vid": vid, "autostate": "Enable", "reserved_vlan": "", "dynamic": "No", "note": "",
                             'member': '', 'mode': ''})
                        intf_name = member_data.get("state").get("interface")
                        dynamic = member_data.get("dynamic", '')
                        if member_data.get("tagging_mode") == 'tagged':
                            tagging_mode = 'T'
                        elif member_data.get("tagging_mode") == 'untagged':
                            tagging_mode = 'A'
                        else:
                            tagging_mode = ''
                        vlan_data.update({"member": intf_name, "mode": tagging_mode, "dynamic": dynamic.title()})
                        result.append(vlan_data)
                else:
                    vlan_res = {"vid": vlan_data_output.get("vlan-id"), "autostate": "Enable", "reserved_vlan": "",
                                "dynamic": "", "note": "", 'status': 'Inactive', 'member': '', 'mode': ''}
                    result.append(vlan_res)
            else:
                vlan_res = {"vid": vlan_data_output.get("vlan-id"), "autostate": "Enable", "reserved_vlan": "",
                            "dynamic": "", "note": "", 'status': 'Inactive', 'member': '', 'mode': ''}
                result.append(vlan_res)
        st.debug(result)
        return result
    elif cli_type == "click":
        st.log("show vlan config")
        command = "show vlan config"
    elif cli_type == "klish":
        command = "show Vlan"
        if vlan_id:
            command += " {}".format(vlan_id)
    elif cli_type in ["rest-put", "rest-patch"]:
        timeout = kwargs.get('timeout', 180)
        if not vlan_id:
            rest_url = st.get_datastore(dut, "rest_urls")["config_interface"]
            get_resp = get_rest(dut, rest_url=rest_url, timeout=timeout)
            if get_resp and rest_status(get_resp["status"]):
                vlan_data = show_vlan_from_rest_response(get_resp["output"])
                if not vlan_id:
                    return vlan_data
                else:
                    filter_vlan_data = list()
                    for vlans in vlan_data:
                        if str(vlans["vid"].replace("Vlan", "")) == vlan_id:
                            filter_vlan_data.append(vlans)
                    return filter_vlan_data
            else:
                return []
        else:
            result = list()
            vlan_name = "Vlan{}".format(vlan_id)
            rest_url = st.get_datastore(dut, "rest_urls")["vlan_member_data"].format(vlan_name, vlan_id)
            get_resp = get_rest(dut, rest_url=rest_url, timeout=timeout)
            if get_resp and rest_status(get_resp["status"]):
                payload = get_resp.get("output")
                if not payload:
                    return result
                output = payload.get("openconfig-network-instance:vlan")
                if not output:
                    return result
                if not output[0].get("config") or not output[0].get("state"):
                    st.error("REST: CONFIG node not found in the output .")
                    return result
                vlan_data_output = output[0].get("config") if output[0].get("config") else output[0].get("state")
                if output[0].get("members"):
                    if output[0].get("members").get("member"):
                        for member_data in output[0].get("members").get("member"):
                            vlan_data = dict()
                            vid = vlan_data_output.get("vlan-id")
                            vlan_data.update(
                                {"vid": vid, "autostate": "Enable", "reserved_vlan": "", "dynamic": "No", "note": ""})
                            intf_name = member_data.get("state").get("interface")
                            rest_url = st.get_datastore(dut, "rest_urls")["per_interface_details"].format(intf_name)
                            get_resp = get_rest(dut, rest_url=rest_url, timeout=timeout)
                            if get_resp and rest_status(get_resp["status"]):
                                payload = get_resp.get("output")
                                if not payload:
                                    vlan_data.update({'status': 'Inactive', 'member': '', 'mode': ''})
                                mem_vlan_data = payload.get("openconfig-interfaces:interface")
                                if not mem_vlan_data:
                                    vlan_data.update({'status': 'Inactive', 'member': '', 'mode': ''})
                                else:
                                    oc_intf_mod_key = "openconfig-if-aggregate:aggregation" if "PortChannel" in intf_name else "openconfig-if-ethernet:ethernet"
                                    member_switched_data = mem_vlan_data[0].get(oc_intf_mod_key)
                                    if not member_switched_data:
                                        vlan_data.update({'status': 'Inactive', 'member': '', 'mode': ''})
                                    else:
                                        switched_vlan = member_switched_data.get("openconfig-vlan:switched-vlan")
                                        if not switched_vlan:
                                            vlan_data.update({'status': 'Inactive', 'member': '', 'mode': ''})
                                        else:
                                            if switched_vlan.get("state"):
                                                trunk_vlans = switched_vlan.get("state").get("trunk-vlans")
                                                access_vlan = switched_vlan.get("state").get("access-vlan")
                                                if access_vlan and int(vid) == int(access_vlan):
                                                    vlan_data.update({"member": intf_name, "mode": "A"})
                                                if trunk_vlans and int(vid) in trunk_vlans:
                                                    vlan_data.update({"member": intf_name, "mode": "T"})
                                                rest_url = st.get_datastore(dut, "rest_urls")[
                                                    "per_interface_details"].format("Vlan{}".format(vid))
                                                get_resp = get_rest(dut, rest_url=rest_url, timeout=timeout)
                                                if get_resp and rest_status(get_resp["status"]):
                                                    payload = get_resp.get("output")
                                                    if not payload:
                                                        vlan_data.update({'status': 'Inactive'})
                                                    intf_state = payload.get("openconfig-interfaces:interface")
                                                    if intf_state:
                                                        state = "Active" if intf_state[0].get("state").get(
                                                            "oper-status") == "UP" else "Inactive"
                                                        vlan_data.update({'status': state})
                                                    else:
                                                        vlan_data.update({'status': 'Inactive'})
                                                else:
                                                    vlan_data.update({'status': 'Inactive'})
                                            else:
                                                vlan_data.update({'status': 'Inactive', 'member': '', 'mode': ''})
                            else:
                                vlan_data.update({'status': 'Inactive', 'member': '', 'mode': ''})
                            result.append(vlan_data)
                    else:
                        vlan_res = {"vid": vlan_data_output.get("vlan-id"), "autostate": "Enable", "reserved_vlan": "",
                                    "dynamic": "", "note": "", 'status': 'Inactive', 'member': '', 'mode': ''}
                        result.append(vlan_res)
                else:
                    vlan_res = {"vid": vlan_data_output.get("vlan-id"), "autostate": "Enable", "reserved_vlan": "",
                                "dynamic": "", "note": "", 'status': 'Inactive', 'member': '', 'mode': ''}
                    result.append(vlan_res)
            st.debug(result)
            return result
    else:
        st.log("Unsupported CLI type")
        return False
    return st.show(dut, command, type=cli_type)


def show_vlan_brief(dut, vlan_id=None, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """
    To get vlan config from 'show vlan brief'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_id:
    :param cli_type:
    :return:
    """
    exec_mode = kwargs.get("exec_mode", "")
    if cli_type in get_supported_ui_type_list():
        if not vlan_id or kwargs.get("autostate"):
            cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        return show_vlan_config(dut, vlan_id=vlan_id, **kwargs)
    elif cli_type == "click":
        st.log("show vlan brief")
        command = "show vlan brief"
    elif cli_type == "klish":
        command = "show Vlan"
        if vlan_id:
            command += " {}".format(vlan_id)
    elif cli_type in ["rest-put", "rest-patch"]:
        timeout = kwargs.get('timeout', 180)
        rest_url = st.get_datastore(dut, "rest_urls")["config_interface"]
        get_resp = get_rest(dut, rest_url=rest_url, timeout=timeout)
        try:
            if get_resp and rest_status(get_resp["status"]):
                vlan_data = show_vlan_from_rest_response(get_resp["output"])
                vlan_data = append_autostate_data(dut, vlan_data)
                if not vlan_id:
                    return vlan_data
                else:
                    filter_vlan_data = list()
                    for vlans in vlan_data:
                        if str(vlans["vid"].replace("Vlan", "")) == vlan_id:
                            filter_vlan_data.append(vlans)
                    return filter_vlan_data
            else:
                return []
        except Exception as e:
            st.error("Exception is :{}".format(e))
            return False
    else:
        st.log("Unsupported CLI type")
        return False

    return st.show(dut, command, type=cli_type, exec_mode=exec_mode)


def get_vlan_count(dut, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To get the Vlan count using - 'show vlan count' command.
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if not _has_vlan_range(dut):
        vlans = get_vlan_list(dut)
        count = len(vlans)
    else:
        if cli_type == "click":
            output = st.show(dut, "show vlan count")
            count = int(output[0]['vlan_count'])
        elif cli_type in ["klish", "rest-put", "rest-patch"]:
            output = get_vlan_list(dut, cli_type=cli_type)
            count = len(output)
        else:
            st.log("Unsupported CLI type")
            return False
    return count


def get_vlan_list(dut, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Get list of VLANs
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param cli_type:
    :return:
    """
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    st.log("show vlan to get vlan list")
    output = show_vlan_config(dut, cli_type=cli_type)
    vlan_list = list(set([eac['vid'] for eac in output]))
    return vlan_list


def add_vlan_member(dut, vlan, port_list, tagging_mode=False, skip_error=False, no_form=False, cli_type='', **kwargs):
    """
    Add Members to VLAN
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param port_list:
    :param tagging_mode:
    :param skip_error:
    :param no_form:
    :param cli_type:
    :return:
    """
    conn_index = kwargs.get("conn_index", None)
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    # st.log("Add member {} to the VLAN {}".format(port_list, vlan))
    port_li = make_list(port_list)
    # Forcing it to klish as UMF doesnt have support for this
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() and tagging_mode and no_form else cli_type

    if cli_type in get_supported_ui_type_list():
        port_hash_list = segregate_intf_list_type(intf=port_li, range_format=False)
        all_port_list = port_hash_list['intf_list_all']
        # Some scripts are passing vlan='' for removing access vlan.
        if not vlan:
            vlan = None
        mode = 'ACCESS'
        if tagging_mode:
            mode = 'TRUNK'
            vlan_id = str(vlan).split('-')
            vlan = '{}..{}'.format(vlan_id[0], vlan_id[1]) if len(vlan_id) > 1 else int(vlan)

        for each_port in all_port_list:
            interface_details = get_interface_number_from_name(each_port)
            each_port = get_portchannel_name_for_rest(each_port)
            if tagging_mode:
                if "Eth" in interface_details.get("type"):
                    vlan_obj = umf_intf.Interface(Name=each_port, EthernetInterfaceMode=mode, EthernetTrunkVlans=vlan)
                else:
                    vlan_obj = umf_intf.Interface(Name=each_port, AggregationInterfaceMode=mode, AggregationTrunkVlans=vlan)
            else:
                if "Eth" in interface_details.get("type"):
                    vlan_obj = umf_intf.Interface(Name=each_port, EthernetInterfaceMode=mode, EthernetAccessVlan=vlan)
                else:
                    vlan_obj = umf_intf.Interface(Name=each_port, AggregationInterfaceMode=mode, AggregationAccessVlan=vlan)
            if not no_form:
                result = vlan_obj.configure(dut, cli_type=cli_type)
            else:
                if tagging_mode:
                    if "Eth" in interface_details.get("type"):
                        result = vlan_obj.unConfigure(dut, target_attr=vlan_obj.EthernetTrunkVlans, cli_type=cli_type)
                    else:
                        result = vlan_obj.unConfigure(dut, target_attr=vlan_obj.AggregationTrunkVlans, cli_type=cli_type)
                else:
                    if "Eth" in interface_details.get("type"):
                        result = vlan_obj.unConfigure(dut, target_attr=vlan_obj.EthernetAccessVlan, cli_type=cli_type)
                    else:
                        result = vlan_obj.unConfigure(dut, target_attr=vlan_obj.AggregationAccessVlan, cli_type=cli_type)
            if not result.ok():
                st.error("test_step_failed: Failed for Members of VLAN: {}".format(result.data))
                return False
    elif cli_type == "click":
        port_hash_list = segregate_intf_list_type(intf=port_li, range_format=False)
        all_port_list = port_hash_list['intf_list_all']
        all_port_list = make_list(convert_intf_name_to_component(dut, all_port_list, component="applications"))
        for each_port in all_port_list:
            if tagging_mode:
                command = "config vlan member add {} {}".format(vlan, each_port)
            else:
                command = "config vlan member add {} {} -u ".format(vlan, each_port)

            # Here handling the error while adding interface to vlan
            out = st.config(dut, command, skip_error_check=True, conn_index=conn_index)

            if "is already a member of Vlan{}".format(vlan) in out:
                st.error("{} is already a member of Vlan{}".format(each_port, vlan))
                return False
            if "Vlan{} doesn't exist".format(vlan) in out:
                st.error(" Vlan{} doesn't exist".format(vlan))
                return False
            if "has ip address configured" in out:
                st.error("Error:  {} has ip address configured".format(each_port))
                return False
            if "Vlan{} does not exist".format(vlan) in out:
                st.error(" Vlan{} does not exist".format(vlan))
                return False
            if "Error: " in out:
                return False
    elif cli_type == "klish":
        commands = list()
        port_hash_list = segregate_intf_list_type(intf=port_li, range_format=True)
        all_port_list = port_hash_list['intf_list_all']
        for each_port in all_port_list:
            if not is_a_single_intf(each_port):
                commands.append("interface range {}".format(each_port))
            else:
                interface_details = get_interface_number_from_name(each_port)
                if not interface_details:
                    st.log("Interface details not found {}".format(interface_details))
                    return False
                zero_or_more_space = get_random_space_string()
                commands.append("interface {}{}{}".format(interface_details.get("type"), zero_or_more_space, interface_details.get("number")))
            participation_mode = "trunk" if tagging_mode else "access"
            if participation_mode == "trunk":
                command = "switchport trunk allowed Vlan {} {}"
                commands.append(command.format('remove', vlan) if no_form else command.format('add', vlan))
            elif participation_mode == "access":
                command = "switchport access Vlan"
                commands.append("no {}".format(command) if no_form else "{} {}".format(command, vlan))
            commands.append("exit")
        if commands:
            out = st.config(dut, commands, type=cli_type, skip_error_check=True, conn_index=conn_index)
            error = "% Error: {} is configured as destination port in a mirror session".format(each_port)
            if "Invalid VLAN:" in out:
                st.log("Vlan{} doesn't exist".format(vlan))
                return False
            elif error in out:
                st.error("Port has mirror session config")
                return False
            elif 'Error:' in out:
                return False
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch"
        port_hash_list = segregate_intf_list_type(intf=port_li, range_format=False)
        all_port_list = port_hash_list['intf_list_all']
        for each_port in all_port_list:
            interface_details = get_interface_number_from_name(each_port)
            if not interface_details:
                st.log("Interface details not found {}".format(interface_details))
                return False
            if "Eth" in interface_details.get("type"):
                url = st.get_datastore(dut, "rest_urls")["interface_member_config"].format(each_port)
            else:
                intf_name = get_portchannel_name_for_rest(each_port)
                url = st.get_datastore(dut, "rest_urls")["aggregate_member_config"].format(intf_name)
            if not no_form:
                add_member = json.loads("""
                {"openconfig-vlan:switched-vlan": {"config": {"interface-mode": "ACCESS"}}}""")
                if tagging_mode:
                    vlan_id = str(vlan).split('-')
                    vlan = '{}..{}'.format(vlan_id[0], vlan_id[1]) if len(vlan_id) > 1 else int(vlan)
                    add_member["openconfig-vlan:switched-vlan"]["config"]["trunk-vlans"] = [vlan]
                    add_member["openconfig-vlan:switched-vlan"]["config"]["interface-mode"] = "TRUNK"
                else:
                    add_member["openconfig-vlan:switched-vlan"]["config"]["access-vlan"] = int(vlan)
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=add_member):
                    return False
            else:
                if not delete_vlan_member(dut, vlan, each_port, tagging_mode=tagging_mode, cli_type=cli_type, skip_error_check=skip_error):
                    return False
    else:
        st.log("Unsupported CLI type")
        return False
    return True


def delete_vlan_member(dut, vlan, port_list, tagging_mode=False, cli_type='', skip_error_check=False, participation_mode=""):
    """
    Delete Members in VLAN
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param port_list:
    :param participation_mode:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    # st.log("Delete member {} from the VLAN {}".format(port_list, vlan))
    if participation_mode != "allowed":
        if tagging_mode:
            participation_mode = "trunk"
        else:
            participation_mode = "access"
    port_li = make_list(port_list)
    commands = list()
    rest_fail_status = False
    # Forcing it to klish as UMF doesnt have support for this
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() and tagging_mode else cli_type
    if cli_type in get_supported_ui_type_list():
        return add_vlan_member(dut, vlan=vlan, port_list=port_list, tagging_mode=tagging_mode, skip_error=skip_error_check, no_form=True, cli_type=cli_type)
    elif cli_type == "click":
        port_hash_list = segregate_intf_list_type(intf=port_li, range_format=False)
        all_port_list = port_hash_list['intf_list_all']
        all_port_list = make_list(convert_intf_name_to_component(dut, all_port_list, component="applications"))
        for each_port in all_port_list:
            command = "config vlan member del {} {}".format(vlan, each_port)
            out = st.config(dut, command, skip_error_check=skip_error_check)
            if "is not a member of Vlan{}".format(vlan) in out:
                st.error("{} is not a member of Vlan{}".format(each_port, vlan))
                return False
            if "Vlan{} doesn't exist".format(vlan) in out:
                st.error("Vlan{} doesn't exist".format(vlan))
                return False
    elif cli_type == "klish":
        port_hash_list = segregate_intf_list_type(intf=port_li, range_format=True)
        all_port_list = port_hash_list['intf_list_all']
        for each_port in all_port_list:
            if not is_a_single_intf(each_port):
                commands.append("interface range {}".format(each_port))
            else:
                interface_details = get_interface_number_from_name(each_port)
                if not interface_details:
                    st.log("Interface details not found {}".format(interface_details))
                    return False
                commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
            if participation_mode == "trunk":
                command = "switchport trunk allowed Vlan remove {}".format(vlan)
                commands.append("{}".format(command))
            elif participation_mode == "access":
                command = "switchport access Vlan"
                commands.append("no {}".format(command))
            elif participation_mode == "allowed":
                command = "switchport allowed Vlan"
                commands.append("no {}".format(command))
            commands.append("exit")
    elif cli_type in ["rest-put", "rest-patch"]:
        port_hash_list = segregate_intf_list_type(intf=port_li, range_format=False)
        all_port_list = port_hash_list['intf_list_all']
        for each_port in all_port_list:
            if participation_mode == "access":
                if "Eth" in get_interface_number_from_name(each_port)["type"]:
                    rest_url = st.get_datastore(dut, "rest_urls")["interface_access_member_config"].format(each_port)
                else:
                    rest_url = st.get_datastore(dut, "rest_urls")["aggregate_access_member_config"].format(each_port)
            else:
                vlan_id = str(vlan).split('-')
                vlan = '{}..{}'.format(vlan_id[0], vlan_id[1]) if len(vlan_id) > 1 else vlan
                if "Eth" in get_interface_number_from_name(each_port)["type"]:
                    rest_url = st.get_datastore(dut, "rest_urls")["interface_trunk_member_config"].format(each_port, vlan)
                else:
                    rest_url = st.get_datastore(dut, "rest_urls")["aggregate_trunk_member_config"].format(each_port, vlan)
            output = delete_rest(dut, rest_url=rest_url, get_response=True)
            if not output:
                st.error("OUTPUT IS EMPTY FROM DELETE VLAN MEMBER REST CALL")
                return False
            st.log("STATUS: {}".format(output["status"]))
            if not rest_status(output["status"]):
                rest_fail_status = True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    if rest_fail_status:
        st.log("One of VLAN member DELETE REST call failed")
        return False
    if commands:
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    return True


def get_vlan_member(dut, vlan_list=[], cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To Get VLANs vs list of Members.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_list:
    :param cli_type:
    :return:
    """
    vlan_val = {}
    vlan_li = make_list(vlan_list)
    if vlan_li:
        out = list()
        for vlan in vlan_li:
            res = show_vlan_config(dut, vlan_id=vlan, cli_type=cli_type)
            if res:
                out.extend(res)
    else:
        out = show_vlan_config(dut, cli_type=cli_type)
    if vlan_li:
        temp = []
        for each in list(set(vlan_li)):
            temp += filter_and_select(out, None, {"vid": each})
        out = temp

    for each in out:
        if each['member']:
            if each['vid'] not in vlan_val:
                vlan_val[each['vid']] = [each['member']]
            else:
                vlan_val[each['vid']].append(each['member'])
    return vlan_val


def get_member_vlan(dut, interface_list=[], cli_type=''):
    # API_Not_Used: To Be removed in CyrusPlus. Also Duplicate API
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To Get Members vs list of VLANs.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param interface_list:
    :param cli_type:
    :return:
    """
    member_val = {}
    interface_li = list(interface_list) if isinstance(interface_list, list) else [interface_list]
    out = show_vlan_config(dut, cli_type=cli_type)
    if interface_li:
        temp = []
        for each in list(set(interface_li)):
            temp += filter_and_select(out, None, {"member": each})
        out = temp

    for each in out:
        if each['member']:
            if each['member'] not in member_val:
                member_val[each['member']] = [each['vid']]
            else:
                member_val[each['member']].append(each['vid'])
    return member_val


def verify_vlan_config(dut, vlan_list, tagged=None, untagged=None, name=None, cli_type='', **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Verify vlan config using 'show vlan config'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_list:
    :param tagged:
    :param untagged:
    :param name:
    :return:
    """
    negative = kwargs.pop('negative', False)
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in get_supported_ui_type_list() and kwargs.get("autostate"):
        cli_type = force_cli_type_to_klish(cli_type=cli_type)
    vlan_li = map(str, vlan_list) if isinstance(vlan_list, list) else [vlan_list]
    if cli_type not in get_supported_ui_type_list():
        output = show_vlan_config(dut, cli_type=cli_type)
    for each_vlan in vlan_li:
        if cli_type in get_supported_ui_type_list():
            output = show_vlan_config(dut, vlan_id=each_vlan, cli_type=cli_type, **kwargs)
        entries = filter_and_select(output, None, {"vid": each_vlan})
        if negative and entries:
            st.log("DUT:{}, Provided VLAN {} entry does not exist in table".format(dut, each_vlan))
            return False
        if not negative and not entries:
            st.log("DUT:{}, Provided VLAN {} entry does not exist in table".format(dut, each_vlan))
            return False
        if tagged:
            interface_list = list(tagged) if isinstance(tagged, list) else [tagged]
            if cli_type == 'click':
                interface_list = make_list(convert_intf_name_to_component(dut, interface_list, component="applications"))
            for each_intr in interface_list:
                if cli_type in ["click", "rest-put", "rest-patch"]:
                    f1 = filter_and_select(entries, None, {"member": each_intr, "mode": "tagged"})
                    if negative and f1:
                        st.log("DUT:{}, Provided interface {} is a tagged member of Vlan {}".format(dut, each_intr, each_vlan))
                        return False
                    if not negative and not f1:
                        st.log("DUT:{}, Provided interface {} is not a tagged member of Vlan {}".format(dut, each_intr, each_vlan))
                        return False
                elif cli_type in ["klish"] + get_supported_ui_type_list():
                    t1 = filter_and_select(entries, None, {"member": each_intr, "mode": "T"})
                    if negative and t1:
                        st.log("DUT:{}, Provided interface {} is not a tagged member of Vlan {}".format(dut, each_intr, each_vlan))
                        return False
                    if not negative and not t1:
                        st.log("DUT:{}, Provided interface {} is not a tagged member of Vlan {}".format(dut, each_intr, each_vlan))
                        return False
                else:
                    st.log("Unsupported CLI TYPE")
                    return False
        if untagged:
            interface_list = list(untagged) if isinstance(untagged, list) else [untagged]
            if cli_type == 'click':
                interface_list = make_list(convert_intf_name_to_component(dut, interface_list, component="applications"))
            for each_intr in interface_list:
                if cli_type in ["click", "rest-put", "rest-patch"]:
                    uf1 = filter_and_select(entries, None, {"member": each_intr, "mode": "untagged"})
                    if negative and not uf1:
                        st.log("DUT:{}, Provided interface {} is not a untagged member of Vlan {}".format(dut, each_intr, each_vlan))
                        return False
                    if not negative and not uf1:
                        st.log("DUT:{}, Provided interface {} is not a untagged member of Vlan {}".format(dut, each_intr, each_vlan))
                        return False
                elif cli_type in ["klish"] + get_supported_ui_type_list():
                    uf2 = filter_and_select(entries, None, {"member": each_intr, "mode": "A"})
                    if negative and uf2:
                        st.log("DUT:{}, Provided interface {} is not a untagged member of Vlan {}".format(dut, each_intr, each_vlan))
                        return False
                    if not negative and not uf2:
                        st.log("DUT:{}, Provided interface {} is not a untagged member of Vlan {}".format(dut, each_intr, each_vlan))
                        return False
                else:
                    st.log("Unsupported CLI TYPE")
                    return False
        if name and not filter_and_select(entries, None, {"name": name}):
            st.log("DUT:{}, Provided and configured VLAN {} name in not match".format(dut, each_vlan))
            return False
    return True


def verify_vlan_brief(dut, vid, tagged=None, untagged=None, ip_address=None, dhcp_helper_add=None, autostate=None, status=None, cli_type='', **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Verify vlan config using 'show vlan brief'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vid:
    :param tagged:
    :param untagged:
    :param ip_address:
    :param dhcp_helper_add:
    :return:
    """
    exec_mode = kwargs.get("exec_mode", "")
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in get_supported_ui_type_list() and autostate:
        cli_type = force_cli_type_to_klish(cli_type=cli_type)
    vid = str(vid)
    if cli_type == 'click' and autostate:
        autostate = autostate.lower()
    if cli_type in ['klish'] + get_supported_ui_type_list():
        if tagged is not None:
            mode = 'T'
        else:
            mode = 'A'
    if cli_type in ['click', 'rest-patch', 'rest-put']:
        if tagged is not None:
            mode = 'tagged'
        else:
            mode = 'untagged'
    if cli_type in get_supported_ui_type_list():
        output = show_vlan_brief(dut, vlan_id=vid, cli_type=cli_type, **kwargs)
    else:
        output = show_vlan_brief(dut, cli_type=cli_type, exec_mode=exec_mode)
    entries = filter_and_select(output, None, {"vid": vid})
    if not entries:
        st.log("Provided VLAN {} entry is not exist in table".format(vid))
        return False
    if tagged and not filter_and_select(entries, None, {"member": tagged, "mode": mode}):
        st.log("Provided interface {} is not a tagged member of Vlan {}".format(tagged, vid))
        return False
    if untagged and not filter_and_select(entries, None, {"member": untagged, "mode": mode}):
        st.log("Provided interface {} is not a untagged member of Vlan {}".format(untagged, vid))
        return False
    if dhcp_helper_add and not filter_and_select(entries, None, {"vid": vid, "dhcphelperadd": dhcp_helper_add}):
        st.log("Provided and configured vlan {} DHCPHelperAdd {} in not match".format(vid, dhcp_helper_add))
        return False
    if autostate and not filter_and_select(entries, None, {"vid": vid, "autostate": autostate}):
        st.log("Provided and configured vlan {} autostate {} in not match".format(vid, autostate))
        return False
    if cli_type in ['klish'] + get_supported_ui_type_list() or cli_type in ['rest-patch', 'rest-put']:
        if status and not filter_and_select(entries, None, {"vid": vid, "status": status}):
            st.log("Provided and configured vlan {} Status {} in not match".format(vid, status))
            return False
    if ip_address and not filter_and_select(entries, None, {"vid": vid, "ipadd": ip_address}):
        st.log("Provided and configured vlan {} IpAdd {} in not match".format(vid, ip_address))
        return False
    return True


def _clear_vlan_configuration_helper(dut_list, cli_type=''):
    """
    Find and clear VLAN and its Members.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut_list:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        cli_type = st.get_ui_type(dut, cli_type=cli_type)
        st.log("############## {} : VLAN Cleanup ################".format(dut))
        if cli_type in get_supported_ui_type_list():
            return delete_all_vlan(dut, cli_type=cli_type)
        elif cli_type == 'click':
            output = show_vlan_config(dut, cli_type=cli_type)

            if not _has_vlan_range(dut):
                (vlans, commands) = ({}, [])
                for eac in output:
                    (vid, member) = (eac['vid'], eac['member'])
                    if vid:
                        vlans[vid] = 1
                        if member:
                            command = "config vlan member del {} {}".format(vid, member)
                            commands.append(command)
                for vid in vlans.keys():
                    command = "config vlan del {}".format(vid)
                    commands.append(command)
                st.config(dut, commands)
                continue

            # Get Vlan list
            vlan_list = list(set([eac['vid'] for eac in output]))
            # Get interface list
            member_list = list(set([eac['member'] for eac in output if eac['member'] != '']))
            if member_list:
                if not config_vlan_range_members(dut, '1 4093', member_list, config='del', skip_verify=True):
                    st.log("VLAN all member delete failed")
                    return False
            if vlan_list:
                if not delete_all_vlan(dut, cli_type=cli_type):
                    st.log("VLAN all delete failed")
                    return False
        elif cli_type in ['klish', "rest-put", "rest-patch"]:
            return delete_all_vlan(dut, cli_type=cli_type)
        else:
            st.log("UNSUPPORTED CLI TYPE")
            return False
    return True


def clear_vlan_configuration(dut_list, thread=True, cli_type=''):
    """
    Find and clear VLAN and its Members on list of DUTs
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut_list:
    :param thread: True(Default) / False
    :param cli_type:
    :return:
    """
    if not thread:
        return _clear_vlan_configuration_helper(dut_list, cli_type)
    out = st.exec_each(make_list(dut_list), _clear_vlan_configuration_helper, cli_type=cli_type)[0]
    return False if False in out else True


def create_vlan_and_add_members(vlan_data, cli_type=''):
    """
    Create VLAN and Add members to VLAN across DUTs
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param vlan_data: List of dictionaries with dut, vlan_id and tagged / untagged members list.
    Sample vlan_data -- [{"dut": [vars.D1, vars.D2], "vlan_id":"100","tagged":["Ethernet0", "Ethernet1"],
                        "untagged":["Ethernet3", "Ethernet4"]},{"dut": [vars.D2], "vlan_id":"200",
                        "tagged":["Ethernet5", "Ethernet6"], "untagged":["Ethernet7", "Ethernet8"]}]
    :param cli_type:
    :return: True / False
    """
    if not isinstance(vlan_data, list):
        return False
    for data in vlan_data:
        if "dut" not in data:
            return False
        dut_list = list(data["dut"]) if isinstance(data["dut"], list) else [data["dut"]]
        for dut in dut_list:
            cli_type = st.get_ui_type(dut, cli_type=cli_type)
            if "vlan_id" in data:
                create_vlan(dut, data["vlan_id"], cli_type=cli_type)
                if "tagged" in data and data["tagged"]:
                    add_vlan_member(dut, data["vlan_id"], data["tagged"], tagging_mode=True, cli_type=cli_type)
                if "untagged" in data and data["untagged"]:
                    add_vlan_member(dut, data["vlan_id"], data["untagged"], tagging_mode=False, cli_type=cli_type)
            else:
                return False
    return True


def get_non_existing_vlan(dut, count=1, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    This API will provide number of non existing vlans
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)s
    :param dut:
    :param count:
    :return:
    """
    vlan_list = get_vlan_list(dut, cli_type=cli_type)
    return random_vlan_list(count, vlan_list)


def _check_config_vlan_output(output):
    if "VLANs already existing" in output:
        st.error("VLANs already existing were tried to be configured")
        return False
    if "Non-existent VLANs" in output:
        st.error("Non-existent VLANs were tried to be deleted")
        return False
    if "error" in str(output).lower():
        st.error("Observed error While executing the CMD")
        return False
    return True


def config_vlan_range(dut, vlan_range, config="add", skip_verify=False, cli_type='', **kwargs):
    """
    Author: sneha.mathew@broadcom.com
    Creates/Deletes range of VLANs given as input.
    :param dut:
    :param vlan_range: range of VLAN IDs in string format, separator space: "first-VLAN last_VLAN".
                        can be list of strings.
    :param config: flag which specifies to configure or unconfigure the cli. add for config, del for unconfig.
                        Default:add
    :param skip_verify: True | False
    :return True: The VLANs were successfully created or deleted.
    :return False: Error in parameter passed.
    """

    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    # Forcing GNMI/REST to klish as it takes ~2 hrs to create 3966 vlans via message driven infra. Will update again after finding a solution
    cli_type = 'klish' if cli_type in ['rest-put', 'rest-patch'] + get_supported_ui_type_list() else cli_type

    if config == "del":
        st.log("Deleting range of vlans {}".format(vlan_range), dut=dut)
        no_form = 'no '
    else:
        st.log("Creating range of vlans {}".format(vlan_range), dut=dut)
        no_form = ''

    vlan_range_list = list(vlan_range) if isinstance(vlan_range, list) else [vlan_range]
    commands = []
    if cli_type in get_supported_ui_type_list():
        vlan_list = []
        for ele in vlan_range_list:
            if ' ' in ele or '-' in ele:
                vlan_temp = ele.split(' ') if ' ' in ele else ele.split('-')
                for i in range(int(vlan_temp[0]), int(vlan_temp[1]) + 1):
                    vlan_list.append(str(i))
            else:
                vlan_list.append(ele)
        st.log("The List of VLANs to be Configured:{}".format(vlan_list))
        if config == 'add':
            return create_vlan(dut, vlan_list=vlan_list, cli_type=cli_type, **kwargs)
        else:
            return delete_vlan(dut, vlan_list=vlan_list, cli_type=cli_type, **kwargs)
    elif cli_type == 'click':
        if not _has_vlan_range(dut):
            for vrange in vlan_range_list:
                [range_min, range_max] = [int(vid) for vid in vrange.split()]
                for vid in range(range_min, range_max + 1):
                    commands.append("config vlan {} {}".format(config, vid))
            output = st.config(dut, commands, type=cli_type, **kwargs)
            return _check_config_vlan_output(output)

        for vrange in vlan_range_list:
            commands.append("config vlan range {} {}".format(config, vrange))

        ver_flag = True
        for command in commands:
            # -w option displays warning, turned on so that existing vlans message can be checked
            if not skip_verify:
                command += " -w"
            output = st.config(dut, command)
            if not _check_config_vlan_output(output):
                ver_flag = False

        return ver_flag
    elif cli_type == 'klish':
        new_vrange = ''
        for vrange in vlan_range_list:
            new_vrange += vrange.replace(' ', '-')
            new_vrange += ','
        new_vrange = new_vrange.strip(',')
        if 'no' not in no_form:
            commands.append('interface range create Vlan {}'.format(new_vrange))
            commands.append('exit')
            commands.append('{}interface range Vlan {}'.format(no_form, new_vrange))
            commands.append('exit')
        else:
            commands.append('{}interface Vlan {}'.format(no_form, new_vrange))
        out = st.config(dut, commands, type=cli_type, **kwargs)
        if kwargs.get('skip_error_check'):
            if not _check_config_vlan_output(out):
                return False
            else:
                return out
        if out:
            return True


def _check_config_vlan_member_output(output, port=None, vlan=None):
    if "is already a member of Vlan" in output:
        if port and vlan:
            st.error("{} is already a member of Vlan{}".format(port, vlan))
        else:
            st.error("one/more interfaces are already VLAN members")
        return False
    if "doesn't exist" in output:
        if port and vlan:
            st.error(" Vlan{} doesn't exist".format(vlan))
        else:
            st.error(" Vlan(s) doesn't exist")
        return False
    return True


def config_vlan_range_members(dut, vlan_range, port, config="add", skip_verify=False, skip_error=False, cli_type=''):
    """
    Author: sneha.mathew@broadcom.com
    Add or remove given member ports to range of VLANs given as input.
    :param dut:
    :param vlan_range: range of VLAN IDs in string format "first-VLAN last_VLAN". can be list of strings.
    :param port: port or list of ports which needs to be added / deleted to vlan_range
    :param config: flag which specifies to configure or unconfigure the cli.
                        add for config, del for unconfig. Default:add
    :param skip_verify: True | False
    :param skip_error: True | False
    :return True: Member ports successfully added or deleted to vlan range.
    :return False: Error in parameter passed.
    """

    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    cli_type = 'klish' if cli_type in ['rest-put', 'rest-patch'] else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    # config = none, except, all, vlanlist is supported in klish only.
    if cli_type == 'click' and config in ['none', 'vlanlist', 'all', 'except']:
        st.log('Option \'{}\' is not supported in {}'.format(config, cli_type))
        return False

    if config == "del":
        st.log("Deleting member ports from range of vlans")
        operation = ' remove'
    elif config in ['none', 'vlanlist', 'all']:
        operation = ''
        vlan_range = config if config in ['none', 'all'] else vlan_range
    elif config in ['except']:
        operation = ' except'
    else:
        st.log("Adding member ports to range of vlans", dut=dut)
        operation = ' add'

    vlan_range_list = list(vlan_range) if isinstance(vlan_range, list) else [vlan_range]
    port_list = list(port) if isinstance(port, list) else [port]

    commands = []
    if cli_type == 'click':
        port_hash_list = segregate_intf_list_type(intf=port_list, range_format=False)
        all_port_list = port_hash_list['intf_list_all']
        if not _has_vlan_range(dut):
            if config == "del":
                skip_error = True
            for each_port in all_port_list:
                for vrange in vlan_range_list:
                    [range_min, range_max] = [int(vid) for vid in vrange.split()]
                    for vid in range(range_min, range_max + 1):
                        commands.append("config vlan member {} {} {}".format(config, vid, each_port))
            output = st.config(dut, commands, skip_error_check=skip_error)
            return _check_config_vlan_member_output(output)

        entries = []
        for vrange in vlan_range_list:
            for each_port in all_port_list:
                command = "config vlan member range {} {} {}".format(config, vrange, each_port)
                entries.append([command, each_port, vrange])

        ver_flag = True
        for [command, each_port, vrange] in entries:
            if not skip_verify:
                # -w option displays warning, turned on so that existing vlans message can be checked
                command += " -w"
            output = st.config(dut, command, skip_error_check=skip_error)
            if not _check_config_vlan_member_output(output, each_port, vrange):
                ver_flag = False

        return ver_flag
    elif cli_type == 'klish':
        port_hash_list = segregate_intf_list_type(intf=port_list, range_format=True)
        all_port_list = port_hash_list['intf_list_all']
        new_vrange = ''
        for vrange in vlan_range_list:
            new_vrange += str(vrange).replace(' ', '-')
            new_vrange += ','
        new_vrange = new_vrange.strip(',')
        for each_port in all_port_list:
            if not is_a_single_intf(each_port):
                commands.append("interface range {}".format(each_port))
            else:
                interface_details = get_interface_number_from_name(each_port)
                commands.append(
                    "interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
            commands.append('switchport trunk allowed Vlan{} {}'.format(operation, new_vrange))
            commands.append('exit')
        try:
            st.config(dut, commands, skip_error_check=skip_error, type=cli_type)
            return True
        except Exception as e:
            st.log(e)
            return False


def config_vlan_members(dut, vlan_list, port_list, config="add", tagged=True, skip_verify=False, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Add or remove given member ports to VLANs given as input.
    :param dut:
    :param vlan_list: range of VLAN IDs is can be list of strings.
    :param port_list: port or list of ports which needs to be added / deleted to vlan_range
    :param config: flag which specifies to configure or unconfigure the cli.
                        add for config, del for unconfig. Default:add
    :param skip_verify: True | False
    :param tagged:
    :param cli_type:
    :return True: Member ports successfully added or deleted to vlan range.
    :return False: Error in parameter passed.
    """
    if config == "del":
        st.log("Deleting member ports from range of vlans", dut=dut)
    else:
        st.log("Adding member ports to range of vlans", dut=dut)

    vlan_li = list(vlan_list) if isinstance(vlan_list, list) else [vlan_list]
    port_li = list(port_list) if isinstance(port_list, list) else [port_list]

    ver_flag = True
    no_form = True if config == "del" else False
    for vlan in vlan_li:
        if cli_type in get_supported_ui_type_list():
            add_vlan_member(dut, vlan=vlan, port_list=port_li, tagging_mode=tagged, skip_error=False, no_form=no_form, cli_type=cli_type)
        elif cli_type == "click":
            for each_port in port_li:
                command = "config vlan member {} {} {}".format(config, vlan, each_port)
                if not tagged and not no_form:
                    command += " -u"
                output = st.config(dut, command)
                if "is already a member of Vlan" in output:
                    st.error("{} is already a member of Vlan{}".format(each_port, vlan))
                    ver_flag = False
                if "doesn't exist" in output:
                    st.error(" Vlan{} doesn't exist".format(vlan))
                    ver_flag = False
        elif cli_type in ["klish", "rest-put", "rest-patch"]:
            add_vlan_member(dut, vlan, port_li, tagging_mode=tagged, skip_error=False, no_form=no_form,
                            cli_type=cli_type)
        else:
            st.log("UNSUPPORTED CLI TYPE")
            return False
    return ver_flag


def create_multiple_vlans_and_members(dut, data, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    :param dut:
    :param data: {'G7': {'normal_vlan': {'vlans': [1577, 1578, 1579], 'members':['Ethernet0', 'PortChannel3', 'PortChannel5', 'PortChannel4']}, 'peer_vlan': {'vlans': 1580, 'members': ['Ethernet12', 'PortChannel2']}}, 'G6':{'normal_vlan': {'vlans': [1577, 1578, 1579], 'members': ['Ethernet0', 'PortChannel5', 'Ethernet24']}}, 'G4': {'normal_vlan': {'vlans': [1577,    1578, 1579], 'members': ['Ethernet120', 'PortChannel2', 'PortChannel3',    'PortChannel4', 'Ethernet112']}, 'peer_vlan': {'vlans': 1581, 'members':   ['PortChannel1']}}, 'G3': {'normal_vlan': {'vlans': [1577, 1578, 1579],  'members': ['Ethernet120', 'PortChannel3', 'PortChannel5', 'PortChannel4']},  'peer_vlan': {'vlans': 1580, 'members': ['Ethernet0', 'PortChannel2']}}, 'G8': {'normal_vlan': {'vlans': [1577, 1578, 1579], 'members': ['Ethernet0',  'PortChannel2', 'PortChannel3', 'PortChannel4']}, 'peer_vlan': {'vlans':1581, 'members': ['PortChannel1']}}}
    :return: True | False
    """
    for _, value in data[dut].items():
        create_vlan(dut, value["vlans"], cli_type=cli_type)
        if not config_vlan_members(dut, value["vlans"], value["members"], cli_type=cli_type):
            st.log("ADDING MEMBERS {} to VLAN {} FAILED".format(value["members"], value["vlans"]))
            st.report_fail("vlan_tagged_member_fail", value["members"], value["vlans"])
    return True


def show_vlan_from_rest_response(rest_response):
    output = list()
    vlan_list = list()
    vlans_output = dict()
    participation_output = list()
    try:
        for _, value in rest_response.items():
            if isinstance(value, list):
                for intf_data in value:
                    vlan_data = dict()
                    vlan_participation_data = dict()
                    if "Vlan" in intf_data.get("name"):
                        vlan_data["vid"] = intf_data.get("name")
                        vlan_data["status"] = intf_data.get("state")["oper-status"] if "oper-status" in intf_data.get("state") else ""
                        vlan_data['status'] = vlan_data['status'].replace('UP', 'Active').replace('DOWN', 'Inactive')
                    if intf_data.get("openconfig-if-ethernet:ethernet"):
                        if intf_data["openconfig-if-ethernet:ethernet"].get("openconfig-vlan:switched-vlan"):
                            vlan_participation_data[intf_data["name"]] = dict()
                            vlan_config = intf_data["openconfig-if-ethernet:ethernet"]["openconfig-vlan:switched-vlan"]["state"]
                            if vlan_config.get("access-vlan"):
                                vlan_participation_data[intf_data["name"]]["untagged"] = vlan_config["access-vlan"]
                            if vlan_config.get("trunk-vlans"):
                                vlan_participation_data[intf_data["name"]]["tagged"] = vlan_config["trunk-vlans"]
                    if intf_data.get("openconfig-if-aggregate:aggregation"):
                        if intf_data["openconfig-if-aggregate:aggregation"].get("openconfig-vlan:switched-vlan"):
                            vlan_participation_data[intf_data["name"]] = dict()
                            vlan_config = intf_data["openconfig-if-aggregate:aggregation"]["openconfig-vlan:switched-vlan"]["state"]
                            if vlan_config.get("access-vlan"):
                                vlan_participation_data[intf_data["name"]]["untagged"] = vlan_config["access-vlan"]
                            if vlan_config.get("trunk-vlans"):
                                vlan_participation_data[intf_data["name"]]["tagged"] = vlan_config["trunk-vlans"]
                    if vlan_data:
                        vlans_output.update({intf_data.get("name"): vlan_data})
                    if vlan_participation_data:
                        participation_output.append(vlan_participation_data)

        if participation_output:
            for participation in participation_output:
                for member, tag_data in participation.items():
                    if tag_data.get("untagged"):
                        vlan_output = dict()
                        vlan_output["mode"] = "untagged"
                        vlan_output["vid"] = str(tag_data.get("untagged"))
                        vlan_output["member"] = member
                        vlan_output["status"] = vlans_output["Vlan{}".format(vlan_output["vid"])]["status"]
                        vlan_output['status'] = vlan_output['status'].replace('UP', 'Active').replace('DOWN', 'Inactive')
                        output.append(vlan_output)
                        vlan_list.append('Vlan' + vlan_output["vid"])
                    if tag_data.get("tagged"):
                        for vlan_id in tag_data.get("tagged"):
                            vlan_output = dict()
                            vlan_output["mode"] = "tagged"
                            vlan_output["vid"] = str(vlan_id)
                            vlan_output["member"] = member
                            vlan_output["status"] = vlans_output["Vlan{}".format(vlan_id)]["status"]
                            vlan_output['status'] = vlan_output['status'].replace('UP', 'Active').replace('DOWN', 'Inactive')
                            output.append(vlan_output)
                            vlan_list.append('Vlan' + vlan_output["vid"])
        for vlan in set(vlan_list):
            if vlan in vlans_output:
                del vlans_output[vlan]

        if vlans_output:
            for vlan_id, vlan_status in vlans_output.items():
                vlan_output = dict()
                vlan_output["vid"] = vlan_id.strip("Vlan")
                vlan_output["status"] = vlan_status["status"]
                vlan_output['status'] = vlan_output['status'].replace('UP', 'Active').replace('DOWN', 'Inactive')
                vlan_output["member"] = ""
                vlan_output["mode"] = ""
                if vlan_output:
                    output.append(vlan_output)
        return output
    except Exception as e:
        st.error("Exception is :{}".format(e))


def config_vlan_autostate(dut, vlan, config='yes', cli_type='', skip_error=False, **kwargs):
    """
    To enable/disable autostate for single vlan, list of vlan,vlan range
    Author:Sooriya.Gajendrababu@broadcom.cm
    :param dut:
    :param vlan: - Accepts string,vlan_range,list of vlans
    :param config:
    :param cli_type:
    :param skip_error:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if isinstance(vlan, int):
        vlan = str(vlan)
    vlan_list = list()
    if '-' not in vlan:
        vlan_list = make_list(vlan)
    vlan_range = False
    if '-' in vlan and _has_vlan_range(dut):
        vlan_range = True
    cmd = list()
    if cli_type == 'click':
        action = 'enable' if config == 'yes' else 'disable'
        if vlan_range:
            vlan = vlan.split('-')
            start_vlan = vlan[0]
            end_vlan = vlan[1]
            cmd.append('config vlan range autostate {} {} {}'.format(start_vlan, end_vlan, action))
        else:
            for each_vlan in vlan_list:
                cmd.append('config vlan autostate {} {}'.format(each_vlan, action))
        st.config(dut, cmd, skip_error_check=skip_error, cli_type='click')
    elif cli_type == 'klish':
        action = '' if config == 'yes' else 'no '
        if vlan_range:
            vlan = vlan.split('-')
            start_vlan = vlan[0]
            end_vlan = vlan[1]
            cmd.append('interface range Vlan {}-{} '.format(start_vlan, end_vlan))
            cmd.append('{}autostate'.format(action))
        else:
            for each_vlan in vlan_list:
                cmd.append('interface Vlan{}'.format(each_vlan))
                cmd.append('{}autostate'.format(action))
                cmd.append('exit')
        out = st.config(dut, cmd, skip_error_check=skip_error, type='klish')
        return False if 'Error' in out else True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        http_method = kwargs.pop('http_method', cli_type)
        if '-' in vlan:
            vlans = vlan.split('-')
            vlan_list = range(int(vlans[0]), int(vlans[-1]) + 1)
        for each_vlan in vlan_list:
            rest_url = rest_urls['config_autostate'].format(each_vlan)
            oc_data = dict()
            oc_data["sonic-vlan:autostate"] = 'enable' if config == 'yes' else 'disable'
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=oc_data)
            if not response:
                return False
    return True


def append_autostate_data(dut, vlan_data):
    rest_urls = st.get_datastore(dut, 'rest_urls')
    rest_url = rest_urls['get_autostate']
    try:
        output = get_rest(dut, rest_url=rest_url)['output']['sonic-vlan:VLAN_LIST']
        for vlans in vlan_data:
            get_autostate = filter_and_select(output, match={"vlanid": vlans['vid']})
            if get_autostate:
                autostate = get_autostate[0].get('autostate', 'enable')
            match_item = filter_and_select(vlan_data, match={'vid': vlans['vid']})
            if match_item:
                for item in match_item:
                    item['autostate'] = autostate.capitalize()
        st.log(vlan_data)
        return vlan_data
    except Exception as e:
        st.error("Exception is :{}".format(e))


def config_reserved_vlan_range(dut, **kwargs):
    '''
    Purpose of this API is to change the Default Reserved  VLAN Range
    :param dut:
    :param reserved_range:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    config = kwargs.get('config', 'yes')
    skip_error = kwargs.get('skip_error', False)
    config = '' if config == 'yes' else 'no'
    command = '{} system vlan {} reserve'.format(config, int(kwargs.get('reserved_range')))
    if cli_type in get_supported_ui_type_list():
        rvlan_obj = umf_vlan_ext.ReserveVlan(VlanName=int(kwargs.get('reserved_range')))
        if config == '':
            result = rvlan_obj.configure(dut, cli_type=cli_type)
        else:
            result = rvlan_obj.unConfigure(dut, target_attr=rvlan_obj.VlanName, cli_type=cli_type)
        if not result.ok():
            st.error("test_step_failed: Reserved VLAN")
            return False
        return True
    elif cli_type == 'klish':
        result = st.config(dut, command, type=cli_type, skip_error_check=skip_error)
        if "%Error" in result or "% Error" in result:
            st.error("Failed to Change the Reserved VLAN Range")
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_url = st.get_datastore(dut, 'rest_urls')['config_show_reserved_vlan']
        if config == '':
            payload = {"openconfig-vlan-ext:reserve-vlans": {"reserve-vlan": []}}
            for vlan_id in range(int(kwargs.get('reserved_range')), int(kwargs.get('reserved_range')) + 128):
                temp = {"config": {"vlan-name": "Vlan{}".format(vlan_id)}, "vlan-name": "Vlan{}".format(vlan_id)}
                payload["openconfig-vlan-ext:reserve-vlans"]["reserve-vlan"].append(temp)
            if not config_rest(dut, http_method=cli_type, json_data=payload, rest_url=rest_url):
                st.error("Failed to Configure Reserved VLAN")
                return False
        else:
            if not delete_rest(dut, http_method=cli_type, rest_url=rest_url):
                st.error("Failed to Delete Reserved VLAN")
                return False
    else:
        st.log("Unsupported UI-TYPE: {}".format(cli_type))
        return False
    return True


def verify_reserved_vlan(dut, **kwargs):
    '''
    Purpose of this API is to Verify the Reserved VLAN
    :param dut:
    :param kwargs:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    skip_tmpl = kwargs.get('skip_tmpl', False)
    command = 'show system vlan reserved'
    if cli_type == 'klish':
        output = st.show(dut, command, type=cli_type, skip_tmpl=skip_tmpl)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_url = st.get_datastore(dut, 'rest_urls')['config_show_reserved_vlan']
        try:
            response = get_rest(dut, http_method=cli_type, rest_url=rest_url)['output']
            if "openconfig-vlan-ext:reserve-vlans" in response:
                total_len = len(response["openconfig-vlan-ext:reserve-vlans"]["reserve-vlan"])
                temp_min = str(response["openconfig-vlan-ext:reserve-vlans"]["reserve-vlan"][0]['config']['vlan-name'].split('n')[1])
                temp_max = str(response["openconfig-vlan-ext:reserve-vlans"]["reserve-vlan"][total_len - 1]['config']['vlan-name'].split('n')[1])
                output = [{'vlan_range': temp_min + '-' + temp_max}]
            else:
                output = st.show(dut, command, type='klish', skip_tmpl=skip_tmpl)
        except Exception as e:
            st.error("Exception Occurred is {}".format(e))
            return False
    else:
        st.log("Unsupported UI-TYPE: {}".format(cli_type))
        return False
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for each in kwargs.keys():
        match = {each: kwargs[each]}
        if not filter_and_select(output, None, match=match):
            st.error("Match not found for {}".format(kwargs[each]))
            return False
    return True


#################################################################################
# DELL APIS
#################################################################################
def configure_vlan_translation(dut, interface, s_vlan, **kwargs):
    '''
    Purpose: To configure single or double tagged vlan translation

    :param dut:
    :param interface:
    :param s_vlan:
    :param outer_c_vlan:
    :param inner_c_vlan:
    :param priority:
    :param multitag:
    :param kwargs:
    :return:

    Usage:
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100,priority=1)	--> Double Tag Translation
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,priority=1)			--> Single Tag Translation
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100)                 --> Double Tag Translation
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10)                                  --> Single Tag Translation
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100,multitag='y')	--> Multi Tag for Double Tag Translation
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,priority=1,multitag='y')		--> Multi tag for Single Tag Translation
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,config="no")					--> Unconfig all translations on s-vlan
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,priority=1,update_priority='y')			--> Config s-vlan priority (Supported only in 4.1)
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,priority='',config="no")				--> Unconfig s-vlan priority (Supported only in 4.1)
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,priority='',config="no")		--> Unconfig priority (Supported from 4.2))
        configure_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100,config="no")     --> Unconfig translation (Supported from 4.2)
    '''

    st.log('API_NAME: configure_vlan_translation, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)

    config = kwargs.get('config', 'yes').lower()
    skip_error = bool(kwargs.get('skip_error', False))
    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0
    outer_c_vlan = kwargs.get('outer_c_vlan', None)
    inner_c_vlan = kwargs.get('inner_c_vlan', None)
    priority = kwargs.get('priority', None)

    if cli_type == 'klish':

        my_cmd = list()
        intf = get_interface_number_from_name(interface)
        my_cmd.append("interface {} {}".format(intf['type'], intf['number']))

        if config == 'yes':
            if 'update_priority' in kwargs:
                if are_multi_flows_supported(dut):
                    if 'inner_c_vlan' in kwargs:
                        my_cmd.append('switchport vlan-mapping {} inner {} {} priority {}'.format(outer_c_vlan, inner_c_vlan, s_vlan, priority))
                    elif 'outer_c_vlan' in kwargs:
                        my_cmd.append('switchport vlan-mapping {} {} priority {}'.format(outer_c_vlan, s_vlan, priority))
                    else:
                        st.error("Starting Release 4.2, both s-vlan and c-vlan are required for priority configuration")
                        return False
                else:
                    my_cmd.append('switchport vlan-mapping {} priority {}'.format(s_vlan, priority))
            elif 'inner_c_vlan' in kwargs:
                double_tag_trans_cmd = 'switchport vlan-mapping {} inner {} {}'.format(outer_c_vlan, inner_c_vlan, s_vlan)
                if 'priority' in kwargs:
                    double_tag_trans_cmd += ' priority {}'.format(priority)
                if 'multitag' in kwargs:
                    double_tag_trans_cmd += ' multi-tag'
                my_cmd.append(double_tag_trans_cmd)
            elif 'outer_c_vlan' in kwargs:
                single_tag_trans_cmd = 'switchport vlan-mapping {} {}'.format(outer_c_vlan, s_vlan)
                if 'priority' in kwargs:
                    single_tag_trans_cmd += ' priority {}'.format(priority)
                if 'multitag' in kwargs:
                    single_tag_trans_cmd += ' multi-tag'
                my_cmd.append(single_tag_trans_cmd)
        else:
            if are_multi_flows_supported(dut):
                if 'inner_c_vlan' in kwargs:
                    double_tag_trans_cmd = 'no switchport vlan-mapping {} inner {} {}'.format(outer_c_vlan, inner_c_vlan, s_vlan)
                    if 'priority' in kwargs:
                        double_tag_trans_cmd += ' priority'
                    my_cmd.append(double_tag_trans_cmd)
                elif 'outer_c_vlan' in kwargs:
                    single_tag_trans_cmd = 'no switchport vlan-mapping {} {}'.format(outer_c_vlan, s_vlan)
                    if 'priority' in kwargs:
                        single_tag_trans_cmd += ' priority'
                    my_cmd.append(single_tag_trans_cmd)
                elif 'priority' in kwargs:
                    st.error("Starting Release 4.2, both s-vlan and c-vlan are required for priority deletion")
                    return False
                else:
                    my_cmd.append('no switchport vlan-mapping {}'.format(s_vlan))
            else:
                if 'priority' in kwargs:
                    my_cmd.append('no switchport vlan-mapping {} priority'.format(s_vlan))
                else:
                    my_cmd.append('no switchport vlan-mapping {}'.format(s_vlan))

        my_cmd.append('exit')
        return st.config(dut, my_cmd, type=cli_type, skip_error_check=skip_error, max_time=maxtime)

    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False


def configure_vlan_stacking(dut, interface, s_vlan, **kwargs):
    '''
    Purpose: To configure vlan stacking

    :param dut:
    :param interface:
    :param s_vlan:
    :param c_vlan_list:
    :param add_c_vlans:
    :param rem_c_vlans:
    :param priority:
    :param kwargs:
    :return:

    Usage:
        configure_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,c_vlan_list=[10,20,30],priority=1)
        configure_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,add_c_vlans=['10','21-25','30'],priority=1)
        configure_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1040,c_vlan_list='40,51-55,60')
        configure_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1040,add_c_vlans=50)
        configure_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1040,rem_c_vlans='41-50')
        configure_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,priority=2)			--> Config s-vlan priority alone
        configure_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,priority='',config="no")	--> Unconfig s-vlan priority alone
        configure_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,config="no")
    '''

    st.log('API_NAME: configure_vlan_stacking, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)

    config = kwargs.get('config', 'yes').lower()
    skip_error = bool(kwargs.get('skip_error', False))
    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0
    c_vlan_list = kwargs.get('c_vlan_list', None)
    add_c_vlans = kwargs.get('add_c_vlans', None)
    rem_c_vlans = kwargs.get('rem_c_vlans', None)
    priority = kwargs.get('priority', None)

    if cli_type == 'klish':

        c_vlan_str = ''

        if 'c_vlan_list' in kwargs:
            if isinstance(c_vlan_list, list):
                for c_vlan in c_vlan_list:
                    c_vlan_str += str(c_vlan)
                    c_vlan_str += ','
                c_vlan_str = c_vlan_str.strip(',')
            else:
                c_vlan_str = c_vlan_list

        if 'add_c_vlans' in kwargs:
            if isinstance(add_c_vlans, list):
                for c_vlan in add_c_vlans:
                    c_vlan_str += str(c_vlan)
                    c_vlan_str += ','
                c_vlan_str = c_vlan_str.strip(',')
            else:
                c_vlan_str = add_c_vlans

        if 'rem_c_vlans' in kwargs:
            if isinstance(rem_c_vlans, list):
                for c_vlan in rem_c_vlans:
                    c_vlan_str += str(c_vlan)
                    c_vlan_str += ','
                c_vlan_str = c_vlan_str.strip(',')
            else:
                c_vlan_str = rem_c_vlans

        my_cmd = list()
        intf = get_interface_number_from_name(interface)
        my_cmd.append("interface {} {}".format(intf['type'], intf['number']))

        if config == 'yes':
            if 'c_vlan_list' in kwargs:
                if 'priority' in kwargs:
                    my_cmd.append('switchport vlan-mapping {} dot1q-tunnel {} priority {}'.format(c_vlan_str, s_vlan, priority))
                else:
                    my_cmd.append('switchport vlan-mapping {} dot1q-tunnel {}'.format(c_vlan_str, s_vlan))
            elif 'add_c_vlans' in kwargs:
                if 'priority' in kwargs:
                    my_cmd.append('switchport vlan-mapping add {} dot1q-tunnel {} priority {}'.format(c_vlan_str, s_vlan, priority))
                else:
                    my_cmd.append('switchport vlan-mapping add {} dot1q-tunnel {}'.format(c_vlan_str, s_vlan))
            elif 'rem_c_vlans' in kwargs:
                my_cmd.append('switchport vlan-mapping remove {} dot1q-tunnel {}'.format(c_vlan_str, s_vlan))
            elif 'priority' in kwargs:
                my_cmd.append('switchport vlan-mapping dot1q-tunnel {} priority {}'.format(s_vlan, priority))
        else:
            if 'priority' in kwargs:
                my_cmd.append('no switchport vlan-mapping {} priority'.format(s_vlan))
            else:
                my_cmd.append('no switchport vlan-mapping {}'.format(s_vlan))
        my_cmd.append('exit')
        return st.config(dut, my_cmd, type=cli_type, skip_error_check=skip_error, max_time=maxtime)

    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False


def verify_vlan_translation(dut, **kwargs):
    '''
    Usage:
        verify_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100,priority=1) 	--> Double Tag
        verify_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,priority=1)				--> Single Tag
        verify_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100)
        verify_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10)
        verify_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,inner_c_vlan=100,flags='M')		--> Multi Tag
        verify_vlan_translation(dut=dut1,interface='Ethernet0',s_vlan=1000,outer_c_vlan=10,intf_filter='')
        verify_vlan_translation(dut=dut1,return_output='')
    '''

    st.log('API_NAME: verify_vlan_translation, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    cmd = ''

    skip_error = kwargs.get('skip_error', False)

    if cli_type == 'klish':
        if 'intf_filter' in kwargs:
            intf = get_interface_number_from_name(kwargs['interface'])
            cmd = "show interface {} {} vlan-mappings".format(intf['type'], intf['number'])
        else:
            cmd = "show interface vlan-mappings"
        output = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error)
        if 'return_output' in kwargs:
            return output

        if len(output) == 0:
            st.error("Output is Empty")
            return False

        input_dict = dict()
        input_dict['interface'] = kwargs.get('interface')
        input_dict['outer_c_vlan'] = kwargs.get('outer_c_vlan')
        input_dict['inner_c_vlan'] = kwargs.get('inner_c_vlan', '-')
        input_dict['s_vlan'] = kwargs.get('s_vlan')
        input_dict['vlan_priority'] = kwargs.get('priority', '-')
        if 'flags' in kwargs:
            input_dict['multi_tag'] = kwargs.get('flags')

        entries = filter_and_select(output, None, match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            return False
        else:
            st.log("DUT {} -> Match Found for {}".format(dut, input_dict))
            return True

    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False


def verify_vlan_stacking(dut, **kwargs):
    '''
    Usage:
        verify_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,c_vlan_list=[10,20,30],priority=1)
        verify_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,c_vlan_list=['10','21-25','30'],priority=1)
        verify_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,c_vlan_list='40,51-55,60')
        verify_vlan_stacking(dut=dut1,interface='Ethernet0',s_vlan=1000,c_vlan_list=10,intf_filter='')
        verify_vlan_stacking(dut=dut1,return_output='')
    '''

    st.log('API_NAME: verify_vlan_stacking, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    cmd = ''

    skip_error = kwargs.get('skip_error', False)

    if cli_type == 'klish':
        if 'intf_filter' in kwargs:
            intf = get_interface_number_from_name(kwargs['interface'])
            cmd = "show interface {} {} vlan-mappings dot1q-tunnel".format(intf['type'], intf['number'])
        else:
            cmd = "show interface vlan-mappings dot1q-tunnel"
        output = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error)

        if 'return_output' in kwargs:
            return output

        if len(output) == 0:
            st.error("Output is Empty")
            return False

        c_vlan_str = ''
        c_vlan_list = kwargs.get('c_vlan_list', None)
        if 'c_vlan_list' in kwargs:
            if isinstance(c_vlan_list, list):
                for c_vlan in c_vlan_list:
                    c_vlan_str += str(c_vlan)
                    c_vlan_str += ','
                c_vlan_str = c_vlan_str.strip(',')
            else:
                c_vlan_str = c_vlan_list

        input_dict = dict()
        input_dict['interface'] = kwargs.get('interface')
        input_dict['c_vlan_list'] = c_vlan_str
        input_dict['s_vlan'] = kwargs.get('s_vlan')
        input_dict['vlan_priority'] = kwargs.get('priority', '-')

        entries = filter_and_select(output, None, match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            return False
        else:
            st.log("DUT {} -> Match Found for {}".format(dut, input_dict))
            return True

    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False


def stacking_feature(dut, **kwargs):
    """
    Author: Divya Balasubramanian (divya_balasubramania@dell.com)
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    cli_cfg = ''
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    if cli_type == 'klish':
        cli_cfg += 'switch-resource \n'
        cli_cfg += '{} vlan-stacking \n'.format(config_cmd)
        st.config(dut, cli_cfg, type='klish')
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False


def are_multi_flows_supported(dut):
    """
    Purpose: This definition is used to check whether multiple VLAN translations can be configured on an interface associated to a S-vlan
    This capability is not supported on Release 4.1 and is supported only from Release 4.2 onwards.
    Hence this definition returns False for Software version 4.1 and True for all other later versions.
    """

    sw_version = st.get_testbed_vars().version[dut]

    release_regex = r'(\d\.\w)'
    release = re.findall(release_regex, sw_version)

    if release[0] == '4.1':
        return False
    # For all other versions including 4.x, return True
    else:
        return True
