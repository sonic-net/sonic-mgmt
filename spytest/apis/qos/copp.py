# This file contains the list of API's which performs copp operations.
# @author : Chaitanya Lohith Bollapragada (chaitanyalohith.bollapragada@broadcom.com)

import re
from spytest import st
from spytest.utils import filter_and_select
import apis.common.asic as asicapi
from apis.system.rest import get_rest
import utilities.utils as utils_obj
from utilities.common import do_eval

def get_copp_config(dut, **kwargs):
    """
    Gets value of an attribute from a table
    Author : Chaitanya Lohith Bollapragada (chaitanyalohith.bollapragada@broadcom.com)

    :param dut:
    :param table_name:
    :param attribute:
    :return value:
    """
    if 'table_name' not in kwargs:
        st.error("Mandatory parameter table_name not found")
        return False
    #command = "docker exec swss cat /etc/swss/config.d/00-copp.config.json"
    output = st.show(dut, "show copp config", skip_tmpl=True)
    reg_output = utils_obj.remove_last_line_from_string(output)
    if not reg_output:
        return False
    data = do_eval(reg_output)
    if not isinstance(data,dict):
        return False
    key = kwargs["table_name"]

    if key == "all":
        return data
    else:
        for each in data:
            if key in each:
                return data[each]['value']
    return False


def verify_copp_config(dut, **kwargs):
    """
    Verifies the table_name,value,attribute,value
    Author : Chaitanya Lohith Bollapragada (chaitanyalohith.bollapragada@broadcom.com)

    :param dut:
    :param table_name:
    :param attribute:
    :param value:
    :return bool:
    """
    if 'table_name' not in kwargs and 'attribute' not in kwargs and 'value' not in kwargs:
        st.error("Mandatory parameter table_name/attribute and value not found")
    if str(kwargs['value']) == get_copp_config(dut, **kwargs):
        return True
    else:
        return False


def set_copp_config(dut, *argv):
    """
    To set the config into copp
    Author : Chaitanya Lohith Bollapragada (chaitanyalohith.bollapragada@broadcom.com)
    Expected input from user should be [[table_name,attribute,value],[table_name,attribute,value],...]

    :param dut:
    :param table_name:
    :param attribute:
    :param value:
    :return bool:

    Example : set_copp_config(dut, ["COPP_TABLE:trap.group.bgp.lacp","queue","4"])
              set_copp_config(dut, ["COPP_TABLE:trap.group.bgp.lacp","queue","4"],["COPP_TABLE:trap.group.lldp.dhcp.udld","trap_priority","6"])
    """
    command = "docker exec swss cat /etc/swss/config.d/00-copp.config.json"
    output = st.show(dut, command, skip_tmpl=True)
    reg_output = utils_obj.remove_last_line_from_string(output)
    try:
        data = do_eval(reg_output)
    except Exception as e:
        st.log(e)
        reg_output = "{} ]".format(reg_output)
        data = do_eval(reg_output)
    st.log("ARGV {}".format(argv))
    for eachli in argv:
        if len(eachli) != 3:
            st.error("Invalid input is provided  {}".format(eachli))
            return False
        table = eachli[0]
        attribute = eachli[1]
        value = eachli[2]
        for each in data:
            if table in each:
                each[table][attribute] = value
                break
            else:
                st.error("Table not found {}".format(table))
                return False
    file_path = utils_obj.write_to_json_file(data, "/tmp/00-copp.config.json")
    st.log("FILE PATH -- {}".format(file_path))
    st.upload_file_to_dut(dut, file_path, "/tmp/00-copp.config.json")
    command = "docker cp /tmp/00-copp.config.json swss:/etc/swss/config.d/00-copp.config.json"
    st.config(dut, command)
    command = "rm /tmp/00-copp.config.json"
    st.config(dut, command)
    return True

def clear_cpu_queue_counters(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    API to clear CPU queue counters
    :param dut:
    :param queue_id: <0-31>
    :return:
    Example : clear_cpu_queue_counters(dut1)
              clear_cpu_queue_counters(dut1,queue_id="0")
    """
    if "queue_id" in kwargs:
        command = "clear queue counters interface CPU queue {}".format(kwargs['queue_id'])
    else:
        command = "clear queue counters interface CPU"

    st.config(dut, command,skip_tmpl=True,type="klish",conf=False, skip_error_check=True)
    return True

def get_cpu_queue_counters(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    API to return CPU queue counters
    :param dut:
    :param queue_id: <0-31>
    :param: <byte_count | pkts_drop | pps | bps | pkts_count | byte_drop >
    :return:
    Example : get_cpu_queue_counters(dut1)
              get_cpu_queue_counters(dut1,queue_id="0",param="pkts_drop")
    """

    if "queue_id" in kwargs:
        command = "show queue counters interface CPU queue {}".format(kwargs['queue_id'])
    else:
        command = "show queue counters interface CPU"

    if "queue_id" in kwargs:
        cli_out = st.show(dut,command,type="klish")
        fil_out = filter_and_select(cli_out, [kwargs['param']], {"txq" : "MC"+kwargs['queue_id']})
        return fil_out[0]
    else:
        cli_out = st.show(dut,command,type="klish")
        return cli_out


def config_copp_classifier(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    To configure classifier of type CoPP
    :param dut:
    :param classifier_name:
    :param protocol_trap_id:
    :param config:
    :return bool:

    Example : config_copp_classifier(dut1)
              config_copp_classifier(dut1,classifier_name="copp-system-arp",protocol_trap_id=["arp_req","arp_resp"],copp_group="copp-user-arp-action")
              config_copp_classifier(vars.D2,classifier_name="class1",protocol_trap_id=["arp_req","arp_resp"],cli_type="rest-put",config="yes")
              config_copp_classifier(vars.D2,classifier_name="class1",protocol_trap_id=["arp_req","arp_resp"],cli_type="rest-put",config="no")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    config_cmd = 'no' if kwargs.get('config','yes').lower() == 'no' else 'yes'

    if cli_type == 'klish':
        command = []
        if config_cmd == 'no':
            command.append("no class-map {}".format(kwargs['classifier_name']))
        else:
            command.append("class-map {} match-type copp".format(kwargs['classifier_name']))
            for id in kwargs['protocol_trap_id']:
                command.append("match protocol {}".format(id))
            command.append("exit")
        st.config(dut, command,type="klish")
    elif cli_type in ['rest-put','rest-patch']:
        class1 = kwargs['classifier_name']
        if config_cmd == 'no':
            bind_class_action_copp_policy(dut,classifier=class1,config="no")
            rest_urls = st.get_datastore(dut, "rest_urls")
            rest_url = rest_urls['copp_trap_config'].format(class1)
            output=st.rest_delete(dut, path=rest_url)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to delete classifier in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for classifier delete return status {}".format(output['status']))
                return True
        if isinstance(kwargs['protocol_trap_id'],list):
            trap1 = ""
            for id in kwargs['protocol_trap_id']:
                if kwargs['protocol_trap_id'].index(id) == 0:
                    trap1 = id
                else:
                    trap1 = trap1 + "," + id
        else:
           trap1 = kwargs['protocol_trap_id']
        copp_group = kwargs['copp_group']
        rest_urls = st.get_datastore(dut, "rest_urls")
        rest_url = rest_urls['copp_trap_global']
        rest_data = {"openconfig-copp-ext:copp-trap":[{"name":class1,"config":{"trap-ids":trap1,"trap-group":copp_group}}]}
        output=st.rest_create(dut, path=rest_url, data=rest_data)
        if output["status"] not in [200, 204, 201]:
            st.error("Failed to configure classifier in {} due to bad request {} seen for REST command".format(dut,output["status"]))
            return False
        else:
            st.log("PASS: Rest operation for classifier config return status {}".format(output['status']))

    return True

def config_copp_action_group(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    To configure classifier of type CoPP
    :param dut:
    :param copp_action_group:
    :param trap_action:
    :param trap_priority:
    :param trap_queue:
    :param police_meter_type:
    :param police_mode:
    :param cir:
    :param cbs:
    :param pir:
    :param pbs:
    :param config:
    :return bool:

    Example : config_copp_action_group(dut1,copp_action_group="copp-user-arp",config="no")
              config_copp_action_group(dut1,copp_action_group="copp-user-arp",
                                          trap_action="trap",trap_priority="3",trap_queue="3",
                                          police_meter_type="pps",police_mode="sr_tcm",
                                          cir="6000",cbs="6000")
              config_copp_action_group(vars.D2,copp_action_group="copp-group-arp",trap_priority="10",trap_queue="10",cir="3500",cbs="3570",
                                          trap_action="TRAP",cli_type="rest-put",config="yes")
              config_copp_action_group(vars.D2,copp_action_group="copp-group-arp",trap_priority="10",trap_queue="10",cir="3500",cbs="3570",
                                          trap_action="TRAP",cli_type="rest-put",config="no")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    config_cmd = 'no' if kwargs.get('config','yes').lower() == 'no' else 'yes'

    if cli_type == 'klish':
        command = []
        if config_cmd == 'no':
            command.append("no copp-action {}".format(kwargs['copp_action_group']))
        else:
            command.append("copp-action {}".format(kwargs['copp_action_group']))
            if "trap_action" in kwargs:
                command.append("set trap-action {}".format(kwargs['trap_action']))
            if "trap_priority" in kwargs:
                command.append("set trap-priority {}".format(kwargs['trap_priority']))
            if "trap_queue" in kwargs:
                command.append("set trap-queue {}".format(kwargs['trap_queue']))
            if "police_meter_type" in kwargs:
                command.append("police meter-type {}".format(kwargs['police_meter_type']))
            if "police_mode" in kwargs:
                command.append("police mode {} red drop".format(kwargs['police_mode']))
            if "cir" in kwargs and "cbs" in kwargs and "pir" not in kwargs:
                command.append("police cir {} cbs {}".format(kwargs['cir'],kwargs['cbs']))
            if "cir" in kwargs and "cbs" in kwargs and "pir" in kwargs and "pbs" in kwargs:
                command.append("police cir {} cbs {} pir {} pbs {}".format(kwargs['cir'],kwargs['cbs'],kwargs['pir'],kwargs['pbs']))
            command.append("exit")
            st.config(dut, command,type="klish")
    elif cli_type in ['rest-put','rest-patch']:
        if config_cmd == 'no':
            rest_urls = st.get_datastore(dut, "rest_urls")
            rest_url = rest_urls['copp_group_config'].format(kwargs['copp_action_group'])
            output=st.rest_delete(dut, path=rest_url)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to delete classifier in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for classifier delete return status {}".format(output['status']))
                return True
        else:
            #action = kwargs['trap_action']
            priority=int(kwargs['trap_priority']);queue=int(kwargs['trap_queue'])
            cir=kwargs['cir'];cbs=kwargs['cbs'];name=kwargs['copp_action_group']
            if 'police_meter_type' not in kwargs:
                ptype = "PACKETS"
            else:
                ptype = kwargs['police_meter_type']
            if 'police_mode' not in kwargs:
                pmode = "SR_TCM"
            else:
                pmode = kwargs['police_mode']
            trap_action = kwargs['trap_action'].upper()
            rest_urls = st.get_datastore(dut, "rest_urls")
            rest_url = rest_urls['copp_global']
            rest_data = {"openconfig-copp-ext:copp-groups":{"copp-group":[{"name":name,"config": \
                {"cbs":cbs,"cir":cir,"meter-type":ptype,"mode":pmode,"queue":queue,"trap-priority":priority, \
                 "trap-action":trap_action}}]}}
            st.rest_create(dut, path=rest_url, data=rest_data)
            output=st.rest_create(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure copp action in {} due to bad request {} seen for REST command".format(dut,output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for copp action config return status {}".format(output['status']))

    return True

def bind_class_action_copp_policy(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    To configure classifier of type CoPP
    :param dut:
    :param classifier:
    :param action_group:
    :param config:
    :return bool:

    Example : bind_class_action_copp_policy(dut1,classifier="copp-system-arp",action_group="copp-system-arp",config="no")
              bind_class_action_copp_policy(dut1,classifier="copp-system-arp",action_group="copp-system-nd")
    """
    config_cmd = 'no' if kwargs.get('config','yes').lower() == 'no' else 'yes'

    command = []
    if config_cmd == 'no':
        command.append("policy-map copp-system-policy type copp")
        command.append("no class {}".format(kwargs['classifier']))
        command.append("exit")
    else:
        command.append("policy-map copp-system-policy type copp")
        command.append("class {}".format(kwargs['classifier']))
        command.append("set copp-action {}".format(kwargs['action_group']))
        command.append("exit")
        command.append("exit")

    st.config(dut, command,type="klish")
    return True

def verify_cpu_queue_counters(dut,queue_name,param_list,val_list,tol_list):
    '''
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verifies CPU queue counters in the CLI show CPU queue counters
    :param dut: Device name where the command to be executed
    :type dut: string
    :param queue_name: queue name to be checked
    :type queue_name: string
    :param param_list: list of params to be verified; example ['pkts_count', 'pkts_drop']
    :param val_list: list of expected values for the params specified; example ['10000','5000']
    :param tol_list: tolerence value for each param while comparing; for example ['1000', '500']
    :return: True/False  True - success case; False - Failure case

    usage:  verify_cpu_queue_counters(dut1,'0',['pkts_count', 'pkts_drop'],
                                                       ['10000','5000'],['1000', '500'])
            verify_cpu_queue_counters(dut1,'0',['pkts_count'],['10000'],['1000'])

    '''

    success = True
    cli_out = st.show(dut,'show queue counters interface CPU queue {}'.format(queue_name),type="klish")
    fil_out = filter_and_select(cli_out, param_list, {"txq" : "MC"+queue_name})
    if not fil_out:
        st.error('port: CPU and queue name: {} not found in output: {}'.format(queue_name,cli_out))
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

def verify_copp_protocols(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_copp_protocols(dut=dut1,protocol=["bgp","lldp"])
    verify_copp_protocols(dut=dut2,protocol=["bgp","lldp","icmp","bgpv6"])

    To verify copp protocols
    :param dut:
    :param protocol:
    :param return_output: if this arg used API will return True, will only display show o/p without validation
    :return: True or False
    """
    if 'protocol' not in kwargs:
        st.error("Mandetory arg protocol is not present")
        return False

    output = st.show(dut,"show copp protocols",type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    ret_val = True
    if len(kwargs.keys()) > 0:
        #Converting all kwargs to list type to handle single or list of instances
        input_dict_list =[]
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val

def verify_copp_actions(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_copp_actions(dut=dut1,copp_group=["copp-system-ospf","copp-system-lldp"],trap-action=["copy","trap"])
    verify_copp_actions(dut=vars.D1,copp_agroup="copp-user-sflow-action",trap_action="trap",cir="6000",cbs="6070",trap_queue="3")

    To verify copp action groups
    :param dut:
    :param copp_agroup:
    :param trap_action:
    :param trap_queue:
    :param trap_priority:
    :param cir:
    :param cbs:
    :param meter_type:
    :param policer_mode:
    :param pol_red_action:
    :param return_output: if this arg used API will return the class entries matching copp class
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if cli_type == 'klish':
        output = st.show(dut,"show copp actions",type="klish")
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['show_copp_actions'].format(kwargs['copp_agroup'])
        response = get_rest(dut, rest_url=url)
        output = parse_show_copp_actions(response)
    elif cli_type == 'click':
        st.error("cli_type click is not not supported")
        return False

    if 'copp_agroup' not in kwargs:
        st.error("Mandetory arg copp_agroup is not present")
        return False
    if len(output) == 0:
        st.error("Output is Empty or copp group is not found through rest GET")
        return False
    if "return_output" in kwargs:
        return filter_and_select(output,None,match={'copp_agroup':kwargs['copp_agroup']})[0]

    ret_val = True
    if len(kwargs.keys()) > 0:
        #Converting all kwargs to list type to handle single or list of instances
        input_dict_list =[]
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val

def verify_classifier_match_type_copp(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_classifier_match_type_copp(dut=dut1,copp_class=["copp-system-ospf","copp-system-lldp"],protocol=["ospf","lldp"])

    To verify copp protocols
    :param dut:
    :param copp_class:
    :param protocol:
    :param return_output: if this arg used API will return parsed O/P
    :return: True or False
    """
    if 'copp_class' not in kwargs or 'protocol' not in kwargs:
        st.error("Mandetory args copp_class and protocol is not present")
        return False

    output = st.show(dut,"show class-map match-type copp",type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return output

    ret_val = True
    if len(kwargs.keys()) > 0:
        #Converting all kwargs to list type to handle single or list of instances
        input_dict_list =[]
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val

def verify_policy_type_copp(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_policy_type_copp(dut=dut1,copp_fgroup=["copp-system-bgp","copp-system-arp"],copp_agroup=["copp-system-bgp",copp-system-arp"])

    To verify copp protocols
    :param dut:
    :param copp_fgroup:
    :param copp_agroup:
    :param trap_action:
    :param trap_queue:
    :param trap_priority:
    :param cir:
    :param cbs:
    :param meter_type:
    :param policer_mode:
    :param pol_red_action:
    :param return_output: if this arg is used API return show o/p in list of dict format
    :return: True or False
    """
    output = st.show(dut,"show policy type copp",type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return output
    if 'copp_fgroup' not in kwargs:
        st.error("Mandetory arg copp_fgroup is not present")
        return False
    ret_val = True
    if len(kwargs.keys()) > 0:
        #Converting all kwargs to list type to handle single or list of instances
        input_dict_list =[]
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val

def verify_copp_classifiers(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_copp_classifiers(dut=dut1,copp_class=["copp-system-ospf","copp-system-lldp"],protocol=["ospf","lldp"])

    To verify copp protocols
    :param dut:
    :param copp_class:
    :param protocol:
    :param return_output: if this arg used API will return True, will only display show o/p without validation
    :return: True or False
    """
    if 'copp_class' not in kwargs:
        st.error("Mandetory arg copp_class is not present")
        return False

    output = st.show(dut,"show copp classifiers",type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    ret_val = True
    if len(kwargs.keys()) > 0:
        #Converting all kwargs to list type to handle single or list of instances
        input_dict_list =[]
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val


def verify_copp_policy(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_copp_policy(dut=dut1,copp_fgroup=["copp-system-bgp","copp-system-arp"],
        copp_agroup=["copp-system-bgp",copp-system-arp"],trap_action=["trap","copy"])

    To verify copp protocols
    :param dut:
    :param copp_fgroup:
    :param copp_agroup:
    :param trap_action:
    :param trap_queue:
    :param trap_priority:
    :param cir:
    :param cbs:
    :param packets:
    :param policer_mode:
    :param pol_red_action:
    :param return_output: if this arg is used API return show o/p in list of dict format
    :return: True or False
    """
    if 'copp_fgroup' not in kwargs:
        st.error("Mandetory arg copp_fgroup is not present")
        return False

    output = st.show(dut,"show copp policy",type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return output

    ret_val = True
    if len(kwargs.keys()) > 0:
        #Converting all kwargs to list type to handle single or list of instances
        input_dict_list =[]
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val

def get_copp_applied_policy_param(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    get_copp_applied_policy_param(dut=dut1,copp_fgroup=["copp-system-arp"])

    To return the parameter from show copp policy type copp output
    :param dut:
    :param copp_fgroup:
    :param param:
    :return: True or False
    """
    if 'copp_fgroup' not in kwargs:
        st.error("Mandetory arg copp_fgroup is not present")
        return False
    output = st.show(dut,"show policy type copp",type="klish")
    for entry in output:
        if entry['copp_fgroup'] == kwargs['copp_fgroup']:
            param_list = ['cbs', 'cir','trap_priority']
            if entry[kwargs['param']] != "":
                if kwargs['param'] in param_list:
                    return int(entry[kwargs['param']])
                else:
                    return entry[kwargs['param']]

    return False

def verify_cpu_queue_pkt_rate(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    API to verify CPU queue packet rate for a particular CPU queue in pkts/sec
    :param dut:
    :param queue_id: <0-31>
    :param exp_rate:
    :param tolerance:
    :return:
    Example : verify_cpu_queue_pkt_rate(dut1,queue_id="0",exp_rate="1800",tolerance="100")
    """
    nooftimes = 3
    for itercountvar in range(nooftimes):
        if itercountvar != 0:
            st.wait(1)

        if "from_pkts_count" in kwargs and kwargs['from_pkts_count'] == "yes":
            out1 = get_cpu_queue_counters(dut,queue_id=kwargs['queue_id'],param="pkts_count")
            st.wait(10)
            out2 = get_cpu_queue_counters(dut,queue_id=kwargs['queue_id'],param="pkts_count")
            ob_value = (int(out2['pkts_count'])-int(out1['pkts_count']))/10
        elif "from_pkts_count" not in kwargs:
            st.wait(13)
            out1 = get_cpu_queue_counters(dut,queue_id=kwargs['queue_id'],param="pps")
            ob_value = int(out1['pps'])

        start_value = int(kwargs['exp_rate']) - int(kwargs['tolerance'])
        end_value = int(kwargs['exp_rate']) + int(kwargs['tolerance'])
        if ob_value >= start_value and ob_value <= end_value:
            st.log('obtained rate {} for queue: {} is in the range b/w '
                   '{} and {}'.format(ob_value,kwargs['queue_id'],start_value,end_value))
            return True
        else:
            st.error('obtained rate {} for queue: {} is NOT in the range b/w '
                     '{} and {}'.format(ob_value, kwargs['queue_id'], start_value, end_value))
            if itercountvar < (nooftimes - 1):
                st.log("Re-verifying again..")
                continue
            return False

def debug_copp_config(dut):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    API to display the system internal details for CoPP config which can bed upon TC failure
    :param dut:
    :return: True
    Example :
    """
    st.log("----------------------------Debug show output 1-----------------------------")
    st.wait(2,"Waiting for debugsh to be ready")
    st.show(dut,'sudo debugsh $@ -c COPPMGRD -e show system internal coppmgr group',skip_tmpl=True)
    st.log("----------------------------Debug show output 2-----------------------------")
    st.wait(2,"Waiting for debugsh to be ready")
    st.show(dut, 'sudo debugsh $@ -c COPPMGRD -e show system internal coppmgr trap',skip_tmpl=True)
    st.log("----------------------------Debug show output 3-----------------------------")
    st.wait(1,"Waiting for debugsh to be ready")
    st.show(dut, "sudo sonic-db-dump -n 'APPL_DB' -k \"COPP_TABLE:*\" -y | grep -v hash",skip_tmpl=True)
    st.log("----------------------------Debug show end here-----------------------------")

    return True

def get_show_c_cpuq_counter(dut,queue):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    API to return CPU queue counters from show c
    :param dut:
    :param queue: <0-31>
    :return:
    Example : get_show_c_cpuq_counter(dut1)
              get_show_c_cpuq_counter(dut1,queue="0")
    """
    queue_mc = queue
    nooftimes = 3
    queue = 'PERQ_PKT(' + queue + ').cpu0'
    queue_mc = 'MC_PERQ_PKT(' + queue_mc + ').cpu0'
    for itercountvar in range(nooftimes):
        if itercountvar != 0:
            st.wait(5)
        cli_out = asicapi.get_counters(dut)
        fil_out = filter_and_select(cli_out, ["value"], {"key": queue})
        if not fil_out:
            fil_out = filter_and_select(cli_out, ["value"], {"key": queue_mc})
        if not fil_out:
            st.error('queue: {} not found in output: {}'.format(queue, cli_out))
            if itercountvar < (nooftimes - 1):
                continue
            return False
        else:
            if not fil_out[0]['value']:
                st.error('queue: {} value is null in the output: {}'.format(queue, fil_out))
                if itercountvar < (nooftimes - 1):
                    asicapi.clear_counters(dut)
                    continue
                return False
            fil_out = fil_out[0]

        if not fil_out['value']:
            st.error('queue: {} value is null in the output: {}'.format(queue, cli_out))
            if itercountvar < (nooftimes - 1):
                continue
            return False

        fil_out['value'] = re.sub(r'|'.join((',', '/s')), "", fil_out['value'])
        return int(fil_out['value'])
    return False

def config_copp_burst_rxrate(dut,**kwargs):
    """
    API to configure the copp rx rate and rx burst rate
    :param dut:
    :param rx_rate:
    :param rx_burst_rate:
    :return:
    """

    if 'skip_error' not in kwargs:
        skip_error = False
    else:
        skip_error = kwargs['skip_error']

    st.show(dut,'show copp rate-limit',skip_tmpl=True,type='click')
    if 'rx_rate' in kwargs:
        command = 'sudo config copp rx-rate {}'.format(kwargs['rx_rate'])
    if 'rx_burst_rate' in kwargs:
        command += '\n sudo config copp rx-burst {}'.format(kwargs['rx_burst_rate'])
    st.config(dut, command, skip_error_check=skip_error, type='click')
    st.show(dut,'show copp rate-limit',skip_tmpl=True,type='click')
    return True

def parse_show_copp_actions(response):
    dict1 = response["output"]
    if 'openconfig-copp-ext:copp-group' not in dict1:
        return []
    list1 = dict1['openconfig-copp-ext:copp-group']
    dict1 = list1[0]
    config = dict1['config']
    #state = dict1['state']
    output = {}
    output["copp_agroup"] = dict1['name']
    for arg in ["cbs","cir","meter-type","mode","queue","trap-action","trap-priority"]:
        if arg == "queue":
            arg1 = "trap_queue"
        elif arg == "meter-type":
            arg1 = "meter_type"
        elif arg == "trap-action":
            arg1 = "trap_action"
        elif arg == "trap-priority":
            arg1 = "trap_priority"
        else:
            arg1 = arg
        if isinstance(config[arg],int):
            output[arg1] = str(config[arg])
        else:
            output[arg1] = config[arg].lower()
    #for arg in ["cbs","cir","mode","queue"]:
    #    output[arg] = state[arg]
    #    st.log("state key and value are {} => {} ".format(arg,state[arg]))
    return [output]

def verify_qos_scheduler_policy(dut,**kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_qos_scheduler_policy(dut=dut1,queue="1",sch_policy_name="copp-scheduler-policy",sch_type="wrr",pir="100")

    To verify copp protocols
    :param dut:
    :param protocol:
    :param return_output: if this arg used API will return True, will only display show o/p without validation
    :return: True or False
    """
    if 'queue' not in kwargs:
        st.error("Mandetory arg queue is not present")
        return False

    output = st.show(dut,"show qos scheduler-policy",type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        for entry in output:
            for key,val in entry.items():
                if key == "queue" and val == kwargs['queue']:
                    return entry
        return False

    ret_val = True
    if len(kwargs.keys()) > 0:
        #Converting all kwargs to list type to handle single or list of instances
        input_dict_list =[]
        for key in kwargs:
            if type(kwargs[key]) is list:
                kwargs[key] = list(kwargs[key])
            else:
                kwargs[key] = [kwargs[key]]

        #convert kwargs into list of dictionary
        for i in range(len(kwargs[kwargs.keys()[0]])):
            temp_dict = {}
            for key in kwargs.keys():
                temp_dict[key] = kwargs[key][i]
            input_dict_list.append(temp_dict)

        for input_dict in input_dict_list:
            entries = filter_and_select(output,None,match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
                ret_val = False

    return ret_val


def config_coppgroup_copptrap_viarest(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    To configure classifier of type CoPP
    :param dut:
    :param classifier:
    :param action_group:
    :param config:
    :return bool:

    Example :
    copp.config_coppgroup_copptrap_viarest(vars.D2,classifier_name="class1", \
         protocol_trap_id=["arp_req","arp_resp"],copp_action_group="copp-group-arp", \
         trap_priority="10",trap_queue="10",cir="3500",cbs="3570",trap_action="trap")
    """

    #action = kwargs['trap_action'];
    priority=int(kwargs['trap_priority']);queue=int(kwargs['trap_queue'])
    cir=kwargs['cir'];cbs=kwargs['cbs'];name=kwargs['copp_action_group']
    if 'police_meter_type' not in kwargs:
        ptype = "PACKETS"
    else:
        ptype = kwargs['police_meter_type']
    if 'police_mode' not in kwargs:
        pmode = "SR_TCM"
    else:
        pmode = kwargs['police_mode']
    trap_action = kwargs['trap_action'].upper()
    class1 = kwargs['classifier_name']
    if isinstance(kwargs['protocol_trap_id'],list):
        trap1 = ""
        for id in kwargs['protocol_trap_id']:
            if kwargs['protocol_trap_id'].index(id) == 0:
                trap1 = id
            else:
                trap1 = trap1 + "," + id
    else:
       trap1 = kwargs['protocol_trap_id']

    rest_urls = st.get_datastore(dut, "rest_urls")
    rest_url = rest_urls['copp_global']
    rest_data = {"openconfig-copp-ext:copp-groups":{"copp-group":[{"name":name,"config": \
                    {"cbs":cbs,"cir":cir,"meter-type":ptype,"mode":pmode,"queue":queue,"trap-priority":priority, \
                    "trap-action":trap_action}}]}, \
                 "openconfig-copp-ext:copp-traps":{"copp-trap":[{"name":class1, \
                    "config":{"trap-ids":trap1,"trap-group":class1}}]}
                }

    output=st.rest_create(dut, path=rest_url, data=rest_data)
    if output["status"] not in [200, 204, 201]:
        st.error("Failed to configure copp group and copp trap in {} due to bad request {} seen for REST command".format(dut,output["status"]))
        return False
    else:
        st.log("PASS: Rest operation for copp group and copp trap config return status {}".format(output['status']))

    return True


def set_copp_pir_config(dut, config, *args):
    """
    To set the config into copp_config.json
    Author : vishnuvardhan.talluri@broadcom.com

    :param dut:
    :param config:
    :param args:
    :return:
    """

    command = "sudo cat /etc/sonic/copp_config.json"
    output = st.show(dut, command, skip_tmpl=True)
    reg_output = utils_obj.remove_last_line_from_string(output)
    try:
        data = eval(reg_output)
    except Exception as e:
        st.log(e)
        reg_output = str(reg_output) + "\n" + "}"
        data = eval(reg_output)
    st.log("ARGS {}".format(args))
    if config == "get":
        return data

    for eachli in args:
        if len(eachli) != 3:
            st.error("Invalid input is provided  {}".format(eachli))
            return False
        table = eachli[0]
        attribute = eachli[1]
        value = eachli[2]
        found_table = False
        if table in data['SCHEDULER'].keys():
            data['SCHEDULER'][table][attribute] = value
            found_table = True
        if not found_table:
            st.error("Table not found {}".format(table))
            return False

    file_path = utils_obj.write_to_json_file(data, "/tmp/00-copp.config.json")
    st.log("FILE PATH -- {}".format(file_path))
    st.upload_file_to_dut(dut, file_path, "/tmp/00-copp.config.json")
    command = "sudo cp /tmp/00-copp.config.json /etc/sonic/copp_config.json"
    st.config(dut, command)
    command = "rm /tmp/00-copp.config.json"
    st.config(dut, command)
    return True


