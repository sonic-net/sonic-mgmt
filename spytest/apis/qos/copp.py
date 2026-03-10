# This file contains the list of API's which performs copp operations.
# @author : Chaitanya Lohith Bollapragada (chaitanyalohith.bollapragada@broadcom.com)

import re
from spytest import st
import apis.common.asic as asicapi
from apis.system.rest import get_rest
from apis.system.rest import config_rest
import apis.system.basic as basic_api
import utilities.utils as utils_obj
from utilities.common import filter_and_select
from utilities.common import kwargs_to_dict_list
from utilities.common import get_query_params

try:
    import apis.yang.codegen.messages.copp_ext as umf_copp
except ImportError:
    pass

try:
    import apis.yang.codegen.messages.fbs_ext as umf_fbs
    from apis.yang.utils.common import Operation
except ImportError:
    pass

try:
    import apis.yang.codegen.messages.qos as umf_qos
except ImportError:
    pass


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
    # command = "docker exec swss cat /etc/swss/config.d/00-copp.config.json"
    output = st.show(dut, "show copp config", skip_tmpl=True)
    reg_output = utils_obj.remove_last_line_from_string(output)
    if not reg_output:
        return False
    try:
        # nosemgrep-next-line
        data = eval(reg_output)
    except Exception:
        st.error("Failed to eval '{}'".format(reg_output), dut=dut)
        return False
    if not isinstance(data, dict):
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
        # nosemgrep-next-line
        data = eval(reg_output)
    except Exception as e:
        st.log(e)
        reg_output = "{} ]".format(reg_output)
        # nosemgrep-next-line
        data = eval(reg_output)
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

    st.config(dut, command, skip_tmpl=True, type="klish", conf=False, skip_error_check=True)
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
        cli_out = st.show(dut, command, type="klish")
        if isinstance(cli_out, list) and len(cli_out) == 0:
            return {kwargs['param']: '0'}
        fil_out = filter_and_select(cli_out, [kwargs['param']], {"txq": "MC" + kwargs['queue_id']})
        return fil_out[0]
    else:
        command = "show queue counters interface CPU"
        cli_out = st.show(dut, command, type="klish")
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
              config_copp_classifier(dut1,classifier_name="copp-user-arp",protocol_trap_id=["arp_req","arp_resp"],copp_group="copp-user-arp-action")
              config_copp_classifier(vars.D2,classifier_name="class1",protocol_trap_id=["arp_req","arp_resp"],cli_type="rest-put",config="yes")
              config_copp_classifier(vars.D2,classifier_name="class1",protocol_trap_id=["arp_req","arp_resp"],cli_type="rest-put",config="no")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    config_cmd = 'no' if kwargs.get('config', 'yes').lower() == 'no' else 'yes'

    if cli_type in utils_obj.get_supported_ui_type_list():
        operation = Operation.CREATE
        if 'protocol_trap_id' in kwargs:
            if isinstance(kwargs['protocol_trap_id'], list):
                trap1 = ""
                for id in kwargs['protocol_trap_id']:
                    if kwargs['protocol_trap_id'].index(id) == 0:
                        trap1 = id
                    else:
                        trap1 = trap1 + "," + id
            else:
                trap1 = kwargs['protocol_trap_id']
        if config_cmd == 'no':
            bind_class_action_copp_policy(dut, classifier=kwargs['classifier_name'], config="no")
            trap_dict = {}
            if 'protocol_trap_id' in kwargs:
                trap_dict['TrapIds'] = trap1
            trap_group_obj = umf_copp.CoppTrap(Name=kwargs['classifier_name'], **trap_dict)
            st.banner("Unconfigure CoPP Classifier/Trap Name={}, TrapIds={}".format(kwargs['classifier_name'], trap_dict))
            result = trap_group_obj.unConfigure(dut, cli_type=cli_type)
        else:
            copp_kwargs = {}
            copp_kwargs["Name"] = kwargs['classifier_name']
            if 'protocol_trap_id' in kwargs:
                copp_kwargs["TrapIds"] = trap1
            if 'copp_group' in kwargs:
                copp_kwargs["TrapGroup"] = kwargs['copp_group']
            trap_group_obj = umf_copp.CoppTrap(**copp_kwargs)
            st.banner("Configure CoPP Classifier/Trap Name={}, TrapIds={}".format(kwargs['classifier_name'], trap1))
            result = trap_group_obj.configure(dut, operation=operation, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Configure CoPP Trap: {}'.format(result.data))
            return False
    elif cli_type == 'klish':
        command = []
        if config_cmd == 'no':
            command.append("no class-map {}".format(kwargs['classifier_name']))
        else:
            command.append("class-map {} match-type copp".format(kwargs['classifier_name']))
            trap_list = kwargs['protocol_trap_id'] if isinstance(kwargs['protocol_trap_id'], list) else [kwargs['protocol_trap_id']]
            for id in trap_list:
                command.append("match protocol {}".format(id))
            command.append("exit")
        st.config(dut, command, type="klish")
    elif cli_type in ['rest-put', 'rest-patch']:
        class1 = kwargs['classifier_name']
        if config_cmd == 'no':
            bind_class_action_copp_policy(dut, classifier=class1, config="no")
            rest_urls = st.get_datastore(dut, "rest_urls")
            rest_url = rest_urls['copp_trap_config'].format(class1)
            st.banner("For CoPP class deletion rest_url is {}".format(rest_url))
            output = st.rest_delete(dut, path=rest_url)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to delete classifier in {} due to bad request {} seen for REST command".format(dut, output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for classifier delete return status {}".format(output['status']))
                return True
        if isinstance(kwargs['protocol_trap_id'], list):
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
        rest_data = {"openconfig-copp-ext:copp-trap": [{"name": class1, "config": {"trap-ids": trap1, "trap-group": copp_group}}]}
        st.banner("For CoPP class creation rest_url is {}".format(rest_url))
        st.banner("For CoPP class creation rest_data is {}".format(rest_data))
        output = st.rest_create(dut, path=rest_url, data=rest_data)
        if output["status"] not in [200, 204, 201]:
            st.error("Failed to configure classifier in {} due to bad request {} seen for REST command".format(dut, output["status"]))
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    config_cmd = 'no' if kwargs.get('config', 'yes').lower() == 'no' else 'yes'

    if cli_type in utils_obj.get_supported_ui_type_list():
        operation = Operation.CREATE
        copp_kwargs = {}
        if "cir" in kwargs:
            copp_kwargs['Cir'] = kwargs['cir']
        if "cbs" in kwargs:
            copp_kwargs['Cbs'] = kwargs['cbs']
        if "trap_priority" in kwargs:
            copp_kwargs['TrapPriority'] = kwargs['trap_priority']
        if "trap_queue" in kwargs:
            copp_kwargs['Queue'] = kwargs['trap_queue']
        if "trap_action" in kwargs:
            copp_kwargs['TrapAction'] = kwargs['trap_action'].upper()
        copp_kwargs['MeterType'] = "PACKETS"
        copp_kwargs['Mode'] = "SR_TCM"
        copp_kwargs['GreenAction'] = "FORWARD"
        copp_kwargs['RedAction'] = "DROP"
        copp_kwargs['YellowAction'] = "FORWARD"
        str = ""
        for key in copp_kwargs.keys():
            str = str + " {} = {},".format(key, copp_kwargs[key])
        st.banner("Configure CoPP Action Group Attributes {} ".format(str))
        copp_group_obj = umf_copp.CoppGroup(kwargs['copp_action_group'], **copp_kwargs)
        if config_cmd == 'no':
            result = copp_group_obj.unConfigure(dut, cli_type=cli_type)
        else:
            result = copp_group_obj.configure(dut, operation=operation, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Configure CoPP Group: {}'.format(result.data))
            return False
    elif cli_type == 'klish':
        command = []
        if config_cmd == 'no':
            command.append("copp-action {}".format(kwargs['copp_action_group']))
            if "cir" in kwargs and "cbs" in kwargs and "pir" not in kwargs:
                command.append("no police cir cbs")
            if "trap_priority" in kwargs:
                command.append("no set trap-priority")
            if "trap_queue" in kwargs:
                command.append("no set trap-queue")
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
                command.append("police cir {} cbs {}".format(kwargs['cir'], kwargs['cbs']))
            if "cir" in kwargs and "cbs" in kwargs and "pir" in kwargs and "pbs" in kwargs:
                command.append("police cir {} cbs {} pir {} pbs {}".format(kwargs['cir'], kwargs['cbs'], kwargs['pir'], kwargs['pbs']))
        command.append("exit")
        st.config(dut, command, type="klish")
    elif cli_type in ['rest-put', 'rest-patch']:
        if config_cmd == 'no':
            rest_urls = st.get_datastore(dut, "rest_urls")
            rest_url = rest_urls['copp_group_config'].format(kwargs['copp_action_group'])
            st.banner("For CoPP action group deletion rest_url is {}".format(rest_url))
            output = st.rest_delete(dut, path=rest_url)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to delete classifier in {} due to bad request {} seen for REST command".format(dut, output["status"]))
                return False
            else:
                st.log("PASS: Rest operation for classifier delete return status {}".format(output['status']))
                return True
        else:
            # action = kwargs['trap_action']
            priority = int(kwargs['trap_priority'])
            queue = int(kwargs['trap_queue'])
            cir = kwargs['cir']
            cbs = kwargs['cbs']
            name = kwargs['copp_action_group']
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
            rest_data = {"openconfig-copp-ext:copp-groups": {"copp-group": [{"name": name, "config":
                                                                             {"cbs": cbs, "cir": cir, "meter-type": ptype, "mode": pmode, "queue": queue, "trap-priority": priority,
                                                                              "trap-action": trap_action}}]}}
            st.rest_create(dut, path=rest_url, data=rest_data)
            st.banner("For CoPP action group creation rest_url is {}".format(rest_url))
            st.banner("For CoPP action group creation rest_data is {}".format(rest_data))
            output = st.rest_create(dut, path=rest_url, data=rest_data)
            if output["status"] not in [200, 204, 201]:
                st.error("Failed to configure copp action in {} due to bad request {} seen for REST command".format(dut, output["status"]))
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
    config_cmd = 'no' if kwargs.get('config', 'yes').lower() == 'no' else 'yes'

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

    st.config(dut, command, type="klish")
    return True


def verify_cpu_queue_counters(dut, queue_name, param_list, val_list, tol_list):
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
    cli_out = st.show(dut, 'show queue counters interface CPU queue {}'.format(queue_name), type="klish")
    fil_out = filter_and_select(cli_out, param_list, {"txq": "MC" + queue_name})
    if not fil_out:
        st.error('port: CPU and queue name: {} not found in output: {}'.format(queue_name, cli_out))
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


def verify_copp_protocols(dut, **kwargs):
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

    output = st.show(dut, "show copp protocols", type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def verify_copp_actions(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_copp_actions(dut=dut1,copp_agroup=["copp-system-ospf","copp-system-lldp"],trap-action=["copy","trap"])
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
    :param pol_green_action:
    :param pol_yellow_action:
    :param pol_red_action:
    :param return_output: if this arg used API will return the class entries matching copp class
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))

    if "return_output" in kwargs:
        output = st.show(dut, "show copp actions", type="klish")
        return filter_and_select(output, None, match={'copp_agroup': kwargs['copp_agroup']})[0]

    if cli_type in utils_obj.get_supported_ui_type_list():
        group_list = list(kwargs['copp_agroup']) if isinstance(kwargs['copp_agroup'], list) else [kwargs['copp_agroup']]
        dict1 = {'cir': 'cir_list', 'cbs': 'cbs_list', 'trap_queue': 'tq_list', 'trap_action': 'ta_list', 'trap_priority': 'tp_list',
                 'meter_type': 'mtl', 'policer_mode': 'pml', 'pol_green_action': 'pgl', 'pol_yellow_action': 'pyl',
                 'pol_red_action': 'prl'}
        dict2 = {}
        dict2['group_list'] = group_list
        for key in dict1.keys():
            if key in kwargs:
                dict2[dict1[key]] = list(kwargs[key]) if isinstance(kwargs[key], list) else [kwargs[key]]
            else:
                dict2[dict1[key]] = [""] * 30
        rv = True
        for cg, cir, cbs, tq, ta, tp, mt, pm, pg, py, pr in zip(dict2['group_list'], dict2['cir_list'], dict2['cbs_list'],
                                                                dict2['tq_list'], dict2['ta_list'], dict2['tp_list'], dict2['mtl'], dict2['pml'],
                                                                dict2['pgl'], dict2['pyl'], dict2['prl']):
            copp_kwargs = {}
            copp_kwargs['Name'] = cg
            if "cir" in kwargs:
                copp_kwargs['Cir'] = cir
            if "cbs" in kwargs:
                copp_kwargs['Cbs'] = cbs
            if "trap_priority" in kwargs:
                copp_kwargs['TrapPriority'] = tp
            if "trap_queue" in kwargs:
                copp_kwargs['Queue'] = tq
            if "trap_action" in kwargs:
                copp_kwargs['TrapAction'] = ta.upper()
            if "meter_type" in kwargs:
                copp_kwargs['MeterType'] = mt.upper()
            if "policer_mode" in kwargs:
                copp_kwargs['Mode'] = pm.upper()
            if "pol_green_action" in kwargs:
                copp_kwargs['GreenAction'] = pg.upper()
            if "pol_yellow_action" in kwargs:
                copp_kwargs['YellowAction'] = py.upper()
            if "pol_red_action" in kwargs:
                copp_kwargs['RedAction'] = pr.upper()
            str = ""
            for key in copp_kwargs.keys():
                str = str + " {} = {},".format(key, copp_kwargs[key])
            st.banner("Verifying CoPP Action Group Attributes {} ".format(str))
            copp_group_obj = umf_copp.CoppGroup(**copp_kwargs)
            result = copp_group_obj.verify(dut, match_subset=True, cli_type=cli_type)
            if not result.ok():
                st.error('test_step_failed: Verify CoPP Action Group: {}'.format(result.data))
                rv = False
        return rv
    elif cli_type == 'klish':
        output = st.show(dut, "show copp actions", type="klish")
    elif cli_type in ['rest-put', 'rest-patch']:
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

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def verify_classifier_match_type_copp(dut, **kwargs):
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))

    if "return_output" in kwargs:
        output = st.show(dut, "show class-map match-type copp", type="klish")
        return output

    if cli_type in utils_obj.get_supported_ui_type_list():
        dict1 = {}
        class_list = list(kwargs['copp_class']) if isinstance(kwargs['copp_class'], list) else [kwargs['copp_class']]
        dict1['class_list'] = class_list
        if "protocol" in kwargs:
            dict1["protocol"] = list(kwargs["protocol"]) if isinstance(kwargs["protocol"], list) else [kwargs["protocol"]]
        else:
            dict1["protocol"] = [""] * 30
        rv = True
        for cl, pro in zip(dict1['class_list'], dict1['protocol']):
            copp_kwargs = {}
            copp_kwargs['Name'] = cl
            copp_kwargs['TrapGroup'] = cl
            if "protocol" in kwargs:
                copp_kwargs['TrapIds'] = pro
            str = ""
            for key in copp_kwargs.keys():
                str = str + " {} = {},".format(key, copp_kwargs[key])
            st.banner("Verifying CoPP Classifier/Trap Attributes {} ".format(str))
            copp_trap_obj = umf_copp.CoppTrap(**copp_kwargs)
            result = copp_trap_obj.verify(dut, match_subset=True, cli_type=cli_type)
            if not result.ok():
                st.error('test_step_failed: Verify CoPP Classifier/Trap: {}'.format(result.data))
                rv = False
        return rv
    else:
        output = st.show(dut, "show class-map match-type copp", type="klish")
        if len(output) == 0:
            st.error("Output is Empty")
            return False

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def verify_policy_type_copp(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_policy_type_copp(dut=dut1,copp_fgroup=["copp-system-bgp","copp-system-arp"],copp_agroup=["copp-system-bgp","copp-system-arp"])

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
    output = st.show(dut, "show policy-map type copp", type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return output
    if 'copp_fgroup' not in kwargs:
        st.error("Mandetory arg copp_fgroup is not present")
        return False
    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def verify_copp_classifiers(dut, **kwargs):
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

    output = st.show(dut, "show copp classifiers", type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return True

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def verify_copp_policy(dut, **kwargs):
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

    output = st.show(dut, "show copp policy", type="klish")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return output

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def get_copp_applied_policy_param(dut, **kwargs):
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
    output = st.show(dut, "show policy-map type copp", type="klish")
    for entry in output:
        if entry['copp_fgroup'] == kwargs['copp_fgroup']:
            param_list = ['cbs', 'cir', 'trap_priority']
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
    if 'queue_id' in kwargs and isinstance(kwargs['queue_id'], bool):
        return False
    nooftimes = 3
    for itercountvar in range(nooftimes):
        if itercountvar != 0:
            st.wait(1)

        if "from_knet_stats" in kwargs and kwargs["from_knet_stats"] != "":
            cli_out = st.show(dut, "show knet stats pkt-type", type="click")
            out1 = filter_and_select(cli_out, ["rx_pkts"], {"pkt_type": kwargs["from_knet_stats"]})
            st.wait(10)
            cli_out = st.show(dut, "show knet stats pkt-type", type="click")
            out2 = filter_and_select(cli_out, ["rx_pkts"], {"pkt_type": kwargs["from_knet_stats"]})
            st.log("{}: 1st Rx_pkts value is {} & 2nd Rx_Pkts value after 10 sec is {}".format(kwargs["from_knet_stats"],
                                                                                               out1[0]['rx_pkts'], out2[0]['rx_pkts']))
            ob_value = (int(out2[0]['rx_pkts']) - int(out1[0]['rx_pkts'])) // 10
        elif "from_pkts_count" in kwargs and kwargs['from_pkts_count'] == "yes":
            out1 = get_cpu_queue_counters(dut, queue_id=kwargs['queue_id'], param="pkts_count")
            st.wait(10)
            out2 = get_cpu_queue_counters(dut, queue_id=kwargs['queue_id'], param="pkts_count")
            ob_value = (int(out2['pkts_count']) - int(out1['pkts_count'])) / 10
        elif "from_pkts_count" not in kwargs and "from_knet_stats" not in kwargs:
            st.wait(13)
            out1 = get_cpu_queue_counters(dut, queue_id=kwargs['queue_id'], param="pps")
            ob_value = int(out1['pps'])

        start_value = int(kwargs['exp_rate']) - int(kwargs['tolerance'])
        end_value = int(kwargs['exp_rate']) + int(kwargs['tolerance'])
        if ob_value >= start_value and ob_value <= end_value:
            st.log('obtained rate {} for queue: {} is in the range b/w '
                   '{} and {}'.format(ob_value, kwargs['queue_id'], start_value, end_value))
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
    st.wait(2, "Waiting for debugsh to be ready")
    st.show(dut, 'sudo debugsh $@ -c COPPMGRD -e show system internal coppmgr group', skip_tmpl=True)
    st.log("----------------------------Debug show output 2-----------------------------")
    st.wait(2, "Waiting for debugsh to be ready")
    st.show(dut, 'sudo debugsh $@ -c COPPMGRD -e show system internal coppmgr trap', skip_tmpl=True)
    st.log("----------------------------Debug show output 3-----------------------------")
    st.wait(2, "Waiting for debugsh to be ready")
    st.show(dut, 'sudo debugsh $@ -c COPPMGRD -e show system internal coppmgr feature', skip_tmpl=True)
    st.log("----------------------------Debug show output 4-----------------------------")
    st.wait(1, "Waiting for debugsh to be ready")
    st.show(dut, "sudo sonic-db-dump -n 'APPL_DB' -k \"COPP_TABLE:*\" -y | grep -v hash", skip_tmpl=True)
    st.log("----------------------------Debug show end here-----------------------------")
    return True


def debug_system_internal_feature(dut):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    API to display the system internal details for CoPP config which can bed upon TC failure
    :param dut:
    :return: True
    Example :
    """
    st.log("----------------------------Debug show output start-----------------------------")
    st.wait(2, "Waiting for debugsh to be ready")
    st.show(dut, 'sudo debugsh $@ -c COPPMGRD -e show system internal coppmgr feature', skip_tmpl=True)
    st.log("----------------------------Debug show output end-----------------------------")
    return True


def get_show_c_cpuq_counter(dut, queue):
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


def config_copp_burst_rxrate(dut, **kwargs):
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

    st.show(dut, 'show copp rate-limit', skip_tmpl=True, type='click')
    if 'rx_rate' in kwargs:
        command = 'sudo config copp rx-rate {}'.format(kwargs['rx_rate'])
        st.config(dut, command, skip_error_check=skip_error, type='click')
    if 'rx_burst_rate' in kwargs:
        command = 'sudo config copp rx-burst {}'.format(kwargs['rx_burst_rate'])
        st.config(dut, command, skip_error_check=skip_error, type='click')
    st.show(dut, 'show copp rate-limit', skip_tmpl=True, type='click')
    return True


def parse_show_copp_actions(response):
    dict1 = response["output"]
    if 'openconfig-copp-ext:copp-group' not in dict1:
        return []
    list1 = dict1['openconfig-copp-ext:copp-group']
    dict1 = list1[0]
    config = dict1['config']
    output = {}
    output["copp_agroup"] = dict1['name']
    if 'red-action' in config:
        arg_list = ["cbs", "cir", "meter-type", "mode", "queue", "trap-action", "trap-priority", "red-action"]
    else:
        arg_list = ["cbs", "cir", "meter-type", "mode", "queue", "trap-action", "trap-priority"]
    for arg in arg_list:
        if arg == "queue":
            arg1 = "trap_queue"
        elif arg == "meter-type":
            arg1 = "meter_type"
        elif arg == "trap-action":
            arg1 = "trap_action"
        elif arg == "trap-priority":
            arg1 = "trap_priority"
        elif arg == "red-action":
            arg1 = "pol_red_action"
        else:
            arg1 = arg
        if isinstance(config[arg], int):
            output[arg1] = str(config[arg])
        else:
            output[arg1] = config[arg].lower()
    return [output]


def verify_qos_scheduler_policy(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_qos_scheduler_policy(dut=dut1,queue="1",sch_policy_name="copp-scheduler-policy",sch_type="wrr",pir="100")

    To verify copp protocols
    :param dut:
    :param protocol:
    :param return_output: returns o/p without validation
    :param return_param: <"weight" | "pir"> - used only if return_output is also passed
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    name = kwargs.pop('sch_policy_name', 'copp-scheduler-policy')

    if 'queue' not in kwargs:
        st.error("Mandetory arg queue is not present")
        return False
    if 'return_output' in kwargs:
        output = st.show(dut, "show qos scheduler-policy {}".format(name), type="klish")
        for entry in output:
            for key, val in list(entry.items()):
                if key == "queue" and val == kwargs['queue']:
                    if 'return_param' in kwargs:
                        return entry[kwargs['return_param']]
                    return entry
        return False

    if cli_type in utils_obj.get_supported_ui_type_list():
        kwarg1 = {}
        if 'queue' in kwargs:
            kwarg1['Sequence'] = kwargs['queue']
        if 'pir' in kwargs:
            kwarg1['Pir'] = kwargs['pir']
        if 'sch_type' in kwargs:
            kwarg1['Priority'] = kwargs['sch_type'].upper()
        qos_obj = umf_qos.Qos()
        scheduler_obj = umf_qos.SchedulerPolicy(Name=name, Qos=qos_obj)
        kwarg1['SchedulerPolicy'] = scheduler_obj
        if 'sch_type' in kwargs or 'pir' in kwargs:
            shaper_obj = umf_qos.SchedulerPoliciesScheduler(**kwarg1)
        else:
            st.error("Mandetory arg pir and sch_type not present")
            return False
        rv = True
        str1 = ""
        for key in kwarg1.keys():
            if key == 'SchedulerPolicy':
                str1 = str1 + " {} = {},".format(key, 'copp-scheduler-policy')
            else:
                str1 = str1 + " {} = {},".format(key, kwarg1[key])
        st.banner("Verifying copp-scheduler-policy attributes {}".format(str1))
        if 'pir' in kwargs:
            result = shaper_obj.verify(dut, target_attr=shaper_obj.Pir, cli_type="gnmi")
            if not result.ok():
                st.error('test_step_failed: Verify Copp Sceduler Policy Queue & Pir attribute: {}'.format(result.data))
                rv = False
        if 'sch_type' in kwargs:
            result = shaper_obj.verify(dut, target_attr=shaper_obj.Priority, cli_type="gnmi")
            if not result.ok():
                st.error('test_step_failed: Verify Copp Sceduler Policy Queue & Sch_type/Priority attribute: {}'.format(result.data))
                rv = False
        return rv
    elif cli_type == 'klish':
        output = st.show(dut, "show qos scheduler-policy {}".format(name), type="klish")
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if name == 'copp-scheduler-policy':
            if "weight" in kwargs:
                kwargs.pop('weight')
            url = rest_urls['shaper_pir_config'].format(name, kwargs['queue'])
            response = get_rest(dut, rest_url=url)
            output = parse_show_qos_scheduler_policy(response)
        else:
            url = rest_urls['scheduler_type_config'].format(name, kwargs['queue'])
            response = get_rest(dut, rest_url=url)
            output = []
            dict1 = {}
            dict1['sch_type'] = parse_show_qos_scheduler_type(response).lower()
            url = rest_urls['scheduler_weight'].format(name, kwargs['queue'])
            response = get_rest(dut, rest_url=url)
            dict1['weight'] = parse_show_qos_scheduler_weight(response)
            output = [dict1]
        output[0]['queue'] = kwargs['queue']
    elif cli_type == 'click':
        st.error("cli_type click is not not supported")
        return False

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
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

    # action = kwargs['trap_action'];
    priority = int(kwargs['trap_priority'])
    queue = int(kwargs['trap_queue'])
    cir = kwargs['cir']
    cbs = kwargs['cbs']
    name = kwargs['copp_action_group']
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
    if isinstance(kwargs['protocol_trap_id'], list):
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
    rest_data = {"openconfig-copp-ext:copp-groups": {"copp-group": [{"name": name, "config":
                                                                     {"cbs": cbs, "cir": cir, "meter-type": ptype, "mode": pmode, "queue": queue, "trap-priority": priority,
                                                                      "trap-action": trap_action}}]},
                 "openconfig-copp-ext:copp-traps": {"copp-trap": [{"name": class1,
                                                                   "config": {"trap-ids": trap1, "trap-group": class1}}]}
                 }

    output = st.rest_create(dut, path=rest_url, data=rest_data)
    st.banner("For CoPP policy creation rest_url is {}".format(rest_url))
    st.banner("For CoPP policy creation rest_data is {}".format(rest_data))
    if output["status"] not in [200, 204, 201]:
        st.error("Failed to configure copp group and copp trap in {} due to bad request {} seen for REST command".format(dut, output["status"]))
        return False
    else:
        st.log("PASS: Rest operation for copp group and copp trap config return status {}".format(output['status']))

    return True


def set_copp_pir_config(dut, config, *argv):
    """
    To set the config into copp_config.json
    Author : vishnuvardhan.talluri@broadcom.com

    :param dut:
    :param config:
    :param argv:
    :return:
    """

    command = "sudo cat /etc/sonic/copp_config.json"
    output = st.show(dut, command, skip_tmpl=True)
    reg_output = utils_obj.remove_last_line_from_string(output)
    try:
        # nosemgrep-next-line
        data = eval(reg_output)
    except Exception as e:
        st.log(e)
        reg_output = str(reg_output) + "\n" + "}"
        # nosemgrep-next-line
        data = eval(reg_output)
    st.log("ARGV {}".format(argv))
    if config == "get":
        return data

    for eachli in argv:
        if len(eachli) != 3:
            st.error("Invalid input is provided  {}".format(eachli))
            return False
        table = eachli[0]
        attribute = eachli[1]
        value = eachli[2]
        found_table = False
        if table in list(data['SCHEDULER'].keys()):
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


def config_acl_copp_policy(dut, policy_name, **kwargs):
    """
    Creating policy of ACL copp type
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to build policy table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type == "click":
        st.error("cli_type click is not supported ...")
        return False

    if 'policy_map' not in kwargs:
        kwargs['policy_map'] = "create"
    if 'class_map' not in kwargs:
        kwargs['class_map'] = "create"
    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False
    if 'config' not in kwargs:
        kwargs['config'] = "yes"
    elif kwargs.get('config', 'yes').lower() in ["yes", "no", "no_police"]:
        kwargs['config'] = kwargs['config'].lower()
    if 'yangtype' not in kwargs:
        kwargs['yangtype'] = "sonicyang"

    if cli_type == "klish":
        command = list()
        if kwargs['policy_map'] == "create":
            command.append("policy-map {} type acl-copp".format(policy_name))
            if 'class_name' in kwargs:
                if kwargs['class_map'] == "del":
                    command.append("no class {}".format(kwargs['class_name']))
                else:
                    if 'class_description' in kwargs:
                        if kwargs['config'] == "no":
                            command.append("no description")
                        else:
                            command.append("description {}".format(kwargs['class_description']))
                    if 'priority' in kwargs:
                        command.append("class {} priority {}".format(kwargs['class_name'], kwargs['priority']))
                    else:
                        command.append("class {}".format(kwargs['class_name']))
                    if 'trap_queue' in kwargs:
                        if kwargs['config'] == "no":
                            command.append("no set trap-queue")
                        else:
                            command.append("set trap-queue {}".format(kwargs['trap_queue']))
                    if 'description' in kwargs:
                        if kwargs['config'] == "no":
                            command.append("no description")
                        else:
                            command.append("description {}".format(kwargs['description']))
                    if kwargs['config'] == "no_police":
                        command.append('no police')
                    elif 'cir' in kwargs or 'cbs' in kwargs or 'pir' in kwargs or 'pbs' in kwargs:
                        keys = list(kwargs.keys())
                        cmd = 'no police' if kwargs['config'] == 'no' else 'police'
                        if 'cir' in keys:
                            cmd += ' cir' if kwargs['config'] == 'no' else ' cir ' + str(kwargs['cir'])
                        if 'cbs' in keys:
                            cmd += ' cbs' if kwargs['config'] == 'no' else ' cbs ' + str(kwargs['cbs'])
                        if 'pir' in keys:
                            cmd += ' pir' if kwargs['config'] == 'no' else ' pir ' + str(kwargs['pir'])
                        if 'pbs' in keys:
                            cmd += ' pbs' if kwargs['config'] == 'no' else ' pbs ' + str(kwargs['pbs'])
                        command.append(cmd)
                command.append('exit')
        elif kwargs['policy_map'] == "del":
            command.append("no policy-map {}".format(policy_name))
        st.config(dut, command, type=cli_type, skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if kwargs['policy_map'] == "create":
            if kwargs['yangtype'] == "sonicyang":
                rest_url = rest_urls['acl_copp_policy']
                ocdata = {"sonic-flow-based-services:POLICY_TABLE_LIST": [{"POLICY_NAME": policy_name, "DESCRIPTION": "", "TYPE": "ACL_COPP"}]}
                response = config_rest(dut, http_method='put', rest_url=rest_url, json_data=ocdata)
            else:
                rest_url = rest_urls['fbs_policies']
                descr = kwargs['description'] if 'description' in kwargs else ""
                ocdata = {"openconfig-fbs-ext:policy": [{"policy-name": policy_name,
                                                         "config": {"name": policy_name, "type": "openconfig-fbs-ext:POLICY_COPP", "description": descr}}]}
                response = config_rest(dut, http_method='post', rest_url=rest_url, json_data=ocdata)
            if 'class_name' in kwargs:
                if kwargs['class_map'] == "del":
                    if kwargs['yangtype'] == "sonicyang":
                        rest_url = rest_urls['policy_flow_nexthop_delete'].format(policy_name, kwargs['class_name'])
                        response = st.rest_delete(dut, path=rest_url)
                        st.log(response)
                    else:
                        rest_url = rest_urls['policy_flow_delete'].format(policy_name, kwargs['class_name'])
                        response = st.rest_delete(dut, path=rest_url)
                        st.log(response)
                else:
                    rest_url = rest_urls['policy_flow_class_delete']
                    if not isinstance(kwargs['class_name'], list):
                        if kwargs['yangtype'] == "sonicyang":
                            if 'description' not in kwargs:
                                kwargs['description'] = ""
                            if 'description' in kwargs and kwargs['config'] == "no":
                                kwargs['description'] = ""
                            ocdata = {"sonic-flow-based-services:POLICY_SECTIONS_TABLE_LIST": [{"CLASSIFIER_NAME": kwargs['class_name'],
                                                                                                "DESCRIPTION": kwargs['description'], "PRIORITY": int(kwargs['priority']), "POLICY_NAME": policy_name}]}
                            response = config_rest(dut, http_method='put', rest_url=rest_url, json_data=ocdata)
                            keys = list(kwargs.keys())
                            if 'trap_queue' in keys:
                                sonicyang_local_rest_function(dut, 'trap_queue', kwargs['trap_queue'], policy_name, kwargs['class_name'], kwargs['config'])
                            if 'cir' in keys:
                                sonicyang_local_rest_function(dut, 'cir', str(kwargs['cir']), policy_name, kwargs['class_name'], kwargs['config'])
                            if 'cbs' in keys:
                                sonicyang_local_rest_function(dut, 'cbs', str(kwargs['cbs']), policy_name, kwargs['class_name'], kwargs['config'])
                            if 'pir' in keys:
                                sonicyang_local_rest_function(dut, 'pir', str(kwargs['pir']), policy_name, kwargs['class_name'], kwargs['config'])
                            if 'pbs' in keys:
                                sonicyang_local_rest_function(dut, 'pbs', str(kwargs['pbs']), policy_name, kwargs['class_name'], kwargs['config'])
                            if 'description' in keys and kwargs['config'] == "no":
                                rest_url = rest_urls['acl_copp_policy_delete'].format(policy_name) + "/DESCRIPTION"
                                response = st.rest_delete(dut, path=rest_url)
                                st.log(response)
                        else:
                            rest_url = rest_urls['policy_flow_delete'].format(policy_name, kwargs['class_name'])
                            ocdata = {"openconfig-fbs-ext:section": [{"class": kwargs['class_name'], "config": {"name": kwargs['class_name'],
                                                                                                                "priority": int(kwargs['priority'])}}]}
                            response = config_rest(dut, http_method='put', rest_url=rest_url, json_data=ocdata)
                            keys = list(kwargs.keys())
                            if 'cir' in keys and 'cbs' not in keys:
                                ocyang_local_rest_function(dut, 'cir', str(kwargs['cir']), policy_name, kwargs['class_name'], kwargs['config'])
                            if 'pir' in keys and 'pbs' not in keys:
                                ocyang_local_rest_function(dut, 'pir', str(kwargs['pir']), policy_name, kwargs['class_name'], kwargs['config'])
                            if 'cir' in keys and 'cbs' in keys and 'pir' in keys and 'pbs' in keys:
                                ocyang_local_rest_function(dut, 'all', [str(kwargs['cir']), str(kwargs['pir']), str(kwargs['cbs']), str(kwargs['pbs'])], policy_name, kwargs['class_name'], kwargs['config'])
                            if 'cir' in keys and 'cbs' in keys and 'pir' not in keys and 'pbs' not in keys:
                                ocyang_local_rest_function(dut, 'cir', str(kwargs['cir']), policy_name, kwargs['class_name'], kwargs['config'])
                            if 'trap_queue' in keys:
                                ocyang_local_rest_function(dut, 'cpu-queue-index', kwargs['trap_queue'], policy_name, kwargs['class_name'], kwargs['config'])

                    else:
                        if kwargs['config'] == "no":
                            response = st.rest_delete(dut, path=rest_url)
                            st.log(response)
                        else:
                            li1 = []
                            li2 = []
                            if 'description' not in kwargs:
                                for cl1 in kwargs['class_name']:
                                    li2.append("")
                                kwargs['description'] = li2
                            for cl1 in kwargs['class_name']:
                                di1 = {}
                                ind = kwargs['class_name'].index(cl1)
                                di1["POLICY_NAME"] = policy_name
                                di1["CLASSIFIER_NAME"] = cl1
                                if isinstance(kwargs['description'], list):
                                    di1["DESCRIPTION"] = kwargs['description'][ind]
                                di1["PRIORITY"] = int(kwargs['priority'][ind])
                                keys = list(kwargs.keys())
                                if 'cir' in keys:
                                    di1["SET_POLICER_CIR"] = str(kwargs['cir'][ind])
                                if 'cbs' in keys:
                                    di1["SET_POLICER_CBS"] = str(kwargs['cbs'][ind])
                                if 'pir' in keys:
                                    di1["SET_POLICER_PIR"] = str(kwargs['pir'][ind])
                                if 'pbs' in keys:
                                    di1["SET_POLICER_PBS"] = str(kwargs['pbs'][ind])
                                if 'trap_queue' in keys:
                                    di1["SET_TRAP_QUEUE"] = int(kwargs['trap_queue'][ind])
                                li1.append(di1)
                            ocdata = {"sonic-flow-based-services:POLICY_SECTIONS_TABLE_LIST": li1}
                            response = config_rest(dut, http_method='put', rest_url=rest_url, json_data=ocdata)
        elif kwargs['policy_map'] == "del":
            if kwargs['yangtype'] == "sonicyang":
                rest_url = rest_urls['acl_copp_policy_delete'].format(policy_name)
                response = st.rest_delete(dut, path=rest_url)
                st.log(response)
            else:
                rest_url = rest_urls['policy_table_config']
                response = st.rest_delete(dut, path=rest_url)
                st.log(response)
    elif cli_type in utils_obj.get_supported_ui_type_list():
        policy_obj = umf_fbs.PolicyMap(Name=policy_name, Type="POLICY_COPP", Description="")
        if kwargs['policy_map'] == "create":
            result = policy_obj.configure(dut, cli_type=cli_type)
        elif kwargs['policy_map'] == "del":
            result = policy_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Configure Policy Map: {}'.format(result.data))
            return False
        if kwargs['policy_map'] == "del":
            return True
        if 'class_name' in kwargs:
            class_list = list(kwargs['class_name']) if isinstance(kwargs['class_name'], list) else [kwargs['class_name']]
            if 'priority' in kwargs:
                pi_list = list(kwargs['priority']) if isinstance(kwargs['priority'], list) else [kwargs['priority']]
            else:
                pi_list = []
                for i in range(len(class_list)):
                    pi_list.append(str(i + 10))
            if 'cir' not in kwargs:
                cir_list = [""] * len(class_list)
            if 'cbs' not in kwargs:
                cbs_list = [""] * len(class_list)
            if 'pir' not in kwargs:
                pir_list = [""] * len(class_list)
            if 'pbs' not in kwargs:
                pbs_list = [""] * len(class_list)
            if 'trap_queue' not in kwargs:
                q_list = [""] * len(class_list)
            if 'cir' in kwargs:
                cir_list = list(kwargs['cir']) if isinstance(kwargs['cir'], list) else [kwargs['cir']]
            if 'cbs' in kwargs:
                cbs_list = list(kwargs['cbs']) if isinstance(kwargs['cbs'], list) else [kwargs['cbs']]
            if 'pir' in kwargs:
                pir_list = list(kwargs['pir']) if isinstance(kwargs['pir'], list) else [kwargs['pir']]
            if 'pbs' in kwargs:
                pbs_list = list(kwargs['pbs']) if isinstance(kwargs['pbs'], list) else [kwargs['pbs']]
            if 'trap_queue' in kwargs:
                q_list = list(kwargs['trap_queue']) if isinstance(kwargs['trap_queue'], list) else [kwargs['trap_queue']]
            for class1, pi, cir, cbs, qu, pir, pbs in zip(class_list, pi_list, cir_list, cbs_list, q_list, pir_list, pbs_list):
                st.banner("Configure class {} pri {} cir {} cbs {} pir {} pbs {} queue {} under policy {}".format(class1, pi, cir, cbs, pir, pbs, qu, policy_name))
                sec_kwargs = {}
                if qu != "":
                    sec_kwargs["SetCpuQ"] = qu
                if cir != "":
                    sec_kwargs["CoppPolCir"] = cir
                if cbs != "":
                    sec_kwargs["CoppPolCbs"] = cbs
                if pir != "":
                    sec_kwargs["CoppPolPir"] = pir
                if pbs != "":
                    sec_kwargs["CoppPolPbs"] = pbs
                sec_kwargs["PolicyMap"] = policy_obj
                class_obj = umf_fbs.ClassMap(Name=class1, Description="", MatchType="MATCH_ACL")
                sec_obj = umf_fbs.PolicyMapSection(Name=class_obj, Priority=pi, Description="", **sec_kwargs)
                if kwargs['class_map'] == "create":
                    result = sec_obj.configure(dut, cli_type=cli_type)
                elif kwargs['class_map'] == "del":
                    result = sec_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.error('test_step_failed: Configure Policy Section: {}'.format(result.data))
                    return False
    elif cli_type == "click":
        st.error("cli_type click is not supported ...")
        return False

    return True


def sonicyang_local_rest_function(dut, key, val, policy_name, class_name, config):
    param = "SET_POLICER_" + key.upper() if key != 'trap_queue' else "SET_" + key.upper()
    value = val if key != 'trap_queue' else int(val)
    rest_urls = st.get_datastore(dut, "rest_urls")
    rest_url = rest_urls['policy_flow_nexthop_delete'].format(policy_name, class_name) + param
    if config == "no":
        response = st.rest_delete(dut, path=rest_url)
        st.log(response)
    else:
        ocdata = {"sonic-flow-based-services:{}".format(param): value}
        response = config_rest(dut, http_method='put', rest_url=rest_url, json_data=ocdata)


def ocyang_local_rest_function(dut, key, val, policy_name, class_name, config):
    val = val if key != 'cpu-queue-index' else int(val)
    rest_urls = st.get_datastore(dut, "rest_urls")
    if key in ["cir", "pir"]:
        rest_url = rest_urls['copp_policer_param_config'].format(policy_name, class_name, key)
    elif key == "cpu-queue-index":
        rest_url = rest_urls['policy_copp_config'].format(policy_name, class_name)
    else:
        rest_url = rest_urls['copp_policer_config'].format(policy_name, class_name)
    if config == "no":
        response = st.rest_delete(dut, path=rest_url)
        st.log(response)
    else:
        if key in ["cir", "pir"]:
            ocdata = {"openconfig-fbs-ext:{}".format(key): val}
        elif key == "cpu-queue-index":
            ocdata = {"openconfig-fbs-ext:config": {key: val}}
        elif key == "all":
            ocdata = {"openconfig-fbs-ext:config": {"cir": val[0], "pir": val[1], "cbs": val[2], "pbs": val[3]}}
        response = config_rest(dut, http_method='put', rest_url=rest_url, json_data=ocdata)


def bind_acl_copp_service_policy(dut, policy_map, **kwargs):
    """
    Bind and unbind ACL CoPP type service policy to interface CPU
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param policy_map:
    :param config: <yes|no>
    :param kwargs: Needed arguments to build policy table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = 'klish' if cli_type in utils_obj.get_supported_ui_type_list() else cli_type
    if 'config' not in kwargs:
        kwargs['config'] = "yes"
    elif kwargs.get('config', 'yes').lower() in ["yes", "no", "no_police"]:
        kwargs['config'] = kwargs['config'].lower()
    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False
    if cli_type == "klish":
        command = list()
        command.append("interface CPU")
        if kwargs['config'] == "yes":
            cli_out = st.show(dut, "show service-policy summary", type="klish")
            if filter_and_select(cli_out, [], {'policy_type': 'acl-copp', 'interface_name': 'CPU'}):
                st.error("One of the ACL CoPP is already active, so binding of this policy map not allowed")
                return False
            command.append("service-policy type acl-copp in {}".format(policy_map))
        else:
            command.append("no service-policy type acl-copp in")
        st.config(dut, command, type=cli_type, skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        if kwargs['config'] == "yes":
            cli_out = st.show(dut, "show service-policy summary", type="klish")
            if filter_and_select(cli_out, [], {'policy_type': 'acl-copp', 'interface_name': 'CPU'}):
                st.error("One of the ACL CoPP is already active, so binding of this policy map not allowed")
                return False
            rest_urls = st.get_datastore(dut, "rest_urls")
            rest_url = rest_urls['policy_bind_table_top']
            ocdata_table_list = {"POLICY_BINDING_TABLE_LIST": [{"INTERFACE_NAME": "CPU", "INGRESS_ACL_COPP_POLICY": policy_map}]}
            ocdata = {"sonic-flow-based-services:POLICY_BINDING_TABLE": ocdata_table_list}
            response = config_rest(dut, http_method='put', rest_url=rest_url, json_data=ocdata)
        else:
            rest_urls = st.get_datastore(dut, "rest_urls")
            rest_url = rest_urls['ingress_acl_copp_policy_bind'].format("CPU")
            response = st.rest_delete(dut, path=rest_url)
            if response:
                st.log(response)
        if not response:
            st.log(response)
            return False
    elif cli_type == "click":
        st.error("cli_type click is not supported ...")
        return False

    return True


def config_copp_acl_class_map(dut, **kwargs):
    """
    Configure the class map and associate or remove access group inside it
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param class_map:
    :param acl_type:
    :param acl_name:
    :param config: <yes|no>
    :param kwargs: Needed arguments to build policy table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))

    if 'config' not in kwargs:
        kwargs['config'] = "yes"
    elif kwargs.get('config', 'yes').lower() in ["yes", "no_class", "no"]:
        kwargs['config'] = kwargs['config'].lower()
    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False

    for key in kwargs:
        if key in ['class_map', 'acl_type', 'acl_name']:
            kwargs[key] = list(kwargs[key]) if type(kwargs[key]) is list else [kwargs[key]]

    if cli_type == "klish":
        command = list()
        for class1, type1, acl in zip(kwargs['class_map'], kwargs['acl_type'], kwargs['acl_name']):
            if kwargs['config'] == "no_class":
                command.append('no class-map {}'.format(class1))
            else:
                cmd = 'class-map {} match-type acl\n'.format(class1)
                cmd += 'match access-group {} {}\n'.format(type1, acl) \
                    if kwargs['config'] == "yes" else 'no match access-group\n'
                cmd += 'exit'
                command.append(cmd)
        st.config(dut, command, type=cli_type, skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        li1 = []
        rest_urls = st.get_datastore(dut, "rest_urls")
        rest_url = rest_urls['show_classifier_ocyang']
        for class1, type1, acl in zip(kwargs['class_map'], kwargs['acl_type'], kwargs['acl_name']):
            if len(kwargs['class_map']) == 1:
                if kwargs['config'] == "yes":
                    if type1 == "mac":
                        ty1 = "ACL_L2"
                    if type1 == "ip":
                        ty1 = "ACL_IPV4"
                    if type1.lower() == "ipv6":
                        ty1 = "ACL_IPV6"
                    ocdata = {"openconfig-fbs-ext:classifier": [{"class-name": class1,
                                                                 "config": {"name": class1, "match-type": "openconfig-fbs-ext:MATCH_ACL", "description": ""},
                                                                 "match-acl": {"config": {"acl-name": acl, "acl-type": ty1}}, "match-hdr-fields": {"config": {"match-all": True}}}]}
                    response = config_rest(dut, http_method='post', rest_url=rest_url, json_data=ocdata)
                else:
                    response = st.rest_delete(dut, path=rest_url)
                    st.log(response)
            else:
                di1 = {}
                if type1 == "mac":
                    ty1 = "ACL_L2"
                if type1 == "ip":
                    ty1 = "ACL_IPV4"
                if type1.lower() == "ipv6":
                    ty1 = "ACL_IPV6"
                match_type = {"name": class1, "match-type": "MATCH_ACL", "description": ""}
                acl_type = {"acl-name": acl, "acl-type": ty1}
                di1.update({"class-name": class1, "config": match_type, "match-acl": {"config": acl_type}})
                li1.append(di1)
        if len(kwargs['class_map']) > 1:
            if kwargs['config'] == "yes":
                ocdata = {"openconfig-fbs-ext:classifiers": {"classifier": li1}}
                response = config_rest(dut, http_method='put', rest_url=rest_url, json_data=ocdata)
            else:
                response = st.rest_delete(dut, path=rest_url)
                st.log(response)
    elif cli_type == "click":
        st.error("cli_type click is not supported ...")
        return False
    elif cli_type in utils_obj.get_supported_ui_type_list():
        for class1, type1, acl in zip(kwargs['class_map'], kwargs['acl_type'], kwargs['acl_name']):
            if type1 == "mac":
                ty1 = "ACL_L2"
            if type1 == "ip":
                ty1 = "ACL_IPV4"
            if type1.lower() == "ipv6":
                ty1 = "ACL_IPV6"
            class_obj = umf_fbs.ClassMap(Name=class1, AclName=acl, AclType=ty1, Description="", MatchType="MATCH_ACL")
            if kwargs['config'] == "yes":
                result = class_obj.configure(dut, cli_type=cli_type)
            else:
                result = class_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.error('test_step_failed: Configure Class Map: {}'.format(result.data))
                return False

    return True


def verify_show_acl_copp_policy(dut, policy_name, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_show_acl_copp_policy(dut=dut1,policy_name="policy1",class_name=["class1","class2"],cir=["100","200"],stage=["Ingress","Ingress"])

    To verify copp action groups
    :param dut:
    :param policy_name:
    :param class_name:
    :param priority:
    :param trap_queue:
    :param cir:
    :param cbs:
    :param pir:
    :param pbs:
    :param direction:
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))

    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False
    if 'return_output' in kwargs:
        return st.show(dut, "show policy-map {}".format(policy_name), type="klish", skip_error_check=kwargs['skip_error_check'])

    if cli_type in utils_obj.get_supported_ui_type_list():
        policy_obj = umf_fbs.PolicyMap(Name=policy_name, Type="POLICY_COPP", Description="")
        class_list = list(kwargs['class_name']) if isinstance(kwargs['class_name'], list) else [kwargs['class_name']]
        if 'cir' not in kwargs:
            cir_list = [""] * len(class_list)
        if 'cbs' not in kwargs:
            cbs_list = [""] * len(class_list)
        if 'pir' not in kwargs:
            pir_list = [""] * len(class_list)
        if 'pbs' not in kwargs:
            pbs_list = [""] * len(class_list)
        if 'trap_queue' not in kwargs:
            q_list = [""] * len(class_list)
        if 'priority_val' not in kwargs:
            pi_list = [""] * len(class_list)
        if 'priority_val' in kwargs:
            pi_list = list(kwargs['priority_val']) if isinstance(kwargs['priority_val'], list) else [kwargs['priority_val']]
        if 'cir' in kwargs:
            cir_list = list(kwargs['cir']) if isinstance(kwargs['cir'], list) else [kwargs['cir']]
        if 'cbs' in kwargs:
            cbs_list = list(kwargs['cbs']) if isinstance(kwargs['cbs'], list) else [kwargs['cbs']]
        if 'pir' in kwargs:
            pir_list = list(kwargs['pir']) if isinstance(kwargs['pir'], list) else [kwargs['pir']]
        if 'pbs' in kwargs:
            pbs_list = list(kwargs['pbs']) if isinstance(kwargs['pbs'], list) else [kwargs['pbs']]
        if 'trap_queue' in kwargs:
            q_list = list(kwargs['trap_queue']) if isinstance(kwargs['trap_queue'], list) else [kwargs['trap_queue']]
        rv = True
        for class1, pi, cir, cbs, pir, pbs, qu in zip(class_list, pi_list, cir_list, cbs_list, pir_list, pbs_list, q_list):
            sec_kwargs = {}
            sec_kwargs["PolicyMap"] = policy_obj
            if qu != "":
                sec_kwargs["SetCpuQ"] = qu
            if cir != "":
                sec_kwargs["CoppPolCir"] = cir
            if cbs != "":
                sec_kwargs["CoppPolCbs"] = cbs
            if pir != "":
                sec_kwargs["CoppPolPir"] = pir
            if pbs != "":
                sec_kwargs["CoppPolPbs"] = pbs
            if pi != "":
                sec_kwargs["Priority"] = pi
            if 'pcp_val' in kwargs:
                sec_kwargs['SetPcp'] = kwargs['pcp_val']
            if 'dscp_val' in kwargs:
                sec_kwargs['SetDscp'] = kwargs['dscp_val']
            if 'tc_val' in kwargs:
                sec_kwargs['SetTc'] = kwargs['tc_val']
            if 'discard_val' in kwargs:
                sec_kwargs['Discard'] = kwargs['discard_val']
            if 'cir_val' in kwargs:
                sec_kwargs['PolCir'] = kwargs['cir_val']
            if 'cbs_val' in kwargs:
                sec_kwargs['PolCbs'] = kwargs['cbs_val']
            class_obj = umf_fbs.ClassMap(Name=class1, Description="", MatchType="MATCH_ACL")
            sec_obj = umf_fbs.PolicyMapSection(Name=class_obj, **sec_kwargs)
            str1 = ""
            for key in sec_kwargs.keys():
                if key == "PolicyMap":
                    str1 = str1 + " {} = {},".format(key, policy_name)
                else:
                    str1 = str1 + " {} = {},".format(key, sec_kwargs[key])
            st.banner("Verifying Policy Map attributes {}".format(str1))
            result = sec_obj.verify(dut, match_subset=True, cli_type=cli_type)
            if not result.ok():
                st.error('test_step_failed: Verifying Policy Map: {}'.format(result.data))
                return False
        return rv
    elif cli_type == 'klish':
        output = st.show(dut, "show policy-map {}".format(policy_name), type="klish", skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        for key1 in ['direction', 'description']:
            kwargs.pop(key1, None)
        output = parse_show_acl_copp_policy(dut=dut, policy_map=policy_name)
    elif cli_type == 'click':
        st.error("cli_type click is not not supported")
        return False
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    del policy_name, kwargs['skip_error_check']
    ret_val = True

    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def verify_show_acl_copp_service_policy(dut, policy_map, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_show_acl_copp_service_policy(dut=dut1,policy_map="policy1",class_map=["class1","class2"],cir=["100","200"],match_frames=["10","11"])

    To verify copp action groups
    :param dut:
    :param policy_map:
    :param class_map:
    :param priority:
    :param trap_queue:
    :param cir:
    :param cbs:
    :param pir:
    :param pbs:
    :param class_status:
    :param policing_status:
    :param match_frames:
    :param match_bytes:
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    for attr in ['cir', 'cbs', 'pir', 'pbs', 'priority', 'trap_queue']:
        if attr in kwargs and cli_type in utils_obj.get_supported_ui_type_list():
            cli_type = "klish"

    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False
    if 'return_output' in kwargs:
        return st.show(dut, "show service-policy interface CPU type acl-copp", type="klish", skip_error_check=kwargs['skip_error_check'])

    if cli_type in utils_obj.get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        if 'class_map' not in kwargs:
            st.log("Mandetory arg class_map not passed")
            return False
        sec_kwarg = {}
        if 'oper_cir' in kwargs:
            sec_kwarg['Cir'] = kwargs['oper_cir']
        if 'oper_cbs' in kwargs:
            sec_kwarg['Cbs'] = kwargs['oper_cbs']
        if 'oper_pir' in kwargs:
            sec_kwarg['Pir'] = kwargs['oper_pir']
        if 'oper_pbs' in kwargs:
            sec_kwarg['Pbs'] = kwargs['oper_pbs']
        if 'class_status' in kwargs:
            sec_kwarg['Active'] = True if kwargs['class_status'] == "Active" else False
        sec_obj = umf_fbs.IngCpuCoPPPolicySection(ClassMap=kwargs['class_map'], **sec_kwarg)
        result = sec_obj.verify(dut, match_subset=True, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Verify IngCpuCoPPPolicySection parameters {}'.format(result.data))
            return False
        else:
            st.log('test_step_pased: Verify IngCpuCoPPPolicySection parameters {}'.format(result.data))
        rv = sec_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        if rv.ok():
            st.log("#### UMF O/P:{} #####".format(rv.payload))
            output = parse_get_payload_show_acl_copp_service_policy(rv.payload)
            for arg in ['oper_cir', 'oper_cbs', 'oper_pir', 'oper_pbs', 'policing_status']:
                if arg in kwargs:
                    del kwargs[arg]
        else:
            output = []
    elif cli_type == "klish":
        output = st.show(dut, "show service-policy interface CPU type acl-copp", type="klish", skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        policy = policy_map
        policy_map = [policy_map]
        for key1 in ["match_frames", "match_bytes", "green_pkts", "green_bytes", "yellow_pkts", "yellow_bytes", "red_pkts", "red_bytes", "class_status"]:
            kwargs.pop(key1, None)
        output = parse_show_acl_copp_service_policy(dut, policy_map)
    elif cli_type == 'click':
        st.error("cli_type click is not not supported")
        return False
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    del policy_map, kwargs['skip_error_check']
    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            if "match_frames" in input_dict or "match_bytes" in input_dict or "green_pkts" in input_dict or "green_bytes" in input_dict \
                    or "yellow_pkts" in input_dict or "yellow_bytes" in input_dict or "red_pkts" in input_dict or "red_bytes" in input_dict:
                for output_dict in output:
                    for key in ["match_frames", "match_bytes", "green_pkts", "green_bytes", "yellow_pkts", "yellow_bytes", "red_pkts", "red_bytes"]:
                        if key in input_dict and input_dict["class_map"] == output_dict["class_map"]:
                            if int(input_dict[key]) <= int(output_dict[key]):
                                st.log("PASS DUT {} -> No of {} observed {} >= expected {} in class {}".format(dut,
                                                                                                               key, output_dict[key], input_dict[key], input_dict["class_map"]))
                            else:
                                st.log("FAIL DUT {} -> No of {} observed {} not >= expected {} in class {}".format(dut,
                                                                                                                   key, output_dict[key], input_dict[key], input_dict["class_map"]))
                                ret_val = False

        for key in ["match_frames", "match_bytes", "green_pkts", "green_bytes", "yellow_pkts", "yellow_bytes", "red_pkts", "red_bytes"]:
            if key in input_dict_list[0]:
                for entry in input_dict_list:
                    ind = input_dict_list.index(entry)
                    del input_dict_list[ind][key]

        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
                if cli_type in ['rest-put', 'rest-patch'] and not verify_acl_copp_service_policy_summary(dut, policy_name=policy):
                    st.banner("ACL CoPP Policy is configured but not applied under interface CPU")
                    ret_val = False
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def verify_show_all_acl_copp_policy(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_show_all_acl_copp_policy(dut=dut1,policy_map=["policy1","policy2"],class_map=["class1","class2"], \
        cir=["100","200"],direction=["Ingress","Ingress"])

    To verify show policy-map type acl-copp
    :param dut:
    :param policy_map:
    :param class_map:
    :param priority:
    :param trap_queue:
    :param cir:
    :param cbs:
    :param pir:
    :param pbs:
    :param direction:
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))

    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False
    if 'return_output' in kwargs:
        return st.show(dut, "show policy-map type acl-copp", type="klish", skip_error_check=kwargs['skip_error_check'])

    if cli_type in utils_obj.get_supported_ui_type_list():
        kwargs['policy_name'] = kwargs['policy_map']
        kwargs['class_name'] = kwargs['class_map']
        kwargs['cli_type'] = cli_type
        kwargs.pop('policy_map')
        kwargs.pop('class_map')
        for key in kwargs.keys():
            st.log("{} = {}".format(key, kwargs[key]))
        return verify_show_acl_copp_policy(dut, **kwargs)
    elif cli_type == 'klish':
        output = st.show(dut, "show policy-map type acl-copp", type="klish", skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        if 'direction' in kwargs:
            del kwargs['direction']
        if type(kwargs['policy_map']) is list:
            kwargs['policy_map'] = list(kwargs['policy_map'])
        else:
            kwargs['policy_map'] = [kwargs['policy_map']]
        output = parse_show_acl_copp_service_policy(dut, kwargs['policy_map'])
    elif cli_type == 'click':
        st.error("cli_type click is not not supported")
        return False
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    del kwargs['skip_error_check']

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def verify_show_all_acl_copp_service_policy(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_show_all_acl_copp_service_policy(dut=dut1,policy_map=["policy1","policy1"],class_map=["class1","class2"], \
        cir=["100","200"],match_frames=["10","11"])

    To verify copp action groups
    :param dut:
    :param policy_map:
    :param class_map:
    :param priority:
    :param trap_queue:
    :param cir:
    :param cbs:
    :param pir:
    :param pbs:
    :param class_status:
    :param policing_status:
    :param match_frames:
    :param match_bytes:
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = 'klish' if cli_type in utils_obj.get_supported_ui_type_list() else cli_type

    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False
    if 'return_output' in kwargs:
        return st.show(dut, "show service-policy interface CPU", type="klish", skip_error_check=kwargs['skip_error_check'])
    if cli_type == "klish":
        output = st.show(dut, "show service-policy interface CPU", type="klish", skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        for key1 in ["match_frames", "match_bytes", "green_pkts", "green_bytes", "yellow_pkts", "yellow_bytes", "red_pkts", "red_bytes", "class_status"]:
            kwargs.pop(key1, None)
        if type(kwargs['policy_map']) is list:
            policy = kwargs['policy_map'][0]
            kwargs['policy_map'] = list(kwargs['policy_map'])
        else:
            policy = kwargs['policy_map']
            kwargs['policy_map'] = [kwargs['policy_map']]
        output = parse_show_acl_copp_service_policy(dut, kwargs['policy_map'])
    elif cli_type == 'click':
        st.error("cli_type click is not not supported")
        return False
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    del kwargs['skip_error_check']
    if 'type_acl_copp' in kwargs:
        del kwargs['type_acl_copp']

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            if "match_frames" in input_dict or "match_bytes" in input_dict or "green_pkts" in input_dict or "green_bytes" in input_dict \
                    or "yellow_pkts" in input_dict or "yellow_bytes" in input_dict or "red_pkts" in input_dict or "red_bytes" in input_dict:
                for output_dict in output:
                    for key in ["match_frames", "match_bytes", "green_pkts", "green_bytes", "yellow_pkts", "yellow_bytes", "red_pkts", "red_bytes"]:
                        if key in input_dict and input_dict["class_map"] == output_dict["class_map"]:
                            if int(input_dict[key]) <= int(output_dict[key]):
                                st.log("PASS DUT {} -> No of {} observed {} >= expected {} in class {}".format(dut,
                                                                                                               key, output_dict[key], input_dict[key], input_dict["class_map"]))
                            else:
                                st.log("FAIL DUT {} -> No of {} observed {} not >= expected {} in class {}".format(dut,
                                                                                                                   key, output_dict[key], input_dict[key], input_dict["class_map"]))
                                ret_val = False

        for key in ["match_frames", "match_bytes", "green_pkts", "green_bytes", "yellow_pkts", "yellow_bytes", "red_pkts", "red_bytes"]:
            if key in input_dict_list[0]:
                for entry in input_dict_list:
                    ind = input_dict_list.index(entry)
                    del input_dict_list[ind][key]

        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
                if cli_type in ['rest-put', 'rest-patch'] and not verify_acl_copp_service_policy_summary(dut, policy_name=policy):
                    st.banner("ACL CoPP Policy is configured but not applied under interface CPU")
                    ret_val = False
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def clear_counters_acl_copp_service_policy(dut, **kwargs):
    """
    Clear counters for the ACL CoPP type service policy
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param policy_map [NOTE: optional for klish but mandatory for REST]:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = 'klish' if cli_type in utils_obj.get_supported_ui_type_list() else cli_type

    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False
    if cli_type == "klish":
        if 'policy_map' in kwargs:
            command = "clear counters service-policy policy-map {}".format(kwargs['policy_map'])
        else:
            command = "clear counters service-policy interface CPU type acl-copp"
        st.config(dut, command, type=cli_type, conf=False, skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        if 'policy_map' in kwargs:
            rest_urls = st.get_datastore(dut, "rest_urls")
            rest_url = rest_urls['clear_service_policy_counters']
            ocdata = {"sonic-flow-based-services:input": {"POLICY_NAME": kwargs['policy_map']}}
            response = config_rest(dut, http_method='post', rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log(response)
                return False
        else:
            st.error("policy_map arg is mandetory when cli_type is REST related")
            return False
    elif cli_type == "click":
        st.error("cli_type click is not supported ...")
        return False

    return True


def verify_acl_copp_service_policy_summary(dut, policy_name, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    API to validate ACL CoPP service-policy if applied under CPU using show service-policy summary
    :param dut:
    :param policy_name : [optional arg]
    :return:
    Example : verify_acl_copp_service_policy_summary(dut1,policy_name="policy1")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = 'klish' if cli_type in utils_obj.get_supported_ui_type_list() else cli_type

    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = False
    if cli_type == "klish":
        command = "show service-policy summary"
        cli_out = st.show(dut, command, type="klish")
        if filter_and_select(cli_out, [], {'policy_type': 'acl-copp', 'interface_name': 'CPU'}):
            out = filter_and_select(cli_out, ['policy_name'], {'policy_type': 'acl-copp', 'interface_name': 'CPU'})
            if filter_and_select(cli_out, [], {'policy_type': 'acl-copp', 'policy_name': policy_name}):
                st.log("Match found for Policy_name seen {} and expected {}".format(out[0]['policy_name'], policy_name))
                return True
            else:
                st.error("No Match found for Policy_name seen {} and expected {}".format(out[0]['policy_name'], policy_name))
                return False
        else:
            st.error("No ACL CoPP service-policy is active under interface CPU")
            return False
    elif cli_type == "click":
        st.error("cli_type click is not supported ...")
        return False
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        rest_url = rest_urls['show_service_policy_summary']
        output = st.rest_read(dut, path=rest_url)['output'].get('sonic-flow-based-services:POLICY_BINDING_TABLE_LIST', [])
        st.banner('Rest output shown {}'.format(output))
        if filter_and_select(output, ['INGRESS_ACL_COPP_POLICY'], {'INTERFACE_NAME': 'CPU'}):
            if filter_and_select(output, [], {'INTERFACE_NAME': 'CPU', 'INGRESS_ACL_COPP_POLICY': policy_name}):
                out = filter_and_select(output, [], {'INTERFACE_NAME': 'CPU', 'INGRESS_ACL_COPP_POLICY': policy_name})
                st.log("Match found for Policy_name seen {} and expected {}".format(out[0]['INGRESS_ACL_COPP_POLICY'], policy_name))
                return True
            else:
                out = filter_and_select(output, ['INGRESS_ACL_COPP_POLICY'], {'INTERFACE_NAME': 'CPU'})
                st.error("No Match found for Policy_name seen {} and expected {}".format(out[0]['INGRESS_ACL_COPP_POLICY'], policy_name))
                return False
        else:
            st.error("No ACL CoPP service-policy is active under interface CPU")
            return False


def parse_show_acl_copp_service_policy(dut, policy_map):
    rest_urls = st.get_datastore(dut, "rest_urls")
    rest_url = rest_urls['show_service_policy_all']
    result = st.rest_read(dut, path=rest_url)['output'].get('sonic-flow-based-services:sonic-flow-based-services', [])

    if 'POLICY_SECTIONS_TABLE' in result and 'POLICY_SECTIONS_TABLE_LIST' in result['POLICY_SECTIONS_TABLE']:
        response = result['POLICY_SECTIONS_TABLE']['POLICY_SECTIONS_TABLE_LIST']
    else:
        return []

    output = []
    dict1 = {'policy_map': '', 'class_map': '', 'priority': '', 'trap_queue': '', 'cir': '', 'cbs': '', 'pir': '', 'pbs': ''}
    output.append(dict1)
    for in_policy in policy_map:
        for out_policy in response:
            dict1 = {}
            if out_policy['POLICY_NAME'] == in_policy:
                dict1['policy_map'] = str(out_policy['POLICY_NAME'])
                dict1['class_map'] = str(out_policy['CLASSIFIER_NAME'])
                dict1['class_name'] = str(out_policy['CLASSIFIER_NAME'])
                dict1['priority'] = str(out_policy['PRIORITY'])
                dict1['priority_val'] = str(out_policy['PRIORITY'])
                if 'SET_TRAP_QUEUE' in out_policy:
                    dict1['trap_queue'] = str(out_policy['SET_TRAP_QUEUE'])
                if 'SET_POLICER_CIR' in out_policy:
                    dict1['cir'] = str(out_policy['SET_POLICER_CIR'])
                if 'SET_POLICER_CBS' in out_policy:
                    dict1['cbs'] = str(out_policy['SET_POLICER_CBS'])
                if 'SET_POLICER_PIR' in out_policy:
                    dict1['pir'] = str(out_policy['SET_POLICER_PIR'])
                if 'SET_POLICER_PBS' in out_policy:
                    dict1['pbs'] = str(out_policy['SET_POLICER_PBS'])
                if 'DESCRIPTION' in out_policy:
                    dict1['description'] = str(out_policy['DESCRIPTION'])
                    dict1['desc_name'] = str(out_policy['DESCRIPTION'])
                output.append(dict1)

    st.banner('REST OUTPUT FROM parse_show_acl_copp_service_policy')
    st.log("REST OUTOUT IS {}".format(response))
    st.banner('MACTHED SERVICE POLICY FROM parse_show_acl_copp_service_policy')
    st.log("MACTHED SERVICE POLICY IS is {}".format(output))
    return output


def parse_show_acl_copp_policy(dut, policy_map):
    rest_urls = st.get_datastore(dut, "rest_urls")
    rest_url = rest_urls['policy_section'].format(policy_map)
    result = st.rest_read(dut, path=rest_url)['output']

    if 'openconfig-fbs-ext:sections' in result and 'section' in result['openconfig-fbs-ext:sections']:
        res_list = result['openconfig-fbs-ext:sections']['section']
    else:
        return []

    output = []
    dict1 = {'policy_map': '', 'class_map': '', 'priority': '', 'trap_queue': '', 'cir': '', 'cbs': '', 'pir': '', 'pbs': ''}
    output.append(dict1)
    for in_policy in policy_map:
        for out_policy in res_list:
            dict1 = {}
            dict1['policy_map'] = in_policy
            dict1['class_map'] = str(out_policy['class'])
            dict1['class_name'] = str(out_policy['class'])
            dict1['priority'] = str(out_policy['state']['priority'])
            dict1['priority_val'] = str(out_policy['state']['priority'])
            if 'cpu-queue-index' in out_policy['copp']['config']:
                dict1['trap_queue'] = str(out_policy['copp']['config']['cpu-queue-index'])
            if 'cir' in out_policy['copp']['policer']['state']:
                dict1['cir'] = str(out_policy['copp']['policer']['state']['cir'])
            if 'cbs' in out_policy['copp']['policer']['state']:
                dict1['cbs'] = str(out_policy['copp']['policer']['state']['cbs'])
            if 'pir' in out_policy['copp']['policer']['state']:
                dict1['pir'] = str(out_policy['copp']['policer']['state']['pir'])
            if 'pbs' in out_policy['copp']['policer']['state']:
                dict1['pbs'] = str(out_policy['copp']['policer']['state']['pbs'])
            output.append(dict1)

    st.banner('REST OUTPUT FROM parse_show_acl_copp_policy')
    st.log("REST OUTOUT IS {}".format(res_list))
    st.banner('MACTHED SERVICE POLICY FROM parse_show_acl_copp_policy')
    st.log("MACTHED SERVICE POLICY IS is {}".format(output))
    return output


def verify_show_class_map_acl(dut, class_name, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_show_class_map_acl(vars.D1,class_name="class1",cli_type="rest-put")
    To verify copp action groups
    :param dut:
    :param acl_name:
    :param class_name:
    :param acl_type:
    :param match_type:
    :param priority_val:
    :param desc_name:
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))

    if 'skip_error_check' not in kwargs:
        kwargs['skip_error_check'] = True
    if 'return_output' in kwargs:
        return st.show(dut, "show class-map {}".format(class_name), type="klish", skip_error_check=kwargs['skip_error_check'])

    if cli_type in utils_obj.get_supported_ui_type_list():
        class_list = list(class_name) if isinstance(class_name, list) else [class_name]
        if 'acl_name' not in kwargs:
            an_list = [""] * len(class_list)
        if 'desc_name' not in kwargs:
            dn_list = [""] * len(class_list)
        if 'acl_type' not in kwargs:
            at_list = [""] * len(class_list)
        if 'match_type' not in kwargs:
            mt_list = [""] * len(class_list)
        if 'acl_name' in kwargs:
            an_list = list(kwargs['acl_name']) if isinstance(kwargs['acl_name'], list) else [kwargs['acl_name']]
        if 'acl_type' in kwargs:
            at_list = list(kwargs['acl_type']) if isinstance(kwargs['acl_type'], list) else [kwargs['acl_type']]
        if 'desc_name' in kwargs:
            dn_list = list(kwargs['desc_name']) if isinstance(kwargs['desc_name'], list) else [kwargs['desc_name']]
        if 'match_type' in kwargs:
            mt_list = list(kwargs['match_type']) if isinstance(kwargs['match_type'], list) else [kwargs['match_type']]
        rv = True
        for class1, type1, acl, dn, mt in zip(class_list, at_list, an_list, dn_list, mt_list):
            kwarg1 = {}
            kwarg1["Name"] = class1
            acl_type_map = {"mac": "ACL_L2", "ip": "ACL_IPV4", "ipv6": "ACL_IPV6"}
            if type1 != "":
                kwarg1["AclType"] = acl_type_map[type1.lower()]
            if acl != "":
                kwarg1["AclName"] = acl
            if dn != "":
                kwarg1["Description"] = dn
            kwarg1["MatchType"] = mt
            if mt != "":
                kwarg1["MatchType"] = "MATCH_FIELDS" if mt in ["fields"] else mt
            else:
                kwarg1["MatchType"] = "MATCH_ACL"
            class_obj = umf_fbs.ClassMap(**kwarg1)
            str1 = ""
            for key in kwarg1.keys():
                str1 = str1 + " {} = {},".format(key, kwarg1[key])
            st.banner("Verifying Class Map attributes {}".format(str1))
            result = class_obj.verify(dut, match_subset=True, cli_type=cli_type)
            if not result.ok():
                st.error('test_step_failed: Verifying Class Map: {}'.format(result.data))
                rv = False
        return rv
    elif cli_type == 'klish':
        output = st.show(dut, "show class-map {}".format(class_name), type=cli_type, skip_error_check=True, skip_tmpl=True)
        error_pattern = r'Error: Classifier(.*)not found'
        if re.findall(error_pattern, output):
            st.error("class_name {} was not found".format(class_name))
            return False
        output = st.show(dut, "show class-map {}".format(class_name), type=cli_type, skip_error_check=kwargs['skip_error_check'])
    elif cli_type in ['rest-put', 'rest-patch']:
        for key1 in ['policy_name', 'priority_val']:
            kwargs.pop(key1, None)
        output = parse_show_class_map_acl(dut, class_name)
    elif cli_type == 'click':
        st.error("cli_type click is not not supported")
        return False
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    del kwargs['skip_error_check']

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            entries = filter_and_select(output, None, match=input_dict)
            if entries:
                st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
            else:
                st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
                ret_val = False

    return ret_val


def parse_show_class_map_acl(dut, class_name):
    rest_urls = st.get_datastore(dut, "rest_urls")
    rest_url = rest_urls['classifier_update_delete'].format(class_name)
    result = st.rest_read(dut, path=rest_url)['output']
    if 'openconfig-fbs-ext:classifier' in result:
        res_list = result['openconfig-fbs-ext:classifier']
    else:
        return []

    output = []
    dict1 = {'class_name': '', 'acl_type': '', 'match_type': '', 'dscription': ''}
    output.append(dict1)
    for out_class in res_list:
        if class_name == out_class['class-name']:
            dict1 = {}
            dict1['class_name'] = out_class['class-name']
            dict1['match_type'] = out_class['state']['match-type']
            if 'match-acl' in out_class and 'acl-type' in out_class['match-acl']['state']:
                dict1['acl_type'] = out_class['match-acl']['state']['acl-type']
                if dict1['acl_type'] == 'openconfig-acl:ACL_L2':
                    dict1['acl_type'] = 'mac'
                elif dict1['acl_type'] == 'openconfig-acl:ACL_IPV4':
                    dict1['acl_type'] = 'ipv4'
                elif dict1['acl_type'] == 'openconfig-acl:ACL_IPV6':
                    dict1['acl_type'] = 'ipv6'
            if dict1['match_type'] == 'openconfig-fbs-ext:MATCH_ACL':
                dict1['match_type'] = 'acl'
            if 'match-acl' in out_class and 'acl-name' in out_class['match-acl']['state']:
                dict1['acl_name'] = out_class['match-acl']['state']['acl-name']
            if 'description' in out_class['state']:
                dict1['description'] = str(out_class['state']['description'])
            output.append(dict1)

    st.banner('REST OUTPUT FROM parse_show_class_map_acl')
    st.log("REST OUTOUT IS {}".format(res_list))
    st.banner('MACTHED SERVICE POLICY FROM parse_show_class_map_acl')
    st.log("MACTHED SERVICE POLICY IS is {}".format(output))
    return output


def verify_per_platform_copp_policer_scheduler(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    Example 1: verify_per_platform_copp_policer_scheduler(dut1,cli_type="rest-put")
    Example 2: verify_per_platform_copp_policer_scheduler(dut1)

    To return the per platform CoPP default parameters
    :param dut:
    :param cli_type < optional arg >
    :param return_output < optional arg >
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = "klish" if cli_type == 'click' else cli_type
    ret_val = True

    platform = basic_api.get_platform_summary(dut, value="platform")
    chip = basic_api.get_hwsku(dut)
    file = "/usr/share/sonic/device/" + platform + "/" + chip + "/copp_platform_config.j2"
    ret_dict = {}
    output = st.show(dut, "ls {}".format(file), type="click", skip_tmpl=True)
    if "ls: cannot access" in output:
        str1 = "DUT does not have this file so per platform CoPP verification skipped"
        st.banner("API STEP 1: File generated is {} but {}".format(file, str1))
        if 'return_output' in kwargs:
            ret_dict["copp_platform_config_Exist"] = "No"
            return ret_dict
        return True
    else:
        str1 = "DUT have this file so lets proceed with verification"
        st.banner("API STEP 1: File generated is {} but {}".format(file, str1))
        output = st.show(dut, "cat {}".format(file), type="click", skip_tmpl=True)
        reg_output = utils_obj.remove_last_line_from_string(output)
        if not reg_output:
            if 'return_output' in kwargs:
                ret_dict["copp_platform_config_FileContent"] = "empty"
                return ret_dict
            return False
        # nosemgrep-next-line
        data = eval(reg_output)
        if not isinstance(data, dict):
            st.error("API STEP 2: File exist but JSON file do not have any line in it")
            if 'return_output' in kwargs:
                ret_dict["copp_platform_config_FileDictFormat"] = "No"
                return ret_dict
            return False

        if 'return_output' in kwargs:
            ret_dict["COPP_GROUP"] = data["COPP_GROUP"]
            ret_dict["SCHEDULER"] = data["SCHEDULER"]
            return ret_dict
        str1 = "Per Platform CoPP Policy Policing Parameter verification"
        if 'COPP_GROUP' not in list(data.keys()):
            st.banner("COPP_GROUP key is not present in the JSON file so {} missed".format(str1))
        else:
            st.banner("COPP_GROUP key is present in the JSON file so proceed to {}".format(str1))
            flow_list = []
            group_list = []
            cir_list = []
            cbs_list = []
            for policy in data['COPP_GROUP']:
                flow_list.append(policy)
                group_list.append(policy)
                cir_list.append(data['COPP_GROUP'][policy]['cir'])
                cbs_list.append(data['COPP_GROUP'][policy]['cbs'])
                for attribute in ["red_action", "trap_queue"]:
                    if attribute in list(data['COPP_GROUP'][policy].keys()):
                        str1 = "in the JSON so verifying show policy-map type copp"
                        st.log("{} was found for the policy {} {}".format(attribute, policy, str1))
                        str1 = "in the policy"
                        str2 = "b/w JSON and show output"
                        if attribute == "red_action":
                            if cli_type in ['rest-put', 'rest-patch'] or cli_type in utils_obj.get_supported_ui_type_list():
                                if not verify_copp_actions(dut, copp_agroup=policy,
                                                           pol_red_action=data['COPP_GROUP'][policy][attribute], cli_type=cli_type):
                                    st.banner("API STEP 3 FAIL: {} {} {} mismatch {}".format(attribute, str1, policy, str2))
                                    ret_val = False
                                else:
                                    st.banner("API STEP 3 PASS: {} {} {} match {}".format(attribute, str1, policy, str2))
                            else:
                                if not verify_policy_type_copp(dut=dut, copp_fgroup=policy, copp_agroup=policy,
                                                               pol_red_action=data['COPP_GROUP'][policy][attribute]):
                                    st.banner("API STEP 3 FAIL: {} {} {} mismatch {}".format(attribute, str1, policy, str2))
                                    ret_val = False
                                else:
                                    st.banner("API STEP 3 PASS: {} {} {} match {}".format(attribute, str1, policy, str2))
                        elif attribute == "trap_queue":
                            if cli_type in ['rest-put', 'rest-patch'] or cli_type in utils_obj.get_supported_ui_type_list():
                                if not verify_copp_actions(dut=dut, copp_agroup=policy,
                                                           trap_queue=data['COPP_GROUP'][policy][attribute]):
                                    st.banner("API STEP 3 FAIL: {} {} {} mismatch {}".format(attribute, str1, policy, str2))
                                    ret_val = False
                                else:
                                    st.banner("API STEP 3 PASS: {} {} {} match {}".format(attribute, str1, policy, str2))
                            else:
                                if not verify_policy_type_copp(dut=dut, copp_fgroup=policy, copp_agroup=policy,
                                                               trap_queue=data['COPP_GROUP'][policy][attribute]):
                                    st.banner("API STEP 3 FAIL: {} {} {} mismatch {}".format(attribute, str1, policy, str2))
                                    ret_val = False
                                else:
                                    st.banner("API STEP 3 PASS: {} {} {} match {}".format(attribute, str1, policy, str2))
                str1 = " Verifying Per Platform CoPP Policy"
                st.log("API STEP 4:{} {} and its parameter {}".format(str1, policy, data['COPP_GROUP'][policy]))
            str1 = " Per Platform CoPP Policy Policing Parameter"
            str2 = "with show policy-map type copp output"
            if cli_type in ['rest-put', 'rest-patch'] or cli_type in utils_obj.get_supported_ui_type_list():
                for group, cir, cbs in zip(group_list, cir_list, cbs_list):
                    if not verify_copp_actions(dut=dut, copp_agroup=group, cir=cir, cbs=cbs, cli_type=cli_type):
                        st.banner("API STEP 4 FAIL:{} mismatch {}".format(str1, str2))
                        ret_val = False
                    else:
                        st.banner("API STEP 4 PASS:{} match {}".format(str1, str2))
            else:
                if not verify_policy_type_copp(dut=dut, copp_fgroup=flow_list, copp_agroup=group_list,
                                               cir=cir_list, cbs=cbs_list):
                    st.banner("API STEP 4 FAIL:{} mismatch {}".format(str1, str2))
                    ret_val = False
                else:
                    st.banner("API STEP 4 PASS:{} match {}".format(str1, str2))

        str1 = "Per Platform CoPP Policy Scheduler Parameter verification"
        if 'SCHEDULER' not in list(data.keys()):
            st.banner("STEP 5 SCHEDULER key in not present in the JSON file so {} skipped".format(str1))
        else:
            st.banner("STEP 5 SCHEDULER key in present in the JSON file so proceed to {}".format(str1))
            cpu_qlist = []
            pir_list = []
            for policy in data['SCHEDULER']:
                str1 = " Verifying Per Platform CoPP scheduler-policy"
                st.log("API STEP 6:{} {} and its parameter {}".format(str1, policy, data['SCHEDULER'][policy]))
                if "copp-scheduler-policy@" in policy:
                    cpu_qlist.append(policy.split("copp-scheduler-policy@")[1])
                    pir_list.append(data['SCHEDULER'][policy]['pir'])
            str1 = "Per Platform CoPP Policy Scheduler Parameter CPU queue and PIR"
            str2 = "in the show qos scheduler-policy output"
            if cli_type in ['rest-put', 'rest-patch'] or cli_type in utils_obj.get_supported_ui_type_list():
                for queue, pir in zip(cpu_qlist, pir_list):
                    if not verify_qos_scheduler_policy(dut=dut, queue=queue,
                                                       sch_policy_name="copp-scheduler-policy", sch_type="wrr", pir=pir, cli_type=cli_type):
                        st.banner("API STEP 6 FAIL: {} mismatch {} and {} {}".format(str1, queue, pir, str2))
                        ret_val = False
                    else:
                        st.banner("API STEP 6 PASS: {} match {} and {} {}".format(str1, queue, pir, str2))
            else:
                if not verify_qos_scheduler_policy(dut=dut, queue=cpu_qlist,
                                                   sch_policy_name="copp-scheduler-policy",
                                                   sch_type=["wrr"] * len(pir_list), pir=pir_list):
                    st.banner("API STEP 6 FAIL: {} mismatch {}".format(str1, str2))
                    ret_val = False
                else:
                    st.banner("API STEP 6 PASS: {} match {}".format(str1, str2))

    return ret_val


def verify_copp_rate_limit(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_copp_rate_limit(dut=dut1,max_rate="30000",max_burst="10000",rate="0",token="10")
    verify_copp_rate_limit(dut=dut1,return_output="yes")

    To verify show copp rate limit
    :param dut:
    :param max_rate:
    :param max_burst:
    :param rate:
    :param tokens:
    :param return_output: if this arg used API will return True, will only display show o/p without validation
    :return: True or False
    """
    output = st.show(dut, "show copp rate-limit", type="click")

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return output

    ret_val = False
    for rlist in output:
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


def parse_show_qos_scheduler_policy(response):
    dict1 = response["output"]
    if 'openconfig-qos:pir' not in dict1:
        return []
    output = {}
    output["pir"] = dict1['openconfig-qos:pir']
    output["sch_policy_name"] = "copp-scheduler-policy"
    output["sch_type"] = "wrr"
    return [output]


def parse_show_qos_scheduler_type(response):
    dict1 = response["output"]
    if 'openconfig-qos:priority' not in dict1:
        return ""
    else:
        return dict1['openconfig-qos:priority']


def parse_show_qos_scheduler_weight(response):
    dict1 = response["output"]
    if 'openconfig-qos:weight' not in dict1:
        return ""
    else:
        return dict1['openconfig-qos:weight']


def verify_per_platform_copp_rate_limit(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    Example 1: verify_per_platform_copp_rate_limit(dut1,cli_type="rest-put")
    Example 2: verify_per_platform_copp_rate_limit(dut1)
    Example 3: verify_per_platform_copp_rate_limit(dut1,return_output="yes")

    To return the per platform CoPP default parameters & cli present only in click mode
    :param dut:
    :param return_output < optional arg >
    :return: True or False
    """
    ret_val = True
    platform = basic_api.get_platform_summary(dut, value="platform")
    chip = basic_api.get_hwsku(dut)
    file = "/usr/share/sonic/device/" + platform + "/" + chip + "/copp_platform_config.j2"
    ret_dict = {}
    output = st.show(dut, "ls {}".format(file), type="click", skip_tmpl=True)
    if "ls: cannot access" in output:
        str1 = "DUT does not have the file so per platform CoPP Rate limit check skipped"
        st.banner("API STEP 1: File {} got generated but {}".format(file, str1))
        if 'return_output' in kwargs:
            ret_dict["copp_platform_config_FileExist"] = "No"
            return ret_dict
        str1 = "Per Platform CoPP copp_capabilities_config is absent"
        if not verify_copp_rate_limit(dut=dut, max_rate="30000"):
            st.banner("API STEP 4 FAIL: Copp Max Rate 30000 is not seen when {}".format(str1))
            ret_val = False
        else:
            st.banner("API STEP 4 PASS: Copp Max Rate 30000 was verified when {}".format(str1))
        return ret_val
    else:
        str1 = "DUT have same file so lets proceed with verification"
        st.banner("API STEP 1: File {} got generated and {}".format(file, str1))
        output = st.show(dut, "cat {}".format(file), type="click", skip_tmpl=True)
        reg_output = utils_obj.remove_last_line_from_string(output)
        if not reg_output:
            if 'return_output' in kwargs:
                ret_dict["copp_platform_config_FileContent"] = "empty"
                return ret_dict
            return False
        # nosemgrep-next-line
        data = eval(reg_output)
        if not isinstance(data, dict):
            st.error("API STEP 1: File exist but JSON file do not have any line in it")
            if 'return_output' in kwargs:
                ret_dict["copp_platform_config_FileDictFormat"] = "No"
                return ret_dict
            return False

        file = "/usr/share/sonic/device/" + platform + "/" + chip + "/copp_capabilities_config.j2"
        output = st.show(dut, "ls {}".format(file), type="click", skip_tmpl=True)
        if "ls: cannot access" in output:
            str1 = "DUT does not have the file so per platform CoPP Rate Limit Check skipped"
            st.banner("API STEP 1: File {} got generated but {}".format(file, str1))
            if 'return_output' in kwargs:
                ret_dict["copp_capabilities_config_FileExist"] = "No"
                return ret_dict
            str1 = "Per Platform CoPP copp_capabilities_config is absent"
            if not verify_copp_rate_limit(dut=dut, max_rate="30000"):
                st.banner("API STEP 4 FAIL: Copp Max Rate 30000 is not seen when {}".format(str1))
                ret_val = False
            else:
                st.banner("API STEP 4 PASS: Copp Max Rate 30000 was verified when {}".format(str1))
        else:
            str1 = "DUT have same file so lets proceed with verification"
            st.banner("API STEP 1: File {} got generated and {}".format(file, str1))
            output = st.show(dut, "cat {}".format(file), type="click", skip_tmpl=True)
            reg_output = utils_obj.remove_last_line_from_string(output)
            if not reg_output:
                if 'return_output' in kwargs:
                    ret_dict["copp_capabilities_config_FileContent"] = "empty"
                    return ret_dict
                return False
            reg_output = reg_output.replace("false", "False")
            reg_output = reg_output.replace("true", "True")
            # nosemgrep-next-line
            data = eval(reg_output)
            if not isinstance(data, dict):
                st.error("API STEP 1: File exist but JSON file do not have any line in it")
                if 'return_output' in kwargs:
                    ret_dict["copp_capabilities_config_FileDictFormat"] = "No"
                    return ret_dict
                return False
            if 'return_output' in kwargs:
                return data
            str1 = "Per Platform CoPP parametrs are applicable"
            if not verify_copp_rate_limit(dut=dut, max_rate=str(data["copp_rx_rate"])):
                st.banner("API STEP 4 FAIL: Copp Max Rate {} is not seen even if {}".format(data["copp_rx_rate"], str1))
                ret_val = False
            else:
                st.banner("API STEP 4 PASS: Copp Max Rate {} was verified as {}".format(data["copp_rx_rate"], str1))
    return ret_val


def verify_per_platform_copp_chip_capability(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    Example 1: verify_per_platform_copp_chip_capability(dut1,cli_type="rest-put")
    Example 2: verify_per_platform_copp_chip_capability(dut1)
    Example 3: verify_per_platform_copp_chip_capability(dut1,return_output="yes")

    To return the per platform CoPP default parameters
    :param dut:
    :param cli_type < optional arg >
    :param return_output < optional arg >
    :return: True or False
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = "klish" if cli_type == 'click' else cli_type
    ret_val = True

    platform = basic_api.get_platform_summary(dut, value="platform")
    chip = basic_api.get_hwsku(dut)
    file = "/usr/share/sonic/device/" + platform + "/" + chip + "/copp_platform_config.j2"
    ret_dict = {}
    output = st.show(dut, "ls {}".format(file), type="click", skip_tmpl=True)
    if "ls: cannot access" in output:
        str1 = "DUT does not have this file so per platform CoPP verification skipped"
        st.banner("API STEP 1: File generated is {} but {}".format(file, str1))
        if 'return_output' in kwargs:
            ret_dict["copp_platform_config_Exist"] = "No"
            return ret_dict
        return True
    else:
        str1 = "DUT have this file so lets proceed with verification"
        st.banner("API STEP 1: File generated is {} and {}".format(file, str1))
        output = st.show(dut, "cat {}".format(file), type="click", skip_tmpl=True)
        reg_output = utils_obj.remove_last_line_from_string(output)
        if not reg_output:
            if 'return_output' in kwargs:
                ret_dict["copp_platform_config_FileContent"] = "empty"
                return ret_dict
            return False
        # nosemgrep-next-line
        data = eval(reg_output)
        if not isinstance(data, dict):
            st.error("API STEP 1: File exist but JSON file do not have any line in it")
            if 'return_output' in kwargs:
                ret_dict["copp_platform_config_FileDictFormat"] = "No"
                return ret_dict
            return False

        output1 = st.show(dut, "ls /proc/linux_ngbde", type="click", skip_tmpl=True)
        output2 = st.show(dut, "ls /proc/linux-kernel-bde", type="click", skip_tmpl=True)
        if "No such file or directory" in output2 and "No such file or directory" not in output1:
            output = st.show(dut, "cat /proc/linux_ngbde | grep 14e4", type="click", skip_tmpl=True)
            output = output.split("14e4:")
            chip_id = output[1][0:3]
        elif "No such file or directory" in output1 and "No such file or directory" not in output2:
            output = st.show(dut, "cat /proc/linux-kernel-bde | grep 14e4", type="click", skip_tmpl=True)
            output = output.split("0x14e4:0x")
            chip_id = output[1][0:3]
        st.log("CHIP type is {}".format(chip_id))
        file = "/usr/share/sonic/device/x86_64-broadcom_common/x86_64-broadcom_" + chip_id + "/copp_capabilities_config.j2"
        output = st.show(dut, "cat {}".format(file), type="click", skip_tmpl=True)
        st.log("CoPP Chip Capabities is {}".format(output))
        reg_output = utils_obj.remove_last_line_from_string(output)
        reg_output = {} if "No such file or directory" in output else reg_output
        str1 = "entry in the DUT chip copp_capabilities_config.j2"
        str2 = "entry in the DUT platform chip copp_capabilities_config.j2"
        data2 = verify_per_platform_copp_rate_limit(dut, return_output="yes")
        if 'copp_rx_rate' in data2:
            del data2['copp_rx_rate']
        for key in data2:
            temp = {}
            if 'copp_feat' in key:
                st.banner("API STEP 2: {} {} so lets proceed with verification".format(key, str2))
                temp[key] = data2[key]
            ret_dict["platform_capabilities"] = temp
        if not reg_output:
            st.banner("API STEP 2: There is no {}".format(str1))
            if 'return_output' in kwargs:
                ret_dict["chip_capabilities_FileExist"] = "No"
                return ret_dict
        else:
            st.banner("API STEP 2: There is {} so lets proceed with verification".format(str1))
            st.log("Chip capabilities is {}".format(reg_output))
            st.log("Platform capabilities is {}".format(data2))
            if len(reg_output) != 0:
                reg_output = reg_output.replace("false", "False")
                reg_output = reg_output.replace("true", "True")
                # nosemgrep-next-line
                data1 = eval(reg_output)
            else:
                data1 = {}
            if 'return_output' in kwargs:
                ret_dict["chip_capabilities"] = data1
                return ret_dict
            if not isinstance(data1, dict):
                st.error("API STEP 3: DUT chip copp capabilities File exist but JSON file do not have any line in it")
                ret_val = False
                if 'return_output' in kwargs:
                    ret_dict["chip_capabilities_FileContent"] = "empty"
                    return ret_dict
            else:
                data = {}
                if len(data2) == 0 and len(data1) == 0:
                    st.log("There is no {} and no {}".format(str1, str2))
                    return ret_val
                elif len(data2) > 0 and len(data1) == 0:
                    data = data2
                elif len(data1) > 0 and len(data2) == 0:
                    data = data1
                elif len(data2) > 0 and len(data1) > 0:
                    for k2 in data2:
                        for k1 in data1:
                            data[k1] = data2[k1] if k1 == k2 else data1[k1]
                for key in data:
                    st.log("Verifying the CoPP Policy {} as per CoPP Chip Capabities entry in this JSON".format(key))
                    policy = "copp-system-" + key.split("copp_feat_")[1]
                    str2 = "exist in show policy-map type copp O/P"
                    if cli_type in ['rest-put', 'rest-patch'] or cli_type in utils_obj.get_supported_ui_type_list():
                        if data[key]:
                            if not verify_copp_actions(dut=dut, copp_agroup=policy, cli_type=cli_type):
                                st.banner("API STEP 3 FAIL: CoPP Policy {} not {} as per {}".format(policy, str2, str1))
                                ret_val = False
                            else:
                                st.banner("API STEP 3 PASS: CoPP Policy {} {} as per {}".format(policy, str2, str1))
                        elif not data[key]:
                            if verify_copp_actions(dut=dut, copp_agroup=policy, cli_type=cli_type):
                                st.banner("API STEP 3 FAIL: CoPP Policy {} {} as per {}".format(policy, str2, str1))
                                ret_val = False
                            else:
                                st.banner("API STEP 3 PASS: CoPP Policy {} not {} as per {}".format(policy, str2, str1))
                    else:
                        if data[key]:
                            if not verify_policy_type_copp(dut=dut, copp_fgroup=policy, copp_agroup=policy):
                                st.banner("API STEP 3 FAIL: CoPP Policy {} not {} as per {}".format(policy, str2, str1))
                                ret_val = False
                            else:
                                st.banner("API STEP 3 PASS: CoPP Policy {} {} as per {}".format(policy, str2, str1))
                        elif not data[key]:
                            if verify_policy_type_copp(dut=dut, copp_fgroup=policy, copp_agroup=policy):
                                st.banner("API STEP 3 FAIL: CoPP Policy {} {} as per {}".format(policy, str2, str1))
                                ret_val = False
                            else:
                                st.banner("API STEP 3 PASS: CoPP Policy {} not {} as per {}".format(policy, str2, str1))
    return ret_val


def parse_get_payload_show_acl_copp_service_policy(response):
    if 'openconfig-fbs-ext:section' not in response:
        return []
    list1 = response['openconfig-fbs-ext:section']
    dict1 = list1[0]
    state = dict1['state']
    output = {}
    arg_dict = {"cbs": "cbs", "cir": "cir", "pir": "pir", "pbs": "pbs", "class-name": "class_map",
                "matched-packets": "match_frames", "matched-octets": "match_bytes", "active": "class_status",
                "conforming-pkts": "green_pkts", "conforming-octets": "green_bytes", "exceeding-pkts": "yellow_pkts",
                "exceeding-octets": "yellow_bytes", "violating-pkts": "red_pkts", "violating-octets": "red_bytes"}
    for key in arg_dict:
        if key == "active":
            output[arg_dict[key]] = 'Active' if state[key] is True else 'Inactive'
        else:
            output[arg_dict[key]] = state[key]
    return [output]


def verify_copp_hw_config(dut, **kwargs):
    """
    :param dut:
    :type dut: string
    :param feature:
    :type feature: string
    :param state:
    :type state: string
    :param copp_trap:
    :type copp_trap: string
    :param copp_group:
    :type copp_group: string
    :param return_output: if this arg used API will return parsed O/P
    :type return_output: True or False
    :return: True or False

    usage:
    verify_copp_hw_config(vars.D1, return_output=True)
    verify_copp_hw_config(vars.D1, feature='vrrp', state='disabled')
    verify_copp_hw_config(vars.D1, feature='vrrp', state='enabled', copp_trap='copp-system-vrrp',copp_group='copp-system-vrrp' return_output=True)
    """

    st.log('API_NAME: verify_copp_hw_config, API_ARGS: {}'.format(kwargs))
    num_args = len(kwargs)
    if num_args == 0:
        st.log('Provide at least one parameter to verify')
        return True

    if 'feature' in kwargs:
        cmd_output = st.show(dut, 'sudo debugsh -c COPPMGRD -e show system internal coppmgr feature {}'.format(kwargs['feature']))
    else:
        cmd_output = cmd_output = st.show(dut, 'sudo debugsh -c COPPMGRD -e show system internal coppmgr feature')

    if 'return_output' in kwargs:
        return cmd_output

    for kv in kwargs.items():
        if not filter_and_select(cmd_output, None, {kv[0]: kv[1]}):
            st.error('{} - Match not found for {}, Expected: {}'.format(dut, kv[0], kv[1]))
        else:
            num_args -= 1

    return True if num_args == 0 else False
