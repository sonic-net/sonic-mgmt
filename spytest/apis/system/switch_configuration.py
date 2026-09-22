import json
import pprint
from spytest import st
import apis.system.basic as basic_obj
import utilities.utils as utils_obj
from utilities.common import make_list


def verify_show_running_configuration(dut, **kwargs):
    '''
    :param filter_type: As of now only grep is supported, which is default.
    :param sub_cmd:
    :param match_flag:
    :param order_flag:
    :param trim_lines:
    :param filter_pattern_list:
    :param match_pattern_list:
    :param return_output:

    verify_show_running_configuration(dut, sub_cmd='interface Ethernet4',match_pattern_list=['mtu 1500', 'shutdown'])
    verify_show_running_configuration(dut, sub_cmd='interface Ethernet4',match_pattern_list=['no shutdown'],match_flag=False)
    verify_show_running_configuration(dut, sub_cmd='interface Ethernet4',filter_pattern_list=[?mtu?], match_pattern_list=['mtu 1500'])
    verify_show_running_configuration(dut, filter_pattern_list=['mtu'], match_pattern_list=['mtu 1500'])
    '''
    st.log('API_NAME: verify_show_running_configuration, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    sub_cmd = kwargs.pop('sub_cmd', False)
    filter_type = kwargs.pop('filter_type', 'grep')
    filter_pattern_list = kwargs.pop('filter_pattern_list', [])
    match_pattern_list = kwargs.pop('match_pattern_list', [])
    match_flag = kwargs.pop('match_flag', True)
    order_flag = kwargs.pop('order_flag', True)
    trim_lines = kwargs.pop('trim_lines', True)
    return_output = kwargs.pop('return_output', False)
    skip_error = kwargs.get('skip_error', False)

    cli_type = 'klish' if cli_type in utils_obj.get_supported_ui_type_list() + ['rest-patch', 'rest-put'] else cli_type

    if cli_type == 'click':
        st.log('Skipping show running config verification for Click')
        return True

    if cli_type == 'klish':
        cmd = 'show running-configuration'
        if sub_cmd:
            cmd = cmd + ' ' + sub_cmd

        for filter_pattern in make_list(filter_pattern_list):
            cmd = cmd + ' | ' + filter_type + ' \"' + filter_pattern + '\"'
        output = st.show(dut, cmd, skip_tmpl=True, type=cli_type, skip_error_check=skip_error)
        if return_output:
            return output
        actual_op_list = output.split('\n')
        expected_op_list = make_list(match_pattern_list)
        if trim_lines:
            actual_op_list = [lines.strip() for lines in actual_op_list]
        st.log('Actual Output: {}'.format(actual_op_list))
        st.log('Expected Output: {}, match_flag: {}, order_flag: {}.'.format(expected_op_list, match_flag, order_flag))

        # orig_output_list = output_list.copy()
        match_result = True
        for match_pattern in expected_op_list:
            try:
                idx = actual_op_list.index(match_pattern)
                if order_flag:
                    actual_op_list = actual_op_list[idx + 1:]
                if not match_flag:
                    st.log('Unexpected Config FOUND: \"{}\"'.format(match_pattern))
                    match_result = False
            except ValueError:
                if match_flag:
                    st.log('Expected Config NOT FOUND or NOT in order: \"{}\"'.format(match_pattern))
                    match_result = False

        # if not match_result:
        #    st.log('Running Config Difference: {}'.format(set(match_pattern_list).difference(orig_output_list)))
        return match_result


def verify_running_config(dut, table, object, attribute=None, value=None, max_retry=3):
    """
    Verify running config value based on table, object, attribute
    Author: Rakesh Kumar Vooturi (rakesh-kumar.vooturi@broadcom.com)
    :param dut:
    :param table:
    :param object:
    :param attribute:
    :param value:
    :return:
    """
    command = "show runningconfiguration all"
    data = basic_obj.get_show_command_data(dut, command, type="json")
    if data is None:
        st.log("Content not found ..")
        return False

    st.log("verifying for Table: {}, Object: {}, Attribute: {} and Value: {} "
           "in show runningconfiguration all o/p".format(table, object, attribute, value))

    if table in data:
        if object in data[table]:
            if attribute is not None and value is not None:
                if attribute in data[table][object]:
                    if data[table][object][attribute] == value:
                        st.log("Found the data in show running config all - {}".format(data[table][object]))
                        return True
                    else:
                        st.log("Did not find the data in show running config all - {}".format(data[table][object]))
                        return False
                else:
                    st.log("Did not find the Table: {}, Object: {}, Attribute: {}"
                           " in show running config all".format(table, object, attribute))
                    return False
            else:
                st.log("Found the data in show running config all - {}".format(data[table][object]))
                return True
        else:
            st.log("Did not find the Table: {}, Object: {} in show running config all".format(table, object))
            return False
    else:
        st.log("Did not find the Table: {} in show running config all".format(table))
        return False


def get_running_config(dut, table=None, object=None, attribute=None, max_retry=3):
    """
    Get running config value based on table, object, attribute
    Author: Rakesh Kumar Vooturi (rakesh-kumar.vooturi@broadcom.com)
    :param dut:
    :param table:
    :param object:
    :param attribute:
    :return:
    """
    command = "show runningconfiguration all"
    i = 1
    while True:
        try:
            output = st.show(dut, command, skip_tmpl=True)
            reg_output = utils_obj.remove_last_line_from_string(output)
            # nosemgrep-next-line
            data = eval(json.dumps(json.loads(reg_output)))
            break
        except Exception as e:
            st.error("Exception occured in try-{} - {}".format(i, e))
            if i == max_retry:
                st.error("MAX retry {} reached..".format(i))
                return None
        i += 1
    try:
        if table is None and object is None and attribute is None:
            return data
        elif table is not None and object is None and attribute is None:
            return data[table]
        elif table is not None and object is not None and attribute is None:
            return data[table][object]
        elif table is not None and object is not None and attribute is not None:
            return data[table][object][attribute]
    except Exception as e:
        st.log(e)
        return None


def verify_config_db(dut, table, object, attribute=None, value=None, max_retry=3):
    """
    Verify Config DB json value based on table, object, attribute
    Author: Rakesh Kumar Vooturi (rakesh-kumar.vooturi@broadcom.com)
    :param dut:
    :param table:
    :param object:
    :param attribute:
    :param value:
    :return:
    """
    command = "cat /etc/sonic/config_db.json"
    # Adding while loop and try/except to catch the truncated data issue.
    i = 1
    while True:
        try:
            output = st.show(dut, command, skip_tmpl=True)
            reg_output = utils_obj.remove_last_line_from_string(output)
            # nosemgrep-next-line
            data = eval(json.dumps(json.loads(reg_output)))
            break
        except Exception as e:
            st.error("Exception occured in try-{} - {}".format(i, e))
            if i == max_retry:
                st.error("MAX retry {} reached..".format(i))
                return False
        i += 1

    st.log("verifying for Table: {}, Object: {}, Attribute: {} and Value: {} in "
           "config DB".format(table, object, attribute, value))

    if table in data:
        if object in data[table]:
            if attribute is not None and value is not None:
                if attribute in data[table][object]:
                    if data[table][object][attribute] == value:
                        st.log("Found the data in config DB - {}".format(data[table][object]))
                        return True
                    else:
                        st.log("Did not find the data in config DB - {}".format(data[table][object]))
                        return False
                else:
                    st.log("Did not find the Table: {}, Object: {}, Attribute: {} "
                           "in config DB".format(table, object, attribute))
                    return False
            else:
                st.log("Found the data in config DB - {}".format(data[table][object]))
                return True
        else:
            st.log("Did not find the Table: {}, Object: {} in config DB".format(table, object))
            return False
    else:
        st.log("Did not find the Table: {} in config DB".format(table))
        return False


def get_config_db(dut, table=None, object=None, attribute=None):
    """
    Get Config DB json value based on table, object, attribute
    Author: Rakesh Kumar Vooturi (rakesh-kumar.vooturi@broadcom.com)
    :param dut:
    :param table:
    :param object:
    :param attribute:
    :return:
    """
    command = "cat /etc/sonic/config_db.json"
    output = st.show(dut, command, skip_tmpl=True)
    reg_output = utils_obj.remove_last_line_from_string(output)
    try:
        # nosemgrep-next-line
        data = eval(json.dumps(json.loads(reg_output)))
        if table is None and object is None and attribute is None:
            return data
        elif table is not None and object is None and attribute is None:
            return data[table]
        elif table is not None and object is not None and attribute is None:
            return data[table][object]
        elif table is not None and object is not None and attribute is not None:
            return data[table][object][attribute]
    except Exception as e:
        st.log(e)
        return None


def write_config_db(dut, data):
    """
    To Write config to config DB
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param data: dictionary/ JSON format
    :return:
    """
    st.log("JSON Data Provided:")
    st.log(pprint.pformat(data, width=2))
    return st.apply_json(dut, json.dumps(data))


def show_running_config(dut, **kwargs):
    """
    :param dut:
    :param module:
    :param skip_tmpl:
    :param skip_error_check:
    :return:
    """
    module = kwargs.get("module")
    skip_tmpl = kwargs.get("skip_tmpl", True)
    skip_error_check = kwargs.get("skip_tmpl", True)
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in utils_obj.get_supported_ui_type_list() else cli_type
    command = "show running-configuration" if not module else "show running-configuration {}".format(module)
    output = st.show(dut, command, skip_tmpl=skip_tmpl, skip_error_check=skip_error_check, type=cli_type)
    reg_output = utils_obj.remove_last_line_from_string(output)
    st.debug(reg_output)
    return reg_output
