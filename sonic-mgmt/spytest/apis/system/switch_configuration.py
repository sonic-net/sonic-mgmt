import json
import pprint
from spytest import st
import apis.system.basic as basic_obj
import utilities.utils as utils_obj
from utilities.common import do_eval


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
    command = "sudo show runningconfiguration all"
    i = 1
    while True:
        try:
            output = st.show(dut, command, skip_tmpl=True)
            reg_output = utils_obj.remove_last_line_from_string(output)
            data = do_eval(json.dumps(json.loads(reg_output)))
            break
        except Exception as e:
            st.error("Exception occured in try-{} - {}".format(i,e))
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
            data = do_eval(json.dumps(json.loads(reg_output)))
            break
        except Exception as e:
            st.error("Exception occured in try-{} - {}".format(i,e))
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
        data = do_eval(json.dumps(json.loads(reg_output)))
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
