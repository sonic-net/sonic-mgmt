# This file contains the list of API's for storm control feature
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

from spytest import st
import utilities.common as utils_obj

def config(dut, **kwargs):
    """
    API to configure storm control on DUT
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs: bits_per_sec, type, interface_name, cli_type, no_form, action
    :return:
    """
    mandatory_args = ["bits_per_sec", "type", "interface_name"]
    cli_type= kwargs["cli_type"] if "cli_type" in kwargs else "click"
    no_form = kwargs["no_form"] if "no_form" in kwargs else ""
    action = kwargs["action"] if "action" in kwargs else "add"
    for arg in mandatory_args:
        if arg not in kwargs:
            st.log("Expecting {} value".format(arg))
            return False
    if cli_type != "click":
        if not no_form:
            command = "storm-control {} {}".format(kwargs["type"], kwargs["bits_per_sec"])
        else:
            command = "no storm-control {}".format(kwargs["type"])
        st.cli_config(dut, command, "mgmt-intf-config", interface=kwargs["interface_name"])
    else:
        if action == "add":
            command = "config interface storm-control {} {} {} {}".format(kwargs["type"], action, kwargs["interface_name"], kwargs["bits_per_sec"])
        else:
            command = "config interface storm-control {} {} {}".format(kwargs["type"], action, kwargs["interface_name"])
        st.config(dut, command, skip_error_check=kwargs.get("skip_error_check", False))
    return True

def show(dut, interface_name=None, cli_type="click"):
    """
        API to show storm control configuration
        Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
        :param dut:
        :param interface_name:
        :param type:
        :param bits_per_sec:
        :return:
    """
    if not interface_name:
        command = "show storm-control" if cli_type != "click" else "show storm-control all"
    else:
        command = "show storm-control interface {}".format(interface_name)
    if cli_type != "click":
        return st.cli_show(dut, command, "mgmt-user")
    else:
        return st.show(dut, command)
    

def verify_config(dut, interface_name=None, type=None, rate=None, cli_type="click"):
    """
        API to verify storm control configuration
        Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
        :param dut:
        :param interface_name:
        :param type:
        :param bits_per_sec:
        :return:
    """
    output = show(dut, interface_name, cli_type=cli_type)
    if not output:
        st.log("Storm control data not found")
        return False
    match = dict()
    if interface_name:
        match["interface"] = interface_name
    if type:
        match["type"] = type
    if rate:
        match["rate"] = rate
    entries = utils_obj.filter_and_select(output, None, match)
    if match:
        st.log("MATCH : {}".format(match))
        st.log("Entries: {}".format(entries))
        if not entries:
            st.log("Entries not found ...")
            return False
        return True
    else:
        st.log("Type and rate not provided")
        return False




