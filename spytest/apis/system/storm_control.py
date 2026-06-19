# This file contains the list of API's for storm control feature
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

from spytest import st
import utilities.common as utils_obj
from utilities import utils
from utilities.utils import get_supported_ui_type_list
from apis.system.rest import get_rest, delete_rest, config_rest

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    from apis.yang.utils.common import Operation
except ImportError:
    pass


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def config(dut, **kwargs):
    """
    API to configure storm control on DUT
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs: bits_per_sec, type, interface_name, cli_type, no_form, action
    :return:
    """
    mandatory_args = ["bits_per_sec", "type", "interface_name"]
    cli_type = st.get_ui_type(dut, **kwargs)
    action = kwargs["action"] if "action" in kwargs else "add"
    command = list()
    for arg in mandatory_args:
        if arg not in kwargs:
            st.log("Expecting {} value".format(arg))
            return False
    if cli_type in get_supported_ui_type_list():
        operation = Operation.CREATE
        stc_type = kwargs["type"]
        if stc_type == "unknown-multicast":
            stc_type = "unknown_multicast"
        if stc_type == "unknown-unicast":
            stc_type = "unknown_unicast"
        intf_obj = umf_intf.Interface(Name=kwargs['interface_name'])
        strm_obj = umf_intf.StormControlList(StormType=str(stc_type.upper()), Kbps=int(kwargs["bits_per_sec"]), Interface=intf_obj)
        if action == 'add':
            result = strm_obj.configure(dut, operation=operation, cli_type=cli_type)
        else:
            result = strm_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config stormcontrol on Interface {}'.format(result.data))
            return False
        return True
    if cli_type == 'click':
        if action == "add":
            command = "config interface storm-control {} {} {} {}".format(kwargs["type"], action, kwargs["interface_name"], kwargs["bits_per_sec"])
        else:
            command = "config interface storm-control {} {} {}".format(kwargs["type"], action, kwargs["interface_name"])
        st.config(dut, command, skip_error_check=kwargs.get("skip_error_check", False))
    elif cli_type == "klish":
        interface_data = utils.get_interface_number_from_name(kwargs["interface_name"])
        command.append('interface {} {}'.format(interface_data["type"], interface_data["number"]))
        if action == "add":
            command.append("storm-control {} {}".format(kwargs["type"], kwargs["bits_per_sec"]))
        else:
            command.append("no storm-control {}".format(kwargs["type"]))
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        stc_type = kwargs["type"]
        if stc_type == "unknown-multicast":
            stc_type = "unknown_multicast"
        if stc_type == "unknown-unicast":
            stc_type = "unknown_unicast"
        url = rest_urls['config_stormcontrol'].format(kwargs["interface_name"], stc_type.upper())
        json_data = {"openconfig-if-ethernet-ext:config": {"ifname": str(kwargs["interface_name"]), "storm-type": str(stc_type.upper()), "kbps": int(kwargs["bits_per_sec"])}}
        if action == "add":
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                return False
        else:
            url = rest_urls['unconfig_stormcontrol_iface'].format(kwargs["interface_name"], stc_type.upper())
            if not delete_rest(dut, rest_url=url):
                return False
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return True


def show(dut, interface_name=None, stc_type=None, **kwargs):
    """
        API to show storm control configuration
        Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
        :param dut:
        :param interface_name:
        :param stc_type:
        :param bits_per_sec:
        :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    interface_data = utils.get_interface_number_from_name(interface_name)
    if cli_type == 'click':
        if not interface_name:
            command = "show storm-control all"
        else:
            command = "show storm-control interface {}".format(interface_name)
        return st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        if not interface_name:
            command = "show storm-control"
        else:
            command = "show storm-control interface {} {}".format(
                interface_data["type"], interface_data["number"])
        return st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if stc_type == "unknown-multicast":
            stc_type = "unknown_multicast"
        if stc_type == "unknown-unicast":
            stc_type = "unknown_unicast"
        url = rest_urls['config_stormcontrol'].format(interface_name, stc_type.upper())
        rest_get_output = get_rest(dut, rest_url=url)
        actual_data = rest_get_output['output']['openconfig-if-ethernet-ext:config']
        temp = {}
        output = []
        temp['interface'] = actual_data['ifname']
        temp['rate'] = actual_data['kbps']
        stc_type = (actual_data['storm-type'].lower())
        if stc_type == "unknown_multicast":
            stc_type = "unknown-multicast"
        if stc_type == "unknown_unicast":
            stc_type = "unknown-unicast"
        temp['type'] = str(stc_type)
        output.append(temp)
        return output
    else:
        st.log("invalid cli type")
        return False


def verify_config(dut, interface_name=None, type=None, rate=None, cli_type="", **kwargs):
    """
        API to verify storm control configuration
        Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
        :param dut:
        :param interface_name:
        :param type:
        :param bits_per_sec:
        :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if not interface_name or not type:
        cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = utils_obj.get_query_params(yang_data_type=filter_type, cli_type=cli_type)

        stc_type = type
        if stc_type == "unknown-multicast":
            stc_type = "unknown_multicast"
        if stc_type == "unknown-unicast":
            stc_type = "unknown_unicast"

        intf_obj = umf_intf.Interface(Name=interface_name)
        strm_obj = umf_intf.StormControlList(StormType=str(stc_type.upper()), Ifname=interface_name, Interface=intf_obj)
        if rate:
            strm_obj.Kbps = int(rate)
        result = strm_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Match NOT Found: storm control parameters')
            return False
        return True

    output = show(dut, interface_name, type, cli_type=cli_type)
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
