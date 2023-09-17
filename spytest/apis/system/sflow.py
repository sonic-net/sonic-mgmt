# This file contains the list of API's which performs SFLOW operations.
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

import re
from spytest import st
from utilities.common import filter_and_select
from apis.routing.ip import get_interface_ip_address

import utilities.utils as utils_obj
import utilities.common as common_utils

try:
    import apis.yang.codegen.messages.sampling_sflow.SamplingSflow as umf_sflow
    from apis.yang.utils.common import Operation

except ImportError:
    pass

YANG_MODULE = "sonic-sflow:sonic-sflow"
REST_URI = "/restconf/data/{}".format(YANG_MODULE)
DEFAULT_COLLECTOR_PORT = 6343
COLLECTORV4_LOG_FILE = '/tmp/sflow_ipv4.log'
COLLECTORV6_LOG_FILE = '/tmp/sflow_ipv6.log'


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in utils_obj.get_supported_ui_type_list() else cli_type
    return cli_type


def add_del_collector(dut, collector_name, ip_address=None, port_number=None, action="add", cli_type="", skip_error_check=False, **kwargs):
    """
    API to add/del SFLOW collector
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param collector_name:
    :param ip_address: IPV4 / IPV6 address, this is optional for del operations
    :param port_number: None, this is optional for del operations
    :param action: add / del
    :return: True / False
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    vrf = kwargs.get('vrf', None)
    command = None
    if action == "add":
        if ip_address:
            if cli_type in utils_obj.get_supported_ui_type_list():
                operation = Operation.CREATE
                vrf_str = vrf or 'default'
                port = 6343 if port_number is None else int(port_number)
                sflow_obj = umf_sflow.Sampling()
                coll_obj = umf_sflow.Collector(Address=ip_address, Port=port, NetworkInstance=vrf_str, Sampling=sflow_obj)
                result = coll_obj.configure(dut, operation=operation, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: GNMI: Config of Sflow Collector: {}'.format(result.data))
                    return False
            elif cli_type == "click":
                command = "config sflow collector add {} {}".format(collector_name, ip_address)
                if vrf:
                    command += " --vrf {}".format(vrf)
                if port_number:
                    command += " --port {}".format(port_number)
            elif cli_type == "klish":
                command = "sflow collector {}".format(ip_address)
                if vrf:
                    command += " vrf {}".format(vrf)
                if port_number:
                    command += " {}".format(port_number)
            elif cli_type == "rest":
                data = dict()
                data["sonic-sflow:SFLOW_COLLECTOR"] = dict()
                data["sonic-sflow:SFLOW_COLLECTOR"]["sonic-sflow:SFLOW_COLLECTOR_LIST"] = list()
                collector_data = dict()
                collector_data["collector_name"] = collector_name
                collector_data["collector_ip"] = ip_address
                collector_data["collector_port"] = int(port_number) if port_number else DEFAULT_COLLECTOR_PORT
                data["sonic-sflow:SFLOW_COLLECTOR"]["sonic-sflow:SFLOW_COLLECTOR_LIST"].append(collector_data)
                json_data = data
                url = "{}/SFLOW_COLLECTOR".format(REST_URI)
                output = st.rest_modify(dut, url, json_data)
                st.log("ADD / DEL COLLECTOR AT INTF level -- {}".format(output))
                if output and output["status"] != 204:
                    return False
                return True
            else:
                st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
                return False
        else:
            st.log("IP ADDRESS not provided for add operation ..")
            return False
    elif action == "del":
        if cli_type in utils_obj.get_supported_ui_type_list():
            if not ip_address:
                st.log("Mandatory argument ip_address not provided ")
                return False
            vrf_str = vrf or 'default'
            # setting default port number as it is mandatory.
            port = 6343 if port_number is None else port_number
            sflow_obj = umf_sflow.Sampling()
            coll_obj = umf_sflow.Collector(Address=ip_address, Port=port, NetworkInstance=vrf_str,
                                           Sampling=sflow_obj)
            result = coll_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: GNMI: UnConfig of Sflow Collector: {}'.format(result.data))
                return False
        elif cli_type == "click":
            command = "config sflow collector del {}".format(collector_name)
        elif cli_type == "klish":
            if not ip_address:
                st.log("Mandatory argument ip_address not provided ")
                return False
            command = "no sflow collector {}".format(ip_address)
            if vrf:
                command += " vrf {}".format(vrf)
            if port_number:
                command += " {}".format(port_number)
        elif cli_type == "rest":
            url = "{}/SFLOW_COLLECTOR".format(REST_URI)
            output = st.rest_delete(dut, url, SFLOW_COLLECTOR_LIST=collector_name)
            st.log("ADD / DEL COLLECTOR AT INTF level -- {}".format(output))
            if output and output["status"] != 204:
                return False
            return True
        else:
            st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
    if cli_type != "rest" and command and utils_obj.ensure_cli_type(cli_type, ["click", "klish"]):
        output = st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        return output
    return True


def add_del_agent_id(dut, interface_name=None, action="add", cli_type="", sflow_list="global", skip_error_check=False):
    """
    API to add/del SFLOW AGENT ID
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface_name:
    :param action: add / del
    :return: True / False
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if action not in ["add", "del"]:
        st.log("Unsupported action {}..".format(action))
        return False

    if cli_type in utils_obj.get_supported_ui_type_list():
        sflow_obj = umf_sflow.Sampling()
        if action == 'add':
            if not interface_name:
                st.log("Interface name -- {} not provided ".format(interface_name))
                return False
            if interface_name == "Management 0":
                interface_name = "eth0" if cli_type != "klish" else interface_name
            sflow_obj.Agent = interface_name
            result = sflow_obj.configure(dut, cli_type=cli_type)
        else:
            result = sflow_obj.unConfigure(dut, target_attr=sflow_obj.Agent, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: GNMI: Config of Sflow agent-id: {}'.format(result.data))
            return False
        return True
    elif cli_type == "click":
        if action != "add":
            command = "config sflow agent-id {}".format(action)
        else:
            if not interface_name:
                st.log("Interface name -- {} not provided ".format(interface_name))
                return False
            command = "config sflow agent-id {} {}".format(action, interface_name)
    elif cli_type == "klish":
        if action != "add":
            command = "no sflow agent-id"
        else:
            command = "sflow agent-id {}".format(interface_name)
    elif cli_type == "rest":
        url = "{}/SFLOW/SFLOW_LIST={}/agent_id".format(REST_URI, sflow_list)
        if action == "add":
            data = {"sonic-sflow:agent_id": interface_name}
            output = st.rest_modify(dut, url, data)
            st.log("REST del agent_id OUTPUT -- {}".format(output))
            if output and output["status"] != 204:
                return False
        else:
            output = st.rest_delete(dut, url)
            st.log("REST del agent_id OUTPUT -- {}".format(output))
            if output and output["status"] != 204:
                return False
        return True
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    if utils_obj.ensure_cli_type(cli_type, ["click", "klish"]) and command:
        output = st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        return output
    return True


def enable_disable_config(dut, interface=False, interface_name=None, action="enable", cli_type="", sflow_key="global"):
    """
    API to enable / disable SFLOW Globally / on interface level
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface:
    :param interface_name:
    :param action:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if action not in ["enable", "disable"]:
        st.log("Unsupported action {} ".format(action))
        return False
    if interface and interface_name:
        commands = list()
        if cli_type in utils_obj.get_supported_ui_type_list():
            sflow_obj = umf_sflow.Sampling()
            sflow_intf_obj = umf_sflow.Interface(Name=interface_name, Sampling=sflow_obj)
            if action == 'enable':
                sflow_intf_obj.Enabled = True
                result = sflow_intf_obj.configure(dut, cli_type=cli_type)
            else:
                sflow_intf_obj.Enabled = False
                result = sflow_intf_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: GNMI: Enable/Disable of Sflow at interface: {}'.format(result.data))
                return False
            return True
        elif cli_type == "click":
            command = "config sflow interface {} {}".format(action, interface_name)
            commands.append(command)
        elif cli_type == "klish":
            interface_details = utils_obj.get_interface_number_from_name(interface_name)
            if not interface_details:
                st.log("Interface details not found {}".format(interface_details))
                return False
            commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
            if action == "enable":
                command = "sflow {}".format(action)
            else:
                command = "no sflow enable"
            commands.append(command)
        elif cli_type == "rest":
            session_list = dict()
            session_list["sonic-sflow:SFLOW_SESSION_LIST"] = list()
            session_data = dict()
            session_data["ifname"] = interface_name
            session_data["admin_state"] = "up" if action == "enable" else "down"
            session_list["sonic-sflow:SFLOW_SESSION_LIST"].append(session_data)
            url = "{}/SFLOW_SESSION".format(REST_URI)
            output = st.rest_modify(dut, url, session_list, SFLOW_SESSION_LIST=interface_name)
            st.log("ENABLE / DISABLE SFLOW AT INTF level -- {}".format(output))
            if output and output["status"] != 204:
                return False
            return True
        else:
            st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
        if commands:
            st.config(dut, commands, type=cli_type)
    else:
        if cli_type in utils_obj.get_supported_ui_type_list():
            sflow_obj = umf_sflow.Sampling()
            if action == 'enable':
                sflow_obj.Enabled = True
                result = sflow_obj.configure(dut, cli_type=cli_type)
            else:
                sflow_obj.Enabled = False
                result = sflow_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: GNMI: Enable/Disable of global sflow : {}'.format(result.data))
                return False
            return True
        elif cli_type == "click":
            command = "config sflow {}".format(action)
        elif cli_type == "klish":
            if action != "enable":
                command = "no sflow enable"
            else:
                command = "sflow enable"
        elif cli_type == "rest":
            data = {"sonic-sflow:admin_state": "up" if action == "enable" else "down"}
            url = "{}/SFLOW/SFLOW_LIST={}/admin_state".format(REST_URI, sflow_key)
            output = st.rest_modify(dut, url, data)
            st.log("ENABLE / DISABLE SFLOW AT GLOBAL level -- {}".format(output))
            if output and output["status"] != 204:
                return False
            return True
        else:
            st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
        if command:
            st.config(dut, command, type=cli_type)
    return True


def config_attributes(dut, **kwargs):
    """
    Common API to configure sflow sample rate on interface, polling interval and sample rate per speed.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :return: True
    NOTE:
    1) To configure interface sample rate,
        config_sflow_attributes(dut, sample_rate=100, interface_name="Ethernet10")
    2) To configure polling interval
        config_sflow_attributes(dut, polling_interval=20)
    3) To configure sample rate per speed
        config_sflow_attributes(dut, speed=10G, sample_rate=10000)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    sflow_key = kwargs.get("sflow_key", "global")
    command = ""
    commands = list()
    if "sample_rate" in kwargs and "interface_name" in kwargs:
        if cli_type in utils_obj.get_supported_ui_type_list():
            operation = Operation.CREATE
            if kwargs.get("no_form") and kwargs.get("no_form") in ["yes", "Yes", True]:
                config = 'no'
            else:
                config = 'yes'
            sflow_obj = umf_sflow.Sampling()
            sflow_intf_obj = umf_sflow.Interface(Name=kwargs["interface_name"], Sampling=sflow_obj)
            sflow_intf_obj.SamplingRate = common_utils.integer_parse(kwargs["sample_rate"])
            if config == 'yes':
                sflow_intf_obj.SamplingRate = common_utils.integer_parse(kwargs["sample_rate"])
                result = sflow_intf_obj.configure(dut, operation=operation, cli_type=cli_type)
            else:
                # sflow_obj.Enabled = False
                result = sflow_intf_obj.unConfigure(dut, target_attr=sflow_intf_obj.SamplingRate, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of sflow interface sampling rate: {}'.format(result.data))
                return False
            # return True
        elif cli_type == "click":
            command += "config sflow interface sample-rate {} {}".format(kwargs["interface_name"], kwargs["sample_rate"])
            commands.append(command)
        elif cli_type == "klish":
            interface_details = utils_obj.get_interface_number_from_name(kwargs["interface_name"])
            if not interface_details:
                st.log("Interface details not found {}".format(interface_details))
                return False
            commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
            if kwargs.get("no_form") and kwargs.get("no_form") in ["yes", "Yes", True]:
                command = "no sflow sampling-rate"
            else:
                command = "sflow sampling-rate {}".format(kwargs["sample_rate"])
            commands.append(command)
            commands.append("exit")
        elif cli_type == "rest":
            data = {"sonic-sflow:sample_rate": int(kwargs["sample_rate"])}
            url = "{}/SFLOW_SESSION/SFLOW_SESSION_LIST={}/sample_rate".format(REST_URI, kwargs["interface_name"])
            output = st.rest_modify(dut, url, data)
            st.log("REST config_attributes SAMPLE RATE OUTPUT  -- {}".format(output))
            if output and output["status"] != 204:
                return False
            return True
        else:
            st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
        if cli_type in ['click', 'klish']:
            st.config(dut, commands, type=cli_type)
    if "polling_interval" in kwargs:
        if cli_type in utils_obj.get_supported_ui_type_list():
            if kwargs.get("no_form") and kwargs.get("no_form") in ["yes", "Yes", True]:
                config = 'no'
            else:
                config = 'yes'
            sflow_obj = umf_sflow.Sampling()
            if config == 'yes':
                sflow_obj.PollingInterval = common_utils.integer_parse(kwargs["polling_interval"])
                result = sflow_obj.configure(dut, cli_type=cli_type)
            else:
                # sflow_obj.Enabled = False
                result = sflow_obj.unConfigure(dut, target_attr=sflow_obj.PollingInterval, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of sflow polling interval: {}'.format(result.data))
                return False
            # return True
        elif cli_type == "click":
            if kwargs.get("no_form") and kwargs.get("no_form") in ["yes", "Yes", True]:
                command += "config sflow polling-interval 0;"
            else:
                command += "config sflow polling-interval {};".format(kwargs["polling_interval"])
            commands.append(command)
        elif cli_type == "klish":
            if kwargs.get("no_form") and kwargs.get("no_form") in ["yes", "Yes", True]:
                command = "no sflow polling-interval"
            else:
                command = "sflow polling-interval {}".format(kwargs["polling_interval"])
            commands.append(command)
        elif cli_type == "rest":
            data = {"sonic-sflow:polling_interval": int(kwargs["polling_interval"])}
            url = "{}/SFLOW/SFLOW_LIST={}/polling_interval".format(REST_URI, sflow_key)
            output = st.rest_modify(dut, url, data)
            st.log("REST config_attributes POLLING RATE OUTPUT  -- {}".format(output))
            if output and output["status"] != 204:
                return False
            return True
        else:
            st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
        if cli_type in ['click', 'klish']:
            st.config(dut, commands, type=cli_type)
    if "sample_rate" in kwargs and "interface_name" not in kwargs:
        if cli_type in utils_obj.get_supported_ui_type_list():
            if kwargs.get("no_form") and kwargs.get("no_form") in ["yes", "Yes", True]:
                config = 'no'
            else:
                config = 'yes'
            sflow_obj = umf_sflow.Sampling()
            if config == 'yes':
                sflow_obj.SamplingRate = common_utils.integer_parse(kwargs["sample_rate"])
                result = sflow_obj.configure(dut, operation=operation, cli_type=cli_type)
            else:
                # sflow_obj.Enabled = False
                result = sflow_intf_obj.unConfigure(dut, target_attr=sflow_obj.SamplingRate, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of sflow sampling rate: {}'.format(result.data))
                return False
        elif cli_type == "click":
            command += "config sflow sample-rate {}".format(kwargs["sample_rate"])
            commands.append(command)
        elif cli_type == "klish":
            if kwargs.get("no_form") and kwargs.get("no_form") in ["yes", "Yes", True]:
                command = "no sflow sampling-rate"
            else:
                command = "sflow sampling-rate {}".format(kwargs["sample_rate"])
            commands.append(command)
        elif cli_type == "rest":
            data = {"sonic-sflow:sample_rate": int(kwargs["sample_rate"])}
            url = "{}/SFLOW/SFLOW_LIST={}/sample_rate".format(REST_URI, sflow_key)
            output = st.rest_modify(dut, url, data)
            st.log("REST config_attributes SAMPLE RATE OUTPUT  -- {}".format(output))
            if output and output["status"] != 204:
                return False
            else:
                output = st.rest_delete(dut, url)
                st.log("REST del agent_id OUTPUT -- {}".format(output))
                if output and output["status"] != 204:
                    return False
            return True
        else:
            st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
        if cli_type in ['click', 'klish']:
            st.config(dut, commands, type=cli_type)
    if kwargs.get("collectors"):  # {"collector_ip":[port, vrf, collector_name], "collector_ip":[port, vrf, collector_name]}
        if not isinstance(kwargs.get("collectors"), dict):
            st.error("Provided Collectors data is not in proper format.")
            return False
        if len(kwargs.get("collectors").keys()) > 2:
            st.error("Only 2 collector can be configured at a time.")
            return False
        rest_data = {"openconfig-sampling-sflow:collectors": {"collector": []}}
        for coll_ip, coll_data in kwargs.get("collectors").items():
            if cli_type in utils_obj.get_supported_ui_type_list():
                collector_name = utils_obj.get_random_string()
                if not kwargs.get("no_form"):
                    config = 'add'
                else:
                    config = 'del'
                if coll_data and len(coll_data) > 1:
                    port = coll_data[0]
                    vrf = coll_data[1]
                elif coll_data and len(coll_data) == 1:
                    port = coll_data[0]
                    vrf = 'default'
                else:
                    port = 6343
                    vrf = 'default'
                add_del_collector(dut, collector_name=collector_name, ip_address=coll_ip, port_number=port,
                                  vrf=vrf, action=config, cli_type=cli_type)
                # return True
            elif cli_type == "click":
                if not kwargs.get("no_form"):
                    collector_name = utils_obj.get_random_string()
                    command += "config sflow collector add {} {}".format(collector_name, coll_ip)
                    if coll_data:
                        if int(coll_data[0]) != 6343:
                            command += " --port {}".format(coll_data[0])
                        if len(coll_data) > 1 and coll_data[1] != "default":
                            command += " --vrf {}".format(coll_data[1])
                    command += ";"
                else:
                    if len(coll_data) > 2 and coll_data[2]:
                        command += "config sflow collector del {};".format(coll_data[2])
                commands.append(command)
            elif cli_type == "klish":
                no_form = "" if not kwargs.get("no_form") else "no"
                command = "{} sflow collector {}".format(no_form, coll_ip)
                if coll_data:
                    if int(coll_data[0]) != 6343:
                        command += " {}".format(coll_data[0])
                    if len(coll_data) > 1 and coll_data[1] != "default":
                        command += " {}".format(coll_data[1])
                commands.append(command)
            elif cli_type == "rest":
                sub_data = {"address": coll_ip}
                sub_data["config"] = {"address": coll_ip}
                if not kwargs.get("no_form"):
                    if coll_data:
                        if int(coll_data[0]) != 6343:
                            sub_data.update({"port": coll_data[0]})
                            sub_data["config"].update({"port": coll_data[0]})
                        if len(coll_data) > 1 and coll_data[1] != "default":
                            sub_data.update({"network-instance": coll_data[1]})
                            sub_data["config"].update({"network-instance": coll_data[1]})
                else:
                    url = st.get_datastore(dut, "rest_urls")['config_sflow_collector']
                    return st.rest_delete(dut, url)
                rest_data["collector"].append(sub_data)
            else:
                st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
                return False
        if cli_type in ["click", "klish"]:
            st.config(dut, commands, type=cli_type)
        else:
            url = st.get_datastore(dut, "rest_urls")['config_sflow_collector']
            output = st.rest_modify(dut, url, rest_data)
            st.log("REST config_attributes COLLECTOR OUTPUT  -- {}".format(output))
            if output and output["status"] != 204:
                return False
            return True
    return True


def show(dut, cli_type=""):
    """
    API to show sflow configuration
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return: {u'agent_ip': '10.0.0.10', 'collectors': [{'port': '6343', 'collector_ip': '10.100.12.13'},
    {'port': '6344', 'collector_ip': '10.144.1.2'}], u'collectors_cnt': '2',
    u'state': 'enabled', u'agent_id': 'loopback0', u'polling_interval': '20'}
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] + utils_obj.get_supported_ui_type_list() else cli_type
    result = dict()
    if cli_type == "klish" or cli_type == "click":
        command = "show sflow"
        output = st.show(dut, command, type=cli_type)
        if output:
            result["collectors"] = list()
            for data in output:
                for key, value in data.items():
                    if value != "":
                        if key not in ["collector_ip", "collector_port", "collector_name"]:
                            result[key] = value
                        else:
                            result["collectors"].append(
                                {"collector_name": data["collector_name"],
                                 "collector_ip": data["collector_ip"], "port": data["collector_port"]})
            if result:
                result["collectors"] = utils_obj.remove_duplicate_dicts_from_list(result["collectors"])
        else:
            return False
    elif cli_type == "rest":
        output = st.rest_read(dut, REST_URI)
        if output and output.get("status") == 200 and output.get("output"):
            if YANG_MODULE in output["output"]:
                data = output["output"][YANG_MODULE]
                if "SFLOW" in data:
                    for key, value in data["SFLOW"].items():
                        if isinstance(value, list):
                            for attributes in value:
                                result.update({"state": attributes.get("admin_state")})
                                result.update({"agent_id": attributes.get("agent_id")})
                                result.update({"polling_interval": attributes.get("polling_interval")})
                                result.update({"sflow_key": attributes.get("sflow_key")})
                                if attributes.get("agent_id"):
                                    ip_address = get_interface_ip_address(dut, attributes.get("agent_id"))
                                    if ip_address:
                                        ip, _ = ip_address[0]['ipaddr'].split('/')
                                        result.update({"agent_ip": ip})
                if "SFLOW_COLLECTOR" in data:
                    result.update({"collectors_cnt": len(data["SFLOW_COLLECTOR"]["SFLOW_COLLECTOR_LIST"])})
                    result.update({"collectors": list()})
                    for value in data["SFLOW_COLLECTOR"]["SFLOW_COLLECTOR_LIST"]:
                        collector_data = dict()
                        collector_data.update({"port": value.get("collector_port", DEFAULT_COLLECTOR_PORT)})
                        collector_data.update({"collector_ip": value.get("collector_ip")})
                        collector_data.update({"collector_name": value.get("collector_name")})
                        st.log("COLLECTORS {}".format(collector_data))
                        result["collectors"].append(collector_data)
            else:
                st.log("{} not observed in ouput".format(YANG_MODULE))
        else:
            st.log("REST show GET CALL --- {}".format(output))
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
    return result


def show_interface(dut, interface_name=None, cli_type=""):
    """
    API to show sflow interface configuration
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] + utils_obj.get_supported_ui_type_list() else cli_type
    output = list()
    if cli_type == "klish" or cli_type == "click":
        command = "show sflow interface"
        if interface_name:
            command = "{} | grep {}".format(command, interface_name)
        return st.show(dut, command, type=cli_type)
    elif cli_type == "rest":
        if not interface_name:
            url = REST_URI
        else:
            url = "{}/SFLOW_SESSION/SFLOW_SESSION_TABLE".format(REST_URI)
        result = st.rest_read(dut, url, SFLOW_SESSION_LIST=interface_name)
        if result and result.get("status") == 200 and result.get("output"):
            if YANG_MODULE in result["output"]:
                data = result["output"][YANG_MODULE]
                if data.get("SFLOW_SESSION_TABLE").get("SFLOW_SESSION_LIST"):
                    for intf_list in data.get("SFLOW_SESSION_TABLE").get("SFLOW_SESSION_LIST"):
                        response = dict()
                        response["sampling_rate"] = intf_list.get("sample_rate")
                        response["admin_status"] = intf_list.get("admin_state")
                        response["interface"] = intf_list.get("ifname")
                        if response:
                            output.append(response)
            else:
                st.log("{} not observed in ouput".format(YANG_MODULE))
        else:
            st.log("REST show INTERFACE GET CALL --- {}".format(output))
        return output
    else:
        st.log("UNSUPPORTED CLI TYPE {}".format(cli_type))
        return output


def verify_config(dut, **kwargs):
    """
    API to verify sflow configuration
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs: {"data" : [{'collector_ip': '1.1.1.1', 'polling_interval': '0',
    'collectors_cnt': '2', 'state': 'enable', 'agent_id': 'Ethernet6', 'port': '6343'},
    {'port': '6343', 'collector_ip': '192.168.4.4'}], "cli_type": "click"}
    :return: True / False
    """
    st.log("KWARGS -- {}".format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if not kwargs.get("data"):
        st.error("VERIFY DATA NOT PROVIDED ...")
        return False
    verify_data = kwargs.get("data") if isinstance(kwargs.get("data"), list) else [kwargs.get("data")]
    supported_params = ["state", "polling_interval", "collector_name", "collectors_cnt", "collector_ip", "port",
                        "agent_id"]

    if cli_type in utils_obj.get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        for data in verify_data:
            # Mandatory param in GNMI for collector verification
            vrf_str = data.pop('vrf', 'default')
            collector_ip = data.pop('collector_ip', None)
            collector_port = data.pop('port', '6343')
            # Collector_name applicable in click only
            data.pop("collector_name", None)

            sflow_obj = umf_sflow.Sampling()
            for key in data:
                if key not in supported_params:
                    st.log("Unsupported params {}".format(key))
                    return False
                if key == 'state':
                    sflow_obj.Enabled = True if data['state'].lower() == 'up' else False
                elif key == 'agent_id':
                    sflow_obj.Agent = data['agent_id']
                elif key == 'polling_interval':
                    sflow_obj.PollingInterval = int(data['polling_interval'])
                elif key == 'collectors_cnt':
                    if not verify_config(dut, data={'collectors_cnt': data['collectors_cnt']}, cli_type='klish'):
                        st.log('test_step_failed: Match NOT Found: Sflow collectors count, expect:{}'.format(
                            data['collectors_cnt']))
                        return False
            result = sflow_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Match NOT Found: sflow global parameters')
                return False
            if collector_ip:
                coll_obj = umf_sflow.Collector(Address=collector_ip, Port=collector_port, NetworkInstance=vrf_str,
                                               Sampling=sflow_obj)
                result = coll_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Match NOT Found: sflow collector parameters')
                    return False
        return True

    output = show(dut, cli_type)
    st.log("OUTPUT === {}".format(output))
    if output:
        for data in verify_data:
            if cli_type == 'klish':
                data.pop("collector_name", None)
            for key in data:
                if key not in supported_params:
                    st.log("Unsupported params {}".format(key))
                    return False
                if key not in ["collector_name", "collector_ip", "port"]:
                    if str(data[key]) != str(output[key]):
                        st.log("Verification failed for {} with {}, hence checking other values ...".format(data[key], output[key]))
                        return False
                else:
                    is_found = 0
                    for collector_data in output["collectors"]:
                        if str(data[key]) != str(collector_data[key]):
                            is_found = 1
                            st.log("Verification failed for {} with {}".format(data[key], collector_data[key]))
                        else:
                            is_found = 0
                            break
                    if is_found >= 1:
                        st.log("Verification failed ...")
                        return False
        st.log("Verification successful ...")
        return True
    else:
        st.error("Show output not found ...")
        return False


def verify_interface(dut, **kwargs):
    """
    API to verify sflow interface configuration
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface_name:
    :param kwargs: sampling_rate, admin_status
    :return: True / False
    """
    if not kwargs.get("interface_name"):
        st.log("Interface name not provided")
        return False
    interface_name = kwargs.get("interface_name")
    if interface_name == "eth0":
        interface_name = "Management0"
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    if cli_type in utils_obj.get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)

        sflow_obj = umf_sflow.Sampling()
        sflow_intf_obj = umf_sflow.Interface(Name=interface_name, Sampling=sflow_obj)
        if "sampling_rate" in kwargs:
            sflow_intf_obj.SamplingRate = str(kwargs["sampling_rate"])
        if "admin_status" in kwargs:
            sflow_intf_obj.Enabled = True if kwargs["admin_status"].lower() == 'up' else False
        result = sflow_intf_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Match NOT Found: sflow Interface  parameters')
            return False
        return True

    output = show_interface(dut, interface_name=interface_name, cli_type=cli_type)
    if output:
        for data in output:
            if data["interface"] == interface_name:
                st.log("Parsing data for interface {}".format(interface_name))
                if "sampling_rate" in kwargs:
                    if str(data["sampling_rate"]) != str(kwargs["sampling_rate"]):
                        st.log("Sampling rate verification failed ..")
                        return False
                if "admin_status" in kwargs:
                    if data["admin_status"] != kwargs["admin_status"]:
                        st.log("Admin status verification failed ..")
                        return False
        st.log("Verification successful ...")
        return True
    else:
        st.log("Show output not found ...")
        return False


def psample_stats(dut, attr_data):
    """
    API to get psampe stats
    :param dut:
    :param attr_list: ["drop_sampling", "psample", "psample_cb"]
    :return:
    """
    result = dict()
    attr_list = common_utils.make_list(attr_data)
    output = st.show(dut, "sudo cat /proc/bcm/knet-cb/psample/stats")
    if not output:
        st.log("Output not found")
        return result
    for attr in attr_list:
        if attr in output[0]:
            result[attr] = output[0][attr]
    return result


def verify_psample_stats(dut, params):
    """
    API to verify psample stats
    :param dut:
    :param params: {u'drop_sampling': '0', u'psample': '140', u'psample_cb': '148',
    u'drop_psample_not_ready': '0',
    u'drop_no_skb': '0', u'drop_no_psample': '0', u'invalid_src_port': '0', u'psample_module': '148'}
    u'pass_through': '8', u'drop_metadeta': '0', u'invalid_dst_port': '0', u'dcb_type': '36',
    :return:
    """
    output = psample_stats(dut, params.keys())
    if not output:
        st.log("Observed empty output")
        return False
    entries = filter_and_select(output, None, params)
    if not entries:
        st.log("PSAMPLE STATS VERIFICATION FAILED")
        return False
    return True


def hsflowd_status(dut):
    """
    Check if hsflowd in sflow docker is running or not
    :param dut:
    """
    st.log("Check hsflowd status")
    command = "docker exec -i sflow /usr/bin/pgrep hsflowd || echo 0"
    result = st.show(dut, command, skip_tmpl=True)
    st.log('hsflowd status {}'.format(result))
    pid = int(re.search(r'\d+', result).group())
    if pid != 0:
        st.log('hsflowd is running')
    else:
        st.log('hsflowd is NOT running')
        command = "docker exec -i sflow cat /var/log/hsflowd.crash"
        st.config(dut, command)
    return True


def get_psample_list_groups(dut):
    """
    To get all psample list groups
    """
    return st.show(dut, "sudo psample --list-groups", skip_tmpl=True)


def sflow_run_sflowtool_linebyline(dut, **kwargs):
    """
    Runs sflowtool for generating sflow samples
    """
    # Remove sflowtool samples file if already present
    # test -e /tmp/sflow_ipv4.log && sudo rm -rf /tmp/sflow_ipv4.log
    timeout = kwargs.get('timeout', 10)
    collector_version = kwargs.get('collector_version', 4)
    log_file = COLLECTORV4_LOG_FILE if collector_version == 4 else COLLECTORV6_LOG_FILE
    clear_command = "test -e {0} && sudo rm -rf {0}".format(log_file)
    st.config(dut, clear_command, skip_error_check=True)

    # Run sflowtool -l and capture samples
    # docker exec -i sflow timeout 10 /usr/bin/sflowtool -l > /tmp/sflow_ipv4.log
    log_file = COLLECTORV4_LOG_FILE if collector_version == 4 else COLLECTORV6_LOG_FILE
    launch_command = "docker exec -i sflow timeout {} /usr/bin/sflowtool -l > {}".format(timeout, log_file)
    st.config(dut, launch_command, skip_error_check=True)
    return True


def sflow_get_num_samples(dut, **kwargs):
    """
    Returns number of FLOW/CNTR sample count from the collector samples
    """
    sample_type = kwargs.get('sample_type', 'FLOW')
    collector_version = kwargs.get('collector_version', 4)
    disp = kwargs.get('disp', False)
    log_file = COLLECTORV4_LOG_FILE if collector_version == 4 else COLLECTORV6_LOG_FILE
    command = "cat {0}".format(log_file)
    if disp:
        command += " | grep {}".format(sample_type)
        st.show(dut, command, skip_tmpl=True, skip_error_check=True)
        return True
    if sample_type is not None:
        command += " | grep {} | wc -l".format(sample_type)
        result = st.show(dut, command, skip_tmpl=True, skip_error_check=True)
        count = re.search(r'\d+', result).group()
        st.debug("The number of samples are: {}".format(count))
    return int(count) if isinstance(count, int) else 0


def init_default_config(dut):
    if not st.is_feature_supported("sflow-default-enabled", dut):
        st.config(dut, "config feature state sflow enabled")
