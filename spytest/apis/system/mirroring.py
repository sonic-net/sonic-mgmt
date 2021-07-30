# This file contains the list of API's which performs Mirroring operations.
# @author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com)

from spytest import st
import json
import utilities.common as common_utils
from utilities.utils import make_list, remove_last_line_from_string
from spytest.utils import filter_and_select
from apis.system.rest import get_rest,delete_rest,config_rest,rest_status

YANG_MODEL = "sonic-mirror-session:sonic-mirror-session"

# create_mirror_session(dut, session_name="<session_name>",src_ip=<src_ip>,
# dst_ip=<dst_ip>,dscp =<dscp>, ttl=<ttl>,gre_type=<gre_type>,queue=<queue>)
def create_session(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """
    API to configure mirror session for both erspan, span and legacy configuration support
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param kwargs:
    session_name : Name of the session (Mandatory)
    mirror_type: erspan or span. (Not mamdatory, as to support Mirror configuration in ARLO)
    destination_ifname: destination interface name in case of span
    source_ifname: source interface name in case of span
    rx_tx: rx/tx in case of span
    src_ip: source ip address in case of erspan
    dst_ip: destination ip address in case of erspan
    dscp: DSCP in case of erspan
    ttl: TTL in case of erspan
    queue: QUEUE in case of erspan
    gre_type: GRE_TYPE in case of erspan
    :return:
    """
    kwargs["mirror_type"] = kwargs.get("mirror_type", "erspan")
    skip_err_check = kwargs.get("skip_err_check", False)
    if 'session_name' not in kwargs:
        st.error("Session name not provided ...")
        return False
    if kwargs.get("mirror_type") not in ["erspan", "span"]:
        st.log("Unsupported mirror type ..")
        return False
    if cli_type == "click":
        if not st.is_feature_supported("span-mirror-session", dut):
            command = "config mirror_session add {}".format(kwargs["session_name"])
        elif not st.is_feature_supported("config_mirror_session_add_type", dut):
            command = "config mirror_session {} add {}".format(kwargs["mirror_type"], kwargs["session_name"])
        else:
            command = "config mirror_session add {} {}".format(kwargs["mirror_type"], kwargs["session_name"])
        if kwargs["mirror_type"] == "span":
            if "destination_ifname" in kwargs:
                command += " {}".format(kwargs["destination_ifname"])
            if "source_ifname" in kwargs:
                command += " {}".format(kwargs["source_ifname"])
            if "rx_tx" in kwargs:
                command += " {}".format(kwargs["rx_tx"])
        else:
            if 'src_ip' not in kwargs:
                st.error("Source IP not provided ...")
                return False
            command += " {}".format(kwargs["src_ip"])
            if 'dst_ip' not in kwargs:
                st.error("Destination IP not provided ...")
                return False
            command += " {}".format(kwargs["dst_ip"])
            if 'dscp' not in kwargs:
                st.error("dscp not provided ...")
                return False
            command += " {}".format(kwargs["dscp"])
            if 'ttl' in kwargs:
                command += " {}".format(kwargs["ttl"])
            if 'gre_type' not in kwargs:
                st.error("gre_type not provided ...")
                return False
            gre_type = kwargs["gre_type"]
            command += " {}".format(gre_type)
            if 'queue' in kwargs:
                command += " {}".format(kwargs["queue"])
            if kwargs.get("src_port"):
                command += " {}".format(kwargs.get("src_port"))
            if kwargs.get("direction"):
                command += " {}".format(kwargs.get("direction"))
        output = st.config(dut, command, type=cli_type, skip_error_check=skip_err_check)
        output = remove_last_line_from_string(output)
        if skip_err_check:
            if "Failed" or "Error" in output:
                st.debug("Failed to create/delete mirror session")
                return False
        if ("mirror_type" in kwargs and kwargs["mirror_type"] != "span") or ("mirror_type" not in kwargs):
            session_data = verify_session(dut, session_name=kwargs["session_name"], src_ip=kwargs["src_ip"],
                                          dst_ip=kwargs["dst_ip"], dscp=kwargs["dscp"], ttl=kwargs["ttl"],
                                          gre_type=gre_type, queue=kwargs["queue"])
            return False if not session_data else True
        return True
    elif cli_type == "klish":
        commands = list()
        cmd_mirror_session = "mirror-session {}".format(kwargs["session_name"])
        commands.append(cmd_mirror_session)
        if kwargs.get("mirror_type") == "span":
            if not kwargs.get("destination_ifname"):
                st.log("Please provide destination interface")
                return False
            command = "destination {}".format(kwargs.get("destination_ifname"))
            if kwargs.get("source_ifname"):
                command = "{} source {}".format(command,kwargs.get("source_ifname"))
                if kwargs.get("rx_tx"):
                    command = "{} direction {}".format(command,kwargs.get("rx_tx"))
        else:
            command = "destination erspan"
            gre_type = kwargs["gre_type"]
            if kwargs.get("src_ip"):
                command += " src-ip {}".format(kwargs.get("src_ip"))
            if kwargs.get("dst_ip"):
                command += " dst-ip {}".format(kwargs.get("dst_ip"))
            if kwargs.get("gre_type"):
                command += " gre {}".format(gre_type)
            if kwargs.get("dscp"):
                command += " dscp {}".format(kwargs.get("dscp"))
            if kwargs.get("ttl"):
                command += " ttl {}".format(kwargs.get("ttl"))
            if kwargs.get("queue"):
                command += " queue {}".format(kwargs.get("queue"))
            if kwargs.get("src_port"):
                command += " source {}".format(kwargs.get("src_port"))
            if kwargs.get("direction"):
                command += " direction {}".format(kwargs.get("direction"))
        commands.append(command)
        commands.append("exit")
        st.log("COMMAND : {}".format(commands))
        output = st.config(dut, commands, type=cli_type, skip_error_check=skip_err_check)
        if skip_err_check:
            if "Error" in output:
                st.debug("Failed to create mirror session")
                return False
        if ("mirror_type" in kwargs and kwargs["mirror_type"] != "span") or ("mirror_type" not in kwargs):
            session_data = verify_session(dut, session_name=kwargs["session_name"], src_ip=kwargs["src_ip"],
                                          dst_ip=kwargs["dst_ip"], dscp=kwargs["dscp"], ttl=kwargs["ttl"],
                                          gre_type=gre_type, queue=kwargs["queue"])
            if not session_data:
                return False
        if kwargs.get("no_form_session_name"):
            command = "no mirror-session {}".format(kwargs["session_name"])
            output = st.config(dut, command, type=cli_type, skip_error_check=skip_err_check)
            output = remove_last_line_from_string(output)
            if skip_err_check:
                if "Error" in output:
                    st.debug("Failed to delete mirror session")
                    return False
        return True
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        mirror_type = kwargs.get("mirror_type")
        url = rest_urls['config_mirror_session'].format(kwargs["session_name"])
        data = {}
        if mirror_type == "span":
            if kwargs.get("source_ifname"):
                data["src-port"] = str(kwargs.get("source_ifname"))
            if kwargs.get("destination_ifname"):
                data["dst-port"] = str(kwargs.get("destination_ifname"))
            if kwargs.get("rx_tx"):
                data["direction"] = str(kwargs.get("rx_tx").upper())
        else:
            if kwargs.get("src_ip"):
                data["src-ip"] = str(kwargs.get("src_ip"))
            if kwargs.get("dst_ip"):
                data["dst-ip"] = str(kwargs.get("dst_ip"))
            if kwargs.get("dscp"):
                data["dscp"] = int(kwargs.get("dscp"))
            if kwargs.get("gre_type"):
                data["gre-type"] = str(kwargs.get("gre_type"))
            if kwargs.get("ttl"):
                data["ttl"] = int(kwargs.get("ttl"))
            if 'queue' in kwargs:
                data["queue"] = int(kwargs.get("queue"))
            if kwargs.get("src_port"):
                data["src-port"] = str(kwargs.get("src_port"))
            if kwargs.get("direction"):
                data["direction"] = str(kwargs.get("direction").upper())
        config_data = {"openconfig-mirror-ext:config": data}
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data):
            return False
    else:
        st.log("Unsupported cli")
        return False
    return True


def show_session(dut, mirror_session='', cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    return show_session_all(dut, mirror_session, cli_type=cli_type)

def verify_session(dut, **kwargs):
    kwargs["mirror_type"] = kwargs.get("mirror_type", "erspan")
    return verify_session_all(dut, **kwargs)

def delete_session(dut, mirror_session='', skip_err_check=False, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    '''
    :param dut:
    :param mirror_session:
    :return:
    '''
    if not mirror_session:
        st.error("Mirror session name not provided ...")
        return False
    if cli_type == "click":
        command = "config mirror_session remove {}".format(mirror_session)
        st.config(dut, command, skip_error_check=skip_err_check)
        return True if show_session(dut, mirror_session) else False
    elif cli_type == "klish":
        commands = list()
        command = "no mirror-session {}".format(mirror_session)
        commands.append(command)
        output = st.config(dut, commands, type=cli_type, skip_error_check=skip_err_check)
        st.config(dut, "exit",type=cli_type)
        output = remove_last_line_from_string(output)
        if output:
            if "Failed" not in output or "Error" not in output:
                return False
        return True
    elif cli_type in ['rest-put', "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['get_session_session_name'].format(mirror_session)
        if not delete_rest(dut, rest_url = url):
            return False
        return True
    else:
        st.log("Unsupported cli")
        return False



def create_session_table(dut, **kwargs):
    """
    Creating monitor session via config_db.json file
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to build mirror session json data
    :return:
    """
    mirror_data = kwargs

    if 'session_name' not in mirror_data:
        st.error("Session name not provided ...")
        return False
    if 'src_ip' not in mirror_data:
        st.error("Source IP not provided ...")
        return False
    if 'dst_ip' not in mirror_data:
        st.error("Destination IP not provided ...")
        return False
    if 'dscp' not in mirror_data:
        st.error("dscp not provided ...")
        return False
    if 'ttl' not in mirror_data:
        st.error("ttl not provided ...")
        return False

    # gre_type and queue is optional arguments to create mirror session.

    # Sample config_db.json output
    """
    "MIRROR_SESSION": {
        "mirr": {
            "dscp": "20",
            "dst_ip": "2.2.2.2",
            "gre_type": "0x88ee",
            "queue": "0",
            "src_ip": "1.1.1.1",
            "ttl": "100"
        }
    },
    """
    mirror_table = dict()
    mirror_table_data = dict()
    mirror_table_data[mirror_data["session_name"]] = dict()
    mirror_table_data[mirror_data["session_name"]]["src_ip"] = mirror_data["src_ip"]
    mirror_table_data[mirror_data["session_name"]]["dst_ip"] = mirror_data["dst_ip"]
    mirror_table_data[mirror_data["session_name"]]["dscp"] = mirror_data["dscp"]
    mirror_table_data[mirror_data["session_name"]]["ttl"] = mirror_data["ttl"]
    mirror_table_data[mirror_data["session_name"]]["gre_type"] = mirror_data[
        "gre_type"] if 'gre_type' in mirror_data else "0x88ee"
    mirror_table_data[mirror_data["session_name"]]["queue"] = mirror_data["queue"] if 'queue' in mirror_data else "0"
    mirror_table["MIRROR_SESSION"] = mirror_table_data
    mirror_table = json.dumps(mirror_table)
    st.apply_json(dut, mirror_table)
    if not verify_session(dut, **kwargs):
        return False
    return True


def show_session_all(dut, session_name=None, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to show the mirror session output for both erspan and span
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param session_name:
    :return:
    {'span': [{u'source_port': 'Ethernet4', u'direction': 'INGRESS', u'span_name': 'portmir0',
    u'destination_port': 'Ethernet0', u'span_status': 'active'},
    {u'source_port': 'Ethernet84', u'direction': 'INGRESS', u'span_name': 'portmir3',
    u'destination_port': 'Ethernet5', u'span_status': 'active'}],
    'erspan': [{u'status': 'active', u'queue': '', u'name': 'everflow0', u'dscp': '78',
    u'src_ip': '10.1.0.32', u'ttl': '', u'dst_ip': '10.0.0.7', u'gre_type': '0x866'},
    {u'status': 'active', u'queue': '', u'name': 'everflow0', u'dscp': '64', u'src_ip': '10.1.0.33',
    u'ttl': '', u'dst_ip': '10.0.0.7', u'gre_type': '0x866'}]}

    """
    result = dict()
    erspan_cols = ["name", "status", "src_ip", "dst_ip", "gre_type", "dscp", "ttl", "queue","policer", "erspan_src_port","erspan_direction"]
    span_cols = ["span_name", "span_status", "destination_port", "source_port", "direction"]
    if cli_type == "click":
        command = "show mirror_session"
        if session_name:
            command += " {}".format(session_name)
        output = st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = "show mirror-session"
        if session_name:
            command += " {}".format(session_name)
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        output = []
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not session_name:
            url = rest_urls['get_session_all']
            rest_get_output = get_rest(dut, rest_url=url)
            if rest_get_output and rest_get_output.get("output") and rest_status(rest_get_output["status"]):
                actual_data = rest_get_output['output']['openconfig-mirror-ext:mirror']['sessions']['session']
                for i in actual_data:
                    process_data = i['state']
                    rest_out_keys = process_data.keys()
                    if 'dscp' in rest_out_keys:
                        temp1 = {}
                        temp1['name'] = i['name']
                        temp1['erspan_direction'] = i['state']['direction'] if 'direction' in i['state'] else ''
                        temp1['erspan_src_port'] = i['state']['src-port'] if 'src-port' in i['state'] else ''
                        temp1['dscp'] = i['state']['dscp'] if 'dscp' in  i['state'] else ''
                        temp1['dst_ip'] = str(i['state']['dst-ip']) if 'dst-ip' in i['state'] else ''
                        temp1['queue'] = str(i['state']['queue']) if 'queue' in i['state'] else ''
                        temp1['src_ip'] = i['state']['src-ip'] if 'src-ip' in i['state'] else ''
                        temp1['gre_type'] = i['state']['gre-type'] if 'gre-type' in i['state'] else ''
                        temp1['ttl'] = str(i['state']['ttl']) if 'ttl' in i['state'] else ''
                        temp1['span_name'] = temp1['direction'] = temp1['source_port'] = temp1['destination_port'] = ''
                        url = rest_urls['get_mirror_status'].format(i['name'])
                        status_out = get_rest(dut, rest_url=url)
                        temp1['status'] = status_out['output']['openconfig-mirror-ext:status']
                        output.append(temp1)
                    else:
                        temp2 = {}
                        temp2['span_name'] = i['name']
                        temp2['direction'] = i['state']['direction'] if 'direction' in i['state'] else ''
                        temp2['source_port'] = i['state']['src-port'] if 'src-port' in i['state'] else ''
                        temp2['destination_port'] = i['state']['dst-port'] if 'dst-port' in i['state'] else ''
                        temp2['name'] = temp2['erspan_direction'] = temp2['erspan_src_port'] = temp2['dscp'] = temp2[
                            'dst_ip'] = temp2['queue'] \
                            = temp2['src_ip'] = temp2['gre_type'] = temp2['ttl'] = ''
                        url = rest_urls['get_mirror_status'].format(i['name'])
                        status_out = get_rest(dut, rest_url=url)
                        temp2['span_status'] = status_out['output']['openconfig-mirror-ext:status']
                        output.append(temp2)
        if session_name:
            url = rest_urls['get_session_session_name'].format(session_name)
            rest_get_output = get_rest(dut, rest_url=url)
            if rest_get_output and rest_get_output.get("output") and rest_status(rest_get_output["status"]):
                actual_data = rest_get_output['output']['openconfig-mirror-ext:session'][0]
                temp = {}
                process_data = actual_data['state']
                rest_out_keys = process_data.keys()
                st.log("getting mirror status")
                url = rest_urls['get_mirror_status'].format(session_name)
                status_out = get_rest(dut, rest_url=url)
                if 'dscp' in rest_out_keys:
                    if 'dscp' in erspan_cols:
                        temp['name'] = actual_data['name']
                        temp['erspan_direction'] = actual_data['state']['direction'] if 'direction' in  actual_data['state'] else ''
                        temp['erspan_src_port'] = actual_data['state']['src-port'] if 'src-port' in  actual_data['state'] else ''
                        temp['dscp'] = str(actual_data['state']['dscp']) if 'dscp' in  actual_data['state'] else ''
                        temp['dst_ip'] = actual_data['state']['dst-ip'] if 'dst-ip' in  actual_data['state'] else ''
                        temp['queue'] = str(actual_data['state']['queue']) if 'queue' in  actual_data['state'] else ''
                        temp['src_ip'] = actual_data['state']['src-ip'] if 'src-ip' in  actual_data['state'] else ''
                        temp['gre_type'] = actual_data['state']['gre-type'] if 'gre-type' in  actual_data['state'] else ''
                        temp['ttl'] = str(actual_data['state']['ttl']) if 'ttl' in  actual_data['state'] else ''
                        temp['span_name'] = temp['direction']= temp['source_port']=temp['destination_port'] = ''
                        temp['status'] = status_out['output']['openconfig-mirror-ext:status']
                        output.append(temp)
                else:
                    temp['span_name'] = actual_data['name']
                    temp['direction'] = actual_data['state']['direction'] if 'direction' in  actual_data['state'] else ''
                    temp['source_port'] = actual_data['state']['src-port'] if 'src-port' in  actual_data['state'] else ''
                    temp['destination_port'] = actual_data['state']['dst-port'] if 'dst-port' in  actual_data['state'] else ''
                    temp['name']=temp['erspan_direction']=temp['erspan_src_port']=temp['dscp']=temp['dst_ip']=temp['queue']\
                        = temp['src_ip'] = temp['gre_type']=temp['ttl'] = ''
                    temp['span_status'] = status_out['output']['openconfig-mirror-ext:status']
                    output.append(temp)
    if output:
        result["erspan"] = list()
        result["span"] = list()
        for data in output:
            erspan_dict = dict()
            span_dict = dict()
            for key, value in data.items():
                if data["name"] and key in erspan_cols:
                    erspan_dict[key] = value
                if data["span_name"] and key in span_cols:
                    span_dict[key] = value
            if span_dict:
                result["span"].append(span_dict)
            if erspan_dict:
                result["erspan"].append(erspan_dict)
    return result

def verify_session_all(dut, **kwargs):
    """
    API to verify the mirror session configuration based on mirror type
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    {"mirror_type":"span","source_port": "Ethernet4", "direction": "INGRESS", "span_name": "portmir0",
    "destination_port": "Ethernet0", "span_status": "active"}
    {"mirror_type":"erspan", "status": "active", "queue": '', "name": "everflow0", "dscp": "78",
    "src_ip": "10.1.0.32", "ttl": '', "dst_ip": "10.0.0.7", "gre_type": "0x866"}
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log("Verifying mirror session config....")
    if "mirror_type" in kwargs:
        if kwargs["mirror_type"] not in ["erspan", "span"]:
            st.log("Unsupported mirror_type provided ...")
            return False
        output = show_session_all(dut, kwargs["session_name"], cli_type=cli_type) if "session_name" in kwargs \
            else show_session_all(dut, cli_type=cli_type)
        if not output or kwargs["mirror_type"] not in output:
            st.log("Observed emtpy response for show command ..")
            return False
        if kwargs["mirror_type"] == "erspan":
            kwargs["name"] = kwargs["session_name"]
        if kwargs["mirror_type"] == "span":
            kwargs["span_name"] = kwargs["session_name"]
        response = output[kwargs["mirror_type"]]
        kwargs.pop("mirror_type")
        kwargs.pop("session_name")
        if "cli_type" in kwargs:
            kwargs.pop("cli_type")
        entries = common_utils.filter_and_select(response, None, kwargs)
        if not entries:
            st.log("Mismatch in entries {}...".format(kwargs))
            return False
        return True
    else:
        st.log("Mirror type not provided ...")
        return False


def config_max_sessions(dut, **kwargs):
    """
    API to configure max mirror sessions
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs: {"cli_ype":"rest","data":[{"name":"Mirror1","src_ip":"10.20.3.1","dst_ip":"10.23.3.5",
    "gre_type":"0x855","dscp":16,"ttl":5,"queue":6,"dst_port":"Ethernet28","src_port":"Ethernet20",
    "direction":"rx/tx"},{"name":"Mirror2","dst_port":"Ethernet20","src_port":"Ethernet22","direction":"rx"},
    {"name":"Mirror3","dst_port":"Ethernet26","src_port":"Ethernet22","direction":"tx"}],"action":"config"}
    :return: response/False
    """
    cli_type = kwargs.get("cli_type","rest")
    if cli_type == "rest":
        status = 204
        data = kwargs.get("data")
        action = data.get("action", "config")
        rest_url = "/restconf/data/{}".format(YANG_MODEL)
        if action == "config":
            if data.get("data"):
                rest_data = dict()
                rest_data[YANG_MODEL] = dict()
                rest_data[YANG_MODEL]["MIRROR_SESSION"] = dict()
                rest_data[YANG_MODEL]["MIRROR_SESSION"]["MIRROR_SESSION_LIST"] = make_list(data.get("data"))
                response = st.rest_modify(dut, rest_url,rest_data)
            else:
                st.log("Required data not found -- {}".format(data))
                return False
        elif action == "unconfig":
            response = st.rest_delete(dut, rest_url)
        elif action == "get":
            response = st.rest_read(dut, rest_url)
            status = 200
        else:
            st.log("Unsupporte ACTION -- {}".format(action))
            return False
        if response and response["status"] == status:
            return response
        else:
            st.log("RESPONSE -- {}".format(response))
            return False
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

def verify_max_sessions(dut, **kwargs):
    """
    API to verify max sessions
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :return: {"cli_ype":"rest","data":[{"name":"Mirror1","src_ip":"10.20.3.1","dst_ip":"10.23.3.5",
    "gre_type":"0x855","dscp":16,"ttl":5,"queue":6,"dst_port":"Ethernet28","src_port":"Ethernet20",
    "direction":"rx/tx"},{"name":"Mirror2","dst_port":"Ethernet20","src_port":"Ethernet22","direction":"rx"},
    {"name":"Mirror3","dst_port":"Ethernet26","src_port":"Ethernet22","direction":"tx"}]}
    """
    st.log("KWARGS -- {}".format(kwargs))
    cli_type = kwargs.get("cli_type", "rest")
    if cli_type == "rest":
        rest_url = "/restconf/data/{}".format(YANG_MODEL)
        verify_data = kwargs.get("data").get("data")
        if not verify_data:
            st.log("DATA TO VERIFY IS NOT PROVIDED -- {}".format(verify_data))
            return False
        response = st.rest_read(dut, rest_url)
        if response and response["status"] == 200:
            data = response["output"][YANG_MODEL]["MIRROR_SESSION"]["MIRROR_SESSION_LIST"]
            if not data:
                st.log("DATA IN RESPONSE IS EMPTY -- {}".format(data))
                return False
            for session_data in verify_data:
                output = filter_and_select(data, session_data.keys(), session_data)
                st.log("FILTER RESPONSE -- {}".format(output))
                if not output:
                    return False
            return True
        else:
            st.log("RESPONSE -- {}".format(response))
            return False
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

