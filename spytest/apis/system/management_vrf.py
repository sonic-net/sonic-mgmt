from spytest import st
from apis.system.rest import rest_status
from apis.system.rest import get_rest
from apis.system.rest import config_rest, delete_rest
import utilities.common as utils


def verify(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """
    Author : Kiran Vedula (kvedula@broadcom.com)
    :param :dut:
    :param :vrf_name:
    :param :interfaces:
    verify(vars.D1, vrf_name='management', interfaces=['eth0'])
    """
    interface_li = utils.make_list(kwargs.get('interfaces'))
    output = show(dut, cli_type=cli_type)
    if cli_type == 'klish':
        if not output:
            st.error("Unable to get command output")
            return False
        else:
            if output[0]['interface'] != 'eth0':
                st.log("Mgmt VRF not bound to eth0")
                return False
    elif cli_type == 'click':
        if not output:
            st.error("Unable to get command output")
            return False
        if output['mvrfstate'] != kwargs.get('mvrfstate'):
            st.log("Management VRF state mismatch")
            return False
        if output['mvrfstate'] == "Enabled":
            match = list()
            for each in interface_li:
                match.append({'mvrf_interface': each})
            intf_list = utils.filter_and_select(output["interfaces"], None, match)
            if kwargs.get('dataport'):
                if intf_list:
                    st.log("No match available for - {} in output".format(match))
                    return False
            else:
                if not intf_list:
                    st.log("No match available for - {} in output".format(match))
                    return False
    elif cli_type in ["rest-patch","rest-put"]:
        if not output:
            st.log("Unable to get Rest operation Get output")
            return False
        if not rest_status(output["status"]):
            st.log("rest_call_failed","GET")
            return False
        if output["output"]["openconfig-network-instance:state"]["name"] != "mgmt":
            st.log("Mgmt VRF not bound to eth0")
            return False
        if not output["output"]["openconfig-network-instance:state"]["enabled"]:
            st.log("Management VRF state mismatch")
            return False
    else:
        st.error("Unsupported cli_type: {}".format(cli_type))
        return False
    return True


def show(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """
    API to show management VRF
    Author : Kiran Vedula (kvedula@broadcom.com)
    :param :dut:
    :return: FOR CLICK : {'mvrfstate': 'Enabled', 'interfaces': [{u'mvrfstate': '', u'intf_state':
    'NOARP,MASTER,UP,LOWER_UP', u'vrf_val': '5000', u'mvrf_interface': 'mgmt'}, {u'mvrfstate': '',
    u'intf_state': 'BROADCAST,NOARP,UP,LOWER_UP', u'vrf_val': '', u'mvrf_interface': 'lo-m'}, {u'mvrfstate': '',
    u'intf_state': 'BROADCAST,MULTICAST,UP,LOWER_UP', u'vrf_val': '', u'mvrf_interface': 'eth0'}]}
    """
    result = dict()
    if cli_type == 'klish':
        command ="show ip vrf mgmt"
        output = st.show(dut, command, type=cli_type, skip_error_check=True)
        if output:
            return output
        else:
            return False
    elif cli_type == 'click':
        command = 'show mgmt-vrf'
        output =  st.show(dut, command, type=cli_type)
        result.update({"interfaces":list()})
        for data in output:
            if data.get("mvrfstate"):
                result.update({"mvrfstate":data.get("mvrfstate")})
            if data.get("mvrf_interface") and data.get("mvrf_interface") == "mgmt":
                result["interfaces"][0] = data
            elif not data.get("vrf_val"):
                result["interfaces"].append(data)
            if data.get("vrf_val"):
                result["interfaces"][0]["vrf_val"] = data.get("vrf_val")
        return result
    elif cli_type in ["rest-patch","rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['mgmt_vrf_state'].format("mgmt")
        return get_rest(dut, rest_url=url)
    else:
        st.error("Unsupported cli_type: {}".format(cli_type))
        return False


def config(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """
    API to create Mgmt VRF.
    Author : Kiran Vedula (kvedula@broadcom.com)
    :param :dut:
    :param :mgmtvrf:
    :param :cli_type:   default - klish
    :param :no_form:   default - False
    :return:

    Usage:
    config(vars.D1, cli_type='klish')

    config(vars.D1, no_form=True,cli_type='klish')

    """
    no_form = "no" if kwargs.get("no_form") else ""
    command_list = []
    if cli_type == 'klish':
        if not no_form:
            command_list.append("ip vrf mgmt")
            st.config(dut, command_list, type=cli_type, expect_ipchange=True)
        else:
            command_list.append("no ip vrf mgmt")
            st.config(dut, command_list, type=cli_type, expect_ipchange=True)
    elif cli_type == "click":
        st.log('Config Mgmt VRF API')
        if no_form != 'no':
            my_cmd = 'sudo config vrf add mgmt'
        else:
            my_cmd = 'sudo config vrf del mgmt'
        st.config(dut, my_cmd, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if no_form != 'no':
            url = rest_urls['config_mgmt_vrf'].format("mgmt")
            config_data =  {"openconfig-network-instance:config": {"enabled": True,"name": "mgmt"}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data):
                return False
        else:
            url = rest_urls['unconfig_mgmt_vrf'].format("mgmt")
            if not delete_rest(dut, rest_url= url):
                return False
    else:
        st.error("Unsupported cli_type: {}".format(cli_type))
        return False
    return True

